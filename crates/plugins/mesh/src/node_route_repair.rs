//! The mesh node's route-repair worker (#483, #489).
//!
//! While a node is up, one worker thread listens for route notifications through the node's
//! [`RouteMonitor`](crate::wireguard::RouteMonitor). It re-adds a deleted peer route at once,
//! runs a full inventory check every [`ROUTE_RECHECK_INTERVAL`] and after lost notifications,
//! and publishes the proven link and the underlay watch that live-endpoint refreshes use.
//!
//! It lives in its own file only to keep `node.rs` under the repository's size limit; it is part
//! of the node module and uses its route state directly.

use crate::{
    mesh_mtu::EndpointProbe,
    policy::model::{Addresses, PublicKey},
    wireguard::{ActiveLink, RouteWake},
};
use std::net::SocketAddr;

use super::{
    Arc, AsFd, BTreeSet, Device, IpAddr, JoinHandle, Mutex, PeerRouteState, Shutdown, UnixStream,
    io, lock_route_state, thread,
};

/// Idle delay before another full inventory check becomes due, independent of notifications.
/// A missed loss is retried after at most one such delay, plus work already in flight, scheduling
/// and mutex waits, and a successful kernel reconciliation pass. This is not a real-time promise
/// when the kernel rejects writes or the process cannot run; failures retry on the next check.
const ROUTE_RECHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Test probe: how many repair passes (one deletion or one full inventory check) the
/// route-repair worker has finished in this process, so a namespace test can wait for the
/// worker instead of guessing a delay (#483 J780).
#[cfg(test)]
pub(super) static ROUTE_REPAIR_PASSES: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Repairs accepted routes using notifications plus a low-frequency complete inventory check.
/// The proven link identity is fixed for the worker's lifetime. Exclusive additions preserve
/// foreign destinations, and the absolute deadline cannot be postponed by unrelated events.
pub(super) struct RouteRepairWorker {
    /// Shutting down this stream wakes both event listening and fallback waits before teardown.
    cancel: UnixStream,
    /// The listener that reads route notifications in the node's network namespace.
    worker: Option<JoinHandle<()>>,
    /// Shared route state, whose `link` this worker publishes while it runs.
    state: Arc<Mutex<PeerRouteState>>,
    /// The proven link this worker repairs, and the only link live-endpoint refreshes may write.
    link: crate::wireguard::ActiveLink,
    /// The underlay watch this worker's route listener feeds and publishes with `link`.
    underlay: Arc<crate::wireguard::UnderlayWatch>,
}

impl RouteRepairWorker {
    /// Start recovery bound to the current owner-marked link, never just its shared name.
    ///
    /// The listener also wakes `announce` on every underlay change that can move our own
    /// endpoint as peers see it (#483); the node's `GotaTun` worker turns that into keepalives.
    /// # Errors
    /// Returns ownership, listener, cancellation-stream, or thread creation errors.
    pub(super) fn start(
        state: Arc<Mutex<PeerRouteState>>,
        announce: Arc<crate::gotatun_node::UnderlayAnnounce>,
    ) -> io::Result<Self> {
        let link = Device::active_link()?.ok_or(io::ErrorKind::NotConnected)?;
        let underlay = Arc::new(crate::wireguard::UnderlayWatch::default());
        let monitor = Some(Device::route_monitor(
            &link,
            Arc::clone(&underlay),
            Arc::clone(&announce),
        )?);
        Self::start_for_link(state, link, monitor, underlay, announce)
    }

    /// Spawn the worker with a proven identity and an optional listener; absence uses the fallback.
    ///
    /// The proven link is published in the shared route state, so live-endpoint refreshes write to
    /// the same link identity this worker verifies (#489 J549 P2). `underlay` is the watch that
    /// `monitor` feeds; it is published too, and marked unwatched whenever no listener runs, so
    /// refreshes then re-derive every peer instead of trusting a silent watch (#489 J552 P2-2).
    pub(super) fn start_for_link(
        state: Arc<Mutex<PeerRouteState>>,
        link: crate::wireguard::ActiveLink,
        mut monitor: Option<crate::wireguard::RouteMonitor>,
        underlay: Arc<crate::wireguard::UnderlayWatch>,
        announce: Arc<crate::gotatun_node::UnderlayAnnounce>,
    ) -> io::Result<Self> {
        let shared = Arc::clone(&state);
        let worker_underlay = Arc::clone(&underlay);
        underlay.set_watched(monitor.is_some());
        let (cancel_read, cancel) = UnixStream::pair()?;
        let worker = thread::Builder::new()
            .name("mesh-route-repair".to_owned())
            .spawn(move || {
                let mut deadline = std::time::Instant::now() + ROUTE_RECHECK_INTERVAL;
                loop {
                    let wake = if let Some(listener) = monitor.as_mut() {
                        listener.wait_for_deleted_peer_route(cancel_read.as_fd(), deadline)
                    } else {
                        wait_for_route_recheck(cancel_read.as_fd(), deadline)
                    };
                    let address = match wake {
                        Ok(RouteWake::Deleted(address)) => Some(address),
                        Ok(RouteWake::Cancelled) => break,
                        Ok(RouteWake::Reconcile | RouteWake::Overflow) => None,
                        Err(ref error) => {
                            tracing::warn!(error = %error, "mesh route notifications unavailable; periodic recovery remains active");
                            // A broken listener cannot spin or permanently disable reconciliation.
                            monitor = None;
                            worker_underlay.set_watched(false);
                            continue;
                        }
                    };
                    if let Err(error) = repair_accepted_routes(&link, &state, address) {
                        tracing::warn!(error = %error, "mesh route repair skipped or failed; retrying on the next inventory check");
                    }
                    #[cfg(test)]
                    ROUTE_REPAIR_PASSES.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    if address.is_none() {
                        // Path-MTU exceptions the kernel caches from ICMP are never announced;
                        // the next refresh after each periodic check re-derives every budget, so
                        // they are picked up within one interval (#489 J552 P2-2).
                        if matches!(wake, Ok(RouteWake::Reconcile)) {
                            worker_underlay.changed();
                        }
                        deadline = std::time::Instant::now() + ROUTE_RECHECK_INTERVAL;
                        if monitor.is_none() {
                            monitor = Device::route_monitor(
                                &link,
                                Arc::clone(&worker_underlay),
                                Arc::clone(&announce),
                            )
                            .ok();
                            worker_underlay.set_watched(monitor.is_some());
                        }
                    }
                }
            })?;
        {
            let mut published = lock_route_state(&shared);
            published.link = Some(link);
            published.underlay = Some(Arc::clone(&underlay));
            published.forget_written();
        }
        Ok(Self {
            cancel,
            worker: Some(worker),
            state: shared,
            link,
            underlay,
        })
    }

    /// Stop and join the passive listener before the node tears down its link.
    ///
    /// It also withdraws the link it published, unless a newer worker already replaced it, so
    /// live-endpoint refreshes stop writing once no worker vouches for the link.
    pub(super) fn stop(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        let _ = self.cancel.shutdown(Shutdown::Write);
        if worker.join().is_err() {
            tracing::error!("mesh route repair listener panicked");
        }
        let mut state = lock_route_state(&self.state);
        if state.link == Some(self.link) {
            state.link = None;
            state.underlay = None;
            state.forget_written();
        }
        self.underlay.set_watched(false);
    }

    /// Reports whether the listener exited early and can be replaced on the next `up` call.
    pub(super) fn is_finished(&self) -> bool {
        self.worker.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for RouteRepairWorker {
    /// Wake and join the listener so it never outlives the owning node.
    fn drop(&mut self) {
        self.stop();
    }
}

/// Wait cheaply on cancellation when notifications fail, retaining the reconciliation deadline.
fn wait_for_route_recheck(
    cancel: std::os::fd::BorrowedFd<'_>,
    deadline: std::time::Instant,
) -> io::Result<crate::wireguard::RouteWake> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Ok(RouteWake::Reconcile);
        }
        let mut descriptors = [PollFd::new(cancel, PollFlags::POLLIN)];
        match poll(
            &mut descriptors,
            PollTimeout::try_from(remaining).map_err(io::Error::other)?,
        ) {
            Ok(0) => return Ok(RouteWake::Reconcile),
            Ok(_) => return Ok(RouteWake::Cancelled),
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

/// A missing route's peer and the inputs used to derive its repair budget.
struct RepairTarget {
    /// Identity whose accepted membership is rechecked before every write.
    key: PublicKey,
    /// Both destinations must still belong to the accepted peer when it is repaired.
    addresses: Addresses,
    /// Configured endpoint used if no relay budget was active when the target was collected.
    endpoint: Option<SocketAddr>,
    /// Relay budget observed before looking up direct paths.
    relay_mtu: Option<u16>,
}

/// Reconcile one deletion or the complete accepted inventory without replacing foreign routes.
/// The inventory dump and normal path lookups run unlocked. Only the final exclusive addition
/// and its bookkeeping need to hold the route-state lock.
pub(super) fn repair_accepted_routes(
    link: &ActiveLink,
    state: &Mutex<PeerRouteState>,
    deleted: Option<IpAddr>,
) -> io::Result<()> {
    let missing = if let Some(address) = deleted {
        BTreeSet::from([address])
    } else {
        let addresses: Vec<_> = lock_route_state(state)
            .peers
            .values()
            .flat_map(crate::dataplane::Peer::routed_addresses)
            .collect();
        Device::missing_peer_routes(link, addresses.into_iter().collect())?
    };
    if missing.is_empty() {
        return Ok(());
    }

    let targets: Vec<_> = {
        let accepted = lock_route_state(state);
        accepted
            .peers
            .values()
            .filter(|peer| {
                peer.routed_addresses()
                    .any(|address| missing.contains(&address))
            })
            .map(|peer| RepairTarget {
                key: peer.key,
                addresses: peer.addresses,
                endpoint: peer.endpoint,
                relay_mtu: accepted.overrides.get(&peer.key).copied(),
            })
            .collect()
    };
    let mut first_error = None;
    let mut probe = EndpointProbe::default();
    for target in &targets {
        if let Err(error) = repair_target(link, state, &missing, target, &mut probe) {
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Derive a missing peer's budget without blocking a refresh, then check the latest accepted
/// state while adding its routes. A configuration change can retire the peer or replace its
/// budget during the lookup. The rare case of a newly configured direct endpoint needs a fresh
/// lookup while committing so repair cannot install a budget for the old path.
fn repair_target(
    link: &ActiveLink,
    state: &Mutex<PeerRouteState>,
    missing: &BTreeSet<IpAddr>,
    target: &RepairTarget,
    probe: &mut EndpointProbe,
) -> io::Result<()> {
    let direct_mtu = target
        .relay_mtu
        .is_none()
        .then(|| probe.mesh_mtu(target.endpoint));
    let mut accepted = lock_route_state(state);
    let Some(peer) = accepted.peers.get(&target.key) else {
        return Ok(());
    };
    if peer.addresses != target.addresses {
        return Ok(());
    }
    let mtu = accepted
        .overrides
        .get(&target.key)
        .copied()
        .unwrap_or_else(|| {
            if let Some(mtu) = direct_mtu
                && peer.endpoint == target.endpoint
            {
                return mtu;
            }
            EndpointProbe::default().mesh_mtu(peer.endpoint)
        });
    let mut first_error = None;
    let mut changed = false;
    for address in peer.routed_addresses() {
        if !missing.contains(&address) {
            continue;
        }
        // EEXIST leaves the written budget alone. A real addition or failed write makes the
        // next live refresh recheck this peer's budget, including its authenticated endpoint.
        match Device::repair_peer_route(link, peer, address, mtu, accepted.underlay.as_deref()) {
            Ok(written) => changed |= written,
            Err(error) => {
                tracing::warn!(%address, error = %error, "mesh peer route repair failed");
                changed = true;
                first_error.get_or_insert(error);
            }
        }
    }
    if changed {
        accepted.forget_written_for(target.key);
    }
    first_error.map_or(Ok(()), Err)
}
