//! The mesh node's route-repair worker (#483, #489).
//!
//! While a node is up, one worker thread listens for route notifications through the node's
//! [`RouteMonitor`](crate::wireguard::RouteMonitor). It re-adds a deleted peer route at once,
//! runs a full inventory check every [`ROUTE_RECHECK_INTERVAL`] and after lost notifications,
//! and publishes the proven link and the underlay watch that live-endpoint refreshes use.
//!
//! It lives in its own file only to keep `node.rs` under the repository's size limit; it is part
//! of the node module and uses its route state directly.

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
    /// # Errors
    /// Returns ownership, listener, cancellation-stream, or thread creation errors.
    pub(super) fn start(state: Arc<Mutex<PeerRouteState>>) -> io::Result<Self> {
        let link = Device::active_link()?.ok_or(io::ErrorKind::NotConnected)?;
        let underlay = Arc::new(crate::wireguard::UnderlayWatch::default());
        let monitor = Some(Device::route_monitor(&link, Arc::clone(&underlay))?);
        Self::start_for_link(state, link, monitor, underlay)
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
                        Ok(crate::wireguard::RouteWake::Deleted(address)) => Some(address),
                        Ok(crate::wireguard::RouteWake::Cancelled) => break,
                        Ok(crate::wireguard::RouteWake::Reconcile) => None,
                        Err(error) => {
                            tracing::warn!(error = %error, "mesh route notifications unavailable; periodic recovery remains active");
                            // A broken listener cannot spin or permanently disable reconciliation.
                            monitor = None;
                            worker_underlay.set_watched(false);
                            continue;
                        }
                    };
                    // Keep membership and relay budgets stable through the kernel writes.
                    let mut route_state = lock_route_state(&state);
                    if let Err(error) = repair_accepted_routes(&link, &mut route_state, address) {
                        tracing::warn!(error = %error, "mesh route repair skipped or failed; retrying on the next inventory check");
                    }
                    #[cfg(test)]
                    ROUTE_REPAIR_PASSES.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    if address.is_none() {
                        // Path-MTU exceptions the kernel caches from ICMP are never announced;
                        // the next refresh after each periodic check re-derives every budget, so
                        // they are picked up within one interval (#489 J552 P2-2).
                        worker_underlay.changed();
                        deadline = std::time::Instant::now() + ROUTE_RECHECK_INTERVAL;
                        if monitor.is_none() {
                            monitor = Device::route_monitor(
                                &link,
                                Arc::clone(&worker_underlay),
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
            return Ok(crate::wireguard::RouteWake::Reconcile);
        }
        let mut descriptors = [PollFd::new(cancel, PollFlags::POLLIN)];
        match poll(
            &mut descriptors,
            PollTimeout::try_from(remaining).map_err(io::Error::other)?,
        ) {
            Ok(0) => return Ok(crate::wireguard::RouteWake::Reconcile),
            Ok(_) => return Ok(crate::wireguard::RouteWake::Cancelled),
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

/// Reconcile one deletion or the complete accepted inventory without replacing foreign routes.
/// The caller holds the route-state lock; a full check dumps once and adds only missing routes.
pub(super) fn repair_accepted_routes(
    link: &crate::wireguard::ActiveLink,
    state: &mut PeerRouteState,
    deleted: Option<IpAddr>,
) -> io::Result<()> {
    Device::verify_repair_link(link)?;
    let missing = if let Some(address) = deleted {
        BTreeSet::from([address])
    } else {
        let expected = state
            .peers
            .values()
            .flat_map(|peer| {
                [
                    IpAddr::V4(peer.addresses.ipv4),
                    IpAddr::V6(peer.addresses.ipv6),
                ]
            })
            .collect();
        Device::missing_peer_routes(link, &expected)?
    };
    let mut first_error = None;
    let mut repaired = BTreeSet::new();
    // Budgets are derived only for peers with a missing route, through one probe for the whole
    // pass. Deriving one for every installed peer cost a socket and two route-netlink requests
    // per peer on every inventory check, under the route-state lock, even with nothing missing:
    // 37-107 s at 4,096 peers on a starved worker thread (#483 J780).
    let mut probe = crate::mesh_mtu::EndpointProbe::default();
    for peer in state.peers.values() {
        let addresses = [
            IpAddr::V4(peer.addresses.ipv4),
            IpAddr::V6(peer.addresses.ipv6),
        ];
        if !addresses.iter().any(|address| missing.contains(address)) {
            continue;
        }
        let mtu = state
            .overrides
            .get(&peer.key)
            .copied()
            .unwrap_or_else(|| probe.mesh_mtu(peer.endpoint));
        for address in addresses {
            if !missing.contains(&address) {
                continue;
            }
            // A re-added route has the configured budget, and a failed add leaves the route
            // unknown: the next live refresh rewrites either. A route that turned out to be
            // there already (`Ok(false)`) still has the budget we wrote, so it is left alone:
            // forgetting it made one inventory check rewrite every peer (#483 J780).
            match Device::repair_peer_route(link, peer, address, mtu) {
                Ok(false) => {}
                Ok(true) => {
                    repaired.insert(peer.key);
                }
                Err(error) => {
                    tracing::warn!(%address, error = %error, "mesh peer route repair failed");
                    repaired.insert(peer.key);
                    first_error.get_or_insert(error);
                }
            }
        }
    }
    for key in &repaired {
        state.forget_written_for(*key);
    }
    first_error.map_or(Ok(()), Err)
}
