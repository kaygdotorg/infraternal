//! The Mac `GotaTun` worker's command loop, its session-keeping peer updates, and its
//! direct-path candidate walks (#515, J704).
//!
//! Linux and macOS both run `GotaTun`, so the Mac drives the same walk bookkeeping as Linux
//! ([`crate::candidate_walks`]) with the same engine call: after moving peers' addresses it sends
//! handshakes there with `Device::rehandshake_all`, which sends even over a live
//! session and keeps that session carrying data until the new one is up.
//!
//! That only works if a snapshot leaves the sessions of unchanged peers alone. The Mac used to
//! re-install every peer on each applied snapshot, which dropped every session, sent every peer a
//! fresh handshake (idle ones included), and would restart every walk. [`update_peers`] now
//! updates only the peers that changed and removes the ones that left, as the Linux worker does.
//! A failed update still rolls back with the full re-install (`rollback_device`), which is rare
//! and restores a known state.
//!
//! The Mac route listener is needed only with connected sends enabled. That mode announces an
//! underlay change immediately; when it is off, the listener must not change the default roaming
//! behavior or request extra keepalives.
//!
//! Rejected: keeping the re-install and relying on it to send the new address its handshake
//! (J586's approach). It drops a working session, which `1f646d4` exists to avoid.

use super::{
    CounterMap, GotaDevice, RuntimeState, WireGuardPeer, WorkerCommand, X25519PublicKey,
    installed_keys, installed_peers, peer_for_policy, peers_for_config,
    underlay::UnderlayAnnouncer,
};
use crate::{
    candidate_walks::{
        EngineEndpoint, HANDSHAKE_WAIT, Observed, active_peer_key, engine_endpoint, kept_address,
        walking_peers,
    },
    dataplane::{Config, Peer, PeerPolicy},
    policy::model::PublicKey,
    underlay_announce::{CoalescedSchedule, confirmed_changed},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
    sync::Arc,
};
use tokio::{sync::mpsc::UnboundedReceiver, time::Instant};

/// Run the Mac worker: apply queued commands one at a time, step candidate walks when one is
/// due, and reap finished handshake tasks. It stops cleanly when told to or when its queue
/// closes.
///
/// A walk reads the counters only after the reply to an apply has been sent, so a snapshot's
/// caller never waits on it. Between commands it also hands the device's confirmed endpoints to
/// the admission guard, as the Linux worker does (J736, #483): when the engine reports a change
/// and after a command that changes the peers, at most every 250 ms, and never on a timer, so
/// an idle node costs no wakeup for it (D81, #260 J1253).
///
/// Every walk reads its peers through [`installed_peers`], the same filter
/// [`peers_for_config`] installs with, so a peer without network access is never walked.
///
/// The worker owns one routing socket for its utun. On an underlay change it invalidates cached
/// source addresses, then asks live sessions to announce the new source (D392, #260).
pub(super) async fn run_worker(
    mut commands: UnboundedReceiver<WorkerCommand>,
    mut state: RuntimeState,
) {
    let mut announcer = start_underlay_listener(
        state.utun.as_ref().map(super::MacUtun::name),
        mac_connected_sends_enabled(),
    );
    let mut confirmed_scan = CoalescedSchedule::default();
    confirmed_scan.arm(Instant::now());
    // A restored configuration may carry subnet routes and candidates; no session predates it.
    state.sync_networks().await;
    state.refresh_walks(&BTreeMap::new()).await;
    loop {
        let next_walk = state.walks.next_due();
        let confirmed = state
            .device
            .as_ref()
            .map(|device| device.confirmed_endpoint_changes());
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                // A command that changes the peers or the device changes what the guard
                // should hold, whether or not any endpoint moved.
                if !confirmed_scan.is_armed()
                    && matches!(
                        command,
                        WorkerCommand::Apply { .. }
                            | WorkerCommand::ReplaceAuthority { .. }
                            | WorkerCommand::SetPrivateKey { .. }
                    )
                {
                    confirmed_scan.arm(Instant::now());
                }
                match command {
                    WorkerCommand::Apply {
                        config,
                        budgets,
                        reply,
                    } => {
                        let before = state.engine_addresses(&config).await;
                        let result = state.apply(*config, budgets, &before).await;
                        // Subnet routes follow the snapshot the device accepted (D197 M3), before
                        // the reply, so `mesh routes` right after it is current.
                        if result.is_ok() {
                            state.sync_networks().await;
                        }
                        // The apply writes routes while the listener is outside the select.
                        if let Some(announcer) = announcer.as_mut() {
                            announcer.resync();
                        }
                        let applied = result.is_ok();
                        let _ = reply.send(result);
                        state.after_apply(applied, &before).await;
                    }
                    WorkerCommand::ReplaceAuthority {
                        config,
                        budgets,
                        reply,
                    } => {
                        let result = state.replace_authority(*config, budgets).await;
                        if result.is_ok() {
                            state.sync_networks().await;
                        }
                        if let Some(announcer) = announcer.as_mut() {
                            announcer.resync();
                        }
                        let applied = result.is_ok();
                        let _ = reply.send(result);
                        if applied {
                            state.refresh_walks(&BTreeMap::new()).await;
                        }
                    }
                    WorkerCommand::SetPrivateKey { private_key, reply } => {
                        let result = state.set_private_key(private_key).await;
                        let _ = reply.send(result);
                    }
                    WorkerCommand::Counters(reply) => {
                        let counters = state.counters().await.unwrap_or_default();
                        let _ = reply.send(counters);
                    }
                    WorkerCommand::Stop(reply) => {
                        let result = state.stop().await;
                        let _ = reply.send(result);
                        return;
                    }
                    #[cfg(test)]
                    WorkerCommand::Admission(reply) => {
                        let _ = reply.send(Arc::clone(&state.admission));
                    }
                }
            }
            () = confirmed_changed(confirmed), if !confirmed_scan.is_armed() => {
                confirmed_scan.arm(Instant::now());
            }
            () = confirmed_scan.wait() => {
                confirmed_scan.start();
                state.admit_confirmed_endpoints().await;
                confirmed_scan.finish(Instant::now());
            }
            () = announcement_due(announcer.as_mut()) => {
                if let Some(device) = &state.device
                    && let Some(sessions) = announce_underlay_on_route_event(
                        announcer.as_mut(),
                        || state.udp.underlay_changed(),
                        async || device.request_keepalives().await,
                    ).await
                {
                    tracing::debug!(sessions, "underlay changed; live sessions announce our endpoint");
                }
            }
            () = crate::candidate_walks::walk_due(next_walk), if next_walk.is_some() => {
                state.step_walks().await;
            }
            // Reap finished handshake tasks; their result shows in the peer counters.
            Some(_) = state.handshakes.join_next(), if !state.handshakes.is_empty() => {}
        }
    }
    let _ = state.stop().await;
}

/// Whether connected per-endpoint sends (S) are on in this process: on by default (owner,
/// 2026-11-21, after J1108 qualified them on #260), off with `GOTATUN_BENCH_MAC_CONNECTED=0`.
///
/// This one answer drives both halves of S: the node passes it to the engine's socket factory
/// (`bind_udp` in the node module), and the worker starts the route listener with it, so an
/// engine with connected sockets always has a listener that restales them on a network change. Where the
/// engine cannot prove the shared port safe (macOS 27 shows a program only its own sockets),
/// it keeps `sendto` by itself, and the listener then only announces.
pub(super) fn mac_connected_sends_enabled() -> bool {
    connected_sends_switch_is_on(std::env::var_os("GOTATUN_BENCH_MAC_CONNECTED").as_deref())
}

/// Read the switch without changing the process environment: only `0` (spaces around it
/// ignored, as the engine's own reader does) turns S off; unset or any other value leaves it on.
fn connected_sends_switch_is_on(value: Option<&std::ffi::OsStr>) -> bool {
    value.and_then(std::ffi::OsStr::to_str).map(str::trim) != Some("0")
}

/// Start the route listener only when the Mac connected-send path needs immediate announcements.
///
/// The disabled mode leaves the listener absent, so route events cannot trigger extra
/// keepalives. A missing utun also leaves the listener absent.
fn start_underlay_listener(
    utun: Option<&str>,
    connected_sends_enabled: bool,
) -> Option<UnderlayAnnouncer> {
    if connected_sends_enabled {
        utun.map(UnderlayAnnouncer::start)
    } else {
        None
    }
}

/// Handle a coalesced route event when the connected-send listener is active.
///
/// No listener means the event cannot invalidate cached sources or request keepalives. With a
/// listener, invalidate sources before asking live sessions to announce their new endpoint.
async fn announce_underlay_on_route_event(
    announcer: Option<&mut UnderlayAnnouncer>,
    invalidate_sources: impl FnOnce(),
    request_keepalives: impl AsyncFnOnce() -> usize,
) -> Option<usize> {
    announcer?;
    Some(announce_underlay(invalidate_sources, request_keepalives).await)
}

/// Wait for the listener's next announcement. With no utun, this branch stays pending.
async fn announcement_due(announcer: Option<&mut UnderlayAnnouncer>) {
    match announcer {
        Some(announcer) => announcer.due().await,
        None => std::future::pending().await,
    }
}

/// Invalidate every cached source before walking the live sessions for keepalives (#260).
/// The walk may find no eligible session, and its keepalive sends can only invalidate the
/// endpoints they use. A busy peer must be able to reconnect on its next data send either way.
async fn announce_underlay(
    invalidate_sources: impl FnOnce(),
    request_keepalives: impl AsyncFnOnce() -> usize,
) -> usize {
    invalidate_sources();
    request_keepalives().await
}

/// Bring the device's peers in line with `next`, touching only what changed: add or update each
/// installed peer whose settings differ from `applied`, and remove each key `next` no longer
/// installs (`admitted`, the keys of `next`'s installed peers). Peers that did not change keep
/// their session, their counters and the address the engine learned from their traffic. A
/// device with no installed peer yet gets the full re-install instead, which is what starts its
/// connection.
///
/// A changed peer is rewritten whole, endpoint included. A walking peer stays on an address its
/// new list still holds (J699 P3-3), and any peer stays on an off-list address confirmed by a
/// recent authenticated session (#483). The caller supplies that one-read snapshot when any
/// installed peer changed.
/// # Errors
/// Reports invalid host routes or a device that rejected the update; the caller rolls back.
pub(super) async fn update_peers(
    device: &GotaDevice,
    applied: Option<&Config>,
    next: &Config,
    admitted: &BTreeSet<PublicKey>,
    before: &BTreeMap<PublicKey, EngineEndpoint>,
) -> io::Result<()> {
    let previous = installed_by_key(applied);
    if previous.is_empty() {
        // A device without peers runs no connection: `GotaTun` opens its sockets and starts its
        // tasks only when built with peers or resumed with them, never when a write adds the
        // first one. With no peer installed there is no session to keep, so the full re-install
        // (which resumes) is the right path here.
        return super::replace_peers(device, peers_for_config(next)?).await;
    }
    let changed = changed_peers(&previous, next)
        .map(|policy| {
            let mut peers = peer_for_policy(policy)?;
            let key = active_peer_key(&policy.peer);
            if let Some(at) = kept_address(
                &policy.peer,
                before.get(&key).copied().unwrap_or_default(),
                None,
            ) && let Some(active) = peers
                .iter_mut()
                .find(|peer| peer.public_key.as_bytes() == &key.0)
            {
                active.endpoint = Some(at);
            }
            Ok(peers)
        })
        .collect::<io::Result<Vec<_>>>()?;
    let changed: Vec<WireGuardPeer> = changed.into_iter().flatten().collect();
    let retired: Vec<X25519PublicKey> = match applied {
        Some(applied) => installed_keys(&peers_for_config(applied)?)
            .difference(admitted)
            .map(|key| X25519PublicKey::from(key.0))
            .collect(),
        None => Vec::new(),
    };
    if changed.is_empty() && retired.is_empty() {
        return Ok(());
    }
    device
        .write(async |device| {
            device.add_or_update_peers(changed).await;
            for key in &retired {
                device.remove_peer(key).await;
            }
        })
        .await
        .map_err(|_| io::Error::other("WireGuard peers could not be updated."))
}

/// The installed peers of `next` that the device must rewrite: new ones, and those whose peer
/// settings or networks differ from `previous` ([`installed_by_key`] of the applied snapshot).
///
/// The networks behind a router peer are its allowed IPs too (D197 M3): a snapshot that changes
/// only them must rewrite the peer, or the device keeps sending the old networks to it and
/// accepting their replies from it.
pub(super) fn changed_peers<'a>(
    previous: &'a BTreeMap<PublicKey, (&'a Peer, &'a Vec<crate::dataplane::ReachableNetwork>)>,
    next: &'a Config,
) -> impl Iterator<Item = &'a PeerPolicy> + 'a {
    installed_peers(next).filter(move |policy| {
        previous.get(&policy.peer.key) != Some(&(&policy.peer, &policy.networks.through))
    })
}

/// The installed peers of `config`, by their current key, with the networks behind each.
pub(super) fn installed_by_key(
    config: Option<&Config>,
) -> BTreeMap<PublicKey, (&Peer, &Vec<crate::dataplane::ReachableNetwork>)> {
    config
        .into_iter()
        .flat_map(installed_peers)
        .map(|policy| (policy.peer.key, (&policy.peer, &policy.networks.through)))
        .collect()
}

/// The peers that stay installed with no candidate list but get a new first address, by device
/// key. Each gets a handshake at its new address right after the apply, as on Linux: an idle
/// peer would otherwise send nothing there until its next keepalive, up to 25 s later, and
/// behind a filtering NAT that first packet is what lets the peer's replies in. A peer with
/// candidates gets that handshake when its walk starts instead.
pub(super) fn readdressed(applied: Option<&Config>, next: &Config) -> Vec<PublicKey> {
    let previous = installed_by_key(applied);
    installed_peers(next)
        .filter(|policy| {
            policy.peer.endpoint.is_some()
                && policy.peer.candidates.is_empty()
                && previous
                    .get(&policy.peer.key)
                    .is_some_and(|(old, _)| old.endpoint != policy.peer.endpoint)
        })
        .map(|policy| active_peer_key(&policy.peer))
        .collect()
}

/// What the walks need from the Mac engine's counters.
fn observed(counters: &CounterMap) -> Observed {
    let unix = crate::candidate_walks::unix_now();
    counters
        .iter()
        .map(|(key, stats)| {
            let seen = crate::candidate_walks::observe(
                stats.received_bytes,
                stats.handshake_secs,
                stats.endpoint,
                unix,
            );
            (*key, seen)
        })
        .collect()
}

impl RuntimeState {
    /// Bring the walks in line with what the device now runs, right after an apply was answered.
    ///
    /// After a successful apply, the walks follow the snapshot ([`Self::refresh_walks`]). After a
    /// failed one, `rollback_device` has re-installed every peer at its first address, so no
    /// walk's position holds any more: they all start again from there.
    async fn after_apply(&mut self, applied: bool, before: &BTreeMap<PublicKey, EngineEndpoint>) {
        if applied {
            self.refresh_walks(before).await;
        } else {
            self.walks.clear();
            self.refresh_walks(&BTreeMap::new()).await;
        }
    }

    /// Bring the candidate walks in line with the applied configuration: the shared rules of
    /// [`crate::candidate_walks::Walks::start`], with this device's counters and addresses.
    ///
    /// Each walk that starts running is moved to its address if the engine is elsewhere, then
    /// gets a real handshake there ([`Self::rehandshake_all`]); a walk that starts finished sends
    /// nothing, and a working peer that the snapshot left unchanged is never walked again.
    async fn refresh_walks(&mut self, before: &BTreeMap<PublicKey, EngineEndpoint>) {
        let Some(config) = self.config.as_ref() else {
            self.walks.clear();
            return;
        };
        let mut wanted = walking_peers(installed_peers(config));
        // A candidate inside a network routed into the utun would send the tunnel into itself.
        let routed = self.installed_networks();
        if !routed.is_empty() {
            for peer in wanted.values_mut() {
                peer.candidates =
                    crate::macos_subnet_routes::reachable_candidates(&peer.candidates, &routed);
            }
            wanted.retain(|_, peer| !peer.candidates.is_empty());
        }
        if !self.walks.prepare(&wanted) {
            return;
        }
        let Ok(counters) = self.counters().await else {
            return;
        };
        let started = self.walks.start(
            wanted,
            &observed(&counters),
            before,
            std::time::Instant::now(),
        );
        let mut moved = Vec::with_capacity(started.len());
        for walk in started {
            if walk.engine_at != Some(walk.address)
                && self.set_endpoint(walk.key, walk.address).await.is_err()
            {
                // The engine could not be moved; the next applied snapshot starts the walk again.
                self.walks.abandon(walk.key);
                continue;
            }
            moved.push(walk.key);
        }
        self.rehandshake_all(moved);
    }

    /// Where the engine sends each peer's packets before `next` is applied, by device key, for
    /// [`Self::refresh_walks`] (J602 F1). Read when `next` re-installs any peer (#483, J1025);
    /// every other snapshot reads nothing here.
    async fn engine_addresses(&self, next: &Config) -> BTreeMap<PublicKey, EngineEndpoint> {
        if !crate::candidate_walks::engine_read_needed(self.config.as_ref(), next) {
            return BTreeMap::new();
        }
        let Some(device) = self.device.as_ref() else {
            return BTreeMap::new();
        };
        device
            .read(async |read| read.peers().await)
            .await
            .into_iter()
            .filter(|peer| !peer.peer.allowed_ips.is_empty())
            .map(|peer| {
                let key = PublicKey(*peer.peer.public_key.as_bytes());
                let endpoint = engine_endpoint(
                    peer.peer.endpoint,
                    peer.stats.confirmed_endpoint,
                    peer.stats.last_handshake,
                );
                (key, endpoint)
            })
            .collect()
    }

    /// Step every due walk with the device's counters and install the addresses they move to,
    /// each followed by a handshake there.
    async fn step_walks(&mut self) {
        if self.device.is_none() {
            return;
        }
        let Ok(counters) = self.counters().await else {
            return;
        };
        let moves = self
            .walks
            .step(std::time::Instant::now(), &observed(&counters));
        let mut installed = Vec::with_capacity(moves.len());
        for (key, endpoint) in moves {
            if self.set_endpoint(key, endpoint).await.is_ok() {
                installed.push(key);
            } else {
                // The engine still holds the old address; the walk's next step tries again.
                self.walks.install_failed(key);
            }
        }
        self.rehandshake_all(installed);
    }

    /// Point the peer whose key owns its host routes at `endpoint`, a walk's next candidate.
    /// Keys, routes and keepalive stay as the configuration says; only where the next packet
    /// goes changes, and the session is kept.
    ///
    /// An address that one of this utun's host routes covers is refused, the same rule the
    /// snapshot's own endpoints pass (`validate_underlay_routes`): the peer's packets would loop
    /// back into the tunnel.
    /// # Errors
    /// Reports an address inside the mesh, a peer the configuration does not install, or a
    /// device that rejected the update.
    async fn set_endpoint(&self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        if self.routes.contains(&endpoint.ip()) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let policy = self
            .config
            .as_ref()
            .and_then(|config| {
                installed_peers(config).find(|policy| active_peer_key(&policy.peer) == key)
            })
            .ok_or(io::ErrorKind::NotFound)?;
        let mut peers = peer_for_policy(policy)?;
        let active = peers
            .iter_mut()
            .find(|peer| peer.public_key.as_bytes() == &key.0)
            .ok_or(io::ErrorKind::NotFound)?;
        active.endpoint = Some(endpoint);
        self.device
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?
            .write(async |device| device.add_or_update_peers(peers).await)
            .await
            .map_err(|_| io::Error::other("WireGuard peer endpoint could not be installed."))
    }

    /// Send a new handshake initiation to each of `keys` at its current address now, even over a
    /// live session, without waiting for any answer (#515, J604 on Linux, J704 here; J1253).
    ///
    /// One task with a deadline sends them all, so the worker never blocks on the sends. An
    /// unanswered initiation is retried by the engine's own rekey timer; nothing new is
    /// scheduled here.
    pub(super) fn rehandshake_all(&mut self, keys: Vec<PublicKey>) {
        if keys.is_empty() {
            return;
        }
        let Some(device) = self.device.as_ref().map(Arc::clone) else {
            return;
        };
        let keys: Vec<_> = keys
            .into_iter()
            .map(|key| X25519PublicKey::from(key.0))
            .collect();
        self.handshakes.spawn(async move {
            let _ = tokio::time::timeout(HANDSHAKE_WAIT, device.rehandshake_all(&keys)).await;
        });
    }
}

#[cfg(test)]
mod tests {
    //! Order of route-change recovery, independent of sockets or eligible `WireGuard` sessions.

    use super::{
        announce_underlay, announce_underlay_on_route_event, connected_sends_switch_is_on,
        mac_connected_sends_enabled, start_underlay_listener,
    };
    use std::{
        cell::Cell,
        ffi::OsStr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    /// The first operation in the keepalive walk must see explicit invalidation, even if the
    /// walk finds no live sessions and sends nothing that might mark an endpoint stale.
    #[tokio::test]
    async fn invalidates_sources_before_walking_live_sessions() {
        let invalidated = Cell::new(false);
        let sessions = announce_underlay(
            || invalidated.set(true),
            async || {
                assert!(
                    invalidated.get(),
                    "live-session walk ran before invalidation"
                );
                0
            },
        )
        .await;
        assert_eq!(sessions, 0);
    }

    /// S is on by default and `0` is the kill switch (J1108). With S on the listener announces
    /// live sessions on route events; with it off it stays quiet.
    #[tokio::test]
    async fn connected_sends_gates_the_route_listener_and_keepalives() {
        assert!(connected_sends_switch_is_on(None), "on by default");
        assert!(connected_sends_switch_is_on(Some(OsStr::new("1"))));
        assert!(!connected_sends_switch_is_on(Some(OsStr::new("0"))));
        assert!(!connected_sends_switch_is_on(Some(OsStr::new(" 0 "))));

        let enabled = mac_connected_sends_enabled();
        let mut listener = start_underlay_listener(Some("lo0"), enabled);
        let listening = listener
            .as_ref()
            .is_some_and(super::super::underlay::UnderlayAnnouncer::is_listening);
        let invalidations = AtomicUsize::new(0);
        let requests = AtomicUsize::new(0);
        let result = announce_underlay_on_route_event(
            listener.as_mut(),
            || {
                invalidations.fetch_add(1, Ordering::SeqCst);
            },
            async || {
                requests.fetch_add(1, Ordering::SeqCst);
                1
            },
        )
        .await;

        let invalidation_count = invalidations.load(Ordering::SeqCst);
        let request_count = requests.load(Ordering::SeqCst);
        if enabled {
            assert!(
                listening && result == Some(1) && invalidation_count == 1 && request_count == 1,
                "S on must start a listener and announce a route event: \
                 listening={listening}, result={result:?}, \
                 invalidations={invalidation_count}, requests={request_count}",
            );
        } else {
            assert!(
                !listening && result.is_none() && invalidation_count == 0 && request_count == 0,
                "S off must not start a listener or handle a route event: \
                 listening={listening}, result={result:?}, \
                 invalidations={invalidation_count}, requests={request_count}",
            );
        }
    }
}
