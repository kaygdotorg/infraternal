//! The Mac `GotaTun` worker's command loop, its session-keeping peer updates, and its
//! direct-path candidate walks (#515, J704).
//!
//! Linux and macOS both run `GotaTun`, so the Mac drives the same walk bookkeeping as Linux
//! ([`crate::candidate_walks`]) with the same engine call: after moving a peer's address it sends
//! a handshake there with `Device::rehandshake` (fork `1f646d4`), which sends even over a live
//! session and keeps that session carrying data until the new one is up.
//!
//! That only works if a snapshot leaves the sessions of unchanged peers alone. The Mac used to
//! re-install every peer on each applied snapshot, which dropped every session, sent every peer a
//! fresh handshake (idle ones included), and would restart every walk. [`update_peers`] now
//! updates only the peers that changed and removes the ones that left, as the Linux worker does.
//! A failed update still rolls back with the full re-install (`rollback_device`), which is rare
//! and restores a known state.
//!
//! Rejected: keeping the re-install and relying on it to send the new address its handshake
//! (J586's approach). It drops a working session, which `1f646d4` exists to avoid.

use super::{
    CounterMap, GotaDevice, RuntimeState, WireGuardPeer, WorkerCommand, X25519PublicKey,
    installed_keys, peer_for_policy, peers_for_config,
};
use crate::{
    candidate_walks::{HANDSHAKE_WAIT, Observed, active_peer_key, kept_address, walking_peers},
    dataplane::{Config, Peer, PeerPolicy},
    policy::model::PublicKey,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::mpsc::UnboundedReceiver;

/// The peers the Mac engine installs for `config`: every configured peer, in the order
/// `peers_for_config` converts them. The D384 packet filter enforces each peer's grants at the
/// utun (#265), so the Mac no longer leaves out peers it could not narrow; the walk bookkeeping
/// must see exactly the peers the engine has.
fn installed_peers(config: &Config) -> impl Iterator<Item = &PeerPolicy> {
    config.peers.values()
}

/// Run the Mac worker: apply queued commands one at a time, step candidate walks when one is
/// due, and reap finished handshake tasks. It stops cleanly when told to or when its queue
/// closes.
///
/// A walk reads the counters only after the reply to an apply has been sent, so a snapshot's
/// caller never waits on it.
pub(super) async fn run_worker(
    mut commands: UnboundedReceiver<WorkerCommand>,
    mut state: RuntimeState,
) {
    // A restored configuration may already carry candidates; no session predates it.
    state.refresh_walks(&BTreeMap::new()).await;
    loop {
        let next_walk = state.walks.next_due();
        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else {
                    break;
                };
                match command {
                    WorkerCommand::Apply {
                        config,
                        budgets,
                        reply,
                    } => {
                        let before = state.engine_addresses(&config).await;
                        let result = state.apply(*config, budgets).await;
                        let applied = result.is_ok();
                        let _ = reply.send(result);
                        state.after_apply(applied, &before).await;
                    }
                    WorkerCommand::ReplaceAuthority {
                        config,
                        budgets,
                        reply,
                    } => {
                        let before = state.engine_addresses(&config).await;
                        let result = state.replace_authority(*config, budgets).await;
                        let applied = result.is_ok();
                        let _ = reply.send(result);
                        state.after_apply(applied, &before).await;
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

/// Bring the device's peers in line with `next`, touching only what changed: add or update each
/// installed peer whose settings differ from `applied`, and remove each key `next` no longer
/// installs (`admitted`, the keys of `next`'s installed peers). Peers that did not change keep
/// their session, their counters and the address the engine learned from their traffic. A
/// device with no installed peer yet gets the full re-install instead, which is what starts its
/// connection.
///
/// A changed peer is rewritten whole, endpoint included, the same known limit as on Linux (J555,
/// #483): a NAT rebind the engine learned is replaced by the coordinator's address until the
/// peer's next packet. A walking peer is the exception, as on Linux: while its new list still
/// holds the address the engine sends to, it stays there ([`kept_address`], J699 P3-3), so a
/// change to the tail of its list does not cost a found peer a walk step. The engine's addresses
/// are read for that only when such a peer changed.
/// # Errors
/// Reports invalid host routes or a device that rejected the update; the caller rolls back.
pub(super) async fn update_peers(
    device: &GotaDevice,
    applied: Option<&Config>,
    next: &Config,
    admitted: &BTreeSet<PublicKey>,
) -> io::Result<()> {
    let previous = installed_by_key(applied);
    if previous.is_empty() {
        // A device without peers runs no connection: `GotaTun` opens its sockets and starts its
        // tasks only when built with peers or resumed with them, never when a write adds the
        // first one. With no peer installed there is no session to keep, so the full re-install
        // (which resumes) is the right path here.
        return super::replace_peers(device, peers_for_config(next)?).await;
    }
    let is_changed = |policy: &&PeerPolicy| previous.get(&policy.peer.key) != Some(&&policy.peer);
    let walking_changed = installed_peers(next)
        .filter(is_changed)
        .any(|policy| !policy.peer.candidates.is_empty());
    let engine: BTreeMap<PublicKey, SocketAddr> = if walking_changed {
        device
            .read(async |read| read.peers().await)
            .await
            .into_iter()
            .filter_map(|stats| {
                let key = PublicKey(*stats.peer.public_key.as_bytes());
                stats.peer.endpoint.map(|endpoint| (key, endpoint))
            })
            .collect()
    } else {
        BTreeMap::new()
    };
    let changed = installed_peers(next)
        .filter(is_changed)
        .map(|policy| {
            let mut peers = peer_for_policy(policy)?;
            let key = active_peer_key(&policy.peer);
            if let Some(at) = kept_address(&policy.peer, engine.get(&key).copied(), None)
                && let Some(active) = peers
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

/// The installed peers of `config`, by their current key.
fn installed_by_key(config: Option<&Config>) -> BTreeMap<PublicKey, &Peer> {
    config
        .into_iter()
        .flat_map(installed_peers)
        .map(|policy| (policy.peer.key, &policy.peer))
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
                    .is_some_and(|old| old.endpoint != policy.peer.endpoint)
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
    async fn after_apply(
        &mut self,
        applied: bool,
        before: &BTreeMap<PublicKey, Option<SocketAddr>>,
    ) {
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
    /// gets a real handshake there ([`Self::rehandshake`]); a walk that starts finished sends
    /// nothing, and a working peer that the snapshot left unchanged is never walked again.
    async fn refresh_walks(&mut self, before: &BTreeMap<PublicKey, Option<SocketAddr>>) {
        let Some(config) = self.config.as_ref() else {
            self.walks.clear();
            return;
        };
        let wanted = walking_peers(installed_peers(config));
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
        for walk in started {
            if walk.engine_at != Some(walk.address)
                && self.set_endpoint(walk.key, walk.address).await.is_err()
            {
                // The engine could not be moved; the next applied snapshot starts the walk again.
                self.walks.abandon(walk.key);
                continue;
            }
            self.rehandshake(walk.key);
        }
    }

    /// Where the engine sends each peer's packets before `next` is applied, by device key, for
    /// [`Self::refresh_walks`] (J602 F1). Read only when `next` re-installs a peer that walks;
    /// every other snapshot reads nothing here.
    async fn engine_addresses(&self, next: &Config) -> BTreeMap<PublicKey, Option<SocketAddr>> {
        let walking = |peer: &Peer| !peer.candidates.is_empty();
        if !crate::candidate_walks::reinstalls_a_peer(self.config.as_ref(), next, walking) {
            return BTreeMap::new();
        }
        self.counters()
            .await
            .map(|counters| {
                counters
                    .into_iter()
                    .map(|(key, counters)| (key, counters.endpoint))
                    .collect()
            })
            .unwrap_or_default()
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
        for (key, endpoint) in moves {
            if self.set_endpoint(key, endpoint).await.is_ok() {
                self.rehandshake(key);
            } else {
                // The engine still holds the old address; the walk's next step tries again.
                self.walks.install_failed(key);
            }
        }
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

    /// Send a new handshake initiation to `key`'s current address now, even over a live session,
    /// without waiting for it (#515, J604 on Linux, J704 here).
    ///
    /// `GotaTun` sends the initiation, then waits for the session; that wait runs in a task with a
    /// deadline, so the worker never blocks on a peer. An unanswered initiation is retried by the
    /// engine's own rekey timer; nothing new is scheduled here.
    pub(super) fn rehandshake(&mut self, key: PublicKey) {
        let Some(device) = self.device.as_ref().map(Arc::clone) else {
            return;
        };
        let key = X25519PublicKey::from(key.0);
        self.handshakes.spawn(async move {
            let _ = tokio::time::timeout(HANDSHAKE_WAIT, device.rehandshake(&key)).await;
        });
    }
}
