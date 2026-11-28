//! Update peers and drive candidate walks without dropping established sessions.

use super::{
    GotaDevice, HostNet, RuntimeState, WireGuardPeer, X25519PublicKey, installed_keys,
    installed_peers, peer_for_policy, peers_for_config,
};
use crate::{
    candidate_walks::{
        EngineEndpoint, HANDSHAKE_WAIT, Observed, active_peer_key, engine_endpoint, kept_address,
        walking_peers,
    },
    dataplane::{Config, Peer, PeerPolicy},
    peer_stats::CounterMap,
    policy::model::PublicKey,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::SocketAddr,
    sync::Arc,
};

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
pub async fn update_peers<H: HostNet>(
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
        return super::replace_peers(device, peers_for_config(next, H::side_socket())?).await;
    }
    let changed = changed_peers(&previous, next)
        .map(|policy| {
            let mut peers = peer_for_policy(policy, H::side_socket())?;
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
        Some(applied) => installed_keys(&peers_for_config(applied, H::side_socket())?)
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
pub fn changed_peers<'a>(
    previous: &'a BTreeMap<PublicKey, (&'a Peer, &'a Vec<crate::dataplane::ReachableNetwork>)>,
    next: &'a Config,
) -> impl Iterator<Item = &'a PeerPolicy> + 'a {
    installed_peers(next).filter(move |policy| {
        previous.get(&policy.peer.key) != Some(&(&policy.peer, &policy.networks.through))
    })
}

/// The installed peers of `config`, by their current key, with the networks behind each.
#[must_use]
pub fn installed_by_key(
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
#[must_use]
pub fn readdressed(applied: Option<&Config>, next: &Config) -> Vec<PublicKey> {
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

impl<H: HostNet> RuntimeState<H> {
    /// Bring the walks in line with what the device now runs, right after an apply was answered.
    ///
    /// After a successful apply, the walks follow the snapshot ([`Self::refresh_walks`]). After a
    /// failed one, `rollback_device` has re-installed every peer at its first address, so no
    /// walk's position holds any more: they all start again from there.
    pub async fn after_apply(
        &mut self,
        applied: bool,
        before: &BTreeMap<PublicKey, EngineEndpoint>,
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
    /// gets a real handshake there ([`Self::rehandshake_all`]); a walk that starts finished sends
    /// nothing, and a working peer that the snapshot left unchanged is never walked again.
    pub async fn refresh_walks(&mut self, before: &BTreeMap<PublicKey, EngineEndpoint>) {
        let Some(config) = self.config.as_ref() else {
            self.walks.clear();
            return;
        };
        let mut wanted = walking_peers(installed_peers(config));
        // A candidate inside a network routed into the utun would send the tunnel into itself.
        let routed = &self.networks;
        if !routed.is_empty() {
            for peer in wanted.values_mut() {
                peer.candidates.retain(|candidate| {
                    !routed
                        .keys()
                        .any(|network| network.contains(candidate.ip()))
                });
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
    pub async fn engine_addresses(&self, next: &Config) -> BTreeMap<PublicKey, EngineEndpoint> {
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
    pub async fn step_walks(&mut self) {
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
            match self.set_endpoint(key, endpoint).await {
                Ok(()) => installed.push(key),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => self.walks.abandon(key),
                // The engine still holds the old address; the walk's next step tries again.
                Err(_) => self.walks.install_failed(key),
            }
        }
        self.rehandshake_all(installed);
    }

    /// Point the peer whose key owns its host routes at `endpoint`, a walk's next candidate.
    /// Keys, routes and keepalive stay as the configuration says; only where the next packet
    /// goes changes, and the session is kept.
    ///
    /// An address that one of this utun's host routes covers is refused, the same rule the
    /// snapshot's own endpoints pass (`validate_underlay_routes`). Also check the current subnet
    /// routes because a walk may still hold a candidate whose exception has expired.
    /// # Errors
    /// Reports an address inside the mesh, a peer the configuration does not install, or a
    /// device that rejected the update.
    async fn set_endpoint(&self, key: PublicKey, endpoint: SocketAddr) -> io::Result<()> {
        let address = endpoint.ip().to_canonical();
        if self.routes.contains(&address) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self
            .networks
            .keys()
            .any(|network| network.contains(address))
        {
            return Err(io::ErrorKind::AddrInUse.into());
        }
        let policy = self
            .config
            .as_ref()
            .and_then(|config| {
                installed_peers(config).find(|policy| active_peer_key(&policy.peer) == key)
            })
            .ok_or(io::ErrorKind::NotFound)?;
        let mut peers = peer_for_policy(policy, H::side_socket())?;
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
    pub fn rehandshake_all(&mut self, keys: Vec<PublicKey>) {
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
