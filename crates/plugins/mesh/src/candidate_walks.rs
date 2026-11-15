//! The candidate walks a `GotaTun` node runs, one per peer (#515, D391): which peers walk, when a
//! walk starts again, and which address each step moves to. Linux and macOS both run `GotaTun`,
//! and both engine workers drive this one bookkeeping, so the two behave the same (the owner's
//! Mac-parity rule).
//!
//! The module does no I/O. Each engine worker:
//! 1. lists the peers it installed ([`walking_peers`]) after applying a snapshot;
//! 2. asks [`Walks::prepare`] whether anything needs the engine's counters, and reads them only
//!    then, as [`Observed`];
//! 3. installs each address [`Walks::start`] and [`Walks::step`] return, and sends a handshake
//!    there with `GotaTun`'s `rehandshake` (fork `1f646d4`), which sends even over a live session
//!    and keeps that session until the new one is up;
//! 4. reports an address it could not install ([`Walks::abandon`], [`Walks::install_failed`]).
//!
//! The walk itself, one peer's [`Rotation`], lives in [`crate::candidates`].
//!
//! Choices, and the alternatives rejected:
//! - The engine stays with the worker, not behind a trait object here: the two workers own their
//!   device differently (a TUN rebuilt after a fatal error on Linux, a utun with host routes on
//!   macOS), and the walk only needs counters in and addresses out.
//! - No timer runs for a finished walk, and a snapshot that leaves a working peer unchanged starts
//!   nothing for it, so an idle node stays idle (D81) and sends no extra handshake to an idle
//!   peer. A snapshot reads the counters only when a peer is new or changed, or a walk that found
//!   its peer must be checked for silence. Known follow-up (J699 P3-2, D393): once any walk has
//!   found its peer, that check reads every peer's counters on each applied snapshot, an O(peers)
//!   read not yet measured at 1,000 and 4,096 peers; a per-walk "earliest silent deadline" would
//!   skip it until a found walk can have gone silent.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    candidates::{Rotation, Seen},
    dataplane::{Config, Peer, PeerPolicy},
    policy::model::PublicKey,
};

/// What the engine reports for each installed peer, by device key, as a walk reads it
/// ([`observe`]). A peer missing from the map reads as silent: no bytes, no handshake.
pub(crate) type Observed = BTreeMap<PublicKey, Seen>;

/// One walk that has just started running: the peer's device key, the address the walk is on,
/// and where the engine sent that peer's packets when the walk started. The worker moves the
/// engine to `address` when the two differ, then sends a handshake there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Started {
    /// The device key that owns the peer's endpoint ([`active_peer_key`]).
    pub key: PublicKey,
    /// The candidate the walk starts on.
    pub address: SocketAddr,
    /// The engine's address for the peer when the walk started, if it had one.
    pub engine_at: Option<SocketAddr>,
}

/// The identity that currently owns a peer's host routes and endpoint: the previous key while a
/// rotation overlap still routes through it, else the current key. Walks are kept under this key,
/// because it is the device peer whose address a walk moves.
#[must_use]
pub(crate) fn active_peer_key(peer: &Peer) -> PublicKey {
    if peer.previous_active {
        peer.previous_key.unwrap_or(peer.key)
    } else {
        peer.key
    }
}

/// The peers that walk, by device key: of the peers the engine `installed`, those with a first
/// address and a candidate list after it.
///
/// Each engine passes the peers it really installs (Linux: any network access; macOS: the
/// server and peers with full inbound access), so a walk never moves a peer the device lacks.
pub(crate) fn walking_peers<'a>(
    installed: impl IntoIterator<Item = &'a PeerPolicy>,
) -> BTreeMap<PublicKey, Peer> {
    installed
        .into_iter()
        .filter(|policy| policy.peer.endpoint.is_some() && !policy.peer.candidates.is_empty())
        .map(|policy| (active_peer_key(&policy.peer), policy.peer.clone()))
        .collect()
}

/// Whether applying `next` over `applied` re-installs (changes) a peer that `watched` picks: one
/// that walks, or on Linux one on its relay. Only then can a re-install keep the engine's address
/// ([`kept_address`]), so only then does a worker read where the engine sends each peer before
/// the apply (the `before` map of [`Walks::start`], J602 F1).
#[must_use]
pub(crate) fn reinstalls_a_peer(
    applied: Option<&Config>,
    next: &Config,
    watched: impl Fn(&Peer) -> bool,
) -> bool {
    let Some(applied) = applied else {
        return false;
    };
    next.peers.iter().any(|(id, policy)| {
        watched(&policy.peer)
            && applied
                .peers
                .get(id)
                .is_some_and(|previous| previous.peer != policy.peer)
    })
}

/// The address a re-installed peer keeps instead of its new first candidate, if any.
///
/// A worker re-installs a peer whose snapshot changed, and a fresh install aims at the first
/// candidate. Two cases keep where the engine already sends (`engine_at`):
/// - a relayed peer stays on its `relay` (J699 P3-1; Linux relay builds only, `None` elsewhere);
/// - a walking peer stays on an address its new list still holds (J699 P3-3): its walk may have
///   found the peer there, and the new walk starts on the engine's address anyway (J602 F2), so
///   moving away first would cost a working session up to one walk step.
///
/// A peer with a single address, or an engine address the list dropped, takes the snapshot's.
#[must_use]
pub(crate) fn kept_address(
    peer: &Peer,
    engine_at: Option<SocketAddr>,
    relay: Option<SocketAddr>,
) -> Option<SocketAddr> {
    let at = engine_at?;
    let listed =
        !peer.candidates.is_empty() && (peer.endpoint == Some(at) || peer.candidates.contains(&at));
    (relay == Some(at) || listed).then_some(at)
}

/// How long a worker's handshake task waits for the session it asked for; `GotaTun`'s own wait
/// has no deadline. One `WireGuard` handshake attempt is 5 s, after which the peer's timers retry.
pub(crate) const HANDSHAKE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The wall clock in Unix seconds, the unit of the engine's handshake times.
#[must_use]
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Turn one peer's engine counters into what a walk reads at `unix_now`: its received bytes, its
/// last handshake (`0` once older than [`crate::candidates::SILENT`]) and the engine's address.
#[must_use]
pub(crate) const fn observe(
    received: u64,
    handshake_secs: u64,
    endpoint: Option<SocketAddr>,
    unix_now: u64,
) -> Seen {
    Seen {
        received,
        handshake: crate::candidates::live_handshake(handshake_secs, unix_now),
        endpoint,
    }
}

/// Wait until the next walk step is due, or forever when no walk is running. A worker selects on
/// it next to its commands, with the time from [`Walks::next_due`].
pub(crate) async fn walk_due(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
        None => std::future::pending().await,
    }
}

/// Every running or finished walk of one node, by device key, with the peer it was started for:
/// a peer that is re-installed (it changed) starts a new walk.
#[derive(Debug, Default)]
pub(crate) struct Walks {
    walks: BTreeMap<PublicKey, (Peer, Rotation)>,
}

impl Walks {
    /// Drop every walk: the device stopped, or no configuration is applied.
    pub(crate) fn clear(&mut self) {
        self.walks.clear();
    }

    /// The first half of bringing the walks in line with an applied snapshot: drop the walks of
    /// peers that no longer walk, and say whether [`Self::start`] needs the engine's counters.
    ///
    /// It does when a `wanted` peer is new or changed, or when a walk that found its peer must be
    /// checked for silence. Otherwise the snapshot changed nothing a walk cares about, and the
    /// worker reads nothing.
    pub(crate) fn prepare(&mut self, wanted: &BTreeMap<PublicKey, Peer>) -> bool {
        self.walks.retain(|key, _| wanted.contains_key(key));
        let changed = wanted
            .iter()
            .any(|(key, peer)| self.walks.get(key).is_none_or(|(old, _)| old != peer));
        let watching = self
            .walks
            .values()
            .any(|(_, walk)| walk.went_silent(Seen::default()));
        changed || watching
    }

    /// The second half: start a walk for each `wanted` peer that is new or changed, and again for
    /// a peer whose walk once found it and whose path has since gone silent. Returns the walks
    /// that start running; a walk that starts finished needs nothing.
    ///
    /// A peer that is unchanged keeps its walk, finished or not (J585 F4), so an unrelated
    /// snapshot never sends a working peer back through its list. `before` holds where the
    /// engine sent each peer's packets before the apply (empty unless
    /// [`reinstalls_a_peer`]). A re-installed peer's live session proves its first
    /// candidate only if the engine was already there: after a change to the rest of its list,
    /// the session may live on a later candidate (J602 F1). The re-install keeps the engine on
    /// such a candidate while the new list still holds it ([`kept_address`], J699 P3-3).
    pub(crate) fn start(
        &mut self,
        wanted: BTreeMap<PublicKey, Peer>,
        observed: &Observed,
        before: &BTreeMap<PublicKey, Option<SocketAddr>>,
        now: Instant,
    ) -> Vec<Started> {
        let mut started = Vec::new();
        for (key, peer) in wanted {
            let mut seen = observed.get(&key).copied().unwrap_or_default();
            let engine_at = seen.endpoint;
            match self.walks.get(&key) {
                Some((old, walk)) if *old == peer => {
                    if !walk.went_silent(seen) {
                        continue;
                    }
                }
                _ => {
                    // The apply moved the engine here, so its live session was made elsewhere.
                    if before.get(&key) != Some(&engine_at) {
                        seen.endpoint = None;
                    }
                }
            }
            let list = peer
                .endpoint
                .into_iter()
                .chain(peer.candidates.iter().copied());
            match Rotation::new(list.collect(), now, seen) {
                Some(walk) => {
                    if !walk.settled() {
                        started.push(Started {
                            key,
                            address: walk.current(),
                            engine_at,
                        });
                    }
                    self.walks.insert(key, (peer, walk));
                }
                None => {
                    self.walks.remove(&key);
                }
            }
        }
        started
    }

    /// The engine could not be moved to a started walk's address. Drop the walk; the next applied
    /// snapshot starts it again.
    pub(crate) fn abandon(&mut self, key: PublicKey) {
        self.walks.remove(&key);
    }

    /// When the earliest running walk needs its next step; `None` when every walk has stopped.
    #[must_use]
    pub(crate) fn next_due(&self) -> Option<Instant> {
        self.walks.values().filter_map(|(_, walk)| walk.due()).min()
    }

    /// Step every due walk at `now` with what the engine reports, and return the addresses to
    /// install, by device key. The worker installs each and sends a handshake there.
    pub(crate) fn step(
        &mut self,
        now: Instant,
        observed: &Observed,
    ) -> Vec<(PublicKey, SocketAddr)> {
        self.walks
            .iter_mut()
            .filter_map(|(key, (_, walk))| {
                walk.tick(now, observed.get(key).copied().unwrap_or_default())
                    .map(|next| (*key, next))
            })
            .collect()
    }

    /// The address the last [`Self::step`] returned for `key` could not be installed; the engine
    /// still sends to the previous one, and the walk's next step tries again.
    pub(crate) fn install_failed(&mut self, key: PublicKey) {
        if let Some((_, walk)) = self.walks.get_mut(&key) {
            walk.install_failed();
        }
    }
}

/// The shared bookkeeping both engines drive.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{
        dataplane::PeerPolicy,
        policy::{model::Addresses, rules::TrafficPolicy},
    };
    use std::time::Duration;

    /// Parse a fixture address.
    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// One fixture peer with a first address and one more candidate.
    fn walking(key: u8) -> PeerPolicy {
        PeerPolicy {
            peer: Peer {
                key: PublicKey([key; 32]),
                previous_key: None,
                previous_active: false,
                addresses: Addresses {
                    ipv4: "10.254.0.4".parse().unwrap(),
                    ipv6: "fd01::4".parse().unwrap(),
                },
                endpoint: Some(at("198.51.100.4:30254")),
                candidates: vec![at("198.51.100.4:10254")],
            },
            inbound: TrafficPolicy::All,
            outbound: TrafficPolicy::All,
            access_ssh: None,
        }
    }

    /// An idle peer with a live session on its first address starts finished: no address to
    /// install, so no handshake, no timer, and later snapshots that leave it unchanged (and its
    /// session live) start nothing either.
    #[test]
    fn an_idle_established_peer_costs_no_handshake() {
        let policy = walking(4);
        let wanted = walking_peers([&policy]);
        let key = PublicKey([4; 32]);
        let mut walks = Walks::default();
        assert!(walks.prepare(&wanted), "a new peer needs one counter read");
        let observed = Observed::from([(
            key,
            Seen {
                received: 148,
                handshake: 1_000,
                endpoint: policy.peer.endpoint,
            },
        )]);
        let before = BTreeMap::from([(key, policy.peer.endpoint)]);
        let none: Vec<Started> = Vec::new();
        assert_eq!(
            walks.start(wanted.clone(), &observed, &before, Instant::now()),
            none
        );
        assert_eq!(walks.next_due(), None, "no timer for a finished walk");
        // A found walk is checked for silence on every snapshot (J699 P3-2), but a live
        // session starts nothing.
        walks.prepare(&wanted);
        assert_eq!(
            walks.start(wanted, &observed, &before, Instant::now()),
            none
        );
        assert_eq!(walks.next_due(), None);
    }

    /// A peer with no session starts running on its first candidate and steps to the next one
    /// after [`crate::candidates::STEP`].
    #[test]
    fn a_silent_peer_walks_to_its_next_candidate() {
        let policy = walking(4);
        let key = PublicKey([4; 32]);
        let mut walks = Walks::default();
        let wanted = walking_peers([&policy]);
        assert!(walks.prepare(&wanted));
        let now = Instant::now();
        let started = walks.start(wanted, &Observed::new(), &BTreeMap::new(), now);
        assert_eq!(
            started,
            [Started {
                key,
                address: at("198.51.100.4:30254"),
                engine_at: None,
            }]
        );
        let later = now + crate::candidates::STEP + Duration::from_millis(1);
        assert_eq!(
            walks.step(later, &Observed::new()),
            [(key, at("198.51.100.4:10254"))]
        );
    }

    /// A peer without a candidate list, or with no first address, never walks.
    #[test]
    fn only_peers_with_a_list_walk() {
        let mut bare = walking(4);
        bare.peer.candidates.clear();
        let mut unaddressed = walking(5);
        unaddressed.peer.endpoint = None;
        assert!(walking_peers([&bare, &unaddressed]).is_empty());
    }

    /// A peer whose grants allow no packet in either direction never walks, even with a first
    /// address and candidates: the engines don't install it, so a walk step would send
    /// handshakes toward a peer the node must not talk to (J781 finding 3, #515, #483).
    #[test]
    fn a_peer_without_network_access_never_walks() {
        let mut denied = walking(4);
        denied.inbound = TrafficPolicy::None;
        denied.outbound = TrafficPolicy::None;
        let mut no_ports = walking(5);
        no_ports.inbound = TrafficPolicy::Ports(std::collections::BTreeSet::new());
        no_ports.outbound = TrafficPolicy::None;
        let mut one_way = walking(6);
        one_way.inbound = TrafficPolicy::None;
        let wanted = walking_peers([&denied, &no_ports, &one_way]);
        assert_eq!(
            wanted.keys().copied().collect::<Vec<_>>(),
            [PublicKey([6; 32])],
            "only the peer with outbound access walks"
        );
    }

    /// A rotation overlap that still routes through the previous key walks under that key.
    #[test]
    fn a_walk_follows_the_key_that_owns_the_routes() {
        let mut policy = walking(4);
        policy.peer.previous_key = Some(PublicKey([9; 32]));
        policy.peer.previous_active = true;
        assert!(walking_peers([&policy]).contains_key(&PublicKey([9; 32])));
    }
}
