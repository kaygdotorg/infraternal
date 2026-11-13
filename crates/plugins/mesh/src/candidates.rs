//! Direct-path candidates: which underlay addresses a node tries for a peer, and in which order
//! (#515, D391, the first slice of D316's path finding).
//!
//! Before this slice the coordinator published one address per node: the source IP it saw on the
//! node's control connection, joined to the node's *local* mesh UDP port. A NAT that changes the
//! port (carrier-grade NAT, a home router behind one, a symmetric NAT) makes every peer aim at a
//! dead port, and two nodes behind one router without hairpin cannot reach each other at all.
//! Three kinds of candidate fix that, without touching the `WireGuard` handshake:
//!
//! - **LAN**: the private address a node's kernel picks for its default route, with its mesh port.
//!   Only a peer the coordinator sees behind the *same* public address gets it, so private
//!   addresses never leave the site they belong to.
//! - **Server-reflexive**: the public address *and port* the server's own mesh device sees the
//!   node's mesh packets come from (`presence.rs` observes it). For an endpoint-independent NAT that
//!   is exactly the mapping every peer must aim at.
//! - **Guess**: the older control-IP-plus-local-port address, kept last. It is still right for a
//!   port-preserving NAT before the server has observed the node, and for older servers.
//!
//! The coordinator puts them in that order ([`order`]); a node that accepts the list
//! ([`crate::dataplane::Peer::candidates`]) walks it with a [`Rotation`] until a packet comes back.
//! Choices, and the alternatives rejected:
//! - LAN addresses come from the default route, not from every interface: an interface list carries
//!   container bridges and VPN addresses, and a peer would aim at its own container bridge.
//! - The walk stops on anything coming back (bytes, a handshake, or the engine roaming to a packet's
//!   source), not on a handshake alone: an established session does not handshake again for two
//!   minutes, so a handshake test would walk away from a working address.
//! - The walk ends after [`ROUNDS`] rounds on the first candidate, so an unreachable peer costs
//!   nothing forever; a new list (the coordinator republishes on any change) starts a new walk.
//! - No ICE engine yet: D316 puts full path finding in its chosen ICE engine. These are the same host
//!   and server-reflexive candidates it would gather, so this slice carries over unchanged.

use std::net::{IpAddr, SocketAddr};

/// The most LAN addresses a node reports: one per address family.
pub const MAX_LAN: usize = 2;

/// Everything the coordinator knows about where one node can be reached.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeCandidates {
    /// The control connection's source IP with the node's own listen port (the pre-#515 address).
    pub guess: Option<SocketAddr>,
    /// The public address and port the server's mesh device last saw this node's packets come from.
    pub reflexive: Option<SocketAddr>,
    /// The node's own private addresses with its listen port, at most [`MAX_LAN`].
    pub lan: Vec<SocketAddr>,
}

impl NodeCandidates {
    /// The public address this node is seen from: the reflexive one when known, else the guess.
    #[must_use]
    pub fn public_ip(&self) -> Option<IpAddr> {
        self.reflexive.or(self.guess).map(|address| address.ip())
    }

    /// The one address an older node gets, which cannot take a list: reflexive first.
    #[must_use]
    pub fn primary(&self) -> Option<SocketAddr> {
        self.reflexive.or(self.guess)
    }
}

/// The addresses `viewer` should try for `peer`, best first, without duplicates.
///
/// LAN addresses come first, and only when both nodes are seen from one public address: a
/// shared router that does not hairpin can only be crossed on the LAN, and the LAN is the
/// shortest path anyway. Then the server-reflexive address, then the guess.
#[must_use]
pub fn order(viewer: &NodeCandidates, peer: &NodeCandidates) -> Vec<SocketAddr> {
    let mut list = Vec::with_capacity(MAX_LAN + 2);
    let shared = viewer.public_ip().is_some() && viewer.public_ip() == peer.public_ip();
    let lan: &[SocketAddr] = if shared { &peer.lan } else { &[] };
    for address in lan.iter().copied().chain(peer.reflexive).chain(peer.guess) {
        if !list.contains(&address) {
            list.push(address);
        }
    }
    list
}

/// Whether `ip` is a private address that only makes sense on a LAN: RFC 1918, the shared
/// carrier range `100.64.0.0/10` (RFC 6598), or an IPv6 unique local address (`fc00::/7`).
#[must_use]
pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private() || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(ip) => (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Keep only LAN addresses that can be sent to another node, at most [`MAX_LAN`].
///
/// The coordinator applies this to what a node reports, so a node cannot make its peers aim at
/// a public host, a loopback or a link-local address in the name of a LAN candidate.
#[must_use]
pub fn valid_lan(reported: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut lan = Vec::new();
    for address in reported {
        if let Ok(address) = crate::policy::discovery::usable_address(*address)
            && is_lan(address.ip())
            && !lan.contains(&address)
            && lan.len() < MAX_LAN
        {
            lan.push(address);
        }
    }
    lan
}

/// This node's LAN candidates: the private source address its kernel picks for the default
/// IPv4 and IPv6 routes, each with the mesh `port`. `exclude` holds the node's own mesh
/// addresses, which are never LAN candidates.
///
/// A UDP socket that is only connected, never written to, asks the kernel for the route's
/// source address; no packet leaves the machine. The destinations are documentation addresses
/// (RFC 5737, RFC 3849), so the answer follows the default route whatever the network is.
#[cfg(feature = "agent")]
#[must_use]
pub fn lan_addresses(port: u16, exclude: &[IpAddr]) -> Vec<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
    let probes = [
        (
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9)),
        ),
        (
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9)),
        ),
    ];
    let found: Vec<SocketAddr> = probes
        .iter()
        .filter_map(|(bind, probe)| {
            let socket = UdpSocket::bind(bind).ok()?;
            socket.connect(probe).ok()?;
            let ip = socket.local_addr().ok()?.ip();
            (!exclude.contains(&ip)).then(|| SocketAddr::new(ip, port))
        })
        .collect();
    valid_lan(&found)
}

/// How long one candidate gets before the next: one `WireGuard` handshake retry interval
/// (`REKEY_TIMEOUT`), so every retry lands on a fresh address.
pub const STEP: std::time::Duration = std::time::Duration::from_secs(5);

/// How many times a walk goes round its list before it settles on the first candidate.
pub const ROUNDS: usize = 3;

/// How long a session lasts without a new handshake: `WireGuard`'s `REJECT_AFTER_TIME`. An idle
/// peer with a persistent keepalive handshakes again about every two minutes, so a handshake older
/// than this means the path carries nothing any more.
pub const SILENT: std::time::Duration = std::time::Duration::from_secs(180);

/// A peer's last handshake time as a walk reads it: `handshake` while it is younger than
/// [`SILENT`] at `unix_now` (both in Unix seconds), else `0`, the same as no handshake at all.
///
/// The engine keeps the time of the last handshake forever, so without this a session that died
/// minutes ago would look exactly like a live one.
#[must_use]
pub const fn live_handshake(handshake: u64, unix_now: u64) -> u64 {
    if handshake != 0 && unix_now.saturating_sub(handshake) < SILENT.as_secs() {
        handshake
    } else {
        0
    }
}

/// What the engine reports for one peer, as far as a walk needs it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// The received-bytes counter. `GotaTun` counts handshakes and data, not keepalives.
    pub received: u64,
    /// The last handshake's time, `0` before the first. Callers read it through
    /// [`live_handshake`], so a session that has gone [`SILENT`] reads as none.
    pub handshake: u64,
    /// Where the engine sends the peer's packets now. A caller that knows the session was not
    /// made on the list's first candidate (the peer was just given a new first address) passes
    /// `None`, so [`Rotation::new`] does not take that session as proof for the new address.
    pub endpoint: Option<SocketAddr>,
}

/// A node's walk through one peer's candidate list.
///
/// It starts on the first candidate. While nothing has come back from the peer, each [`STEP`]
/// moves it to the next one, wrapping, for [`ROUNDS`] rounds; then it returns to the first and
/// stops. Anything coming back stops it: new bytes, a newer handshake, or the engine's address
/// moving away from the walk's (`WireGuard` roams to the source of every authenticated packet,
/// keepalives included). The engine then already sends to a working address.
///
/// A stopped walk is kept, not dropped (J585 F4, #515). The node starts a new one only when the
/// peer's list changes, or when a walk that found the peer later sees its path go silent
/// ([`Self::went_silent`]). So an idle, working peer is never walked off its address, and a
/// republished mesh does not restart every walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    list: Vec<SocketAddr>,
    index: usize,
    since: std::time::Instant,
    start: Seen,
    steps_left: usize,
    settled: bool,
    /// The walk stopped because the peer answered, not because its rounds ran out.
    found: bool,
}

impl Rotation {
    /// Start a walk over `list` at `now`, from what the engine reports for the peer. `None` when
    /// there is nothing to walk (fewer than two candidates).
    ///
    /// A peer that already has a live session on the first candidate needs no walk: the walk
    /// starts stopped, as found. Moving such a peer would send an idle peer's next packets to an
    /// address that may be dead, until its next keepalive roams it back.
    #[must_use]
    pub fn new(list: Vec<SocketAddr>, now: std::time::Instant, seen: Seen) -> Option<Self> {
        let established = seen.handshake != 0 && seen.endpoint == list.first().copied();
        (list.len() >= 2).then(|| Self {
            steps_left: ROUNDS * list.len() - 1,
            list,
            index: 0,
            since: now,
            start: seen,
            settled: established,
            found: established,
        })
    }

    /// The candidate list this walk covers, first candidate first.
    #[must_use]
    pub fn list(&self) -> &[SocketAddr] {
        &self.list
    }

    /// Whether the walk has stopped: a packet came back, or every round is spent.
    #[must_use]
    pub const fn settled(&self) -> bool {
        self.settled
    }

    /// Whether this walk found the peer (or started on a live session) and the peer has since
    /// gone silent: no handshake within [`SILENT`], read through [`live_handshake`]. The node
    /// then walks the same list again. A walk that ran out of rounds never restarts this way, so
    /// an unreachable peer costs nothing until its list changes.
    #[must_use]
    pub const fn went_silent(&self, seen: Seen) -> bool {
        self.settled && self.found && seen.handshake == 0
    }

    /// When the walk next needs a [`Self::tick`], if it has not stopped.
    #[must_use]
    pub fn due(&self) -> Option<std::time::Instant> {
        (!self.settled).then(|| self.since + STEP)
    }

    /// Advance the walk at `now` with what the engine reports for the peer. Returns the address
    /// to install when the node should switch, else `None`.
    pub fn tick(&mut self, now: std::time::Instant, seen: Seen) -> Option<SocketAddr> {
        if self.settled {
            return None;
        }
        // Any change of the byte counter, including a reset after a rebuild, means packets
        // flowed; so does a handshake newer than the one the walk started with. The engine reports
        // a handshake's time as "now minus its age", which can read one second apart for the same
        // handshake, so only a later second counts. A handshake that only aged past `SILENT` reads
        // as 0 and is not news either. An address other than the one the walk installed can only
        // come from an authenticated packet.
        let roamed = seen
            .endpoint
            .is_some_and(|endpoint| endpoint != self.list[self.index]);
        let newer_handshake = seen.handshake > self.start.handshake.saturating_add(1);
        if seen.received != self.start.received || newer_handshake || roamed {
            self.settled = true;
            self.found = true;
            return None;
        }
        if now.saturating_duration_since(self.since) < STEP {
            return None;
        }
        self.since = now;
        if self.steps_left == 0 {
            self.settled = true;
            return (self.index != 0).then(|| {
                self.index = 0;
                self.list[0]
            });
        }
        self.steps_left -= 1;
        self.index = (self.index + 1) % self.list.len();
        Some(self.list[self.index])
    }
}

/// Candidate ordering, LAN filtering and the walk.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::time::{Duration, Instant};

    /// Parse a fixture address.
    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// What the coordinator knows about one fixture node.
    fn node(guess: &str, reflexive: Option<&str>, lan: &[&str]) -> NodeCandidates {
        NodeCandidates {
            guess: Some(at(guess)),
            reflexive: reflexive.map(at),
            lan: lan.iter().map(|address| at(address)).collect(),
        }
    }

    /// Behind a port-translating NAT the reflexive address comes before the stale guess.
    #[test]
    fn reflexive_comes_before_the_guess() {
        let viewer = node("198.51.100.22:10254", Some("198.51.100.22:30254"), &[]);
        let peer = node(
            "198.51.100.21:10254",
            Some("198.51.100.21:30254"),
            &["10.1.0.2:10254"],
        );
        assert_eq!(
            order(&viewer, &peer),
            [at("198.51.100.21:30254"), at("198.51.100.21:10254")]
        );
    }

    /// A peer behind the same public address gets the LAN address first; others never see it.
    #[test]
    fn lan_addresses_go_only_to_peers_behind_the_same_public_address() {
        let peer = node(
            "198.51.100.21:10254",
            Some("198.51.100.21:10255"),
            &["10.9.0.3:10254"],
        );
        let neighbour = node("198.51.100.21:10254", Some("198.51.100.21:10254"), &[]);
        assert_eq!(
            order(&neighbour, &peer),
            [
                at("10.9.0.3:10254"),
                at("198.51.100.21:10255"),
                at("198.51.100.21:10254")
            ]
        );
        let stranger = node("203.0.113.9:10254", None, &[]);
        assert!(
            !order(&stranger, &peer).contains(&at("10.9.0.3:10254")),
            "a private address must not leave its site"
        );
    }

    /// Before any observation the list is the guess alone, exactly the pre-#515 address.
    #[test]
    fn an_unobserved_peer_keeps_the_older_address() {
        let viewer = node("198.51.100.22:10254", None, &[]);
        let peer = node("198.51.100.21:10254", None, &[]);
        assert_eq!(order(&viewer, &peer), [at("198.51.100.21:10254")]);
        assert_eq!(peer.primary(), Some(at("198.51.100.21:10254")));
    }

    /// Reported LAN addresses must be private, sendable and few.
    #[test]
    fn only_private_sendable_addresses_count_as_lan() {
        let reported = [
            at("10.1.0.2:10254"),
            at("198.51.100.4:10254"),
            at("127.0.0.1:10254"),
            at("169.254.1.1:10254"),
            at("100.64.11.2:10254"),
            at("[fd00::2]:10254"),
            at("10.1.0.2:10254"),
        ];
        assert_eq!(
            valid_lan(&reported),
            [at("10.1.0.2:10254"), at("100.64.11.2:10254")]
        );
        assert!(is_lan("172.16.0.1".parse().unwrap()));
        assert!(is_lan("fd12::1".parse().unwrap()));
        assert!(!is_lan("100.128.0.1".parse().unwrap()));
        assert!(!is_lan("2001:db8::1".parse().unwrap()));
    }

    /// J585 F9b (#515): [`MAX_LAN`] promises one LAN address per address family, so a second
    /// IPv4 address must not displace the node's IPv6 one.
    #[test]
    fn lan_addresses_are_one_per_address_family() {
        let reported = [
            at("10.1.0.2:10254"),
            at("192.168.1.2:10254"),
            at("[fd00::2]:10254"),
            at("[fd00::3]:10254"),
        ];
        assert_eq!(
            valid_lan(&reported),
            [at("10.1.0.2:10254"), at("[fd00::2]:10254")]
        );
    }

    /// The walk moves every step, wraps, and settles on the first candidate after its rounds.
    #[test]
    fn a_silent_peer_is_walked_round_then_left_on_the_first_candidate() {
        let start = Instant::now();
        let list = vec![at("10.9.0.3:10254"), at("198.51.100.21:10255")];
        let quiet = |at: SocketAddr| Seen {
            received: 7,
            handshake: 0,
            endpoint: Some(at),
        };
        let mut walk = Rotation::new(list.clone(), start, quiet(list[0])).unwrap();
        assert_eq!(
            walk.tick(start + Duration::from_secs(4), quiet(list[0])),
            None
        );
        let mut installed = Vec::new();
        let mut current = list[0];
        let mut now = start;
        for _ in 0..10 {
            now += STEP;
            if let Some(next) = walk.tick(now, quiet(current)) {
                installed.push(next);
                current = next;
            }
        }
        assert_eq!(
            installed,
            [list[1], list[0], list[1], list[0], list[1], list[0]]
        );
        assert!(walk.settled());
        assert_eq!(walk.due(), None);
    }

    /// Bytes, a handshake or a roamed address coming back each end the walk where it is.
    #[test]
    fn anything_coming_back_stops_the_walk() {
        let start = Instant::now();
        let list = vec![at("10.9.0.3:10254"), at("198.51.100.21:10255")];
        let first = Seen {
            endpoint: Some(list[0]),
            ..Seen::default()
        };
        let second = Seen {
            endpoint: Some(list[1]),
            ..Seen::default()
        };
        for back in [
            Seen {
                received: 92,
                ..second
            },
            Seen {
                handshake: 1_800_000_000,
                ..second
            },
            Seen {
                endpoint: Some(at("198.51.100.21:41000")),
                ..second
            },
        ] {
            let mut walk = Rotation::new(list.clone(), start, first).unwrap();
            assert_eq!(walk.tick(start + STEP, first), Some(list[1]));
            assert_eq!(walk.tick(start + STEP * 2, back), None, "{back:?}");
            assert!(walk.settled());
            assert_eq!(walk.tick(start + STEP * 9, back), None);
        }
    }

    /// J585 F4 (#515): `step_walks` drops a settled walk and `refresh_walks` starts a new one for
    /// every peer missing from `walks`, so each later snapshot apply walks every settled peer again.
    /// An idle established peer (a handshake, no data in the next 5 s; keepalives add no bytes)
    /// sitting on its working first candidate must not be moved to the next one: that sends its
    /// traffic to a dead address until the peer's next keepalive roams it back (up to 25 s).
    #[test]
    fn an_established_idle_peer_is_not_walked_off_its_working_address() {
        let start = Instant::now();
        let list = vec![at("198.51.100.21:30254"), at("198.51.100.21:10254")];
        let established = Seen {
            received: 4_096,
            handshake: 1_800_000_000,
            endpoint: Some(list[0]),
        };
        let walk = Rotation::new(list.clone(), start, established);
        let moved = walk.and_then(|mut walk| walk.tick(start + STEP, established));
        assert_eq!(
            moved, None,
            "an established session on the first candidate was walked to {moved:?}"
        );
    }

    /// A walk that found its peer starts again only once that peer goes silent; one that ran out
    /// of rounds does not, so an unreachable peer is not walked again and again.
    #[test]
    fn only_a_found_peer_that_goes_silent_is_walked_again() {
        let start = Instant::now();
        let list = vec![at("198.51.100.21:30254"), at("198.51.100.21:10254")];
        let live = Seen {
            received: 4_096,
            handshake: 1_800_000_000,
            endpoint: Some(list[0]),
        };
        let found = Rotation::new(list.clone(), start, live).unwrap();
        assert!(found.settled());
        assert!(!found.went_silent(live));
        assert!(found.went_silent(Seen {
            handshake: 0,
            ..live
        }));
        // The engine follows every address the walk installs, and nothing ever comes back.
        let quiet = |address| Seen {
            endpoint: Some(address),
            ..Seen::default()
        };
        let mut exhausted = Rotation::new(list.clone(), start, quiet(list[0])).unwrap();
        let (mut now, mut current) = (start, list[0]);
        while !exhausted.settled() {
            now += STEP;
            if let Some(next) = exhausted.tick(now, quiet(current)) {
                current = next;
            }
        }
        assert!(!exhausted.went_silent(quiet(current)));
    }

    /// A handshake older than [`SILENT`] reads as none; a fresh one reads as itself.
    #[test]
    fn a_stale_handshake_reads_as_none() {
        assert_eq!(live_handshake(0, 1_000), 0);
        assert_eq!(live_handshake(1_000, 1_179), 1_000);
        assert_eq!(live_handshake(1_000, 1_180), 0);
    }

    /// A session made before the peer got a new first address is no proof for that address:
    /// the caller passes no endpoint, and the walk runs.
    #[test]
    fn a_session_on_an_old_address_does_not_stop_a_new_walk() {
        let start = Instant::now();
        let list = vec![at("198.51.100.21:41000"), at("198.51.100.21:10254")];
        let old_session = Seen {
            received: 4_096,
            handshake: 1_800_000_000,
            endpoint: None,
        };
        let mut walk = Rotation::new(list.clone(), start, old_session).unwrap();
        assert!(!walk.settled());
        let on_first = Seen {
            endpoint: Some(list[0]),
            ..old_session
        };
        assert_eq!(walk.tick(start + STEP, on_first), Some(list[1]));
    }

    /// A single candidate needs no walk.
    #[test]
    fn one_candidate_has_nothing_to_walk() {
        let seen = Seen::default();
        assert!(Rotation::new(vec![at("198.51.100.21:10255")], Instant::now(), seen).is_none());
    }
}
