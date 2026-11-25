//! Real-Mac proofs that the macOS node keeps idle sessions across snapshots, sends a handshake to
//! a peer's new address at once, and walks a dead first candidate to a live one (#515, J704).
//!
//! Each test runs a real utun node against a real `GotaTun` echo peer on loopback
//! ([`super::authority_mtu::mtu_echo_peer`]), so it needs root and the Mac lock:
//! `sudo <test binary> --ignored --test-threads=1 macos_node::tests::walks`.

use super::{
    AUTHORITY_EPOCH_A, Duration, Instant, Ipv4Addr, Node, NodeId, PublicKey, SocketAddr,
    TestDirectory, chunks_with_epoch, config, test_directory, write_key,
};
use crate::{
    dataplane::{Config, Peer, PeerPolicy},
    policy::{model::Addresses, rules::TrafficPolicy},
};
use std::net::UdpSocket;

/// The echo application's UDP port inside the encrypted tunnel.
const ECHO_PORT: u16 = 4287;

/// A running node with one echo peer, torn down in order when dropped.
struct Fixture {
    node: Node,
    config: Config,
    peer_key: PublicKey,
    live: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    remote: Option<std::thread::JoinHandle<()>>,
    /// Dropped last: the node's state directory.
    _directory: TestDirectory,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.node.down();
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(remote) = self.remote.take() {
            let _ = remote.join();
        }
    }
}

impl Fixture {
    /// Start a node with mesh address `10.253.<subnet>.1` and an echo peer at `.4`, without
    /// installing any snapshot yet.
    fn start(subnet: u8) -> Self {
        let directory = test_directory();
        write_key(&directory);
        let mut node = Node::restore(&directory.0, None).expect("restore isolated node");
        let identity = node.up().expect("start isolated node");
        let mut config = config();
        config.local_key = Some(identity.public_key);
        config.addresses.ipv4 = Ipv4Addr::new(10, 253, subnet, 1);
        config.addresses.ipv6 = format!("fd53:{subnet}::1").parse().expect("local IPv6");
        #[cfg(feature = "mesh-dns")]
        {
            config.dns_suffix = "j704.invalid".to_owned();
        }
        let peer = &mut config.peers.get_mut(&NodeId(4)).expect("peer").peer;
        peer.addresses = Addresses {
            ipv4: Ipv4Addr::new(10, 253, subnet, 4),
            ipv6: format!("fd53:{subnet}::4").parse().expect("peer IPv6"),
        };
        let (peer_key, live, stop, remote) = super::authority_mtu::mtu_echo_peer(
            identity.public_key,
            config.addresses.ipv4,
            config.peers[&NodeId(4)].peer.addresses.ipv4,
        );
        config.peers.get_mut(&NodeId(4)).expect("peer").peer.key = peer_key;
        Self {
            node,
            config,
            peer_key,
            live,
            stop: Some(stop),
            remote: Some(remote),
            _directory: directory,
        }
    }

    /// Install the fixture's current configuration as a complete snapshot at `version`.
    fn install(&mut self, version: u64) {
        self.config.version = version;
        for chunk in chunks_with_epoch(None, &self.config, AUTHORITY_EPOCH_A) {
            self.node.chunk(chunk).expect("install snapshot");
        }
    }

    /// Point the echo peer at `endpoint`, with `candidates` after it.
    fn address(&mut self, endpoint: SocketAddr, candidates: Vec<SocketAddr>) {
        let peer = &mut self.config.peers.get_mut(&NodeId(4)).expect("peer").peer;
        peer.endpoint = Some(endpoint);
        peer.candidates = candidates;
    }

    /// Add a second, unreachable peer: a snapshot change that has nothing to do with the echo
    /// peer.
    fn add_unrelated_peer(&mut self) {
        let subnet = self.config.addresses.ipv4.octets()[2];
        self.config.peers.insert(
            NodeId(5),
            PeerPolicy {
                peer: Peer {
                    key: PublicKey([5; 32]),
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: Ipv4Addr::new(10, 253, subnet, 5),
                        ipv6: format!("fd53:{subnet}::5").parse().expect("IPv6"),
                    },
                    endpoint: Some("192.0.2.5:51820".parse().expect("endpoint")),
                    candidates: Vec::new(),
                    ipv4_only: false,
                    side_port: false,
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
                access_ssh: None,
                networks: crate::dataplane::PeerNetworks::default(),
            },
        );
    }

    /// Send one datagram to the echo application through the tunnel and wait up to `wait` for
    /// it to come back.
    fn echo(&self, wait: Duration) -> bool {
        let peer = self.config.peers[&NodeId(4)].peer.addresses.ipv4;
        let Ok(socket) = UdpSocket::bind((self.config.addresses.ipv4, 0)) else {
            return false;
        };
        let _ = socket.set_read_timeout(Some(wait));
        if socket.connect((peer, ECHO_PORT)).is_err() || socket.send(b"j704").is_err() {
            return false;
        }
        let mut reply = [0_u8; 8];
        socket
            .recv(&mut reply)
            .is_ok_and(|length| &reply[..length] == b"j704")
    }

    /// Echo until one comes back or `limit` passes; the time the first one took.
    fn first_echo(&self, limit: Duration) -> Option<Duration> {
        let started = Instant::now();
        while started.elapsed() < limit {
            if self.echo(Duration::from_millis(500)) {
                return Some(started.elapsed());
            }
        }
        None
    }

    /// The echo peer's handshake time (Unix seconds), received bytes and engine address.
    fn counters(&self) -> (u64, u64, Option<SocketAddr>) {
        let counters = self.node.counters().expect("counters");
        let counters = counters.get(&self.peer_key).expect("echo peer installed");
        (
            counters.handshake_secs,
            counters.received_bytes,
            counters.endpoint,
        )
    }
}

/// A snapshot that changes another peer leaves an established, idle peer alone: same session
/// (no new handshake), counters not reset. Before J704 every snapshot re-installed every Mac
/// peer, which dropped the session and sent each peer, idle or not, a fresh handshake.
#[test]
#[ignore = "Run on the macOS VM with root privileges under the Mac lock."]
fn an_unrelated_snapshot_keeps_an_idle_peers_session() {
    let mut fixture = Fixture::start(71);
    let live = fixture.live;
    fixture.address(live, Vec::new());
    fixture.install(3);
    assert!(
        fixture.first_echo(Duration::from_secs(10)).is_some(),
        "peer reachable"
    );
    let (handshake, received, _) = fixture.counters();
    assert_ne!(handshake, 0, "the echo established a session");
    // sleep: a new handshake must read at least two seconds later to count as new.
    std::thread::sleep(Duration::from_secs(3));
    fixture.add_unrelated_peer();
    fixture.install(4);
    // sleep: give a dropped session's re-install time to send its handshake and complete.
    std::thread::sleep(Duration::from_secs(2));
    let (after, received_after, _) = fixture.counters();
    eprintln!(
        "J704_IDLE handshake_before={handshake} handshake_after={after} \
         received_before={received} received_after={received_after}"
    );
    assert!(
        !crate::candidates::newer_handshake(after, handshake) && after != 0,
        "the idle peer got a new handshake: {handshake} -> {after}"
    );
    assert!(
        received_after >= received,
        "the idle peer's session was dropped: received {received} -> {received_after}"
    );
    assert!(fixture.echo(Duration::from_secs(2)), "still reachable");
}

/// An established peer republished at a new address gets a handshake there at once, not at its
/// next keepalive up to 25 s later (J587's rebind case on Linux, `Device::rehandshake`).
#[test]
#[ignore = "Run on the macOS VM with root privileges under the Mac lock."]
fn a_readdressed_established_peer_handshakes_at_once() {
    let mut fixture = Fixture::start(72);
    let live = fixture.live;
    fixture.address(live, Vec::new());
    fixture.install(3);
    assert!(
        fixture.first_echo(Duration::from_secs(10)).is_some(),
        "peer reachable"
    );
    let recorder = UdpSocket::bind("127.0.0.1:0").expect("recorder");
    recorder
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let moved = recorder.local_addr().expect("recorder address");
    fixture.address(moved, Vec::new());
    let started = Instant::now();
    fixture.install(4);
    let mut packet = [0_u8; 256];
    let first = loop {
        match recorder.recv(&mut packet) {
            // Message type 1 is a handshake initiation.
            Ok(length) if length > 0 && packet[0] == 1 => break Some(started.elapsed()),
            Ok(_) => {}
            Err(_) => break None,
        }
    };
    eprintln!("J704_READDRESS first_initiation={first:?}");
    assert!(
        first.is_some_and(|first| first < Duration::from_secs(2)),
        "no handshake at the new address within 2 s: {first:?}"
    );
}

/// A changed authority snapshot rebuilds peers and restarts the walks it still authorizes.
#[test]
#[ignore = "Run on the macOS VM with root privileges under the Mac lock."]
fn changed_authority_rebuilds_peers_and_restarts_candidate_walks() {
    use super::super::J472_REBUILDS;
    use std::sync::atomic::Ordering;

    let mut fixture = Fixture::start(75);
    let dead = UdpSocket::bind("127.0.0.1:0").expect("hold an unanswered address");
    fixture.address(dead.local_addr().unwrap(), vec![fixture.live]);
    fixture.install(3);
    assert!(fixture.first_echo(Duration::from_secs(10)).is_some());

    let before = J472_REBUILDS.load(Ordering::SeqCst);
    fixture.add_unrelated_peer();
    fixture.config.authority_epoch = Some(super::AUTHORITY_EPOCH_B.to_owned());
    fixture
        .node
        .worker
        .as_ref()
        .expect("running worker")
        .replace_authority(fixture.config.clone())
        .expect("replace authority");
    assert_eq!(J472_REBUILDS.load(Ordering::SeqCst), before + 1);
    assert!(fixture.first_echo(Duration::from_secs(10)).is_some());
}

/// A peer whose first candidate is dead is walked to its live second candidate within about one
/// walk step, and a later unrelated snapshot neither restarts the finished walk nor sends that
/// peer another handshake.
#[test]
#[ignore = "Run on the macOS VM with root privileges under the Mac lock."]
fn a_dead_first_candidate_is_walked_to_a_live_one() {
    let mut fixture = Fixture::start(73);
    // A bound socket that never answers: the first candidate.
    let dead = UdpSocket::bind("127.0.0.1:0").expect("dead candidate");
    let dead_address = dead.local_addr().expect("dead address");
    let live = fixture.live;
    fixture.address(dead_address, vec![live]);
    fixture.install(3);
    let first = fixture.first_echo(Duration::from_secs(20));
    eprintln!("J704_WALK first_echo={first:?}");
    let limit = crate::candidates::STEP * 2;
    assert!(
        first.is_some_and(|first| first < limit),
        "the walk did not reach the live candidate within {limit:?}: {first:?}"
    );
    let (handshake, _, endpoint) = fixture.counters();
    assert_eq!(
        endpoint,
        Some(live),
        "the engine sends to the live candidate"
    );
    // sleep: a new handshake must read at least two seconds later to count as new.
    std::thread::sleep(Duration::from_secs(3));
    fixture.add_unrelated_peer();
    fixture.install(4);
    // sleep: longer than one walk step, so a restarted walk would have moved the peer.
    std::thread::sleep(crate::candidates::STEP + Duration::from_secs(1));
    let (after, _, endpoint_after) = fixture.counters();
    eprintln!("J704_WALK_SETTLED handshake_before={handshake} handshake_after={after}");
    assert_eq!(
        endpoint_after,
        Some(live),
        "the found peer stays on its address"
    );
    assert!(
        !crate::candidates::newer_handshake(after, handshake),
        "the settled peer got another handshake: {handshake} -> {after}"
    );
    drop(dead);
}

/// J699 P3-3 on the Mac: a snapshot that changes only the tail of a found peer's list keeps the
/// peer on the address its walk found, so traffic flows on at once instead of waiting a walk
/// step on the dead first candidate.
#[test]
#[ignore = "Run on the macOS VM with root privileges under the Mac lock."]
fn a_tail_change_keeps_a_found_peer_on_its_address() {
    let mut fixture = Fixture::start(74);
    let dead = UdpSocket::bind("127.0.0.1:0").expect("dead candidate");
    let dead_address = dead.local_addr().expect("dead address");
    let live = fixture.live;
    fixture.address(dead_address, vec![live]);
    fixture.install(3);
    assert!(
        fixture.first_echo(Duration::from_secs(20)).is_some(),
        "the walk found the peer"
    );
    let tail = "192.0.2.9:9".parse().expect("tail candidate");
    fixture.address(dead_address, vec![live, tail]);
    fixture.install(4);
    let (_, _, endpoint) = fixture.counters();
    let echoed = fixture.echo(Duration::from_secs(1));
    eprintln!("J704_TAIL endpoint={endpoint:?} echo_within_1s={echoed}");
    assert_eq!(endpoint, Some(live), "the tail change moved the found peer");
    assert!(echoed, "traffic stopped after the tail change");
    drop(dead);
}

/// A snapshot that changes only the networks behind a router peer rewrites that peer (its allowed
/// IPs carry them, D197 M3), and one that changes nothing rewrites none (#580, J1169).
#[test]
fn a_networks_only_change_rewrites_the_router_peer() {
    use crate::dataplane::{PeerNetworks, ReachableNetwork};
    use crate::macos_node::walks::{changed_peers, installed_by_key};
    let applied = config();
    let previous = installed_by_key(Some(&applied));
    assert_eq!(changed_peers(&previous, &applied).count(), 0);
    let mut next = applied.clone();
    next.peers.get_mut(&NodeId(4)).unwrap().networks = PeerNetworks {
        through: vec![ReachableNetwork {
            network: "10.77.0.0/24".parse().unwrap(),
            outbound: TrafficPolicy::All,
        }],
        served: Vec::new(),
    };
    let changed: Vec<_> = changed_peers(&previous, &next).collect();
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].peer.key, applied.peers[&NodeId(4)].peer.key);
}
