//! Proves that the Mac worker teaches its handshake admission guard where a roamed peer really
//! is, so the peer keeps the guard's reserved budget under a flood (J717, J736, #483).
//!
//! A peer that moved (a NAT rebinding, a new network) reaches the node from an address the
//! coordinator has not published yet. `GotaTun` confirms that address from the peer's first
//! authenticated packet. Unless the worker hands it to the guard, the guard treats the peer as
//! a stranger, and a wide flood spends the strangers' share before the peer's retries arrive.

use super::{
    AUTHORITY_EPOCH_A, Duration, Instant, Ipv4Addr, Node, NodeId, PublicKey, SocketAddr,
    WorkerCommand, chunks_with_epoch, config, test_directory, thread, write_key,
};
use crate::handshake_admission::flood_fairness::{Flood, flood_against, initiation_to, report};
use gotatun::x25519::{PublicKey as XKey, StaticSecret};

/// The remote peer's fixed test identity.
const PEER: [u8; 32] = [0x36; 32];

/// The endpoint the coordinator still has for the peer: nothing listens there, as after the
/// peer roamed away from it.
const STALE_ENDPOINT: &str = "127.0.0.1:9";

/// Start a real `GotaTun` peer on loopback that initiates to the node at `node` and keeps the
/// session alive every second, from its own (unpublished) port.
///
/// Returns the peer's key, the address it sends from, a stop signal and its thread.
fn roaming_peer(
    node_key: PublicKey,
    node: SocketAddr,
    node_address: Ipv4Addr,
    peer_address: Ipv4Addr,
) -> (
    PublicKey,
    SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    thread::JoinHandle<()>,
) {
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let join = thread::spawn(move || {
        use gotatun::{
            device::{DeviceBuilder, Peer},
            tun::{MtuWatcher, channel::new_udp_tun_channel},
            udp::socket::UdpSocketFactory,
        };
        super::super::RuntimeBuilder::new_current_thread()
            .enable_all()
            .build()
            .expect("peer runtime")
            .block_on(async {
                let secret = StaticSecret::from(PEER);
                let key = PublicKey(*XKey::from(&secret).as_bytes());
                // Only the node has a utun; the peer's IP side is an in-memory channel.
                let (tx, rx, _app) = new_udp_tun_channel(
                    64,
                    peer_address,
                    "fd36::4".parse().expect("peer IPv6"),
                    MtuWatcher::new(1280),
                );
                let mut node_peer = Peer::new(XKey::from(node_key.0)).with_allowed_ips(vec![
                    ipnetwork::IpNetwork::new(node_address.into(), 32).expect("node route"),
                ]);
                node_peer.endpoint = Some(node);
                node_peer.keepalive = Some(1);
                let device = DeviceBuilder::new()
                    .with_udp(UdpSocketFactory::default())
                    .with_private_key(secret)
                    .with_listen_port(0)
                    .with_ip_pair(tx, rx)
                    .with_peers(vec![node_peer])
                    .build()
                    .await
                    .expect("peer device");
                let port = device.read(async |read| read.listen_port()).await;
                ready_tx
                    .send((key, SocketAddr::from(([127, 0, 0, 1], port))))
                    .expect("report the peer");
                let _ = stop_rx.await;
                device.stop().await;
            });
    });
    let (key, endpoint) = ready_rx.recv().expect("peer started");
    (key, endpoint, stop_tx, join)
}

/// J736: a peer that roamed to an endpoint `GotaTun` confirmed but the coordinator never
/// configured keeps every initiation under J717's widest flood (64 /48s x 16 /64s at 20,000
/// initiations a second for 90 s), on the real Mac worker's guard.
///
/// Before J736 only configured endpoints counted on the Mac, so this peer was a stranger to
/// the guard and got 0 of 18 at a 500 ms offset (the documented unknown-endpoint limit).
#[test]
#[ignore = "Run on the macOS VM with system service privileges."]
fn a_roamed_peer_keeps_the_reserve_on_the_mac() {
    let directory = test_directory();
    write_key(&directory);
    let mut node = Node::restore(&directory.0, None).expect("restore isolated node");
    let identity = node.up().expect("start isolated node");
    let mut current = config();
    current.local_key = Some(identity.public_key);
    current.addresses.ipv4 = "10.253.36.1".parse().expect("node IPv4");
    current.addresses.ipv6 = "fd36::1".parse().expect("node IPv6");
    // A suffix nothing else uses, so the resolver file this run installs is its own.
    #[cfg(feature = "mesh-dns")]
    {
        current.dns_suffix = "j736.invalid".to_owned();
    }
    let peer_ipv4: Ipv4Addr = "10.253.36.4".parse().expect("peer IPv4");
    let node_port = SocketAddr::from(([127, 0, 0, 1], identity.port));
    let (key, roamed, stop, remote) = roaming_peer(
        identity.public_key,
        node_port,
        current.addresses.ipv4,
        peer_ipv4,
    );
    let peer = &mut current.peers.get_mut(&NodeId(4)).expect("peer 4").peer;
    peer.key = key;
    peer.addresses.ipv4 = peer_ipv4;
    peer.addresses.ipv6 = "fd36::4".parse().expect("peer IPv6");
    peer.endpoint = Some(STALE_ENDPOINT.parse().expect("stale endpoint"));
    for chunk in chunks_with_epoch(None, &current, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).expect("install the snapshot");
    }
    let (reply, admission) = std::sync::mpsc::sync_channel(1);
    node.test_state()
        .worker
        .as_ref()
        .expect("running worker")
        .commands
        .send(WorkerCommand::Admission(reply))
        .expect("ask for the guard");
    let admission = admission.recv().expect("the worker's guard");

    // The peer's handshake and first keepalive confirm `roamed`; the worker's scan runs every
    // 250 ms, so allow a few handshake retries before calling it missing.
    let deadline = Instant::now() + Duration::from_secs(20);
    let learned = loop {
        let known = admission.blocking_read().is_known_endpoint(roamed);
        if known || Instant::now() >= deadline {
            break known;
        }
        // sleep: polling the worker's own 250 ms scan; nothing to wait on from outside.
        thread::sleep(Duration::from_millis(100));
    };
    let handshake = node
        .counters()
        .expect("peer counters")
        .get(&key)
        .map(|counters| counters.handshake_secs);
    let configured_known = admission
        .blocking_read()
        .is_known_endpoint(STALE_ENDPOINT.parse().expect("stale endpoint"));
    eprintln!(
        "J736 roamed={roamed} learned={learned} handshake_secs={handshake:?} \
         configured_known={configured_known}"
    );

    let granted = initiation_to(XKey::from(identity.public_key.0), PEER);
    let mut runs = Vec::new();
    // Past every real window the live guard has seen. Each run reuses this one guard, so the
    // next starts after the last one's simulated 90 s; an earlier start would land inside a
    // window the previous run already spent, and the flood would not be J717's.
    let mut start = Instant::now() + Duration::from_secs(10);
    for offset in [10_u64, 100, 500, 900] {
        let run = flood_against(
            &admission.blocking_read(),
            XKey::from(identity.public_key.0),
            &granted,
            roamed,
            Flood {
                rate: 20_000,
                networks: 64,
                prefixes_per_network: 16,
                peer_offset_ms: offset,
                peer_endpoint_known: true,
            },
            start,
        );
        start += Duration::from_secs(100);
        report(
            &format!("Mac live guard, 64 /48s x 16 /64s, roamed peer, offset {offset} ms"),
            &run,
        );
        runs.push((offset, run.peer_admitted, run.peer_attempts));
    }
    let _ = stop.send(());
    remote.join().expect("peer thread");
    node.down()
        .expect("remove isolated routes, resolver and utun");

    assert!(configured_known, "the configured endpoint stays known");
    assert!(
        learned,
        "the Mac worker never taught its guard the peer's confirmed endpoint {roamed}"
    );
    for (offset, admitted, attempts) in runs {
        assert_eq!(
            admitted, attempts,
            "a wide flood starved a roamed peer on the Mac (offset {offset} ms)"
        );
    }
}
