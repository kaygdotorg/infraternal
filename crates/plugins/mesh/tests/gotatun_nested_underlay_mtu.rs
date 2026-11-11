//! Checks that a learned peer endpoint moves its route budget to the active underlay (#489, F6).
//!
//! The isolated peers have a 1450-byte configured path and a separate 1280-byte path. The
//! second peer initiates from the low-MTU path, which makes `GotaTun` learn that endpoint on the
//! first peer just as it learns an address inside a nested tunnel. The route must follow that
//! learned endpoint before the two sides exchange ten-second bulk streams.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![expect(
    clippy::unwrap_used,
    reason = "namespace fixture failures stop this proof at the failing operation"
)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer, PeerPolicy},
    node::{EngineKind, Identity, Node},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
};
use nix::sched::{CloneFlags, setns};
use openssl::hash::{Hasher, MessageDigest};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant},
};

/// The first isolated mesh peer and its underlay interfaces.
const NS_A: &str = "j502-a";
/// The second isolated mesh peer that teaches the lower-MTU endpoint.
const NS_B: &str = "j502-b";
/// Duration for which each checksum stream keeps sending bulk data.
const STREAM_DURATION: Duration = Duration::from_secs(10);
/// Maximum time to wait for the learned endpoint's route budget.
const ROUTE_WAIT: Duration = Duration::from_secs(5);
/// Generous socket timeout that bounds hangs without asserting transfer speed.
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Reusable stream buffer size for the bidirectional bulk proof.
const CHUNK_BYTES: usize = 64 << 10;

/// Run one command and return stdout after requiring a successful exit.
fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Run `f` on a thread inside the named network namespace.
fn in_ns<T: Send>(ns: &str, f: impl FnOnce() -> T + Send) -> T {
    thread::scope(|scope| {
        scope
            .spawn(|| {
                enter(ns);
                f()
            })
            .join()
            .unwrap()
    })
}

/// Enter a namespace created by this test.
fn enter(ns: &str) {
    let file = fs::File::open(format!("/run/netns/{ns}")).unwrap();
    setns(&file, CloneFlags::CLONE_NEWNET).unwrap();
}

/// Create a private node state directory for one peer.
fn state(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

/// Return the mesh addresses used for one test peer.
fn addresses(id: u32) -> Addresses {
    Addresses {
        ipv4: (0x0afe_0000 + id).into(),
        ipv6: ((0xfd01_u128 << 112) + u128::from(id)).into(),
    }
}

/// Build an open-access coordinator snapshot for one peer and its configured endpoint.
fn snapshot(local: (u32, PublicKey), peer: (u32, PublicKey), endpoint: SocketAddr) -> Chunk {
    Chunk {
        local_key: Some(local.1),
        server: Some(NodeId(1)),
        authority_epoch: None,
        node: NodeId(local.0.into()),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: "internal".to_owned(),
        from_version: None,
        version: 1,
        index: 0,
        last: true,
        addresses: addresses(local.0),
        default_policy: DefaultPolicy::Allow,
        exposure: None,
        upserted: BTreeMap::from([(
            NodeId(peer.0.into()),
            PeerPolicy {
                peer: Peer {
                    key: peer.1,
                    previous_key: None,
                    previous_active: false,
                    addresses: addresses(peer.0),
                    endpoint: Some(endpoint),
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
                access_ssh: None,
            },
        )]),
        merged: BTreeMap::new(),
        removed: Vec::new(),
        #[cfg(feature = "mesh-dns")]
        peer_names: BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        removed_peer_names: Vec::new(),
        access_updates: Vec::new(),
    }
}

/// Read the route MTU selected for one destination inside a test namespace.
fn route_mtu(ns: &str, destination: &str) -> Option<u16> {
    let output = run("ip", &["-n", ns, "route", "get", destination]);
    output
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|fields| {
            (fields[0] == "mtu")
                .then(|| fields[1].parse::<u16>().ok())
                .flatten()
        })
}

/// Wait until one route has the learned endpoint's expected packet budget.
fn wait_for_route_mtu(ns: &str, destination: &str, expected: u16) -> Option<u16> {
    let deadline = Instant::now() + ROUTE_WAIT;
    loop {
        let actual = route_mtu(ns, destination);
        if actual == Some(expected) || Instant::now() >= deadline {
            return actual;
        }
        // sleep: let the bounded endpoint refresh run without spinning on netlink.
        thread::sleep(Duration::from_millis(20));
    }
}

/// Fill one reusable buffer with bytes that the receiver can independently reproduce.
fn fill_pattern(buffer: &mut [u8], offset: u64, seed: u8) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = u8::try_from((offset + u64::try_from(index).unwrap()) % 251).unwrap() ^ seed;
    }
}

/// Send patterned bytes for ten seconds and return length, SHA-256 and elapsed time.
fn send_bulk(ns: &'static str, destination: SocketAddr, seed: u8) -> (u64, [u8; 32], Duration) {
    enter(ns);
    let mut stream = TcpStream::connect_timeout(&destination, IO_TIMEOUT).unwrap();
    stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    let started = Instant::now();
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut checksum = Hasher::new(MessageDigest::sha256()).unwrap();
    let mut sent = 0_u64;
    while started.elapsed() < STREAM_DURATION {
        fill_pattern(&mut buffer, sent, seed);
        stream.write_all(&buffer).unwrap();
        checksum.update(&buffer).unwrap();
        sent += u64::try_from(buffer.len()).unwrap();
    }
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let digest: [u8; 32] = checksum.finish().unwrap().as_ref().try_into().unwrap();
    (sent, digest, started.elapsed())
}

/// Receive one patterned stream, verifying every byte and its SHA-256 digest.
fn receive_bulk(ns: &'static str, listener: &TcpListener, seed: u8) -> (u64, [u8; 32]) {
    enter(ns);
    let (mut stream, _) = listener.accept().unwrap();
    stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    let mut checksum = Hasher::new(MessageDigest::sha256()).unwrap();
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut received = 0_u64;
    loop {
        let count = stream.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        for (index, byte) in buffer[..count].iter().enumerate() {
            let offset = received + u64::try_from(index).unwrap();
            let expected = u8::try_from(offset % 251).unwrap() ^ seed;
            assert_eq!(*byte, expected, "stream byte {offset} differs");
        }
        checksum.update(&buffer[..count]).unwrap();
        received += u64::try_from(count).unwrap();
    }
    let digest: [u8; 32] = checksum.finish().unwrap().as_ref().try_into().unwrap();
    (received, digest)
}

/// Remove the test namespaces and private state directories.
fn cleanup(states: &[&PathBuf]) {
    for ns in [NS_A, NS_B] {
        let _ = Command::new("ip").args(["netns", "del", ns]).status();
    }
    for state in states {
        let _ = fs::remove_dir_all(state);
    }
}

/// The live endpoint on a 1280-byte underlay replaces a configured 1450-byte route budget.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn learned_nested_underlay_endpoint_caps_routes_and_keeps_bulk_bidirectional() {
    nested_underlay_case(ReviewCase::Bulk);
}

/// A stable authenticated endpoint must recover its budget when the carrier MTU increases.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn stable_endpoint_recovers_after_underlay_mtu_grows() {
    nested_underlay_case(ReviewCase::Growth);
}

/// Repeated authenticated endpoint moves converge on the final path in both IP families.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn flapping_authenticated_endpoints_converge_on_final_route_budget() {
    nested_underlay_case(ReviewCase::Flap);
}

/// An authenticated handshake alone must refresh the endpoint before any inner IP traffic.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn authenticated_handshake_refreshes_route_without_inbound_payload() {
    nested_underlay_case(ReviewCase::Handshake);
}

/// A later carrier shrink must lower the budget even when the authenticated address stays fixed.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn stable_endpoint_tracks_later_underlay_mtu_shrink() {
    nested_underlay_case(ReviewCase::Shrink);
}

/// IPv6 inner streams must remain bidirectional over an authenticated IPv6 nested endpoint.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn ipv6_nested_underlay_keeps_bulk_bidirectional() {
    nested_underlay_case(ReviewCase::Ipv6Bulk);
}

/// Select the extra review assertion after learning the nested endpoint.
#[derive(Clone, Copy)]
enum ReviewCase {
    /// Preserve the author's bidirectional checksum proof.
    Bulk,
    /// Observe an authenticated control-only endpoint change.
    Handshake,
    /// Raise the carrier MTU without changing the endpoint identity or address.
    Growth,
    /// Lower the carrier MTU at an unchanged endpoint.
    Shrink,
    /// Exercise large inner IPv6 packets on the nested IPv6 carrier.
    Ipv6Bulk,
    /// Alternate the authenticated peer between the two carriers.
    Flap,
}

/// Run the isolated two-carrier fixture for one review scenario.
fn nested_underlay_case(case: ReviewCase) {
    let (state_a, state_b) = (state("j502-node-a"), state("j502-node-b"));
    run("mkdir", &["-p", "/run/netns"]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }

    // The high-MTU carrier is the configured endpoint path; the 1280-byte pair models a nested
    // underlay whose peer address is learned from an authenticated packet.
    run(
        "ip",
        &[
            "link", "add", "j502ea", "netns", NS_A, "type", "veth", "peer", "j502eb", "netns", NS_B,
        ],
    );
    run("ip", &["-n", NS_A, "link", "set", "j502ea", "mtu", "1450"]);
    run("ip", &["-n", NS_B, "link", "set", "j502eb", "mtu", "1450"]);
    run(
        "ip",
        &[
            "-n",
            NS_A,
            "address",
            "add",
            "192.0.2.1/24",
            "dev",
            "j502ea",
        ],
    );
    // Leave B's high-path address absent: A's initial keepalive to the configured endpoint
    // cannot teach both peers the high-MTU path before B initiates on the lower-MTU link.
    run("ip", &["-n", NS_A, "link", "set", "j502ea", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j502eb", "up"]);
    run(
        "ip",
        &[
            "link", "add", "j502la", "netns", NS_A, "type", "veth", "peer", "j502lb", "netns", NS_B,
        ],
    );
    run("ip", &["-n", NS_A, "link", "set", "j502la", "mtu", "1280"]);
    run("ip", &["-n", NS_B, "link", "set", "j502lb", "mtu", "1280"]);
    run(
        "ip",
        &[
            "-n",
            NS_A,
            "address",
            "add",
            "198.51.100.1/24",
            "dev",
            "j502la",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            NS_B,
            "address",
            "add",
            "198.51.100.2/24",
            "dev",
            "j502lb",
        ],
    );
    run("ip", &["-n", NS_A, "link", "set", "j502la", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j502lb", "up"]);

    if matches!(case, ReviewCase::Shrink) {
        // A distinct initial budget proves the first live-endpoint refresh has completed before
        // narrowing the same carrier; the configured high path still derives 1360.
        for (ns, link) in [(NS_A, "j502la"), (NS_B, "j502lb")] {
            run("ip", &["-n", ns, "link", "set", link, "mtu", "1500"]);
        }
    }
    if matches!(case, ReviewCase::Ipv6Bulk) {
        for (ns, address, link) in [
            (NS_A, "2001:db8:523::1/64", "j502la"),
            (NS_B, "2001:db8:523::2/64", "j502lb"),
        ] {
            run(
                "ip",
                &[
                    "-n", ns, "-6", "address", "add", address, "dev", link, "nodad",
                ],
            );
        }
    }

    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, EngineKind::GotaTun).unwrap();
            let identity: Identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    let a = (1, id_a.public_key);
    let b = (2, id_b.public_key);
    let configured_a = SocketAddr::from(([192, 0, 2, 2], id_b.port));
    let active_b = if matches!(case, ReviewCase::Ipv6Bulk) {
        SocketAddr::new("2001:db8:523::1".parse().unwrap(), id_a.port)
    } else {
        SocketAddr::from(([198, 51, 100, 1], id_a.port))
    };
    let expected_learned = if matches!(case, ReviewCase::Ipv6Bulk) {
        SocketAddr::new("2001:db8:523::2".parse().unwrap(), id_b.port)
    } else {
        SocketAddr::from(([198, 51, 100, 2], id_b.port))
    };
    in_ns(NS_A, || {
        assert!(node_a.chunk(snapshot(a, b, configured_a)).unwrap());
    });
    // Check the configured high-path budget before B starts on the alternate path: an
    // authenticated keepalive may roam A before the next route read.
    assert_eq!(route_mtu(NS_A, "10.254.0.2"), Some(1360));
    in_ns(NS_B, || {
        assert!(node_b.chunk(snapshot(b, a, active_b)).unwrap());
    });

    let configured_route = run("ip", &["-n", NS_A, "route", "get", "192.0.2.2"]);
    assert!(
        configured_route.contains("dev j502ea"),
        "{configured_route}"
    );
    let learned_route = run("ip", &["-n", NS_B, "route", "get", "198.51.100.1"]);
    assert!(learned_route.contains("dev j502lb"), "{learned_route}");

    if matches!(case, ReviewCase::Handshake) {
        let deadline = Instant::now() + IO_TIMEOUT;
        let endpoint = loop {
            let endpoint = in_ns(NS_A, || node_a.counters().unwrap())
                .get(&id_b.public_key)
                .and_then(|counter| counter.endpoint);
            if endpoint == Some(SocketAddr::from(([198, 51, 100, 2], id_b.port)))
                || Instant::now() >= deadline
            {
                break endpoint;
            }
            // sleep: wait for the engine's authenticated keepalive handshake without inner traffic.
            thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(
            endpoint,
            Some(SocketAddr::from(([198, 51, 100, 2], id_b.port))),
            "fixture must authenticate the low-path endpoint"
        );
        let actual = wait_for_route_mtu(NS_A, "10.254.0.2", 1200);
        eprintln!("REVIEW handshake endpoint={endpoint:?} route_mtu={actual:?} expected=1200");
        assert_eq!(
            actual,
            Some(1200),
            "authenticated control-only roaming must refresh the route"
        );
        in_ns(NS_A, || node_a.down().unwrap());
        in_ns(NS_B, || node_b.down().unwrap());
        cleanup(&[&state_a, &state_b]);
        return;
    }

    // A small first connection makes B initiate from the low-MTU interface. A learns B's actual
    // source address while its coordinator snapshot still names B's high-MTU address.
    let trigger_address = SocketAddr::from(([10, 254, 0, 1], 49201));
    let trigger_listener = in_ns(NS_A, || TcpListener::bind(trigger_address).unwrap());
    let accept = thread::spawn(move || {
        enter(NS_A);
        trigger_listener.accept().unwrap().0
    });
    let mut trigger = in_ns(NS_B, || {
        TcpStream::connect_timeout(&trigger_address, IO_TIMEOUT).unwrap()
    });
    let mut accepted = accept.join().unwrap();
    trigger.write_all(b"endpoint learned").unwrap();
    let mut probe = [0; 16];
    accepted.read_exact(&mut probe).unwrap();
    assert_eq!(&probe, b"endpoint learned");
    drop(trigger);
    drop(accepted);

    let learned = in_ns(NS_A, || node_a.counters().unwrap());
    assert_eq!(
        learned
            .get(&id_b.public_key)
            .and_then(|counter| counter.endpoint),
        Some(expected_learned),
        "GotaTun did not report the endpoint learned from the low-MTU path"
    );
    let initial_budget = if matches!(case, ReviewCase::Shrink) {
        1408
    } else {
        1200
    };
    let selected = wait_for_route_mtu(NS_A, "10.254.0.2", initial_budget);
    assert_eq!(
        selected,
        Some(initial_budget),
        "learned endpoint route MTU: {selected:?}"
    );

    if !matches!(case, ReviewCase::Bulk | ReviewCase::Ipv6Bulk) {
        let receiver = in_ns(NS_A, || UdpSocket::bind(("10.254.0.1", 49204)).unwrap());
        receiver.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        let sender = in_ns(NS_B, || UdpSocket::bind(("10.254.0.2", 0)).unwrap());
        let pulse = || {
            sender
                .send_to(b"authenticated route probe", ("10.254.0.1", 49204))
                .unwrap();
            let mut bytes = [0_u8; 64];
            receiver.recv_from(&mut bytes).unwrap();
        };
        match case {
            ReviewCase::Growth | ReviewCase::Shrink => {
                let growth = matches!(case, ReviewCase::Growth);
                let carrier_mtu = if growth { "1450" } else { "1280" };
                let expected = if growth { 1360 } else { 1200 };
                for (ns, link) in [(NS_A, "j502la"), (NS_B, "j502lb")] {
                    run("ip", &["-n", ns, "link", "set", link, "mtu", carrier_mtu]);
                }
                let deadline = Instant::now() + ROUTE_WAIT;
                while route_mtu(NS_A, "10.254.0.2") != Some(expected) && Instant::now() < deadline {
                    pulse();
                    // sleep: allow the rate-limited refresh between authenticated probes.
                    thread::sleep(Duration::from_millis(50));
                }
                let current = route_mtu(NS_A, "10.254.0.2");
                let endpoint = in_ns(NS_A, || node_a.counters().unwrap())
                    .get(&id_b.public_key)
                    .and_then(|counter| counter.endpoint);
                eprintln!(
                    "REVIEW carrier growth={growth}: underlay={} endpoint={endpoint:?} route_mtu={current:?} expected={expected}",
                    run("ip", &["-n", NS_A, "link", "show", "j502la"])
                );
                assert_eq!(
                    current,
                    Some(expected),
                    "unchanged authenticated endpoint must follow the current carrier budget"
                );
            }
            ReviewCase::Flap => {
                run(
                    "ip",
                    &[
                        "-n",
                        NS_B,
                        "address",
                        "add",
                        "192.0.2.2/24",
                        "dev",
                        "j502eb",
                    ],
                );
                for step in 0..8 {
                    let high = step % 2 == 0;
                    let endpoint = SocketAddr::from((
                        if high {
                            [192, 0, 2, 1]
                        } else {
                            [198, 51, 100, 1]
                        },
                        id_a.port,
                    ));
                    let mut changed = snapshot(b, a, endpoint);
                    changed.version = step + 2;
                    in_ns(NS_B, || assert!(node_b.chunk(changed).unwrap()));
                    pulse();
                    let expected = if high { 1360 } else { 1200 };
                    assert_eq!(
                        wait_for_route_mtu(NS_A, "10.254.0.2", expected),
                        Some(expected),
                        "flap {step}"
                    );
                    let ipv6 = run("ip", &["-n", NS_A, "-6", "route", "get", "fd01::2"]);
                    assert!(
                        ipv6.contains(&format!("mtu {expected}")),
                        "flap {step}: {ipv6}"
                    );
                    eprintln!("REVIEW flap={step} high={high} expected_mtu={expected} ipv6={ipv6}");
                }
                for (ns, address, link) in [
                    (NS_A, "2001:db8:523::1/64", "j502la"),
                    (NS_B, "2001:db8:523::2/64", "j502lb"),
                ] {
                    run(
                        "ip",
                        &[
                            "-n", ns, "-6", "address", "add", address, "dev", link, "nodad",
                        ],
                    );
                }
                // Switch faster than the refresh cadence, then require convergence on the last
                // authenticated endpoint. Every pulse is received before moving again.
                for step in 0..40 {
                    let endpoint = if step % 2 == 0 {
                        SocketAddr::from(([192, 0, 2, 1], id_a.port))
                    } else {
                        SocketAddr::new("2001:db8:523::1".parse().unwrap(), id_a.port)
                    };
                    let mut changed = snapshot(b, a, endpoint);
                    changed.version = step + 10;
                    in_ns(NS_B, || assert!(node_b.chunk(changed).unwrap()));
                    pulse();
                }
                assert_eq!(
                    wait_for_route_mtu(NS_A, "10.254.0.2", 1200),
                    Some(1200),
                    "rapid flaps must converge on the final low path"
                );
                let final_endpoint = in_ns(NS_A, || node_a.counters().unwrap())
                    .get(&id_b.public_key)
                    .and_then(|counter| counter.endpoint);
                assert_eq!(
                    final_endpoint,
                    Some(SocketAddr::new(
                        "2001:db8:523::2".parse().unwrap(),
                        id_b.port
                    ))
                );
                eprintln!(
                    "REVIEW 40 rapid flaps converged endpoint={final_endpoint:?} route_mtu=1200"
                );
            }
            ReviewCase::Bulk | ReviewCase::Ipv6Bulk | ReviewCase::Handshake => unreachable!(),
        }
        in_ns(NS_A, || node_a.down().unwrap());
        in_ns(NS_B, || node_b.down().unwrap());
        cleanup(&[&state_a, &state_b]);
        return;
    }

    let destination_a = if matches!(case, ReviewCase::Ipv6Bulk) {
        SocketAddr::new("fd01::1".parse().unwrap(), 49202)
    } else {
        SocketAddr::from(([10, 254, 0, 1], 49202))
    };
    let destination_b = if matches!(case, ReviewCase::Ipv6Bulk) {
        SocketAddr::new("fd01::2".parse().unwrap(), 49203)
    } else {
        SocketAddr::from(([10, 254, 0, 2], 49203))
    };
    let listener_a = in_ns(NS_A, || TcpListener::bind(destination_a).unwrap());
    let listener_b = in_ns(NS_B, || TcpListener::bind(destination_b).unwrap());
    let rx_a = thread::spawn(move || receive_bulk(NS_A, &listener_a, 0x72));
    let rx_b = thread::spawn(move || receive_bulk(NS_B, &listener_b, 0x31));
    let tx_a = thread::spawn(move || send_bulk(NS_A, destination_b, 0x31));
    let tx_b = thread::spawn(move || send_bulk(NS_B, destination_a, 0x72));
    let (sent_a, sent_b) = (tx_a.join().unwrap(), tx_b.join().unwrap());
    let (received_a, received_b) = (rx_a.join().unwrap(), rx_b.join().unwrap());
    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    cleanup(&[&state_a, &state_b]);

    assert!(
        sent_a.0 > 0 && sent_b.0 > 0,
        "both directions must carry bytes"
    );
    assert_eq!(sent_a.0, received_b.0);
    assert_eq!(sent_b.0, received_a.0);
    assert_eq!(sent_a.1, received_b.1, "A to B SHA-256 differs");
    assert_eq!(sent_b.1, received_a.1, "B to A SHA-256 differs");
    eprintln!(
        "METRIC j502_nested_mtu inner_ipv6={} a_to_b_bytes={} b_to_a_bytes={} a_to_b_ms={} b_to_a_ms={} mtu=1200",
        matches!(case, ReviewCase::Ipv6Bulk),
        sent_a.0,
        sent_b.0,
        sent_a.2.as_millis(),
        sent_b.2.as_millis(),
    );
}
