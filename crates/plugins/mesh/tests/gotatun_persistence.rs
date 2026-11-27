//! A `GotaTun` node's interface survives an infraternal agent restart, as kernel `WireGuard`'s does: a route a person added and an open TCP flow are kept (D332, #260).
//!
//! Run as root, alone, in a disposable mount and network namespace (`unshare -m -n`), with `ip`
//! and `nft`. Two network namespaces, joined by a veth pair, each hold one `GotaTun` node; each
//! node runs on a thread that entered its namespace, because the TUN, netlink and `nft` all act
//! in the calling thread's namespace. The restart drops node A, which stops its engine and closes
//! its last TUN descriptor exactly as a process exit does, then restores it from its state.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer, PeerPolicy},
    node::{EngineKind, Identity, Node},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
};
use nix::sched::{CloneFlags, setns};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const NS_A: &str = "d332-a";
const NS_B: &str = "d332-b";
/// Names the isolated nftables table used by the direct endpoint proof.
const HOLE_PUNCH_TABLE: &str = "j510_mesh";
/// Names the output counter table used to measure a reflected UDP endpoint.
const J534_OUTPUT_TABLE: &str = "j534_output";
const STREAM_BYTES: usize = 8 << 20;
const CHUNK: usize = 64 << 10;
const RESTART_AFTER: usize = 2 << 20;
const MANUAL_ROUTE: &str = "10.99.0.0/24";

fn run(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Run `f` on a thread inside network namespace `ns`.
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

fn enter(ns: &str) {
    let file = fs::File::open(format!("/run/netns/{ns}")).unwrap();
    setns(&file, CloneFlags::CLONE_NEWNET).unwrap();
}

fn state(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn addresses(id: u32) -> Addresses {
    Addresses {
        ipv4: (0x0afe_0000 + id).into(),
        ipv6: ((0xfd01_u128 << 112) + u128::from(id)).into(),
    }
}

/// The coordinator's first snapshot for `local`, after it has observed `peer` at `endpoint`.
fn snapshot(local: (u32, PublicKey), peer: (u32, PublicKey), endpoint: SocketAddr) -> Chunk {
    snapshot_with_endpoint(local, peer, Some(endpoint), 1)
}

/// Build one coordinator snapshot, including snapshots sent before a peer endpoint is observed.
fn snapshot_with_endpoint(
    local: (u32, PublicKey),
    peer: (u32, PublicKey),
    endpoint: Option<SocketAddr>,
    version: u64,
) -> Chunk {
    Chunk {
        local_key: Some(local.1),
        server: Some(NodeId(1)),
        authority_epoch: None,
        rotation_operation: None,
        node: NodeId(local.0.into()),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: "internal".to_owned(),
        from_version: None,
        version,
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
                    endpoint,
                    candidates: Vec::new(),
                    ipv4_only: false,
                    side_port: false,
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
                access_ssh: None,
                networks: infraternal_plugin_mesh::dataplane::PeerNetworks::default(),
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

fn pattern(offset: usize) -> u8 {
    u8::try_from(offset % 251).unwrap()
}

fn manual_route_present() -> bool {
    !run("ip", &["-n", NS_A, "route", "show", MANUAL_ROUTE])
        .trim()
        .is_empty()
}

/// Removes only the namespaces, firewall table, and state directories created by this fixture.
fn cleanup(states: &[&PathBuf]) {
    for ns in [NS_A, NS_B] {
        let _ = Command::new("ip").args(["netns", "del", ns]).output();
    }
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "infraternal_mesh"])
        .output();
    for state in states {
        let _ = fs::remove_dir_all(state);
    }
}

/// Install the stateful input guard used by the direct-endpoint test.
///
/// The only underlay input rule is established/related. The TUN input rule is added later in the
/// test so encrypted UDP reachability and new connections through the tunnel stay distinct.
fn install_hole_punch_firewall(ns: &str, rules: &Path) {
    in_ns(ns, || {
        run("nft", &["-f", rules.to_str().unwrap()]);
        let table = run("nft", &["list", "table", "inet", HOLE_PUNCH_TABLE]);
        assert!(table.contains("policy drop"), "{ns} input policy: {table}");
        assert!(
            table.contains("ct state established,related"),
            "{ns} has no established/related input allowance: {table}"
        );
        assert!(
            !table.contains("udp"),
            "{ns} unexpectedly allows an inbound UDP mesh port: {table}"
        );
    });
}

/// Return the packets that the firewall admitted through its established/related rule.
fn established_input_packets(ns: &str) -> u64 {
    let chain = in_ns(ns, || {
        run("nft", &["list", "chain", "inet", HOLE_PUNCH_TABLE, "input"])
    });
    let rule = chain
        .lines()
        .find(|line| line.contains("ct state established,related"))
        .unwrap_or_else(|| panic!("{ns} lost its established/related rule: {chain}"));
    rule.split("packets ")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("{ns} rule has no packet counter: {rule}"))
}

/// Return the packets that the input firewall dropped after rejecting a new underlay flow.
fn dropped_input_packets(ns: &str) -> u64 {
    let chain = in_ns(ns, || {
        run("nft", &["list", "chain", "inet", HOLE_PUNCH_TABLE, "input"])
    });
    let rule = chain
        .lines()
        .find(|line| line.trim_end().ends_with("drop"))
        .unwrap_or_else(|| panic!("{ns} has no final counter drop rule: {chain}"));
    rule.split("packets ")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .and_then(|count| count.parse().ok())
        .unwrap_or_else(|| panic!("{ns} drop rule has no packet counter: {rule}"))
}

/// Keep the topology, open flow and restart in one scenario so the assertions observe the same interfaces.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
// One scenario: the topology, the open flow, the restart in the middle of it, and the checks.
fn manual_route_and_open_tcp_flow_survive_an_agent_restart() {
    let (state_a, state_b) = (state("d332-node-a"), state("d332-node-b"));
    cleanup(&[]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "link", "add", "d332a", "netns", NS_A, "type", "veth", "peer", "d332b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &["-n", NS_A, "address", "add", "192.0.2.1/24", "dev", "d332a"],
    );
    run(
        "ip",
        &["-n", NS_B, "address", "add", "192.0.2.2/24", "dev", "d332b"],
    );
    run("ip", &["-n", NS_A, "link", "set", "d332a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "d332b", "up"]);

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
    in_ns(NS_A, || {
        assert!(
            node_a
                .chunk(snapshot(
                    a,
                    b,
                    SocketAddr::from(([192, 0, 2, 2], id_b.port))
                ))
                .unwrap()
        );
    });
    in_ns(NS_B, || {
        assert!(
            node_b
                .chunk(snapshot(
                    b,
                    a,
                    SocketAddr::from(([192, 0, 2, 1], id_a.port))
                ))
                .unwrap()
        );
    });
    // A route the person added on the mesh interface.
    run(
        "ip",
        &[
            "-n",
            NS_A,
            "route",
            "add",
            MANUAL_ROUTE,
            "dev",
            "infraternal0",
        ],
    );
    let index_before = run("ip", &["-n", NS_A, "-o", "link", "show", "infraternal0"]);

    // One TCP flow from A to B's mesh address, paced so it is open across the restart.
    let server_address = SocketAddr::from(([10, 254, 0, 2], 5001));
    let (listening, ready) = mpsc::channel();
    let server = thread::spawn(move || {
        enter(NS_B);
        let listener = TcpListener::bind(server_address).unwrap();
        listening.send(()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut received = 0;
        let mut buffer = vec![0; CHUNK];
        // The longest wait between two reads: how long the restart held the flow up.
        let mut longest_gap = Duration::ZERO;
        let mut last = Instant::now();
        loop {
            let read = stream.read(&mut buffer)?;
            longest_gap = longest_gap.max(last.elapsed());
            last = Instant::now();
            if read == 0 {
                break;
            }
            if let Some(offset) = (0..read).find(|&i| buffer[i] != pattern(received + i)) {
                return Err(std::io::Error::other(format!(
                    "byte {} differs",
                    received + offset
                )));
            }
            received += read;
        }
        Ok::<_, std::io::Error>((received, longest_gap))
    });
    ready.recv().unwrap();
    let (sent_half, restart_now) = mpsc::channel();
    let client = thread::spawn(move || {
        enter(NS_A);
        let mut stream = TcpStream::connect_timeout(&server_address, Duration::from_secs(10))?;
        stream.set_write_timeout(Some(Duration::from_secs(60)))?;
        let mut sent = 0;
        let mut chunk = vec![0; CHUNK];
        while sent < STREAM_BYTES {
            for (i, byte) in chunk.iter_mut().enumerate() {
                *byte = pattern(sent + i);
            }
            stream.write_all(&chunk)?;
            sent += CHUNK;
            if sent == RESTART_AFTER {
                let _ = sent_half.send(());
            }
            thread::sleep(Duration::from_millis(20));
        }
        stream.shutdown(std::net::Shutdown::Write)?;
        Ok::<_, std::io::Error>(sent)
    });

    restart_now.recv_timeout(Duration::from_secs(30)).unwrap();
    // The infraternal agent restarts: its engine and TUN descriptor go, then it restores.
    let restart = Instant::now();
    drop(node_a);
    let route_while_down = manual_route_present();
    thread::sleep(Duration::from_millis(300));
    let mut node_a = in_ns(NS_A, || {
        Node::restore_with_engine(&state_a, EngineKind::GotaTun).unwrap()
    });
    let restored_in = restart.elapsed();

    let sent = client.join().unwrap();
    let received = server.join().unwrap();
    let route_after = manual_route_present();
    let index_after = run("ip", &["-n", NS_A, "-o", "link", "show", "infraternal0"]);
    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    cleanup(&[&state_a, &state_b]);

    let (received, longest_gap) = received.unwrap();
    // Reported, not asserted: timing belongs to the perf harness.
    eprintln!(
        "METRIC d332_restore_ms={} d332_longest_receive_gap_ms={} sent={sent:?} received={received}",
        restored_in.as_millis(),
        longest_gap.as_millis()
    );
    assert!(
        route_while_down,
        "the manual route went with the stopped agent"
    );
    assert!(route_after, "the manual route did not survive the restart");
    assert_eq!(
        index_before.split(':').next(),
        index_after.split(':').next(),
        "the restart replaced the interface"
    );
    assert_eq!(
        sent.unwrap(),
        STREAM_BYTES,
        "the open flow broke on the sender"
    );
    assert_eq!(
        received, STREAM_BYTES,
        "the open flow broke on the receiver"
    );
}

/// A lower-revision restore either replaces its peers or stops before any stale peer stays reachable.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft, issue #382."]
fn restored_snapshot_makes_a_removed_peer_unreachable() {
    let (state_a, state_b) = (state("j287-rollback-a"), state("j287-rollback-b"));
    run("mkdir", &["-p", "/run/netns"]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    cleanup(&[]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "link", "add", "d332a", "netns", NS_A, "type", "veth", "peer", "d332b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &["-n", NS_A, "address", "add", "192.0.2.1/24", "dev", "d332a"],
    );
    run(
        "ip",
        &["-n", NS_B, "address", "add", "192.0.2.2/24", "dev", "d332b"],
    );
    run("ip", &["-n", NS_A, "link", "set", "d332a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "d332b", "up"]);

    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, EngineKind::GotaTun).unwrap();
            let identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    let a = (1, id_a.public_key);
    let b = (2, id_b.public_key);
    let endpoint_a = SocketAddr::from(([192, 0, 2, 1], id_a.port));
    let endpoint_b = SocketAddr::from(([192, 0, 2, 2], id_b.port));

    let mut accepted = snapshot(a, b, endpoint_b);
    accepted.version = 11;
    in_ns(NS_A, || assert!(node_a.chunk(accepted).unwrap()));
    in_ns(NS_B, || {
        assert!(node_b.chunk(snapshot(b, a, endpoint_a)).unwrap());
    });

    let address = SocketAddr::from(([10, 254, 0, 2], 5001));
    let listener = in_ns(NS_B, || TcpListener::bind(address).unwrap());
    let accept_listener = listener.try_clone().unwrap();
    let accepting = thread::spawn(move || {
        enter(NS_B);
        accept_listener.accept().unwrap().0
    });
    let mut client = in_ns(NS_A, || {
        TcpStream::connect_timeout(&address, Duration::from_secs(5)).unwrap()
    });
    let mut accepted_stream = accepting.join().unwrap();
    client.write_all(b"peer reachable").unwrap();
    let mut received = [0; 14];
    accepted_stream.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"peer reachable");

    let mut restored = snapshot(a, b, endpoint_b);
    restored.version = 2;
    restored.default_policy = DefaultPolicy::Deny;
    restored.upserted.clear();
    let (restored_result, retained_version, installed_peers) = in_ns(NS_A, || {
        let result = node_a.chunk(restored);
        (
            result,
            node_a.config().map(|config| config.version),
            node_a.counters().map(|counters| counters.len()),
        )
    });
    let attempt = in_ns(NS_A, || {
        TcpStream::connect_timeout(&address, Duration::from_secs(2))
    });
    let replacement_applied = match restored_result {
        Ok(applied) => {
            assert!(applied, "the restored full snapshot was not committed");
            assert_eq!(retained_version, Some(2));
            assert!(installed_peers.as_ref().is_ok_and(|count| *count == 0));
            true
        }
        Err(error) => {
            // If retirement itself fails, `chunk` stops the mesh before returning the refusal.
            // That fallback is acceptable only when no stale configuration or peer remains.
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert_eq!(retained_version, None);
            assert!(installed_peers.is_err());
            false
        }
    };
    assert!(
        attempt.is_err(),
        "the peer removed by the restored snapshot still reached the listener"
    );

    drop(client);
    drop(accepted_stream);
    drop(listener);
    if replacement_applied {
        in_ns(NS_A, || node_a.down().unwrap());
    }
    in_ns(NS_B, || node_b.down().unwrap());
    cleanup(&[&state_a, &state_b]);
}

/// Independently installed endpoints start direct handshakes through stateful firewalls without a UDP allow rule.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn peers_punch_through_established_only_input_and_tunnel_input_stays_separate() {
    assert!(
        std::env::var_os("INFRATERNAL_MESH_PORT").is_none(),
        "the test exercises the automatic mesh listener"
    );
    let (state_a, state_b) = (state("j510-hole-a"), state("j510-hole-b"));
    let firewall = std::env::temp_dir().join(format!("j510-nft-{}.conf", std::process::id()));
    fs::write(
        &firewall,
        format!(
            "table inet {HOLE_PUNCH_TABLE} {{\n\
                 chain input {{\n\
                     type filter hook input priority filter; policy drop;\n\
                     iifname \"lo\" accept\n\
                     ct state established,related counter accept\n\
                     counter drop\n\
                 }}\n\
             }}\n"
        ),
    )
    .unwrap();
    run("mkdir", &["-p", "/run/netns"]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    cleanup(&[]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "link", "add", "j510a", "netns", NS_A, "type", "veth", "peer", "j510b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &["-n", NS_A, "address", "add", "192.0.2.1/24", "dev", "j510a"],
    );
    run(
        "ip",
        &["-n", NS_B, "address", "add", "192.0.2.2/24", "dev", "j510b"],
    );
    run("ip", &["-n", NS_A, "link", "set", "j510a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j510b", "up"]);
    install_hole_punch_firewall(NS_A, &firewall);
    install_hole_punch_firewall(NS_B, &firewall);

    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, EngineKind::GotaTun).unwrap();
            let identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    assert_eq!(id_a.port, 10_254, "node A uses the default UDP listener");
    assert_eq!(id_b.port, 10_254, "node B uses the default UDP listener");
    let a = (1, id_a.public_key);
    let b = (2, id_b.public_key);
    let endpoint_a = SocketAddr::from(([192, 0, 2, 1], id_a.port));
    let endpoint_b = SocketAddr::from(([192, 0, 2, 2], id_b.port));
    in_ns(NS_A, || {
        assert!(node_a.chunk(snapshot_with_endpoint(a, b, None, 1)).unwrap());
    });
    in_ns(NS_B, || {
        assert!(node_b.chunk(snapshot_with_endpoint(b, a, None, 1)).unwrap());
    });
    in_ns(NS_A, || {
        assert!(
            node_a
                .chunk(snapshot_with_endpoint(a, b, Some(endpoint_b), 2))
                .unwrap()
        );
    });
    let first_initiation_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < first_initiation_deadline && dropped_input_packets(NS_B) == 0 {
        // sleep: wait for GotaTun to send its first packet after the coordinator installs an endpoint
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        dropped_input_packets(NS_B) > 0,
        "node A sent no first packet for the firewall to reject before node B had an endpoint"
    );
    in_ns(NS_B, || {
        assert!(
            node_b
                .chunk(snapshot_with_endpoint(b, a, Some(endpoint_a), 2))
                .unwrap()
        );
    });

    // The test waits on an external protocol event, not a measured duration.
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut handshake_a, mut handshake_b) = (false, false);
    while Instant::now() < deadline && !(handshake_a && handshake_b) {
        handshake_a = node_a
            .counters()
            .unwrap()
            .get(&id_b.public_key)
            .is_some_and(|counters| counters.handshake_secs != 0);
        handshake_b = node_b
            .counters()
            .unwrap()
            .get(&id_a.public_key)
            .is_some_and(|counters| counters.handshake_secs != 0);
        if !(handshake_a && handshake_b) {
            // sleep: allow the GotaTun packet worker and conntrack rules to process each initiation
            thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(
        handshake_a,
        "node A did not establish its direct peer session"
    );
    assert!(
        handshake_b,
        "node B did not establish its direct peer session"
    );
    assert!(
        established_input_packets(NS_A) > 0,
        "node A accepted no UDP packet through its established/related input rule"
    );
    assert!(
        established_input_packets(NS_B) > 0,
        "node B accepted no UDP packet through its established/related input rule"
    );

    let mesh_server = SocketAddr::from(([10, 254, 0, 2], 5_101));
    let listener = in_ns(NS_B, || TcpListener::bind(mesh_server).unwrap());
    let route = run("ip", &["-n", NS_A, "route", "get", "10.254.0.2"]);
    assert!(
        route.contains("dev infraternal0"),
        "mesh route is absent: {route}"
    );
    let blocked = in_ns(NS_A, || {
        TcpStream::connect_timeout(&mesh_server, Duration::from_millis(250))
    });
    assert!(
        blocked.is_err(),
        "new tunnel input passed without the separate infraternal0 rule"
    );

    for ns in [NS_A, NS_B] {
        in_ns(ns, || {
            run(
                "nft",
                &[
                    "insert",
                    "rule",
                    "inet",
                    HOLE_PUNCH_TABLE,
                    "input",
                    "iifname",
                    "infraternal0",
                    "accept",
                ],
            );
        });
    }
    let accept_listener = listener.try_clone().unwrap();
    let server = thread::spawn(move || {
        enter(NS_B);
        let (mut stream, _) = accept_listener.accept().unwrap();
        let mut request = [0; 5];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"hello");
        stream.write_all(b"world").unwrap();
    });
    let mut client = in_ns(NS_A, || {
        TcpStream::connect_timeout(&mesh_server, Duration::from_secs(3)).unwrap()
    });
    client.write_all(b"hello").unwrap();
    let mut response = [0; 5];
    client.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"world");
    server.join().unwrap();
    drop(client);
    drop(listener);

    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    cleanup(&[&state_a, &state_b]);
    fs::remove_file(firewall).unwrap();
}

/// A grant after a deny installs the peer in `GotaTun` (#515): only the Access policy changes, no
/// peer field does, and `GotaTun` installs only peers with network access, so the node must hand
/// the access change to the engine as well as to its firewall.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn a_grant_after_a_deny_reaches_the_gotatun_engine() {
    let (state_a, state_b) = (state("j564-grant-a"), state("j564-grant-b"));
    run("mkdir", &["-p", "/run/netns"]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    cleanup(&[]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "link", "add", "j564a", "netns", NS_A, "type", "veth", "peer", "j564b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &["-n", NS_A, "address", "add", "192.0.2.1/24", "dev", "j564a"],
    );
    run(
        "ip",
        &["-n", NS_B, "address", "add", "192.0.2.2/24", "dev", "j564b"],
    );
    run("ip", &["-n", NS_A, "link", "set", "j564a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j564b", "up"]);
    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, EngineKind::GotaTun).unwrap();
            let identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    let a = (1, id_a.public_key);
    let b = (2, id_b.public_key);
    let endpoint_a = Some(SocketAddr::from(([192, 0, 2, 1], id_a.port)));
    let endpoint_b = Some(SocketAddr::from(([192, 0, 2, 2], id_b.port)));
    for (version, allowed) in [(1, false), (2, true)] {
        in_ns(NS_A, || {
            assert!(
                node_a
                    .chunk(j534_snapshot(a, b, endpoint_b, version, allowed))
                    .unwrap()
            );
        });
        in_ns(NS_B, || {
            assert!(
                node_b
                    .chunk(j534_snapshot(b, a, endpoint_a, version, allowed))
                    .unwrap()
            );
        });
    }
    // The test waits on an external protocol event, not a measured duration.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut handshake = false;
    while Instant::now() < deadline && !handshake {
        handshake = node_a
            .counters()
            .unwrap()
            .get(&id_b.public_key)
            .is_some_and(|counters| counters.handshake_secs != 0);
        if !handshake {
            // sleep: allow the GotaTun workers to exchange the first handshake
            thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(
        handshake,
        "the granted peer never reached the GotaTun engine, so no handshake happened"
    );
    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    cleanup(&[&state_a, &state_b]);
}

/// J585 F4 (#515), end to end: a peer whose candidate walk already found it stays on its working
/// address when an unrelated snapshot is applied later. Before the fix the worker dropped every
/// settled walk, so the next apply started a new one; with the session idle (keepalives add no
/// received bytes, and no new handshake comes within 5 s) that walk moved the peer to its dead
/// second candidate after one step.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn a_settled_walk_survives_a_later_snapshot() {
    let (state_a, state_b) = (state("j587-walk-a"), state("j587-walk-b"));
    run("mkdir", &["-p", "/run/netns"]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    cleanup(&[]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "link", "add", "j587a", "netns", NS_A, "type", "veth", "peer", "j587b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &["-n", NS_A, "address", "add", "192.0.2.1/24", "dev", "j587a"],
    );
    run(
        "ip",
        &["-n", NS_B, "address", "add", "192.0.2.2/24", "dev", "j587b"],
    );
    run("ip", &["-n", NS_A, "link", "set", "j587a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j587b", "up"]);
    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, EngineKind::GotaTun).unwrap();
            let identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    let a = (1, id_a.public_key);
    let b = (2, id_b.public_key);
    let working = SocketAddr::from(([192, 0, 2, 2], id_b.port));
    // Nothing listens there: a walk that reaches it loses the peer.
    let dead = SocketAddr::from(([192, 0, 2, 2], id_b.port.wrapping_add(1)));
    let for_a = |version| {
        let mut chunk = j534_snapshot(a, b, Some(working), version, true);
        for policy in chunk.upserted.values_mut() {
            policy.peer.candidates = vec![dead];
        }
        chunk
    };
    let started = Instant::now();
    in_ns(NS_A, || assert!(node_a.chunk(for_a(1)).unwrap()));
    in_ns(NS_B, || {
        let endpoint_a = Some(SocketAddr::from(([192, 0, 2, 1], id_a.port)));
        assert!(
            node_b
                .chunk(j534_snapshot(b, a, endpoint_a, 1, true))
                .unwrap()
        );
    });
    // The test waits on an external protocol event, not a measured duration.
    let deadline = Instant::now() + Duration::from_secs(10);
    let seen = |node: &Node| node.counters().unwrap().get(&id_b.public_key).cloned();
    while Instant::now() < deadline && seen(&node_a).is_none_or(|c| c.handshake_secs == 0) {
        // sleep: allow the GotaTun workers to exchange the first handshake
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        seen(&node_a).is_some_and(|c| c.handshake_secs != 0),
        "fixture: no handshake on the working address"
    );
    // sleep: let the first walk take its 5 s step, see the handshake and settle
    thread::sleep(
        (started + Duration::from_millis(5_500)).saturating_duration_since(Instant::now()),
    );
    in_ns(NS_A, || assert!(node_a.chunk(for_a(2)).unwrap()));
    // sleep: one walk step (5 s) and margin, still well before B's first 25 s keepalive
    thread::sleep(Duration::from_millis(6_500));
    let endpoint = seen(&node_a).and_then(|c| c.endpoint);
    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    cleanup(&[&state_a, &state_b]);
    assert_eq!(
        endpoint,
        Some(working),
        "an idle, established peer was walked off its working address"
    );
}

/// J602 F1 (#515): a list change that keeps the first address must not pin a found peer to it.
///
/// Node A's list for B is a dead first address and B's working address second, the shape of a
/// LAN candidate from another site under one shared public address. A finds B on the second
/// one. Then only the tail of the list changes, as when B's NAT rebinds and the coordinator
/// republishes B's reflexive address while the LAN address stays first. `apply` re-installs the
/// changed peer, which moves the engine back to the dead first address while keeping the session.
/// `refresh_walks` sees the first address unchanged and the engine on it with a live handshake,
/// so the new walk starts finished ("live on its first address"). Nothing moves A off the dead
/// address; only a packet from B could, and behind a filtering NAT none gets through.
///
/// J699 P3-3: the re-install itself must not move the engine off the working address either,
/// which is still on the new list; it used to cost the found peer up to one walk step (5 s).
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn a_changed_tail_does_not_pin_a_found_peer_to_a_dead_first_address() {
    let (state_a, state_b) = (state("j602-tail-a"), state("j602-tail-b"));
    run("mkdir", &["-p", "/run/netns"]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    cleanup(&[]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "link", "add", "j602a", "netns", NS_A, "type", "veth", "peer", "j602b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &["-n", NS_A, "address", "add", "192.0.2.1/24", "dev", "j602a"],
    );
    run(
        "ip",
        &["-n", NS_B, "address", "add", "192.0.2.2/24", "dev", "j602b"],
    );
    run("ip", &["-n", NS_A, "link", "set", "j602a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j602b", "up"]);
    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, EngineKind::GotaTun).unwrap();
            let identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    let a = (1, id_a.public_key);
    let b = (2, id_b.public_key);
    let working = SocketAddr::from(([192, 0, 2, 2], id_b.port));
    // Nothing listens on either: a node sending there has lost its peer.
    let dead = SocketAddr::from(([192, 0, 2, 2], id_b.port.wrapping_add(1)));
    let other_dead = SocketAddr::from(([192, 0, 2, 2], id_b.port.wrapping_add(2)));
    let for_a = |version, tail: Vec<SocketAddr>| {
        let mut chunk = j534_snapshot(a, b, Some(dead), version, true);
        for policy in chunk.upserted.values_mut() {
            policy.peer.candidates.clone_from(&tail);
        }
        chunk
    };
    in_ns(NS_A, || {
        assert!(node_a.chunk(for_a(1, vec![working])).unwrap());
    });
    in_ns(NS_B, || {
        let endpoint_a = Some(SocketAddr::from(([192, 0, 2, 1], id_a.port)));
        assert!(
            node_b
                .chunk(j534_snapshot(b, a, endpoint_a, 1, true))
                .unwrap()
        );
    });
    let seen = |node: &Node| node.counters().unwrap().get(&id_b.public_key).cloned();
    // The test waits on an external protocol event, not a measured duration: B's initiation
    // reaches A, and A's engine follows it to the working address.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline
        && seen(&node_a).is_none_or(|c| c.handshake_secs == 0 || c.endpoint != Some(working))
    {
        // sleep: allow the GotaTun workers to exchange the first handshake
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        seen(&node_a).is_some_and(|c| c.handshake_secs != 0 && c.endpoint == Some(working)),
        "fixture: A never reached B on the working address"
    );
    // sleep: one walk step (5 s) and margin, so A's first walk sees the peer and settles
    thread::sleep(Duration::from_millis(5_500));
    // Only the tail changes; the dead first address stays first.
    in_ns(NS_A, || {
        assert!(node_a.chunk(for_a(2, vec![working, other_dead])).unwrap());
    });
    // J699 P3-3: the re-install keeps the engine on the address it found, which is still on
    // the new list, so the peer loses no walk step to the change.
    let right_after = seen(&node_a).and_then(|c| c.endpoint);
    // sleep: one walk step (5 s) and margin, still before B's first 25 s keepalive
    thread::sleep(Duration::from_millis(6_500));
    let endpoint = seen(&node_a).and_then(|c| c.endpoint);
    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    cleanup(&[&state_a, &state_b]);
    assert_eq!(
        right_after,
        Some(working),
        "the config change moved a found peer off its working address"
    );
    assert_ne!(
        endpoint,
        Some(dead),
        "a found peer was pinned to its dead first address after a tail-only list change"
    );
}

/// Write `rules` to a file under `dir` and load it with `nft -f` inside `ns`.
fn j603_nft(ns: &str, dir: &Path, rules: &str) {
    let path = dir.join("j603.nft");
    fs::write(&path, rules).unwrap();
    in_ns(ns, || run("nft", &["-f", path.to_str().unwrap()]));
    fs::remove_file(path).unwrap();
}

/// Make A's mesh socket appear on the underlay as `outside` instead of its own `port`, the way a
/// NAT's mapping does. The rewrite is stateless (`notrack`), so changing `outside` is a rebind:
/// packets to the old outside port reach nobody from then on.
fn j603_map_a(dir: &Path, port: u16, outside: u16, first: bool) {
    let reset = if first { "" } else { "delete table ip j603\n" };
    let rules = format!(
        "{reset}table ip j603 {{\n\
         chain out {{ type filter hook output priority raw; policy accept;\n\
          udp sport {port} notrack udp sport set {outside}\n }}\n\
         chain pre {{ type filter hook prerouting priority raw; policy accept;\n\
          udp dport {outside} notrack udp dport set {port}\n }}\n}}\n"
    );
    j603_nft(NS_A, dir, &rules);
}

/// #515 (J587's finding, J603): an established peer behind a filtering NAT rebinds, and the path
/// comes back within one walk step plus a handshake.
///
/// B accepts underlay UDP on its mesh port only from an address and port it has sent to (an
/// address-and-port-dependent filter, as a typical home router's). A's mesh port is mapped to an
/// outside port by a stateless rewrite. After a session is up, B sends last, A rebinds to a new
/// outside port, and B is given that port as its new first address (the coordinator's
/// republication). A's packets from the new port are dropped at B's filter until B sends there.
///
/// Before the fix B sent nothing there: `GotaTun`'s forced handshake is a no-op while a session
/// exists, so the walk's steps changed only the address, and the path came back only when B's own
/// timers fired (15–25 s later here, 10–65 s in the NAT matrix). With the fix (J604) the new
/// address gets a real handshake at once (`GotaTun`'s `rehandshake`), over the old session, so
/// the path is back about one round trip after the republication.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn a_rebound_established_peer_comes_back_within_one_walk_step() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    const PROBE_PORT: u16 = 5603;
    let (state_a, state_b) = (state("j603-a"), state("j603-b"));
    run("mkdir", &["-p", "/run/netns"]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    cleanup(&[]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "link", "add", "j603a", "netns", NS_A, "type", "veth", "peer", "j603b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &["-n", NS_A, "address", "add", "192.0.2.1/24", "dev", "j603a"],
    );
    run(
        "ip",
        &["-n", NS_B, "address", "add", "192.0.2.2/24", "dev", "j603b"],
    );
    run("ip", &["-n", NS_A, "link", "set", "j603a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j603b", "up"]);
    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, EngineKind::GotaTun).unwrap();
            let identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    let a = (1, id_a.public_key);
    let b = (2, id_b.public_key);
    let (old_outside, new_outside, never) = (41_001, 41_002, 41_003);
    j603_map_a(&state_a, id_a.port, old_outside, true);
    j603_nft(
        NS_B,
        &state_b,
        &format!(
            "table inet j603 {{\n chain input {{ type filter hook input priority filter; \
             policy accept;\n  udp dport {} ct state established accept\n  udp dport {} drop\n \
             }}\n}}\n",
            id_b.port, id_b.port
        ),
    );
    let a_at = |port: u16| SocketAddr::from(([192, 0, 2, 1], port));
    // What B is told about A: a first address and one more candidate, so B walks.
    let for_b = |version, first: u16, other: u16| {
        let mut chunk = j534_snapshot(b, a, Some(a_at(first)), version, true);
        for policy in chunk.upserted.values_mut() {
            policy.peer.candidates = vec![a_at(other)];
        }
        chunk
    };
    let endpoint_b = Some(SocketAddr::from(([192, 0, 2, 2], id_b.port)));
    in_ns(NS_A, || {
        assert!(
            node_a
                .chunk(j534_snapshot(a, b, endpoint_b, 1, true))
                .unwrap()
        );
    });
    in_ns(NS_B, || {
        assert!(node_b.chunk(for_b(1, old_outside, never)).unwrap());
    });
    let mesh_a = SocketAddr::from((addresses(1).ipv4, PROBE_PORT));
    let mesh_b = SocketAddr::from((addresses(2).ipv4, PROBE_PORT));
    let sender_b = in_ns(NS_B, || UdpSocket::bind("0.0.0.0:0").unwrap());
    let listener_b = in_ns(NS_B, || UdpSocket::bind(mesh_b).unwrap());
    listener_b
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let sender_a = in_ns(NS_A, || UdpSocket::bind("0.0.0.0:0").unwrap());
    // B opens its filter for A by sending first, as a node behind such a NAT must.
    let deadline = Instant::now() + Duration::from_secs(10);
    let handshake = |node: &Node| {
        node.counters()
            .unwrap()
            .get(&id_a.public_key)
            .is_some_and(|counters| counters.handshake_secs != 0)
    };
    while Instant::now() < deadline && !handshake(&node_b) {
        let _ = sender_b.send_to(b"open", mesh_a);
        // sleep: allow the GotaTun workers to exchange the first handshake
        thread::sleep(Duration::from_millis(200));
    }
    assert!(handshake(&node_b), "fixture: no session between A and B");
    // A streams small datagrams to B for the rest of the test; `paused` holds them back.
    let paused = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let streamer = {
        let (paused, stop) = (Arc::clone(&paused), Arc::clone(&stop));
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if !paused.load(Ordering::Relaxed) {
                    let _ = sender_a.send_to(b"flow", mesh_b);
                }
                // sleep: the stream's pacing, one datagram every 50 ms
                thread::sleep(Duration::from_millis(50));
            }
        })
    };
    let arrival = |deadline: Instant| {
        let mut buffer = [0_u8; 16];
        while Instant::now() < deadline {
            if listener_b.recv(&mut buffer).is_ok() {
                return Some(Instant::now());
            }
        }
        None
    };
    assert!(
        arrival(Instant::now() + Duration::from_secs(10)).is_some(),
        "fixture: A's stream never reached B before the rebind"
    );
    // B sends last before the rebind, so none of its own timers is about to send for it: its
    // next keepalive is 25 s away, and A's later packets never reach it to ask for one.
    paused.store(true, Ordering::Relaxed);
    // sleep: let A's last datagrams land before B's final send
    thread::sleep(Duration::from_millis(200));
    sender_b.send_to(b"last", mesh_a).unwrap();
    // sleep: B's datagram crosses before the mapping changes under it
    thread::sleep(Duration::from_millis(200));
    j603_map_a(&state_a, id_a.port, new_outside, false);
    let mut drain = [0_u8; 16];
    while listener_b.recv(&mut drain).is_ok() {}
    let republished = Instant::now();
    in_ns(NS_B, || {
        assert!(node_b.chunk(for_b(2, new_outside, old_outside)).unwrap());
    });
    paused.store(false, Ordering::Relaxed);
    let budget = infraternal_plugin_mesh::candidates::STEP + Duration::from_secs(3);
    let recovered = arrival(republished + Duration::from_secs(30));
    stop.store(true, Ordering::Relaxed);
    streamer.join().unwrap();
    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    cleanup(&[&state_a, &state_b]);
    let took = recovered.map(|at| at.saturating_duration_since(republished));
    eprintln!("j603 rebind recovery after republication: {took:?}");
    assert!(
        took.is_some_and(|took| took <= budget),
        "the rebound peer came back after {took:?}, not within one walk step plus a handshake \
         ({budget:?})"
    );
}

/// Build a peer snapshot with either full directional network access or no access.
fn j534_snapshot(
    local: (u32, PublicKey),
    peer: (u32, PublicKey),
    endpoint: Option<SocketAddr>,
    version: u64,
    allowed: bool,
) -> Chunk {
    let mut chunk = snapshot_with_endpoint(local, peer, endpoint, version);
    chunk.default_policy = DefaultPolicy::Allow;
    for policy in chunk.upserted.values_mut() {
        let access = if allowed {
            TrafficPolicy::All
        } else {
            TrafficPolicy::None
        };
        policy.inbound = access.clone();
        policy.outbound = access;
    }
    chunk
}

/// Build a test-only MAC1-valid initiation without printing the ephemeral peer secret.
fn j534_mac1_initiation(secret_bytes: [u8; 32], receiver: PublicKey) -> (PublicKey, Vec<u8>) {
    let secret = gotatun::x25519::StaticSecret::from(secret_bytes);
    let public = gotatun::x25519::PublicKey::from(&secret);
    let mut initiator = gotatun::noise::Tunn::new(
        secret,
        gotatun::x25519::PublicKey::from(receiver.0),
        None,
        None,
        gotatun::noise::index_table::IndexTable::from_os_rng(),
        std::sync::Arc::new(gotatun::noise::rate_limiter::RateLimiter::new(&public, 100)),
    );
    let initiation = initiator
        .format_handshake_initiation(false)
        .expect("the test peer can produce a public-key-valid MAC1 initiation")
        .into_bytes();
    (PublicKey(*public.as_bytes()), initiation.as_ref().to_vec())
}

/// Read one marked nft rule's handle and packet count in its own network namespace.
fn j534_rule(ns: &str, marker: &str) -> (String, u64) {
    in_ns(ns, || {
        let chain = run(
            "nft",
            &["-a", "list", "chain", "inet", HOLE_PUNCH_TABLE, "input"],
        );
        let line = chain
            .lines()
            .find(|line| line.contains(marker))
            .unwrap_or_else(|| panic!("{ns} has no nft rule marked {marker:?}: {chain}"));
        let handle = line
            .split("handle ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .unwrap_or_else(|| panic!("{ns} nft rule has no handle: {line}"))
            .to_owned();
        let packets = line
            .split("packets ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("{ns} nft rule has no packet count: {line}"));
        (handle, packets)
    })
}

/// Read one marked nft output rule's handle and packet count in its network namespace.
fn j534_output_rule(ns: &str, marker: &str) -> (String, u64) {
    in_ns(ns, || {
        let chain = run(
            "nft",
            &["-a", "list", "chain", "inet", J534_OUTPUT_TABLE, "output"],
        );
        let line = chain
            .lines()
            .find(|line| line.contains(marker))
            .unwrap_or_else(|| panic!("{ns} has no nft output rule marked {marker:?}: {chain}"));
        let handle = line
            .split("handle ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .unwrap_or_else(|| panic!("{ns} nft output rule has no handle: {line}"))
            .to_owned();
        let packets = line
            .split("packets ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("{ns} nft output rule has no packet count: {line}"));
        (handle, packets)
    })
}

/// Read one marked nft postrouting NAT rule's handle and packet count in its network namespace.
fn j534_nat_rule(ns: &str, marker: &str) -> (String, u64) {
    in_ns(ns, || {
        let chain = run(
            "nft",
            &["-a", "list", "chain", "ip6", "j534_nat", "postrouting"],
        );
        let line = chain
            .lines()
            .find(|line| line.contains(marker))
            .unwrap_or_else(|| panic!("{ns} has no nft NAT rule marked {marker:?}: {chain}"));
        let handle = line
            .split("handle ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .unwrap_or_else(|| panic!("{ns} nft NAT rule has no handle: {line}"))
            .to_owned();
        let packets = line
            .split("packets ")
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("{ns} nft NAT rule has no packet count: {line}"));
        (handle, packets)
    })
}

/// Denied and unknown peer keys get no cookie while an allowed peer keeps normal rate limiting.
///
/// `GotaTun` sends cookies only while its handshake backlog is at least 128 messages (#260,
/// J1112), so the allowed peer's flood must outrun the receive task: a thousand replayed
/// initiations sent at once leave hundreds waiting (the guard admits about 400 from one known
/// endpoint per second, and each costs two key agreements). The 101 the old per-source count
/// needed would now be served without a cookie, which is the point of that change.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn peers_without_network_access_get_no_reply_while_registered_peers_keep_cookie_behavior() {
    assert!(
        std::env::var_os("INFRATERNAL_MESH_PORT").is_none(),
        "the case exercises the automatic UDP listener"
    );
    let state_a = state("j534-cookie-a");
    let firewall =
        std::env::temp_dir().join(format!("j534-cookie-nft-{}.conf", std::process::id()));
    fs::write(
        &firewall,
        format!(
            "table inet {HOLE_PUNCH_TABLE} {{\n\
                 chain input {{\n\
                     type filter hook input priority filter; policy drop;\n\
                     iifname \"lo\" accept\n\
                     ct state established,related counter accept\n\
                     counter drop\n\
                 }}\n\
             }}\n"
        ),
    )
    .unwrap();
    run("mkdir", &["-p", "/run/netns"]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    cleanup(&[]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "link", "add", "j534a", "netns", NS_A, "type", "veth", "peer", "j534b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            NS_B,
            "address",
            "add",
            "192.0.2.24/24",
            "dev",
            "j534b",
        ],
    );
    run(
        "ip",
        &["-n", NS_A, "address", "add", "192.0.2.1/24", "dev", "j534a"],
    );
    run(
        "ip",
        &["-n", NS_B, "address", "add", "192.0.2.2/24", "dev", "j534b"],
    );
    run(
        "ip",
        &[
            "-n",
            NS_B,
            "address",
            "add",
            "192.0.2.23/24",
            "dev",
            "j534b",
        ],
    );
    run("ip", &["-n", NS_A, "link", "set", "j534a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j534b", "up"]);
    install_hole_punch_firewall(NS_A, &firewall);
    in_ns(NS_A, || {
        run(
            "nft",
            &[
                "insert",
                "rule",
                "inet",
                HOLE_PUNCH_TABLE,
                "input",
                "udp",
                "dport",
                "10254",
                "counter",
                "accept",
                "comment",
                "j534-cookie-probe",
            ],
        );
    });

    let (mut node_a, id_a) = in_ns(NS_A, || {
        let mut node = Node::restore_with_engine(&state_a, EngineKind::GotaTun).unwrap();
        let identity = node.up().unwrap();
        (node, identity)
    });
    assert_eq!(
        id_a.port, 10_254,
        "the fixture uses the default UDP listener"
    );
    let registered_endpoint = SocketAddr::from(([192, 0, 2, 2], 40_001));
    let denied_endpoint = SocketAddr::from(([192, 0, 2, 23], 40_002));
    let unregistered_endpoint = SocketAddr::from(([192, 0, 2, 24], 40_003));
    let (registered_key, registered_packet) = j534_mac1_initiation([0x66; 32], id_a.public_key);
    let (denied_key, denied_packet) = j534_mac1_initiation([0x77; 32], id_a.public_key);
    let (_, unregistered_packet) = j534_mac1_initiation([0x55; 32], id_a.public_key);
    let registered_socket = in_ns(NS_B, || {
        let socket = UdpSocket::bind(registered_endpoint).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        socket
    });
    let denied_socket = in_ns(NS_B, || {
        let socket = UdpSocket::bind(denied_endpoint).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        socket
    });
    let unregistered_socket = in_ns(NS_B, || {
        let socket = UdpSocket::bind(unregistered_endpoint).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        socket
    });
    let mut snapshot = j534_snapshot(
        (1, id_a.public_key),
        (2, registered_key),
        Some(registered_endpoint),
        1,
        true,
    );
    let denied_snapshot = j534_snapshot(
        (1, id_a.public_key),
        (3, denied_key),
        Some(denied_endpoint),
        1,
        false,
    );
    snapshot.upserted.extend(denied_snapshot.upserted);
    in_ns(NS_A, || node_a.chunk(snapshot).unwrap());
    let listener = SocketAddr::from(([192, 0, 2, 1], id_a.port));

    let denied_reply = in_ns(NS_B, || {
        for _ in 0..101 {
            denied_socket.send_to(&denied_packet, listener).unwrap();
        }
        let mut packet = [0_u8; 128];
        denied_socket.recv_from(&mut packet)
    });
    assert!(
        denied_reply.is_err(),
        "a configured peer with no network access received a UDP reply: {denied_reply:?}"
    );

    let unregistered_reply = in_ns(NS_B, || {
        for _ in 0..101 {
            unregistered_socket
                .send_to(&unregistered_packet, listener)
                .unwrap();
        }
        let mut packet = [0_u8; 128];
        unregistered_socket.recv_from(&mut packet)
    });
    assert!(
        unregistered_reply.is_err(),
        "an unknown valid-MAC1 sender received a UDP reply: {unregistered_reply:?}"
    );

    let registered_cookie = in_ns(NS_B, || {
        for _ in 0..J534_REGISTERED_FLOOD {
            registered_socket
                .send_to(&registered_packet, listener)
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut packet = [0_u8; 128];
        loop {
            match registered_socket.recv_from(&mut packet) {
                Ok((length, source)) if length == 64 && packet[..4] == [3, 0, 0, 0] => {
                    return Some((length, source));
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => panic!("registered socket receive failed: {error}"),
            }
            if Instant::now() >= deadline {
                return None;
            }
        }
    });
    assert_eq!(
        registered_cookie,
        Some((64, listener)),
        "a configured peer with network access keeps the standard cookie response under load"
    );
    assert!(
        j534_rule(NS_A, "j534-cookie-probe").1 >= 202 + J534_REGISTERED_FLOOD,
        "all three packet floods must reach the listener before its response is checked"
    );

    in_ns(NS_A, || node_a.down().unwrap());
    drop((registered_socket, denied_socket, unregistered_socket));
    cleanup(&[&state_a]);
    fs::remove_file(firewall).unwrap();
}

/// How many replayed initiations the allowed peer sends at once in the j534 cookie case: enough
/// to build `GotaTun`'s handshake backlog past its under-load mark of 128.
const J534_REGISTERED_FLOOD: u64 = 1_000;

/// Delete a marked nft rule after a controlled adversarial packet phase.
fn j534_delete_rule(ns: &str, marker: &str) {
    let (handle, _) = j534_rule(ns, marker);
    in_ns(ns, || {
        run(
            "nft",
            &[
                "delete",
                "rule",
                "inet",
                HOLE_PUNCH_TABLE,
                "input",
                "handle",
                &handle,
            ],
        );
    });
}

/// Wait for IPv6 duplicate-address detection before a fixture binds a socket to a new address.
fn j534_wait_for_ipv6_address(ns: &str, interface: &str, address: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let output = run(
            "ip",
            &["-n", ns, "-6", "-o", "address", "show", "dev", interface],
        );
        let line = output
            .lines()
            .find(|line| line.split_whitespace().any(|field| field == address))
            .unwrap_or_else(|| panic!("{ns} has no IPv6 address {address}: {output}"));
        assert!(
            !line.contains("dadfailed"),
            "{ns} IPv6 address failed duplicate detection: {line}"
        );
        if !line.contains("tentative") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{ns} IPv6 address did not finish duplicate detection: {line}"
        );
        // sleep: Linux completes duplicate-address detection asynchronously after an address is added.
        thread::sleep(Duration::from_millis(10));
    }
}

/// Poll both nodes until each records a completed handshake with the other, returning elapsed ms.
fn j534_wait_for_handshakes(
    node_a: &Node,
    key_b: &PublicKey,
    node_b: &Node,
    key_a: &PublicKey,
    context: &str,
) -> u128 {
    let handshake_started = Instant::now();
    let handshake_deadline = handshake_started + Duration::from_secs(20);
    let (mut handshake_a, mut handshake_b) = (false, false);
    while Instant::now() < handshake_deadline && !(handshake_a && handshake_b) {
        handshake_a = node_a
            .counters()
            .unwrap()
            .get(key_b)
            .is_some_and(|counters| counters.handshake_secs != 0);
        handshake_b = node_b
            .counters()
            .unwrap()
            .get(key_a)
            .is_some_and(|counters| counters.handshake_secs != 0);
        if !(handshake_a && handshake_b) {
            // sleep: poll until both direct handshakes arrive or the deadline expires.
            thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(
        handshake_a,
        "node A did not establish handshake ({context})"
    );
    assert!(
        handshake_b,
        "node B did not establish handshake ({context})"
    );
    handshake_started.elapsed().as_millis()
}

/// Exercise simultaneous IPv6 endpoint delivery, grants, NAT rebinding, and UDP reflection.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft."]
fn simultaneous_ipv6_punch_rebinding_and_tunnel_grants() {
    assert!(
        std::env::var_os("INFRATERNAL_MESH_PORT").is_none(),
        "the case exercises the automatic UDP listener"
    );
    let (state_a, state_b) = (state("j534-a"), state("j534-b"));
    let firewall = std::env::temp_dir().join(format!("j534-nft-{}.conf", std::process::id()));
    let nat_rules = std::env::temp_dir().join(format!("j534-nat-{}.conf", std::process::id()));
    let reflection_rules =
        std::env::temp_dir().join(format!("j534-reflection-{}.conf", std::process::id()));
    fs::write(
        &firewall,
        format!(
            "table inet {HOLE_PUNCH_TABLE} {{\n\
                 chain input {{\n\
                     type filter hook input priority filter; policy drop;\n\
                     iifname \"lo\" accept\n\
                     icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept\n\
                     ct state established,related counter accept\n\
                     counter drop\n\
                 }}\n\
             }}\n"
        ),
    )
    .unwrap();
    run("mkdir", &["-p", "/run/netns"]);
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    cleanup(&[]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    run(
        "ip",
        &[
            "link", "add", "j534a", "netns", NS_A, "type", "veth", "peer", "j534b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &["-n", NS_A, "address", "add", "192.0.2.1/24", "dev", "j534a"],
    );
    run(
        "ip",
        &["-n", NS_B, "address", "add", "192.0.2.2/24", "dev", "j534b"],
    );
    run(
        "ip",
        &[
            "-n",
            NS_A,
            "address",
            "add",
            "2001:db8:1::1/64",
            "dev",
            "j534a",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            NS_B,
            "address",
            "add",
            "2001:db8:1::2/64",
            "dev",
            "j534b",
        ],
    );
    run("ip", &["-n", NS_A, "link", "set", "j534a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j534b", "up"]);
    install_hole_punch_firewall(NS_A, &firewall);
    install_hole_punch_firewall(NS_B, &firewall);
    let output_rules =
        std::env::temp_dir().join(format!("j534-output-{}.conf", std::process::id()));
    fs::write(
        &output_rules,
        format!(
            "table inet {J534_OUTPUT_TABLE} {{\n\
                 chain output {{ type filter hook output priority filter; policy accept;\n\
                     udp dport 10254 counter accept comment \"j534-output\"\n\
                 }}\n\
             }}\n"
        ),
    )
    .unwrap();
    for ns in [NS_A, NS_B] {
        in_ns(ns, || run("nft", &["-f", output_rules.to_str().unwrap()]));
    }
    // Keep the live UDP peer flow while allowing its old conntrack mapping to expire quickly.
    for setting in [
        "net.netfilter.nf_conntrack_udp_timeout=1",
        "net.netfilter.nf_conntrack_udp_timeout_stream=1",
    ] {
        in_ns(NS_B, || run("sysctl", &["-w", setting]));
    }

    // The app-owned host input accepts TCP on 10254 while the mesh binds UDP 10254.
    let tcp_health = in_ns(NS_A, || TcpListener::bind("0.0.0.0:10254").unwrap());
    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, EngineKind::GotaTun).unwrap();
            let identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    assert_eq!(id_a.port, 10_254, "node A uses the default UDP listener");
    assert_eq!(id_b.port, 10_254, "node B uses the default UDP listener");
    let a = (1, id_a.public_key);
    let b = (2, id_b.public_key);
    let underlay_a: std::net::Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let underlay_b: std::net::Ipv6Addr = "2001:db8:1::2".parse().unwrap();
    let endpoint_a = SocketAddr::new(underlay_a.into(), id_a.port);
    let endpoint_b = SocketAddr::new(underlay_b.into(), id_b.port);

    // Admit each node's actual UDP listener, matching host policy while keeping tunnel input separate.
    for (ns, port) in [(NS_A, id_a.port), (NS_B, id_b.port)] {
        let port = port.to_string();
        in_ns(ns, || {
            run(
                "nft",
                &[
                    "insert",
                    "rule",
                    "inet",
                    HOLE_PUNCH_TABLE,
                    "input",
                    "udp",
                    "dport",
                    &port,
                    "counter",
                    "accept",
                    "comment",
                    "j534-wireguard-listener",
                ],
            );
        });
    }

    // Create the peer engines before injecting packets; endpoint-less peers do not start a punch.
    thread::scope(|scope| {
        let a_update = scope.spawn(|| {
            in_ns(NS_A, || {
                node_a.chunk(j534_snapshot(a, b, None, 1, true)).unwrap()
            })
        });
        let b_update = scope.spawn(|| {
            in_ns(NS_B, || {
                node_b.chunk(j534_snapshot(b, a, None, 1, true)).unwrap()
            })
        });
        assert!(a_update.join().unwrap());
        assert!(b_update.join().unwrap());
    });

    // Let malformed traffic reach the engine so this check observes its response behavior.
    in_ns(NS_A, || {
        run(
            "nft",
            &[
                "insert",
                "rule",
                "inet",
                HOLE_PUNCH_TABLE,
                "input",
                "udp",
                "dport",
                "10254",
                "counter",
                "accept",
                "comment",
                "j534-untrusted-probe",
            ],
        );
    });
    run(
        "ip",
        &[
            "-n",
            NS_B,
            "address",
            "add",
            "2001:db8:1::23/64",
            "dev",
            "j534b",
        ],
    );
    j534_wait_for_ipv6_address(NS_B, "j534b", "2001:db8:1::23/64");
    fs::write(
        &reflection_rules,
        format!(
            "add rule inet {J534_OUTPUT_TABLE} output ip6 daddr 2001:db8:1::23 udp dport 40003 counter comment \"j534-reflection\"\n"
        ),
    )
    .unwrap();
    in_ns(NS_A, || {
        run("nft", &["-f", reflection_rules.to_str().unwrap()])
    });
    let untrusted = in_ns(NS_B, || {
        let socket = UdpSocket::bind("[2001:db8:1::23]:40001").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        for _ in 0..100 {
            socket
                .send_to(b"not-a-wireguard-handshake", "[2001:db8:1::1]:10254")
                .unwrap();
        }
        socket
    });
    let mut response = [0_u8; 128];
    let reply = untrusted.recv_from(&mut response);
    assert!(
        reply.is_err(),
        "an unauthenticated packet caused a UDP response to an arbitrary endpoint: {reply:?}"
    );

    // MAC1 is computable from the receiver's public key. A flood crosses the rate limiter's
    // per-source threshold; the unregistered source must still receive no UDP reply.
    let (_, initiation) = j534_mac1_initiation([0x55; 32], id_a.public_key);
    let unauthenticated_reply = in_ns(NS_B, || {
        let socket = UdpSocket::bind("[2001:db8:1::23]:40003").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        for _ in 0..101 {
            socket
                .send_to(&initiation, "[2001:db8:1::1]:10254")
                .unwrap();
        }
        let mut packet = [0_u8; 128];
        socket.recv_from(&mut packet)
    });
    assert!(
        unauthenticated_reply.is_err(),
        "an unregistered valid-MAC1 sender received a UDP reply: {unauthenticated_reply:?}"
    );
    let output = in_ns(NS_A, || {
        run(
            "nft",
            &["list", "chain", "inet", J534_OUTPUT_TABLE, "output"],
        )
    });
    let reflection = output
        .lines()
        .find(|line| line.contains("j534-reflection"))
        .unwrap_or_else(|| panic!("no output counter for the unregistered peer address: {output}"));
    let reflected_packets = reflection
        .split("packets ")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .and_then(|count| count.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("the reflection output rule has no packet count: {reflection}"));
    assert_eq!(
        reflected_packets, 0,
        "the listener reflected a cookie to an unregistered endpoint: {output}"
    );
    eprintln!(
        "J534_METRIC unauth_cookie_reply_bytes=0 reflected_packets={reflected_packets} reflected_reply_bytes=0 requests=101 request_bytes_each={} request_bytes_total={}",
        initiation.len(),
        initiation.len() * 101
    );
    j534_delete_rule(NS_A, "j534-untrusted-probe");
    drop(untrusted);
    in_ns(NS_B, || {
        run(
            "ip",
            &["-6", "address", "del", "2001:db8:1::23/64", "dev", "j534b"],
        );
    });
    let mesh_server_a = SocketAddr::from(([10, 254, 0, 1], 5_102));
    let mesh_server_b = SocketAddr::from(([10, 254, 0, 2], 5_101));
    let listener_a = in_ns(NS_A, || TcpListener::bind(mesh_server_a).unwrap());
    let listener_b = in_ns(NS_B, || TcpListener::bind(mesh_server_b).unwrap());
    let route_a = in_ns(NS_A, || run("ip", &["route", "get", "10.254.0.2"]));
    let route_b = in_ns(NS_B, || run("ip", &["route", "get", "10.254.0.1"]));
    assert!(
        route_a.contains("dev infraternal0"),
        "A mesh route: {route_a}"
    );
    assert!(
        route_b.contains("dev infraternal0"),
        "B mesh route: {route_b}"
    );
    eprintln!("J534_ROUTE_A={route_a} J534_ROUTE_B={route_b}");

    // Enroll both IPv6 endpoints together so the test exercises the simultaneous punch path.
    let simultaneous_start = std::sync::Barrier::new(3);
    thread::scope(|scope| {
        let a_update = scope.spawn(|| {
            simultaneous_start.wait();
            in_ns(NS_A, || {
                node_a
                    .chunk(j534_snapshot(a, b, Some(endpoint_b), 2, true))
                    .unwrap()
            })
        });
        let b_update = scope.spawn(|| {
            simultaneous_start.wait();
            in_ns(NS_B, || {
                node_b
                    .chunk(j534_snapshot(b, a, Some(endpoint_a), 2, true))
                    .unwrap()
            })
        });
        simultaneous_start.wait();
        assert!(a_update.join().unwrap());
        assert!(b_update.join().unwrap());
    });
    let simultaneous_handshake_ms = j534_wait_for_handshakes(
        &node_a,
        &id_b.public_key,
        &node_b,
        &id_a.public_key,
        "simultaneous IPv6 direct path",
    );
    eprintln!("J534_METRIC simultaneous_ipv6_handshake_ms={simultaneous_handshake_ms}");
    // Grant decrypted tunnel input only after the direct underlay handshake is established.
    for ns in [NS_A, NS_B] {
        in_ns(ns, || {
            run(
                "nft",
                &[
                    "insert",
                    "rule",
                    "inet",
                    HOLE_PUNCH_TABLE,
                    "input",
                    "iifname",
                    "infraternal0",
                    "accept",
                ],
            );
        });
    }
    let client_a = thread::spawn(move || {
        in_ns(NS_A, || {
            TcpStream::connect_timeout(&mesh_server_b, Duration::from_secs(20))
        })
    });
    let client_b = thread::spawn(move || {
        in_ns(NS_B, || {
            TcpStream::connect_timeout(&mesh_server_a, Duration::from_secs(20))
        })
    });
    let client_stream_a = client_a
        .join()
        .unwrap()
        .expect("A's simultaneous tunnel connection");
    let client_stream_b = client_b
        .join()
        .unwrap()
        .expect("B's simultaneous tunnel connection");
    let (server_stream_a, _) = listener_a.accept().unwrap();
    let (server_stream_b, _) = listener_b.accept().unwrap();
    client_stream_b
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    server_stream_a
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    drop((client_stream_a, server_stream_b));
    thread::scope(|scope| {
        let a_update = scope.spawn(|| {
            in_ns(NS_A, || {
                node_a
                    .chunk(j534_snapshot(a, b, Some(endpoint_b), 3, false))
                    .unwrap()
            })
        });
        let b_update = scope.spawn(|| {
            in_ns(NS_B, || {
                node_b
                    .chunk(j534_snapshot(b, a, Some(endpoint_a), 3, false))
                    .unwrap()
            })
        });
        assert!(a_update.join().unwrap());
        assert!(b_update.join().unwrap());
    });
    let no_grant = in_ns(NS_A, || {
        TcpStream::connect_timeout(&mesh_server_b, Duration::from_millis(300))
    });
    assert!(
        no_grant.is_err(),
        "the host infraternal0 accept bypassed a peer with no mesh grant"
    );

    thread::scope(|scope| {
        let a_update = scope.spawn(|| {
            in_ns(NS_A, || {
                node_a
                    .chunk(j534_snapshot(a, b, Some(endpoint_b), 4, true))
                    .unwrap()
            })
        });
        let b_update = scope.spawn(|| {
            in_ns(NS_B, || {
                node_b
                    .chunk(j534_snapshot(b, a, Some(endpoint_a), 4, true))
                    .unwrap()
            })
        });
        assert!(a_update.join().unwrap());
        assert!(b_update.join().unwrap());
    });
    let restore_handshake_ms = j534_wait_for_handshakes(
        &node_a,
        &id_b.public_key,
        &node_b,
        &id_a.public_key,
        "after grant restoration",
    );
    eprintln!("J534_METRIC restore_handshake_ms={restore_handshake_ms}");
    let granted = in_ns(NS_A, || {
        TcpStream::connect_timeout(&mesh_server_b, Duration::from_secs(3))
    });
    assert!(granted.is_ok(), "a granted tunnel connection was blocked");
    drop(granted);
    drop(listener_b);

    // Snapshot v3 removed the peers, so do not mistake a pre-revocation TCP socket for a live
    // data path after v4 restores them. Start and exercise the flow that will survive the NAT move.
    drop((client_stream_b, server_stream_a));
    let mut client_stream_b = in_ns(NS_B, || {
        TcpStream::connect_timeout(&mesh_server_a, Duration::from_secs(3))
    })
    .expect("a granted B-to-A tunnel connection");
    let (mut server_stream_a, _) = listener_a.accept().unwrap();
    client_stream_b
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    server_stream_a
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client_stream_b.write_all(b"baseline-request").unwrap();
    let mut baseline_request = [0; 16];
    server_stream_a.read_exact(&mut baseline_request).unwrap();
    assert_eq!(&baseline_request, b"baseline-request");
    server_stream_a.write_all(b"baseline-response").unwrap();
    let mut baseline_response = [0; 17];
    client_stream_b.read_exact(&mut baseline_response).unwrap();
    assert_eq!(&baseline_response, b"baseline-response");

    // Add an address for B's new public NAT mapping while keeping its local UDP socket and address.
    run(
        "ip",
        &[
            "-n",
            NS_B,
            "address",
            "add",
            "2001:db8:1::22/64",
            "dev",
            "j534b",
        ],
    );
    j534_wait_for_ipv6_address(NS_B, "j534b", "2001:db8:1::22/64");
    let rebound_route = in_ns(NS_B, || run("ip", &["-6", "route", "get", "2001:db8:1::1"]));
    assert!(
        rebound_route.contains("dev j534b"),
        "node B cannot route to the peer through its underlay: {rebound_route}"
    );
    fs::write(
        &nat_rules,
        "table ip6 j534_nat {\n\
             chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n\
                 ip6 daddr 2001:db8:1::1 udp sport 10254 counter snat to [2001:db8:1::22]:40002 comment \"j534-rebound-snat\"\n\
             }\n\
         }\n",
    )
    .unwrap();
    in_ns(NS_B, || run("nft", &["-f", nat_rules.to_str().unwrap()]));
    let listener_port = id_a.port.to_string();
    let rebound_address: std::net::Ipv6Addr = "2001:db8:1::22".parse().unwrap();
    let rebound_port = 40_002_u16;
    // Count packets from the rebound address without opening a new rule or changing peer state.
    in_ns(NS_A, || {
        run(
            "nft",
            &[
                "insert",
                "rule",
                "inet",
                HOLE_PUNCH_TABLE,
                "input",
                "ip6",
                "saddr",
                "2001:db8:1::22",
                "udp",
                "dport",
                &listener_port,
                "counter",
                "comment",
                "j534-rebound-observe",
            ],
        );
    });
    let rebound_endpoint = SocketAddr::new(rebound_address.into(), rebound_port);
    let rebound_packets_before = j534_rule(NS_A, "j534-rebound-observe").1;
    let output_before = j534_output_rule(NS_B, "j534-output").1;
    let snat_before = j534_nat_rule(NS_B, "j534-rebound-snat").1;
    let nat_before = in_ns(NS_B, || {
        run("nft", &["list", "chain", "ip6", "j534_nat", "postrouting"])
    });
    // Expire the old UDP mapping; the established TCP and WireGuard sessions remain open.
    // sleep: allow the isolated one-second conntrack timeout to remove the old source mapping.
    thread::sleep(Duration::from_secs(2));
    // Version 4 is the last coordinator snapshot; no `node_a.chunk` follows this point.
    client_stream_b.write_all(b"rebind-request").unwrap();
    let rebind_deadline = Instant::now() + Duration::from_secs(5);
    let mut learned = None;
    while Instant::now() < rebind_deadline {
        learned = node_a
            .counters()
            .unwrap()
            .get(&id_b.public_key)
            .and_then(|counters| counters.endpoint);
        if learned == Some(rebound_endpoint) {
            break;
        }
        // sleep: the authenticated packet updates GotaTun's peer endpoint asynchronously.
        thread::sleep(Duration::from_millis(10));
    }
    let rebound_packets_after = j534_rule(NS_A, "j534-rebound-observe").1;
    let output_after = j534_output_rule(NS_B, "j534-output").1;
    let snat_after = j534_nat_rule(NS_B, "j534-rebound-snat").1;
    let peer_output = in_ns(NS_B, || {
        run(
            "nft",
            &["list", "chain", "inet", J534_OUTPUT_TABLE, "output"],
        )
    });
    let nat_after = in_ns(NS_B, || {
        run("nft", &["list", "chain", "ip6", "j534_nat", "postrouting"])
    });
    eprintln!(
        "J534_REBIND_DIAG route={rebound_route} input_packets={rebound_packets_after} learned={learned:?} udp_output={output_before}->{output_after} snat={snat_before}->{snat_after} nat_before={nat_before} nat_after={nat_after} peer_output={peer_output}"
    );
    assert!(
        output_after > output_before,
        "the node did not emit the live-flow UDP packet"
    );
    assert!(
        snat_after > snat_before,
        "the new NAT mapping did not translate a packet"
    );
    assert!(
        rebound_packets_after > rebound_packets_before,
        "the rebind packet did not reach the listener through the host UDP rule"
    );
    assert_eq!(learned, Some(rebound_endpoint));
    let mut received = [0; 14];
    server_stream_a.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"rebind-request");
    server_stream_a.write_all(b"rebind-response").unwrap();
    let mut response = [0; 15];
    client_stream_b.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"rebind-response");
    j534_delete_rule(NS_A, "j534-rebound-observe");
    eprintln!("J534_METRIC rebound_endpoint={learned:?}");

    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    drop(tcp_health);
    drop(listener_a);
    drop((client_stream_b, server_stream_a));
    cleanup(&[&state_a, &state_b]);
    fs::remove_file(firewall).unwrap();
    fs::remove_file(nat_rules).unwrap();
    fs::remove_file(reflection_rules).unwrap();
    fs::remove_file(output_rules).unwrap();
}

/// Verify that an explicit override is the live port and fails rather than changing when occupied.
#[test]
#[ignore = "Run as root, alone, inside a disposable network namespace with CAP_NET_ADMIN."]
fn explicit_override_binds_exact_port_and_fails_when_occupied() {
    const CHILD: &str = "J534_EXPLICIT_OVERRIDE_CHILD";
    match std::env::var(CHILD).as_deref() {
        Ok("occupied") => {
            let path = state("j534-explicit-child");
            // Root restore starts enabled nodes, so the bind may fail before `up` is called.
            let error = Node::restore_with_engine(&path, EngineKind::GotaTun)
                .and_then(|mut node| node.up())
                .expect_err("an occupied explicit port must fail");
            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
            let _ = fs::remove_dir_all(path);
            return;
        }
        Ok("available") => {
            let path = state("j534-explicit-child");
            let mut node = Node::restore_with_engine(&path, EngineKind::GotaTun).unwrap();
            assert_eq!(
                node.listen_port(),
                Some(32_001),
                "root restore publishes its actual explicit listener"
            );
            let identity = node.up().unwrap();
            assert_eq!(identity.port, 32_001);
            assert_eq!(
                node.listen_port(),
                Some(32_001),
                "host policy reads the actual explicit listener port"
            );
            node.down().unwrap();
            let _ = fs::remove_dir_all(path);
            return;
        }
        _ => {}
    }

    assert!(
        std::env::var_os("INFRATERNAL_MESH_PORT").is_none(),
        "the parent case must not inherit an explicit override"
    );
    assert!(
        std::env::var_os(CHILD).is_none(),
        "only the two child cases set the marker"
    );
    let executable = std::env::current_exe().unwrap();
    let run_child = |case: &str| {
        Command::new(&executable)
            .args([
                "--exact",
                "--ignored",
                "explicit_override_binds_exact_port_and_fails_when_occupied",
                "--nocapture",
            ])
            .env(CHILD, case)
            .env("INFRATERNAL_MESH_PORT", "32001")
            .output()
            .unwrap()
    };
    let occupied = UdpSocket::bind("0.0.0.0:32001").unwrap();
    let collision = run_child("occupied");
    assert!(
        collision.status.success(),
        "explicit collision child failed: {}{}",
        String::from_utf8_lossy(&collision.stdout),
        String::from_utf8_lossy(&collision.stderr)
    );
    drop(occupied);

    let available = run_child("available");
    assert!(
        available.status.success(),
        "available override child failed: {}{}",
        String::from_utf8_lossy(&available.stdout),
        String::from_utf8_lossy(&available.stderr)
    );
}
