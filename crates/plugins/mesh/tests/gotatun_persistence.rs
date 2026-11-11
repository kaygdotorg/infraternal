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
    net::{SocketAddr, TcpListener, TcpStream},
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
