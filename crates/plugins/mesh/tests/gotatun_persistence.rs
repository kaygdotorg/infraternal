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
    path::PathBuf,
    process::Command,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const NS_A: &str = "d332-a";
const NS_B: &str = "d332-b";
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

/// The coordinator's snapshot for `local`, with `peer` reachable at `endpoint`; access is open.
fn snapshot(local: (u32, PublicKey), peer: (u32, PublicKey), endpoint: SocketAddr) -> Chunk {
    Chunk {
        local_key: Some(local.1),
        server: Some(NodeId(1)),
        node: NodeId(local.0.into()),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
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
                    addresses: addresses(peer.0),
                    endpoint: Some(endpoint),
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
            },
        )]),
        merged: BTreeMap::new(),
        removed: Vec::new(),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: BTreeMap::new(),
        #[cfg(feature = "mesh-dns-spike")]
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

fn cleanup(states: &[&PathBuf]) {
    for ns in [NS_A, NS_B] {
        let _ = Command::new("ip").args(["netns", "del", ns]).status();
    }
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "infraternal_mesh"])
        .status();
    for state in states {
        let _ = fs::remove_dir_all(state);
    }
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
