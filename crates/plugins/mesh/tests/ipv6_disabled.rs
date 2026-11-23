//! A node on a host with IPv6 turned off joins the mesh IPv4-only instead of being refused (#578).
//!
//! Many hosts set `net.ipv6.conf.all.disable_ipv6=1`, and every link they create inherits it.
//! The kernel then refuses the mesh link's IPv6 address and IPv6 routes with `EACCES`, which used
//! to refuse the whole `mesh.configure` with only "plugin action rejected". Here each engine
//! (`GotaTun` and kernel `WireGuard`) joins two such nodes and checks the result: the IPv4
//! address, the IPv4 peer routes and an IPv4 TCP flow work; nothing IPv6 is installed. When IPv6
//! is turned back on for the mesh link, the next snapshot installs the IPv6 address and routes.
//!
//! Run as root, alone, in a disposable mount and network namespace (`unshare -m -n`), with `ip`
//! and `nft`. Two network namespaces joined by a veth pair hold one node each. Each node runs on
//! a thread that entered its namespace, because the TUN, netlink and `nft` all act in the calling
//! thread's namespace. The documentation addresses on the veth never leave the sandbox.
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
    time::Duration,
};

/// Node A's network namespace.
const NS_A: &str = "j1138-a";
/// Node B's network namespace.
const NS_B: &str = "j1138-b";

/// Run `program` and return its standard output, failing the test on a non-zero exit.
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

/// Move the calling thread into network namespace `ns`.
fn enter(ns: &str) {
    let file = fs::File::open(format!("/run/netns/{ns}")).unwrap();
    setns(&file, CloneFlags::CLONE_NEWNET).unwrap();
}

/// A fresh, private (0700) state directory for one node.
fn state(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

/// The mesh addresses the coordinator gives node `id`.
fn addresses(id: u32) -> Addresses {
    Addresses {
        ipv4: (0x0afe_0000 + id).into(),
        ipv6: ((0xfd01_u128 << 112) + u128::from(id)).into(),
    }
}

/// One full coordinator snapshot at `version` for `local`, with `peer` reachable at `endpoint`.
fn snapshot(
    local: (u32, PublicKey),
    peer: (u32, PublicKey),
    endpoint: SocketAddr,
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
                    endpoint: Some(endpoint),
                    candidates: Vec::new(),
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

/// Build the two namespaces with IPv6 off everywhere in them, as a host that disables IPv6 does.
fn topology() {
    let _ = fs::create_dir_all("/run/netns");
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
        // `all` also sets `default`, which every new link (the mesh link too) inherits.
        in_ns(ns, || {
            fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1").unwrap();
            fs::write("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1").unwrap();
        });
    }
    run(
        "ip",
        &[
            "link", "add", "j1138a", "netns", NS_A, "type", "veth", "peer", "j1138b", "netns", NS_B,
        ],
    );
    run(
        "ip",
        &[
            "-n",
            NS_A,
            "address",
            "add",
            "192.0.2.1/24",
            "dev",
            "j1138a",
        ],
    );
    run(
        "ip",
        &[
            "-n",
            NS_B,
            "address",
            "add",
            "192.0.2.2/24",
            "dev",
            "j1138b",
        ],
    );
    run("ip", &["-n", NS_A, "link", "set", "j1138a", "up"]);
    run("ip", &["-n", NS_B, "link", "set", "j1138b", "up"]);
}

/// Remove both namespaces and the namespace mount, whatever state the test left.
fn cleanup() {
    for ns in [NS_A, NS_B] {
        let _ = Command::new("ip").args(["netns", "del", ns]).output();
    }
    let _ = Command::new("umount").arg("/run/netns").output();
}

/// The mesh link's addresses in `ns`, one `ip -o addr` line each.
fn mesh_addresses(ns: &str) -> String {
    run(
        "ip",
        &["-n", ns, "-o", "address", "show", "dev", "infraternal0"],
    )
}

/// The IPv4 and IPv6 routes through the mesh link in `ns`.
fn mesh_routes(ns: &str) -> (String, String) {
    (
        run(
            "ip",
            &["-n", ns, "-4", "route", "show", "dev", "infraternal0"],
        ),
        run(
            "ip",
            &["-n", ns, "-6", "route", "show", "dev", "infraternal0"],
        ),
    )
}

/// Send `payload` over TCP from namespace A to B's mesh IPv4 address and return B's echo.
fn tcp_echo(payload: &[u8]) -> Vec<u8> {
    let server_address = SocketAddr::from(([10, 254, 0, 2], 5001));
    let (listening, ready) = mpsc::channel();
    let server = thread::spawn(move || {
        enter(NS_B);
        let listener = TcpListener::bind(server_address).unwrap();
        listening.send(()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        stream.write_all(&received).unwrap();
    });
    ready.recv().unwrap();
    let echoed = in_ns(NS_A, || {
        let mut stream =
            TcpStream::connect_timeout(&server_address, Duration::from_secs(20)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        stream.write_all(payload).unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).unwrap();
        echoed
    });
    server.join().unwrap();
    echoed
}

/// Join two IPv6-off nodes on `engine`, prove IPv4 works and nothing IPv6 was installed, then
/// turn IPv6 back on for node A's mesh link and prove the next snapshot installs it.
fn ipv4_only_pair(engine: EngineKind) {
    cleanup();
    topology();
    let (state_a, state_b) = (state("j1138-node-a"), state("j1138-node-b"));
    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, engine).unwrap();
            let identity: Identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    let a = (1, id_a.public_key);
    let b = (2, id_b.public_key);
    let endpoint_a = SocketAddr::from(([192, 0, 2, 1], id_a.port));
    let endpoint_b = SocketAddr::from(([192, 0, 2, 2], id_b.port));
    let applied_a = in_ns(NS_A, || node_a.chunk(snapshot(a, b, endpoint_b, 1)));
    let applied_b = in_ns(NS_B, || node_b.chunk(snapshot(b, a, endpoint_a, 1)));
    assert!(
        applied_a.as_ref().is_ok_and(|applied| *applied),
        "{engine:?}: node A refused its first snapshot with IPv6 off: {applied_a:?}"
    );
    assert!(
        applied_b.as_ref().is_ok_and(|applied| *applied),
        "{engine:?}: node B refused its first snapshot with IPv6 off: {applied_b:?}"
    );

    let before = mesh_addresses(NS_A);
    assert!(
        before.contains("inet 10.254.0.1/32"),
        "{engine:?}: no IPv4 mesh address: {before}"
    );
    assert!(
        !before.contains("inet6"),
        "{engine:?}: an IPv6 address on an IPv6-off link: {before}"
    );
    let (routes4, routes6) = mesh_routes(NS_A);
    assert!(
        routes4.contains("10.254.0.2"),
        "{engine:?}: no IPv4 peer route: {routes4}"
    );
    assert!(
        routes6.trim().is_empty(),
        "{engine:?}: IPv6 routes on an IPv6-off link: {routes6}"
    );
    let payload: Vec<u8> = (0..64 * 1024_u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    assert_eq!(
        tcp_echo(&payload),
        payload,
        "{engine:?}: the IPv4 flow over the mesh broke"
    );

    // IPv6 comes back on node A's mesh link: the next full snapshot installs its IPv6 parts.
    in_ns(NS_A, || {
        fs::write("/proc/sys/net/ipv6/conf/infraternal0/disable_ipv6", "0").unwrap();
    });
    let reapplied = in_ns(NS_A, || node_a.chunk(snapshot(a, b, endpoint_b, 2)));
    assert!(
        reapplied.as_ref().is_ok_and(|applied| *applied),
        "{engine:?}: the snapshot after IPv6 came back was refused: {reapplied:?}"
    );
    let after = mesh_addresses(NS_A);
    assert!(
        after.contains("inet6 fd01::1/128"),
        "{engine:?}: IPv6 is back but the IPv6 mesh address is not: {after}"
    );
    let (_, routes6) = mesh_routes(NS_A);
    assert!(
        routes6.contains("fd01::2"),
        "{engine:?}: IPv6 is back but the IPv6 peer route is not: {routes6}"
    );

    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    let _ = fs::remove_dir_all(&state_a);
    let _ = fs::remove_dir_all(&state_b);
    cleanup();
}

/// The default engine, `GotaTun`, joins IPv4-only and takes IPv6 back.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft, issue #578."]
fn gotatun_nodes_join_ipv4_only_when_ipv6_is_disabled() {
    ipv4_only_pair(EngineKind::GotaTun);
}

/// Kernel `WireGuard`, the opt-out engine, joins IPv4-only and takes IPv6 back.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft, issue #578."]
fn kernel_nodes_join_ipv4_only_when_ipv6_is_disabled() {
    ipv4_only_pair(EngineKind::Kernel);
}
