//! A node on a host with IPv6 turned off joins the mesh IPv4-only instead of being refused (#578).
//!
//! Many hosts set `net.ipv6.conf.all.disable_ipv6=1`, and every link they create inherits it.
//! The kernel then refuses the mesh link's IPv6 address and IPv6 routes with `EACCES`, which used
//! to refuse the whole `mesh.configure` with only "plugin action rejected". Here each engine
//! (`GotaTun` and kernel `WireGuard`) joins two such nodes and checks the result: the IPv4
//! address, the IPv4 peer routes and an IPv4 TCP flow work; nothing IPv6 is installed. When IPv6
//! is turned back on for the mesh link, the next snapshot installs the IPv6 address and routes.
//!
//! The second half (J1142) is the peer's side: a dual-stack node that is told a peer runs IPv4-only
//! installs no IPv6 route to it and answers no `AAAA` for its name, so resolving the name gives only
//! an `A` record and connecting is immediate, with no IPv6 attempt to wait out. When the peer
//! reports IPv6 again, both come back.
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
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
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

/// Build the two namespaces with IPv6 off everywhere in them, as a host that disables IPv6 does.
fn topology() {
    topology_with(&[NS_A, NS_B]);
}

/// Build the two namespaces; IPv6 is off only in the namespaces named in `ipv6_off`.
fn topology_with(ipv6_off: &[&str]) {
    let _ = fs::create_dir_all("/run/netns");
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    for ns in [NS_A, NS_B] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
        // `all` also sets `default`, which every new link (the mesh link too) inherits.
        if ipv6_off.contains(&ns) {
            in_ns(ns, || {
                fs::write("/proc/sys/net/ipv6/conf/all/disable_ipv6", "1").unwrap();
                fs::write("/proc/sys/net/ipv6/conf/default/disable_ipv6", "1").unwrap();
            });
        }
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
    tcp_echo_to(Ipv4Addr::new(10, 254, 0, 2), payload)
}

/// Send `payload` over TCP from namespace A to `address`, port 5001, on B, and return B's echo.
fn tcp_echo_to(address: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let server_address = SocketAddr::from((address, 5001));
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

/// The wire form of one DNS question for `name` of `record_type` (1 = `A`, 28 = `AAAA`).
#[cfg(feature = "mesh-dns")]
fn dns_question(name: &str, record_type: u16) -> Vec<u8> {
    let mut wire = vec![0x4a, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        wire.push(u8::try_from(label.len()).unwrap());
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire.extend_from_slice(&record_type.to_be_bytes());
    wire.extend_from_slice(&1_u16.to_be_bytes());
    wire
}

/// The response code and the addresses in a DNS reply.
#[cfg(feature = "mesh-dns")]
fn dns_answers(reply: &[u8]) -> (hickory_proto::op::ResponseCode, Vec<std::net::IpAddr>) {
    use hickory_proto::{op::Message, rr::RData};
    let message = Message::from_vec(reply).unwrap();
    let answers = message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address) => Some(std::net::IpAddr::V4(address.0)),
            RData::AAAA(address) => Some(std::net::IpAddr::V6(address.0)),
            _ => None,
        })
        .collect();
    (message.metadata.response_code, answers)
}

/// One question asked of node A's mesh DNS, answered as `A`'s resolver answers it.
///
/// Both engines are asked over a real UDP socket, from A's own mesh address as a local client
/// (the system resolver) would. `GotaTun` used to drop such a query in its `prerouting` anti-spoofing
/// rule, so the node could not resolve through its own mesh resolver (#578, J1154); the live query
/// is the regression check, and the dedicated rows below keep the spoofing protection honest.
#[cfg(feature = "mesh-dns")]
fn ask_dns(
    _engine: EngineKind,
    _node: &Node,
    name: &str,
    record_type: u16,
) -> (hickory_proto::op::ResponseCode, Vec<std::net::IpAddr>) {
    let wire = dns_question(name, record_type);
    in_ns(NS_A, || {
        let socket = std::net::UdpSocket::bind((Ipv4Addr::new(10, 254, 0, 1), 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .send_to(
                &wire,
                (
                    Ipv4Addr::new(10, 254, 0, 1),
                    infraternal_plugin_mesh::dns::DNS_PORT,
                ),
            )
            .unwrap();
        let mut reply = [0_u8; 512];
        let (length, _) = socket.recv_from(&mut reply).unwrap();
        dns_answers(&reply[..length])
    })
}

/// A dual-stack node A is told that peer B runs IPv4-only (J1142): A installs no IPv6 route to B, its
/// DNS gives B's name only an `A` record, and a client that connects to what DNS returned connects at
/// once. Then B reports IPv6 and the next snapshot brings the IPv6 route and the `AAAA` back.
#[cfg(feature = "mesh-dns")]
fn ipv4_only_peer_gets_no_aaaa_and_no_route(engine: EngineKind) {
    cleanup();
    // Only B has IPv6 off: A is an ordinary dual-stack node.
    topology_with(&[NS_B]);
    let (state_a, state_b) = (state("j1142-node-a"), state("j1142-node-b"));
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

    // What the coordinator sends A once B has reported IPv6 off: B's mark and both names.
    let for_a = |version: u64, ipv4_only: bool| {
        let mut chunk = snapshot(a, b, endpoint_b, version);
        chunk.name = Some("a".to_owned());
        chunk.peer_names.insert(NodeId(2), "b".to_owned());
        chunk.upserted.get_mut(&NodeId(2)).unwrap().peer.ipv4_only = ipv4_only;
        chunk
    };
    let applied_a = in_ns(NS_A, || node_a.chunk(for_a(1, true)));
    let applied_b = in_ns(NS_B, || node_b.chunk(snapshot(b, a, endpoint_a, 1)));
    assert!(
        applied_a.as_ref().is_ok_and(|applied| *applied),
        "{engine:?}: dual-stack node A refused the snapshot: {applied_a:?}"
    );
    assert!(
        applied_b.as_ref().is_ok_and(|applied| *applied),
        "{engine:?}: IPv4-only node B refused its snapshot: {applied_b:?}"
    );
    assert!(
        !in_ns(NS_A, || node_a.ipv4_only()) && in_ns(NS_B, || node_b.ipv4_only()),
        "{engine:?}: each node must report its own IPv6 state: A dual-stack, B IPv4-only"
    );

    // A kept its own IPv6 address, and has the IPv4 route to B but not the IPv6 one.
    let own = mesh_addresses(NS_A);
    assert!(own.contains("inet6 fd01::1/128"), "{engine:?}: {own}");
    let (routes4, routes6) = mesh_routes(NS_A);
    assert!(routes4.contains("10.254.0.2"), "{engine:?}: {routes4}");
    assert!(
        !routes6.contains("fd01::2"),
        "{engine:?}: an IPv6 route to an IPv4-only peer: {routes6}"
    );

    // The peer's name resolves to its IPv4 address only: `AAAA` is "no data", not an error and not an address.
    let (code, a_records) = ask_dns(engine, &node_a, "b.internal", 1);
    assert_eq!(code, hickory_proto::op::ResponseCode::NoError);
    assert_eq!(
        a_records,
        [std::net::IpAddr::V4(Ipv4Addr::new(10, 254, 0, 2))]
    );
    let (code, aaaa_records) = ask_dns(engine, &node_a, "b.internal", 28);
    assert_eq!(
        code,
        hickory_proto::op::ResponseCode::NoError,
        "{engine:?}: the name exists"
    );
    assert!(
        aaaa_records.is_empty(),
        "{engine:?}: AAAA for an IPv4-only peer: {aaaa_records:?}"
    );
    // A dual-stack name is unchanged: A's own name still has its AAAA.
    assert_eq!(ask_dns(engine, &node_a, "a.internal", 28).1.len(), 1);

    // A client that tries what DNS gave it connects at once: no IPv6 attempt, no timeout to wait out.
    let std::net::IpAddr::V4(resolved) = a_records[0] else {
        unreachable!("the answer was filtered to an IPv4 address");
    };
    let started = std::time::Instant::now();
    let payload = b"resolved by name".to_vec();
    assert_eq!(tcp_echo_to(resolved, &payload), payload);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{engine:?}: connecting to the resolved address took {:?}",
        started.elapsed()
    );
    // And a client that goes for B's IPv6 address anyway fails at once (no route), not after a timeout.
    let started = std::time::Instant::now();
    let refused = in_ns(NS_A, || {
        TcpStream::connect_timeout(
            &SocketAddr::from(("fd01::2".parse::<std::net::Ipv6Addr>().unwrap(), 5001)),
            Duration::from_secs(10),
        )
    });
    assert!(refused.is_err(), "{engine:?}: connected to a dead end");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{engine:?}: the IPv6 attempt waited {:?} instead of failing at once",
        started.elapsed()
    );

    // B turns IPv6 on and reports it: the next snapshot drops the mark, and the route and AAAA return.
    in_ns(NS_B, || {
        fs::write("/proc/sys/net/ipv6/conf/infraternal0/disable_ipv6", "0").unwrap();
    });
    let reapplied_b = in_ns(NS_B, || node_b.chunk(snapshot(b, a, endpoint_a, 2)));
    assert!(
        reapplied_b.as_ref().is_ok_and(|applied| *applied),
        "{engine:?}: {reapplied_b:?}"
    );
    assert!(
        !in_ns(NS_B, || node_b.ipv4_only()),
        "{engine:?}: B must report IPv6 on"
    );
    let reapplied_a = in_ns(NS_A, || node_a.chunk(for_a(2, false)));
    assert!(
        reapplied_a.as_ref().is_ok_and(|applied| *applied),
        "{engine:?}: {reapplied_a:?}"
    );
    let (_, routes6) = mesh_routes(NS_A);
    assert!(
        routes6.contains("fd01::2"),
        "{engine:?}: the IPv6 route did not return: {routes6}"
    );
    let (_, aaaa_records) = ask_dns(engine, &node_a, "b.internal", 28);
    assert_eq!(
        aaaa_records,
        [std::net::IpAddr::V6("fd01::2".parse().unwrap())],
        "{engine:?}: the AAAA did not return"
    );

    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    let _ = fs::remove_dir_all(&state_a);
    let _ = fs::remove_dir_all(&state_b);
    cleanup();
}

/// `GotaTun`: a peer resolving an IPv4-only node gets only `A` and connects at once.
#[cfg(feature = "mesh-dns")]
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft, issue #578."]
fn gotatun_peer_resolving_an_ipv4_only_node_gets_only_a() {
    ipv4_only_peer_gets_no_aaaa_and_no_route(EngineKind::GotaTun);
}

/// Kernel `WireGuard`: a peer resolving an IPv4-only node gets only `A` and connects at once.
#[cfg(feature = "mesh-dns")]
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft, issue #578."]
fn kernel_peer_resolving_an_ipv4_only_node_gets_only_a() {
    ipv4_only_peer_gets_no_aaaa_and_no_route(EngineKind::Kernel);
}
