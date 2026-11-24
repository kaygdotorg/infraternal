//! A peer reaches a LAN behind a router node through an approved subnet route (D197 M3, #580).
//!
//! Three network namespaces stand in for the real thing: node A (the client), node B (the
//! router) and C, a host on B's LAN that runs no mesh at all. A and B are joined by an underlay
//! veth; B and C by a LAN veth (`198.51.100.0/24`). Both nodes run the default `GotaTun` engine
//! and take hand-built coordinator snapshots, so the test pins the node side exactly:
//! - with masquerade (the default), C sees B's LAN address and needs no route back;
//! - keeping the source, C sees A's mesh address (and is given a route back, as an operator would);
//! - only the granted port reaches C, and nothing on C can open a connection into the mesh;
//! - a snapshot without the route (revoked) removes A's route and allowed IPs, refuses the
//!   flow, stops B forwarding and turns IPv4 forwarding back off, as it was before.
//!
//! Run as root, alone, in a disposable mount and network namespace (`unshare -m -n`), with `ip`
//! and `nft`. Each node runs on a thread that entered its namespace. The documentation addresses
//! never leave the sandbox, which has no route to an uplink.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use infraternal_plugin_mesh::{
    dataplane::{
        Chunk, DefaultPolicy, Peer, PeerNetworks, PeerPolicy, ReachableNetwork, ServedNetwork,
    },
    node::{EngineKind, Identity, Node},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        networks::Network,
        rules::{Port, Protocol, TrafficPolicy},
    },
};
use nix::sched::{CloneFlags, setns};
use std::{
    collections::{BTreeMap, BTreeSet},
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

/// The client node's namespace.
const NS_A: &str = "j1156-a";
/// The router node's namespace.
const NS_B: &str = "j1156-b";
/// The LAN host's namespace; it runs no mesh.
const NS_C: &str = "j1156-c";
/// The LAN behind the router.
const LAN: &str = "198.51.100.0/24";
/// The router's own address on the LAN.
const ROUTER_LAN: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
/// The LAN host.
const HOST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
/// The one port the client is granted into the LAN.
const GRANTED: u16 = 7000;
/// A port on the LAN host the grant does not cover.
const NOT_GRANTED: u16 = 7001;

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

/// The LAN as a network.
fn lan() -> Network {
    LAN.parse().unwrap()
}

/// TCP to the granted port only.
fn granted() -> TrafficPolicy {
    TrafficPolicy::Ports(BTreeSet::from([Port {
        protocol: Protocol::Tcp,
        number: GRANTED,
    }]))
}

/// One full snapshot at `version` for `local`, whose only peer is `peer` at `endpoint` with the
/// subnet routes `networks`. Node-to-node access is `None` both ways: whatever reaches the LAN
/// does so through the network grant alone.
fn snapshot(
    local: (u32, PublicKey),
    peer: (u32, PublicKey),
    endpoint: SocketAddr,
    version: u64,
    networks: PeerNetworks,
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
        default_policy: DefaultPolicy::Deny,
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
                },
                inbound: TrafficPolicy::None,
                outbound: TrafficPolicy::None,
                access_ssh: None,
                networks,
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

/// Build the three namespaces and their two links.
fn topology() {
    let _ = fs::create_dir_all("/run/netns");
    run("mount", &["-t", "tmpfs", "netns", "/run/netns"]);
    for ns in [NS_A, NS_B, NS_C] {
        run("ip", &["netns", "add", ns]);
        run("ip", &["-n", ns, "link", "set", "lo", "up"]);
    }
    for (a, b, ns_a, ns_b, address_a, address_b) in [
        (
            "j1156ab",
            "j1156ba",
            NS_A,
            NS_B,
            "192.0.2.1/24",
            "192.0.2.2/24",
        ),
        (
            "j1156bc",
            "j1156cb",
            NS_B,
            NS_C,
            "198.51.100.1/24",
            "198.51.100.2/24",
        ),
    ] {
        run(
            "ip",
            &[
                "link", "add", a, "netns", ns_a, "type", "veth", "peer", b, "netns", ns_b,
            ],
        );
        run("ip", &["-n", ns_a, "address", "add", address_a, "dev", a]);
        run("ip", &["-n", ns_b, "address", "add", address_b, "dev", b]);
        run("ip", &["-n", ns_a, "link", "set", a, "up"]);
        run("ip", &["-n", ns_b, "link", "set", b, "up"]);
    }
}

/// Remove the namespaces and the namespace mount, whatever state the test left.
fn cleanup() {
    for ns in [NS_A, NS_B, NS_C] {
        let _ = Command::new("ip").args(["netns", "del", ns]).output();
    }
    let _ = Command::new("umount").arg("/run/netns").output();
}

/// Start a one-shot TCP server on the LAN host at `port` that answers with the source address
/// it saw. Returns a receiver that yields that address once a client connected.
fn lan_server(port: u16) -> mpsc::Receiver<Ipv4Addr> {
    let (ready_tx, ready) = mpsc::channel();
    let (seen_tx, seen) = mpsc::channel();
    thread::spawn(move || {
        enter(NS_C);
        let listener = TcpListener::bind((HOST, port)).unwrap();
        ready_tx.send(()).unwrap();
        if let Ok((mut stream, peer)) = listener.accept() {
            let std::net::IpAddr::V4(source) = peer.ip() else {
                return;
            };
            let _ = stream.write_all(source.to_string().as_bytes());
            let _ = seen_tx.send(source);
        }
    });
    ready.recv().unwrap();
    seen
}

/// From namespace A, connect to the LAN host at `port` and read its answer; `None` when the
/// connection fails within a few seconds.
fn connect_from_a(port: u16) -> Option<String> {
    in_ns(NS_A, || {
        let mut stream =
            TcpStream::connect_timeout(&SocketAddr::from((HOST, port)), Duration::from_secs(4))
                .ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).ok()?;
        Some(answer)
    })
}

/// The routes to the LAN through the mesh link in `ns`.
fn lan_route(ns: &str) -> String {
    run(
        "ip",
        &["-n", ns, "-4", "route", "show", LAN, "dev", "infraternal0"],
    )
}

/// IPv4 forwarding in `ns`.
fn ip_forward(ns: &str) -> String {
    in_ns(ns, || {
        fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .unwrap()
            .trim()
            .to_owned()
    })
}

/// Bring up both nodes and apply the routed snapshots at `version`, masquerading unless
/// `keep_source`.
fn routed(
    node_a: &mut Node,
    node_b: &mut Node,
    ids: ((u32, PublicKey), (u32, PublicKey)),
    endpoints: (SocketAddr, SocketAddr),
    version: u64,
    keep_source: bool,
) {
    let (a, b) = ids;
    let through = PeerNetworks {
        through: vec![ReachableNetwork {
            network: lan(),
            outbound: granted(),
        }],
        served: Vec::new(),
    };
    let served = PeerNetworks {
        through: Vec::new(),
        served: vec![ServedNetwork {
            network: lan(),
            inbound: granted(),
            keep_source,
        }],
    };
    let applied_a = in_ns(NS_A, || {
        node_a.chunk(snapshot(a, b, endpoints.1, version, through))
    });
    let applied_b = in_ns(NS_B, || {
        node_b.chunk(snapshot(b, a, endpoints.0, version, served))
    });
    assert!(
        applied_a.as_ref().is_ok_and(|applied| *applied),
        "client refused its routed snapshot: {applied_a:?}"
    );
    assert!(
        applied_b.as_ref().is_ok_and(|applied| *applied),
        "router refused its routed snapshot: {applied_b:?}"
    );
}

/// The whole story on the default engine: masquerade, port grant, keep source, revoke.
#[test]
#[ignore = "Run as root, alone, inside unshare -m -n with ip and nft, issue #580."]
fn a_peer_reaches_a_lan_behind_a_router_only_through_an_approved_route() {
    cleanup();
    topology();
    let (state_a, state_b) = (state("j1156-node-a"), state("j1156-node-b"));
    let up = |ns: &str, path: &PathBuf| {
        in_ns(ns, || {
            let mut node = Node::restore_with_engine(path, EngineKind::GotaTun).unwrap();
            let identity: Identity = node.up().unwrap();
            (node, identity)
        })
    };
    let (mut node_a, id_a) = up(NS_A, &state_a);
    let (mut node_b, id_b) = up(NS_B, &state_b);
    let ids = ((2, id_a.public_key), (3, id_b.public_key));
    let endpoints = (
        SocketAddr::from(([192, 0, 2, 1], id_a.port)),
        SocketAddr::from(([192, 0, 2, 2], id_b.port)),
    );
    // A new namespace may inherit the host's IPv4 forwarding (`devconf_inherit_init_net`); start
    // the router with it off, so the test proves it is turned on and back off again.
    in_ns(NS_B, || {
        fs::write("/proc/sys/net/ipv4/ip_forward", "0").unwrap()
    });
    assert_eq!(
        ip_forward(NS_B),
        "0",
        "the router starts without forwarding"
    );

    // First the two nodes are ordinary peers with full node access and no route, so the router
    // is already installed in the client's device when the route arrives: the route must still
    // reach its allowed IPs, the filter and the router's kernel table (not a mere endpoint
    // update).
    for (ns, node, local, peer, endpoint) in [
        (NS_A, &mut node_a, ids.0, ids.1, endpoints.1),
        (NS_B, &mut node_b, ids.1, ids.0, endpoints.0),
    ] {
        let mut plain = snapshot(local, peer, endpoint, 1, PeerNetworks::default());
        for policy in plain.upserted.values_mut() {
            policy.inbound = TrafficPolicy::All;
            policy.outbound = TrafficPolicy::All;
        }
        let applied = in_ns(ns, || node.chunk(plain));
        assert!(applied.is_ok_and(|applied| applied), "{ns}: plain snapshot");
    }
    assert_eq!(lan_route(NS_A).trim(), "", "no route before approval");
    assert_eq!(
        connect_from_a(GRANTED),
        None,
        "the LAN is unreachable before approval"
    );

    // Masquerade (the default): C sees the router's LAN address.
    routed(&mut node_a, &mut node_b, ids, endpoints, 2, false);
    assert!(
        lan_route(NS_A).contains(LAN),
        "the client has no route to the LAN: {}",
        lan_route(NS_A)
    );
    assert_eq!(ip_forward(NS_B), "1", "the router turned forwarding on");
    let forwarding = in_ns(NS_B, || node_b.forwarding_state());
    assert_eq!(forwarding["state"], "on", "{forwarding}");
    let seen = lan_server(GRANTED);
    assert_eq!(
        connect_from_a(GRANTED).as_deref(),
        Some(ROUTER_LAN.to_string().as_str()),
        "with masquerade the LAN host must see the router's LAN address"
    );
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(5)).unwrap(),
        ROUTER_LAN
    );

    // A port the grant does not cover never reaches the LAN host.
    let refused = lan_server(NOT_GRANTED);
    assert_eq!(
        connect_from_a(NOT_GRANTED),
        None,
        "an ungranted port reached the LAN"
    );
    assert!(refused.recv_timeout(Duration::from_millis(500)).is_err());

    // Nothing on the LAN may open a connection into the mesh, even toward the client.
    let into_mesh = in_ns(NS_C, || {
        let _ = Command::new("ip")
            .args(["route", "add", "10.254.0.0/16", "via", "198.51.100.1"])
            .output();
        TcpStream::connect_timeout(
            &SocketAddr::from((addresses(2).ipv4, 22)),
            Duration::from_secs(3),
        )
        .is_ok()
    });
    assert!(!into_mesh, "a LAN host opened a connection into the mesh");

    // Keep the source: C sees the client's mesh address (it has the route back from above).
    routed(&mut node_a, &mut node_b, ids, endpoints, 3, true);
    let seen = lan_server(GRANTED);
    assert_eq!(
        connect_from_a(GRANTED).as_deref(),
        Some(addresses(2).ipv4.to_string().as_str()),
        "keeping the source must show the client's mesh address"
    );
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(5)).unwrap(),
        addresses(2).ipv4
    );

    // Revoked: the next snapshots carry no route.
    let none = PeerNetworks::default();
    let revoked_a = in_ns(NS_A, || {
        node_a.chunk(snapshot(ids.0, ids.1, endpoints.1, 4, none.clone()))
    });
    let revoked_b = in_ns(NS_B, || {
        node_b.chunk(snapshot(ids.1, ids.0, endpoints.0, 4, none))
    });
    assert!(revoked_a.is_ok_and(|applied| applied));
    assert!(revoked_b.is_ok_and(|applied| applied));
    assert_eq!(
        lan_route(NS_A).trim(),
        "",
        "the revoked route is still installed"
    );
    let _gone = lan_server(GRANTED);
    assert_eq!(
        connect_from_a(GRANTED),
        None,
        "a revoked route still carried traffic"
    );
    assert_eq!(ip_forward(NS_B), "0", "forwarding was not turned back off");
    let forwarding = in_ns(NS_B, || node_b.forwarding_state());
    assert_eq!(forwarding["state"], "idle", "{forwarding}");

    in_ns(NS_A, || node_a.down().unwrap());
    in_ns(NS_B, || node_b.down().unwrap());
    let _ = fs::remove_dir_all(&state_a);
    let _ = fs::remove_dir_all(&state_b);
    cleanup();
}
