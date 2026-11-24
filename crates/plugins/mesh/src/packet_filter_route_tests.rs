//! Subnet routes at the `GotaTun` TUN edge (D197 M3, D164, D384): the packet filter's side.
//!
//! The client may start only what its network grant allows into a network behind a router peer,
//! and accepts only replies from it. The router forwards only while forwarding is switched on,
//! only what each peer's grant into its served network allows, and never lets a host on that
//! network start anything toward the mesh. A network grant is never a node grant, and a node grant
//! is never a network grant.
use super::*;
use crate::dataplane::{PeerNetworks, ReachableNetwork, ServedNetwork};

/// A host on the routed LAN.
const LAN_HOST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
/// An address outside the routed LAN.
const OUTSIDE: Ipv4Addr = Ipv4Addr::new(192, 168, 2, 10);

/// The routed LAN.
fn lan() -> infraternal_mesh::networks::Network {
    "192.168.1.0/24".parse().expect("fixture network")
}

/// This node as a client of peer 2, which routes the LAN and grants TCP 5432 into it. Node-to-node
/// access is `None` both ways.
fn client() -> Config {
    let mut config = config(TrafficPolicy::None, TrafficPolicy::None);
    config
        .peers
        .get_mut(&NodeId(2))
        .expect("fixture peer")
        .networks = PeerNetworks {
        through: vec![ReachableNetwork {
            network: lan(),
            outbound: grant(Protocol::Tcp, 5432),
        }],
        served: Vec::new(),
    };
    config
}

/// This node as the LAN's router, serving peer 2 TCP 5432 into it. Node-to-node access is `All`
/// both ways, to prove it never leaks onto the network.
fn router() -> Config {
    let mut config = config(TrafficPolicy::All, TrafficPolicy::All);
    config
        .peers
        .get_mut(&NodeId(2))
        .expect("fixture peer")
        .networks = PeerNetworks {
        through: Vec::new(),
        served: vec![ServedNetwork {
            network: lan(),
            inbound: grant(Protocol::Tcp, 5432),
            keep_source: false,
        }],
    };
    config
}

/// Whether `packet` passes in `direction`.
fn passes(filter: &PacketFilter, mut packet: Vec<u8>, direction: Direction) -> bool {
    filter.check(&mut packet, direction)
}

/// A client starts only granted flows into a network behind its router, takes only replies from it, and loses them on revoke.
#[test]
fn a_client_starts_only_granted_flows_into_a_routed_network_and_takes_only_replies() {
    let filter = PacketFilter::new(&client(), MeshProxyIngress::default()).expect("compile client");
    // The granted port opens, and the router's reply returns.
    assert!(passes(
        &filter,
        tcp4(LOCAL4, LAN_HOST, 40_000, 5432, SYN),
        Direction::HostToMesh
    ));
    assert!(passes(
        &filter,
        tcp4(LAN_HOST, LOCAL4, 5432, 40_000, SYN_ACK),
        Direction::MeshToHost
    ));
    assert!(passes(
        &filter,
        tcp4(LOCAL4, LAN_HOST, 40_000, 5432, ACK),
        Direction::HostToMesh
    ));
    // Other ports, addresses outside the network, and the router itself stay closed.
    assert!(!passes(
        &filter,
        tcp4(LOCAL4, LAN_HOST, 40_001, 22, SYN),
        Direction::HostToMesh
    ));
    assert!(!passes(
        &filter,
        tcp4(LOCAL4, OUTSIDE, 40_002, 5432, SYN),
        Direction::HostToMesh
    ));
    assert!(
        !passes(
            &filter,
            tcp4(LOCAL4, PEER4, 40_003, 5432, SYN),
            Direction::HostToMesh
        ),
        "a network grant is not a grant to its router"
    );
    // A host on the network cannot start anything toward this node.
    assert!(!passes(
        &filter,
        tcp4(LAN_HOST, LOCAL4, 1234, 22, SYN),
        Direction::MeshToHost
    ));
    assert!(!passes(
        &filter,
        tcp4(LAN_HOST, LOCAL4, 1234, 5432, SYN),
        Direction::MeshToHost
    ));

    // Revoked: the next snapshot has no route, and the open flow stops at once.
    filter.publish_policy(
        PacketFilter::prepare_policy(
            &config(TrafficPolicy::None, TrafficPolicy::None),
            MeshProxyIngress::default(),
        )
        .expect("compile revoked"),
    );
    assert!(!passes(
        &filter,
        tcp4(LOCAL4, LAN_HOST, 40_000, 5432, ACK),
        Direction::HostToMesh
    ));
    assert!(!passes(
        &filter,
        tcp4(LAN_HOST, LOCAL4, 5432, 40_000, ACK),
        Direction::MeshToHost
    ));
}

/// A router forwards only granted flows, only while forwarding is on, and nothing a network host starts.
#[test]
fn a_router_forwards_only_granted_flows_and_only_while_forwarding_is_on() {
    let filter = PacketFilter::new(&router(), MeshProxyIngress::default()).expect("compile router");
    // Forwarding is off until the node has its kernel table in place.
    assert!(!passes(
        &filter,
        tcp4(PEER4, LAN_HOST, 40_000, 5432, SYN),
        Direction::MeshToHost
    ));
    filter.set_forwarding(true);
    assert!(passes(
        &filter,
        tcp4(PEER4, LAN_HOST, 40_000, 5432, SYN),
        Direction::MeshToHost
    ));
    // The LAN host's reply, after the kernel undid the masquerade, goes back to the peer.
    assert!(passes(
        &filter,
        tcp4(LAN_HOST, PEER4, 5432, 40_000, SYN_ACK),
        Direction::HostToMesh
    ));
    // The peer's `All` node grant does not widen what it may start into the network.
    assert!(!passes(
        &filter,
        tcp4(PEER4, LAN_HOST, 40_001, 22, SYN),
        Direction::MeshToHost
    ));
    assert!(!passes(
        &filter,
        tcp4(PEER4, OUTSIDE, 40_002, 5432, SYN),
        Direction::MeshToHost
    ));
    // A host on the network cannot start toward the peer, though this node may (`All`).
    assert!(!passes(
        &filter,
        tcp4(LAN_HOST, PEER4, 1234, 22, SYN),
        Direction::HostToMesh
    ));
    // An unknown mesh source never reaches the network.
    assert!(!passes(
        &filter,
        tcp4(UNKNOWN4, LAN_HOST, 40_003, 5432, SYN),
        Direction::MeshToHost
    ));
    // The node's own grants are unchanged.
    assert!(passes(
        &filter,
        tcp4(PEER4, LOCAL4, 40_004, 8080, SYN),
        Direction::MeshToHost
    ));

    // Forwarding switched off: the open flow stops at once.
    filter.set_forwarding(false);
    assert!(!passes(
        &filter,
        tcp4(PEER4, LAN_HOST, 40_000, 5432, ACK),
        Direction::MeshToHost
    ));
    assert!(!passes(
        &filter,
        tcp4(LAN_HOST, PEER4, 5432, 40_000, ACK),
        Direction::HostToMesh
    ));
}

/// Forwarding survives a republished snapshot, and a withdrawn peer's forwarded flow stops.
#[test]
fn a_router_keeps_forwarding_across_a_publish_and_a_withdrawn_peer_loses_it() {
    let filter = PacketFilter::new(&router(), MeshProxyIngress::default()).expect("compile router");
    filter.set_forwarding(true);
    assert!(passes(
        &filter,
        tcp4(PEER4, LAN_HOST, 40_000, 5432, SYN),
        Direction::MeshToHost
    ));
    // A republished snapshot shares the node's forwarding switch.
    filter.publish_policy(
        PacketFilter::prepare_policy(&router(), MeshProxyIngress::default())
            .expect("compile republish"),
    );
    assert!(passes(
        &filter,
        tcp4(PEER4, LAN_HOST, 40_000, 5432, ACK),
        Direction::MeshToHost
    ));
    filter.withdraw_peers(&BTreeSet::from([NodeId(2)]));
    assert!(!passes(
        &filter,
        tcp4(PEER4, LAN_HOST, 40_000, 5432, ACK),
        Direction::MeshToHost
    ));
}
