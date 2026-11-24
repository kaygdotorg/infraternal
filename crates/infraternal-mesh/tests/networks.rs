//! Subnet routes in the coordinator (D197 M3): approval, overlap refusal and arrow targets.
//!
//! These checks pin the security rules of the model: a network grants nothing until it is
//! approved, only arrows that name it (never node-to-node arrows) reach it, a network cannot be
//! an arrow's source, overlaps are refused with a sentence that names the approved network, and
//! a revoked approval never comes back through an old arrow.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_mesh::{
    coordinator::Coordinator,
    model::{MeshError, MeshSettings, Node, NodeId, PublicKey},
    networks::{ApprovedNetwork, Network, NetworkId, NetworkRefusal},
    rules::{Arrow, Endpoint, Port, Protocol, RuleId, TrafficPolicy},
};
use std::collections::BTreeSet;

/// A synthetic public key whose first 8 bytes are `value`.
fn key(value: u64) -> PublicKey {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    PublicKey(bytes)
}

/// Node `value`, named `host-<value>`, with the given tags.
fn node(value: u64, tags: &[&str]) -> Node {
    Node {
        id: NodeId(value),
        public_key: key(value),
        host: format!("host-{value}"),
        tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
    }
}

/// Parse a network the test knows is valid.
fn net(text: &str) -> Network {
    text.parse().unwrap()
}

/// A mesh with server 0, router 1, and clients 2 (tag `ops`) and 3 (tag `dev`), plus the
/// approved network 10 = `192.168.1.0/24` routed by node 1 with masquerade.
fn mesh() -> Coordinator {
    let mut coordinator =
        Coordinator::new(MeshSettings::new([1, 2, 3, 4, 5]), &[], node(0, &[])).unwrap();
    coordinator.join(node(1, &["routers"])).unwrap();
    coordinator.join(node(2, &["ops"])).unwrap();
    coordinator.join(node(3, &["dev"])).unwrap();
    coordinator
        .approve_network(ApprovedNetwork {
            id: NetworkId(10),
            router: NodeId(1),
            network: net("192.168.1.0/24"),
            masquerade: true,
        })
        .unwrap();
    coordinator
}

/// A one-way arrow from `from` to `to` granting TCP 5432.
fn arrow(id: u64, from: Endpoint, to: Endpoint) -> Arrow {
    Arrow {
        id: RuleId(id),
        from,
        to,
        both_ways: false,
        ports: TrafficPolicy::Ports(BTreeSet::from([Port {
            protocol: Protocol::Tcp,
            number: 5432,
        }])),
    }
}

/// A grant to the router is not a grant to its network; only arrows that name the network grant it, per source and port.
#[test]
fn only_arrows_that_name_the_network_grant_access_to_it() {
    let mut coordinator = mesh();
    // A node-to-node arrow toward the router is not access to the network behind it.
    let mut to_router = arrow(1, Endpoint::Node(NodeId(2)), Endpoint::Node(NodeId(1)));
    to_router.ports = TrafficPolicy::All;
    coordinator.add_arrow(to_router).unwrap();
    assert_eq!(
        coordinator.network_granted(NodeId(2), NetworkId(10)),
        TrafficPolicy::None
    );

    coordinator
        .add_arrow(arrow(
            2,
            Endpoint::Tag("ops".into()),
            Endpoint::Network(NetworkId(10)),
        ))
        .unwrap();
    let granted = coordinator.network_granted(NodeId(2), NetworkId(10));
    assert!(granted.allows(Port {
        protocol: Protocol::Tcp,
        number: 5432
    }));
    assert!(!granted.allows(Port {
        protocol: Protocol::Tcp,
        number: 22
    }));
    assert_eq!(
        coordinator.network_granted(NodeId(3), NetworkId(10)),
        TrafficPolicy::None,
        "a node outside the arrow's source gets nothing"
    );
    assert_eq!(
        coordinator.network_granted(NodeId(1), NetworkId(10)),
        TrafficPolicy::None,
        "the router reaches its own network outside the mesh"
    );
    // A network arrow adds no node-to-node grant.
    assert_eq!(
        coordinator.granted(NodeId(2), NodeId(1)),
        TrafficPolicy::All,
        "the earlier node arrow is unchanged"
    );
    assert_eq!(
        coordinator.granted(NodeId(3), NodeId(1)),
        TrafficPolicy::None
    );

    // Tag membership changes follow at once.
    coordinator
        .set_tags(NodeId(3), BTreeSet::from(["ops".to_owned()]))
        .unwrap();
    assert_ne!(
        coordinator.network_granted(NodeId(3), NetworkId(10)),
        TrafficPolicy::None
    );
}

/// A network as source, a two-way arrow to a network, and an arrow to an unapproved network are refused.
#[test]
fn a_network_is_only_ever_the_target_of_a_one_way_arrow() {
    let mut coordinator = mesh();
    assert_eq!(
        coordinator.add_arrow(arrow(
            1,
            Endpoint::Network(NetworkId(10)),
            Endpoint::Node(NodeId(2))
        )),
        Err(MeshError::NetworkEndpoint)
    );
    let mut both = arrow(
        2,
        Endpoint::Node(NodeId(2)),
        Endpoint::Network(NetworkId(10)),
    );
    both.both_ways = true;
    assert_eq!(coordinator.add_arrow(both), Err(MeshError::NetworkEndpoint));
    assert_eq!(
        coordinator.add_arrow(arrow(
            3,
            Endpoint::Node(NodeId(2)),
            Endpoint::Network(NetworkId(99))
        )),
        Err(MeshError::UnknownNetwork),
        "an arrow cannot name a network that is not approved"
    );
}

/// Overlaps (also the same network on another router), the mesh range and never-routed blocks are refused, with the reason.
#[test]
fn overlapping_and_unroutable_networks_are_refused_with_a_plain_reason() {
    let mut coordinator = mesh();
    let refusal = coordinator
        .network_refusal(net("192.168.0.0/16"), None)
        .unwrap();
    assert!(matches!(refusal, NetworkRefusal::Overlap { .. }));
    let text = refusal.to_string();
    assert!(
        text.contains("192.168.0.0/16 overlaps 192.168.1.0/24, which is already approved"),
        "{text}"
    );
    // The same network on a second router is an overlap too.
    assert_eq!(
        coordinator.approve_network(ApprovedNetwork {
            id: NetworkId(11),
            router: NodeId(2),
            network: net("192.168.1.0/24"),
            masquerade: true,
        }),
        Err(MeshError::UnroutableNetwork)
    );
    // Re-approving the same approval with other options does not collide with itself.
    assert!(
        coordinator
            .network_refusal(net("192.168.1.0/24"), Some(NetworkId(10)))
            .is_none()
    );
    assert!(
        coordinator
            .network_refusal(net("192.168.2.0/24"), None)
            .is_none()
    );
    for text in ["10.254.9.0/24", "0.0.0.0/0", "127.0.0.0/8", "fd00::/64"] {
        assert!(
            coordinator.network_refusal(net(text), None).is_some(),
            "{text} must be refused"
        );
    }
    assert_eq!(
        coordinator.approve_network(ApprovedNetwork {
            id: NetworkId(12),
            router: NodeId(99),
            network: net("172.16.0.0/24"),
            masquerade: false,
        }),
        Err(MeshError::UnknownNode),
        "only a member can route"
    );
}

/// Revoking ends access, a new approval does not revive old arrows, and a removed router takes its approvals with it.
#[test]
fn revoking_or_removing_the_router_ends_access_and_old_arrows_stay_dormant() {
    let mut coordinator = mesh();
    coordinator
        .add_arrow(arrow(
            1,
            Endpoint::Node(NodeId(2)),
            Endpoint::Network(NetworkId(10)),
        ))
        .unwrap();
    assert_ne!(
        coordinator.network_granted(NodeId(2), NetworkId(10)),
        TrafficPolicy::None
    );
    coordinator.revoke_network(NetworkId(10)).unwrap();
    assert_eq!(
        coordinator.network_granted(NodeId(2), NetworkId(10)),
        TrafficPolicy::None
    );
    // Approving the same network again gives a new identity; the old arrow grants nothing.
    coordinator
        .approve_network(ApprovedNetwork {
            id: NetworkId(20),
            router: NodeId(1),
            network: net("192.168.1.0/24"),
            masquerade: true,
        })
        .unwrap();
    assert_eq!(
        coordinator.network_granted(NodeId(2), NetworkId(20)),
        TrafficPolicy::None
    );
    // Removing the router removes its approvals.
    coordinator.remove_node(NodeId(1)).unwrap();
    assert_eq!(
        coordinator.networks().len(),
        0,
        "the router's approvals left with it"
    );
}

/// Approvals survive a checkpoint round trip, and a checkpoint with overlapping approvals is refused.
#[test]
fn approvals_survive_a_checkpoint_and_a_bad_one_refuses_the_restore() {
    let mut coordinator = mesh();
    coordinator
        .add_arrow(arrow(
            1,
            Endpoint::Node(NodeId(2)),
            Endpoint::Network(NetworkId(10)),
        ))
        .unwrap();
    let checkpoint = coordinator.checkpoint();
    let restored = Coordinator::restore(checkpoint.clone(), &[]).unwrap();
    assert_eq!(restored.networks(), coordinator.networks());
    assert_ne!(
        restored.network_granted(NodeId(2), NetworkId(10)),
        TrafficPolicy::None
    );
    let mut overlapping = checkpoint;
    overlapping.networks.push(ApprovedNetwork {
        id: NetworkId(11),
        router: NodeId(3),
        network: net("192.168.1.128/25"),
        masquerade: true,
    });
    assert_eq!(
        Coordinator::restore(overlapping, &[]).err(),
        Some(MeshError::InvalidCheckpoint)
    );
}
