//! Proves edition defaults, directed port narrowing and reach-loss previews using the real coordinator [164,216].
#![allow(clippy::unwrap_used)]
use infraternal_plugin_mesh::{
    configuration,
    dataplane::DefaultPolicy,
    policy::{
        coordinator::Coordinator,
        model::{MeshSettings, Node, NodeId, PublicKey},
        rules::{Arrow, Endpoint, Port, Protocol, RuleId, TrafficPolicy},
    },
};
use std::collections::{BTreeMap, BTreeSet};
fn coordinator() -> Coordinator {
    let node = |id| Node {
        id: NodeId(id),
        public_key: PublicKey([u8::try_from(id).unwrap(); 32]),
        host: format!("host-{id}"),
        tags: BTreeSet::new(),
    };
    let mut coord = Coordinator::new(MeshSettings::new([1, 2, 3, 4, 5]), &[], node(1)).unwrap();
    coord.join(node(2)).unwrap();
    coord.join(node(3)).unwrap();
    coord
}
#[test]
fn edition_default_is_explicit_and_build_selected() {
    assert_eq!(
        DefaultPolicy::default(),
        if cfg!(feature = "ee") {
            DefaultPolicy::Deny
        } else {
            DefaultPolicy::Allow
        }
    );
}
#[test]
fn port_grant_narrows_allow_opens_deny_and_preserves_direction() {
    let mut coord = coordinator();
    let port = Port {
        protocol: Protocol::Tcp,
        number: 5432,
    };
    coord
        .add_arrow(Arrow {
            id: RuleId(1),
            from: Endpoint::Node(NodeId(2)),
            to: Endpoint::Node(NodeId(3)),
            both_ways: false,
            ports: TrafficPolicy::Ports(BTreeSet::from([port])),
        })
        .unwrap();
    for default in [DefaultPolicy::Allow, DefaultPolicy::Deny] {
        let view = configuration::compile(&coord, NodeId(2), default, &BTreeMap::new()).unwrap();
        let peer = &view.peers[&NodeId(3)];
        assert!(peer.outbound.allows(port));
        assert!(!peer.outbound.allows(Port {
            protocol: Protocol::Tcp,
            number: 22
        }));
        assert_eq!(
            peer.inbound,
            if default == DefaultPolicy::Allow {
                TrafficPolicy::All
            } else {
                TrafficPolicy::None
            }
        );
        assert_eq!(view.peers[&NodeId(1)].outbound, TrafficPolicy::All);
    }
    let lost = configuration::preview(&coord, DefaultPolicy::Allow, DefaultPolicy::Deny).unwrap();
    assert!(lost.contains(&(NodeId(3), NodeId(2))));
    assert!(!lost.contains(&(NodeId(2), NodeId(3))));
    assert!(!lost.iter().any(|(_, to)| *to == NodeId(1)));
}
#[test]
fn chunks_fit_body_budget_and_one_peer_delta_does_not_repeat_the_snapshot() {
    let coord = coordinator();
    let config =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Allow, &BTreeMap::new()).unwrap();
    let chunks = configuration::chunks(None, &config).unwrap();
    for chunk in &chunks {
        assert!(
            serde_json::to_vec(chunk).unwrap().len() <= infraternal_plugin_api::MAX_ACTION_BYTES
        );
    }
    let mut next = config.clone();
    next.version += 1;
    next.peers.get_mut(&NodeId(3)).unwrap().peer.endpoint =
        Some("192.0.2.3:44000".parse().unwrap());
    let delta = configuration::chunks(Some(&config), &next).unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].upserted.len(), 1);
    assert!(delta[0].last);
}

#[test]
fn large_valid_port_policy_is_split_without_a_port_count_cap() {
    let coord = coordinator();
    let mut config =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();
    let policy = TrafficPolicy::Ports(
        (1..=1000)
            .map(|number| Port {
                protocol: Protocol::Tcp,
                number,
            })
            .collect(),
    );
    config.peers.get_mut(&NodeId(3)).unwrap().outbound = policy.clone();
    let chunks = configuration::chunks(None, &config).unwrap();
    assert!(chunks.len() > 1);
    let mut assembled = TrafficPolicy::None;
    for chunk in chunks {
        assert!(
            serde_json::to_vec(&chunk).unwrap().len() <= infraternal_plugin_api::MAX_ACTION_BYTES
        );
        for (id, peer) in chunk.upserted.iter().chain(&chunk.merged) {
            if *id == NodeId(3) {
                assembled.union(&peer.outbound);
            }
        }
    }
    assert_eq!(assembled, policy);
}

#[test]
fn compiled_chunks_identify_the_server_and_old_snapshots_have_no_proposal() {
    let coord = coordinator();
    let config =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Allow, &BTreeMap::new()).unwrap();
    assert_eq!(config.server, Some(NodeId(1)));
    let chunks = configuration::chunks(None, &config).unwrap();
    assert!(chunks.iter().all(|chunk| chunk.server == config.server));
    let mut old = serde_json::to_value(&config).unwrap();
    old.as_object_mut().unwrap().remove("server");
    let old: infraternal_plugin_mesh::dataplane::Config = serde_json::from_value(old).unwrap();
    assert_eq!(old.server, None);
}

#[test]
#[cfg(feature = "mesh-dns-spike")]
fn compiled_snapshot_carries_local_and_peer_names_even_when_access_is_denied() {
    let coord = coordinator();
    let config =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();

    assert_eq!(config.name.as_deref(), Some("host-2"));
    assert_eq!(config.peer_names[&NodeId(1)], "host-1");
    assert_eq!(config.peer_names[&NodeId(3)], "host-3");
    assert_eq!(config.peers[&NodeId(3)].inbound, TrafficPolicy::None);
}

#[test]
#[cfg(feature = "mesh-dns-spike")]
fn name_renames_are_carried_by_the_existing_versioned_configuration_chunks() {
    let coord = coordinator();
    let old =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Allow, &BTreeMap::new()).unwrap();
    let mut next = old.clone();
    next.version += 1;
    next.name = Some("renamed-local".to_owned());
    next.peer_names.insert(NodeId(3), "renamed-peer".to_owned());

    let chunks = configuration::chunks(Some(&old), &next).unwrap();

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].name.as_deref(), Some("renamed-local"));
    assert_eq!(chunks[0].peer_names[&NodeId(3)], "renamed-peer");
    assert!(chunks[0].last);
}
