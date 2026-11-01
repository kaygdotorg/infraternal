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
#[cfg(all(feature = "mesh-dns-spike", target_os = "linux"))]
fn denied_peer_name_is_absent_and_dns_returns_nxdomain() {
    let coord = coordinator();
    let config =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();

    assert_eq!(config.name.as_deref(), Some("host-2"));
    assert_eq!(config.peer_names[&NodeId(1)], "host-1");
    assert!(!config.peer_names.contains_key(&NodeId(3)));
    assert_eq!(config.peers[&NodeId(3)].inbound, TrafficPolicy::None);
    assert_eq!(config.peers[&NodeId(3)].outbound, TrafficPolicy::None);

    let response = infraternal_plugin_mesh::dns::response(&query("host-3.internal"), &config)
        .unwrap()
        .unwrap();
    assert_eq!(
        simple_dns::Packet::parse(&response).unwrap().rcode(),
        simple_dns::RCODE::NameError
    );
}

#[test]
#[cfg(all(feature = "mesh-dns-spike", target_os = "linux"))]
fn one_way_node_grant_publishes_the_real_hostname_only_to_the_allowed_receiver() {
    let mut coord = coordinator();
    coord
        .add_arrow(Arrow {
            id: RuleId(7),
            from: Endpoint::Node(NodeId(2)),
            to: Endpoint::Node(NodeId(3)),
            both_ways: false,
            ports: TrafficPolicy::All,
        })
        .unwrap();

    let allowed =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();
    let denied =
        configuration::compile(&coord, NodeId(3), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();

    assert_eq!(allowed.peers[&NodeId(3)].outbound, TrafficPolicy::All);
    assert_eq!(denied.peers[&NodeId(2)].outbound, TrafficPolicy::None);
    assert_eq!(
        allowed.peer_names.get(&NodeId(3)).map(String::as_str),
        Some("host-3")
    );
    assert!(!denied.peer_names.contains_key(&NodeId(2)));

    let response = infraternal_plugin_mesh::dns::response(&query("host-3.internal"), &allowed)
        .unwrap()
        .unwrap();
    let answer = simple_dns::Packet::parse(&response).unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].name.to_string(), "host-3.internal");

    let reverse_response =
        infraternal_plugin_mesh::dns::response(&query("host-2.internal"), &denied)
            .unwrap()
            .unwrap();
    assert_eq!(
        simple_dns::Packet::parse(&reverse_response)
            .unwrap()
            .rcode(),
        simple_dns::RCODE::NameError
    );
}

#[test]
#[cfg(all(feature = "mesh-dns-spike", target_os = "linux"))]
fn a_port_limited_grant_still_publishes_the_reachable_hostname() {
    let mut coord = coordinator();
    coord
        .add_arrow(Arrow {
            id: RuleId(11),
            from: Endpoint::Node(NodeId(2)),
            to: Endpoint::Node(NodeId(3)),
            both_ways: false,
            ports: TrafficPolicy::Ports(BTreeSet::from([Port {
                protocol: Protocol::Tcp,
                number: 22,
            }])),
        })
        .unwrap();

    let allowed =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();
    assert!(matches!(
        &allowed.peers[&NodeId(3)].outbound,
        TrafficPolicy::Ports(_)
    ));
    assert_eq!(
        allowed.peer_names.get(&NodeId(3)).map(String::as_str),
        Some("host-3")
    );

    let response = infraternal_plugin_mesh::dns::response(&query("host-3.internal"), &allowed)
        .unwrap()
        .unwrap();
    assert_eq!(
        simple_dns::Packet::parse(&response).unwrap().answers.len(),
        1
    );
}

#[test]
#[cfg(feature = "mesh-dns-spike")]
fn one_way_tag_grant_publishes_names_only_to_tag_members_allowed_to_reach_them() {
    let mut coord = coordinator();
    coord
        .join(Node {
            id: NodeId(4),
            public_key: PublicKey([4; 32]),
            host: "host-4".to_owned(),
            tags: BTreeSet::new(),
        })
        .unwrap();
    coord
        .set_tags(NodeId(2), BTreeSet::from(["clients".to_owned()]))
        .unwrap();
    coord
        .set_tags(NodeId(4), BTreeSet::from(["clients".to_owned()]))
        .unwrap();
    coord
        .set_tags(NodeId(3), BTreeSet::from(["build".to_owned()]))
        .unwrap();
    coord
        .add_arrow(Arrow {
            id: RuleId(8),
            from: Endpoint::Tag("clients".to_owned()),
            to: Endpoint::Tag("build".to_owned()),
            both_ways: false,
            ports: TrafficPolicy::All,
        })
        .unwrap();

    let clients =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();
    let second_client =
        configuration::compile(&coord, NodeId(4), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();
    let build =
        configuration::compile(&coord, NodeId(3), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();

    assert_eq!(
        clients.peer_names.get(&NodeId(3)).map(String::as_str),
        Some("host-3")
    );
    assert_eq!(clients.peers[&NodeId(3)].outbound, TrafficPolicy::All);
    assert_eq!(
        second_client.peer_names.get(&NodeId(3)).map(String::as_str),
        Some("host-3")
    );
    assert_eq!(second_client.peers[&NodeId(3)].outbound, TrafficPolicy::All);
    assert!(!build.peer_names.contains_key(&NodeId(2)));
    assert!(!build.peer_names.contains_key(&NodeId(4)));
    assert_eq!(build.peers[&NodeId(2)].outbound, TrafficPolicy::None);
    assert_eq!(build.peers[&NodeId(4)].outbound, TrafficPolicy::None);
}

#[test]
#[cfg(feature = "mesh-dns-spike")]
fn tag_membership_alone_does_not_publish_peer_names() {
    let mut coord = coordinator();
    for node in [NodeId(2), NodeId(3)] {
        coord
            .set_tags(node, BTreeSet::from(["shared".to_owned()]))
            .unwrap();
    }

    let config =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();

    assert_eq!(config.peers[&NodeId(3)].outbound, TrafficPolicy::None);
    assert!(!config.peer_names.contains_key(&NodeId(3)));
}

#[test]
#[cfg(feature = "mesh-dns-spike")]
fn removing_a_node_from_a_granted_tag_removes_its_name_from_the_next_snapshot() {
    let mut coord = coordinator();
    coord
        .set_tags(NodeId(2), BTreeSet::from(["clients".to_owned()]))
        .unwrap();
    coord
        .set_tags(NodeId(3), BTreeSet::from(["build".to_owned()]))
        .unwrap();
    coord
        .add_arrow(Arrow {
            id: RuleId(12),
            from: Endpoint::Tag("clients".to_owned()),
            to: Endpoint::Tag("build".to_owned()),
            both_ways: false,
            ports: TrafficPolicy::All,
        })
        .unwrap();
    let old =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();
    assert_eq!(
        old.peer_names.get(&NodeId(3)).map(String::as_str),
        Some("host-3")
    );

    coord.set_tags(NodeId(3), BTreeSet::new()).unwrap();
    let new =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();

    assert!(!new.peer_names.contains_key(&NodeId(3)));
    assert_eq!(new.peers[&NodeId(3)].outbound, TrafficPolicy::None);
    let chunks = configuration::chunks(Some(&old), &new).unwrap();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.removed_peer_names.contains(&NodeId(3)))
    );
}

#[test]
#[cfg(feature = "mesh-dns-spike")]
fn default_allow_policy_also_publishes_reachable_peer_names() {
    let coord = coordinator();

    let config =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Allow, &BTreeMap::new()).unwrap();

    assert_eq!(config.peers[&NodeId(3)].outbound, TrafficPolicy::All);
    assert_eq!(
        config.peer_names.get(&NodeId(3)).map(String::as_str),
        Some("host-3")
    );
}

#[test]
#[cfg(all(feature = "mesh-dns-spike", target_os = "linux"))]
fn configured_custom_suffix_is_used_for_peer_dns_answers() {
    let mut coord = coordinator();
    coord.set_suffix("mesh.kayg.org".to_owned()).unwrap();
    let config =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Allow, &BTreeMap::new()).unwrap();

    let response = infraternal_plugin_mesh::dns::response(&query("host-3.mesh.kayg.org"), &config)
        .unwrap()
        .unwrap();
    let answer = simple_dns::Packet::parse(&response).unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].name.to_string(), "host-3.mesh.kayg.org");
    assert!(
        infraternal_plugin_mesh::dns::response(&query("host-3.external.example"), &config)
            .unwrap()
            .is_none()
    );
}

#[test]
#[cfg(feature = "mesh-dns-spike")]
fn user_scoped_grants_remain_unexpressible_until_user_devices_are_in_the_policy_model() {
    let mut coord = coordinator();
    assert_eq!(
        coord.add_arrow(Arrow {
            id: RuleId(9),
            from: Endpoint::User(42),
            to: Endpoint::Node(NodeId(3)),
            both_ways: false,
            ports: TrafficPolicy::All,
        }),
        Err(infraternal_plugin_mesh::policy::model::MeshError::UserEndpoint)
    );
}

#[test]
#[cfg(all(feature = "mesh-dns-spike", target_os = "linux"))]
fn revoking_a_node_grant_removes_its_name_from_the_next_snapshot_and_chunk() {
    let mut coord = coordinator();
    let grant = Arrow {
        id: RuleId(10),
        from: Endpoint::Node(NodeId(2)),
        to: Endpoint::Node(NodeId(3)),
        both_ways: false,
        ports: TrafficPolicy::All,
    };
    coord.add_arrow(grant).unwrap();
    let old =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();
    assert_eq!(
        old.peer_names.get(&NodeId(3)).map(String::as_str),
        Some("host-3")
    );

    coord.remove_arrow(RuleId(10)).unwrap();
    let new =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Deny, &BTreeMap::new()).unwrap();

    assert!(!new.peer_names.contains_key(&NodeId(3)));
    let denied = infraternal_plugin_mesh::dns::response(&query("host-3.internal"), &new)
        .unwrap()
        .unwrap();
    assert_eq!(
        simple_dns::Packet::parse(&denied).unwrap().rcode(),
        simple_dns::RCODE::NameError
    );
    let chunks = configuration::chunks(Some(&old), &new).unwrap();
    let removed_names: Vec<_> = chunks
        .iter()
        .flat_map(|chunk| {
            serde_json::to_value(chunk).unwrap()["removed_peer_names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_u64)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(removed_names, [NodeId(3).0]);
}

#[cfg(all(feature = "mesh-dns-spike", target_os = "linux"))]
fn query(name: &str) -> Vec<u8> {
    let mut wire = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        wire.push(u8::try_from(label.len()).unwrap());
        wire.extend_from_slice(label.as_bytes());
    }
    wire.extend_from_slice(&[0, 0, 1, 0, 1]);
    wire
}

#[test]
#[cfg(feature = "mesh-dns-spike")]
fn name_renames_are_carried_by_the_existing_versioned_configuration_chunks() {
    let coord = coordinator();
    let old =
        configuration::compile(&coord, NodeId(2), DefaultPolicy::Allow, &BTreeMap::new()).unwrap();
    let default_snapshot = configuration::chunks(None, &old).unwrap();
    assert!(
        serde_json::to_value(&default_snapshot[0])
            .unwrap()
            .get("dns_suffix")
            .is_none()
    );
    let mut next = old.clone();
    next.version += 1;
    next.name = Some("renamed-local".to_owned());
    next.dns_suffix = "mesh.kayg.org".to_owned();
    next.peer_names.insert(NodeId(3), "renamed-peer".to_owned());

    let chunks = configuration::chunks(Some(&old), &next).unwrap();

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].name.as_deref(), Some("renamed-local"));
    assert_eq!(chunks[0].dns_suffix, "mesh.kayg.org");
    assert_eq!(
        serde_json::to_value(&chunks[0]).unwrap()["dns_suffix"],
        "mesh.kayg.org"
    );
    assert_eq!(chunks[0].peer_names[&NodeId(3)], "renamed-peer");
    assert!(chunks[0].last);
}
