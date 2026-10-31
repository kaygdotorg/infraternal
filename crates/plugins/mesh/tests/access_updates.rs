//! Regressions for negotiated bounded access deltas and refusal before mutation [242,252], #173.
#![cfg(feature = "agent")]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_mesh::{
    configuration,
    dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::TrafficPolicy,
    },
};
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

fn config() -> Config {
    Config {
        local_key: Some(PublicKey([1; 32])),
        server: Some(NodeId(1)),
        node: NodeId(2),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        version: 1,
        addresses: Addresses {
            ipv4: Ipv4Addr::from(0x0afe_0002),
            ipv6: Ipv6Addr::from(0xfd02_u128 << 112 | 2),
        },
        default_policy: DefaultPolicy::Allow,
        peers: (3_u32..=1002)
            .map(|id| {
                (
                    NodeId(u64::from(id)),
                    PeerPolicy {
                        peer: Peer {
                            key: PublicKey([3; 32]),
                            addresses: Addresses {
                                ipv4: Ipv4Addr::from(0x0afe_0000 + id),
                                ipv6: Ipv6Addr::from((0xfd02_u128 << 112) + u128::from(id)),
                            },
                            endpoint: None,
                        },
                        inbound: TrafficPolicy::All,
                        outbound: TrafficPolicy::All,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: std::collections::BTreeMap::new(),
    }
}

#[cfg(feature = "agent")]
#[test]
fn negotiated_access_chunk_is_accepted_by_the_strict_action_parser() {
    let old = config();
    let mut next = old.clone();
    next.version += 1;
    let chunk = configuration::chunks(Some(&old), &next).unwrap().remove(0);
    let mut wire = serde_json::to_value(chunk).unwrap();
    wire["access_updates"] =
        serde_json::json!([{"first":3,"last":1002,"inbound":"None","outbound":"None"}]);
    let parsed = infraternal_plugin_mesh::node_actions::parse_action(
        "mesh.configure",
        &serde_json::to_vec(&wire).unwrap(),
    );
    assert!(
        parsed.is_ok(),
        "negotiated access updates must retain the strict bounded action parser"
    );
}

#[test]
fn default_tightening_at_1000_peers_fits_one_round_trip() {
    let old = config();
    let mut next = old.clone();
    next.version += 1;
    next.default_policy = DefaultPolicy::Deny;
    for peer in next.peers.values_mut() {
        peer.inbound = TrafficPolicy::None;
        peer.outbound = TrafficPolicy::None;
    }
    let parts = infraternal_plugin_mesh::access_updates::chunks(Some(&old), &next).unwrap();
    assert_eq!(
        parts.len(),
        1,
        "uniform access removal must not serialize one round trip per peer chunk"
    );
    assert!(
        serde_json::to_vec(&parts[0]).unwrap().len() <= infraternal_plugin_api::MAX_ACTION_BYTES
    );
}

#[test]
fn range_objects_reject_unknown_duplicate_and_positional_fields() {
    let old = config();
    let mut next = old.clone();
    next.version += 1;
    let chunk = configuration::chunks(Some(&old), &next).unwrap().remove(0);
    let mut wire = serde_json::to_value(chunk).unwrap();
    for update in [
        serde_json::json!([3, 1002, "None", "None"]),
        serde_json::json!({"first":3,"last":1002,"inbound":"None","outbound":"None","unknown":true}),
    ] {
        wire["access_updates"] = serde_json::json!([update]);
        assert!(
            infraternal_plugin_mesh::node_actions::parse_action(
                "mesh.configure",
                &serde_json::to_vec(&wire).unwrap()
            )
            .is_err()
        );
    }
    wire["access_updates"] =
        serde_json::json!([{"first":3,"last":1002,"inbound":"None","outbound":"None"}]);
    let duplicate = serde_json::to_string(&wire)
        .unwrap()
        .replace("\"first\":3", "\"first\":3,\"first\":4");
    assert!(
        infraternal_plugin_mesh::node_actions::parse_action("mesh.configure", duplicate.as_bytes())
            .is_err()
    );
}

#[test]
#[ignore = "Run in an isolated user/network namespace with CAP_NET_ADMIN."]
fn nft_compact_delta_preserves_identity_and_refuses_invalid_bases() {
    kernel_case(false);
}

#[test]
#[ignore = "Run in an isolated user/network namespace with CAP_NET_ADMIN."]
fn nf_tables_compact_delta_preserves_identity_and_refuses_invalid_bases() {
    kernel_case(true);
}

fn kernel_case(fallback: bool) {
    use infraternal_plugin_mesh::{access_updates, node::Node, wireguard::Device};
    assert_eq!(
        std::fs::read_to_string("/proc/self/uid_map")
            .unwrap()
            .split_whitespace()
            .nth(2),
        Some("1"),
        "isolated namespace required"
    );
    let mut node = if fallback {
        Node::with_firewall(infraternal_plugin_mesh::firewall::Firewall::nf_tables())
    } else {
        Node::default()
    };
    let identity = node.up().unwrap();
    assert!(identity.compact_access);
    let mut old = config();
    old.local_key = Some(identity.public_key);
    old.server = None;
    for (id, peer) in &mut old.peers {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&id.0.to_le_bytes());
        key[31] = 128;
        peer.peer.key = PublicKey(key);
    }
    for part in configuration::chunks(None, &old).unwrap() {
        node.chunk(part).unwrap();
    }
    assert_eq!(Device::counters().unwrap().len(), 1000);
    let mut next = old.clone();
    next.version += 1;
    next.default_policy = DefaultPolicy::Deny;
    for peer in next.peers.values_mut() {
        peer.inbound = TrafficPolicy::None;
        peer.outbound = TrafficPolicy::None;
    }
    let parts = access_updates::chunks(Some(&old), &next).unwrap();
    assert_eq!(parts.len(), 1);
    let valid = &parts[0];
    for variant in 0..7 {
        let mut invalid = valid.clone();
        match variant {
            0 => invalid.from_version = Some(0),
            1 => invalid.from_version = None,
            2 => invalid.last = false,
            3 => invalid.removed.push(NodeId(3)),
            4 => invalid.access_updates[0].last = NodeId(u64::MAX),
            5 => invalid.local_key = Some(PublicKey([9; 32])),
            _ => invalid
                .access_updates
                .push(invalid.access_updates[0].clone()),
        }
        assert_eq!(
            node.chunk(invalid).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(node.config(), Some(&old));
    }
    node.chunk(valid.clone()).unwrap();
    assert_eq!(node.config(), Some(&next));
    assert_eq!(Device::counters().unwrap().len(), 1000);
    assert_eq!(
        node.ensure().unwrap().unwrap().public_key,
        identity.public_key
    );
    // Ordinary complete snapshots remain the recovery path after a lost ACK.
    for part in configuration::chunks(None, &next).unwrap() {
        node.chunk(part).unwrap();
    }
    assert_eq!(node.config(), Some(&next));
    node.down().unwrap();
    assert!(!Device::owned().unwrap());
}

#[test]
fn uniform_changes_fit_one_frame_after_churn_with_distinct_kept_services() {
    use infraternal_plugin_mesh::policy::rules::{Port, Protocol};
    let mut old = config();
    old.peers = old
        .peers
        .into_iter()
        .map(|(id, mut peer)| {
            peer.outbound = TrafficPolicy::Ports(std::collections::BTreeSet::from([Port {
                protocol: Protocol::Tcp,
                number: u16::try_from(id.0).unwrap(),
            }]));
            (NodeId(id.0 * 100), peer)
        })
        .collect();
    let mut next = old.clone();
    next.version += 1;
    next.default_policy = DefaultPolicy::Deny;
    for peer in next.peers.values_mut() {
        peer.inbound = TrafficPolicy::None;
    }
    let parts = infraternal_plugin_mesh::access_updates::chunks(Some(&old), &next).unwrap();
    assert_eq!(
        parts.len(),
        1,
        "churn and preserved distinct services cannot add round trips"
    );
    assert!(
        serde_json::to_vec(&parts[0]).unwrap().len() <= infraternal_plugin_api::MAX_ACTION_BYTES
    );
}

#[test]
fn compact_identity_support_requires_an_explicit_strict_probe() {
    let parse = infraternal_plugin_mesh::node_actions::parse_action;
    assert!(parse("mesh.identity", br#"{"compact_access":true}"#).is_ok());
    assert!(parse("mesh.identity", b"{}").is_ok());
    #[cfg(feature = "mesh-dns-spike")]
    assert!(
        parse(
            "mesh.identity",
            br#"{"compact_access":true,"dns_names":true}"#
        )
        .is_ok()
    );
    #[cfg(not(feature = "mesh-dns-spike"))]
    assert!(
        parse(
            "mesh.identity",
            br#"{"compact_access":true,"dns_names":true}"#
        )
        .is_err(),
        "DNS support must be compiled in before the agent accepts its capability probe"
    );
    for input in [
        br#"{"compact_access":true,"unknown":true}"#.as_slice(),
        br#"{"compact_access":true,"compact_access":false}"#.as_slice(),
        br#"{"compact_access":1}"#.as_slice(),
    ] {
        assert!(parse("mesh.identity", input).is_err());
    }
}

#[test]
#[ignore = "requires an isolated user/network namespace"]
fn ordinary_up_and_identity_keep_the_legacy_reply_shape() {
    use infraternal_plugin_api::AgentPlugin;
    assert_eq!(
        std::fs::read_to_string("/proc/self/uid_map")
            .unwrap()
            .split_whitespace()
            .last(),
        Some("1")
    );
    let mut plugin = infraternal_plugin_mesh::node_actions::MeshNodePlugin::default();
    let up: serde_json::Value =
        serde_json::from_slice(&plugin.call("mesh.up", b"{}").unwrap()).unwrap();
    let legacy: serde_json::Value =
        serde_json::from_slice(&plugin.call("mesh.identity", b"{}").unwrap()).unwrap();
    let probe: serde_json::Value = serde_json::from_slice(
        &plugin
            .call("mesh.identity", br#"{"compact_access":true}"#)
            .unwrap(),
    )
    .unwrap();
    plugin.call("mesh.down", b"{}").unwrap();
    assert_eq!(
        up.as_object().unwrap().len(),
        2,
        "ordinary up must keep the strict legacy identity shape"
    );
    assert_eq!(legacy.as_object().unwrap().len(), 2);
    assert_eq!(probe["compact_access"], true);
}
