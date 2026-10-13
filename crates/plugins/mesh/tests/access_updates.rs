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
    }
}

#[cfg(feature = "agent")]
#[test]
#[ignore = "Fail-first additive wire regression; enable after node range staging is implemented."]
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
#[ignore = "Fail-first encoding regression; enable when the compact encoder is wired."]
fn default_tightening_at_1000_peers_fits_one_round_trip() {
    let old = config();
    let mut next = old.clone();
    next.version += 1;
    next.default_policy = DefaultPolicy::Deny;
    for peer in next.peers.values_mut() {
        peer.inbound = TrafficPolicy::None;
        peer.outbound = TrafficPolicy::None;
    }
    let parts = configuration::chunks(Some(&old), &next).unwrap();
    assert_eq!(
        parts.len(),
        1,
        "uniform access removal must not serialize one round trip per peer chunk"
    );
    assert!(
        serde_json::to_vec(&parts[0]).unwrap().len() <= infraternal_plugin_api::MAX_ACTION_BYTES
    );
}
