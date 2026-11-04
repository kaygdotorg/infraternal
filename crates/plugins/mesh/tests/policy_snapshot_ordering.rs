//! Real-kernel snapshot identity/version regressions; conflicting replay must not widen policy [166], #173.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    configuration,
    dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
    firewall::Firewall,
    node::Node,
    policy::{
        model::{Addresses, NodeId},
        rules::TrafficPolicy,
    },
    wireguard::{Device, Key},
};
use std::{collections::BTreeMap, process::Command};

fn install(fallback: bool) -> (Node, Config) {
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    let mut node = Node::with_firewall(if fallback {
        Firewall::nf_tables()
    } else {
        Firewall::default()
    });
    node.up().unwrap();
    let config = Config {
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix: "internal".to_owned(),
        version: 10,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::from([(
            NodeId(2),
            PeerPolicy {
                peer: Peer {
                    key: Key::generate().unwrap().1,
                    addresses: Addresses {
                        ipv4: "10.254.0.2".parse().unwrap(),
                        ipv6: "fd01::2".parse().unwrap(),
                    },
                    endpoint: None,
                },
                inbound: TrafficPolicy::None,
                outbound: TrafficPolicy::None,
            },
        )]),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: std::collections::BTreeMap::new(),
    };
    for chunk in configuration::chunks(None, &config).unwrap() {
        node.chunk(chunk).unwrap();
    }
    (node, config)
}

fn snapshot_change(fallback: bool, identity: bool) {
    let (mut node, old) = install(fallback);
    // Identical equal-version replay remains useful after reconnect.
    for chunk in configuration::chunks(None, &old).unwrap() {
        assert!(node.chunk(chunk).unwrap());
    }
    let mut proposed = old.clone();
    if identity {
        proposed.node = NodeId(3);
        proposed.version += 1;
    }
    proposed.peers.get_mut(&NodeId(2)).unwrap().inbound = TrafficPolicy::All;
    proposed.peers.get_mut(&NodeId(2)).unwrap().outbound = TrafficPolicy::All;
    let result = node.chunk(configuration::chunks(None, &proposed).unwrap().remove(0));
    let retained = node.config().unwrap().clone();
    let peers = Device::counters().unwrap().len();
    node.down().unwrap();
    assert!(
        result.is_err(),
        "conflicting snapshot was accepted: {retained:?}"
    );
    assert_eq!(
        retained, old,
        "refusal must preserve the accepted configuration"
    );
    assert_eq!(peers, 1);
}

#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nft_equal_version_conflicting_snapshot_is_refused() {
    snapshot_change(false, false);
}
#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nf_tables_equal_version_conflicting_snapshot_is_refused() {
    snapshot_change(true, false);
}
#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nft_snapshot_cannot_replace_local_node_identity() {
    snapshot_change(false, true);
}
#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nf_tables_snapshot_cannot_replace_local_node_identity() {
    snapshot_change(true, true);
}

fn split_replay(fallback: bool) {
    let (mut node, old) = install(fallback);
    let mut first = configuration::chunks(None, &old).unwrap().remove(0);
    first.last = false;
    let mut last = first.clone();
    last.index = 1;
    last.last = true;
    last.upserted.clear();
    // Matching version cannot be refused before the complete contents arrive.
    assert!(!node.chunk(first.clone()).unwrap());
    assert!(node.chunk(last.clone()).unwrap());
    assert_eq!(node.config(), Some(&old));
    first.upserted.get_mut(&NodeId(2)).unwrap().inbound = TrafficPolicy::All;
    assert!(!node.chunk(first).unwrap());
    let refused = node.chunk(last);
    let retained = node.config().unwrap().clone();
    node.down().unwrap();
    assert!(refused.is_err(), "conflicting replay was not refused");
    assert_eq!(retained, old);
}

#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nft_split_snapshot_replay_requires_complete_identical_contents() {
    split_replay(false);
}
#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nf_tables_split_snapshot_replay_requires_complete_identical_contents() {
    split_replay(true);
}
