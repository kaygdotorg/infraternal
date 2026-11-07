//! Real-kernel snapshot identity/version regressions; conflicting replay must not widen policy [166], #173.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    configuration,
    dataplane::{Chunk, Config, DefaultPolicy, Peer, PeerPolicy},
    firewall::Firewall,
    node::{EngineKind, Node},
    policy::{
        model::{Addresses, NodeId},
        rules::TrafficPolicy,
    },
    wireguard::{Device, Key},
};
use std::{collections::BTreeMap, process::Command};

/// Stable server process epochs used to distinguish one authenticated authority from another.
const AUTHORITY_EPOCH_A: &str = "00000000-0000-4000-8000-000000000001";
/// A second server process epoch for restore and retirement regressions.
const AUTHORITY_EPOCH_B: &str = "00000000-0000-4000-8000-000000000002";

/// Encode a complete snapshot with the same authenticated process epoch on every chunk.
fn chunks_with_epoch(old: Option<&Config>, new: &Config, authority_epoch: &str) -> Vec<Chunk> {
    configuration::chunks(old, new)
        .unwrap()
        .into_iter()
        .map(|mut chunk| {
            chunk.authority_epoch = Some(authority_epoch.to_owned());
            chunk
        })
        .collect()
}

/// Give each persistence regression its own short state directory.
fn j330_state_path(test_name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("j330-{test_name}-{}", std::process::id()))
}

/// Bring up a node with a policy snapshot, with or without the fallback policy.
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
    })
    .with_engine(EngineKind::Kernel);
    let identity = node.up().unwrap();
    let config = Config {
        authority_epoch: Some(AUTHORITY_EPOCH_A.to_owned()),
        local_key: Some(identity.public_key),
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
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: "10.254.0.2".parse().unwrap(),
                        ipv6: "fd01::2".parse().unwrap(),
                    },
                    endpoint: None,
                },
                inbound: TrafficPolicy::None,
                outbound: TrafficPolicy::None,
                access_ssh: None,
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

/// A full snapshot from a restored server replaces a newer retained config and retires its peers.
#[test]
#[ignore = "Run in a disposable user/network namespace, issue #382."]
fn nft_server_revision_rollback_replaces_stale_peers() {
    let (mut node, mut accepted) = install(false);
    let identity = node.up().unwrap();
    accepted.local_key = Some(identity.public_key);
    accepted.server = Some(NodeId(1));
    accepted.authority_epoch = Some(AUTHORITY_EPOCH_A.to_owned());
    accepted.version = 11;
    for chunk in chunks_with_epoch(None, &accepted, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).unwrap();
    }

    let mut restored = accepted.clone();
    restored.version = 2;
    restored.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    restored.peers.clear();
    let result = chunks_with_epoch(None, &restored, AUTHORITY_EPOCH_B)
        .into_iter()
        .try_for_each(|chunk| node.chunk(chunk).map(|_| ()));
    let retained = node.config().cloned();
    let installed_peers = Device::counters().unwrap().len();
    node.down().unwrap();

    assert!(
        result.is_ok(),
        "restored full snapshot was refused: {result:?}"
    );
    assert_eq!(retained, Some(restored));
    assert_eq!(installed_peers, 0, "a stale peer key remained installed");
}

/// A rejected snapshot from a newly enrolled server cannot leave the previous server's peers reachable.
#[test]
#[ignore = "Run in a disposable user/network namespace, issue #382."]
fn nft_new_server_rejection_retires_previous_peers() {
    let (mut node, mut accepted) = install(false);
    let identity = node.up().unwrap();
    accepted.local_key = Some(identity.public_key);
    accepted.server = Some(NodeId(1));
    accepted.authority_epoch = Some(AUTHORITY_EPOCH_A.to_owned());
    accepted.version = 11;
    for chunk in chunks_with_epoch(None, &accepted, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).unwrap();
    }

    let mut invalid = accepted.clone();
    invalid.server = Some(NodeId(2));
    invalid.version = 12;
    invalid.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    invalid.peers.get_mut(&NodeId(2)).unwrap().peer.key = identity.public_key;
    let result = chunks_with_epoch(None, &invalid, AUTHORITY_EPOCH_B)
        .into_iter()
        .try_for_each(|chunk| node.chunk(chunk).map(|_| ()));
    let retained = node.config().cloned();
    let installed_peers = Device::counters().unwrap().len();
    node.down().unwrap();

    assert!(
        result.is_err(),
        "the invalid new-server snapshot was accepted"
    );
    assert!(
        retained.as_ref().is_none_or(|config| {
            config.authority_epoch.as_deref() == Some(AUTHORITY_EPOCH_B)
                && config.peers.is_empty()
                && config.default_policy == DefaultPolicy::Deny
        }),
        "an invalid replacement must leave no peers from the previous server: {retained:?}"
    );
    assert_eq!(installed_peers, 0, "a stale peer key remained installed");
}

/// Persistent rollback must install the restored snapshot and keep mesh enabled.
#[test]
#[ignore = "Run in an isolated user/network namespace; J330 review."]
fn j330_persisted_rollback_accepts_replacement() {
    let (mut initial, mut accepted) = install(false);
    initial.down().unwrap();
    let path = j330_state_path("rollback");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::set_permissions(
        &path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    let mut node = Node::restore_with_engine(&path, EngineKind::Kernel).unwrap();
    let identity = node.up().unwrap();
    accepted.local_key = Some(identity.public_key);
    accepted.server = Some(NodeId(1));
    accepted.authority_epoch = Some(AUTHORITY_EPOCH_A.to_owned());
    accepted.version = 11;
    accepted.peers.get_mut(&NodeId(2)).unwrap().inbound = TrafficPolicy::All;
    accepted.peers.get_mut(&NodeId(2)).unwrap().outbound = TrafficPolicy::All;
    for chunk in chunks_with_epoch(None, &accepted, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).unwrap();
    }
    let mut restored = accepted.clone();
    restored.version = 2;
    restored.authority_epoch = Some(AUTHORITY_EPOCH_A.to_owned());
    restored.peers.clear();
    let result = node.chunk(chunks_with_epoch(None, &restored, AUTHORITY_EPOCH_A).remove(0));
    let retained = node.config().cloned();
    let installed_peers = Device::counters().unwrap().len();
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("mesh-public.json")).unwrap()).unwrap();
    println!(
        "J330_RESULT={result:?} RETAINED_VERSION={:?} DURABLE={saved}",
        retained.as_ref().map(|c| c.version)
    );
    node.down().unwrap();
    std::fs::remove_dir_all(path).unwrap();
    assert!(
        result.is_ok(),
        "persistent restored snapshot rejected: {result:?}"
    );
    assert_eq!(retained, Some(restored));
    assert_eq!(saved["enabled"], true);
    assert_eq!(saved["config"]["authority_epoch"], AUTHORITY_EPOCH_A);
    assert_eq!(saved["config"]["version"], 2);
    assert!(saved["config"]["peers"].as_object().unwrap().is_empty());
    assert_eq!(installed_peers, 0, "the replaced peer remained installed");
}

/// A failed retirement write must not leave the old peer installed.
#[test]
#[ignore = "Run in an isolated user/network namespace; J330 review."]
fn j330_failed_retirement_stops_mesh_even_if_disabled_write_fails() {
    let (mut initial, mut accepted) = install(false);
    initial.down().unwrap();
    let path = j330_state_path("retirement");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::set_permissions(
        &path,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    let mut node = Node::restore_with_engine(&path, EngineKind::Kernel).unwrap();
    let identity = node.up().unwrap();
    accepted.local_key = Some(identity.public_key);
    accepted.server = Some(NodeId(1));
    accepted.authority_epoch = Some(AUTHORITY_EPOCH_A.to_owned());
    accepted.version = 11;
    accepted.peers.get_mut(&NodeId(2)).unwrap().inbound = TrafficPolicy::All;
    accepted.peers.get_mut(&NodeId(2)).unwrap().outbound = TrafficPolicy::All;
    for chunk in chunks_with_epoch(None, &accepted, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).unwrap();
    }
    let mut restored = accepted.clone();
    restored.version = 2;
    restored.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    restored.peers.clear();
    // An occupied temporary name injects a failure publishing disabled intent.
    let obstruction = path.join(format!("mesh-public.{}.new", std::process::id()));
    std::fs::write(&obstruction, b"occupied temporary name").unwrap();
    let result = node.chunk(chunks_with_epoch(None, &restored, AUTHORITY_EPOCH_B).remove(0));
    let retained = node.config().cloned();
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("mesh-public.json")).unwrap()).unwrap();
    println!(
        "J330_RESULT={result:?} RETAINED_VERSION={:?} DURABLE={saved}",
        retained.as_ref().map(|c| c.version)
    );
    let installed_peers = Device::counters().map(|p| p.len());
    println!("J330_INSTALLED_PEERS={installed_peers:?}");
    std::fs::remove_file(obstruction).unwrap();
    node.down().unwrap();
    std::fs::remove_dir_all(path).unwrap();
    assert!(result.is_err());
    assert_eq!(
        saved["config"]["authority_epoch"], AUTHORITY_EPOCH_B,
        "a failed replacement must retain the new peer-free authority epoch"
    );
    assert!(saved["config"]["peers"].as_object().unwrap().is_empty());
    assert_eq!(saved["config"]["default_policy"], "Deny");
    assert!(retained.as_ref().is_some_and(|config| {
        config.authority_epoch.as_deref() == Some(AUTHORITY_EPOCH_B)
            && config.peers.is_empty()
            && config.default_policy == DefaultPolicy::Deny
    }));
    assert!(
        installed_peers.is_err() || installed_peers.as_ref().is_ok_and(|n| *n == 0),
        "stale peers remain installed after retirement and shutdown fail"
    );
}

/// A fresh authority reusing server node 1 must not retain peers at an equal revision.
#[test]
#[ignore = "Run in an isolated user/network namespace; J330 review."]
fn j330_equal_revision_restore_retires_stale_peers() {
    let (mut node, mut accepted) = install(false);
    let identity = node.up().unwrap();
    accepted.local_key = Some(identity.public_key);
    accepted.server = Some(NodeId(1));
    accepted.authority_epoch = Some(AUTHORITY_EPOCH_A.to_owned());
    accepted.version = 11;
    accepted.peers.get_mut(&NodeId(2)).unwrap().inbound = TrafficPolicy::All;
    accepted.peers.get_mut(&NodeId(2)).unwrap().outbound = TrafficPolicy::All;
    for chunk in chunks_with_epoch(None, &accepted, AUTHORITY_EPOCH_A) {
        node.chunk(chunk).unwrap();
    }
    let mut restored = accepted.clone();
    restored.authority_epoch = Some(AUTHORITY_EPOCH_B.to_owned());
    restored.peers.clear();
    let result = node.chunk(chunks_with_epoch(None, &restored, AUTHORITY_EPOCH_B).remove(0));
    let retained = node.config().cloned();
    let installed = Device::counters().unwrap().len();
    println!(
        "J330_EQUAL_RESTORE={result:?} RETAINED_PEERS={:?} INSTALLED_PEERS={installed}",
        retained.as_ref().map(|c| c.peers.len())
    );
    node.down().unwrap();
    assert!(
        result.is_ok(),
        "the new authority snapshot was refused: {result:?}"
    );
    assert_eq!(retained, Some(restored));
    assert_eq!(
        installed, 0,
        "same-id equal-revision server restore retained the previous authority's peers"
    );
}
