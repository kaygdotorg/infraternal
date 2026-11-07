//! Verifies reconciliation of owned peer routes after an interrupted apply leaves kernel state newer than durable state [166], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer},
    node::{EngineKind, Node},
    policy::model::{Addresses, NodeId},
    wireguard::{Device, Key},
};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, process::Command};

/// A restart retires host routes of peers that are gone.
#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn restart_retires_orphan_peer_host_routes() {
    let target = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let directory = target.join(format!("review-routes-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut node = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    node.up().unwrap();
    node.chunk(Chunk {
        access_updates: Vec::new(),
        local_key: None,
        authority_epoch: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix: "internal".to_owned(),
        from_version: None,
        version: 1,
        index: 0,
        last: true,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        upserted: BTreeMap::new(),
        merged: BTreeMap::new(),
        removed: Vec::new(),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: std::collections::BTreeMap::new(),
        #[cfg(feature = "mesh-dns-spike")]
        removed_peer_names: Vec::new(),
    })
    .unwrap();
    let (_, key) = Key::generate().unwrap();
    let orphan = Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01::2".parse().unwrap(),
        },
        endpoint: None,
    };
    // Model a stop after peers/routes reached the kernel, before public-state
    // fsync. Node deliberately has no Drop cleanup so existing sessions survive.
    Device::peers(std::slice::from_ref(&orphan), &[]).unwrap();
    Device::routes(std::slice::from_ref(&orphan), false).unwrap();
    assert!(Device::counters().unwrap().contains_key(&key));
    drop(node);
    let mut restored = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    assert!(restored.config().unwrap().peers.is_empty());
    assert!(!Device::counters().unwrap().contains_key(&key));
    let routes = Command::new("ip")
        .args(["-j", "route", "show", "10.254.0.2/32"])
        .output()
        .unwrap();
    assert!(routes.status.success());
    let routes: serde_json::Value = serde_json::from_slice(&routes.stdout).unwrap();
    restored.down().unwrap();
    fs::remove_dir_all(directory).unwrap();
    assert!(
        routes.as_array().unwrap().is_empty(),
        "restart retained a removed peer's owned host route: {routes}"
    );
}
