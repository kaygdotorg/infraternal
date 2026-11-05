//! Checks that route retirement removes orphan routes in both families while preserving routes outside mesh ownership [206,228], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer},
    node::{EngineKind, Node},
    policy::model::{Addresses, NodeId},
    wireguard::{Device, Key},
};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn orphan_route_retirement_preserves_foreign_routes() {
    let target = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let directory = target.join(format!("review-routes-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut node = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    node.up().unwrap();
    node.chunk(Chunk {
        access_updates: Vec::new(),
        local_key: None,
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
    install_foreign_routes();
    Device::retain_routes(&[]).unwrap();
    drop(node);
    let mut restored = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    assert!(restored.config().unwrap().peers.is_empty());
    assert!(!Device::counters().unwrap().contains_key(&key));
    let mut counts = Vec::new();
    for arguments in [
        vec!["-j", "route", "show", "10.254.0.2/32"],
        vec!["-j", "-6", "route", "show", "fd01::2/128"],
        vec!["-j", "route", "show", "10.253.0.1/32"],
        vec!["-j", "route", "show", "table", "100", "10.252.0.1/32"],
        vec!["-j", "route", "show", "10.251.0.0/24"],
        vec!["-j", "route", "show", "10.250.0.1/32"],
        vec!["-j", "route", "show", "table", "local", "10.254.0.1/32"],
    ] {
        let output = Command::new("ip").args(arguments).output().unwrap();
        assert!(output.status.success());
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        counts.push(routes.as_array().unwrap().len());
    }
    restored.down().unwrap();
    fs::remove_dir_all(directory).unwrap();
    assert_eq!(counts, [0, 0, 1, 1, 1, 1, 1]);
}

// Each route falls outside one ownership boundary; none may be retired.
fn install_foreign_routes() {
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    for arguments in [
        vec![
            "route",
            "add",
            "10.253.0.1/32",
            "dev",
            "lo",
            "proto",
            "static",
        ],
        vec![
            "route",
            "add",
            "10.252.0.1/32",
            "dev",
            "infraternal0",
            "table",
            "100",
            "proto",
            "static",
        ],
        vec![
            "route",
            "add",
            "10.251.0.0/24",
            "dev",
            "infraternal0",
            "proto",
            "static",
        ],
        vec![
            "route",
            "add",
            "10.250.0.1/32",
            "dev",
            "infraternal0",
            "proto",
            "boot",
        ],
    ] {
        assert!(
            Command::new("ip")
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
}
