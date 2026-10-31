//! Checks restart retirement preserves operator gateway routes outside the installed peer-route shape [165,166], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy},
    node::Node,
    policy::model::{Addresses, NodeId},
};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn restart_preserves_operator_gateway_host_route() {
    let target = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let directory = target.join(format!("review-route-scope-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let mut node = Node::restore(&directory).unwrap();
    node.up().unwrap();
    node.chunk(Chunk {
        access_updates: Vec::new(),
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        from_version: None,
        version: 1,
        index: 0,
        last: true,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        upserted: BTreeMap::new(),
        merged: BTreeMap::new(),
        removed: Vec::new(),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: std::collections::BTreeMap::new(),
    })
    .unwrap();
    // Peer routes are direct scope-link entries. This operator entry instead
    // has a gateway and global scope, and was never in the saved peer inventory.
    assert!(
        Command::new("ip")
            .args([
                "route",
                "add",
                "10.250.0.1/32",
                "via",
                "10.254.0.2",
                "dev",
                "infraternal0",
                "onlink",
                "proto",
                "static",
            ])
            .status()
            .unwrap()
            .success()
    );
    let before = route();
    assert_eq!(before.as_array().unwrap().len(), 1);
    drop(node);
    let mut restored = Node::restore(&directory).unwrap();
    let after = route();
    restored.down().unwrap();
    fs::remove_dir_all(directory).unwrap();
    assert_eq!(after, before, "restart retired an operator gateway route");
}

fn route() -> serde_json::Value {
    let output = Command::new("ip")
        .args(["-j", "route", "show", "10.250.0.1/32"])
        .output()
        .unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}
