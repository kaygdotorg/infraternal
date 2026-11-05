//! Verifies durable peer-route ownership and write-ahead recovery without claiming operator routes [165,166], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy, Peer},
    node::{EngineKind, Node},
    policy::model::{Addresses, NodeId},
    wireguard::{Device, Key},
};
use std::{
    collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command,
};

fn fixture() -> (PathBuf, Node) {
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let directory = target.join(format!("review-inventory-{}", std::process::id()));
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
    (directory, node)
}
fn routes(ipv6: bool, destination: &str) -> serde_json::Value {
    let mut arguments = vec!["-j"];
    if ipv6 {
        arguments.push("-6");
    }
    arguments.extend(["route", "show", destination]);
    let output = Command::new("ip").args(arguments).output().unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn restart_preserves_unrecorded_direct_host_routes() {
    let (directory, node) = fixture();
    for arguments in [
        vec![
            "route",
            "add",
            "10.250.0.2/32",
            "dev",
            "infraternal0",
            "proto",
            "static",
            "scope",
            "link",
        ],
        vec![
            "-6",
            "route",
            "add",
            "fd02::2/128",
            "dev",
            "infraternal0",
            "proto",
            "static",
            "scope",
            "link",
        ],
        vec![
            "-6",
            "route",
            "add",
            "fd02::3/128",
            "via",
            "fd01::2",
            "dev",
            "infraternal0",
            "onlink",
            "proto",
            "static",
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
    let before = [
        routes(false, "10.250.0.2/32"),
        routes(true, "fd02::2/128"),
        routes(true, "fd02::3/128"),
    ];
    assert!(
        before
            .iter()
            .all(|route| route.as_array().unwrap().len() == 1)
    );
    drop(node);
    let mut restored = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    let after = [
        routes(false, "10.250.0.2/32"),
        routes(true, "fd02::2/128"),
        routes(true, "fd02::3/128"),
    ];
    restored.down().unwrap();
    fs::remove_dir_all(directory).unwrap();
    assert_eq!(
        after, before,
        "restart claimed routes outside its peer inventory"
    );
}
#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn refused_recovery_inventory_save_does_not_retire_kernel_peers_or_routes() {
    let (directory, node) = fixture();
    let (_, key) = Key::generate().unwrap();
    let peer = Peer {
        key,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01::2".parse().unwrap(),
        },
        endpoint: None,
    };
    Device::peers(std::slice::from_ref(&peer), &[]).unwrap();
    Device::routes(std::slice::from_ref(&peer), false).unwrap();
    let before = [routes(false, "10.254.0.2/32"), routes(true, "fd01::2/128")];
    drop(node);
    // Refuse the existing atomic-save boundary, without altering kernel privilege.
    let obstruction = directory.join(format!("mesh-public.{}.new", std::process::id()));
    fs::write(&obstruction, b"public fixture obstruction").unwrap();
    assert!(Node::restore_with_engine(&directory, EngineKind::Kernel).is_err());
    let retained = Device::counters().unwrap().contains_key(&key);
    let after = [routes(false, "10.254.0.2/32"), routes(true, "fd01::2/128")];
    fs::remove_file(obstruction).unwrap();
    let mut restored = Node::restore_with_engine(&directory, EngineKind::Kernel).unwrap();
    restored.down().unwrap();
    fs::remove_dir_all(directory).unwrap();
    assert!(
        retained,
        "recovery retired a peer before recording route ownership"
    );
    assert_eq!(
        after, before,
        "recovery retired routes before recording ownership"
    );
}
