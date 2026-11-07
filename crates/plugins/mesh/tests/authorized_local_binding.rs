//! Checks authenticated local-key rotation, split binding refusal and exact address recovery on both backends [166,199], #173.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_mesh::{
    configuration,
    dataplane::{Config, DefaultPolicy},
    firewall::Backend,
    node::Node,
    policy::model::{Addresses, NodeId, PublicKey},
    wireguard::{Device, INTERFACE},
};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, process::Command};
fn installed() -> serde_json::Value {
    let output = Command::new("ip")
        .args(["-j", "address", "show", "dev", INTERFACE])
        .output()
        .unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}
/// Exercise refusal, replacement, and restart boundaries on a real kernel backend.
fn check(backend: Backend) {
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join(format!("binding-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut node = Node::restore(&root).unwrap();
    // Selecting the backend in persisted public intent keeps restart on that frontend.
    node.down().unwrap();
    drop(node);
    let store = infraternal_plugin_mesh::node_state::Store::open(&root)
        .unwrap()
        .0;
    store
        .save(&infraternal_plugin_mesh::node_state::State {
            enabled: true,
            config: None,
            authority_reset_pending: false,
            backend: Some(backend),
        })
        .unwrap();
    let mut node = Node::restore(&root).unwrap();
    let identity = node.up().unwrap();
    let mut old = Config {
        authority_epoch: None,
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns-spike")]
        name: None,
        #[cfg(feature = "mesh-dns-spike")]
        dns_suffix: "internal".to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: "10.254.0.1".parse().unwrap(),
            ipv6: "fd01::1".parse().unwrap(),
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::new(),
        #[cfg(feature = "mesh-dns-spike")]
        peer_names: std::collections::BTreeMap::new(),
    };
    for chunk in configuration::chunks(None, &old).unwrap() {
        node.chunk(chunk).unwrap();
    }
    // An upgrade must bind an unchanged legacy snapshot without needing an
    // unrelated policy edit. Every previously accepted field stays identical.
    old.local_key = Some(identity.public_key);
    for chunk in configuration::chunks(None, &old).unwrap() {
        node.chunk(chunk).unwrap();
    }
    assert_eq!(node.config(), Some(&old));
    let mut new = old.clone();
    new.node = NodeId(3);
    new.version = 2;
    new.addresses = Addresses {
        ipv4: "10.254.0.3".parse().unwrap(),
        ipv6: "fd01::3".parse().unwrap(),
    };
    let mut wrong = configuration::chunks(None, &new).unwrap().remove(0);
    wrong.local_key = Some(PublicKey([7; 32]));
    assert!(node.chunk(wrong).is_err());
    assert_eq!(node.config(), Some(&old));
    let mut first = configuration::chunks(None, &new).unwrap().remove(0);
    first.last = false;
    let mut last = first.clone();
    last.index = 1;
    last.last = true;
    last.local_key = Some(PublicKey([8; 32]));
    assert!(!node.chunk(first).unwrap());
    assert!(node.chunk(last).is_err());
    assert_eq!(node.config(), Some(&old));
    for chunk in configuration::chunks(None, &new).unwrap() {
        node.chunk(chunk).unwrap();
    }
    assert_eq!(node.config(), Some(&new));
    let live = installed().to_string();
    assert!(live.contains("10.254.0.3") && live.contains("fd01::3"));
    assert!(!live.contains("10.254.0.1") && !live.contains("fd01::1"));
    // Simulate an old alias retained across an interrupted replacement. Recovery
    // must reconcile the owned interface from the accepted durable snapshot.
    assert!(
        Command::new("ip")
            .args(["addr", "add", "10.254.0.1/32", "dev", INTERFACE])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("ip")
            .args([
                "-6",
                "addr",
                "add",
                "fd01::1/128",
                "dev",
                INTERFACE,
                "nodad"
            ])
            .status()
            .unwrap()
            .success()
    );
    drop(node);
    let mut recovered = Node::restore(&root).unwrap();
    assert_eq!(recovered.config(), Some(&new));
    let live = installed().to_string();
    assert!(!live.contains("10.254.0.1") && !live.contains("fd01::1"));
    assert!(Device::owned().unwrap());
    recovered.down().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nft_local_binding_and_address_recovery() {
    check(Backend::Nft);
}
#[test]
#[ignore = "Run in a disposable user/network namespace, #173."]
fn nf_tables_local_binding_and_address_recovery() {
    check(Backend::NfTables);
}
