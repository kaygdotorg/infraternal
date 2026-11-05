//! Checks that the translated-ingress fence preserves node-local service access [163,216], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, DefaultPolicy},
    firewall::Firewall,
    node::Node,
    policy::model::{Addresses, NodeId},
};
use std::{collections::BTreeMap, net::UdpSocket, process::Command, time::Duration};

fn check(firewall: Firewall) {
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    let mut node = Node::with_firewall(firewall);
    node.up().unwrap();
    node.chunk(Chunk {
        access_updates: Vec::new(),
        local_key: None,
        server: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
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
        #[cfg(feature = "mesh-dns")]
        peer_names: std::collections::BTreeMap::new(),
        #[cfg(feature = "mesh-dns")]
        removed_peer_names: Vec::new(),
    })
    .unwrap();
    let mut results = Vec::new();
    for address in ["10.254.0.1:5222", "[fd01::1]:5222"] {
        let listener = UdpSocket::bind(address).unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let sender = UdpSocket::bind(if address.starts_with('[') {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        })
        .unwrap();
        sender.send_to(b"public local fixture", address).unwrap();
        let mut bytes = [0; 64];
        results.push(listener.recv(&mut bytes).ok());
    }
    node.down().unwrap();
    assert_eq!(results, [Some(20), Some(20)], "node-local delivery refused");
}

#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn nft_node_local_mesh_delivery_remains_available() {
    check(Firewall::default());
}

#[test]
#[ignore = "Run inside a dedicated user/network namespace with CAP_NET_ADMIN."]
fn nf_tables_node_local_mesh_delivery_remains_available() {
    check(Firewall::nf_tables());
}
