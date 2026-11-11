//! J411 review reproducers (#381): a relay route-MTU callback keeps the peer record it was built
//! with, so a later coordinator snapshot cannot change what that callback writes.
#![cfg(all(feature = "agent", feature = "relay", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use infraternal_plugin_mesh::{
    dataplane::{Chunk, Peer},
    node::{EngineKind, Node},
    policy::model::{Addresses, PublicKey},
    relay_path::EndpointUpdater,
    wireguard::Key,
};
use serde_json::{Value, json};
use std::process::Command;

/// Run one `ip` command in the disposable namespace and return its output.
fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Build the snapshot entry for peer 2 with the given endpoint.
fn peer_entry(key: PublicKey, endpoint: &str) -> Value {
    json!({
        "peer": {"key": key, "addresses": {"ipv4": "10.254.0.2", "ipv6": "fd01::2"}, "endpoint": endpoint},
        "inbound": "All", "outbound": "All"
    })
}

/// Two underlays: a normal 1500-byte path and a narrow 1280-byte path.
fn underlays() {
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "wide0", "type", "dummy"]);
    ip(&["link", "set", "wide0", "mtu", "1500", "up"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "wide0"]);
    ip(&["link", "add", "narrow0", "type", "dummy"]);
    ip(&["link", "set", "narrow0", "mtu", "1280", "up"]);
    ip(&["addr", "add", "198.51.100.1/24", "dev", "narrow0"]);
}

/// The peer record a relay shim captures when it is created (`relay_with_endpoint`).
fn captured_peer(key: PublicKey, endpoint: &str) -> Peer {
    Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01::2".parse().unwrap(),
        },
        endpoint: Some(endpoint.parse().unwrap()),
    }
}

/// Direct fallback after an endpoint change must use the accepted endpoint, not the old one.
#[test]
#[ignore = "Run as root inside a disposable network namespace."]
fn relay_fallback_after_endpoint_change_uses_current_endpoint_budget() {
    underlays();
    let mut node = Node::default().with_engine(EngineKind::Kernel);
    node.up().unwrap();
    let (_, key) = Key::generate().unwrap();
    let mut chunk: Value = json!({"node": 1, "from_version": null, "version": 1, "index": 0, "last": true,
        "addresses": {"ipv4": "10.254.0.1", "ipv6": "fd01::1"}, "default_policy": "Allow",
        "upserted": {"2": peer_entry(key, "192.0.2.2:51820")}, "removed": []});
    node.chunk(serde_json::from_value::<Chunk>(chunk.clone()).unwrap())
        .unwrap();
    // The relay shim is created while the peer's endpoint is on the wide path.
    let updater = node.route_mtu_updater(&captured_peer(key, "192.0.2.2:51820"));
    updater(Some(1392)).unwrap();
    let relayed = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    // The coordinator moves the peer to an endpoint on the narrow path.
    chunk["from_version"] = json!(1);
    chunk["version"] = json!(2);
    chunk["upserted"] = json!({"2": peer_entry(key, "198.51.100.2:51820")});
    node.chunk(serde_json::from_value::<Chunk>(chunk).unwrap())
        .unwrap();
    let moved = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    // The relay link drops and settle restores the direct budget.
    updater(None).unwrap();
    let fallback = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    node.down().unwrap();
    println!("relayed={relayed}after_endpoint_move={moved}after_direct_fallback={fallback}");
    assert!(moved.contains("mtu 1200"), "{moved}");
    assert!(
        fallback.contains("mtu 1200"),
        "direct fallback wrote the old endpoint's budget onto the narrow path: {fallback}"
    );
}

/// A relay callback for a peer the coordinator removed must not reinstall its host route.
#[test]
#[ignore = "Run as root inside a disposable network namespace."]
fn relay_callback_after_peer_removal_does_not_reinstall_route() {
    underlays();
    let mut node = Node::default().with_engine(EngineKind::Kernel);
    node.up().unwrap();
    let (_, key) = Key::generate().unwrap();
    let mut chunk: Value = json!({"node": 1, "from_version": null, "version": 1, "index": 0, "last": true,
        "addresses": {"ipv4": "10.254.0.1", "ipv6": "fd01::1"}, "default_policy": "Allow",
        "upserted": {"2": peer_entry(key, "192.0.2.2:51820")}, "removed": []});
    node.chunk(serde_json::from_value::<Chunk>(chunk.clone()).unwrap())
        .unwrap();
    let updater = node.route_mtu_updater(&captured_peer(key, "192.0.2.2:51820"));
    chunk["from_version"] = json!(1);
    chunk["version"] = json!(2);
    chunk["upserted"] = json!({});
    chunk["removed"] = json!([2]);
    node.chunk(serde_json::from_value::<Chunk>(chunk).unwrap())
        .unwrap();
    let removed = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    // A relay MTU poll or settle for the removed peer fires afterwards.
    let late = updater(Some(1392));
    let after = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    node.down().unwrap();
    println!("after_removal=[{removed}] late_callback={late:?} after_late_callback=[{after}]");
    assert!(removed.trim().is_empty(), "{removed}");
    assert!(
        after.trim().is_empty(),
        "a late relay callback reinstalled a removed peer's route: {after}"
    );
}
