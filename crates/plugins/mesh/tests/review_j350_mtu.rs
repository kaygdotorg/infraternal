//! Reproduces stale peer route MTUs after an underlay change and an unrelated peer update (#381).
#![cfg(feature = "agent")]
#![allow(clippy::unwrap_used)]

#[cfg(target_os = "linux")]
use infraternal_plugin_mesh::{
    dataplane::Chunk,
    node::{EngineKind, Node},
    wireguard::Key,
};
#[cfg(target_os = "linux")]
use serde_json::{Value, json};
#[cfg(target_os = "linux")]
use std::process::Command;

/// Direct-path budgets must also fit the relay's additional framing on narrow and normal paths.
#[cfg(feature = "relay")]
#[tokio::test]
async fn narrow_path_mesh_budget_fits_relay_datagram() {
    use infraternal_plugin_relay::{
        client::Client,
        quinn,
        relay::{Admission, Limits, Relay},
        testing::{Authority, Purpose},
        tls,
        wire::HostId,
    };
    use std::{sync::Arc, time::Duration};
    let mut authority = Authority::new();
    let admission: Admission = Arc::new(|_| true);
    let relay = Relay::start(
        "127.0.0.1:0".parse().unwrap(),
        authority.issue(Purpose::Relay("relay.mesh.test")),
        Limits::default(),
        admission,
    )
    .unwrap();
    let mut results = Vec::new();
    for (id, underlay, previous_inner, safe_inner, expected_max) in
        [(1, 1280, 1200, 1168, 1214), (2, 1500, 1420, 1392, 1434)]
    {
        let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut config =
            tls::client_config(authority.issue(Purpose::Host(HostId([id; 16])))).unwrap();
        let mut transport = quinn::TransportConfig::default();
        // IPv4 and UDP consume 28 bytes of each underlay packet.
        transport
            .initial_mtu(underlay - 28)
            .min_mtu(underlay - 28)
            .mtu_discovery_config(None);
        config.transport_config(Arc::new(transport));
        let (client, _notices) = Client::connect(
            &endpoint,
            config,
            relay.local_addr().unwrap(),
            "relay.mesh.test",
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let maximum = client.connection().max_datagram_size();
        assert_eq!(maximum, Some(expected_max));
        // Quinn reserves QUIC framing. WireGuard pads each inner packet to 16 bytes before
        // adding its 32-byte header/tag; the relay prefixes a 4-byte link id.
        let pad_to_wireguard_block = |size: u16| {
            let size = usize::from(size);
            (size + 15) & !15
        };
        let inner = usize::from(safe_inner);
        let padded_inner = pad_to_wireguard_block(safe_inner);
        let relay_frame = padded_inner + 32 + 4;
        let result = client
            .connection()
            .send_datagram(bytes::Bytes::from(vec![0; relay_frame]));
        // The previous direct-path budgets exceed both relay limits.
        let previous_frame = pad_to_wireguard_block(previous_inner) + 32 + 4;
        let legacy = client
            .connection()
            .send_datagram(bytes::Bytes::from(vec![0; previous_frame]));
        // The shipped 1380-byte packet fitted a normal relay path but not a narrow one.
        let shipped_frame = pad_to_wireguard_block(1380) + 32 + 4;
        let shipped = client
            .connection()
            .send_datagram(bytes::Bytes::from(vec![0; shipped_frame]));
        println!(
            "underlay={underlay} inner_mtu={inner} padded_inner={padded_inner} relay_frame={relay_frame} actual_max={maximum:?} send_result={result:?} previous_budget_send={legacy:?} shipped_1380_send={shipped:?}"
        );
        assert!(
            legacy.is_err(),
            "previous budget unexpectedly fit: {legacy:?}"
        );
        assert_eq!(shipped.is_ok(), underlay == 1500);
        results.push(result);
        client.connection().close(0_u32.into(), b"done");
    }
    relay.close().await;
    assert!(
        results.iter().all(Result::is_ok),
        "derived mesh budgets cannot pass through the relay: {results:?}"
    );
}

/// An explicit route metric must not make the mesh budget exceed its actual egress link.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Run as root inside a disposable network namespace."]
fn endpoint_route_metric_is_bounded_by_egress_link_mtu() {
    use infraternal_plugin_mesh::{dataplane::Peer, policy::model::Addresses, wireguard::Device};
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "underlay0", "type", "dummy"]);
    ip(&["link", "set", "underlay0", "mtu", "1280", "up"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "underlay0"]);
    ip(&[
        "route",
        "add",
        "198.51.100.2/32",
        "dev",
        "underlay0",
        "mtu",
        "9000",
    ]);
    let mut node = Node::default().with_engine(EngineKind::Kernel);
    node.up().unwrap();
    Device::addresses(Addresses {
        ipv4: "10.254.0.1".parse().unwrap(),
        ipv6: "fd01::1".parse().unwrap(),
    })
    .unwrap();
    let (_, key) = Key::generate().unwrap();
    let peer = Peer {
        key,
        previous_key: None,
        previous_active: false,
        addresses: Addresses {
            ipv4: "10.254.0.2".parse().unwrap(),
            ipv6: "fd01::2".parse().unwrap(),
        },
        endpoint: Some("198.51.100.2:51820".parse().unwrap()),
    };
    Device::routes(&[peer], false).unwrap();
    let underlay = ip(&["route", "get", "198.51.100.2"]);
    let mesh = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    node.down().unwrap();
    println!("underlay_link_mtu=1280 underlay={underlay}mesh={mesh}");
    assert!(
        mesh.contains("mtu 1200"),
        "mesh budget exceeds the egress link: {mesh}"
    );
}

/// Run a route command in the disposable namespace, retaining its output on failure.
#[cfg(target_os = "linux")]
fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// A successful full peer update must refresh the unchanged peer's budget after its path narrows.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Run as root inside a disposable network namespace."]
fn full_peer_update_refreshes_existing_peer_route_mtu() {
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "underlay0", "type", "dummy"]);
    ip(&["link", "set", "underlay0", "mtu", "1500", "up"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "underlay0"]);
    let mut node = Node::default().with_engine(EngineKind::Kernel);
    node.up().unwrap();
    let (_, first) = Key::generate().unwrap();
    let (_, second) = Key::generate().unwrap();
    let peer = |key, id: u8| {
        json!({
            "peer": {"key": key, "addresses": {"ipv4": format!("10.254.0.{id}"), "ipv6": format!("fd01::{id}")}, "endpoint": format!("192.0.2.{id}:51820")},
            "inbound": "All", "outbound": "All"
        })
    };
    let mut chunk: Value = json!({"node": 1, "from_version": null, "version": 1, "index": 0, "last": true,
        "addresses": {"ipv4": "10.254.0.1", "ipv6": "fd01::1"}, "default_policy": "Allow",
        "upserted": {"2": peer(first, 2)}, "removed": []});
    node.chunk(serde_json::from_value::<Chunk>(chunk.clone()).unwrap())
        .unwrap();
    let before = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    ip(&["link", "set", "underlay0", "mtu", "1280"]);
    chunk["from_version"] = json!(1);
    chunk["version"] = json!(2);
    chunk["upserted"] = json!({"3": peer(second, 3)});
    node.chunk(serde_json::from_value::<Chunk>(chunk).unwrap())
        .unwrap();
    let after = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    let added = ip(&["route", "show", "exact", "10.254.0.3/32"]);
    node.down().unwrap();
    println!("before={before}after={after}new_peer={added}");
    assert!(before.contains("mtu 1420"), "{before}");
    assert!(added.contains("mtu 1200"), "{added}");
    assert!(
        after.contains("mtu 1200"),
        "unchanged peer kept an unsafe route budget: {after}"
    );
}
/// Access-only snapshots must also refresh the path budget after the underlay narrows.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Run as root inside a disposable network namespace."]
fn access_only_update_refreshes_existing_peer_route_mtu() {
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "underlay0", "type", "dummy"]);
    ip(&["link", "set", "underlay0", "mtu", "1500", "up"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "underlay0"]);
    let mut node = Node::default().with_engine(EngineKind::Kernel);
    node.up().unwrap();
    let (_, first) = Key::generate().unwrap();
    let peer = |key, id: u8| {
        json!({
            "peer": {"key": key, "addresses": {"ipv4": format!("10.254.0.{id}"), "ipv6": format!("fd01::{id}")}, "endpoint": format!("192.0.2.{id}:51820")},
            "inbound": "All", "outbound": "All"
        })
    };
    let mut chunk: Value = json!({"node": 1, "from_version": null, "version": 1, "index": 0, "last": true,
        "addresses": {"ipv4": "10.254.0.1", "ipv6": "fd01::1"}, "default_policy": "Allow",
        "upserted": {"2": peer(first, 2)}, "removed": []});
    node.chunk(serde_json::from_value::<Chunk>(chunk.clone()).unwrap())
        .unwrap();
    let before = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    ip(&["link", "set", "underlay0", "mtu", "1280"]);
    chunk["from_version"] = json!(1);
    chunk["version"] = json!(2);
    chunk["upserted"] = json!({"2": peer(first, 2)});
    chunk["upserted"]["2"]["inbound"] = json!("None");
    node.chunk(serde_json::from_value::<Chunk>(chunk).unwrap())
        .unwrap();
    let after = ip(&["route", "show", "exact", "10.254.0.2/32"]);
    node.down().unwrap();
    println!("before={before}after_access_only_update={after}");
    assert!(before.contains("mtu 1420"), "{before}");
    assert!(
        after.contains("mtu 1200"),
        "unchanged peer kept an unsafe route budget: {after}"
    );
}
