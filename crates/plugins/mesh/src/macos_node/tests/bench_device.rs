//! The ignored J461 bench harness (#260): the exact Mac data path with one static peer and no
//! coordinator, so the macOS send and receive cells can be measured against other engines on
//! the same link. It lives in its own file to keep `macos_node.rs` under the repository's
//! 200,000-byte source cap.

use super::super::{MacUtun, OpenUtun, bind_udp, installed_keys};
use std::{fs, net::IpAddr, path::PathBuf};

/// Decode a 64-character hex `WireGuard` key from the bench environment.
fn bench_key(name: &str) -> [u8; 32] {
    let hex = std::env::var(name).expect("bench key variable");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex key"))
        .collect();
    bytes.try_into().expect("32-byte key")
}

/// J461 bench harness (#260): the exact Mac data path (this module's `MacUtun` reader and
/// writer, the bound UDP factory, the pinned `GotaTun` device on a current-thread runtime, as
/// `Node` builds it) with one static peer and no coordinator, so the macOS send and receive
/// cells can be measured against other engines on the same link.
///
/// Root only (utun). Environment: `J461_PRIVATE_HEX`, `J461_PEER_PUBLIC_HEX`,
/// `J461_ENDPOINT` (peer `ip:port`), `J461_PORT`, `J461_ADDR` and `J461_PEER_ADDR` (tunnel
/// IPv4 addresses), `J461_IFNAME_FILE` (the utun name is written there once up) and `J461_STOP` (the
/// device stops when that file appears). Run with
/// `cargo test --release --features agent --lib mac_bench_device -- --ignored`.
#[test]
#[ignore = "bench harness: root, a live peer and the J461_* environment"]
fn mac_bench_device() {
    use gotatun::{
        device::{DeviceBuilder, Peer as WireGuardPeer},
        x25519::{PublicKey as WgPublicKey, StaticSecret},
    };
    let var = |name: &str| std::env::var(name).expect("bench variable");
    let port: u16 = var("J461_PORT").parse().expect("port");
    let endpoint: std::net::SocketAddr = var("J461_ENDPOINT").parse().expect("endpoint");
    let peer_addr: IpAddr = var("J461_PEER_ADDR").parse().expect("peer address");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    // The worker's packet filter, compiled from a one-peer snapshot that grants the bench
    // peer every port both ways, so the filter's per-packet cost is part of the measurement
    // and nothing is dropped. An empty filter would deny all traffic.
    let mut snapshot = super::config();
    snapshot.addresses.ipv4 = var("J461_ADDR").parse().expect("tunnel IPv4");
    let peer_key = bench_key("J461_PEER_PUBLIC_HEX");
    for policy in snapshot.peers.values_mut() {
        policy.peer.key = crate::policy::model::PublicKey(peer_key);
        policy.peer.addresses.ipv4 = var("J461_PEER_ADDR").parse().expect("peer IPv4");
        policy.peer.endpoint = Some(endpoint);
    }
    let filter = std::sync::Arc::new(
        crate::packet_filter::PacketFilter::new(
            &snapshot,
            infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
        )
        .expect("compile filter"),
    );
    runtime.block_on(async {
        let utun =
            MacUtun::from_open(OpenUtun::open().expect("utun"), filter).expect("register utun");
        let private_key = StaticSecret::from(bench_key("J461_PRIVATE_HEX"));
        // The same listener `Node` binds: the exact port, behind the handshake admission
        // guard, which admits the one bench peer as an applied snapshot would.
        let request = crate::listen_port::Request {
            port,
            allow_fallback: false,
        };
        let (factory, _) = bind_udp(request, private_key.clone()).await.expect("bind");
        let mut peer = WireGuardPeer::new(WgPublicKey::from(peer_key))
            .with_allowed_ips(vec![ipnetwork::IpNetwork::new(peer_addr, 32).expect("net")]);
        peer.endpoint = Some(endpoint);
        peer.keepalive = Some(25);
        factory
            .admission
            .write()
            .await
            .set_peers(installed_keys(std::slice::from_ref(&peer)));
        let device = DeviceBuilder::new()
            .with_udp(factory)
            .with_private_key(private_key)
            .with_listen_port(port)
            .with_ip_pair(utun.sender(), utun.receiver())
            .with_peers(vec![peer])
            .build()
            .await
            .expect("device");
        utun.set_mtu(1280);
        let status = std::process::Command::new("/sbin/ifconfig")
            .args([
                utun.name(),
                "inet",
                &var("J461_ADDR"),
                &peer_addr.to_string(),
            ])
            .args(["mtu", "1280", "up"])
            .status()
            .expect("ifconfig");
        assert!(status.success(), "ifconfig failed");
        fs::write(var("J461_IFNAME_FILE"), utun.name()).expect("publish the utun name");
        let stop = PathBuf::from(var("J461_STOP"));
        while !stop.exists() {
            // sleep: poll the stop file
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        device.stop().await;
    });
}
