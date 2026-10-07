//! Measure `nlink`'s high-level Linux WireGuard configuration API against the
//! same 1,000-peer kernel device used by the other control-plane benchmarks.
//!
//! Synthetic public keys and allowed IPs exercise replacement, one-peer update,
//! removal, and GET_DEVICE stats readback. The program contains no private key
//! or endpoint and writes no peer data to disk.

use std::{
    collections::HashSet,
    error::Error,
    net::Ipv4Addr,
    time::Instant,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use nlink::{
    netlink::{Connection, Wireguard},
    netlink::genl::wireguard::{AllowedIp, WgDeviceBuilder, WgPeerBuilder},
};
use nl_wireguard::{
    WireguardIpAddress, WireguardParsed, WireguardParsedDeviceFlags,
    WireguardParsedPeerFlags, WireguardPeerParsed, new_connection,
};

const IFACE: &str = "wgctl";
const PEER_COUNT: usize = 1_000;
const PORT: u16 = 51_820;

fn key(index: usize) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key[..4].copy_from_slice(&(index as u32 + 1).to_be_bytes());
    for (offset, byte) in key[4..].iter_mut().enumerate() {
        *byte = ((index.wrapping_mul(37) + offset.wrapping_mul(19) + 1) % 255 + 1) as u8;
    }
    key
}

fn allowed_ip(index: usize, changed: bool) -> AllowedIp {
    let (a, b) = if changed { (10, 99) } else { (10, 88) };
    AllowedIp::v4(Ipv4Addr::new(a, b, (index / 256) as u8, (index % 256) as u8), 32)
}

fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|value| value.split_whitespace().take(3).map(str::to_owned).reduce(|a, b| format!("{a}/{b}")))
        .unwrap_or_else(|| "NA".to_owned())
}

fn chunked_baseline() -> WireguardParsed {
    let mut peers = Vec::with_capacity(PEER_COUNT);
    for index in 0..PEER_COUNT {
        let mut peer = WireguardPeerParsed::default();
        peer.public_key = Some(STANDARD.encode(key(index)));
        peer.allowed_ips = Some(vec![WireguardIpAddress {
            ip_addr: std::net::IpAddr::V4(Ipv4Addr::new(
                10,
                88,
                (index / 256) as u8,
                (index % 256) as u8,
            )),
            prefix_length: 32,
            flags: None,
        }]);
        peer.flags = Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);
        peers.push(peer);
    }
    let mut config = WireguardParsed::default();
    config.iface_name = Some(IFACE.to_owned());
    config.listen_port = Some(PORT);
    config.peers = Some(peers);
    config.flags = Some(vec![WireguardParsedDeviceFlags::ReplacePeers]);
    config
}

fn verify_state(
    peers: &[nlink::netlink::genl::wireguard::WgPeer],
    expected_count: usize,
    changed_index: Option<usize>,
) -> Result<usize, Box<dyn Error>> {
    if peers.len() != expected_count {
        return Err(format!("expected {expected_count} peers, got {}", peers.len()).into());
    }
    let mut seen = HashSet::with_capacity(expected_count);
    let mut stats_fields = 0;
    for peer in peers {
        let index = (0..PEER_COUNT)
            .find(|i| key(*i) == peer.public_key)
            .ok_or("kernel returned unknown peer key")?;
        if !seen.insert(index) {
            return Err("kernel returned a duplicate peer key".into());
        }
        let changed = changed_index == Some(index);
        if peer.allowed_ips != vec![allowed_ip(index, changed)] {
            return Err(format!("peer {index} allowed-IP readback mismatch").into());
        }
        if peer.last_handshake.is_some() || peer.rx_bytes == 0 || peer.tx_bytes == 0 {
            stats_fields += 1;
        }
    }
    Ok(stats_fields)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let load_start = load_average();
    let connection = Connection::<Wireguard>::new_async().await?;

    let mut desired = WgDeviceBuilder::new().listen_port(PORT).replace_peers();
    for index in 0..PEER_COUNT {
        desired = desired.peer(WgPeerBuilder::new(key(index)).allowed_ip(allowed_ip(index, false)));
    }
    let start = Instant::now();
    let apply_result = connection.set_device_by_name(IFACE, |_| desired).await;
    let apply_1000_us = start.elapsed().as_micros();
    let mut apply_status = "ok";
    let mut fallback_set_1000_us = "NA".to_owned();
    if let Err(error) = apply_result {
        apply_status = if error.to_string().contains("errno 22") {
            "rejected_einval"
        } else {
            "rejected_error"
        };
        let partial = connection.get_device_by_name(IFACE).await?;
        if !partial.peers.is_empty() {
            return Err("nlink 1,000-peer failure left a partial peer set".into());
        }
        let start = Instant::now();
        let (task, mut handle, _) = new_connection()?;
        tokio::spawn(task);
        handle.set(chunked_baseline()).await?;
        fallback_set_1000_us = start.elapsed().as_micros().to_string();
    }

    let current = connection.get_device_by_name(IFACE).await?;
    if current.listen_port != Some(PORT) {
        return Err("listen-port readback mismatch".into());
    }
    let _initial_stats = verify_state(&current.peers, PEER_COUNT, None)?;

    let changed_index = 500;
    let start = Instant::now();
    connection
        .set_peer_by_name(IFACE, key(changed_index), |peer| {
            peer.replace_allowed_ips().allowed_ip(allowed_ip(changed_index, true))
        })
        .await?;
    let update_one_us = start.elapsed().as_micros();
    let updated = connection.get_device_by_name(IFACE).await?;
    let stats_fields = verify_state(&updated.peers, PEER_COUNT, Some(changed_index))?;

    let start = Instant::now();
    connection.del_peer_by_name(IFACE, key(PEER_COUNT - 1)).await?;
    let remove_one_us = start.elapsed().as_micros();
    let after_remove = connection.get_device_by_name(IFACE).await?;
    verify_state(&after_remove.peers, PEER_COUNT - 1, Some(changed_index))?;
    let stats_device = connection.get_device_by_name("wgstatA").await?;
    let handshake_stats_verified = stats_device.peers.iter().any(|peer| {
        peer.last_handshake.is_some() && peer.rx_bytes > 0 && peer.tx_bytes > 0
    });
    if !handshake_stats_verified {
        return Err("live handshake and traffic counters did not read back".into());
    }
    let load_end = load_average();

    println!(
        "loadavg_start,loadavg_end,apply_status,apply_1000_us,chunked_baseline_set_1000_us,update_one_of_1000_us,remove_one_of_1000_us,get_peers,get_listen_port,handshake_stats_fields_read,handshake_stats_verified\n{load_start},{load_end},{apply_status},{apply_1000_us},{fallback_set_1000_us},{update_one_us},{remove_one_us},{},{},{stats_fields},{handshake_stats_verified}",
        after_remove.peers.len(),
        after_remove.listen_port == Some(PORT),
    );
    Ok(())
}
