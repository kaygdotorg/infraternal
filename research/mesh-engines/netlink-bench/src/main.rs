//! Measure typed Generic Netlink configuration against a live kernel WireGuard device.
//!
//! The benchmark creates 1,000 distinct public peer keys and allowed IPv4 routes,
//! applies them through `nl-wireguard`, then verifies a one-peer update, removal,
//! and the readback fields used for handshake and traffic statistics. The keys
//! are synthetic public test values; the device has no private key or endpoint.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use nl_wireguard::{
    WireguardIpAddress, WireguardParsed, WireguardParsedDeviceFlags,
    WireguardParsedPeerFlags, WireguardPeerParsed, new_connection,
};

const IFACE: &str = "wgctl";
const PEER_COUNT: usize = 1_000;
const PORT: u16 = 51_820;

fn public_key(index: usize) -> String {
    let mut key = [0_u8; 32];
    key[..4].copy_from_slice(&(index as u32 + 1).to_be_bytes());
    for (offset, byte) in key[4..].iter_mut().enumerate() {
        *byte = ((index.wrapping_mul(37) + offset.wrapping_mul(19) + 1) % 255 + 1) as u8;
    }
    STANDARD.encode(key)
}

fn allowed_ip(index: usize, changed: bool) -> WireguardIpAddress {
    let address = if changed {
        Ipv4Addr::new(10, 99, (index / 256) as u8, (index % 256) as u8)
    } else {
        Ipv4Addr::new(10, 88, (index / 256) as u8, (index % 256) as u8)
    };
    WireguardIpAddress {
        ip_addr: IpAddr::V4(address),
        prefix_length: 32,
        flags: None,
    }
}

fn peer(index: usize, changed: bool) -> WireguardPeerParsed {
    let mut peer = WireguardPeerParsed::default();
    peer.public_key = Some(public_key(index));
    peer.allowed_ips = Some(vec![allowed_ip(index, changed)]);
    peer.flags = Some(vec![WireguardParsedPeerFlags::ReplaceAllowedIps]);
    peer
}

fn initial_config() -> WireguardParsed {
    let mut config = WireguardParsed::default();
    config.iface_name = Some(IFACE.to_owned());
    config.listen_port = Some(PORT);
    config.peers = Some((0..PEER_COUNT).map(|i| peer(i, false)).collect());
    config.flags = Some(vec![WireguardParsedDeviceFlags::ReplacePeers]);
    config
}

fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|value| value.split_whitespace().take(3).map(str::to_owned).reduce(|a, b| format!("{a}/{b}")))
        .unwrap_or_else(|| "NA".to_owned())
}

fn verify_peer_set(config: &WireguardParsed, count: usize, changed_index: Option<usize>) -> Result<(), Box<dyn Error>> {
    let peers = config.peers.as_ref().ok_or("kernel readback omitted peers")?;
    if peers.len() != count {
        return Err(format!("expected {count} peers, got {}", peers.len()).into());
    }
    let indices: HashMap<_, _> = (0..PEER_COUNT).map(|i| (public_key(i), i)).collect();
    let mut seen = HashSet::with_capacity(count);
    for got in peers {
        let key = got.public_key.as_deref().ok_or("kernel readback omitted a public key")?;
        let index = *indices.get(key).ok_or("kernel returned an unknown peer key")?;
        if !seen.insert(index) {
            return Err(format!("kernel returned peer {index} more than once").into());
        }
        let changed = changed_index == Some(index);
        if got.allowed_ips.as_ref() != Some(&vec![allowed_ip(index, changed)]) {
            return Err(format!("peer {index} allowed IP readback mismatch").into());
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let load_start = load_average();
    let (connection, mut handle, _) = new_connection()?;
    tokio::spawn(connection);

    let config = initial_config();
    let start = Instant::now();
    handle.set(config).await?;
    let apply_1000_us = start.elapsed().as_micros();

    let current = handle.get_by_name(IFACE).await?;
    if current.listen_port != Some(PORT) {
        return Err("listen port readback mismatch".into());
    }
    verify_peer_set(&current, PEER_COUNT, None)?;
    let stats_fields_present = current
        .peers
        .as_ref()
        .and_then(|peers| peers.first())
        .is_some_and(|p| p.last_handshake.is_some() || p.rx_bytes.is_some() || p.tx_bytes.is_some());
    let stats_device = handle.get_by_name("wgstatA").await?;
    let handshake_stats_verified = stats_device
        .peers
        .as_ref()
        .and_then(|peers| peers.first())
        .is_some_and(|p| p.last_handshake.is_some() && p.rx_bytes.unwrap_or(0) > 0 && p.tx_bytes.unwrap_or(0) > 0);
    if !handshake_stats_verified {
        return Err("live handshake and traffic counters did not read back".into());
    }

    let changed_index = 500;
    let start = Instant::now();
    let mut update = WireguardParsed::default();
    update.iface_name = Some(IFACE.to_owned());
    update.peers = Some(vec![peer(changed_index, true)]);
    handle.set(update).await?;
    let update_one_us = start.elapsed().as_micros();
    let current = handle.get_by_name(IFACE).await?;
    verify_peer_set(&current, PEER_COUNT, Some(changed_index))?;

    let remove_key = public_key(PEER_COUNT - 1);
    let start = Instant::now();
    handle.remove_peer(IFACE, &remove_key).await?;
    let remove_one_us = start.elapsed().as_micros();
    let after_remove = handle.get_by_name(IFACE).await?;
    let remaining = after_remove.peers.as_ref().ok_or("remove readback omitted peers")?;
    if remaining.len() != PEER_COUNT - 1 || remaining.iter().any(|p| p.public_key.as_deref() == Some(remove_key.as_str())) {
        return Err("peer removal did not preserve the remaining peer set".into());
    }

    let load_end = load_average();
    println!(
        "loadavg_start,loadavg_end,apply_1000_us,update_one_of_1000_us,remove_one_of_1000_us,get_peers,get_listen_port,handshake_stats_fields_present,handshake_stats_verified\n{load_start},{load_end},{apply_1000_us},{update_one_us},{remove_one_us},{},{},{stats_fields_present},{handshake_stats_verified}",
        remaining.len(),
        after_remove.listen_port == Some(PORT),
    );
    Ok(())
}
