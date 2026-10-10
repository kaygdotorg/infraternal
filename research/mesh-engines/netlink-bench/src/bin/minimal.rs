//! Benchmark a thin Generic Netlink client built directly on typed WireGuard
//! attributes and the synchronous netlink socket API.
//!
//! The program constructs each request itself, splits a 1,000-peer update into
//! safe chunks, and checks GET_DEVICE replies for peer keys, allowed IPs, the
//! listen port, handshake time, and traffic counters. It contains no private
//! device key and never writes peer data to disk.

use std::{
    collections::HashSet,
    error::Error,
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};

use netlink_bindings::wireguard::{self, WgpeerFlags, WgdeviceFlags};
use netlink_socket2::NetlinkSocket;

const IFACE: &[u8] = b"wgctl";
const PEER_COUNT: usize = 1_000;
const PORT: u16 = 51_820;
const CHUNK_SIZE: usize = 400;

fn key(index: usize) -> [u8; wireguard::KEY_LEN as usize] {
    let mut key = [0_u8; wireguard::KEY_LEN as usize];
    key[..4].copy_from_slice(&(index as u32 + 1).to_be_bytes());
    for (offset, byte) in key[4..].iter_mut().enumerate() {
        *byte = ((index.wrapping_mul(37) + offset.wrapping_mul(19) + 1) % 255 + 1) as u8;
    }
    key
}

fn allowed_ip(index: usize, changed: bool) -> IpAddr {
    if changed {
        IpAddr::V4(Ipv4Addr::new(10, 99, (index / 256) as u8, (index % 256) as u8))
    } else {
        IpAddr::V4(Ipv4Addr::new(10, 88, (index / 256) as u8, (index % 256) as u8))
    }
}

fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|value| value.split_whitespace().take(3).map(str::to_owned).reduce(|a, b| format!("{a}/{b}")))
        .unwrap_or_else(|| "NA".to_owned())
}

fn set_peers(sock: &mut NetlinkSocket, keys: &[[u8; wireguard::KEY_LEN as usize]]) -> Result<u128, Box<dyn Error>> {
    let start = Instant::now();
    for (chunk_index, peers) in keys.chunks(CHUNK_SIZE).enumerate() {
        let mut request = wireguard::Request::new().op_set_device_do();
        let entries = request.encode().push_ifname_bytes(IFACE);
        let mut peer_array = if chunk_index == 0 {
            entries
                .push_flags(WgdeviceFlags::ReplacePeers as u32)
                .push_listen_port(PORT)
                .array_peers()
        } else {
            entries.array_peers()
        };
        for (offset, public_key) in peers.iter().enumerate() {
            let index = chunk_index * CHUNK_SIZE + offset;
            peer_array = peer_array
                .entry_nested()
                .push_public_key(public_key)
                .array_allowedips()
                .entry_nested()
                .push_family(libc::AF_INET as u16)
                .push_ipaddr(allowed_ip(index, false))
                .push_cidr_mask(32)
                .end_nested()
                .end_array()
                .end_nested();
        }
        peer_array.end_array();
        sock.request(&request)?.recv_ack()?;
    }
    Ok(start.elapsed().as_micros())
}

fn set_one(sock: &mut NetlinkSocket, public_key: &[u8; wireguard::KEY_LEN as usize], index: usize) -> Result<u128, Box<dyn Error>> {
    let start = Instant::now();
    let mut request = wireguard::Request::new().op_set_device_do();
    request
        .encode()
        .push_ifname_bytes(IFACE)
        .array_peers()
        .entry_nested()
        .push_public_key(public_key)
        .push_flags(WgpeerFlags::ReplaceAllowedips as u32)
        .array_allowedips()
        .entry_nested()
        .push_family(libc::AF_INET as u16)
        .push_ipaddr(allowed_ip(index, true))
        .push_cidr_mask(32)
        .end_nested()
        .end_array()
        .end_nested()
        .end_array();
    sock.request(&request)?.recv_ack()?;
    Ok(start.elapsed().as_micros())
}

fn remove_one(sock: &mut NetlinkSocket, public_key: &[u8; wireguard::KEY_LEN as usize]) -> Result<u128, Box<dyn Error>> {
    let start = Instant::now();
    let mut request = wireguard::Request::new().op_set_device_do();
    request
        .encode()
        .push_ifname_bytes(IFACE)
        .array_peers()
        .entry_nested()
        .push_public_key(public_key)
        .push_flags(WgpeerFlags::RemoveMe as u32)
        .end_nested()
        .end_array();
    sock.request(&request)?.recv_ack()?;
    Ok(start.elapsed().as_micros())
}

struct Readback {
    peers: HashSet<Vec<u8>>,
    allowed_ips: usize,
    listen_port: Option<u16>,
    stats_fields_read: usize,
    changed_peer_updated: bool,
}

fn read_device(sock: &mut NetlinkSocket, changed_key: &[u8; wireguard::KEY_LEN as usize], changed_index: usize) -> Result<Readback, Box<dyn Error>> {
    let mut request = wireguard::Request::new().op_get_device_dump();
    request.encode().push_ifname_bytes(IFACE);
    let mut response = sock.request(&request)?;
    let mut readback = Readback {
        peers: HashSet::with_capacity(PEER_COUNT),
        allowed_ips: 0,
        listen_port: None,
        stats_fields_read: 0,
        changed_peer_updated: false,
    };
    while let Some(attrs) = response.recv().transpose()? {
        if let Ok(port) = attrs.get_listen_port() {
            readback.listen_port = Some(port);
        }
        for peer in attrs.get_peers()? {
            let public_key = peer.get_public_key()?;
            readback.peers.insert(public_key.to_vec());
            if peer.get_last_handshake_time().is_ok() {
                readback.stats_fields_read += 1;
            }
            if peer.get_rx_bytes().is_ok() {
                readback.stats_fields_read += 1;
            }
            if peer.get_tx_bytes().is_ok() {
                readback.stats_fields_read += 1;
            }
            if public_key == changed_key {
                for allowed in peer.get_allowedips()? {
                    readback.allowed_ips += 1;
                    readback.changed_peer_updated |=
                        allowed.get_ipaddr()? == allowed_ip(changed_index, true);
                }
            } else {
                readback.allowed_ips += peer.get_allowedips()?.count();
            }
        }
    }
    Ok(readback)
}

fn read_live_handshake_stats(sock: &mut NetlinkSocket) -> Result<bool, Box<dyn Error>> {
    let mut request = wireguard::Request::new().op_get_device_dump();
    request.encode().push_ifname_bytes(b"wgstatA");
    let mut response = sock.request(&request)?;
    while let Some(attrs) = response.recv().transpose()? {
        for peer in attrs.get_peers()? {
            let handshake = peer.get_last_handshake_time()?;
            let rx_bytes = peer.get_rx_bytes()?;
            let tx_bytes = peer.get_tx_bytes()?;
            if (handshake.sec > 0 || handshake.nsec > 0) && rx_bytes > 0 && tx_bytes > 0 {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn main() -> Result<(), Box<dyn Error>> {
    let load_start = load_average();
    let mut sock = NetlinkSocket::new();
    let keys: Vec<_> = (0..PEER_COUNT).map(key).collect();

    let apply_1000_us = set_peers(&mut sock, &keys)?;
    let first = read_device(&mut sock, &keys[500], 500)?;
    if first.peers.len() != PEER_COUNT || first.allowed_ips != PEER_COUNT || first.listen_port != Some(PORT) {
        return Err(format!("initial readback mismatch: {} peers, {} allowed IPs, port {:?}", first.peers.len(), first.allowed_ips, first.listen_port).into());
    }

    let update_one_us = set_one(&mut sock, &keys[500], 500)?;
    let updated = read_device(&mut sock, &keys[500], 500)?;
    if updated.peers.len() != PEER_COUNT || !updated.changed_peer_updated {
        return Err("single peer allowed-IP update did not read back".into());
    }

    let remove_one_us = remove_one(&mut sock, &keys[PEER_COUNT - 1])?;
    let after_remove = read_device(&mut sock, &keys[500], 500)?;
    if after_remove.peers.len() != PEER_COUNT - 1 || after_remove.peers.contains(keys.last().unwrap().as_slice()) {
        return Err("single peer removal did not read back".into());
    }
    let handshake_stats_verified = read_live_handshake_stats(&mut sock)?;
    if !handshake_stats_verified {
        return Err("live handshake and traffic counters did not read back".into());
    }
    let load_end = load_average();

    println!(
        "loadavg_start,loadavg_end,apply_1000_us,update_one_of_1000_us,remove_one_of_1000_us,get_peers,get_listen_port,handshake_stats_fields_read,handshake_stats_verified\n{load_start},{load_end},{apply_1000_us},{update_one_us},{remove_one_us},{},{},{},{}",
        after_remove.peers.len(),
        after_remove.listen_port == Some(PORT),
        after_remove.stats_fields_read,
        handshake_stats_verified,
    );
    Ok(())
}
