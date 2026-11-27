//! Answers mesh-name queries sent to the mesh resolver address straight from the tunnel
//! (#146, owner decision 2026-11-21, review J1027 F2).
//!
//! A user-mode Mac's system resolver sends `*.internal` queries to the deployment's mesh
//! resolver address ([`infraternal_mesh::address::resolver_address`], `fd<id>:ffff::53`, port
//! 53). That address is on no interface; the helper's `/48` route sends it into this node's
//! utun, so the query arrives on the same read path as any packet bound for a peer. This module
//! recognises such a packet and builds the reply packet, which the node writes back into the
//! utun. No socket is bound, so no other account on the Mac can take the port or answer in the
//! agent's place, and nothing answers at all while the agent is not running (the J1027 F2
//! squatting window is gone).
//!
//! Only plain UDP queries are answered. Every reply here is one short question with at most a
//! couple of records, so it always fits a UDP datagram and the system resolver never needs TCP.
//! A packet read from the utun was written by this Mac's own network stack (only the host can
//! write into it), so the query is answered with the node's own view, the same as a query from
//! the node's mesh address.
//!
//! Everything here is pure byte work, so the Linux gate tests it.

use std::net::Ipv6Addr;

/// The fixed IPv6 header length; queries with extension headers are not answered.
pub const IPV6_HEADER: usize = 40;
/// The UDP header length.
pub const UDP_HEADER: usize = 8;
/// IPv6 next-header value for UDP.
pub const UDP: u8 = 17;
/// The DNS port the resolver file names.
pub const PORT: u16 = 53;
/// Hop limit of reply packets; they never leave the host.
const HOP_LIMIT: u8 = 64;

/// A cheap first test on every packet the node reads from its utun: an IPv6 UDP datagram to
/// port 53 of an address with the resolver's subnet and interface ID.
///
/// It reads a few fixed bytes and takes no lock, so ordinary mesh traffic pays almost nothing.
/// Only a packet that passes goes on to [`answer_with`], which checks the full address against the
/// node's own deployment.
#[must_use]
pub fn looks_like_resolver_query(packet: &[u8]) -> bool {
    packet.len() >= IPV6_HEADER + UDP_HEADER
        && packet[0] >> 4 == 6
        && packet[6] == UDP
        && packet[30..32] == infraternal_mesh::address::SERVICE_SUBNET.to_be_bytes()
        && packet[32..40] == infraternal_mesh::address::RESOLVER_INTERFACE_ID.to_be_bytes()
        && packet[42..44] == PORT.to_be_bytes()
}

/// The reply packet for one query to `resolver`, or `None` when the packet is not a well-formed
/// UDP query to it or the reply would exceed `mtu`. A name outside the mesh zones gets `REFUSED`.
///
/// `respond` answers with the node's current name snapshot. The reply swaps the addresses and ports of the
/// query and carries a correct UDP checksum, which IPv6 requires.
#[must_use]
pub fn answer_with(
    packet: &[u8],
    resolver: Ipv6Addr,
    mtu: usize,
    respond: impl FnOnce(&[u8]) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    if !looks_like_resolver_query(packet) || packet[24..40] != resolver.octets() {
        return None;
    }
    let payload_length = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let udp_length = usize::from(u16::from_be_bytes([packet[44], packet[45]]));
    if packet.len() != IPV6_HEADER + payload_length
        || udp_length != payload_length
        || udp_length < UDP_HEADER
    {
        return None;
    }
    let query = &packet[IPV6_HEADER + UDP_HEADER..];
    let reply = respond(query)?;
    let source: [u8; 16] = packet[8..24].try_into().ok()?;
    let source_port = [packet[40], packet[41]];
    build_reply(resolver, Ipv6Addr::from(source), source_port, &reply, mtu)
}

/// Wrap `dns` in IPv6 and UDP headers from `resolver`:53 to `client`:`client_port`.
fn build_reply(
    resolver: Ipv6Addr,
    client: Ipv6Addr,
    client_port: [u8; 2],
    dns: &[u8],
    mtu: usize,
) -> Option<Vec<u8>> {
    let udp_length = UDP_HEADER + dns.len();
    if IPV6_HEADER + udp_length > mtu {
        return None;
    }
    let length = u16::try_from(udp_length).ok()?;
    let mut packet = Vec::with_capacity(IPV6_HEADER + udp_length);
    packet.extend_from_slice(&[0x60, 0, 0, 0]);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[UDP, HOP_LIMIT]);
    packet.extend_from_slice(&resolver.octets());
    packet.extend_from_slice(&client.octets());
    packet.extend_from_slice(&PORT.to_be_bytes());
    packet.extend_from_slice(&client_port);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(dns);
    let checksum = udp_checksum(&packet[8..24], &packet[24..40], &packet[IPV6_HEADER..]);
    packet[IPV6_HEADER + 6..IPV6_HEADER + 8].copy_from_slice(&checksum.to_be_bytes());
    Some(packet)
}

/// The UDP checksum over the IPv6 pseudo-header and `datagram` (whose checksum field is zero).
///
/// RFC 8200 §8.1: the pseudo-header is source, destination, the upper-layer length as 32 bits,
/// three zero bytes and the next-header value. A computed zero is sent as `0xffff`, because a
/// zero checksum means "none", which IPv6 UDP does not allow.
#[must_use]
pub fn udp_checksum(source: &[u8], destination: &[u8], datagram: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut add = |bytes: &[u8]| {
        for pair in bytes.chunks(2) {
            let high = u64::from(pair[0]) << 8;
            let low = pair.get(1).copied().map_or(0, u64::from);
            sum += high | low;
        }
    };
    add(source);
    add(destination);
    let length = u32::try_from(datagram.len()).unwrap_or(u32::MAX);
    add(&length.to_be_bytes());
    add(&[0, 0, 0, UDP]);
    add(datagram);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // The loop above leaves at most 16 bits.
    let folded = u16::try_from(sum).unwrap_or(u16::MAX);
    match !folded {
        0 => 0xffff,
        checksum => checksum,
    }
}
