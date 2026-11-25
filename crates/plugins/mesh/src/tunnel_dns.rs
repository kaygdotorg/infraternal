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

use crate::dns::Records;
use std::net::Ipv6Addr;

/// The fixed IPv6 header length; queries with extension headers are not answered.
const IPV6_HEADER: usize = 40;
/// The UDP header length.
const UDP_HEADER: usize = 8;
/// IPv6 next-header value for UDP.
const UDP: u8 = 17;
/// The DNS port the resolver file names.
pub(crate) const PORT: u16 = 53;
/// Hop limit of reply packets; they never leave the host.
const HOP_LIMIT: u8 = 64;

/// A cheap first test on every packet the node reads from its utun: an IPv6 UDP datagram to
/// port 53 of an address with the resolver's subnet and interface ID.
///
/// It reads a few fixed bytes and takes no lock, so ordinary mesh traffic pays almost nothing.
/// Only a packet that passes goes on to [`answer`], which checks the full address against the
/// node's own deployment.
#[must_use]
pub(crate) fn looks_like_resolver_query(packet: &[u8]) -> bool {
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
/// `records` is the node's current name snapshot. The reply swaps the addresses and ports of the
/// query and carries a correct UDP checksum, which IPv6 requires.
#[must_use]
pub(crate) fn answer(
    packet: &[u8],
    resolver: Ipv6Addr,
    records: &Records,
    mtu: usize,
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
    let reply = crate::dns::response_for_records(query, records).ok()?;
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
fn udp_checksum(source: &[u8], destination: &[u8], datagram: &[u8]) -> u16 {
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

/// Packet recognition, replies and checksums, checked without a Mac.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hickory_proto::op::Message;

    /// The node's own address, inside a deployment `/48`.
    fn own() -> Ipv6Addr {
        "fd12:3456:789a::7".parse().unwrap()
    }

    /// The deployment's resolver address.
    fn resolver() -> Ipv6Addr {
        infraternal_mesh::address::resolver_address(own())
    }

    /// One `A` query for `<host>.internal`, built by hand.
    fn query(host: &str) -> Vec<u8> {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in [host, "internal"] {
            dns.push(u8::try_from(label.len()).unwrap());
            dns.extend_from_slice(label.as_bytes());
        }
        dns.extend_from_slice(&[0, 0, 1, 0, 1]);
        dns
    }

    /// The IPv6 UDP packet the system resolver would send from the node's address.
    fn packet(destination: Ipv6Addr, port: u16, dns: &[u8]) -> Vec<u8> {
        let length = u16::try_from(UDP_HEADER + dns.len()).unwrap();
        let mut packet = vec![0x60, 0, 0, 0];
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&[UDP, 64]);
        packet.extend_from_slice(&own().octets());
        packet.extend_from_slice(&destination.octets());
        packet.extend_from_slice(&50_000_u16.to_be_bytes());
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend_from_slice(&length.to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.extend_from_slice(dns);
        packet
    }

    /// A snapshot with this node and one peer, `web` at 10.254.0.9.
    fn records() -> Records {
        Records::for_tests(
            "10.254.0.7".parse().unwrap(),
            &[("web", "10.254.0.9".parse().unwrap())],
        )
    }

    /// A query to the resolver gets a reply from the resolver, back to the asking port, with
    /// the peer's address and a checksum that verifies.
    #[test]
    fn a_query_to_the_resolver_is_answered_from_the_tunnel() {
        let query_packet = packet(resolver(), PORT, &query("web"));
        assert!(looks_like_resolver_query(&query_packet));
        let reply = answer(&query_packet, resolver(), &records(), 1280).unwrap();
        assert_eq!(reply[0] >> 4, 6);
        assert_eq!(reply[6], UDP);
        assert_eq!(&reply[8..24], &resolver().octets());
        assert_eq!(&reply[24..40], &own().octets());
        assert_eq!(&reply[40..42], &PORT.to_be_bytes());
        assert_eq!(&reply[42..44], &50_000_u16.to_be_bytes());
        let length = usize::from(u16::from_be_bytes([reply[4], reply[5]]));
        assert_eq!(reply.len(), IPV6_HEADER + length);
        // Summing a datagram with its checksum in place gives zero once complemented.
        let mut check = reply[IPV6_HEADER..].to_vec();
        let sent = u16::from_be_bytes([check[6], check[7]]);
        check[6..8].copy_from_slice(&[0, 0]);
        assert_eq!(udp_checksum(&reply[8..24], &reply[24..40], &check), sent);
        let message = Message::from_vec(&reply[IPV6_HEADER + UDP_HEADER..]).unwrap();
        assert_eq!(message.answers.len(), 1, "{message:?}");
    }

    /// Other ports, other addresses in the service subnet, another deployment's resolver and
    /// truncated packets get nothing; a name outside the zone gets `REFUSED`.
    #[test]
    fn everything_else_is_left_alone() {
        let records = records();
        assert!(!looks_like_resolver_query(&packet(
            resolver(),
            5353,
            &query("web")
        )));
        let neighbour = {
            let mut octets = resolver().octets();
            octets[15] = 0x54;
            Ipv6Addr::from(octets)
        };
        assert!(!looks_like_resolver_query(&packet(
            neighbour,
            PORT,
            &query("web")
        )));
        let foreign: Ipv6Addr = "fd99:9999:9999:ffff::53".parse().unwrap();
        let foreign_query = packet(foreign, PORT, &query("web"));
        assert!(looks_like_resolver_query(&foreign_query));
        assert_eq!(answer(&foreign_query, resolver(), &records, 1280), None);
        let mut short = packet(resolver(), PORT, &query("web"));
        short.pop();
        assert_eq!(answer(&short, resolver(), &records, 1280), None);
        let mut outside = query("web");
        // "\x08internal", then the root label and four bytes of type and class.
        let at = outside.len() - 14;
        outside[at..at + 9].copy_from_slice(b"\x08external");
        // A name outside the zones is refused, not ignored, so the host moves on at once (#580).
        let refused = answer(
            &packet(resolver(), PORT, &outside),
            resolver(),
            &records,
            1280,
        )
        .unwrap();
        let message = Message::from_vec(&refused[IPV6_HEADER + UDP_HEADER..]).unwrap();
        assert_eq!(
            message.metadata.response_code,
            hickory_proto::op::ResponseCode::Refused
        );
        // A reply that would not fit the utun MTU is dropped rather than truncated.
        assert_eq!(
            answer(
                &packet(resolver(), PORT, &query("web")),
                resolver(),
                &records,
                60
            ),
            None
        );
    }

    /// The checksum folds carries and never sends zero.
    #[test]
    fn the_checksum_folds_and_avoids_zero() {
        let zero = [0_u8; 16];
        // An all-zero datagram sums to the pseudo-header only.
        let checksum = udp_checksum(&zero, &zero, &[0; 8]);
        assert_eq!(checksum, !(8_u16 + u16::from(UDP)));
        // A datagram whose sum is 0xffff complements to zero and goes out as 0xffff.
        let length_and_protocol = 2 + u16::from(UDP);
        let filler = 0xffff - length_and_protocol;
        assert_eq!(udp_checksum(&zero, &zero, &filler.to_be_bytes()), 0xffff);
    }
}
