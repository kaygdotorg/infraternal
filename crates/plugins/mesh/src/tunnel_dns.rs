//! Adapts the host DNS records to the shared tunnel packet responder.

use crate::dns::{Records, response_for_records};
use std::net::Ipv6Addr;

/// Identify resolver packets and name the port the host resolver uses.
pub(crate) use infraternal_mesh_node::tunnel_dns::looks_like_resolver_query;

/// The port in the host resolver configuration.
#[cfg(target_os = "macos")]
pub(crate) use infraternal_mesh_node::tunnel_dns::PORT;

#[cfg(test)]
use infraternal_mesh_node::tunnel_dns::{IPV6_HEADER, UDP, UDP_HEADER, udp_checksum};

/// Answer a tunnel query using the host's current mesh DNS records.
pub(crate) fn answer(
    packet: &[u8],
    resolver: Ipv6Addr,
    records: &Records,
    mtu: usize,
) -> Option<Vec<u8>> {
    infraternal_mesh_node::tunnel_dns::answer_with(packet, resolver, mtu, |query| {
        response_for_records(query, records).ok()
    })
}

/// Packet recognition, replies and checksums, checked without a Mac.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use hickory_proto::op::Message;
    #[cfg(not(target_os = "macos"))]
    use infraternal_mesh_node::tunnel_dns::PORT;

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
