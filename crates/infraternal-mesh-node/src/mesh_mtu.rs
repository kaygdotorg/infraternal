//! Derive mesh route budgets from MTUs supplied by the host platform.

use std::io;

/// The per-peer route MTU used before an endpoint route is available or when lookup fails.
pub const FALLBACK_MESH_MTU: u16 = 1200;
/// The minimum shared interface MTU needed to keep IPv6 addresses and routes installed.
pub const IPV6_MINIMUM_MTU: u16 = 1280;
/// The largest `WireGuard` UDP overhead for an outer IPv6 packet.
const OUTER_OVERHEAD: u32 = 80;
/// `WireGuard` pads each encrypted data payload to this block size.
const WIREGUARD_PADDING: u32 = 16;
/// The encrypted `WireGuard` transport header and tag in one data packet.
const WIREGUARD_PACKET_OVERHEAD: u32 = 32;
/// The peer link id prefixed to each relayed datagram.
const RELAY_LINK_ID_OVERHEAD: u32 = 4;
/// The lowest useful interface MTU and the minimum MTU we accept on an owned peer route.
pub const MIN_MESH_MTU: u16 = 68;

/// One peer's derived route budget, and whether it is the path's answer or a stand-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteBudget {
    /// The budget to write on the peer's host routes.
    pub mtu: u16,
    /// The underlay lookup failed, so `mtu` is [`FALLBACK_MESH_MTU`]: safe to write for now, but
    /// not known to be the path's budget, so the caller should look the path up again
    /// (#489 J609 P3). A peer with no endpoint has nothing to look up and is never marked.
    pub lookup_failed: bool,
}

/// Derive a relayed peer's inner MTU from Quinn's current application-payload limit.
///
/// Quinn's `max_datagram_size` already accounts for QUIC packet and DATAGRAM framing. The relay
/// adds the `WireGuard` data-packet overhead and its four-byte link id before sending. `WireGuard`
/// pads each plaintext packet to a 16-byte boundary, so the returned MTU is rounded down to a
/// boundary that still fits after that padding. Unknown limits use the same conservative fallback
/// as unresolved direct endpoints.
#[must_use]
pub fn for_relay_datagram(max_datagram_size: Option<usize>) -> u16 {
    max_datagram_size.map_or(FALLBACK_MESH_MTU, |size| {
        let size = u32::try_from(size).unwrap_or(u32::MAX);
        let inner_budget = size
            .saturating_sub(WIREGUARD_PACKET_OVERHEAD + RELAY_LINK_ID_OVERHEAD)
            .min(u32::from(u16::MAX));
        mtu_for_inner_budget(inner_budget)
    })
}

/// Keep a shared link at IPv6's minimum while allowing larger peer route budgets.
#[must_use]
pub fn interface_mtu(peer_mtus: &[u16]) -> u16 {
    peer_mtus
        .iter()
        .copied()
        .max()
        .unwrap_or(FALLBACK_MESH_MTU)
        .max(IPV6_MINIMUM_MTU)
}

/// Return the safe inner MTU after reserving IPv6 encapsulation and encryption padding.
#[must_use]
pub fn mtu_for_route(route_mtu: u32) -> u16 {
    mtu_for_inner_budget(route_mtu.saturating_sub(OUTER_OVERHEAD))
}

/// Round a packet budget down to the cipher padding boundary and a useful 16-bit mesh MTU.
#[must_use]
pub fn mtu_for_inner_budget(inner: u32) -> u16 {
    let inner = inner - inner % WIREGUARD_PADDING;
    if inner < u32::from(MIN_MESH_MTU) {
        return MIN_MESH_MTU;
    }
    u16::try_from(inner.min(u32::from(u16::MAX))).unwrap_or(FALLBACK_MESH_MTU)
}

/// Read the route MTU and interface name from macOS `route -n get` output.
///
/// # Errors
/// Reports malformed or missing route or interface fields.
pub fn parse_macos_route(output: &str) -> io::Result<(u32, String)> {
    let interface = parse_macos_route_interface(output)?;
    let lines: Vec<_> = output.lines().collect();
    let route_mtu = lines
        .windows(2)
        .find_map(|pair| {
            let column = pair[0]
                .split_whitespace()
                .position(|field| field == "mtu")?;
            pair[1].split_whitespace().nth(column)?.parse::<u32>().ok()
        })
        .filter(|mtu| *mtu > 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok((route_mtu, interface))
}

/// Read the selected interface from macOS `route -n get` output even when the route has no MTU.
///
/// # Errors
/// Reports malformed or missing route or interface fields.
pub fn parse_macos_route_interface(output: &str) -> io::Result<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: "))
        .filter(|interface| !interface.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

/// Bound the route metric by the selected underlay interface's actual MTU (parser check only;
/// the host reads the interface once and calls [`bound_route_mtu`] directly).
#[cfg(all(target_os = "macos", test))]
///
/// # Errors
/// Reports malformed or missing route or interface fields.
fn parse_macos_route_mtu(route_output: &str, interface_output: &str) -> io::Result<u32> {
    let link_mtu = parse_macos_interface_mtu(interface_output)?;
    Ok(bound_route_mtu(route_output, link_mtu))
}

/// Bound a `route -n get` reply's MTU by its interface MTU, or use the interface MTU alone.
#[must_use]
pub fn bound_route_mtu(route_output: &str, link_mtu: u32) -> u32 {
    parse_macos_route(route_output).map_or(link_mtu, |(route_mtu, _)| route_mtu.min(link_mtu))
}

/// Read the MTU from macOS `ifconfig` output when the route has no explicit MTU.
///
/// # Errors
/// Reports malformed or missing route or interface fields.
pub fn parse_macos_interface_mtu(output: &str) -> io::Result<u32> {
    let mut fields = output.split_whitespace();
    while let Some(field) = fields.next() {
        if field == "mtu" {
            return fields
                .next()
                .ok_or(io::ErrorKind::InvalidData)?
                .parse()
                .map_err(|_| io::ErrorKind::InvalidData.into());
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
mod tests {
    //! Checks route-to-inner-MTU conversion at overlay and normal Ethernet sizes.
    #![cfg_attr(
        target_os = "macos",
        allow(
            clippy::unwrap_used,
            reason = "route-parsing tests panic on unexpected parse results"
        )
    )]
    use super::*;

    /// A 1280-byte outer route leaves 1200 bytes for an inner packet.
    #[test]
    fn subtracts_worst_case_overhead_from_a_1280_byte_route() {
        assert_eq!(mtu_for_route(1280), 1200);
    }

    /// A normal 1500-byte route rounds down so encryption padding still fits its IPv6 packets.
    #[test]
    fn keeps_the_largest_safe_mtu_on_a_normal_route() {
        assert_eq!(mtu_for_route(1500), 1408);
    }

    /// Relay budgets include `WireGuard`'s 16-byte packet padding as well as its framing.
    #[test]
    fn relay_route_budget_fits_padded_wireguard_packets() {
        for (maximum, expected) in [(1214_u32, 1168_u16), (1434, 1392)] {
            let mtu = for_relay_datagram(Some(maximum as usize));
            assert_eq!(mtu, expected);

            // A data packet pads to 16 bytes, then adds 32 WireGuard bytes and the 4-byte link id.
            let padded_mtu = u32::from(mtu);
            assert!(padded_mtu + 32 + 4 <= maximum);
            let next_inner = padded_mtu + 1;
            let next_padded = (next_inner + 15) & !15;
            assert!(next_padded + 32 + 4 > maximum);
        }
        assert_eq!(for_relay_datagram(Some(80)), MIN_MESH_MTU);
        assert_eq!(for_relay_datagram(None), FALLBACK_MESH_MTU);
    }

    /// A route too small for normal IPv4 still selects the minimum usable IPv4 interface MTU.
    #[test]
    fn keeps_the_minimum_interface_mtu_when_the_path_is_too_small() {
        assert_eq!(mtu_for_route(80), MIN_MESH_MTU);
    }

    /// The shared interface follows the largest peer budget and the IPv6 link floor.
    #[test]
    fn the_largest_peer_budget_sets_the_interface_mtu() {
        assert_eq!(interface_mtu(&[1200, 1408]), 1408);
    }

    /// An interface keeps the IPv6 minimum while every peer route uses a smaller packet budget.
    #[test]
    fn interface_mtu_keeps_the_ipv6_floor_for_narrow_paths() {
        assert_eq!(interface_mtu(&[1200]), IPV6_MINIMUM_MTU);
    }

    /// A new interface with no peer routes starts at the IPv6-safe floor.
    #[test]
    fn interface_mtu_uses_the_ipv6_floor_without_peer_routes() {
        assert_eq!(interface_mtu(&[]), IPV6_MINIMUM_MTU);
    }

    /// macOS route output supplies an interface MTU in a header and its matching value row.
    #[cfg(target_os = "macos")]
    #[test]
    fn reads_route_mtu_and_interface_from_macos_route_output() {
        let output = "route to: 10.69.69.218\ndestination: 10.69.69.218\ninterface: utun100\nflags: <UP,HOST>\n recvpipe sendpipe ssthresh rtt,msec rttvar hopcount mtu expire\n 0 0 1 152 11 0 1280 0\n";
        assert_eq!(
            parse_macos_route(output).unwrap(),
            (1280, "utun100".to_owned())
        );
    }

    /// A zero route MTU is unspecified and must fall back to the selected interface's MTU.
    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_an_unspecified_route_mtu() {
        let output = "route to: 10.69.69.218\ndestination: 10.69.69.218\ninterface: utun100\nflags: <UP,HOST>\n recvpipe sendpipe ssthresh rtt,msec rttvar hopcount mtu expire\n 0 0 1 152 11 0 0 0\n";
        assert_eq!(
            parse_macos_route(output).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// An unspecified route MTU falls back to the selected underlay interface's MTU.
    #[cfg(target_os = "macos")]
    #[test]
    fn falls_back_to_the_selected_interface_mtu_when_route_mtu_is_unspecified() {
        let route = "route to: 10.69.69.218\ndestination: 10.69.69.218\ninterface: en0\nflags: <UP,HOST>\n recvpipe sendpipe ssthresh rtt,msec rttvar hopcount mtu expire\n 0 0 1 152 11 0 0 0\n";
        let interface = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1280\n";
        assert_eq!(parse_macos_route_mtu(route, interface).unwrap(), 1280);
    }

    /// An explicit route metric cannot exceed the selected underlay interface's MTU.
    #[cfg(target_os = "macos")]
    #[test]
    fn endpoint_route_metric_is_bounded_by_egress_link_mtu() {
        let route = "route to: 10.69.69.218\ndestination: 10.69.69.218\ninterface: en0\nflags: <UP,HOST>\n recvpipe sendpipe ssthresh rtt,msec rttvar hopcount mtu expire\n 0 0 1 152 11 0 9000 0\n";
        let interface = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1280\n";
        assert_eq!(parse_macos_route_mtu(route, interface).unwrap(), 1280);
    }
}
