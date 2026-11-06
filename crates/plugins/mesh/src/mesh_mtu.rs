//! Chooses per-peer route MTUs and an IPv6-safe shared Mesh interface MTU.
//!
//! Each peer host route carries its endpoint path's packet budget after the largest
//! outer-IP allowance. A shared interface uses the largest peer budget and never
//! falls below IPv6's 1280-byte link minimum; unknown paths use a 1200-byte route
//! budget without lowering that interface floor.

use crate::dataplane::Config;
#[cfg(target_os = "linux")]
use gotatun::tun::MtuWatcher;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::{io, net::SocketAddr};
#[cfg(target_os = "linux")]
use tokio::sync::watch;

/// The per-peer route MTU used before an endpoint route is available or when lookup fails.
pub(crate) const FALLBACK_MESH_MTU: u16 = 1200;
/// The minimum shared interface MTU needed to keep IPv6 addresses and routes installed.
pub(crate) const IPV6_MINIMUM_MTU: u16 = 1280;
/// The largest `WireGuard` UDP overhead for an outer IPv6 packet.
const OUTER_OVERHEAD: u32 = 80;
/// The lowest useful interface MTU and the minimum MTU we accept on an owned peer route.
pub(crate) const MIN_MESH_MTU: u16 = 68;

/// Derive the shared interface MTU from the largest configured peer route budget.
///
/// A peer whose endpoint cannot be resolved uses [`FALLBACK_MESH_MTU`] only for its
/// host routes. The shared link remains at least [`IPV6_MINIMUM_MTU`], including
/// before the first peer exists.
pub(crate) fn for_config(config: Option<&Config>) -> u16 {
    let peer_mtus: Vec<_> = config
        .into_iter()
        .flat_map(|config| config.peers.values())
        .map(|peer| for_endpoint(peer.peer.endpoint))
        .collect();
    interface_mtu(&peer_mtus)
}

/// Derive one peer's route MTU from its numeric endpoint, using the safe fallback on lookup error.
pub(crate) fn for_endpoint(endpoint: Option<SocketAddr>) -> u16 {
    endpoint
        .and_then(|endpoint| endpoint_route_mtu(endpoint).ok())
        .map_or(FALLBACK_MESH_MTU, mtu_for_route)
}

/// Keep a shared link at IPv6's minimum while allowing larger peer route budgets.
fn interface_mtu(peer_mtus: &[u16]) -> u16 {
    peer_mtus
        .iter()
        .copied()
        .max()
        .unwrap_or(FALLBACK_MESH_MTU)
        .max(IPV6_MINIMUM_MTU)
}

/// Create a `GotaTun` MTU watcher and the sender that updates its current value.
#[cfg(target_os = "linux")]
pub(crate) fn watcher(mtu: u16) -> (watch::Sender<u16>, MtuWatcher) {
    let (sender, receiver) = watch::channel(mtu);
    (sender, receiver.into())
}

/// Return the safe inner MTU for one route after reserving worst-case encapsulation overhead.
fn mtu_for_route(route_mtu: u32) -> u16 {
    let inner = route_mtu.saturating_sub(OUTER_OVERHEAD);
    if inner < u32::from(MIN_MESH_MTU) {
        return MIN_MESH_MTU;
    }
    u16::try_from(inner.min(u32::from(u16::MAX))).unwrap_or(FALLBACK_MESH_MTU)
}

#[cfg(target_os = "linux")]
/// Query a numeric endpoint's route MTU through Linux route netlink.
/// # Errors
/// Reports an unreachable endpoint, missing egress link, or malformed route reply.
fn endpoint_route_mtu(endpoint: SocketAddr) -> io::Result<u32> {
    crate::wireguard::route_mtu(endpoint)
}

#[cfg(target_os = "macos")]
/// Query a numeric endpoint's route MTU with macOS routing tools.
/// # Errors
/// Reports a failed route lookup or malformed route/interface output.
fn endpoint_route_mtu(endpoint: SocketAddr) -> io::Result<u32> {
    let route = Command::new("/sbin/route")
        .args(["-n", "get", &endpoint.ip().to_string()])
        .output()?;
    if !route.status.success() {
        return Err(io::ErrorKind::NetworkUnreachable.into());
    }
    let route_output = String::from_utf8_lossy(&route.stdout);
    let interface = parse_macos_route_interface(&route_output)?;
    if let Ok((mtu, _)) = parse_macos_route(&route_output) {
        return Ok(mtu);
    }
    let interface_output = Command::new("/sbin/ifconfig").arg(interface).output()?;
    if !interface_output.status.success() {
        return Err(io::ErrorKind::NotFound.into());
    }
    parse_macos_route_mtu(
        &route_output,
        &String::from_utf8_lossy(&interface_output.stdout),
    )
}

/// Read the route MTU and interface name from macOS `route -n get` output.
#[cfg(target_os = "macos")]
pub(crate) fn parse_macos_route(output: &str) -> io::Result<(u32, String)> {
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
#[cfg(target_os = "macos")]
pub(crate) fn parse_macos_route_interface(output: &str) -> io::Result<String> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: "))
        .filter(|interface| !interface.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

/// Use the selected underlay interface's MTU when `route -n get` reports zero or no route MTU.
#[cfg(target_os = "macos")]
pub(crate) fn parse_macos_route_mtu(route_output: &str, interface_output: &str) -> io::Result<u32> {
    parse_macos_route(route_output)
        .map(|(mtu, _)| mtu)
        .or_else(|_| parse_macos_interface_mtu(interface_output))
}

/// Read the MTU from macOS `ifconfig` output when the route has no explicit MTU.
#[cfg(target_os = "macos")]
pub(crate) fn parse_macos_interface_mtu(output: &str) -> io::Result<u32> {
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
    use super::*;

    /// A 1280-byte outer route leaves 1200 bytes for an inner packet.
    #[test]
    fn subtracts_worst_case_overhead_from_a_1280_byte_route() {
        assert_eq!(mtu_for_route(1280), 1200);
    }

    /// A normal 1500-byte route keeps the standard 1420-byte inner packet size.
    #[test]
    fn keeps_the_largest_safe_mtu_on_a_normal_route() {
        assert_eq!(mtu_for_route(1500), 1420);
    }

    /// A route too small for normal IPv4 still selects the minimum usable IPv4 interface MTU.
    #[test]
    fn keeps_the_minimum_interface_mtu_when_the_path_is_too_small() {
        assert_eq!(mtu_for_route(80), MIN_MESH_MTU);
    }

    /// The shared interface follows the largest peer budget and the IPv6 link floor.
    #[test]
    fn the_largest_peer_budget_sets_the_interface_mtu() {
        assert_eq!(interface_mtu(&[1200, 1420]), 1420);
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
}
