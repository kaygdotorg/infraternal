//! Chooses per-peer route MTUs and an IPv6-safe shared Mesh interface MTU.
//!
//! Each peer host route carries its endpoint path's packet budget after the largest
//! outer-IP allowance. A shared interface uses the largest peer budget and never
//! falls below IPv6's 1280-byte link minimum; unknown paths use a 1200-byte route
//! budget without lowering that interface floor.

#[cfg(target_os = "linux")]
use crate::dataplane::Config;
#[cfg(target_os = "linux")]
use gotatun::tun::MtuWatcher;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
};
#[cfg(target_os = "linux")]
use tokio::sync::watch;

/// The per-peer route MTU used before an endpoint route is available or when lookup fails.
pub(crate) const FALLBACK_MESH_MTU: u16 = 1200;
/// The minimum shared interface MTU needed to keep IPv6 addresses and routes installed.
pub(crate) const IPV6_MINIMUM_MTU: u16 = 1280;
/// The largest `WireGuard` UDP overhead for an outer IPv6 packet.
const OUTER_OVERHEAD: u32 = 80;
/// `WireGuard` pads each encrypted data payload to this block size.
const WIREGUARD_PADDING: u32 = 16;
#[cfg(any(all(feature = "relay", target_os = "linux"), test))]
/// The encrypted `WireGuard` transport header and tag in one data packet.
const WIREGUARD_PACKET_OVERHEAD: u32 = 32;
#[cfg(any(all(feature = "relay", target_os = "linux"), test))]
/// The peer link id prefixed to each relayed datagram.
const RELAY_LINK_ID_OVERHEAD: u32 = 4;
/// The lowest useful interface MTU and the minimum MTU we accept on an owned peer route.
pub(crate) const MIN_MESH_MTU: u16 = 68;

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    /// Underlay route lookups this thread made, so tests can show which refreshes probed the
    /// underlay without timing them (#489 J552 P2-2).
    pub(crate) static ROUTE_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Derive the shared interface MTU from the largest configured peer route budget.
///
/// A peer whose endpoint cannot be resolved uses [`FALLBACK_MESH_MTU`] only for its
/// host routes. The shared link remains at least [`IPV6_MINIMUM_MTU`], including
/// before the first peer exists.
#[cfg(target_os = "linux")]
pub(crate) fn for_config(config: Option<&Config>) -> u16 {
    let mut probe = EndpointProbe::default();
    let peer_mtus: Vec<_> = config
        .into_iter()
        .flat_map(|config| config.peers.values())
        .map(|peer| probe.mesh_mtu(peer.peer.endpoint))
        .collect();
    interface_mtu(&peer_mtus)
}

/// Derive one peer's route MTU from its numeric endpoint, using the safe fallback on lookup error.
#[cfg(target_os = "linux")]
pub(crate) fn for_endpoint(endpoint: Option<SocketAddr>) -> u16 {
    EndpointProbe::default().mesh_mtu(endpoint)
}

/// Derives route MTUs for many peers of one snapshot, looking each underlay path up once.
///
/// Peers often share an endpoint address, and on macOS every lookup starts two
/// processes (`route` and `ifconfig`, about 6.5 ms together). The probe remembers the
/// budget per endpoint IP and, on macOS, each underlay interface's MTU. Create a fresh
/// probe per snapshot: its answers are only as current as the moment they were read.
#[derive(Debug, Default)]
pub(crate) struct EndpointProbe {
    /// Mesh MTU already derived for an endpoint address.
    endpoints: HashMap<IpAddr, u16>,
    /// Underlay interface MTUs read with `ifconfig` during this probe (`None` if unreadable).
    #[cfg(target_os = "macos")]
    interfaces: HashMap<String, Option<u32>>,
}

impl EndpointProbe {
    /// Return the mesh route MTU for `endpoint`, or the safe fallback when it is unknown.
    pub(crate) fn mesh_mtu(&mut self, endpoint: Option<SocketAddr>) -> u16 {
        let Some(endpoint) = endpoint else {
            return FALLBACK_MESH_MTU;
        };
        if let Some(mtu) = self.endpoints.get(&endpoint.ip()) {
            return *mtu;
        }
        let mtu = self
            .route_mtu(endpoint)
            .map_or(FALLBACK_MESH_MTU, mtu_for_route);
        self.endpoints.insert(endpoint.ip(), mtu);
        mtu
    }

    /// Query the underlay route MTU toward `endpoint` through Linux route netlink.
    /// # Errors
    /// Reports an unreachable endpoint, missing egress link, or malformed route reply.
    #[cfg(target_os = "linux")]
    #[allow(clippy::unused_self)] // The macOS twin caches interface MTUs in `self`.
    fn route_mtu(&mut self, endpoint: SocketAddr) -> io::Result<u32> {
        #[cfg(test)]
        ROUTE_LOOKUPS.with(|lookups| lookups.set(lookups.get() + 1));
        crate::wireguard::route_mtu(endpoint)
    }

    /// Query the underlay route MTU toward `endpoint` with macOS routing tools.
    ///
    /// The route's own MTU is bounded by its interface's MTU; the interface is read once
    /// per probe.
    /// # Errors
    /// Reports a failed route lookup or malformed route/interface output.
    #[cfg(target_os = "macos")]
    fn route_mtu(&mut self, endpoint: SocketAddr) -> io::Result<u32> {
        let route = Command::new("/sbin/route")
            .args(["-n", "get", &endpoint.ip().to_string()])
            .output()?;
        if !route.status.success() {
            return Err(io::ErrorKind::NetworkUnreachable.into());
        }
        let route_output = String::from_utf8_lossy(&route.stdout);
        let interface = parse_macos_route_interface(&route_output)?;
        let link_mtu = if let Some(link_mtu) = self.interfaces.get(&interface) {
            *link_mtu
        } else {
            let link_mtu = Command::new("/sbin/ifconfig")
                .arg(&interface)
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| {
                    parse_macos_interface_mtu(&String::from_utf8_lossy(&output.stdout)).ok()
                });
            self.interfaces.insert(interface, link_mtu);
            link_mtu
        }
        .ok_or(io::ErrorKind::NotFound)?;
        Ok(bound_route_mtu(&route_output, link_mtu))
    }
}

/// Derive a relayed peer's inner MTU from Quinn's current application-payload limit.
///
/// Quinn's `max_datagram_size` already accounts for QUIC packet and DATAGRAM framing. The relay
/// adds the `WireGuard` data-packet overhead and its four-byte link id before sending. `WireGuard`
/// pads each plaintext packet to a 16-byte boundary, so the returned MTU is rounded down to a
/// boundary that still fits after that padding. Unknown limits use the same conservative fallback
/// as unresolved direct endpoints.
#[cfg(any(all(feature = "relay", target_os = "linux"), test))]
pub(crate) fn for_relay_datagram(max_datagram_size: Option<usize>) -> u16 {
    max_datagram_size.map_or(FALLBACK_MESH_MTU, |size| {
        let size = u32::try_from(size).unwrap_or(u32::MAX);
        let inner_budget = size
            .saturating_sub(WIREGUARD_PACKET_OVERHEAD + RELAY_LINK_ID_OVERHEAD)
            .min(u32::from(u16::MAX));
        mtu_for_inner_budget(inner_budget)
    })
}

/// Keep a shared link at IPv6's minimum while allowing larger peer route budgets.
pub(crate) fn interface_mtu(peer_mtus: &[u16]) -> u16 {
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

/// Return the safe inner MTU after reserving IPv6 encapsulation and encryption padding.
fn mtu_for_route(route_mtu: u32) -> u16 {
    mtu_for_inner_budget(route_mtu.saturating_sub(OUTER_OVERHEAD))
}

/// Round a packet budget down to the cipher padding boundary and a useful 16-bit mesh MTU.
fn mtu_for_inner_budget(inner: u32) -> u16 {
    let inner = inner - inner % WIREGUARD_PADDING;
    if inner < u32::from(MIN_MESH_MTU) {
        return MIN_MESH_MTU;
    }
    u16::try_from(inner.min(u32::from(u16::MAX))).unwrap_or(FALLBACK_MESH_MTU)
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

/// Bound the route metric by the selected underlay interface's actual MTU (parser check only;
/// [`EndpointProbe`] reads the interface once and calls [`bound_route_mtu`] directly).
#[cfg(all(target_os = "macos", test))]
pub(crate) fn parse_macos_route_mtu(route_output: &str, interface_output: &str) -> io::Result<u32> {
    let link_mtu = parse_macos_interface_mtu(interface_output)?;
    Ok(bound_route_mtu(route_output, link_mtu))
}

/// Bound a `route -n get` reply's MTU by its interface MTU, or use the interface MTU alone.
#[cfg(target_os = "macos")]
fn bound_route_mtu(route_output: &str, link_mtu: u32) -> u32 {
    parse_macos_route(route_output).map_or(link_mtu, |(route_mtu, _)| route_mtu.min(link_mtu))
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

#[cfg(test)]
mod review_j375_padding_tests {
    //! Checks direct IPv6 budgets against the pinned engine's shared-MTU padding rule (#381).
    use super::*;
    use gotatun::{
        noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter},
        packet::{Packet, WgKind},
        tun::MtuWatcher,
        x25519,
    };
    use std::sync::Arc;

    /// A narrow direct IPv6 peer must fit its underlay even when another peer raises the TUN MTU.
    #[test]
    fn mixed_path_direct_ipv6_budget_accounts_for_wireguard_padding() {
        let narrow_underlay = 1450_u32;
        let narrow_inner = mtu_for_route(narrow_underlay);
        let shared_mtu = interface_mtu(&[narrow_inner, mtu_for_route(1500)]);
        let a = x25519::StaticSecret::from([1_u8; 32]);
        let b = x25519::StaticSecret::from([2_u8; 32]);
        let a_pub = x25519::PublicKey::from(&a);
        let b_pub = x25519::PublicKey::from(&b);
        let mut sender = Tunn::new(
            a,
            b_pub,
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&a_pub, 100)),
        );
        let mut receiver = Tunn::new(
            b,
            a_pub,
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::new(RateLimiter::new(&b_pub, 100)),
        );
        let Some(init) = sender.format_handshake_initiation(false) else {
            panic!("expected a handshake initiation");
        };
        let TunnResult::WriteToNetwork(response) =
            receiver.handle_incoming_packet(WgKind::HandshakeInit(init))
        else {
            panic!("handshake response");
        };
        let TunnResult::WriteToNetwork(_) = sender.handle_incoming_packet(response) else {
            panic!("handshake finish");
        };
        let mut watcher = MtuWatcher::new(shared_mtu);
        let packet = Packet::from_bytes(bytes::BytesMut::from(
            vec![0_u8; usize::from(narrow_inner)].as_slice(),
        ));
        let Some(WgKind::Data(encrypted)) =
            sender.handle_outgoing_packet(packet, Some(&mut watcher))
        else {
            panic!("data packet");
        };
        let encrypted_bytes = encrypted.into_bytes().len();
        let Ok(encrypted_bytes) = u32::try_from(encrypted_bytes) else {
            panic!("encrypted packet length fits in a 32-bit MTU");
        };
        let outer_packet = encrypted_bytes.saturating_add(48);
        println!(
            "underlay={narrow_underlay} route_mtu={narrow_inner} shared_mtu={shared_mtu} actual_encrypted_bytes={encrypted_bytes} ipv6_outer={outer_packet}"
        );
        assert!(
            outer_packet <= narrow_underlay,
            "direct IPv6 budget forces outer fragmentation after padding"
        );
    }
}
