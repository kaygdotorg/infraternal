//! Chooses per-peer route MTUs and an IPv6-safe shared Mesh interface MTU.
//!
//! Each peer host route carries its endpoint path's packet budget after the largest
//! outer-IP allowance. A shared interface uses the largest peer budget and never
//! falls below IPv6's 1280-byte link minimum; unknown paths use a 1200-byte route
//! budget without lowering that interface floor.

#[cfg(target_os = "linux")]
pub(crate) use infraternal_mesh_node::mesh_mtu::MIN_MESH_MTU;
#[cfg(all(feature = "relay", target_os = "linux"))]
pub(crate) use infraternal_mesh_node::mesh_mtu::for_relay_datagram;
use infraternal_mesh_node::mesh_mtu::mtu_for_route;
#[cfg(target_os = "macos")]
pub(crate) use infraternal_mesh_node::mesh_mtu::parse_macos_interface_mtu;
#[cfg(all(test, target_os = "macos"))]
pub(crate) use infraternal_mesh_node::mesh_mtu::parse_macos_route;
/// Shared MTU values used by the host's interface and route setup.
pub(crate) use infraternal_mesh_node::mesh_mtu::{
    FALLBACK_MESH_MTU, IPV6_MINIMUM_MTU, RouteBudget, interface_mtu,
};
#[cfg(target_os = "macos")]
use infraternal_mesh_node::mesh_mtu::{bound_route_mtu, parse_macos_route_interface};

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

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    /// Underlay route lookups this thread made, so tests can show which refreshes probed the
    /// underlay without timing them (#489 J552 P2-2).
    pub(crate) static ROUTE_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// One-shot checkpoint for a namespace test to change route state during its next lookup.
    pub(crate) static BEFORE_ROUTE_LOOKUP: std::cell::Cell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::Cell::new(None) };
    /// How many of this thread's next underlay route lookups fail as if the kernel refused them,
    /// so tests can show what a refresh does after a failed lookup (#489 J609 P3).
    pub(crate) static FAIL_ROUTE_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
/// budget per endpoint IP and, on macOS, each underlay interface's MTU. On Linux, every lookup
/// of one probe shares one route-netlink socket, opened on the first lookup (#489 J552 P2-2).
/// Create a fresh probe per snapshot: its answers are only as current as the moment they were
/// read.
#[derive(Default)]
pub(crate) struct EndpointProbe {
    /// Budget already derived for an endpoint address, failed lookups included, so peers that
    /// share a dead path cost one failed request per probe, not one each.
    endpoints: HashMap<IpAddr, RouteBudget>,
    /// The route-netlink socket this probe's lookups share, once one was needed.
    #[cfg(target_os = "linux")]
    socket: Option<crate::netlink::Socket>,
    /// Underlay interface MTUs read with `ifconfig` during this probe (`None` if unreadable).
    #[cfg(target_os = "macos")]
    interfaces: HashMap<String, Option<u32>>,
}

impl EndpointProbe {
    /// Return the mesh route MTU for `endpoint`, or the safe fallback when it is unknown.
    pub(crate) fn mesh_mtu(&mut self, endpoint: Option<SocketAddr>) -> u16 {
        self.route_budget(endpoint).mtu
    }

    /// Return the mesh route budget for `endpoint`, marking a fallback that stands in for a
    /// failed lookup so a caller that keeps budgets current can retry it.
    pub(crate) fn route_budget(&mut self, endpoint: Option<SocketAddr>) -> RouteBudget {
        let Some(endpoint) = endpoint else {
            return RouteBudget {
                mtu: FALLBACK_MESH_MTU,
                lookup_failed: false,
            };
        };
        if let Some(budget) = self.endpoints.get(&endpoint.ip()) {
            return *budget;
        }
        let budget = self.route_mtu(endpoint).map_or(
            RouteBudget {
                mtu: FALLBACK_MESH_MTU,
                lookup_failed: true,
            },
            |route| RouteBudget {
                mtu: mtu_for_route(route),
                lookup_failed: false,
            },
        );
        self.endpoints.insert(endpoint.ip(), budget);
        budget
    }

    /// Query the underlay route MTU toward `endpoint` through Linux route netlink.
    /// # Errors
    /// Reports an unreachable endpoint, missing egress link, or malformed route reply.
    #[cfg(target_os = "linux")]
    fn route_mtu(&mut self, endpoint: SocketAddr) -> io::Result<u32> {
        #[cfg(test)]
        ROUTE_LOOKUPS.with(|lookups| lookups.set(lookups.get() + 1));
        #[cfg(test)]
        if let Some(before) = BEFORE_ROUTE_LOOKUP.take() {
            before();
        }
        #[cfg(test)]
        if FAIL_ROUTE_LOOKUPS.with(|failures| {
            let remaining = failures.get();
            failures.set(remaining.saturating_sub(1));
            remaining > 0
        }) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let socket = match &mut self.socket {
            Some(socket) => socket,
            empty => empty.insert(crate::netlink::Socket::open(
                nix::sys::socket::SockProtocol::NetlinkRoute,
            )?),
        };
        let result = crate::wireguard::route_mtu_on(socket, endpoint);
        if result.is_err() {
            // An error may leave unread replies behind; the next lookup starts on a fresh socket.
            self.socket = None;
        }
        result
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

/// Create a `GotaTun` MTU watcher and the sender that updates its current value.
#[cfg(target_os = "linux")]
pub(crate) fn watcher(mtu: u16) -> (watch::Sender<u16>, MtuWatcher) {
    let (sender, receiver) = watch::channel(mtu);
    (sender, receiver.into())
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
