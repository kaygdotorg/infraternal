//! Owns peer route installation and endpoint-derived MTU policy for the macOS utun.

use super::utun_io::valid_utun_name;
use crate::dataplane::Config;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    process::Command,
};

/// Add, change or remove one peer host route through our allocated utun.
///
/// Add and change operations carry an unlocked route MTU so the system can refine it with later
/// PMTU information. Deletes carry no MTU.
/// # Errors
/// Reports invalid operation arguments, routing command failures, or an unexpected missing route.
pub(super) fn route(
    interface: &str,
    address: IpAddr,
    operation: &str,
    mtu: Option<u16>,
) -> io::Result<()> {
    if operation != "delete" && mtu.is_none() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let family = if address.is_ipv4() { "-inet" } else { "-inet6" };
    let mut command = Command::new("/sbin/route");
    command
        .args(["-n", operation, family, "-host"])
        .arg(address.to_string())
        .args(["-interface", interface]);
    let mtu_argument = mtu.map(|mtu| mtu.to_string());
    if let Some(mtu) = mtu_argument.as_deref() {
        command.args(["-mtu", mtu]);
    }
    let output = command.output()?;
    if output.status.success() {
        Ok(())
    } else if operation == "delete"
        && String::from_utf8_lossy(&output.stderr)
            .to_ascii_lowercase()
            .contains("not in table")
    {
        Ok(())
    } else {
        Err(io::ErrorKind::AddrInUse.into())
    }
}

/// Delete only peer host routes installed through the validated utun interface.
/// # Errors
/// Rejects a malformed utun name or reports a route deletion failure.
pub(super) fn remove_routes(interface: &str, routes: &BTreeSet<IpAddr>) -> io::Result<()> {
    if !valid_utun_name(interface) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    for address in routes {
        route(interface, *address, "delete", None)?;
    }
    Ok(())
}

/// Configure this owned utun at an IPv6-safe MTU and install its local addresses.
///
/// Callers pass a staging MTU no smaller than either the old or new peer budget until route
/// metrics have been updated. No other tunnel or resolver is changed.
pub(super) fn configure_interface(
    interface: &str,
    config: Option<&Config>,
    mtu: u16,
) -> io::Result<()> {
    run_ifconfig([interface, "mtu", &mtu.to_string(), "up"])?;
    if let Some(config) = config {
        run_ifconfig([
            interface,
            "inet",
            &config.addresses.ipv4.to_string(),
            &config.addresses.ipv4.to_string(),
            "netmask",
            "255.255.255.255",
        ])?;
        run_ifconfig([
            interface,
            "inet6",
            &config.addresses.ipv6.to_string(),
            "prefixlen",
            "128",
            "alias",
        ])?;
    }
    Ok(())
}

/// Change the packet size on the already-owned utun interface.
/// # Errors
/// Reports a rejected `ifconfig` request.
pub(super) fn set_interface_mtu(interface: &str, mtu: u16) -> io::Result<()> {
    run_ifconfig([interface, "mtu", &mtu.to_string()])
}

fn run_ifconfig<'a>(arguments: impl IntoIterator<Item = &'a str>) -> io::Result<()> {
    let output = Command::new("/sbin/ifconfig").args(arguments).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::ErrorKind::Other.into())
    }
}

/// The peers this node may connect to while it cannot enforce access rules.
///
/// The coordinator also distributes a peer when only the opposite direction is
/// granted (`inbound` is `None`) or when the grant is narrowed to ports. A
/// `WireGuard` peer would reach every port on this Mac in both cases, so only a
/// peer that may open connections to every port here (`inbound` is `All`) is
/// installed. The coordinator is always installed: every node may reach it
/// (D164). Its own inbound policy is not checked, so the server host can reach
/// every port on this Mac, which a Linux node would deny without an arrow.
/// The owner accepted that gap until the slice-3 filter (#265, J162 F1), and
/// `mesh status` says so. The cost is that an arrow from this Mac to a node
/// without the reverse arrow does not work until enforcement arrives.
pub(super) fn installed_peers(
    config: &Config,
) -> impl Iterator<Item = &crate::dataplane::PeerPolicy> {
    config.peers.iter().filter_map(|(node, policy)| {
        (config.server == Some(*node)
            || matches!(policy.inbound, crate::policy::rules::TrafficPolicy::All))
        .then_some(policy)
    })
}

/// Return only the installed peers' host addresses that belong on the utun interface.
pub(super) fn route_addresses(config: &Config) -> BTreeSet<IpAddr> {
    installed_peers(config)
        .flat_map(|policy| {
            [
                IpAddr::V4(policy.peer.addresses.ipv4),
                IpAddr::V6(policy.peer.addresses.ipv6),
            ]
        })
        .collect()
}

/// The endpoint-derived MTUs for one snapshot: each installed peer host route's budget and
/// the shared interface MTU.
///
/// Reading them costs a `route` and an `ifconfig` process per underlay path (about 6.5 ms
/// each on the Mac VM). [`PathBudgets::probe`] therefore runs on the caller's thread before a
/// snapshot is handed to the worker, never on the worker's runtime, which also drives every
/// packet through the utun: probing there stalled traffic for the whole update (#381 J411).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PathBudgets {
    /// Route MTU for each installed peer host route.
    pub(super) route_mtus: BTreeMap<IpAddr, u16>,
    /// Shared utun MTU: the largest peer budget, never below IPv6's minimum.
    pub(super) interface_mtu: u16,
}

impl PathBudgets {
    /// Probe each distinct underlay path of `config` once. `None` means no peers yet.
    pub(super) fn probe(config: Option<&Config>) -> Self {
        let mut probe = crate::mesh_mtu::EndpointProbe::default();
        let mut route_mtus = BTreeMap::new();
        let mut peer_mtus = Vec::new();
        if let Some(config) = config {
            for policy in installed_peers(config) {
                let mtu = probe.mesh_mtu(policy.peer.endpoint);
                route_mtus.insert(IpAddr::V4(policy.peer.addresses.ipv4), mtu);
                route_mtus.insert(IpAddr::V6(policy.peer.addresses.ipv6), mtu);
            }
            peer_mtus.extend(
                config
                    .peers
                    .values()
                    .map(|policy| probe.mesh_mtu(policy.peer.endpoint)),
            );
        }
        Self {
            route_mtus,
            interface_mtu: crate::mesh_mtu::interface_mtu(&peer_mtus),
        }
    }
}

/// Return retained host routes whose freshly derived MTU differs from the installed metric.
pub(super) fn route_mtus_to_refresh(
    old_routes: &BTreeSet<IpAddr>,
    new_routes: &BTreeSet<IpAddr>,
    old_mtus: &BTreeMap<IpAddr, u16>,
    new_mtus: &BTreeMap<IpAddr, u16>,
) -> BTreeSet<IpAddr> {
    old_routes
        .intersection(new_routes)
        .copied()
        .filter(|address| old_mtus.get(address).copied() != new_mtus.get(address).copied())
        .collect()
}

/// Refuse an endpoint that a host route would send back into this tunnel.
pub(super) fn validate_underlay_routes(
    config: &Config,
    routes: &BTreeSet<IpAddr>,
) -> io::Result<()> {
    if config.peers.values().any(|policy| {
        policy
            .peer
            .endpoint
            .is_some_and(|endpoint| routes.contains(&endpoint.ip()))
    }) {
        Err(io::ErrorKind::InvalidInput.into())
    } else {
        Ok(())
    }
}
