//! Which subnet routes a Mac puts on its mesh utun (D197 M3, #580): the pure plan shared by root
//! mode, where the infraternal agent runs `route` itself, and user mode, where the root helper does
//! it for the agent (#146). Free of side effects, so its tests also run in the Linux gate.
//!
//! A Mac is only ever a *client* of subnet routes: an approved network behind a router peer is
//! routed into the utun, the `GotaTun` device sends it to that peer (the network is in the peer's
//! allowed IPs), and the shared packet filter decides which flows may start (D164, D384). The
//! plan leaves a network out, and says why, when routing it would break something the Mac already
//! has:
//! - it overlaps a route or an interface network on another interface: the Mac's own LAN, or
//!   another VPN (on the Mac VM, `NetBird` holds `10.69.69/24` on `utun100`). A more specific mesh
//!   route would cut the Mac off from that network;
//! - it holds the underlay address of a mesh peer. The mesh's UDP socket is not bound to an
//!   interface, so the kernel would route the tunnel's own packets back into the tunnel;
//! - it overlaps the mesh's own address or prefix route on this utun;
//! - in user mode, it is not private space. The helper routes only RFC 1918 and shared CGNAT
//!   networks, the same limit it applies to the mesh route, so a process running as one person
//!   can never take public addresses away from the Mac's other accounts.
//!
//! The plan is declarative: it lists what to add, what to keep and which of *our* routes on the
//! utun to remove, so each reconcile converges on the snapshot no matter what was there before.
use crate::macos_user_mode::{Network as TableNetwork, Refusal, Route};
use infraternal_mesh::networks::Network;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr},
};

/// The most networks one Mac routes, the same limit a router has for what it advertises.
pub const MAX_NETWORKS: usize = 64;

/// Why the plan leaves a wanted network off the utun.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Skip {
    /// The Mac already reaches part of it another way: `network` through `interface`.
    Overlaps {
        /// The overlapping route or interface network, such as `192.168.64.0/24`.
        network: TableNetwork,
        /// Where the Mac sends it, such as `en0` or another VPN's `utun100`.
        interface: String,
    },
    /// It holds this mesh peer's underlay address.
    HoldsEndpoint(IpAddr),
    /// It overlaps the mesh's own address or prefix on this utun.
    Mesh,
    /// User mode routes only private networks (see the module notes).
    NotPrivate,
}

impl Skip {
    /// The reason in words a person can act on, for `mesh routes`.
    #[must_use]
    pub fn sentence(&self) -> String {
        match self {
            Self::Overlaps { network, interface } => format!(
                "this Mac already reaches {network} through {interface} (its own network or \
                 another VPN), which overlaps it"
            ),
            Self::HoldsEndpoint(address) => {
                crate::subnet_routes::holds_endpoint_sentence(*address, "this Mac")
            }
            Self::Mesh => "it overlaps this Mac's mesh addresses".to_owned(),
            Self::NotPrivate => "user mode routes only private networks (10.0.0.0/8, \
                                 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10); run the mesh as \
                                 root to reach it"
                .to_owned(),
        }
    }
}

/// What one reconcile does on the utun.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkPlan {
    /// Wanted networks to route into the utun now.
    pub add: Vec<Network>,
    /// Wanted networks already routed into the utun; nothing to do.
    pub keep: Vec<Network>,
    /// Our routes on the utun that are no longer wanted (or are now skipped).
    pub remove: Vec<Network>,
    /// Exact copies of a wanted network on an earlier utun of this same agent, to delete
    /// before the new utun takes it: `(network, interface)`.
    pub replace: Vec<(Network, String)>,
    /// Wanted networks left out, and why.
    pub skipped: BTreeMap<Network, Skip>,
}

/// The table form of a mesh network, for comparing with routing-table rows and for `route`.
#[must_use]
pub fn table_network(network: Network) -> TableNetwork {
    match network.address() {
        IpAddr::V4(address) => TableNetwork::v4(address, network.prefix()),
        IpAddr::V6(address) => TableNetwork::v6(address, network.prefix()),
    }
}

/// Whether `network` lies wholly inside one private IPv4 block (RFC 1918 or shared CGNAT).
#[must_use]
pub fn is_private(network: Network) -> bool {
    match network.address() {
        IpAddr::V4(address) => crate::macos_user_mode::private_ipv4_block(address)
            .is_some_and(|block| network.prefix() >= block.prefix),
        IpAddr::V6(_) => false,
    }
}

/// Check the networks a user-mode agent asks the helper to route.
///
/// # Errors
/// Refuses more than [`MAX_NETWORKS`], an IPv6 network (none are approved in this slice), a
/// network outside private space, and two networks that overlap each other (the server never
/// approves overlapping networks, so such a list is not a snapshot's).
pub fn check_requested(networks: &[Network]) -> Result<(), Refusal> {
    if networks.len() > MAX_NETWORKS {
        return Err(Refusal::Invalid(format!(
            "a request routes at most {MAX_NETWORKS} networks"
        )));
    }
    for (index, network) in networks.iter().enumerate() {
        if !network.is_ipv4() {
            return Err(Refusal::Invalid(format!(
                "{network} is IPv6; the mesh routes only IPv4 networks"
            )));
        }
        if !is_private(*network) {
            return Err(Refusal::Invalid(format!(
                "{network} is not a private network; {}",
                Skip::NotPrivate.sentence()
            )));
        }
        if networks[..index]
            .iter()
            .any(|other| other.overlaps(*network))
        {
            return Err(Refusal::Invalid(format!(
                "{network} overlaps another network in the same request"
            )));
        }
    }
    Ok(())
}

/// The mesh prefix routes on `interface`: IPv4 rows there that hold the node's own address
/// `own`. In user mode that is the helper's mesh route; root mode has none (host routes only).
fn mesh_rows<'a>(
    interface: &'a str,
    own: Option<Ipv4Addr>,
    routes: &'a [Route],
) -> impl Iterator<Item = &'a Route> + 'a {
    routes.iter().filter(move |row| {
        row.interface == interface
            && row.is_ipv4()
            && own.is_some_and(|own| row.network.contains(IpAddr::V4(own)))
    })
}

/// The subnet routes the helper finds on the caller's `interface`: every IPv4 row there that does
/// not hold the node's own address `own`.
///
/// In user mode the helper routes only the mesh prefix (which holds `own`), the node's own host
/// address and these networks onto the utun, and peers get no host routes (#146), so every other
/// IPv4 row on the caller's utun is one of ours. The helper keeps no state; this is how a fresh
/// helper process knows what an earlier one added. Root mode tracks its own list instead, because
/// its peer host routes share the utun.
#[must_use]
pub fn routes_on(interface: &str, own: Ipv4Addr, routes: &[Route]) -> Vec<Network> {
    let mut found: Vec<Network> = routes
        .iter()
        .filter(|row| {
            row.interface == interface && row.is_ipv4() && !row.network.contains(IpAddr::V4(own))
        })
        .filter_map(|row| Network::new(row.network.address, row.network.prefix).ok())
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

/// Plan the subnet routes on `interface`.
///
/// - `wanted`: the reachable networks of the applied snapshot, IPv4 only.
/// - `own`: the node's mesh IPv4 address (none before the first snapshot).
/// - `installed`: our routes on `interface` today ([`routes_on`] in user mode, the worker's own
///   list in root mode).
/// - `routes` and `local`: the routing table and every interface network, as the helper reads
///   them for the mesh route ([`crate::macos_user_mode::plan_route`]).
/// - `ours`: other utuns proved to belong to this same agent (an earlier utun still closing);
///   their rows are never conflicts, and an exact copy of a wanted network there is replaced.
/// - `endpoints`: every underlay address the mesh sends to (configured and live peer endpoints).
/// - `private_only`: user mode's limit ([`Skip::NotPrivate`]).
///
/// Host routes on `lo0` that the table lists are skipped as in `plan_route`: macOS adds one for
/// every local address, and the address itself is checked on its real interface through `local`.
#[must_use]
pub fn plan_networks(
    wanted: &[Network],
    interface: &str,
    own: Option<Ipv4Addr>,
    installed: &[Network],
    routes: &[Route],
    local: &[Route],
    ours: &[String],
    endpoints: &[IpAddr],
    private_only: bool,
) -> NetworkPlan {
    let mut plan = NetworkPlan::default();
    let wanted: BTreeSet<Network> = wanted.iter().copied().collect();
    let installed: BTreeSet<Network> = installed.iter().copied().collect();
    for network in &wanted {
        let table = table_network(*network);
        if let Some(skip) = skip_reason(
            *network,
            table,
            interface,
            own,
            routes,
            local,
            ours,
            endpoints,
            private_only,
        ) {
            plan.skipped.insert(*network, skip);
            continue;
        }
        for row in routes {
            if row.network == table
                && ours.contains(&row.interface)
                && !plan
                    .replace
                    .iter()
                    .any(|(n, i)| n == network && *i == row.interface)
            {
                plan.replace.push((*network, row.interface.clone()));
            }
        }
        if installed.contains(network) {
            plan.keep.push(*network);
        } else {
            plan.add.push(*network);
        }
    }
    plan.remove = installed
        .iter()
        .filter(|network| !plan.add.contains(network) && !plan.keep.contains(network))
        .copied()
        .collect();
    plan
}

/// The first reason to leave `network` out, if any (see [`plan_networks`]).
fn skip_reason(
    network: Network,
    table: TableNetwork,
    interface: &str,
    own: Option<Ipv4Addr>,
    routes: &[Route],
    local: &[Route],
    ours: &[String],
    endpoints: &[IpAddr],
    private_only: bool,
) -> Option<Skip> {
    if !network.is_ipv4() {
        return Some(Skip::Mesh);
    }
    if private_only && !is_private(network) {
        return Some(Skip::NotPrivate);
    }
    if own.is_some_and(|own| network.contains(IpAddr::V4(own)))
        || mesh_rows(interface, own, routes).any(|row| row.network.overlaps(&table))
    {
        return Some(Skip::Mesh);
    }
    if let Some(address) = crate::subnet_routes::holds_endpoint(network, endpoints) {
        return Some(Skip::HoldsEndpoint(address));
    }
    for row in local.iter().chain(routes) {
        let loopback_host = row.interface == "lo0"
            && row.network.prefix == if row.is_ipv4() { 32 } else { 128 }
            && routes.contains(row);
        if row.interface == interface
            || ours.contains(&row.interface)
            || loopback_host
            || !row.network.overlaps(&table)
        {
            continue;
        }
        return Some(Skip::Overlaps {
            network: row.network,
            interface: row.interface.clone(),
        });
    }
    None
}

/// Drop the candidate addresses that fall inside an installed network.
///
/// A router peer usually lists its LAN address as a candidate, and that address sits inside
/// the very network it routes. Once that network is routed into the utun, a walk toward the
/// candidate would send the tunnel's handshake into the tunnel, and if it ever answered (the
/// router can reach its own address), the engine would move the peer there and loop every
/// packet. A Mac that is really on that LAN never installs the network (it overlaps), so it
/// keeps the candidate.
#[must_use]
pub fn reachable_candidates(
    candidates: &[std::net::SocketAddr],
    installed: &BTreeSet<Network>,
) -> Vec<std::net::SocketAddr> {
    candidates
        .iter()
        .filter(|candidate| {
            !installed
                .iter()
                .any(|network| network.contains(candidate.ip()))
        })
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    //! The Mac route plan: what is added, kept, removed and left out, and the helper's checks.
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Parse a canonical network.
    fn net(text: &str) -> Network {
        text.parse().unwrap()
    }

    /// One routing-table row.
    fn row(network: &str, interface: &str) -> Route {
        let (address, prefix) = network.split_once('/').unwrap();
        Route {
            network: TableNetwork::v4(address.parse().unwrap(), prefix.parse().unwrap()),
            interface: interface.to_owned(),
        }
    }

    /// The Mac VM's real IPv4 table (`netstat -rn -f inet`, 2026-11-24), with the mesh route
    /// on utun7 in user mode.
    fn mac_vm_table() -> Vec<Route> {
        let output = "Routing tables\n\nInternet:\n\
Destination        Gateway            Flags               Netif Expire\n\
default            192.168.64.1       UGScg                 en0       \n\
10.69.69/24        utun100            USc               utun100       \n\
10.69.69.58        10.69.69.58        UH                utun100       \n\
10.254/16          utun7              USc                 utun7       \n\
10.254.0.9         10.254.0.9         UH                  utun7       \n\
127                127.0.0.1          UCS                   lo0       \n\
127.0.0.1          127.0.0.1          UH                    lo0       \n\
169.254            link#7             UCS                   en0      !\n\
192.168.64         link#7             UCS                   en0      !\n\
192.168.64.1/32    link#7             UCS                   en0      !\n\
192.168.64.1       7e:d6:2c:40:e8:64  UHLWIir               en0   1086\n\
192.168.64.6/32    link#7             UCS                   en0      !\n\
224.0.0/4          link#7             UmCS                  en0      !\n";
        crate::macos_user_mode::parse_routes(output, true).unwrap()
    }

    /// The Mac VM's interface networks.
    fn mac_vm_local() -> Vec<Route> {
        vec![
            row("192.168.64.0/24", "en0"),
            row("10.69.69.58/32", "utun100"),
            row("10.254.0.9/32", "utun7"),
        ]
    }

    /// Plan in user mode on the Mac VM's table.
    fn user_plan(wanted: &[&str], installed: &[&str]) -> NetworkPlan {
        let wanted: Vec<Network> = wanted.iter().map(|text| net(text)).collect();
        let installed: Vec<Network> = installed.iter().map(|text| net(text)).collect();
        plan_networks(
            &wanted,
            "utun7",
            Some("10.254.0.9".parse().unwrap()),
            &installed,
            &mac_vm_table(),
            &mac_vm_local(),
            &[],
            &["203.0.113.7".parse().unwrap()],
            true,
        )
    }

    /// A free private network is added; one already on the utun is kept; one no longer wanted
    /// is removed.
    #[test]
    fn free_networks_are_added_kept_and_removed() {
        let plan = user_plan(
            &["10.77.0.0/24", "172.20.0.0/16"],
            &["172.20.0.0/16", "10.9.0.0/24"],
        );
        assert_eq!(plan.add, vec![net("10.77.0.0/24")]);
        assert_eq!(plan.keep, vec![net("172.20.0.0/16")]);
        assert_eq!(plan.remove, vec![net("10.9.0.0/24")]);
        assert!(plan.skipped.is_empty());
    }

    /// The Mac's own LAN, a network inside it, a network around it, and another VPN's range are
    /// left out with the overlapping route and its interface named.
    #[test]
    fn networks_the_mac_reaches_another_way_are_left_out_with_why() {
        let plan = user_plan(
            &[
                "192.168.64.0/24",
                "192.168.64.128/25",
                "192.168.0.0/16",
                "10.69.69.0/24",
            ],
            &["192.168.64.0/24"],
        );
        assert!(plan.add.is_empty() && plan.keep.is_empty());
        // A network that is now skipped and was on the utun is taken off again.
        assert_eq!(plan.remove, vec![net("192.168.64.0/24")]);
        assert_eq!(
            plan.skipped[&net("10.69.69.0/24")],
            Skip::Overlaps {
                network: TableNetwork::v4("10.69.69.58".parse().unwrap(), 32),
                interface: "utun100".to_owned(),
            }
        );
        let lan = plan.skipped[&net("192.168.64.128/25")].sentence();
        assert!(lan.contains("through en0"), "{lan}");
        assert!(matches!(
            plan.skipped[&net("192.168.0.0/16")],
            Skip::Overlaps { ref interface, .. } if interface == "en0"
        ));
    }

    /// The mesh's own prefix and a network holding a peer's underlay address are never routed
    /// into the utun; in user mode neither is public space.
    #[test]
    fn mesh_endpoints_and_public_space_are_left_out() {
        let plan = user_plan(&["10.254.8.0/24", "10.0.0.0/8"], &[]);
        assert_eq!(plan.skipped[&net("10.254.8.0/24")], Skip::Mesh);
        // 10.0.0.0/8 holds the mesh route and NetBird's range; the mesh check comes first.
        assert_eq!(plan.skipped[&net("10.0.0.0/8")], Skip::Mesh);
        let plan = plan_networks(
            &[net("203.0.113.0/24"), net("198.51.100.0/24")],
            "utun7",
            None,
            &[],
            &[],
            &[],
            &[],
            &["203.0.113.7".parse().unwrap()],
            false,
        );
        assert_eq!(
            plan.skipped[&net("203.0.113.0/24")],
            Skip::HoldsEndpoint("203.0.113.7".parse().unwrap())
        );
        // Root mode routes what the server approved, public or not.
        assert_eq!(plan.add, vec![net("198.51.100.0/24")]);
        let user = user_plan(&["198.51.100.0/24"], &[]);
        assert_eq!(user.skipped[&net("198.51.100.0/24")], Skip::NotPrivate);
    }

    /// A copy of a wanted network on an earlier utun of the same agent is replaced, not treated
    /// as another VPN; on a utun that is not ours it is a conflict.
    #[test]
    fn an_earlier_utun_of_this_agent_is_replaced() {
        let routes = vec![row("10.77.0.0/24", "utun5")];
        let ours = plan_networks(
            &[net("10.77.0.0/24")],
            "utun7",
            None,
            &[],
            &routes,
            &[],
            &["utun5".to_owned()],
            &[],
            true,
        );
        assert_eq!(
            ours.replace,
            vec![(net("10.77.0.0/24"), "utun5".to_owned())]
        );
        assert_eq!(ours.add, vec![net("10.77.0.0/24")]);
        let other = plan_networks(
            &[net("10.77.0.0/24")],
            "utun7",
            None,
            &[],
            &routes,
            &[],
            &[],
            &[],
            true,
        );
        assert!(matches!(
            other.skipped[&net("10.77.0.0/24")],
            Skip::Overlaps { .. }
        ));
    }

    /// The helper finds what an earlier helper process added: rows on the caller's utun other
    /// than the mesh prefix and the node's own address.
    #[test]
    fn the_helper_reads_its_earlier_networks_from_the_table() {
        let mut table = mac_vm_table();
        table.push(row("10.77.0.0/24", "utun7"));
        table.push(row("10.88.0.5/32", "utun7"));
        assert_eq!(
            routes_on("utun7", "10.254.0.9".parse().unwrap(), &table),
            vec![net("10.77.0.0/24"), net("10.88.0.5/32")]
        );
    }

    /// The helper refuses too many networks, IPv6, public space and overlapping entries.
    #[test]
    fn helper_requests_are_checked() {
        assert!(check_requested(&[net("10.77.0.0/24"), net("192.168.5.0/24")]).is_ok());
        assert!(check_requested(&[net("fd00:1::/64")]).is_err());
        assert!(check_requested(&[net("8.8.8.0/24")]).is_err());
        assert!(check_requested(&[net("10.0.0.0/7")]).is_err());
        assert!(check_requested(&[net("10.1.0.0/16"), net("10.1.2.0/24")]).is_err());
        let many: Vec<Network> = (0..=64_u8)
            .map(|third| Network::new(IpAddr::V4(Ipv4Addr::new(10, 1, third, 0)), 24).unwrap())
            .collect();
        assert!(check_requested(&many).is_err());
        assert!(check_requested(&many[..64]).is_ok());
    }

    /// Candidates inside an installed network are dropped; others stay in order.
    #[test]
    fn candidates_inside_an_installed_network_are_dropped() {
        let installed: BTreeSet<Network> = [net("192.168.77.0/24")].into();
        let candidates = vec![
            "192.168.77.10:51820".parse().unwrap(),
            "203.0.113.9:51820".parse().unwrap(),
            "192.168.78.10:51820".parse().unwrap(),
        ];
        assert_eq!(
            reachable_candidates(&candidates, &installed),
            vec![candidates[1], candidates[2]]
        );
    }
}
