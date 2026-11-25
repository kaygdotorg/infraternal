//! Subnet routes on a node (D197 M3): what this node installs and forwards, and how it says so.
//!
//! Linux plays both parts below. A Mac is only ever a client: it shares the route states and the
//! snapshot-derived network list here, and plans its utun routes in
//! [`crate::macos_subnet_routes`]; the forwarding switch is Linux-only.
//!
//! A node plays up to two parts, both derived from the snapshot it last applied:
//! - **Client.** For every approved network behind a router peer that this node may reach
//!   (`PeerNetworks::through`), it installs a route through the mesh link. The `GotaTun` device
//!   already has the network in that peer's allowed IPs, and the packet filter decides which flows
//!   may start. A network that overlaps a route this machine already has (it sits on that LAN, or
//!   reaches it another way) is *not* installed: taking it over would cut the machine off from its
//!   own network. `mesh routes` says so instead.
//! - **Router.** For the networks it serves (`PeerNetworks::served`), it forwards only while the
//!   kernel guard holds the forward and masquerade rules ([`crate::firewall::Firewall::forwards_served`])
//!   and IPv4 forwarding is on. If forwarding was off, the node turns it on and records that it did
//!   (`mesh-ip-forward.json`), so it turns it off again when it stops serving, goes down, or finds
//!   the record after a crash. Forwarding that was already on (Docker, a router) is left alone.
//!
//! Nothing here fails a snapshot: a route or forwarding problem is reported in `mesh routes` and
//! the rest of the mesh keeps working. The packet filter refuses forwarded packets whenever
//! forwarding is not fully in place, so a half-configured router forwards nothing.
use crate::policy::networks::Network;
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::{io, path::Path};

/// Where the kernel keeps the IPv4 forwarding switch, per network namespace.
#[cfg(target_os = "linux")]
const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

/// What happened to one network this node may reach through a router peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RouteState {
    /// The route through the mesh link is in place.
    Installed,
    /// Not installed: this machine already routes part of the network elsewhere. Holds the
    /// overlapping route, such as `192.168.1.0/24`.
    #[cfg(target_os = "linux")]
    Overlaps(Network),
    /// Installing failed; the error text is kept for the status.
    Failed(String),
    /// Not installed on purpose; the sentence says why (a Mac's LAN or another VPN overlaps it,
    /// it holds a peer's underlay address, ...; see [`crate::macos_subnet_routes::Skip`]).
    Skipped(String),
}

/// The status of one reachable network, for `mesh routes`: `pending` until a reconcile has
/// decided it.
#[must_use]
pub(crate) fn route_json(state: Option<&RouteState>) -> serde_json::Value {
    match state {
        Some(RouteState::Installed) => serde_json::json!({"state": "installed"}),
        #[cfg(target_os = "linux")]
        Some(RouteState::Overlaps(other)) => serde_json::json!({
            "state": "not installed",
            "reason": format!("this machine already routes {other}, which overlaps it"),
        }),
        Some(RouteState::Failed(error)) => {
            serde_json::json!({"state": "failed", "reason": error})
        }
        Some(RouteState::Skipped(reason)) => {
            serde_json::json!({"state": "not installed", "reason": reason})
        }
        None => serde_json::json!({"state": "pending"}),
    }
}

/// Whether this node forwards for the networks it serves (Linux: a Mac never forwards).
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Forwarding {
    /// This node serves no approved network.
    #[default]
    Idle,
    /// Forwarding and masquerading for the served networks. `turned_on` says whether this node
    /// switched IPv4 forwarding on itself (and will switch it off again).
    On {
        /// IPv4 forwarding was off and this node turned it on.
        turned_on: bool,
    },
    /// Serving is approved but cannot happen; the sentence says why.
    Unavailable(String),
}

/// The subnet-route part of a Linux node's runtime state, rebuilt by every reconcile.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub(crate) struct SubnetState {
    /// The networks this node may reach through router peers, and what happened to each.
    pub(crate) routes: BTreeMap<Network, RouteState>,
    /// Whether this node forwards for its served networks.
    pub(crate) forwarding: Forwarding,
}

#[cfg(target_os = "linux")]
impl SubnetState {
    /// The status of one reachable network, for `mesh routes`.
    #[must_use]
    pub(crate) fn route_json(&self, network: Network) -> serde_json::Value {
        route_json(self.routes.get(&network))
    }

    /// The forwarding status, for `mesh routes`.
    #[must_use]
    pub(crate) fn forwarding_json(&self) -> serde_json::Value {
        match &self.forwarding {
            Forwarding::Idle => serde_json::json!({"state": "idle"}),
            Forwarding::On { turned_on } => serde_json::json!({
                "state": "on",
                "ip_forward": if *turned_on { "turned on by infraternal" } else { "already on" },
            }),
            Forwarding::Unavailable(reason) => {
                serde_json::json!({"state": "unavailable", "reason": reason})
            }
        }
    }
}

/// Whether IPv4 forwarding is on in this network namespace.
/// # Errors
/// Reports an unreadable or malformed sysctl.
#[cfg(target_os = "linux")]
pub(crate) fn ip_forward() -> io::Result<bool> {
    read_switch(Path::new(IP_FORWARD))
}

/// Turn IPv4 forwarding on or off in this network namespace.
/// # Errors
/// Reports a failed write, such as a read-only `/proc/sys` in a container.
#[cfg(target_os = "linux")]
pub(crate) fn set_ip_forward(on: bool) -> io::Result<()> {
    std::fs::write(IP_FORWARD, if on { "1\n" } else { "0\n" })
}

/// Read a `0`/`1` kernel switch.
#[cfg(target_os = "linux")]
fn read_switch(path: &Path) -> io::Result<bool> {
    match std::fs::read_to_string(path)?.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

/// The first underlay address in `endpoints` that lies inside `network`, if any.
///
/// The mesh's UDP socket is not bound to the mesh link, so routing such a network into the link
/// would send the tunnel's own packets to that peer back into the tunnel. Both the Mac plan
/// ([`crate::macos_subnet_routes::Skip::HoldsEndpoint`]) and the Linux install use this one test,
/// so the two systems leave out the same networks.
#[must_use]
pub(crate) fn holds_endpoint(
    network: Network,
    endpoints: &[std::net::IpAddr],
) -> Option<std::net::IpAddr> {
    endpoints
        .iter()
        .find(|address| network.contains(**address))
        .copied()
}

/// The reason, in words a person can act on, why a network holding `address` is left out;
/// `machine` is how this system calls itself (`this Mac`, `this machine`).
#[must_use]
pub(crate) fn holds_endpoint_sentence(address: std::net::IpAddr, machine: &str) -> String {
    format!(
        "it holds {address}, where {machine} reaches a mesh peer; routing it into the mesh \
         would send the tunnel's own packets back into it"
    )
}

/// Every underlay address this node sends to: each peer's configured endpoint and walk
/// candidates (a walk may move the peer to any of them) and the authenticated endpoints the
/// engine learned since (`live`). A wanted network holding one of them is never routed into the
/// mesh link.
#[cfg(target_os = "linux")]
#[must_use]
pub(crate) fn underlay_addresses(
    config: &crate::dataplane::Config,
    live: impl IntoIterator<Item = std::net::SocketAddr>,
) -> Vec<std::net::IpAddr> {
    let mut addresses: Vec<std::net::IpAddr> = config
        .peers
        .values()
        .flat_map(|policy| {
            policy
                .peer
                .endpoint
                .iter()
                .chain(policy.peer.candidates.iter())
        })
        .map(std::net::SocketAddr::ip)
        .chain(live.into_iter().map(|endpoint| endpoint.ip()))
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

/// Split `wanted` into the networks that may be routed and the ones left out because they hold
/// an underlay address (see [`holds_endpoint`]), with the reason text for `mesh routes`.
#[cfg(target_os = "linux")]
#[must_use]
pub(crate) fn split_by_underlay(
    wanted: &[Network],
    endpoints: &[std::net::IpAddr],
) -> (
    Vec<Network>,
    std::collections::BTreeMap<Network, RouteState>,
) {
    let mut routable = Vec::new();
    let mut left_out = std::collections::BTreeMap::new();
    for network in wanted {
        match holds_endpoint(*network, endpoints) {
            Some(address) => {
                left_out.insert(
                    *network,
                    RouteState::Skipped(holds_endpoint_sentence(address, "this machine")),
                );
            }
            None => routable.push(*network),
        }
    }
    (routable, left_out)
}

/// The networks to route through router peers, and the networks to forward, from one snapshot.
///
/// Only IPv4 networks with a non-empty grant count, the same set the packet filter compiles.
#[must_use]
pub(crate) fn reachable_networks(config: &crate::dataplane::Config) -> Vec<Network> {
    let mut networks: Vec<Network> = config
        .peers
        .values()
        .flat_map(|policy| policy.networks.through.iter())
        .filter(|network| {
            network.network.is_ipv4()
                && network.outbound != crate::policy::rules::TrafficPolicy::None
        })
        .map(|network| network.network)
        .collect();
    networks.sort_unstable();
    networks.dedup();
    networks
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    //! Status wording and the snapshot-derived network list.
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// The route and forwarding status name what happened and why.
    #[test]
    fn route_and_forwarding_status_say_what_happened() {
        let network: Network = "192.168.1.0/24".parse().unwrap();
        let mut state = SubnetState::default();
        assert_eq!(state.route_json(network)["state"], "pending");
        state.routes.insert(network, RouteState::Overlaps(network));
        assert!(
            state.route_json(network)["reason"]
                .as_str()
                .unwrap()
                .contains("already routes 192.168.1.0/24")
        );
        state.routes.insert(
            network,
            RouteState::Skipped("this Mac already reaches it through en0".to_owned()),
        );
        assert_eq!(state.route_json(network)["state"], "not installed");
        assert_eq!(
            state.route_json(network)["reason"],
            "this Mac already reaches it through en0"
        );
        assert_eq!(state.forwarding_json()["state"], "idle");
        state.forwarding = Forwarding::On { turned_on: true };
        assert_eq!(
            state.forwarding_json()["ip_forward"],
            "turned on by infraternal"
        );
    }

    /// A snapshot whose one peer sits at `endpoint` with `candidates`.
    fn config_with_peer(endpoint: Option<&str>, candidates: &[&str]) -> crate::dataplane::Config {
        use crate::{
            dataplane::{Config, DefaultPolicy, Peer, PeerNetworks, PeerPolicy},
            policy::{
                model::{Addresses, NodeId, PublicKey},
                rules::TrafficPolicy,
            },
        };
        Config {
            authority_epoch: None,
            rotation_operation: None,
            local_key: Some(PublicKey([1; 32])),
            server: Some(NodeId(1)),
            node: NodeId(2),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 1,
            addresses: Addresses {
                ipv4: "10.254.0.2".parse().unwrap(),
                ipv6: "fd01::2".parse().unwrap(),
            },
            default_policy: DefaultPolicy::Deny,
            exposure: None,
            peers: std::collections::BTreeMap::from([(
                NodeId(1),
                PeerPolicy {
                    peer: Peer {
                        key: PublicKey([3; 32]),
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: "10.254.0.1".parse().unwrap(),
                            ipv6: "fd01::1".parse().unwrap(),
                        },
                        endpoint: endpoint.map(|text| text.parse().unwrap()),
                        candidates: candidates
                            .iter()
                            .map(|text| text.parse().unwrap())
                            .collect(),
                        ipv4_only: false,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                    networks: PeerNetworks::default(),
                },
            )]),
            #[cfg(feature = "mesh-dns")]
            peer_names: std::collections::BTreeMap::new(),
        }
    }

    /// A network holding a peer's endpoint, a walk candidate or a learned endpoint is left out
    /// with the shared reason; the rest stays routable (J1195: a Linux route to it would loop the
    /// tunnel into itself).
    #[test]
    fn a_network_holding_an_underlay_address_is_left_out() {
        let config = config_with_peer(Some("192.168.1.9:51820"), &["10.20.0.5:51820"]);
        let learned: std::net::SocketAddr = "172.16.4.2:40000".parse().unwrap();
        let endpoints = underlay_addresses(&config, [learned]);
        assert_eq!(endpoints.len(), 3);
        let wanted: Vec<Network> = [
            "192.168.1.0/24",
            "10.20.0.0/16",
            "172.16.0.0/12",
            "10.99.0.0/24",
        ]
        .iter()
        .map(|text| text.parse().unwrap())
        .collect();
        let (routable, left_out) = split_by_underlay(&wanted, &endpoints);
        assert_eq!(routable, vec!["10.99.0.0/24".parse::<Network>().unwrap()]);
        assert_eq!(left_out.len(), 3);
        let state = left_out[&"192.168.1.0/24".parse::<Network>().unwrap()].clone();
        assert_eq!(
            route_json(Some(&state))["reason"],
            "it holds 192.168.1.9, where this machine reaches a mesh peer; routing it into the \
             mesh would send the tunnel's own packets back into it"
        );
        // The Mac says the same thing in its own words.
        assert_eq!(
            holds_endpoint_sentence("192.168.1.9".parse().unwrap(), "this Mac"),
            crate::macos_subnet_routes::Skip::HoldsEndpoint("192.168.1.9".parse().unwrap())
                .sentence()
        );
    }
}
