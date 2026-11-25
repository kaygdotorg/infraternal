//! Subnet routes on a Linux node (D197 M3): what this node installs and forwards, and how it says so.
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
use std::{collections::BTreeMap, io, path::Path};

/// Where the kernel keeps the IPv4 forwarding switch, per network namespace.
const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

/// What happened to one network this node may reach through a router peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RouteState {
    /// The route through the mesh link is in place.
    Installed,
    /// Not installed: this machine already routes part of the network elsewhere. Holds the
    /// overlapping route, such as `192.168.1.0/24`.
    Overlaps(Network),
    /// Installing failed; the error text is kept for the status.
    Failed(String),
}

/// Whether this node forwards for the networks it serves.
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
#[derive(Debug, Default)]
pub(crate) struct SubnetState {
    /// The networks this node may reach through router peers, and what happened to each.
    pub(crate) routes: BTreeMap<Network, RouteState>,
    /// Whether this node forwards for its served networks.
    pub(crate) forwarding: Forwarding,
}

impl SubnetState {
    /// The status of one reachable network, for `mesh routes`.
    #[must_use]
    pub(crate) fn route_json(&self, network: Network) -> serde_json::Value {
        match self.routes.get(&network) {
            Some(RouteState::Installed) => serde_json::json!({"state": "installed"}),
            Some(RouteState::Overlaps(other)) => serde_json::json!({
                "state": "not installed",
                "reason": format!("this machine already routes {other}, which overlaps it"),
            }),
            Some(RouteState::Failed(error)) => {
                serde_json::json!({"state": "failed", "reason": error})
            }
            None => serde_json::json!({"state": "pending"}),
        }
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
pub(crate) fn ip_forward() -> io::Result<bool> {
    read_switch(Path::new(IP_FORWARD))
}

/// Turn IPv4 forwarding on or off in this network namespace.
/// # Errors
/// Reports a failed write, such as a read-only `/proc/sys` in a container.
pub(crate) fn set_ip_forward(on: bool) -> io::Result<()> {
    std::fs::write(IP_FORWARD, if on { "1\n" } else { "0\n" })
}

/// Read a `0`/`1` kernel switch.
fn read_switch(path: &Path) -> io::Result<bool> {
    match std::fs::read_to_string(path)?.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
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

#[cfg(test)]
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
        assert_eq!(state.forwarding_json()["state"], "idle");
        state.forwarding = Forwarding::On { turned_on: true };
        assert_eq!(
            state.forwarding_json()["ip_forward"],
            "turned on by infraternal"
        );
    }
}
