//! Derives which Mesh peers may use the proxy's Mesh listener pair [#281, D316].
//!
//! Both firewall frontends and conntrack retirement read the same answer, so a
//! peer admitted for a new connection is also admitted for that connection's
//! later packets, and its existing flows survive unrelated grant changes.
//!
//! A peer is a proxy source when its inbound policy allows TCP to at least one
//! published backend port (or allows everything). Traefik's per-route
//! allowlist then narrows the source to the routes it was granted. The
//! listener pair itself is never a grant, so it is checked here and not in the
//! ordinary per-port sets.
use crate::{
    dataplane::{Config, PeerPolicy},
    policy::rules::{Port, Protocol},
};
use infraternal_mesh::proxy_ports::{MeshProxyIngress, PROXY_INGRESS_PORT_RANGES};
use std::collections::BTreeSet;

/// The selected Mesh listener ports, when at least one Mesh route is applied.
///
/// A pair outside the declared proxy port ranges, or one with equal ports, is
/// treated as absent so a malformed update can never open an arbitrary port.
#[must_use]
pub fn selected_ports(ingress: &MeshProxyIngress) -> Option<[u16; 2]> {
    ingress
        .listener_pair
        .filter(|pair| {
            !ingress.backend_ports.is_empty()
                && pair.http != pair.https
                && PROXY_INGRESS_PORT_RANGES
                    .iter()
                    .any(|range| range.contains(pair.http))
                && PROXY_INGRESS_PORT_RANGES
                    .iter()
                    .any(|range| range.contains(pair.https))
        })
        .map(|pair| [pair.http, pair.https])
}

/// The published backend ports this peer may reach through the proxy.
#[must_use]
pub fn routes(peer: &PeerPolicy, ingress: &MeshProxyIngress) -> BTreeSet<u16> {
    if selected_ports(ingress).is_none() {
        return BTreeSet::new();
    }
    ingress
        .backend_ports
        .iter()
        .copied()
        .filter(|number| {
            peer.inbound.allows(Port {
                protocol: Protocol::Tcp,
                number: *number,
            })
        })
        .collect()
}

/// Peers admitted to the selected listener pair, in configuration order.
pub fn sources<'a>(
    config: &'a Config,
    ingress: &'a MeshProxyIngress,
) -> impl Iterator<Item = &'a PeerPolicy> + 'a {
    config
        .peers
        .values()
        .filter(move |peer| !routes(peer, ingress).is_empty())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::{
        dataplane::Peer,
        policy::model::{Addresses, PublicKey},
    };
    use infraternal_mesh::proxy_ports::{ListenerPortPair, MIXED_LISTENER_PAIRS};

    use crate::policy::rules::TrafficPolicy;

    fn peer(inbound: TrafficPolicy) -> PeerPolicy {
        PeerPolicy {
            peer: Peer {
                key: PublicKey([1; 32]),
                addresses: Addresses {
                    ipv4: "10.254.0.3".parse().expect("IPv4"),
                    ipv6: "fd01::3".parse().expect("IPv6"),
                },
                endpoint: None,
            },
            inbound,
            outbound: TrafficPolicy::None,
            access_ssh: None,
        }
    }

    fn tcp(numbers: &[u16]) -> TrafficPolicy {
        TrafficPolicy::Ports(
            numbers
                .iter()
                .map(|number| Port {
                    protocol: Protocol::Tcp,
                    number: *number,
                })
                .collect(),
        )
    }

    #[test]
    fn a_peer_reaches_only_the_published_ports_its_grant_names() {
        let ingress = MeshProxyIngress {
            listener_pair: Some(MIXED_LISTENER_PAIRS[1]),
            backend_ports: BTreeSet::from([3000, 8080]),
            ..MeshProxyIngress::default()
        };
        assert_eq!(
            routes(&peer(tcp(&[8080, 22])), &ingress),
            BTreeSet::from([8080])
        );
        assert_eq!(
            routes(&peer(TrafficPolicy::All), &ingress),
            BTreeSet::from([3000, 8080])
        );
        assert!(routes(&peer(tcp(&[22])), &ingress).is_empty());
        let unsafe_pair = MeshProxyIngress {
            listener_pair: Some(ListenerPortPair {
                http: 22,
                https: 23,
            }),
            ..ingress
        };
        assert!(routes(&peer(TrafficPolicy::All), &unsafe_pair).is_empty());
    }
}
