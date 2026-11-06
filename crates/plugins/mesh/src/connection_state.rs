//! Retires exactly the mesh connection state no longer permitted after final installation [242,252].
//!
//! Kernel dumps are streamed. Deletion carries the full initiating tuple, zone
//! and observed state ID, so a concurrent replacement cannot be mistaken for
//! the observed entry. The selected kernel object owns both original and reply
//! indexes; removing it retires both directions, regardless of which endpoint
//! initiated it. Fresh TCP acceptance requires SYN so reverse continuation
//! cannot recreate that object. No namespace-wide removal request is constructed.
//!
//! A flow to the proxy's selected Mesh listener pair is judged by the proxy
//! source test the firewall uses, not by a per-port grant: the pair is never a
//! grant, so a port-granted peer's proxied flows would otherwise be retired on
//! every unrelated narrowing [#281].
//!
//! The reverse also holds: a source that loses any proxied route has all of its
//! flows to the pair retired, because Traefik keeps upgraded connections (such
//! as web sockets) across a route reload and one flow can't be attributed to a
//! route at this layer. Its other proxied connections reconnect with a fresh SYN.
use crate::{
    dataplane::{Config, PeerPolicy},
    netlink::{self, ConnectionTuple, Socket},
    policy::rules::{Port, Protocol, TrafficPolicy},
};
use infraternal_mesh::proxy_ports::MeshProxyIngress;
use nix::sys::socket::SockProtocol;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
};

fn contains(next: &TrafficPolicy, old: &TrafficPolicy) -> bool {
    match (next, old) {
        (TrafficPolicy::All, _) | (_, TrafficPolicy::None) => true,
        (TrafficPolicy::Ports(next), TrafficPolicy::Ports(old)) => old.is_subset(next),
        _ => false,
    }
}
fn unchanged_reach(old: &Config, next: &Config) -> bool {
    old.addresses == next.addresses
        && old.peers.iter().all(|(id, old)| {
            next.peers.get(id).is_some_and(|next| {
                next.peer.addresses == old.peer.addresses
                    && contains(&next.inbound, &old.inbound)
                    && contains(&next.outbound, &old.outbound)
            })
        })
}
fn permits(rules: &TrafficPolicy, tuple: ConnectionTuple) -> bool {
    match rules {
        TrafficPolicy::All => true,
        TrafficPolicy::None => false,
        TrafficPolicy::Ports(_) => {
            let protocol = match tuple.protocol {
                6 => Protocol::Tcp,
                17 => Protocol::Udp,
                _ => return false,
            };
            tuple
                .destination_port
                .is_some_and(|number| rules.allows(Port { protocol, number }))
        }
    }
}
// An incoming TCP flow to the selected listener pair from a current proxy source.
fn proxied(peer: &PeerPolicy, tuple: ConnectionTuple, ingress: &MeshProxyIngress) -> bool {
    tuple.protocol == 6
        && tuple.destination_port.is_some_and(|port| {
            crate::proxy_access::selected_ports(ingress).is_some_and(|pair| pair.contains(&port))
        })
        && !crate::proxy_access::routes(peer, ingress).is_empty()
}
/// Proxy routes as last applied: the configuration and route snapshot they were derived from.
pub type ProxyView<'a> = (&'a Config, &'a MeshProxyIngress);

/// Proxied flows that must end: those to a pair that is no longer selected, and those of
/// sources that lost at least one route since `previous` (a narrowed grant or a removed route).
#[must_use]
pub fn retired_proxy_flows(
    previous: Option<ProxyView<'_>>,
    next: &Config,
    ingress: &MeshProxyIngress,
) -> (BTreeSet<u16>, BTreeSet<IpAddr>) {
    let Some((old_config, old_ingress)) = previous else {
        return (BTreeSet::new(), BTreeSet::new());
    };
    let Some(old_pair) = crate::proxy_access::selected_ports(old_ingress) else {
        return (BTreeSet::new(), BTreeSet::new());
    };
    if crate::proxy_access::selected_ports(ingress) != Some(old_pair) {
        return (BTreeSet::from(old_pair), BTreeSet::new());
    }
    let lost = old_config
        .peers
        .iter()
        .filter(|(id, old)| {
            let before = crate::proxy_access::routes(old, old_ingress);
            let after = next
                .peers
                .get(id)
                .filter(|peer| peer.peer.addresses == old.peer.addresses)
                .map(|peer| crate::proxy_access::routes(peer, ingress))
                .unwrap_or_default();
            !before.is_subset(&after)
        })
        .flat_map(|(_, old)| {
            [
                IpAddr::V4(old.peer.addresses.ipv4),
                IpAddr::V6(old.peer.addresses.ipv6),
            ]
        })
        .collect::<BTreeSet<_>>();
    if lost.is_empty() {
        (BTreeSet::new(), lost)
    } else {
        (BTreeSet::from(old_pair), lost)
    }
}
/// Remove only entries with an owned local mesh endpoint and a retired initiating service.
/// # Errors
/// Reports interrupted dumps, ambiguous kernel selectors or deletion errors;
/// already-expired entries are idempotent. Current rules refuse traffic before this runs.
pub fn retire(
    old: Option<&Config>,
    next: &Config,
    previous_proxy: Option<ProxyView<'_>>,
    ingress: &MeshProxyIngress,
) -> io::Result<()> {
    let (retired_ports, lost_sources) = retired_proxy_flows(previous_proxy, next, ingress);
    if retired_ports.is_empty() && old.is_some_and(|old| unchanged_reach(old, next)) {
        return Ok(());
    }
    let local = [
        IpAddr::V4(next.addresses.ipv4),
        IpAddr::V6(next.addresses.ipv6),
    ];
    let owned: Vec<_> = std::iter::once(next.addresses)
        .chain(old.map(|old| old.addresses))
        .flat_map(|addresses| [IpAddr::V4(addresses.ipv4), IpAddr::V6(addresses.ipv6)])
        .collect();
    let peers: BTreeMap<_, _> = next
        .peers
        .values()
        .flat_map(|peer| {
            [
                (IpAddr::V4(peer.peer.addresses.ipv4), peer),
                (IpAddr::V6(peer.peer.addresses.ipv6), peer),
            ]
        })
        .collect();
    let mut dump = Socket::open(SockProtocol::NetlinkNetFilter)?;
    let mut deletion = Socket::open(SockProtocol::NetlinkNetFilter)?;
    dump.visit(0x101, 0x300, &[0, 0, 0, 0], |body| {
        let header = body.get(..4).ok_or(io::ErrorKind::InvalidData)?;
        let fields = netlink::attributes(&body[4..])?;
        let unique = |kind| -> io::Result<Option<&[u8]>> {
            let mut matching = fields.iter().filter(|field| field.kind == kind);
            let result = matching.next().map(|field| field.payload);
            if matching.next().is_some() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(result)
        };
        let original = unique(1)?.ok_or(io::ErrorKind::InvalidData)?;
        let tuple = netlink::connection_tuple(original)?;
        // Node-local loopback and all unrelated host endpoints remain untouched.
        let incoming = owned.contains(&tuple.destination);
        let outgoing = owned.contains(&tuple.source);
        if incoming == outgoing {
            return Ok(());
        }
        let (address, current_local) = if incoming {
            (tuple.source, local.contains(&tuple.destination))
        } else {
            (tuple.destination, local.contains(&tuple.source))
        };
        let proxy_retired = incoming
            && tuple.protocol == 6
            && tuple
                .destination_port
                .is_some_and(|port| retired_ports.contains(&port))
            && (lost_sources.is_empty() || lost_sources.contains(&address));
        if current_local
            && !proxy_retired
            && peers.get(&address).is_some_and(|peer| {
                permits(
                    if incoming {
                        &peer.inbound
                    } else {
                        &peer.outbound
                    },
                    tuple,
                ) || incoming && proxied(peer, tuple, ingress)
            })
        {
            return Ok(());
        }
        let id = unique(12)?
            .filter(|id| id.len() == 4)
            .ok_or(io::ErrorKind::InvalidData)?;
        let zone = unique(18)?;
        if zone.is_some_and(|zone| zone.len() != 2) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut request = header.to_vec();
        netlink::attribute(&mut request, 1 | netlink::NESTED, original)?;
        netlink::attribute(&mut request, 12, id)?;
        if let Some(zone) = zone {
            netlink::attribute(&mut request, 18, zone)?;
        }
        // Tuple + ID is a compare-and-remove operation. A missing/changed entry
        // is safe; any other failure must keep the revision unacknowledged.
        match deletion.request(0x102, 4, &request) {
            Ok(_) => Ok(()),
            Err(error) if error.raw_os_error() == Some(2) => Ok(()),
            Err(error) => Err(error),
        }
    })
}

/// Connection-state checks for proxied flows and their routes.
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use std::collections::BTreeSet;
    #[test]
    fn narrowing_depends_on_services_and_direction_not_the_fallback_label() {
        let tcp = Port {
            protocol: Protocol::Tcp,
            number: 5540,
        };
        let udp = Port {
            protocol: Protocol::Udp,
            number: 5540,
        };
        let one = TrafficPolicy::Ports(BTreeSet::from([tcp]));
        let both = TrafficPolicy::Ports(BTreeSet::from([tcp, udp]));
        assert!(!contains(&one, &both));
        assert!(contains(&both, &one));
        assert!(!contains(&one, &TrafficPolicy::All));
        assert!(contains(&TrafficPolicy::All, &both));
        let tuple = ConnectionTuple {
            source: IpAddr::from([10, 254, 0, 1]),
            destination: IpAddr::from([10, 254, 0, 2]),
            protocol: 6,
            destination_port: Some(5540),
        };
        assert!(permits(&one, tuple));
        assert!(!permits(
            &one,
            ConnectionTuple {
                protocol: 17,
                ..tuple
            }
        ));
        assert!(!permits(
            &one,
            ConnectionTuple {
                destination_port: Some(5541),
                ..tuple
            }
        ));
        assert!(permits(
            &TrafficPolicy::All,
            ConnectionTuple {
                protocol: 1,
                destination_port: None,
                ..tuple
            }
        ));
        assert!(!permits(&TrafficPolicy::None, tuple));
    }

    /// A peer granted a port keeps its proxied flows while it is a proxy source.
    #[test]
    fn a_port_granted_peer_keeps_its_proxied_flows_while_it_is_a_proxy_source() {
        let selected = infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS[1];
        let ingress = MeshProxyIngress {
            listener_pair: Some(selected),
            backend_ports: BTreeSet::from([8080]),
            ..MeshProxyIngress::default()
        };
        let granted = |numbers: &[u16]| PeerPolicy {
            peer: crate::dataplane::Peer {
                key: crate::policy::model::PublicKey([1; 32]),
                previous_key: None,
                previous_active: false,
                addresses: crate::policy::model::Addresses {
                    ipv4: "10.254.0.3".parse().expect("IPv4"),
                    ipv6: "fd01::3".parse().expect("IPv6"),
                },
                endpoint: None,
            },
            inbound: TrafficPolicy::Ports(
                numbers
                    .iter()
                    .map(|number| Port {
                        protocol: Protocol::Tcp,
                        number: *number,
                    })
                    .collect(),
            ),
            outbound: TrafficPolicy::None,
            access_ssh: None,
        };
        let tuple = ConnectionTuple {
            source: IpAddr::from([10, 254, 0, 3]),
            destination: IpAddr::from([10, 254, 0, 1]),
            protocol: 6,
            destination_port: Some(selected.https),
        };
        let peer = granted(&[8080]);
        assert!(!permits(&peer.inbound, tuple), "the pair is never a grant");
        assert!(proxied(&peer, tuple, &ingress));
        assert!(!proxied(&granted(&[22]), tuple, &ingress));
        assert!(!proxied(
            &peer,
            ConnectionTuple {
                destination_port: Some(selected.https + 1),
                ..tuple
            },
            &ingress
        ));
        assert!(!proxied(&peer, tuple, &MeshProxyIngress::default()));
    }

    /// Losing any proxied route retires that source's flows to the pair.
    #[test]
    fn losing_any_proxied_route_retires_that_sources_flows_to_the_pair() {
        let selected = infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS[1];
        let ingress = |ports: &[u16]| MeshProxyIngress {
            listener_pair: Some(selected),
            backend_ports: ports.iter().copied().collect(),
            ..MeshProxyIngress::default()
        };
        let config = |granted: &[u16]| {
            let mut config: Config = serde_json::from_value(serde_json::json!({
                "node": 1, "version": 1,
                "addresses": {"ipv4": "10.254.0.1", "ipv6": "fd01::1"},
                "default_policy": "Deny", "exposure": null, "peers": {}
            }))
            .expect("fixture configuration");
            config.peers.insert(
                crate::policy::model::NodeId(3),
                PeerPolicy {
                    peer: crate::dataplane::Peer {
                        key: crate::policy::model::PublicKey([1; 32]),
                        previous_key: None,
                        previous_active: false,
                        addresses: crate::policy::model::Addresses {
                            ipv4: "10.254.0.3".parse().expect("IPv4"),
                            ipv6: "fd01::3".parse().expect("IPv6"),
                        },
                        endpoint: None,
                    },
                    inbound: TrafficPolicy::Ports(
                        granted
                            .iter()
                            .map(|number| Port {
                                protocol: Protocol::Tcp,
                                number: *number,
                            })
                            .collect(),
                    ),
                    outbound: TrafficPolicy::None,
                    access_ssh: None,
                },
            );
            config
        };
        let source = IpAddr::from([10, 254, 0, 3]);
        let both = ingress(&[8080, 9090]);
        let before = config(&[8080, 9090]);
        let pair = BTreeSet::from([selected.http, selected.https]);

        // Unchanged routes and grants retire nothing.
        let (ports, _) = retired_proxy_flows(Some((&before, &both)), &before, &both);
        assert!(ports.is_empty());
        // The peer keeps route 8080 but its grant for route 9090 is revoked.
        let (ports, sources) = retired_proxy_flows(Some((&before, &both)), &config(&[8080]), &both);
        assert_eq!((ports, sources.contains(&source)), (pair.clone(), true));
        // Route 9090 is unpublished while the grant stays.
        let (ports, sources) =
            retired_proxy_flows(Some((&before, &both)), &before, &ingress(&[8080]));
        assert_eq!((ports, sources.contains(&source)), (pair.clone(), true));
        // A gained route is not a loss.
        let (ports, _) = retired_proxy_flows(Some((&config(&[8080]), &both)), &before, &both);
        assert!(ports.is_empty());
        // A new listener pair retires every flow to the old one.
        let (ports, sources) = retired_proxy_flows(
            Some((&before, &both)),
            &before,
            &MeshProxyIngress::default(),
        );
        assert_eq!((ports, sources.is_empty()), (pair, true));
    }
}
