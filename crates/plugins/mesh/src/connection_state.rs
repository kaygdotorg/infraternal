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
use crate::{
    dataplane::{Config, PeerPolicy},
    netlink::{self, ConnectionTuple, Socket},
    policy::rules::{Port, Protocol, TrafficPolicy},
};
use infraternal_mesh::proxy_ports::MeshProxyIngress;
use nix::sys::socket::SockProtocol;
use std::{collections::BTreeMap, io, net::IpAddr};

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
/// Remove only entries with an owned local mesh endpoint and a retired initiating service.
/// # Errors
/// Reports interrupted dumps, ambiguous kernel selectors or deletion errors;
/// already-expired entries are idempotent. Current rules refuse traffic before this runs.
pub fn retire(old: Option<&Config>, next: &Config, ingress: &MeshProxyIngress) -> io::Result<()> {
    if old.is_some_and(|old| unchanged_reach(old, next)) {
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
        if current_local
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
}
