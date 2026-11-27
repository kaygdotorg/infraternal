//! Exercises D164 policy shapes and tuple behavior using real packet bytes.
//!
//! The unit tests of [`super`], the mesh packet filter. They live in their own file to keep
//! `packet_filter.rs` under the repository's per-file size limit (J721, #265).

#![allow(clippy::expect_used)]

use super::{
    Direction, FLOW_SLOTS_PER_PEER, FLOW_SLOTS_PER_PEER_HASH, FLOWS_PER_DIRECTION,
    FRAGMENT_IDLE_TIMEOUT, FRAGMENTS_PER_PEER, FlowSlot, FragmentCoverage, FragmentSlot,
    PER_PEER_MEMORY_BUDGET, PacketFilter, PeerAccess, PeerFlows, TCP_CLOSED_TIMEOUT,
    TCP_ESTABLISHED_EVICTABLE_IDLE, TCP_ESTABLISHED_TIMEOUT, UDP, UDP_IDLE_TIMEOUT,
};
use crate::{
    dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
    policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::{Port, Protocol, TrafficPolicy},
    },
};
use infraternal_mesh::{
    mesh_ssh,
    proxy_ports::{ListenerPortPair, MeshProxyIngress},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

/// Local IPv4 mesh address used by the rule contract fixtures.
const LOCAL4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 1);
/// Peer IPv4 mesh address used by the rule contract fixtures.
const PEER4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 2);
/// Second known peer used to prove one source cannot consume another's flow budget.
const OTHER_PEER4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 3);
/// Unknown IPv4 source used to prove spoofed packets are refused.
const UNKNOWN4: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 99);
/// Local IPv6 mesh address used by the rule contract fixtures.
const LOCAL6: Ipv6Addr = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 1);
/// Peer IPv6 mesh address used by the rule contract fixtures.
const PEER6: Ipv6Addr = Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 2);
/// TCP SYN flag used to start a test flow.
const SYN: u8 = 0x02;
/// TCP SYN plus ACK flags used for a test reply.
const SYN_ACK: u8 = 0x12;
/// TCP ACK flag used to prove midstream packets cannot start a flow.
const ACK: u8 = 0x10;

/// Build one local mesh and one peer with the supplied directional access rules.
fn config(inbound: TrafficPolicy, outbound: TrafficPolicy) -> Config {
    Config {
        local_key: None,
        server: None,
        authority_epoch: None,
        rotation_operation: None,
        node: NodeId(1),
        #[cfg(feature = "mesh-dns")]
        name: None,
        #[cfg(feature = "mesh-dns")]
        dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: LOCAL4,
            ipv6: LOCAL6,
        },
        default_policy: DefaultPolicy::Deny,
        exposure: None,
        peers: BTreeMap::from([(
            NodeId(2),
            PeerPolicy {
                peer: Peer {
                    key: PublicKey([2; 32]),
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: PEER4,
                        ipv6: PEER6,
                    },
                    endpoint: None,
                    candidates: Vec::new(),
                    ipv4_only: false,
                    side_port: false,
                },
                inbound,
                outbound,
                access_ssh: None,
                networks: crate::dataplane::PeerNetworks::default(),
            },
        )]),
        #[cfg(feature = "mesh-dns")]
        peer_names: BTreeMap::new(),
    }
}

/// Build a one-port grant for one transport protocol.
fn grant(protocol: Protocol, number: u16) -> TrafficPolicy {
    TrafficPolicy::Ports(BTreeSet::from([Port { protocol, number }]))
}

/// Find peer ids that collided in the old shared-shard layout, so the test keeps covering that regression.
fn legacy_shard(peer: NodeId) -> usize {
    let mut hasher = DefaultHasher::new();
    peer.0.hash(&mut hasher);
    usize::try_from(hasher.finish() & 63).expect("legacy shard index")
}

/// Build a minimal IPv4 TCP packet with a valid TCP checksum.
fn tcp4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = flags;
    let checksum = tcp_checksum4(&packet);
    packet[36..38].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Build a minimal IPv6 TCP packet with a valid TCP checksum.
fn tcp6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    flags: u8,
) -> Vec<u8> {
    let mut packet = vec![0; 60];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&20_u16.to_be_bytes());
    packet[6] = 6;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    packet[52] = 0x50;
    packet[53] = flags;
    let checksum = tcp_checksum6(&packet);
    packet[56..58].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Build a minimal IPv4 UDP packet.
fn udp4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut packet = vec![0; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    packet
}

/// Build an IPv4 UDP datagram long enough to split into two valid IP fragments.
fn udp4_payload(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut packet = udp4(source, destination, source_port, destination_port);
    packet.extend_from_slice(&[0xa5; 16]);
    let total_len = u16::try_from(packet.len()).expect("test packet fits IPv4 length");
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[24..26].copy_from_slice(&24_u16.to_be_bytes());
    packet
}

/// Copy one portion of an IPv4 datagram into a valid fragment for filter tests.
fn ipv4_fragment(
    packet: &[u8],
    identification: u16,
    offset_bytes: usize,
    payload_bytes: usize,
    more_fragments: bool,
) -> Vec<u8> {
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let payload_start = header_len + offset_bytes;
    let payload_end = payload_start + payload_bytes;
    let mut fragment = Vec::with_capacity(header_len + payload_bytes);
    fragment.extend_from_slice(&packet[..header_len]);
    fragment.extend_from_slice(&packet[payload_start..payload_end]);
    let total_len = u16::try_from(fragment.len()).expect("test fragment fits IPv4 length");
    fragment[2..4].copy_from_slice(&total_len.to_be_bytes());
    fragment[4..6].copy_from_slice(&identification.to_be_bytes());
    let offset = u16::try_from(offset_bytes / 8).expect("test offset fits IPv4 field");
    let flags = offset | if more_fragments { 0x2000 } else { 0 };
    fragment[6..8].copy_from_slice(&flags.to_be_bytes());
    fragment
}

/// Build an IPv6 UDP datagram long enough to split into two valid fragments.
fn udp6_payload(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let mut packet = vec![0; 64];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&24_u16.to_be_bytes());
    packet[6] = UDP;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..42].copy_from_slice(&source_port.to_be_bytes());
    packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
    packet[44..46].copy_from_slice(&24_u16.to_be_bytes());
    packet
}

/// Copy one portion of an IPv6 datagram into a valid Fragment-header packet.
fn ipv6_fragment(
    packet: &[u8],
    identification: u32,
    offset_bytes: usize,
    payload_bytes: usize,
    more_fragments: bool,
) -> Vec<u8> {
    let payload_len = u16::try_from(8 + payload_bytes).expect("test fragment payload fits");
    let mut fragment = vec![0; 48 + payload_bytes];
    fragment[..40].copy_from_slice(&packet[..40]);
    fragment[4..6].copy_from_slice(&payload_len.to_be_bytes());
    fragment[6] = 44;
    fragment[40] = packet[6];
    let offset = u16::try_from(offset_bytes / 8).expect("test offset fits IPv6 field");
    let more = u16::from(more_fragments);
    let offset_and_flags = (offset << 3) | more;
    fragment[42..44].copy_from_slice(&offset_and_flags.to_be_bytes());
    fragment[44..48].copy_from_slice(&identification.to_be_bytes());
    let payload_start = 40 + offset_bytes;
    let payload_end = payload_start + payload_bytes;
    fragment[48..].copy_from_slice(&packet[payload_start..payload_end]);
    fragment
}

/// Calculate the checksum of an IPv4 TCP packet, including its pseudo-header.
fn tcp_checksum4(packet: &[u8]) -> u16 {
    let mut pseudo = [0_u8; 12];
    pseudo[..4].copy_from_slice(&packet[12..16]);
    pseudo[4..8].copy_from_slice(&packet[16..20]);
    pseudo[9] = 6;
    let transport_len = u16::try_from(packet.len() - 20).expect("test TCP segment fits");
    pseudo[10..12].copy_from_slice(&transport_len.to_be_bytes());
    checksum(&[&pseudo, &packet[20..]])
}

/// Calculate the checksum of an IPv6 TCP packet, including its pseudo-header.
fn tcp_checksum6(packet: &[u8]) -> u16 {
    let mut pseudo = [0_u8; 40];
    pseudo[..32].copy_from_slice(&packet[8..40]);
    pseudo[32..36].copy_from_slice(&20_u32.to_be_bytes());
    pseudo[39] = 6;
    checksum(&[&pseudo, &packet[40..]])
}

/// Calculate the Internet checksum over several adjacent slices.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    for part in parts {
        for pair in part.chunks(2) {
            sum += u32::from(u16::from_be_bytes([
                pair[0],
                pair.get(1).copied().unwrap_or(0),
            ]));
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("folded checksum fits")
}

/// A packet policy change applies to the next packet and cannot keep a revoked flow open.
#[test]
fn none_denies_new_flows_in_both_directions() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut outgoing = tcp4(LOCAL4, PEER4, 40000, 443, SYN);
    let mut incoming = tcp4(PEER4, LOCAL4, 40001, 443, SYN);
    assert!(!filter.check_at(&mut outgoing, Direction::HostToMesh, now));
    assert!(!filter.check_at(&mut incoming, Direction::MeshToHost, now));
}

/// An all-ports grant admits new TCP SYN and UDP flows, but never a midstream TCP packet.
#[test]
fn all_grants_allow_new_tcp_and_udp_but_not_midstream_tcp() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::All, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut syn = tcp4(LOCAL4, PEER4, 40000, 443, SYN);
    let mut udp = udp4(LOCAL4, PEER4, 40001, 53);
    let mut ack = tcp4(LOCAL4, PEER4, 40002, 443, ACK);
    assert!(filter.check_at(&mut syn, Direction::HostToMesh, now));
    assert!(filter.check_at(&mut udp, Direction::HostToMesh, now));
    assert!(!filter.check_at(&mut ack, Direction::HostToMesh, now));
}

/// A busy peer reaches its per-caller flow bound without exhausting another peer's budget.
#[test]
fn flow_state_is_bounded_per_peer() {
    const PER_PEER_LIMIT: usize = FLOWS_PER_DIRECTION;
    let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
    policy.peers.insert(
        NodeId(3),
        PeerPolicy {
            peer: Peer {
                key: PublicKey([3; 32]),
                previous_key: None,
                previous_active: false,
                addresses: Addresses {
                    ipv4: OTHER_PEER4,
                    ipv6: "fd01::3".parse().expect("other IPv6 peer"),
                },
                endpoint: None,
                candidates: Vec::new(),
                ipv4_only: false,
                side_port: false,
            },
            inbound: TrafficPolicy::All,
            outbound: TrafficPolicy::All,
            access_ssh: None,
            networks: crate::dataplane::PeerNetworks::default(),
        },
    );
    let filter =
        PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile two-peer policy");
    let now = Instant::now();
    for index in 0..PER_PEER_LIMIT {
        assert!(
            establish4(
                &filter,
                PEER4,
                20_000 + u16::try_from(index).expect("flow index"),
                now
            ),
            "peer flow {index}"
        );
    }
    let mut over_limit = tcp4(
        LOCAL4,
        PEER4,
        20_000 + u16::try_from(PER_PEER_LIMIT).expect("limit"),
        443,
        SYN,
    );
    assert!(!filter.check_at(&mut over_limit, Direction::HostToMesh, now));

    let mut other_peer = tcp4(LOCAL4, OTHER_PEER4, 40_000, 443, SYN);
    assert!(filter.check_at(&mut other_peer, Direction::HostToMesh, now));
}

/// Four peers filling a former shared shard cannot consume a fifth peer's independent quota.
#[test]
fn colliding_peers_keep_independent_flow_quotas() {
    const PER_PEER_LIMIT: usize = FLOWS_PER_DIRECTION;
    let target_shard = legacy_shard(NodeId(2));
    let colliders: Vec<_> = (3_u64..=100_000)
        .filter(|id| legacy_shard(NodeId(*id)) == target_shard)
        .take(4)
        .map(NodeId)
        .collect();
    assert_eq!(colliders.len(), 4);

    let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
    let mut addresses = vec![(NodeId(2), PEER4)];
    for (index, node) in colliders.iter().enumerate() {
        let last = u8::try_from(index + 20).expect("fixture address");
        let address = Ipv4Addr::new(10, 254, 0, last);
        policy.peers.insert(
            *node,
            PeerPolicy {
                peer: Peer {
                    key: PublicKey([last; 32]),
                    previous_key: None,
                    previous_active: false,
                    addresses: Addresses {
                        ipv4: address,
                        ipv6: Ipv6Addr::from(0xfd01_u128 << 112 | u128::from(last)),
                    },
                    endpoint: None,
                    candidates: Vec::new(),
                    ipv4_only: false,
                    side_port: false,
                },
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
                access_ssh: None,
                networks: crate::dataplane::PeerNetworks::default(),
            },
        );
        addresses.push((*node, address));
    }
    let filter = PacketFilter::new(&policy, MeshProxyIngress::default())
        .expect("compile colliding peer policies");
    let now = Instant::now();
    for (node, address) in addresses.iter().take(4) {
        for index in 0..PER_PEER_LIMIT {
            assert!(
                establish4(
                    &filter,
                    *address,
                    20_000 + u16::try_from(index).expect("flow index"),
                    now
                ),
                "peer {} flow {index}",
                node.0
            );
        }
    }

    let (fifth, address) = addresses.last().expect("fifth peer");
    let mut packet = tcp4(LOCAL4, *address, 50_000, 443, SYN);
    assert!(
        filter.check_at(&mut packet, Direction::HostToMesh, now),
        "peer {} must retain its own quota after older shard occupants fill theirs",
        fifth.0
    );
}

/// One peer cannot double its conntrack allowance by alternating IPv4 and IPv6.
#[test]
fn flow_state_limit_is_shared_across_address_families() {
    const PER_PEER_LIMIT: usize = FLOWS_PER_DIRECTION;
    let filter = PacketFilter::new(
        &config(TrafficPolicy::All, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    for index in 0..PER_PEER_LIMIT {
        assert!(establish4(
            &filter,
            PEER4,
            20_000 + u16::try_from(index).expect("flow index"),
            now
        ));
    }
    let mut ipv6 = tcp6(LOCAL6, PEER6, 40_000, 443, SYN);
    assert!(
        !filter.check_at(&mut ipv6, Direction::HostToMesh, now),
        "IPv4 and IPv6 addresses for one peer share the same flow quota"
    );
}

/// A policy replacement immediately releases tuple quota for flows it revokes.
#[test]
fn policy_replacement_reclaims_revoked_flow_quota() {
    const PER_PEER_LIMIT: usize = FLOWS_PER_DIRECTION;
    let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
    let filter =
        PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile initial policy");
    let now = Instant::now();
    for index in 0..PER_PEER_LIMIT {
        assert!(establish4(
            &filter,
            PEER4,
            20_000 + u16::try_from(index).expect("flow index"),
            now
        ));
    }

    policy.peers.get_mut(&NodeId(2)).expect("peer").outbound = TrafficPolicy::None;
    filter.publish_policy(
        PacketFilter::prepare_policy(&policy, MeshProxyIngress::default())
            .expect("prepare revocation"),
    );
    policy.peers.get_mut(&NodeId(2)).expect("peer").outbound = grant(Protocol::Tcp, 8443);
    filter.publish_policy(
        PacketFilter::prepare_policy(&policy, MeshProxyIngress::default())
            .expect("prepare replacement grant"),
    );

    let mut replacement = tcp4(LOCAL4, PEER4, 40_000, 8443, SYN);
    assert!(filter.check_at(
        &mut replacement,
        Direction::HostToMesh,
        now + Duration::from_secs(1)
    ));
}

/// A port grant matches both the protocol and destination port, not just the number.
#[test]
fn port_grants_are_narrowed_by_transport_and_port() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut https = tcp4(LOCAL4, PEER4, 40000, 443, SYN);
    let mut ssh = tcp4(LOCAL4, PEER4, 40001, 22, SYN);
    let mut udp = udp4(LOCAL4, PEER4, 40002, 443);
    assert!(filter.check_at(&mut https, Direction::HostToMesh, now));
    assert!(!filter.check_at(&mut ssh, Direction::HostToMesh, now));
    assert!(!filter.check_at(&mut udp, Direction::HostToMesh, now));
}

/// Inbound and outbound grants remain separate, while a permitted flow keeps its reply.
#[test]
fn inbound_and_outbound_grants_are_directional_and_stateful() {
    let filter = PacketFilter::new(
        &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut request = tcp4(PEER4, LOCAL4, 40000, 443, SYN);
    let mut response = tcp4(LOCAL4, PEER4, 443, 40000, SYN_ACK);
    let mut continuation = tcp4(PEER4, LOCAL4, 40000, 443, ACK);
    let mut unrelated = tcp4(LOCAL4, PEER4, 40001, 443, SYN);
    assert!(filter.check_at(&mut request, Direction::MeshToHost, now));
    assert!(filter.check_at(&mut response, Direction::HostToMesh, now));
    assert!(filter.check_at(&mut continuation, Direction::MeshToHost, now));
    assert!(!filter.check_at(&mut unrelated, Direction::HostToMesh, now));
}

/// A TCP flow starts only with SYN set and ACK, FIN and RST clear.
#[test]
fn tcp_initiation_requires_syn_without_ack() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    for flags in [ACK, SYN_ACK, 0x01, 0x04] {
        let mut packet = tcp4(LOCAL4, PEER4, 40000, 443, flags);
        assert!(
            !filter.check_at(&mut packet, Direction::HostToMesh, now),
            "flags {flags:#04x}"
        );
    }
}

/// Host-origin packets use only the local addresses, and tunnel packets use known peer sources.
#[test]
fn spoofed_mesh_addresses_are_rejected_at_both_tun_edges() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::All, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut spoofed_local = tcp4(UNKNOWN4, PEER4, 40000, 443, SYN);
    let mut unknown_peer = tcp4(UNKNOWN4, LOCAL4, 40001, 443, SYN);
    assert!(!filter.check_at(&mut spoofed_local, Direction::HostToMesh, now));
    assert!(!filter.check_at(&mut unknown_peer, Direction::MeshToHost, now));
}

/// Expired state cannot admit a reply whose reverse-direction grant is absent.
#[test]
fn expired_flows_stop_admitting_replies() {
    let filter = PacketFilter::new(
        &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let started = Instant::now();
    let mut request = tcp4(PEER4, LOCAL4, 40000, 443, SYN);
    let mut reply = tcp4(LOCAL4, PEER4, 443, 40000, SYN_ACK);
    assert!(filter.check_at(&mut request, Direction::MeshToHost, started));
    assert!(!filter.check_at(
        &mut reply,
        Direction::HostToMesh,
        started + super::TCP_OPENING_TIMEOUT + Duration::from_secs(1)
    ));
}

/// Updating one complete snapshot preserves still-allowed flows and closes revoked ones.
#[test]
fn policy_updates_apply_to_existing_flows() {
    let mut initial = config(grant(Protocol::Tcp, 443), TrafficPolicy::None);
    let filter =
        PacketFilter::new(&initial, MeshProxyIngress::default()).expect("compile initial policy");
    let now = Instant::now();
    let mut request = tcp4(PEER4, LOCAL4, 40000, 443, SYN);
    let mut reply = tcp4(LOCAL4, PEER4, 443, 40000, SYN_ACK);
    assert!(filter.check_at(&mut request, Direction::MeshToHost, now));
    filter.publish_policy(
        PacketFilter::prepare_policy(&initial, MeshProxyIngress::default())
            .expect("prepare same policy"),
    );
    assert!(filter.check_at(
        &mut reply,
        Direction::HostToMesh,
        now + Duration::from_secs(1)
    ));
    initial.peers.get_mut(&NodeId(2)).expect("peer").inbound = TrafficPolicy::None;
    filter.publish_policy(
        PacketFilter::prepare_policy(&initial, MeshProxyIngress::default())
            .expect("prepare revocation"),
    );
    let mut revoked = tcp4(PEER4, LOCAL4, 40000, 443, ACK);
    assert!(!filter.check_at(
        &mut revoked,
        Direction::MeshToHost,
        now + Duration::from_secs(2)
    ));
}

/// Reassigning one peer address cannot transfer its already-open flow to another mesh node.
#[test]
fn a_reassigned_peer_address_does_not_inherit_existing_flow_state() {
    let mut initial = config(grant(Protocol::Tcp, 443), TrafficPolicy::None);
    let filter =
        PacketFilter::new(&initial, MeshProxyIngress::default()).expect("compile initial policy");
    let now = Instant::now();
    let mut request = tcp4(PEER4, LOCAL4, 40000, 443, SYN);
    assert!(filter.check_at(&mut request, Direction::MeshToHost, now));

    let previous_shard = legacy_shard(NodeId(2));
    let replacement = (3_u64..=100_000)
        .map(NodeId)
        .find(|node| legacy_shard(*node) == previous_shard)
        .expect("another peer id shares this shard");
    let mut reassigned = initial.peers.remove(&NodeId(2)).expect("old peer");
    reassigned.peer.key = PublicKey([3; 32]);
    initial.peers.insert(replacement, reassigned);
    filter.publish_policy(
        PacketFilter::prepare_policy(&initial, MeshProxyIngress::default())
            .expect("prepare address reassignment"),
    );

    let mut continuation = tcp4(PEER4, LOCAL4, 40000, 443, ACK);
    assert!(!filter.check_at(
        &mut continuation,
        Direction::MeshToHost,
        now + Duration::from_secs(1)
    ));
}

/// IPv6 packets use the same directional and port-narrowing rules as IPv4.
#[test]
fn ipv6_uses_directional_port_policy() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let mut allowed = tcp6(LOCAL6, PEER6, 40000, 443, SYN);
    let mut denied = tcp6(LOCAL6, PEER6, 40001, 22, SYN);
    let now = Instant::now();
    assert!(filter.check_at(&mut allowed, Direction::HostToMesh, now));
    assert!(!filter.check_at(&mut denied, Direction::HostToMesh, now));
}

/// Mesh SSH checks the original TCP/22 grant before translation and restores replies to port 22.
#[test]
fn ssh_redirect_translates_requests_and_replies_inside_the_filter() {
    let mut policy = config(TrafficPolicy::All, TrafficPolicy::None);
    policy.server = Some(NodeId(3));
    let filter = PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
    mesh_ssh::publish_listener(IpAddr::V4(LOCAL4), 1001).expect("publish private listener");
    let now = Instant::now();
    let mut request = tcp4(PEER4, LOCAL4, 40000, 22, SYN);
    assert!(filter.check_at(&mut request, Direction::MeshToHost, now));
    assert_eq!(u16::from_be_bytes([request[22], request[23]]), 1001);
    assert_eq!(tcp_checksum4(&request), 0);
    let mut reply = tcp4(LOCAL4, PEER4, 1001, 40000, SYN_ACK);
    assert!(filter.check_at(
        &mut reply,
        Direction::HostToMesh,
        now + Duration::from_secs(1)
    ));
    assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 22);
    assert_eq!(tcp_checksum4(&reply), 0);
    mesh_ssh::clear_listener(IpAddr::V4(LOCAL4), 1001);
}

/// A fragmented mesh SSH redirect adjusts the TCP checksum for the reassembled segment.
#[test]
fn ssh_redirect_translates_fragmented_tcp_with_a_valid_checksum() {
    let local = Ipv4Addr::new(10, 254, 99, 20);
    let peer = Ipv4Addr::new(10, 254, 99, 21);
    let address = IpAddr::V4(local);
    mesh_ssh::clear_listener(address, 1007);
    mesh_ssh::publish_listener(address, 1007).expect("publish private listener");
    let mut policy = config(TrafficPolicy::All, TrafficPolicy::None);
    policy.server = Some(NodeId(3));
    policy.addresses.ipv4 = local;
    policy
        .peers
        .get_mut(&NodeId(2))
        .expect("fixture peer")
        .peer
        .addresses
        .ipv4 = peer;
    let filter = PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
    let mut datagram = tcp4(peer, local, 40_000, 22, SYN);
    datagram.extend_from_slice(&[0xa5; 16]);
    let total_len = u16::try_from(datagram.len()).expect("test TCP packet fits IPv4 length");
    datagram[2..4].copy_from_slice(&total_len.to_be_bytes());
    datagram[36..38].fill(0);
    let checksum = tcp_checksum4(&datagram);
    datagram[36..38].copy_from_slice(&checksum.to_be_bytes());
    let mut first = ipv4_fragment(&datagram, 0x123b, 0, 24, true);
    let mut later = ipv4_fragment(&datagram, 0x123b, 24, 12, false);

    assert!(filter.check_at(&mut first, Direction::MeshToHost, Instant::now()));
    assert_eq!(u16::from_be_bytes([first[22], first[23]]), 1007);
    assert!(filter.check_at(
        &mut later,
        Direction::MeshToHost,
        Instant::now() + Duration::from_secs(1)
    ));

    let mut reassembled = vec![0; datagram.len()];
    reassembled[..20].copy_from_slice(&first[..20]);
    reassembled[2..4].copy_from_slice(&total_len.to_be_bytes());
    reassembled[6..8].fill(0);
    reassembled[20..44].copy_from_slice(&first[20..44]);
    reassembled[44..].copy_from_slice(&later[20..]);
    assert_eq!(tcp_checksum4(&reassembled), 0);
    mesh_ssh::clear_listener(address, 1007);
}

/// A grant for all ports cannot reach the SSH listener's private redirect port directly.
#[test]
fn ssh_private_redirect_port_is_not_a_grantable_mesh_port() {
    let local = Ipv4Addr::new(10, 254, 99, 5);
    let peer = Ipv4Addr::new(10, 254, 99, 6);
    let address = IpAddr::V4(local);
    mesh_ssh::clear_listener(address, 1005);
    mesh_ssh::publish_listener(address, 1005).expect("publish private listener");
    let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
    policy.addresses.ipv4 = local;
    policy
        .peers
        .get_mut(&NodeId(2))
        .expect("fixture peer")
        .peer
        .addresses
        .ipv4 = peer;
    let filter = PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
    let mut direct = tcp4(peer, local, 40_005, 1005, SYN);

    assert!(!filter.check_at(&mut direct, Direction::MeshToHost, Instant::now()));
    mesh_ssh::clear_listener(address, 1005);
}

/// An IPv6 peer with an `All` grant cannot use the SSH redirect port as an independent port.
#[test]
fn ipv6_ssh_private_redirect_port_is_not_a_grantable_mesh_port() {
    let local: Ipv6Addr = "fd01::5".parse().expect("local IPv6 address");
    let peer: Ipv6Addr = "fd01::6".parse().expect("peer IPv6 address");
    let address = IpAddr::V6(local);
    mesh_ssh::clear_listener(address, 1006);
    mesh_ssh::publish_listener(address, 1006).expect("publish private listener");
    let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
    policy.addresses.ipv6 = local;
    policy
        .peers
        .get_mut(&NodeId(2))
        .expect("fixture peer")
        .peer
        .addresses
        .ipv6 = peer;
    let filter = PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
    let mut direct = tcp6(peer, local, 40_006, 1006, SYN);

    assert!(!filter.check_at(&mut direct, Direction::MeshToHost, Instant::now()));
    mesh_ssh::clear_listener(address, 1006);
}

/// A TCP/22 grant cannot fall through to the host SSH daemon without a mesh listener.
#[test]
fn ssh_access_is_refused_without_a_published_local_listener() {
    let local = Ipv4Addr::new(10, 254, 99, 1);
    let peer = Ipv4Addr::new(10, 254, 99, 2);
    let address = IpAddr::V4(local);
    mesh_ssh::clear_listener(address, 1001);
    let mut policy = config(TrafficPolicy::All, TrafficPolicy::None);
    policy.server = Some(NodeId(3));
    policy.addresses.ipv4 = local;
    policy
        .peers
        .get_mut(&NodeId(2))
        .expect("fixture peer")
        .peer
        .addresses
        .ipv4 = peer;
    let filter = PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
    let mut request = tcp4(peer, local, 40_000, 22, SYN);

    assert!(!filter.check_at(&mut request, Direction::MeshToHost, Instant::now()));
}

/// Closing a mesh SSH listener retires its existing TCP/22 flow immediately.
#[test]
fn stopping_ssh_listener_revokes_open_filter_flows() {
    let local = Ipv4Addr::new(10, 254, 99, 3);
    let peer = Ipv4Addr::new(10, 254, 99, 4);
    let address = IpAddr::V4(local);
    mesh_ssh::clear_listener(address, 1003);
    mesh_ssh::publish_listener(address, 1003).expect("publish private listener");
    let mut policy = config(TrafficPolicy::All, TrafficPolicy::None);
    policy.server = Some(NodeId(3));
    policy.addresses.ipv4 = local;
    policy
        .peers
        .get_mut(&NodeId(2))
        .expect("fixture peer")
        .peer
        .addresses
        .ipv4 = peer;
    let filter = PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
    let now = Instant::now();
    let mut request = tcp4(peer, local, 40_000, 22, SYN);
    assert!(filter.check_at(&mut request, Direction::MeshToHost, now));
    mesh_ssh::clear_listener(address, 1003);
    let mut continuation = tcp4(peer, local, 40_000, 22, ACK);

    assert!(!filter.check_at(
        &mut continuation,
        Direction::MeshToHost,
        now + Duration::from_secs(1)
    ));
}

/// The selected proxy pair is admitted only to peers with an inbound backend-port grant.
#[test]
fn proxy_listener_exception_uses_the_peer_backend_grant() {
    let ingress = MeshProxyIngress {
        listener_pair: Some(ListenerPortPair {
            http: 10080,
            https: 10443,
        }),
        backend_ports: BTreeSet::from([8080]),
        ..MeshProxyIngress::default()
    };
    let filter = PacketFilter::new(
        &config(grant(Protocol::Tcp, 8080), TrafficPolicy::None),
        ingress,
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut proxy = tcp4(PEER4, LOCAL4, 40000, 10080, SYN);
    let mut unselected = tcp4(PEER4, LOCAL4, 40001, 10081, SYN);
    assert!(filter.check_at(&mut proxy, Direction::MeshToHost, now));
    assert!(!filter.check_at(&mut unselected, Direction::MeshToHost, now));
}

/// A narrow UDP grant admits later IPv4 fragments only after its first fragment passes.
#[test]
fn ipv4_fragments_follow_only_an_admitted_first_fragment() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let datagram = udp4_payload(LOCAL4, PEER4, 40_000, 53);
    let mut later = ipv4_fragment(&datagram, 0x1234, 16, 8, false);
    let mut first = ipv4_fragment(&datagram, 0x1234, 0, 16, true);

    assert!(!filter.check_at(&mut later, Direction::HostToMesh, now));
    assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
    assert!(filter.check_at(
        &mut later,
        Direction::HostToMesh,
        now + Duration::from_secs(1)
    ));

    let denied = udp4_payload(LOCAL4, PEER4, 40_001, 5353);
    let mut denied_first = ipv4_fragment(&denied, 0x1235, 0, 16, true);
    let mut denied_later = ipv4_fragment(&denied, 0x1235, 16, 8, false);
    assert!(!filter.check_at(&mut denied_first, Direction::HostToMesh, now));
    assert!(!filter.check_at(&mut denied_later, Direction::HostToMesh, now));
}

/// Completed fragmented datagrams release slots while an out-of-order tail still passes.
#[test]
fn completed_ipv4_datagrams_release_fragment_slots() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::All, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();

    for index in 0..=FRAGMENTS_PER_PEER {
        let number = u16::try_from(index).expect("fragment test index fits");
        let source_port = 40_000 + number;
        let datagram = udp4_payload(LOCAL4, PEER4, source_port, 53);
        let mut first = ipv4_fragment(&datagram, 0x4000 + number, 0, 8, true);
        let mut last = ipv4_fragment(&datagram, 0x4000 + number, 16, 8, false);
        let mut middle = ipv4_fragment(&datagram, 0x4000 + number, 8, 8, true);

        assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut last, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut middle, Direction::HostToMesh, now));
    }
}

/// Completed IPv6 datagrams release slots while an out-of-order tail still passes.
#[test]
fn completed_ipv6_datagrams_release_fragment_slots() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::All, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();

    for index in 0..=FRAGMENTS_PER_PEER {
        let number = u32::try_from(index).expect("fragment test index fits");
        let source_port = 40_000 + u16::try_from(number).expect("port index fits");
        let datagram = udp6_payload(LOCAL6, PEER6, source_port, 53);
        let mut first = ipv6_fragment(&datagram, 0x4000 + number, 0, 8, true);
        let mut last = ipv6_fragment(&datagram, 0x4000 + number, 16, 8, false);
        let mut middle = ipv6_fragment(&datagram, 0x4000 + number, 8, 8, true);

        assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut last, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut middle, Direction::HostToMesh, now));
    }
}

/// A TCP first fragment must carry the whole TCP header. One cut after its ports hides the
/// flags in a later fragment the filter never parses, so it is refused, and its later
/// fragment finds no association to follow (J672 P2, #265). This also covers a mesh SSH
/// redirect, whose checksum then always sits in the first fragment.
#[test]
fn a_tcp_first_fragment_without_the_whole_header_is_refused() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let datagram = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
    let mut first = ipv4_fragment(&datagram, 0x1239, 0, 16, true);
    let mut later = ipv4_fragment(&datagram, 0x1239, 16, 4, false);

    assert!(!filter.check_at(&mut first, Direction::HostToMesh, now));
    assert!(!filter.check_at(
        &mut later,
        Direction::HostToMesh,
        now + Duration::from_secs(1)
    ));
}

/// A full fragment table refuses a new datagram without leaving a conntrack flow behind.
#[test]
fn fragment_capacity_refusal_does_not_open_a_flow() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    for index in 0..FRAGMENTS_PER_PEER {
        let source_port = 40_000 + u16::try_from(index).expect("port index fits");
        let datagram = udp4_payload(LOCAL4, PEER4, source_port, 53);
        let mut first = ipv4_fragment(
            &datagram,
            0x2000 + u16::try_from(index).expect("fragment id fits"),
            0,
            16,
            true,
        );
        assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
    }

    let refused_port = 40_000 + u16::try_from(FRAGMENTS_PER_PEER).expect("port index fits");
    let refused = udp4_payload(LOCAL4, PEER4, refused_port, 53);
    let mut refused_first = ipv4_fragment(&refused, 0x3000, 0, 16, true);
    assert!(!filter.check_at(&mut refused_first, Direction::HostToMesh, now));

    let mut unsolicited_reply = udp4(PEER4, LOCAL4, 53, refused_port);
    assert!(!filter.check_at(
        &mut unsolicited_reply,
        Direction::MeshToHost,
        now + Duration::from_secs(1)
    ));
}

/// A narrow UDP grant admits later IPv6 fragments only after its first fragment passes.
#[test]
fn ipv6_fragments_follow_only_an_admitted_first_fragment() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let datagram = udp6_payload(LOCAL6, PEER6, 40_000, 53);
    let mut later = ipv6_fragment(&datagram, 0x1234_5678, 16, 8, false);
    let mut first = ipv6_fragment(&datagram, 0x1234_5678, 0, 16, true);

    assert!(!filter.check_at(&mut later, Direction::HostToMesh, now));
    assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
    assert!(filter.check_at(
        &mut later,
        Direction::HostToMesh,
        now + Duration::from_secs(1)
    ));
}

/// Fragment state expires with the flow and cannot survive a policy that revokes its grant.
#[test]
fn fragment_state_expires_and_policy_publication_revokes_it() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let datagram = udp4_payload(LOCAL4, PEER4, 40_000, 53);
    let mut first = ipv4_fragment(&datagram, 0x1236, 0, 16, true);
    let mut later = ipv4_fragment(&datagram, 0x1236, 16, 8, false);
    assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
    assert!(!filter.check_at(
        &mut later,
        Direction::HostToMesh,
        now + FRAGMENT_IDLE_TIMEOUT + Duration::from_secs(1)
    ));

    let fresh = udp4_payload(LOCAL4, PEER4, 40_001, 53);
    let mut fresh_first = ipv4_fragment(&fresh, 0x1237, 0, 16, true);
    let mut fresh_later = ipv4_fragment(&fresh, 0x1237, 16, 8, false);
    let refreshed = now + UDP_IDLE_TIMEOUT + Duration::from_secs(2);
    assert!(filter.check_at(&mut fresh_first, Direction::HostToMesh, refreshed));
    let revoked = PacketFilter::prepare_policy(
        &config(TrafficPolicy::None, TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("prepare revoked policy");
    filter.publish_policy(revoked);
    assert!(!filter.check_at(
        &mut fresh_later,
        Direction::HostToMesh,
        refreshed + Duration::from_secs(1)
    ));
}

/// A fragmented ICMP error inherits access only from its quoted, still-authorized flow.
#[test]
fn fragmented_icmp_errors_follow_the_quoted_flow() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut request = udp4(LOCAL4, PEER4, 40_000, 53);
    assert!(filter.check_at(&mut request, Direction::HostToMesh, now));

    let mut error = vec![0; 64];
    error[0] = 0x45;
    error[2..4].copy_from_slice(&64_u16.to_be_bytes());
    error[8] = 64;
    error[9] = 1;
    error[12..16].copy_from_slice(&PEER4.octets());
    error[16..20].copy_from_slice(&LOCAL4.octets());
    error[20] = 3;
    error[21] = 3;
    error[28..56].copy_from_slice(&request);
    let mut first = ipv4_fragment(&error, 0x123a, 0, 40, true);
    let mut later = ipv4_fragment(&error, 0x123a, 40, 4, false);

    assert!(filter.check_at(&mut first, Direction::MeshToHost, now));
    assert!(filter.check_at(
        &mut later,
        Direction::MeshToHost,
        now + Duration::from_secs(1)
    ));
}

/// A fragment from an unconfigured source cannot reuse another peer's admitted fragment ID.
#[test]
fn fragment_state_is_scoped_to_the_configured_peer_address() {
    let filter = PacketFilter::new(
        &config(grant(Protocol::Udp, 53), TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let datagram = udp4_payload(PEER4, LOCAL4, 40_000, 53);
    let mut first = ipv4_fragment(&datagram, 0x1238, 0, 16, true);
    assert!(filter.check_at(&mut first, Direction::MeshToHost, now));

    let spoofed = udp4_payload(OTHER_PEER4, LOCAL4, 40_000, 53);
    let mut spoofed_later = ipv4_fragment(&spoofed, 0x1238, 16, 8, false);
    assert!(!filter.check_at(
        &mut spoofed_later,
        Direction::MeshToHost,
        now + Duration::from_secs(1)
    ));
}

/// Malformed packets and non-final fragments with invalid lengths fail closed.
#[test]
fn malformed_and_fragmented_packets_are_rejected() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::All, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut malformed = vec![0; 8];
    let mut fragmented = tcp4(LOCAL4, PEER4, 40000, 443, SYN);
    fragmented[6] = 0x20;
    assert!(!filter.check_at(&mut malformed, Direction::HostToMesh, now));
    assert!(!filter.check_at(&mut fragmented, Direction::HostToMesh, now));
}

/// The parsed test addresses are ordinary values, not packet-path allocations.
#[test]
fn test_addresses_match_the_configured_families() {
    assert_eq!(
        IpAddr::V4(LOCAL4),
        "10.254.0.1".parse::<IpAddr>().expect("IPv4")
    );
    assert_eq!(
        IpAddr::V6(PEER6),
        "fd01::2".parse::<IpAddr>().expect("IPv6")
    );
}

/// TCP FIN plus ACK, used to close a test connection.
const FIN_ACK: u8 = 0x11;
/// J592 review (P1, availability, D384, #265): closing a connection never ends its flow
/// entry. FIN and RST are only inspected when a flow starts, so a closed TCP flow keeps one
/// of the peer's 128 slots for the full 300 s idle timeout, and a full table drops every new
/// flow. A peer granted TCP/443 that opens and cleanly closes 129 short connections within
/// a few seconds (a browser, a health check, a backup job) is cut off for minutes. Kernel
/// conntrack, which the full policy used, ends closed flows and holds far more.
#[test]
fn review_j592_closed_tcp_connections_do_not_exhaust_the_peer_flow_table() {
    let filter = PacketFilter::new(
        &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let start = Instant::now();
    for index in 0..200_u16 {
        // One complete connection every 20 ms: 200 connections in 4 s.
        let now = start + Duration::from_millis(u64::from(index) * 20);
        let port = 40_000 + index;
        let steps = [
            (tcp4(PEER4, LOCAL4, port, 443, SYN), Direction::MeshToHost),
            (
                tcp4(LOCAL4, PEER4, 443, port, SYN_ACK),
                Direction::HostToMesh,
            ),
            (tcp4(PEER4, LOCAL4, port, 443, ACK), Direction::MeshToHost),
            (
                tcp4(PEER4, LOCAL4, port, 443, FIN_ACK),
                Direction::MeshToHost,
            ),
            (
                tcp4(LOCAL4, PEER4, 443, port, FIN_ACK),
                Direction::HostToMesh,
            ),
            (tcp4(PEER4, LOCAL4, port, 443, ACK), Direction::MeshToHost),
        ];
        for (step, (mut packet, direction)) in steps.into_iter().enumerate() {
            assert!(
                filter.check_at(&mut packet, direction, now),
                "connection {index} (step {step}) was dropped: closed connections still \
                 hold the peer's flow slots"
            );
        }
    }
}

/// J592 review (P1, availability, D384, #265): UDP has no close, so each request from a new
/// source port holds a slot for 60 s. 128 slots per peer allow about two new UDP flows per
/// second: a peer resolving names through the mesh DNS service at four queries a second is
/// cut off after about 32 s, and the kernel conntrack it replaced did not do that.
#[test]
fn review_j592_a_peer_can_send_four_dns_queries_a_second_for_a_minute() {
    let filter = PacketFilter::new(
        &config(grant(Protocol::Udp, 53), TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let start = Instant::now();
    let mut dropped = Vec::new();
    for index in 0..240_u16 {
        let now = start + Duration::from_millis(u64::from(index) * 250);
        let port = 30_000 + index;
        let mut query = udp4(PEER4, LOCAL4, port, 53);
        let mut answer = udp4(LOCAL4, PEER4, 53, port);
        if !filter.check_at(&mut query, Direction::MeshToHost, now)
            || !filter.check_at(&mut answer, Direction::HostToMesh, now)
        {
            dropped.push(index);
        }
    }
    assert!(
        dropped.is_empty(),
        "{} of 240 queries dropped, the first at query {:?}",
        dropped.len(),
        dropped.first()
    );
}

/// TCP RST, used to abort a test connection.
const RST: u8 = 0x04;

/// J592 review (P2, security, D384 vs D164, #265): the established path never looks at TCP
/// flags and matches a tuple in either direction. After this host's outbound connection
/// from port 40000 to the peer's 443 is reset, the peer can still send a SYN from 443 to
/// 40000 and it is admitted as "established", although the peer has no inbound grant and
/// kernel conntrack would treat that SYN as a new, refused connection. By refreshing the
/// tuple every 299 s the peer keeps that door open indefinitely.
#[test]
fn review_j592_a_reset_outbound_flow_cannot_be_reopened_by_the_peer() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut open = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
    assert!(filter.check_at(&mut open, Direction::HostToMesh, now));
    let mut accept = tcp4(PEER4, LOCAL4, 443, 40_000, SYN_ACK);
    assert!(filter.check_at(&mut accept, Direction::MeshToHost, now));
    let mut reset = tcp4(LOCAL4, PEER4, 40_000, 443, RST);
    assert!(filter.check_at(&mut reset, Direction::HostToMesh, now));

    let mut reverse_syn = tcp4(PEER4, LOCAL4, 443, 40_000, SYN);
    assert!(
        !filter.check_at(
            &mut reverse_syn,
            Direction::MeshToHost,
            now + Duration::from_secs(299)
        ),
        "a peer with no inbound grant opened a connection to this host's port 40000"
    );
}

/// J592 review (P3, security, D384, #265): IPv6 next-header values 135, 139 and 140 are
/// parsed as extension headers, but Linux delivers them as upper-layer protocols (raw
/// sockets, MIP6). A peer granted only TCP/443 wraps a TCP/443 segment behind next header
/// 139: the filter checks TCP/443 while the kernel hands protocol 139 to whatever listens
/// for it. The filter and the kernel must agree on the protocol; protocols outside a
/// port grant need an `All` grant.
#[test]
fn review_j592_ipv6_upper_layer_protocols_are_not_skipped_as_extension_headers() {
    let filter = PacketFilter::new(
        &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    // An 8-byte header claiming next header TCP, then the unchanged TCP segment.
    let wrap = |next_header: u8, source_port: u16| {
        let plain = tcp6(PEER6, LOCAL6, source_port, 443, SYN);
        let mut wrapped = plain[..40].to_vec();
        wrapped.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]);
        wrapped.extend_from_slice(&plain[40..]);
        wrapped[6] = next_header;
        wrapped[4..6].copy_from_slice(&28_u16.to_be_bytes());
        wrapped
    };
    // Control: a real Destination Options header (60) in front of TCP/443 is admitted, so
    // the refusal below is about the protocol number, not the packet shape.
    let mut options = wrap(60, 40_001);
    assert!(filter.check_at(&mut options, Direction::MeshToHost, Instant::now()));
    let mut wrapped = wrap(139, 40_000);
    assert!(
        !filter.check_at(&mut wrapped, Direction::MeshToHost, Instant::now()),
        "a TCP/443 grant admitted an IPv6 packet whose upper-layer protocol is 139"
    );
}

/// J592 review (P3, D384, #265): only ICMP errors may follow a flow as related traffic.
/// `ICMPv4` redirects (type 5) and source quench (4), and `ICMPv6` types 0 and 5-127 (not
/// errors), are admitted today whenever they quote a live flow.
#[test]
fn review_j592_only_real_icmp_errors_are_related_to_a_flow() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Udp, 53)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut request = udp4(LOCAL4, PEER4, 40_000, 53);
    assert!(filter.check_at(&mut request, Direction::HostToMesh, now));
    for (kind, code) in [(5_u8, 1_u8), (4, 0)] {
        let mut message = vec![0; 56];
        message[0] = 0x45;
        message[2..4].copy_from_slice(&56_u16.to_be_bytes());
        message[8] = 64;
        message[9] = 1;
        message[12..16].copy_from_slice(&PEER4.octets());
        message[16..20].copy_from_slice(&LOCAL4.octets());
        message[20] = kind;
        message[21] = code;
        message[28..56].copy_from_slice(&request);
        assert!(
            !filter.check_at(&mut message, Direction::MeshToHost, now),
            "ICMP type {kind} code {code} was admitted as related to the flow"
        );
    }
}

/// Open an established outbound TCP connection from `port` to `peer`:443 with the whole
/// three-way handshake (SYN out, SYN-ACK back, ACK out); true when all three packets pass.
///
/// Stopping at the SYN-ACK would leave a half-open connection, which the filter rightly
/// treats as still opening (J617 P3, #265).
fn establish4(filter: &PacketFilter, peer: Ipv4Addr, port: u16, now: Instant) -> bool {
    let mut syn = tcp4(LOCAL4, peer, port, 443, SYN);
    let mut syn_ack = tcp4(peer, LOCAL4, 443, port, SYN_ACK);
    let mut ack = tcp4(LOCAL4, peer, port, 443, ACK);
    filter.check_at(&mut syn, Direction::HostToMesh, now)
        && filter.check_at(&mut syn_ack, Direction::MeshToHost, now)
        && filter.check_at(&mut ack, Direction::HostToMesh, now)
}

/// A full table evicts the least recently seen flow that is not an established connection:
/// here the oldest unanswered SYN goes, the next oldest stays, and established connections
/// are never evicted (J592 P1-3, #265).
#[test]
fn a_full_table_evicts_the_oldest_unestablished_flow_and_never_an_established_one() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let start = Instant::now();
    let half = u16::try_from(FLOWS_PER_DIRECTION / 2).expect("half the quota fits a port count");
    for index in 0..half {
        assert!(establish4(&filter, PEER4, 10_000 + index, start));
    }
    for index in 0..half {
        let mut syn = tcp4(LOCAL4, PEER4, 20_000 + index, 443, SYN);
        let at = start + Duration::from_millis(u64::from(index) + 1);
        assert!(filter.check_at(&mut syn, Direction::HostToMesh, at));
    }
    let later = start + Duration::from_secs(1);
    let mut extra = tcp4(LOCAL4, PEER4, 30_000, 443, SYN);
    assert!(
        filter.check_at(&mut extra, Direction::HostToMesh, later),
        "a full table must make room by evicting an unanswered SYN"
    );
    let mut evicted = tcp4(PEER4, LOCAL4, 443, 20_000, SYN_ACK);
    assert!(
        !filter.check_at(&mut evicted, Direction::MeshToHost, later),
        "the oldest unanswered SYN was the one evicted"
    );
    let mut kept = tcp4(PEER4, LOCAL4, 443, 20_001, SYN_ACK);
    assert!(filter.check_at(&mut kept, Direction::MeshToHost, later));
    for index in 0..half {
        let mut data = tcp4(PEER4, LOCAL4, 443, 10_000 + index, ACK);
        assert!(
            filter.check_at(&mut data, Direction::MeshToHost, later),
            "established connection {index} was evicted"
        );
    }
}

/// A closed connection lingers only for its last ACK: after `TCP_CLOSED_TIMEOUT` its tuple
/// is gone, and a half-closed one still carries data the other way.
#[test]
fn closed_tcp_flows_expire_quickly_and_half_closed_ones_keep_flowing() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    assert!(establish4(&filter, PEER4, 40_000, now));
    let mut fin = tcp4(LOCAL4, PEER4, 40_000, 443, FIN_ACK);
    assert!(filter.check_at(&mut fin, Direction::HostToMesh, now));
    let half_closed = now + TCP_CLOSED_TIMEOUT + Duration::from_secs(1);
    let mut data = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
    assert!(
        filter.check_at(&mut data, Direction::MeshToHost, half_closed),
        "a half-closed connection still carries the other direction's data"
    );
    let mut fin_back = tcp4(PEER4, LOCAL4, 443, 40_000, FIN_ACK);
    assert!(filter.check_at(&mut fin_back, Direction::MeshToHost, half_closed));
    let mut last_ack = tcp4(LOCAL4, PEER4, 40_000, 443, ACK);
    assert!(filter.check_at(&mut last_ack, Direction::HostToMesh, half_closed));
    let mut late = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
    assert!(
        !filter.check_at(
            &mut late,
            Direction::MeshToHost,
            half_closed + TCP_CLOSED_TIMEOUT + Duration::from_secs(1)
        ),
        "a closed connection's tuple outlived its close timeout"
    );
}

/// A SYN in the opening direction on a closed tuple starts a new connection, checked
/// against the current grant; on a live connection a reverse SYN is refused.
#[test]
fn a_syn_reopens_a_closed_tuple_only_through_a_fresh_grant_check() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    assert!(establish4(&filter, PEER4, 40_000, now));
    let mut reverse = tcp4(PEER4, LOCAL4, 443, 40_000, SYN);
    assert!(
        !filter.check_at(&mut reverse, Direction::MeshToHost, now),
        "a reverse SYN rode a live outbound connection"
    );
    let mut data = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
    assert!(
        filter.check_at(&mut data, Direction::MeshToHost, now),
        "a refused reverse SYN must not tear down the live connection"
    );
    let mut reset = tcp4(PEER4, LOCAL4, 443, 40_000, RST);
    assert!(filter.check_at(&mut reset, Direction::MeshToHost, now));
    let mut again = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
    assert!(
        filter.check_at(&mut again, Direction::HostToMesh, now),
        "this host may reopen its own granted tuple after a reset"
    );
    let mut accept = tcp4(PEER4, LOCAL4, 443, 40_000, SYN_ACK);
    assert!(filter.check_at(&mut accept, Direction::MeshToHost, now));
}

/// Removing flows turns their slots back into empty ones once no probe chain needs them,
/// so a table that has seen churn still ends a miss at the first empty slot.
#[test]
fn revoked_flows_leave_empty_slots_not_tombstones() {
    let mut policy = config(TrafficPolicy::None, TrafficPolicy::All);
    let filter = PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile policy");
    let now = Instant::now();
    for index in 0..100_u16 {
        assert!(establish4(&filter, PEER4, 20_000 + index, now));
    }
    policy.peers.get_mut(&NodeId(2)).expect("peer").outbound = TrafficPolicy::None;
    filter.publish_policy(
        PacketFilter::prepare_policy(&policy, MeshProxyIngress::default())
            .expect("prepare revocation"),
    );
    assert!(
        filter.with_table(NodeId(2), |table| table.is_none_or(|shard| shard
            .slots
            .iter()
            .all(|slot| matches!(slot, FlowSlot::Empty)))),
        "every slot of a fully revoked table is empty again"
    );
    assert_eq!(
        filter.allocated_tables(),
        0,
        "the sweep after the publish frees a table left empty"
    );
}

/// Memory of one active peer's fixed conntrack and fragment tables, times D393's 1,000-peer
/// design scale and 4,096-peer test scale, the worst case where every peer has flows
/// (PROCESS §1: memory per unit times the expected count). Printed for the issue; the
/// bound keeps a later change from growing it unnoticed. Idle peers allocate none; see
/// `idle_peers_add_under_five_mib_of_rss`.
#[test]
fn flow_table_memory_per_peer_times_one_thousand_peers() {
    let per_peer = std::mem::size_of::<FlowSlot>() * FLOW_SLOTS_PER_PEER
        + (std::mem::size_of::<FragmentSlot>() + std::mem::size_of::<FragmentCoverage>())
            * FRAGMENTS_PER_PEER
        + std::mem::size_of::<PeerFlows>()
        + std::mem::size_of::<PeerAccess>();
    println!(
        "FLOW_TABLE_MEMORY flow_slot={} flow_slots={} per_direction={} fragment_slot={} \
         coverage={} fragments={} per_peer={per_peer} x1000={} x4096={}",
        std::mem::size_of::<FlowSlot>(),
        FLOW_SLOTS_PER_PEER,
        FLOWS_PER_DIRECTION,
        std::mem::size_of::<FragmentSlot>(),
        std::mem::size_of::<FragmentCoverage>(),
        FRAGMENTS_PER_PEER,
        per_peer * 1000,
        per_peer * 4096
    );
    assert_eq!(
        usize::try_from(FLOW_SLOTS_PER_PEER_HASH).ok(),
        Some(FLOW_SLOTS_PER_PEER)
    );
    assert!(
        per_peer <= PER_PEER_MEMORY_BUDGET,
        "{per_peer} bytes per peer exceeds the {PER_PEER_MEMORY_BUDGET}-byte budget"
    );
}

/// Each direction has its own quota: this host holding a full quota of established
/// outbound connections still admits the peer's new inbound connection, and a full
/// direction makes room by evicting its own oldest unestablished flow, never one the other
/// side opened (J617 P2, #265).
#[test]
fn each_direction_keeps_its_own_quota_and_evicts_only_its_own_flows() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::All, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let start = Instant::now();
    let mut inbound_syn = tcp4(PEER4, LOCAL4, 30_000, 443, SYN);
    assert!(filter.check_at(&mut inbound_syn, Direction::MeshToHost, start));
    let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota fits a port count");
    for index in 0..quota {
        let mut syn = tcp4(LOCAL4, PEER4, 20_000 + index, 443, SYN);
        let at = start + Duration::from_millis(u64::from(index) + 1);
        assert!(filter.check_at(&mut syn, Direction::HostToMesh, at));
    }
    let later = start + Duration::from_secs(1);
    let mut extra = tcp4(LOCAL4, PEER4, 21_000, 443, SYN);
    assert!(
        filter.check_at(&mut extra, Direction::HostToMesh, later),
        "a full outbound quota makes room among its own flows"
    );
    let mut evicted = tcp4(PEER4, LOCAL4, 443, 20_000, SYN_ACK);
    assert!(
        !filter.check_at(&mut evicted, Direction::MeshToHost, later),
        "the oldest outbound SYN is the one evicted"
    );
    let mut accept = tcp4(LOCAL4, PEER4, 443, 30_000, SYN_ACK);
    assert!(
        filter.check_at(&mut accept, Direction::HostToMesh, later),
        "the older inbound SYN belongs to the other quota and must survive"
    );

    let held = PacketFilter::new(
        &config(grant(Protocol::Tcp, 8443), TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    for index in 0..quota {
        assert!(establish4(&held, PEER4, 20_000 + index, start));
    }
    let mut inbound = tcp4(PEER4, LOCAL4, 40_000, 8443, SYN);
    assert!(
        held.check_at(&mut inbound, Direction::MeshToHost, later),
        "this host's {quota} held outbound connections locked the peer out of its inbound grant"
    );
}

/// Withdrawn peers lose their address at once: the old owner's open flows and grants stop
/// matching before the engine hands the address to a new node, and the new owner starts
/// with only its own grants when the next policy is published (J592 P2-5).
#[test]
fn a_withdrawn_peer_address_admits_nothing_until_its_new_owner_is_published() {
    let old = config(TrafficPolicy::All, TrafficPolicy::All);
    let filter = PacketFilter::new(&old, MeshProxyIngress::default()).expect("compile policy");
    let now = Instant::now();
    assert!(establish4(&filter, PEER4, 40_000, now));

    filter.withdraw_peers(&BTreeSet::from([NodeId(2)]));
    let mut data = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
    assert!(!filter.check_at(&mut data, Direction::MeshToHost, now));
    let mut syn = tcp4(PEER4, LOCAL4, 40_001, 22, SYN);
    assert!(!filter.check_at(&mut syn, Direction::MeshToHost, now));

    let mut moved = config(TrafficPolicy::None, TrafficPolicy::None);
    let owner = moved.peers.remove(&NodeId(2)).expect("peer");
    moved.peers.insert(NodeId(9), owner);
    filter.publish_policy(
        PacketFilter::prepare_policy(&moved, MeshProxyIngress::default())
            .expect("prepare moved address"),
    );
    let mut data = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
    assert!(
        !filter.check_at(&mut data, Direction::MeshToHost, now),
        "the new owner inherited the old owner's flow"
    );
}

/// Only readable settings above their limit are reported, with the dotted name.
#[test]
fn sysctl_gaps_report_only_values_above_their_limit() {
    let gaps = super::sysctl_gaps(|name| match name {
        "net/ipv4/conf/all/accept_source_route" => Some("1\n".to_owned()),
        _ => None,
    });
    assert_eq!(
        gaps,
        ["net.ipv4.conf.all.accept_source_route = 1 (want <= 0)"]
    );
    assert_eq!(
        super::sysctl_gaps(|name| Some(if name.contains("ipv6") { "-1" } else { "0" }.to_owned())),
        Vec::<String>::new()
    );
}

/// J617 review (P2, #265, D384): one peer's held inbound connections must not stop this
/// host from opening its own connections to that peer.
///
/// The 128 slots are shared by both directions and established connections are never
/// evicted. Any process on the peer, an unprivileged account or an ordinary connection pool
/// included, that holds 128 connections to a granted port therefore refuses every new
/// connection in both directions for as long as it holds them: this host can no longer
/// reach the peer, and nobody else on the peer can reach this host (mesh SSH included). The
/// kernel conntrack this replaces had no per-peer cap. The fix commit's doc says such a peer
/// "can only stop itself"; this test shows the host is stopped too.
#[test]
fn review_j617_a_peers_inbound_connections_cannot_lock_this_host_out_of_it() {
    let filter = PacketFilter::new(
        &config(grant(Protocol::Tcp, 443), TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let held = u16::try_from(FLOWS_PER_DIRECTION).expect("cap fits a port count");
    for index in 0..held {
        let port = 40_000 + index;
        let mut syn = tcp4(PEER4, LOCAL4, port, 443, SYN);
        let mut syn_ack = tcp4(LOCAL4, PEER4, 443, port, SYN_ACK);
        let mut ack = tcp4(PEER4, LOCAL4, port, 443, ACK);
        assert!(filter.check_at(&mut syn, Direction::MeshToHost, now));
        assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut ack, Direction::MeshToHost, now));
    }
    let mut outbound = tcp4(LOCAL4, PEER4, 50_000, 22, SYN);
    assert!(
        filter.check_at(
            &mut outbound,
            Direction::HostToMesh,
            now + Duration::from_secs(1)
        ),
        "the peer's {held} inbound connections locked this host out of its own outbound grant"
    );
}

/// J617 review (P3, #265, D384): an answered SYN that never gets its final ACK is a
/// half-open connection, not an established one.
///
/// `observe` marks a flow replied on the SYN-ACK, so `established()` is true before the
/// handshake completes: a half-open connection keeps the 300 s established timeout and can
/// never be evicted. Kernel conntrack keeps it in `SYN_RECV` (60 s) and may drop it under
/// pressure. Here 127 complete connections plus one half-open fill the table; a new SYN
/// must evict the half-open one.
#[test]
fn review_j617_a_half_open_connection_is_not_established() {
    let filter = PacketFilter::new(
        &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let complete = u16::try_from(FLOWS_PER_DIRECTION - 1).expect("cap fits a port count");
    for index in 0..complete {
        let port = 40_000 + index;
        let mut syn = tcp4(PEER4, LOCAL4, port, 443, SYN);
        let mut syn_ack = tcp4(LOCAL4, PEER4, 443, port, SYN_ACK);
        let mut ack = tcp4(PEER4, LOCAL4, port, 443, ACK);
        assert!(filter.check_at(&mut syn, Direction::MeshToHost, now));
        assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut ack, Direction::MeshToHost, now));
    }
    let mut half_syn = tcp4(PEER4, LOCAL4, 45_000, 443, SYN);
    let mut half_syn_ack = tcp4(LOCAL4, PEER4, 443, 45_000, SYN_ACK);
    assert!(filter.check_at(&mut half_syn, Direction::MeshToHost, now));
    assert!(filter.check_at(&mut half_syn_ack, Direction::HostToMesh, now));
    let mut fresh = tcp4(PEER4, LOCAL4, 46_000, 443, SYN);
    assert!(
        filter.check_at(
            &mut fresh,
            Direction::MeshToHost,
            now + Duration::from_secs(1)
        ),
        "a half-open connection (SYN, SYN-ACK, no ACK) was treated as established and never evicted"
    );
}

/// J672 P1 (#265): an established connection that stays quiet for six minutes still
/// carries its next packet in both directions. Kernel conntrack, which the `GotaTun` path
/// used before D384, keeps an established TCP entry for 5 days.
#[test]
fn an_idle_established_connection_survives_six_quiet_minutes() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    assert!(establish4(&filter, PEER4, 40_000, now));
    let later = now + Duration::from_secs(360);
    let mut data = tcp4(LOCAL4, PEER4, 40_000, 443, ACK);
    assert!(
        filter.check_at(&mut data, Direction::HostToMesh, later),
        "an established connection idle for 6 minutes was cut: its next ACK was dropped"
    );
    let mut answer = tcp4(PEER4, LOCAL4, 443, 40_000, ACK);
    assert!(filter.check_at(&mut answer, Direction::MeshToHost, later));
}

/// An established connection still ends at conntrack's 5-day limit: after it, a
/// continuation cannot reopen the tuple.
#[test]
fn an_established_connection_expires_after_five_idle_days() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    assert!(establish4(&filter, PEER4, 40_000, now));
    let just_before = now + TCP_ESTABLISHED_TIMEOUT;
    let mut data = tcp4(LOCAL4, PEER4, 40_000, 443, ACK);
    assert!(filter.check_at(&mut data, Direction::HostToMesh, just_before));
    let past = just_before + TCP_ESTABLISHED_TIMEOUT + Duration::from_secs(1);
    let mut stale = tcp4(LOCAL4, PEER4, 40_000, 443, ACK);
    assert!(!filter.check_at(&mut stale, Direction::HostToMesh, past));
}

/// J672 P2 (#265): a peer with no inbound grant cannot get a reverse SYN to this host's
/// port by splitting it after the ports, so the first fragment carries no TCP flags and the
/// SYN bit arrives in a later fragment. Here on a reset tuple (J592's case).
#[test]
fn a_tiny_first_fragment_cannot_hide_a_reverse_syn() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut open = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
    assert!(filter.check_at(&mut open, Direction::HostToMesh, now));
    let mut accept = tcp4(PEER4, LOCAL4, 443, 40_000, SYN_ACK);
    assert!(filter.check_at(&mut accept, Direction::MeshToHost, now));
    let mut reset = tcp4(LOCAL4, PEER4, 40_000, 443, RST);
    assert!(filter.check_at(&mut reset, Direction::HostToMesh, now));
    let later = now + Duration::from_secs(1);
    let whole = tcp4(PEER4, LOCAL4, 443, 40_000, SYN);
    let mut first = ipv4_fragment(&whole, 7, 0, 8, true);
    let mut second = ipv4_fragment(&whole, 7, 8, 12, false);
    let first_ok = filter.check_at(&mut first, Direction::MeshToHost, later);
    let second_ok = filter.check_at(&mut second, Direction::MeshToHost, later);
    assert!(
        !first_ok && !second_ok,
        "a reverse SYN split after its ports reached port 40000 with no inbound grant \
         (first fragment {first_ok}, second {second_ok})"
    );
}

/// J672 P2 (#265): the same split on a live established tuple, where the whole reverse
/// SYN is refused by the bare-SYN rule, is refused too; and the same for IPv6.
#[test]
fn a_tiny_first_fragment_cannot_hide_a_reverse_syn_on_a_live_tuple() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    assert!(establish4(&filter, PEER4, 40_000, now));
    let whole = tcp4(PEER4, LOCAL4, 443, 40_000, SYN);
    let mut control = whole.clone();
    assert!(!filter.check_at(&mut control, Direction::MeshToHost, now));
    let mut first = ipv4_fragment(&whole, 9, 0, 8, true);
    let mut second = ipv4_fragment(&whole, 9, 8, 12, false);
    assert!(!filter.check_at(&mut first, Direction::MeshToHost, now));
    assert!(!filter.check_at(&mut second, Direction::MeshToHost, now));

    let mut open6 = tcp6(LOCAL6, PEER6, 40_000, 443, SYN);
    let mut accept6 = tcp6(PEER6, LOCAL6, 443, 40_000, SYN_ACK);
    let mut ack6 = tcp6(LOCAL6, PEER6, 40_000, 443, ACK);
    assert!(filter.check_at(&mut open6, Direction::HostToMesh, now));
    assert!(filter.check_at(&mut accept6, Direction::MeshToHost, now));
    assert!(filter.check_at(&mut ack6, Direction::HostToMesh, now));
    let whole6 = tcp6(PEER6, LOCAL6, 443, 40_000, SYN);
    let mut first6 = ipv6_fragment(&whole6, 11, 0, 8, true);
    let mut second6 = ipv6_fragment(&whole6, 11, 8, 12, false);
    assert!(!filter.check_at(&mut first6, Direction::MeshToHost, now));
    assert!(!filter.check_at(&mut second6, Direction::MeshToHost, now));
}

/// RFC 1858: a later TCP fragment that starts inside the minimum TCP header could
/// overwrite the flags the filter judged in the first fragment, so it is refused even
/// when its first fragment was admitted.
#[test]
fn a_later_tcp_fragment_cannot_overlap_the_tcp_header() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut datagram = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
    datagram.extend_from_slice(&[0; 16]);
    let total_len = u16::try_from(datagram.len()).expect("test TCP packet fits IPv4 length");
    datagram[2..4].copy_from_slice(&total_len.to_be_bytes());
    let mut first = ipv4_fragment(&datagram, 13, 0, 24, true);
    let mut overlap = ipv4_fragment(&datagram, 13, 8, 8, true);
    let mut rest = ipv4_fragment(&datagram, 13, 24, 12, false);
    assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
    assert!(!filter.check_at(&mut overlap, Direction::HostToMesh, now));
    assert!(filter.check_at(&mut rest, Direction::HostToMesh, now));
}

/// The IPv4 overlap guard covers TCP options, not only the 20-byte minimum header (J750
/// P3 1, #265). The first fragment's TCP header carries 20 bytes of options (data offset
/// 10), so the filter judged bytes up to 40. A later fragment at offset 24 passes the
/// parser's stateless "starts inside 20 bytes" check, yet would rewrite judged options, so
/// `FragmentEntry::judged_end` must refuse it. The fragment at offset 40 still passes.
#[test]
fn an_ipv4_later_fragment_cannot_overlap_tcp_options() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut datagram = tcp4(LOCAL4, PEER4, 40_000, 443, SYN);
    // Data offset 10 words: a 40-byte TCP header, 20 of it options.
    datagram[32] = 0xa0;
    datagram.extend_from_slice(&[0; 40]);
    let total_len = u16::try_from(datagram.len()).expect("test TCP packet fits IPv4 length");
    datagram[2..4].copy_from_slice(&total_len.to_be_bytes());
    let mut first = ipv4_fragment(&datagram, 31, 0, 40, true);
    let mut overlap = ipv4_fragment(&datagram, 31, 24, 16, true);
    let mut rest = ipv4_fragment(&datagram, 31, 40, 20, false);
    assert!(filter.check_at(&mut first, Direction::HostToMesh, now));
    assert!(
        !filter.check_at(&mut overlap, Direction::HostToMesh, now),
        "a later IPv4 fragment at offset 24 overlapped TCP options judged up to 40"
    );
    assert!(filter.check_at(&mut rest, Direction::HostToMesh, now));
}

/// Build an `ICMPv4` message of `kind` (code 0) with identifier `identifier`.
fn icmp4(source: Ipv4Addr, destination: Ipv4Addr, kind: u8, identifier: u16) -> Vec<u8> {
    let mut packet = vec![0_u8; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20] = kind;
    packet[24..26].copy_from_slice(&identifier.to_be_bytes());
    packet
}

/// J672 P3 (#265): an outbound ping with identifier 0 lets back only its echo reply, not
/// the peer's other ICMP types (here a timestamp request) and not the peer's own echo
/// request, which shares the reply's tuple.
#[test]
fn an_outbound_ping_admits_only_its_echo_reply() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut ping = icmp4(LOCAL4, PEER4, 8, 0);
    assert!(filter.check_at(&mut ping, Direction::HostToMesh, now));
    let mut timestamp = icmp4(PEER4, LOCAL4, 13, 0);
    assert!(
        !filter.check_at(&mut timestamp, Direction::MeshToHost, now),
        "the peer's ICMP timestamp request rode this host's echo flow"
    );
    let mut request = icmp4(PEER4, LOCAL4, 8, 0);
    assert!(
        !filter.check_at(&mut request, Direction::MeshToHost, now),
        "the peer's echo request rode this host's echo flow"
    );
    let mut reply = icmp4(PEER4, LOCAL4, 0, 0);
    assert!(filter.check_at(&mut reply, Direction::MeshToHost, now));
    let mut other_id = icmp4(PEER4, LOCAL4, 0, 7);
    assert!(!filter.check_at(&mut other_id, Direction::MeshToHost, now));
}

/// ICMP that is neither an echo nor an error passes only under an `All` grant in its own
/// direction and leaves no state behind for the other direction.
#[test]
fn other_icmp_is_judged_alone_and_leaves_no_state() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut outbound = icmp4(LOCAL4, PEER4, 13, 0);
    assert!(filter.check_at(&mut outbound, Direction::HostToMesh, now));
    let mut back = icmp4(PEER4, LOCAL4, 14, 0);
    assert!(!filter.check_at(&mut back, Direction::MeshToHost, now));
    assert!(
        filter.with_table(NodeId(2), |table| table.is_none_or(|shard| shard
            .slots
            .iter()
            .all(|slot| !matches!(slot, FlowSlot::Occupied(_))))),
        "a stateless ICMP message created a flow"
    );
}

/// J672 owner question (a), green: a peer holding a full direction of established inbound
/// connections does not stop this host opening its own full quota of outbound ones.
#[test]
fn held_inbound_quota_does_not_block_outbound() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::All, TrafficPolicy::All),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota fits a port count");
    for port in 0..quota {
        let mut syn = tcp4(PEER4, LOCAL4, 20_000 + port, 22_000, SYN);
        let mut syn_ack = tcp4(LOCAL4, PEER4, 22_000, 20_000 + port, SYN_ACK);
        let mut ack = tcp4(PEER4, LOCAL4, 20_000 + port, 22_000, ACK);
        assert!(filter.check_at(&mut syn, Direction::MeshToHost, now));
        assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, now));
        assert!(filter.check_at(&mut ack, Direction::MeshToHost, now));
    }
    let mut extra = tcp4(PEER4, LOCAL4, 30_000, 22_000, SYN);
    assert!(!filter.check_at(&mut extra, Direction::MeshToHost, now));
    for port in 0..quota {
        assert!(establish4(&filter, PEER4, 40_000 + port, now));
    }
}

/// The IPv4 mesh address of synthetic peer `n` (2 ≤ n < 65,536), for scale tests.
fn scale_peer4(n: u32) -> Ipv4Addr {
    let [_, _, high, low] = n.to_be_bytes();
    Ipv4Addr::new(10, 254, high, low)
}

/// One local node with `peers` synthetic peers, every one with `All` grants both ways,
/// shaped like D393's design and test scales (J718's fixture, #265).
fn scale_config(peers: u32) -> Config {
    let mut config = config(TrafficPolicy::All, TrafficPolicy::All);
    let template = config.peers.remove(&NodeId(2)).expect("template peer");
    for n in 2..peers + 2 {
        let mut peer = template.clone();
        let [_, _, high, low] = n.to_be_bytes();
        peer.peer.addresses = Addresses {
            ipv4: scale_peer4(n),
            ipv6: Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 1, u16::from_be_bytes([high, low])),
        };
        config.peers.insert(NodeId(u64::from(n)), peer);
    }
    config
}

/// Only peers with flows get a flow table (J721, #265): compiling, preparing and
/// publishing a 1,000-peer policy allocates none, and the 10 peers that open flows get one
/// each. Their flows survive the publish without being copied.
#[test]
fn idle_peers_allocate_no_flow_tables() {
    let config = scale_config(1000);
    let filter = PacketFilter::new(&config, MeshProxyIngress::default()).expect("compile");
    assert_eq!(
        filter.allocated_tables(),
        0,
        "compiling allocated flow tables"
    );
    let now = Instant::now();
    for n in 2..12 {
        for port in 0..8 {
            assert!(establish4(&filter, scale_peer4(n), 40_000 + port, now));
        }
    }
    assert_eq!(filter.allocated_tables(), 10);
    let prepared =
        PacketFilter::prepare_policy(&config, MeshProxyIngress::default()).expect("prepare");
    assert_eq!(
        filter.allocated_tables(),
        10,
        "preparing allocated flow tables"
    );
    filter.publish_policy(prepared);
    assert_eq!(
        filter.allocated_tables(),
        10,
        "publishing allocated or lost tables"
    );
    for n in 2..12 {
        let mut reply = tcp4(scale_peer4(n), LOCAL4, 443, 40_000, ACK);
        assert!(
            filter.check_at(&mut reply, Direction::MeshToHost, now),
            "peer {n}'s connection did not survive the publish"
        );
    }
}

/// A publish never waits for a peer's flow table (J721, #265): with the tables of every
/// active peer held by a packet worker, it still completes and the new grants apply at
/// once. The lock every packet waits behind is held only to swap a pointer. Before J721 a
/// publish locked and scanned every peer's table under that lock (J718: 7.3 ms at 4,096
/// peers). This checks the structure, not wall-clock time: PROCESS keeps timing in the
/// bench harness.
#[test]
fn publish_never_waits_for_a_peer_table() {
    let mut config = scale_config(64);
    let filter = std::sync::Arc::new(
        PacketFilter::new(&config, MeshProxyIngress::default()).expect("compile"),
    );
    let now = Instant::now();
    for n in 2..6 {
        assert!(establish4(&filter, scale_peer4(n), 40_000, now));
    }
    let cells: Vec<_> = filter
        .tables
        .lock()
        .expect("tables")
        .values()
        .cloned()
        .collect();
    assert_eq!(cells.len(), 4);
    let guards: Vec<_> = cells
        .iter()
        .map(|cell| cell.table.lock().expect("table"))
        .collect();
    config.peers.get_mut(&NodeId(2)).expect("peer").outbound = TrafficPolicy::None;
    let prepared =
        PacketFilter::prepare_policy(&config, MeshProxyIngress::default()).expect("prepare");
    let (done, publish_finished) = std::sync::mpsc::channel();
    let publisher = std::sync::Arc::clone(&filter);
    let thread = std::thread::spawn(move || {
        publisher.publish_policy(prepared);
        done.send(()).expect("report publish");
    });
    let finished = publish_finished.recv_timeout(Duration::from_secs(30));
    drop(guards);
    thread.join().expect("publisher thread");
    assert!(
        finished.is_ok(),
        "publish waited for a peer table held by a packet worker"
    );
    // The sweep skipped the held tables, so the revoked flow's entry is still there, yet
    // its next packet is refused.
    let mut revoked = tcp4(LOCAL4, scale_peer4(2), 40_000, 443, ACK);
    assert!(!filter.check_at(&mut revoked, Direction::HostToMesh, now));
    let mut kept = tcp4(LOCAL4, scale_peer4(3), 40_000, 443, ACK);
    assert!(filter.check_at(&mut kept, Direction::HostToMesh, now));
}

/// A packet never waits for the sweep that follows a publish (J753, #265; J750 P2). After
/// a publish every active peer's next packet binds its flow cell through the `tables` lock.
/// The sweep is paused part-way through, and a packet from an active peer must still pass.
/// Before J753 the sweep held `tables` for its whole scan, and J750 measured that packet
/// waiting 3.6-13 ms (median) at 4,096 active peers. This checks the structure, not
/// wall-clock time: the timeout only turns a wait into a failure instead of a hang.
#[test]
fn a_packet_binds_its_peer_while_the_sweep_is_paused() {
    let config = scale_config(8);
    let filter = std::sync::Arc::new(
        PacketFilter::new(&config, MeshProxyIngress::default()).expect("compile"),
    );
    let now = Instant::now();
    for n in 2..6 {
        assert!(establish4(&filter, scale_peer4(n), 40_000, now));
    }
    let (paused, sweep_paused) = std::sync::mpsc::channel();
    let (resume, resumed) = std::sync::mpsc::channel::<()>();
    let resumed = std::sync::Mutex::new(resumed);
    let first_visit = std::sync::atomic::AtomicBool::new(true);
    *filter.sweep_probe.lock().expect("probe") = Some(Box::new(move || {
        if first_visit.swap(false, std::sync::atomic::Ordering::SeqCst) {
            paused.send(()).expect("report pause");
            // Wait for the test to finish its packet; a broken channel just resumes.
            let _ = resumed.lock().expect("resume").recv();
        }
    }));
    let prepared =
        PacketFilter::prepare_policy(&config, MeshProxyIngress::default()).expect("prepare");
    let publisher = std::sync::Arc::clone(&filter);
    let publish = std::thread::spawn(move || publisher.publish_policy(prepared));
    sweep_paused
        .recv_timeout(Duration::from_secs(30))
        .expect("the sweep never visited a peer");

    let (report_packet, packet_result) = std::sync::mpsc::channel();
    let worker = std::sync::Arc::clone(&filter);
    let packet = std::thread::spawn(move || {
        let mut reply = tcp4(scale_peer4(5), LOCAL4, 443, 40_000, ACK);
        report_packet
            .send(worker.check_at(&mut reply, Direction::MeshToHost, now))
            .expect("report packet");
    });
    let result = packet_result.recv_timeout(Duration::from_secs(30));
    resume.send(()).expect("resume the sweep");
    publish.join().expect("publisher thread");
    packet.join().expect("packet thread");
    assert_eq!(
        result,
        Ok(true),
        "a packet binding its peer waited for the paused sweep"
    );
}

/// Revocation ends flows at publish even when the sweep could not visit the peer's table
/// (J721, #265): no revoked flow admits another packet, and their slots go back to the
/// quota the moment the full direction needs them. The first check comes before any
/// reclaim, so it guards the busy-skip case on its own; the checks after the replacement SYN
/// show the slots really were freed.
#[test]
fn revoked_flows_skipped_by_the_sweep_free_their_quota_on_demand() {
    let mut policy = config(TrafficPolicy::All, TrafficPolicy::All);
    let filter = PacketFilter::new(&policy, MeshProxyIngress::default()).expect("compile");
    let now = Instant::now();
    let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota");
    for port in 0..quota {
        assert!(establish4(&filter, PEER4, 20_000 + port, now));
    }
    policy.peers.get_mut(&NodeId(2)).expect("peer").outbound = grant(Protocol::Tcp, 8443);
    let prepared =
        PacketFilter::prepare_policy(&policy, MeshProxyIngress::default()).expect("prepare");
    let cell = filter
        .tables
        .lock()
        .expect("tables")
        .get(&NodeId(2))
        .cloned()
        .expect("peer cell");
    // Hold the table as a packet worker would, so the sweep skips it. The publish runs on
    // its own thread: a sweep that waited for the table would otherwise deadlock this test
    // instead of failing it (J750 P3 2). The timeout only detects that wait.
    let busy = cell.table.lock().expect("table");
    let published = std::thread::scope(|scope| {
        let (done, publish_finished) = std::sync::mpsc::channel();
        let filter = &filter;
        scope.spawn(move || {
            filter.publish_policy(prepared);
            // After a timeout the receiver is gone; the assert below reports the failure.
            done.send(()).ok();
        });
        let finished = publish_finished.recv_timeout(Duration::from_secs(30));
        drop(busy);
        finished
    });
    assert!(published.is_ok(), "the sweep waited for a busy table");
    assert_eq!(
        filter.with_table(NodeId(2), |table| table.map(|shard| shard.initiated)),
        Some([usize::from(quota), 0]),
        "the sweep waited for a busy table"
    );
    // The sweep skipped this table, so every revoked flow is still in it. A packet of one of
    // them must be refused before anything has reclaimed the slot: only the per-packet grant
    // check stands between the stale entry and the peer (J772 P3 3, #265).
    let mut stale_before = tcp4(LOCAL4, PEER4, 20_000 + quota / 2, 443, ACK);
    assert!(
        !filter.check_at(&mut stale_before, Direction::HostToMesh, now),
        "a revoked flow in a table the sweep skipped admitted a packet"
    );
    // Refusing that packet dropped its flow, which freed one slot. Fill it with a flow the
    // new policy allows, so the direction is full again and the next SYN must reclaim.
    let mut topping_up = tcp4(LOCAL4, PEER4, 39_999, 8443, SYN);
    assert!(filter.check_at(&mut topping_up, Direction::HostToMesh, now));
    let mut replacement = tcp4(LOCAL4, PEER4, 40_000, 8443, SYN);
    assert!(filter.check_at(&mut replacement, Direction::HostToMesh, now));
    assert_eq!(
        filter.with_table(NodeId(2), |table| table.map(|shard| shard.initiated)),
        Some([2, 0]),
        "the full direction did not reclaim its revoked flows"
    );
    for port in [0, quota / 2, quota - 1] {
        let mut stale = tcp4(LOCAL4, PEER4, 20_000 + port, 443, ACK);
        assert!(!filter.check_at(&mut stale, Direction::HostToMesh, now));
    }
}

/// Set in the child process that [`idle_peers_add_under_five_mib_of_rss`] starts, so the
/// measurement runs alone and other tests' allocations do not blur it.
#[cfg(target_os = "linux")]
const RSS_CHILD_ENV: &str = "INFRATERNAL_PACKET_FILTER_RSS_CHILD";

/// Read one `/proc/self/status` field, in KiB.
#[cfg(target_os = "linux")]
fn status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .expect("status")
        .lines()
        .find(|line| line.starts_with(field))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .expect("status field")
}

/// Build a filter for `peers` peers, open 8 connections on each of up to 10 of them, then
/// prepare and publish the same policy 21 times, the way config applies do. Print the RSS
/// added since before the filter existed, the peak (`VmHWM`, reset first) and the median and
/// worst publish time. The config is built before the baseline, so only the filter is
/// counted.
#[cfg(target_os = "linux")]
fn measure_filter_rss(peers: u32) -> (u64, u64) {
    let config = scale_config(peers);
    // "5" resets VmHWM to the current RSS, so the peak below is this run's own.
    std::fs::write("/proc/self/clear_refs", "5").expect("reset peak RSS");
    let baseline = status_kib("VmRSS:");
    let filter = PacketFilter::new(&config, MeshProxyIngress::default()).expect("compile");
    let now = Instant::now();
    for n in 2..peers.min(10) + 2 {
        for port in 0..8 {
            assert!(establish4(&filter, scale_peer4(n), 40_000 + port, now));
        }
    }
    // 21 prepare + publish rounds: the first is the memory figure, all give the timing.
    let mut publish_us = Vec::new();
    for _ in 0..21 {
        let prepared =
            PacketFilter::prepare_policy(&config, MeshProxyIngress::default()).expect("prepare");
        let started = Instant::now();
        filter.publish_policy(prepared);
        publish_us.push(started.elapsed().as_micros());
    }
    let rss = status_kib("VmRSS:").saturating_sub(baseline);
    let peak = status_kib("VmHWM:").saturating_sub(baseline);
    publish_us.sort_unstable();
    println!(
        "FILTER_RSS peers={peers} active={}x8 rss_added_kib={rss} peak_added_kib={peak} \
         publish_us_median={} publish_us_max={} tables={}",
        peers.min(10),
        publish_us[publish_us.len() / 2],
        publish_us[publish_us.len() - 1],
        filter.allocated_tables()
    );
    drop(filter);
    (rss, peak)
}

/// RSS regression guard (J721, #265; J718 measured +66.2 MiB and a 137.5 MiB peak): at
/// D393's 1,000 peers with 10 active, the filter adds under 5 MiB, and a prepare plus
/// publish raises the peak by under 5 MiB too, so memory never doubles. It re-runs itself
/// in a child process, so the numbers are this filter's alone; it also prints the 4,096-peer
/// figures and the publish time for the issue. A one-peer run first pays the fixed cost of
/// faulting in the filter's executable and library pages and starting the allocator. That
/// startup cost is printed separately: it depends on the linked image's layout, not peer
/// state (J841, #531: 4,288 KiB of the failing 5,360 KiB was file-backed). Warming one peer
/// keeps growth at the 1,000-peer design scale, including refresh peaks, under the same bound.
#[cfg(target_os = "linux")]
#[test]
fn idle_peers_add_under_five_mib_of_rss() {
    const LIMIT_KIB: u64 = 5 * 1024;
    if std::env::var_os(RSS_CHILD_ENV).is_some() {
        measure_filter_rss(1);
        let (rss, peak) = measure_filter_rss(1000);
        assert!(
            rss < LIMIT_KIB,
            "1,000 peers with 10 active added {rss} KiB of RSS"
        );
        assert!(
            peak < LIMIT_KIB,
            "a publish at 1,000 peers peaked {peak} KiB above baseline"
        );
        measure_filter_rss(4096);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "packet_filter::tests::idle_peers_add_under_five_mib_of_rss",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(RSS_CHILD_ENV, "1")
        .output()
        .expect("run the measurement child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().filter(|line| line.contains("FILTER_RSS")) {
        println!("{line}");
    }
    assert!(
        output.status.success() && stdout.contains("FILTER_RSS peers=4096"),
        "the RSS measurement failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Connections that ended where the filter could not see it (the peer lost power, or its
/// host timed out without a RST on the wire) do not lock the peer out for the 5-day
/// established timeout (J718 P2, #265; J718's red test). With a full inbound quota of such
/// connections, a new one is still refused for the first hour of silence, because they may
/// be live and idle. After that, it evicts the oldest silent connection, and only that one.
#[test]
fn silent_established_connections_give_way_after_an_hour_only_when_full() {
    let filter = PacketFilter::new(
        &config(grant(Protocol::Tcp, 443), TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let start = Instant::now();
    let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota");
    for index in 0..quota {
        let port = 20_000 + index;
        // Port 20,000 is the oldest; later ones were seen a millisecond apart.
        let at = start + Duration::from_millis(u64::from(index));
        let mut syn = tcp4(PEER4, LOCAL4, port, 443, SYN);
        let mut syn_ack = tcp4(LOCAL4, PEER4, 443, port, SYN_ACK);
        let mut ack = tcp4(PEER4, LOCAL4, port, 443, ACK);
        assert!(filter.check_at(&mut syn, Direction::MeshToHost, at));
        assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, at));
        assert!(filter.check_at(&mut ack, Direction::MeshToHost, at));
    }
    // One connection stays live: it carries a packet just before the hour is up.
    let live_at = start + TCP_ESTABLISHED_EVICTABLE_IDLE.saturating_sub(Duration::from_secs(1));
    let mut live = tcp4(PEER4, LOCAL4, 20_001, 443, ACK);
    assert!(filter.check_at(&mut live, Direction::MeshToHost, live_at));

    let mut too_soon = tcp4(PEER4, LOCAL4, 50_000, 443, SYN);
    assert!(
        !filter.check_at(&mut too_soon, Direction::MeshToHost, live_at),
        "a connection silent for under an hour was evicted"
    );
    let day = start + Duration::from_hours(24);
    let mut fresh = tcp4(PEER4, LOCAL4, 50_001, 443, SYN);
    assert!(
        filter.check_at(&mut fresh, Direction::MeshToHost, day),
        "a day after {quota} connections went silent, the peer still cannot open a new one"
    );
    // Only the oldest silent connection (20,000) made room. The one that carried a packet
    // later (20,001) and every younger one are still admitted.
    let mut evicted = tcp4(PEER4, LOCAL4, 20_000, 443, ACK);
    assert!(!filter.check_at(&mut evicted, Direction::MeshToHost, day));
    for port in [20_001, 20_002, 20_000 + quota - 1] {
        let mut kept = tcp4(PEER4, LOCAL4, port, 443, ACK);
        assert!(
            filter.check_at(&mut kept, Direction::MeshToHost, day),
            "connection {port} was evicted too"
        );
    }
    let mut later = tcp4(PEER4, LOCAL4, 50_004, 443, SYN);
    assert!(
        filter.check_at(
            &mut later,
            Direction::MeshToHost,
            start + Duration::from_hours(96)
        ),
        "4 days after the connections went silent, the peer still cannot open a new one"
    );
}

/// A full direction still evicts an unestablished flow before any established
/// connection, however long that connection has been silent (J721, #265).
#[test]
fn unestablished_flows_go_before_silent_established_ones() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::All, TrafficPolicy::None),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let start = Instant::now();
    let quota = u16::try_from(FLOWS_PER_DIRECTION).expect("quota");
    for index in 0..quota - 1 {
        let port = 20_000 + index;
        let mut syn = tcp4(PEER4, LOCAL4, port, 443, SYN);
        let mut syn_ack = tcp4(LOCAL4, PEER4, 443, port, SYN_ACK);
        let mut ack = tcp4(PEER4, LOCAL4, port, 443, ACK);
        assert!(filter.check_at(&mut syn, Direction::MeshToHost, start));
        assert!(filter.check_at(&mut syn_ack, Direction::HostToMesh, start));
        assert!(filter.check_at(&mut ack, Direction::MeshToHost, start));
    }
    // A UDP flow opened last, and seen more recently than every connection.
    let udp_at = start + Duration::from_hours(2);
    let mut udp = udp4(PEER4, LOCAL4, 5_353, 5_353);
    assert!(filter.check_at(&mut udp, Direction::MeshToHost, udp_at));
    let mut fresh = tcp4(PEER4, LOCAL4, 50_000, 443, SYN);
    assert!(filter.check_at(&mut fresh, Direction::MeshToHost, udp_at));
    let mut udp_again = udp4(LOCAL4, PEER4, 5_353, 5_353);
    assert!(
        !filter.check_at(&mut udp_again, Direction::HostToMesh, udp_at),
        "the unestablished UDP flow should have been evicted first"
    );
    let mut oldest = tcp4(PEER4, LOCAL4, 20_000, 443, ACK);
    assert!(filter.check_at(&mut oldest, Direction::MeshToHost, udp_at));
}

/// An IPv6 first fragment of a reply on an established outbound connection, whose
/// fragmentable part starts with an 8-byte destination-options header: IPv6 | Fragment
/// (next 60, offset 0, more) | Destination options (next TCP) | TCP ACK (20 bytes) | 4
/// bytes of data. The judged headers end 28 bytes into the fragmentable part.
fn ipv6_first_fragment_behind_destination_options(identification: u32) -> Vec<u8> {
    let mut first = vec![0_u8; 40 + 8 + 32];
    first[0] = 0x60;
    first[4..6].copy_from_slice(&40_u16.to_be_bytes());
    first[6] = 44;
    first[7] = 64;
    first[8..24].copy_from_slice(&PEER6.octets());
    first[24..40].copy_from_slice(&LOCAL6.octets());
    first[40] = 60;
    first[42..44].copy_from_slice(&1_u16.to_be_bytes());
    first[44..48].copy_from_slice(&identification.to_be_bytes());
    first[48] = 6;
    first[50] = 1; // PadN, filling the header's 6 option bytes.
    first[51] = 4;
    first[56..58].copy_from_slice(&443_u16.to_be_bytes());
    first[58..60].copy_from_slice(&40_000_u16.to_be_bytes());
    first[68] = 0x50;
    first[69] = ACK;
    first
}

/// A later IPv6 fragment of `first` at `offset` bytes into the fragmentable part, with 16
/// bytes of payload whose byte 5 is a SYN flag (where TCP's flags sit if it starts at 16).
fn ipv6_later_fragment(first: &[u8], offset: u16) -> Vec<u8> {
    let mut later = vec![0_u8; 40 + 8 + 16];
    later[..40].copy_from_slice(&first[..40]);
    later[4..6].copy_from_slice(&24_u16.to_be_bytes());
    later[40] = 60;
    later[42..44].copy_from_slice(&((offset / 8) << 3).to_be_bytes());
    later[44..48].copy_from_slice(&first[44..48]);
    later[48 + 5] = SYN;
    later
}

/// The overlap guard covers every header the filter judged, IPv6 extension headers
/// included (J718 P3, #265; J718's red test). When a destination-options header comes
/// before TCP, a later fragment's next header is 60, not TCP, so the parser's stateless
/// TCP check never runs. A later fragment at offset 16 would overwrite the TCP flags, at
/// byte 21, after they were judged. It is refused. One that starts past the headers, at
/// offset 32, still passes.
#[test]
fn ipv6_later_fragments_cannot_overlap_headers_behind_destination_options() {
    let filter = PacketFilter::new(
        &config(TrafficPolicy::None, grant(Protocol::Tcp, 443)),
        MeshProxyIngress::default(),
    )
    .expect("compile policy");
    let now = Instant::now();
    let mut open6 = tcp6(LOCAL6, PEER6, 40_000, 443, SYN);
    let mut accept6 = tcp6(PEER6, LOCAL6, 443, 40_000, SYN_ACK);
    let mut ack6 = tcp6(LOCAL6, PEER6, 40_000, 443, ACK);
    assert!(filter.check_at(&mut open6, Direction::HostToMesh, now));
    assert!(filter.check_at(&mut accept6, Direction::MeshToHost, now));
    assert!(filter.check_at(&mut ack6, Direction::HostToMesh, now));

    let mut first = ipv6_first_fragment_behind_destination_options(21);
    let mut overlapping = ipv6_later_fragment(&first, 16);
    let mut following = ipv6_later_fragment(&first, 32);
    assert!(filter.check_at(&mut first, Direction::MeshToHost, now));
    assert!(
        !filter.check_at(&mut overlapping, Direction::MeshToHost, now),
        "a later fragment overlapping the TCP flags behind destination options was admitted"
    );
    assert!(
        filter.check_at(&mut following, Direction::MeshToHost, now),
        "a later fragment past the judged headers was refused"
    );
}

/// Subnet route cases of the packet filter (D197 M3).
#[path = "packet_filter_route_tests.rs"]
mod routes;
