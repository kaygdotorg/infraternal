//! Regression test for the flow table's slot hash (#260, J1226, from J1204's collision probe).
//!
//! A peer chooses the inner 5-tuples of its flows. While the slot function was SipHash with fixed
//! zero keys, the peer could search offline for tuples that all start at slot 0 and make every
//! lookup walk the probe chain (mean probe 127.5 of 512 for one direction's 256 flows). The slot
//! function is now seeded per process, so tuples crafted against the old function must spread.

#![allow(clippy::expect_used)]

use super::{
    Direction, FLOW_SLOTS_PER_PEER, FLOW_SLOTS_PER_PEER_HASH, FLOWS_PER_DIRECTION, FlowEntry,
    FlowKey, FlowShard, Grant, flow_start,
};
use crate::policy::model::NodeId;
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    net::{IpAddr, Ipv4Addr},
    time::Instant,
};

/// The retired slot function (SipHash-1-3, fixed zero keys): the attacker's model of the table.
fn retired_start(key: FlowKey) -> usize {
    let mut hasher = DefaultHasher::new();
    key.min(key.reverse()).hash(&mut hasher);
    usize::try_from(hasher.finish() % FLOW_SLOTS_PER_PEER_HASH).expect("slot index")
}

/// One crafted tuple: a peer's own address pair with the given ports.
fn tuple(source_port: u16, destination_port: u16) -> FlowKey {
    FlowKey {
        source: IpAddr::V4(Ipv4Addr::new(10, 254, 0, 2)),
        destination: IpAddr::V4(Ipv4Addr::new(10, 254, 0, 1)),
        source_port,
        destination_port,
        protocol: 6,
    }
}

/// A grant that carries nothing: the probe length does not depend on it.
const GRANT: Grant = Grant {
    protocol: None,
    port: None,
    ssh: false,
    proxy: None,
    ssh_redirect_port: None,
};

/// Mean and max probe length (slots walked past the starting slot) of `flows`, placed with the
/// real [`FlowShard::insert`] through `start`.
fn probe_stats(flows: &[FlowKey], start: impl Fn(FlowKey) -> usize) -> (f64, usize) {
    let mut shard = FlowShard::new().expect("allocate flow slots");
    let now = Instant::now();
    for key in flows {
        let entry = FlowEntry {
            key: *key,
            peer_address: key.source,
            peer_id: NodeId(2),
            initiated: Direction::MeshToHost,
            grant: GRANT,
            last_seen: now,
            ssh_redirect_port: None,
            state: 0,
        };
        assert!(shard.insert(entry, start(*key)), "flow admitted");
    }
    let mut total = 0;
    let mut max = 0;
    for key in flows {
        let begin = start(*key);
        let (index, _) = shard.find(*key, begin).expect("flow found");
        let probe = (index + FLOW_SLOTS_PER_PEER - begin) % FLOW_SLOTS_PER_PEER;
        total += probe;
        max = max.max(probe);
    }
    let count = |n: usize| f64::from(u32::try_from(n).expect("small count"));
    (count(total) / count(flows.len()), max)
}

/// 256 tuples crafted so the retired function starts every one at slot 0 pile up under it, and
/// stay spread under the product's seeded function.
#[test]
fn flow_slot_collisions_stay_spread_under_a_crafted_search() {
    let mut flows = Vec::new();
    'search: for destination_port in 1..=u16::MAX {
        for source_port in 1024..=u16::MAX {
            let key = tuple(source_port, destination_port);
            if retired_start(key) == 0 {
                flows.push(key);
                if flows.len() == FLOWS_PER_DIRECTION {
                    break 'search;
                }
            }
        }
    }
    assert_eq!(
        flows.len(),
        FLOWS_PER_DIRECTION,
        "the search found its tuples"
    );

    let (retired_mean, _) = probe_stats(&flows, retired_start);
    assert!(
        retired_mean > 100.0,
        "the crafted tuples must break the retired function (mean probe {retired_mean})"
    );

    let (seeded_mean, seeded_max) = probe_stats(&flows, flow_start);
    assert!(
        seeded_mean < 2.0,
        "seeded slot function: mean probe {seeded_mean} (max {seeded_max}) should stay near 1"
    );
}

/// Each tuple and its reverse start at the same slot for both address families.
#[test]
fn flow_slot_is_independent_of_packet_direction() {
    for port in [0, 1, 443, 32_768, u16::MAX] {
        for protocol in [0, 6, 17, u8::MAX] {
            let mut key = tuple(port, 443);
            key.protocol = protocol;
            assert_eq!(flow_start(key), flow_start(key.reverse()));
            key.source = "2001:db8::1".parse().expect("IPv6 address");
            key.destination = "2001:db8::2".parse().expect("IPv6 address");
            assert_eq!(flow_start(key), flow_start(key.reverse()));
            key.destination = key.source;
            assert_eq!(flow_start(key), flow_start(key.reverse()));
        }
    }
}
