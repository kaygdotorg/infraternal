//! Compares the prior two-map routing layout with shared slots at 1000 admitted nodes on the perf VM [5,243,256], #201.
use super::*;
use std::{hint::black_box, time::Instant};

// These are the prior peer fields, before the shared slot gained its logical
// tuple. Keep that layout only in this opt-in comparison, never in transport.
type PriorPeer = (
    u64,
    SocketAddr,
    SocketAddr,
    Option<u64>,
    Option<IpAddr>,
    Recent,
);

#[test]
#[ignore = "Measure only on the perf VM under its benchmark lock."]
fn routing_lookup_at_1000_nodes() {
    let mut prior_logical = HashMap::<SocketAddr, PriorPeer>::new();
    let mut prior_alternate = HashMap::<SocketAddr, SocketAddr>::new();
    let mut slots = Peers::default();
    let mut addresses = Vec::new();
    for index in 0u16..1000 {
        let [a, b] = index.to_be_bytes();
        let logical = SocketAddr::from(([10, 220, a, b], 7443));
        let alternate = SocketAddr::from(([10, 254, a, b], 7443));
        let id = u64::from(index);
        prior_logical.insert(
            logical,
            (id, alternate, logical, None, None, Recent::default()),
        );
        prior_alternate.insert(alternate, logical);
        assert!(slots.insert(id, logical, alternate));
        addresses.push((logical, alternate));
    }
    let load = std::fs::read_to_string("/proc/loadavg").unwrap();
    let mut before = Vec::new();
    let mut after = Vec::new();
    for _ in 0..31 {
        let started = Instant::now();
        for _ in 0..1000 {
            for &(_, physical) in &addresses {
                let logical = black_box(&prior_alternate)
                    .get(&physical)
                    .copied()
                    .unwrap_or(physical);
                black_box(black_box(&prior_logical).get(&logical).unwrap().0);
            }
        }
        before.push(started.elapsed().as_nanos());
        let started = Instant::now();
        for _ in 0..1000 {
            for &(_, physical) in &addresses {
                black_box(black_box(&mut slots).by_physical(physical).unwrap().id);
            }
        }
        after.push(started.elapsed().as_nanos());
    }
    before.sort_unstable();
    after.sort_unstable();
    // Capacity-weighted element bytes exclude allocator/control overhead. This
    // describes the layouts; it is not a process-RSS or kernel-memory claim.
    let prior_elements = prior_logical.capacity() * std::mem::size_of::<(SocketAddr, PriorPeer)>()
        + prior_alternate.capacity() * std::mem::size_of::<(SocketAddr, SocketAddr)>();
    let slot_elements = slots.keys.capacity() * std::mem::size_of::<(SocketAddr, u64)>()
        + slots.slots.capacity() * std::mem::size_of::<Option<Peer>>()
        + slots.free.capacity() * std::mem::size_of::<usize>();
    println!(
        "routing_lookup nodes=1000 batches=31 lookups_per_batch=1000000 prior_p50_ns={} prior_p99_ns={} slots_p50_ns={} slots_p99_ns={} prior_element_capacity_bytes={} slots_element_capacity_bytes={} machine={} load={}",
        before[15],
        before[30],
        after[15],
        after[30],
        prior_elements,
        slot_elements,
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        load.trim()
    );
}
