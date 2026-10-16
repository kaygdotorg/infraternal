//! Compares the prior two-map routing layout with shared slots at 1000 admitted nodes on the perf VM [5,243,256], #201.
use super::*;
use std::{hint::black_box, time::Instant};

/// Compare equivalent complete tag representations without changing routing.
#[test]
#[ignore = "Measure only on the perf VM under its benchmark lock."]
fn complete_tag_lookup_at_1000_peers() {
    let mut bytes = vec![Vec::<[u8; 16]>::new(); 1000];
    let mut integers = vec![Vec::<u128>::new(); 1000];
    for (tags, packed) in bytes.iter_mut().zip(&mut integers) {
        for value in 0_u128..256 {
            tags.push(value.to_le_bytes());
            packed.push(value);
        }
    }
    let load = std::fs::read_to_string("/proc/loadavg").unwrap();
    let mut arrays = Vec::new();
    let mut packed = Vec::new();
    for batch in 0..31_u128 {
        let started = Instant::now();
        for index in 0..20000_usize {
            let tag = black_box((256 + batch * 20000 + index as u128).to_le_bytes());
            assert!(!black_box(&bytes[index % 1000]).contains(&tag));
            assert!(black_box(&bytes[index % 1000]).contains(&black_box(255_u128.to_le_bytes())));
        }
        arrays.push(started.elapsed().as_nanos());
        let started = Instant::now();
        for index in 0..20000_usize {
            let tag = black_box(256 + batch * 20000 + index as u128);
            assert!(!black_box(&integers[index % 1000]).contains(&tag));
            assert!(black_box(&integers[index % 1000]).contains(&black_box(255_u128)));
        }
        packed.push(started.elapsed().as_nanos());
    }
    arrays.sort_unstable();
    packed.sort_unstable();
    println!(
        "complete_tag_lookup peers=1000 batches=31 pairs_per_batch=20000 array_p50_ns={} array_p99_ns={} u128_p50_ns={} u128_p99_ns={} retained_tag_bytes=4096000 scope=equivalent_full_128bit_tags_fixed_arrays_no_crypto_or_udp machine={} load={}",
        arrays[15],
        arrays[30],
        packed[15],
        packed[30],
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        load.trim()
    );
}

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
