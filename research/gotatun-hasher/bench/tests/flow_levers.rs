//! Correctness tests for the two J1227 prototypes (#260): the symmetric flow hash and the
//! host-route table in front of the allowed-IPs trie.

use hasher_bench::*;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Random tuples of both families, including the edge shapes (same endpoint on both sides, port 0,
/// protocol 0/255, mapped-looking v6).
fn random_keys(n: usize, seed: u64) -> Vec<FlowKey> {
    let mut r = Rng(seed | 1);
    (0..n)
        .map(|i| {
            let v6 = r.next() & 1 == 1;
            let mk = |r: &mut Rng| {
                if v6 { IpAddr::V6(Ipv6Addr::from(u128::from(r.next()) << 64 | u128::from(r.next()))) } else { IpAddr::V4(Ipv4Addr::from(r.next() as u32)) }
            };
            let a = mk(&mut r);
            let b = if i % 17 == 0 { a } else { mk(&mut r) };
            FlowKey {
                source: a,
                destination: b,
                source_port: if i % 13 == 0 { 0 } else { r.next() as u16 },
                destination_port: if i % 11 == 0 { 0 } else { r.next() as u16 },
                protocol: [0u8, 1, 6, 17, 58, 255][(r.next() % 6) as usize],
            }
        })
        .collect()
}

#[test]
fn symmetric_hash_puts_both_directions_in_one_slot() {
    for seed in 0..8u64 {
        let state = foldhash::fast::FixedState::with_seed(seed);
        for k in random_keys(200_000, seed + 100) {
            assert_eq!(start_symmetric_mixed(&state, k), start_symmetric_mixed(&state, k.reverse()));
            assert_eq!(start_symmetric(&state, k), start_symmetric(&state, k.reverse()));
        }
        let secret = 0xD1B5_4A32_D192_ED03u64 ^ seed;
        for k in random_keys(200_000, seed + 900) {
            assert_eq!(start_manual(secret, k), start_manual(secret, k.reverse()));
        }
    }
    // The product's own function, for the same keys, is the reference for what "one slot" means.
    for k in random_keys(100_000, 7) {
        assert_eq!(start_sip13_fixed(k), start_sip13_fixed(k.reverse()));
    }
}

/// A different 5-tuple must not be forced into the same slot as its reverse by accident: over many
/// keys the share of "key and a different random key share a slot" must be near 1/512.
#[test]
fn symmetric_hash_does_not_merge_unrelated_flows() {
    let state = foldhash::fast::FixedState::with_seed(3);
    let keys = random_keys(400_000, 5);
    let same = keys.chunks(2).filter(|p| start_symmetric_mixed(&state, p[0]) == start_symmetric_mixed(&state, p[1])).count();
    let expected = keys.len() / 2 / 512;
    assert!(same > expected * 8 / 10 && same < expected * 12 / 10, "same={same} expected~{expected}");
}

/// The pre-mix sum is additive in the two endpoints for every seed (by construction). That is why
/// the product-shaped function ends with one more seeded hash of the sum: the relation below must
/// not be visible in the slots.
#[test]
fn pre_mix_sum_is_additive_in_the_endpoints() {
    let state = foldhash::fast::FixedState::with_seed(11);
    let a = IpAddr::V4(mesh_v4(1));
    let b = IpAddr::V4(mesh_v4(2));
    let k = |p, q| FlowKey { source: a, destination: b, source_port: p, destination_port: q, protocol: 6 };
    let (x, y, z, w) = (k(1000, 80), k(1001, 81), k(1000, 81), k(1001, 80));
    let s = |f| symmetric_sum(&state, f);
    // Pre-mix: the additive relation holds for every seed (protocol terms cancel).
    assert_eq!(s(x).wrapping_add(s(y)), s(z).wrapping_add(s(w)));
    // After the final mix the four slots carry no such relation: over many seeds the relation
    // "slot(x)+slot(y) == slot(z)+slot(w) (mod 512)" holds for ~1/512 of them, as for random slots.
    let mut hits = 0;
    for seed in 0..20_000u64 {
        let st = foldhash::fast::FixedState::with_seed(seed);
        let sl = |f| start_symmetric_mixed(&st, f);
        if (sl(x) + sl(y)) % 512 == (sl(z) + sl(w)) % 512 {
            hits += 1;
        }
    }
    assert!(hits < 20_000 / 512 * 2, "relation visible in slots: {hits}");
}

/// Both families: the hybrid table answers exactly like the plain trie under a random sequence of
/// inserts (new, replacing, nested prefixes, overlapping hosts), removals and lookups.
#[test]
fn hybrid_table_matches_the_trie_under_random_operations() {
    for seed in 1..40u64 {
        let mut r = Rng(seed * 0x9E37 + 1);
        let mut hybrid: HybridTable<u32, foldhash::fast::RandomState> = HybridTable::new();
        let mut trie: IpNetworkTable<u32> = IpNetworkTable::new();
        let pool4: Vec<Ipv4Addr> = (0..48u32).map(|i| Ipv4Addr::from(0x0AFE_0000 + (i % 24) * 3 + (i / 24) * 0x0100_0000)).collect();
        let pool6: Vec<Ipv6Addr> = (0..32u128).map(|i| Ipv6Addr::from(0xfd7a_115c_a1e0_0000_0000_0000_0000_0000u128 + (i % 16) * 5 + (i / 16) * (1 << 100))).collect();
        for step in 0..3000u32 {
            let v6 = r.next() % 3 == 0;
            let ip: IpAddr = if v6 { IpAddr::V6(pool6[(r.next() % 32) as usize]) } else { IpAddr::V4(pool4[(r.next() % 48) as usize]) };
            let full = if v6 { 128 } else { 32 };
            match r.next() % 10 {
                0..=4 => {
                    // Mostly host routes, with some shorter prefixes mixed in.
                    let prefix = if r.next() % 3 == 0 { (r.next() % (full as u64 + 1)) as u8 } else { full };
                    let v = step;
                    let net = IpNetwork::new_truncate(ip, prefix).unwrap();
                    assert_eq!(hybrid.insert(ip, prefix, v), trie.insert(net, v), "insert returns the replaced value");
                }
                5 => {
                    let drop_mod = 2 + (r.next() % 5) as u32;
                    let m = drop_mod;
                    hybrid.remove(&|v| v % m == 0);
                    trie.retain(|_, v| *v % m != 0);
                }
                _ => {}
            }
            for _ in 0..8 {
                let q: IpAddr = if r.next() % 3 == 0 {
                    IpAddr::V6(Ipv6Addr::from(u128::from(pool6[(r.next() % 32) as usize]) ^ u128::from(r.next() % 3)))
                } else {
                    IpAddr::V4(Ipv4Addr::from(u32::from(pool4[(r.next() % 48) as usize]) ^ (r.next() % 4) as u32))
                };
                assert_eq!(hybrid.find(q), trie.longest_match(q).map(|(_, d)| d), "seed {seed} step {step} query {q}");
            }
        }
    }
}

/// A host route is replaced in place, removed on its own, and does not hide a shorter prefix once
/// it is gone (the "route change" invalidation cases).
#[test]
fn host_route_changes_are_visible_at_once() {
    let mut t: HybridTable<&'static str, foldhash::fast::RandomState> = HybridTable::new();
    let host = IpAddr::V4(Ipv4Addr::new(10, 254, 0, 7));
    t.insert(IpAddr::V4(Ipv4Addr::new(10, 254, 0, 0)), 16, "net");
    assert_eq!(t.find(host), Some(&"net"));
    assert_eq!(t.insert(host, 32, "a"), None);
    assert_eq!(t.find(host), Some(&"a"));
    assert_eq!(t.insert(host, 32, "b"), Some("a"));
    assert_eq!(t.find(host), Some(&"b"));
    t.remove(&|v| *v == "b");
    assert_eq!(t.find(host), Some(&"net"));
    t.remove(&|v| *v == "net");
    assert_eq!(t.find(host), None);
}
