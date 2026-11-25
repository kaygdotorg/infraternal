//! Criterion bench for the per-packet hash tables on GotaTun's data path (#260, J1204).
//!
//! Every group walks a fixed stream of 1,024 lookups per iteration, so criterion's per-element
//! throughput is the ns/op of one packet's lookup, including the stream's own loop overhead
//! (identical for every candidate). Key streams are shuffled so the branch predictor cannot learn
//! one key; table sizes are 1, 100 and 1,000 peers where a table scales with peers.

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};
use hasher_bench::*;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::Arc;

/// Lookups per iteration.
const STREAM: usize = 1024;

/// Hashers exercised on std `HashMap`s, by the label used in the report.
macro_rules! for_each_hasher {
    ($mac:ident, $($args:tt)*) => {
        $mac!("sip13_random", std::hash::RandomState, $($args)*);
        $mac!("foldhash_fast", foldhash::fast::RandomState, $($args)*);
        $mac!("foldhash_quality", foldhash::quality::RandomState, $($args)*);
        $mac!("ahash", ahash::RandomState, $($args)*);
        $mac!("fxhash", rustc_hash::FxBuildHasher, $($args)*);
    };
}

/// The flow-table slot function, per packet: canonical tuple + hash + modulo.
fn flow_start(c: &mut Criterion) {
    for (family, v6) in [("v4", false), ("v6", true)] {
        let flows = tcp_flows(STREAM, v6, 0xF10);
        let mut g = c.benchmark_group(format!("flow_start/{family}"));
        g.throughput(Throughput::Elements(STREAM as u64));
        g.bench_function("sip13_fixed(current)", |b| {
            b.iter(|| {
                let mut acc = 0usize;
                for f in &flows {
                    acc = acc.wrapping_add(start_sip13_fixed(black_box(*f)));
                }
                acc
            })
        });
        macro_rules! cand {
            ($label:expr, $ty:ty,) => {
                let state = <$ty>::default();
                g.bench_function($label, |b| {
                    b.iter(|| {
                        let mut acc = 0usize;
                        for f in &flows {
                            acc = acc.wrapping_add(start_with(&state, black_box(*f)));
                        }
                        acc
                    })
                });
                g.bench_function(format!("{}+symmetric(no canonical)", $label), |b| {
                    b.iter(|| {
                        let mut acc = 0usize;
                        for f in &flows {
                            acc = acc.wrapping_add(start_symmetric(&state, black_box(*f)));
                        }
                        acc
                    })
                });
            };
        }
        for_each_hasher!(cand,);
        g.bench_function("manual_fold(no hasher)", |b| {
            let secret = 0x9E37_79B9_7F4A_7C15u64;
            b.iter(|| {
                let mut acc = 0usize;
                for f in &flows {
                    acc = acc.wrapping_add(start_manual(secret, black_box(*f)));
                }
                acc
            })
        });
        g.bench_function("canonical_only(floor)", |b| {
            b.iter(|| {
                let mut acc = 0u16;
                for f in &flows {
                    acc = acc.wrapping_add(black_box(*f).canonical().source_port);
                }
                acc
            })
        });
        g.finish();
    }
}

/// `peer_addresses: HashMap<IpAddr, usize>` (twice per packet in the filter).
fn peer_addresses(c: &mut Criterion) {
    for n in [1u32, 100, 1000] {
        let mut rng = Rng(0xADD5);
        let stream: Vec<IpAddr> = (0..STREAM)
            .map(|_| IpAddr::V4(mesh_v4((rng.next() % u64::from(n)) as u32 + 1)))
            .collect();
        let mut g = c.benchmark_group(format!("peer_addresses/{n}_peers"));
        g.throughput(Throughput::Elements(STREAM as u64));
        macro_rules! cand {
            ($label:expr, $ty:ty,) => {
                let map = peer_map::<$ty>(n);
                g.bench_function($label, |b| {
                    b.iter(|| {
                        let mut acc = 0usize;
                        for a in &stream {
                            acc = acc.wrapping_add(*map.get(black_box(a)).unwrap());
                        }
                        acc
                    })
                });
            };
        }
        for_each_hasher!(cand,);
        let peers: Vec<_> = (0..n).map(|i| (mesh_v4(i + 1), i)).collect();
        let direct = DirectV4::new(&peers);
        g.bench_function("direct_index(no hash)", |b| {
            b.iter(|| {
                let mut acc = 0u32;
                for a in &stream {
                    let IpAddr::V4(v4) = black_box(*a) else { unreachable!() };
                    acc = acc.wrapping_add(direct.get(v4).unwrap());
                }
                acc
            })
        });
        g.finish();
    }
}

/// `peers_by_idx: HashMap<u32, Arc<..>>` read per received data packet; keys are 2 sessions per
/// peer, random u32 (the receiver index), cloned `Arc` like `peer_by_index`.
fn peers_by_idx(c: &mut Criterion) {
    for n in [1u32, 100, 1000] {
        let mut rng = Rng(0x1D);
        let keys: Vec<u32> = (0..2 * n).map(|_| rng.next() as u32).collect();
        let stream: Vec<u32> = (0..STREAM).map(|_| keys[(rng.next() % keys.len() as u64) as usize]).collect();
        let mut g = c.benchmark_group(format!("peers_by_idx/{n}_peers"));
        g.throughput(Throughput::Elements(STREAM as u64));
        macro_rules! cand {
            ($label:expr, $ty:ty,) => {
                let map: HashMap<u32, Arc<u64>, $ty> =
                    keys.iter().map(|k| (*k, Arc::new(u64::from(*k)))).collect();
                g.bench_function($label, |b| {
                    b.iter(|| {
                        let mut acc = 0u64;
                        for k in &stream {
                            acc = acc.wrapping_add(*map.get(black_box(k)).cloned().unwrap());
                        }
                        acc
                    })
                });
            };
        }
        for_each_hasher!(cand,);
        cand_identity(&mut g, &keys, &stream);
        g.finish();
    }
}

/// The ceiling for `peers_by_idx`: an identity hash (not safe, the peer picks the stored keys).
fn cand_identity(
    g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    keys: &[u32],
    stream: &[u32],
) {
    let map: HashMap<u32, Arc<u64>, IdentityState> =
        keys.iter().map(|k| (*k, Arc::new(u64::from(*k)))).collect();
    g.bench_function("identity(unsafe ceiling)", |b| {
        b.iter(|| {
            let mut acc = 0u64;
            for k in stream {
                acc = acc.wrapping_add(*map.get(black_box(k)).cloned().unwrap());
            }
            acc
        })
    });
}

/// `incoming_runs: HashMap<usize, Run>` in `handle_incoming`: per packet, `entry(peer_key)` over
/// a small map that is rebuilt every batch (so creation and drain count), 64 packets per batch.
fn incoming_runs(c: &mut Criterion) {
    for peers in [1usize, 8] {
        let mut g = c.benchmark_group(format!("incoming_runs/{peers}_peers_per_batch"));
        g.throughput(Throughput::Elements(64));
        let peer_keys: Vec<usize> = (0..peers).map(|i| 0x5581_0000_0000 + i * 0x1040).collect();
        macro_rules! cand {
            ($label:expr, $ty:ty,) => {
                g.bench_function($label, |b| {
                    b.iter_batched(
                        || (),
                        |()| {
                            let mut runs: HashMap<usize, Vec<u32>, $ty> = HashMap::default();
                            for i in 0..64usize {
                                runs.entry(peer_keys[i % peers]).or_default().push(i as u32);
                            }
                            runs.into_values().map(|v| v.len()).sum::<usize>()
                        },
                        BatchSize::SmallInput,
                    )
                });
            };
        }
        for_each_hasher!(cand,);
        g.finish();
    }
}

/// `side_port::BulkRecency::recent`: `HashMap<SocketAddr, Instant>` read per sent datagram when the
/// side socket is on (off by default); up to 64 live destinations.
fn bulk_recency(c: &mut Criterion) {
    use std::net::{Ipv4Addr, SocketAddr};
    for n in [1u32, 64] {
        let addrs: Vec<SocketAddr> = (0..n)
            .map(|i| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x5DB8_D800 + i)), 41641))
            .collect();
        let mut rng = Rng(0x5);
        let stream: Vec<SocketAddr> = (0..STREAM).map(|_| addrs[(rng.next() % u64::from(n)) as usize]).collect();
        let mut g = c.benchmark_group(format!("bulk_recency/{n}_destinations"));
        g.throughput(Throughput::Elements(STREAM as u64));
        macro_rules! cand {
            ($label:expr, $ty:ty,) => {
                let map: HashMap<SocketAddr, u64, $ty> = addrs.iter().map(|a| (*a, 1u64)).collect();
                g.bench_function($label, |b| {
                    b.iter(|| {
                        let mut acc = 0u64;
                        for a in &stream {
                            acc += *map.get(black_box(a)).unwrap();
                        }
                        acc
                    })
                });
            };
        }
        for_each_hasher!(cand,);
        g.finish();
    }
}

/// The allowed-IPs table (`ip_network_table`, a radix trie): one `longest_match` per packet in
/// each direction. Alternatives: a hash table of host routes first (mesh peers are /32s), and
/// the direct index. Both only answer exact host routes; a hybrid would fall back to the trie.
fn allowed_ips(c: &mut Criterion) {
    use ip_network::{IpNetwork, Ipv4Network};
    use ip_network_table::IpNetworkTable;
    for n in [1u32, 100, 1000] {
        let mut trie: IpNetworkTable<usize> = IpNetworkTable::new();
        for i in 0..n {
            let v4 = Ipv4Network::new(mesh_v4(i + 1), 32).unwrap();
            trie.insert(IpNetwork::V4(v4), i as usize);
        }
        // A tenth of the peers also route a /24 behind them, as gateway peers do.
        for i in (0..n).step_by(10) {
            let v4 = Ipv4Network::new_truncate(std::net::Ipv4Addr::new(172, (i % 200) as u8, 0, 0), 24).unwrap();
            trie.insert(IpNetwork::V4(v4), i as usize);
        }
        let mut rng = Rng(0xA11);
        let stream: Vec<IpAddr> = (0..STREAM)
            .map(|_| IpAddr::V4(mesh_v4((rng.next() % u64::from(n)) as u32 + 1)))
            .collect();
        let mut g = c.benchmark_group(format!("allowed_ips/{n}_peers"));
        g.throughput(Throughput::Elements(STREAM as u64));
        g.bench_function("ip_network_table_trie(current)", |b| {
            b.iter(|| {
                let mut acc = 0usize;
                for a in &stream {
                    acc = acc.wrapping_add(*trie.longest_match(black_box(*a)).unwrap().1);
                }
                acc
            })
        });
        macro_rules! cand {
            ($label:expr, $ty:ty,) => {
                let map = peer_map::<$ty>(n);
                g.bench_function(format!("host_route_hash+{}", $label), |b| {
                    b.iter(|| {
                        let mut acc = 0usize;
                        for a in &stream {
                            acc = acc.wrapping_add(*map.get(black_box(a)).unwrap());
                        }
                        acc
                    })
                });
            };
        }
        for_each_hasher!(cand,);
        let peers: Vec<_> = (0..n).map(|i| (mesh_v4(i + 1), i)).collect();
        let direct = DirectV4::new(&peers);
        g.bench_function("direct_index(host routes)", |b| {
            b.iter(|| {
                let mut acc = 0u32;
                for a in &stream {
                    let IpAddr::V4(v4) = black_box(*a) else { unreachable!() };
                    acc = acc.wrapping_add(direct.get(v4).unwrap());
                }
                acc
            })
        });
        g.finish();
    }
    let _ = std::hint::black_box(std::hash::RandomState::new().hash_one(1u8));
}

/// `peer_ids: HashSet<usize>` behind `contains_peer`, asked once or twice per received packet.
/// Keys are heap addresses of the peer cells (`Arc::as_ptr`), so nothing remote chooses them.
fn peer_ids(c: &mut Criterion) {
    use std::collections::HashSet;
    for n in [1u32, 100, 1000] {
        let mut rng = Rng(0x9E);
        let keys: Vec<usize> = (0..n).map(|i| 0x5581_a000_0000 + (i as usize) * 0x140 + (rng.next() % 4) as usize * 0x10).collect();
        let stream: Vec<usize> = (0..STREAM).map(|_| keys[(rng.next() % keys.len() as u64) as usize]).collect();
        let mut g = c.benchmark_group(format!("peer_ids/{n}_peers"));
        g.throughput(Throughput::Elements(STREAM as u64));
        macro_rules! cand {
            ($label:expr, $ty:ty,) => {
                let set: HashSet<usize, $ty> = keys.iter().copied().collect();
                g.bench_function($label, |b| {
                    b.iter(|| {
                        let mut acc = 0usize;
                        for k in &stream {
                            acc += usize::from(set.contains(black_box(k)));
                        }
                        acc
                    })
                });
            };
        }
        for_each_hasher!(cand,);
        g.finish();
    }
}

criterion_group!(benches, flow_start, peer_addresses, peers_by_idx, peer_ids, incoming_runs, bulk_recency, allowed_ips);
criterion_main!(benches);
