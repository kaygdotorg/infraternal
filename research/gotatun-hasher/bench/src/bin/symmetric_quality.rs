//! Collision-resistance comparison for the symmetric flow hash (#260, J1227).
//!
//! The claim to check: a slot function with no `canonical()` keeps the quality of the keyed
//! canonical-tuple hashes it would replace. Three measurements per candidate, each over many
//! independent seeds (a seed is a process start):
//!   1. probe length of a 512-slot open-addressing table filled with 256 realistic flows (what
//!      `probe_stats` measures, mean and max, aggregated over seeds);
//!   2. uniformity: chi-square of 512 buckets over 102,400 flows (expected ~511, sd ~32);
//!   3. offline precomputation: craft 256 flows that all start at slot 0 under ONE seed, then place
//!      them under every other seed (the HashDoS case a per-process seed has to defeat). A hash
//!      that resists it looks like the random baseline.
//! Prints a markdown table. All candidates are symmetric except the canonical references.

use hasher_bench::*;
use std::net::{IpAddr, Ipv4Addr};

/// A candidate: given a seed, the slot function.
type Make = Box<dyn Fn(u64) -> Box<dyn Fn(FlowKey) -> usize>>;

fn candidates() -> Vec<(&'static str, Make)> {
    vec![
        ("canonical + sip13 random key (reference, PRF)", Box::new(|seed| {
            // std's RandomState draws its own keys; a distinct state per call stands in for a seed.
            let _ = seed;
            let s = std::hash::RandomState::new();
            Box::new(move |k| start_with(&s, k))
        })),
        ("canonical + foldhash fast (J1204 recommendation)", Box::new(|seed| {
            let s = foldhash::fast::FixedState::with_seed(seed);
            Box::new(move |k| start_with(&s, k))
        })),
        ("symmetric sum, no final mix (start_symmetric)", Box::new(|seed| {
            let s = foldhash::fast::FixedState::with_seed(seed);
            Box::new(move |k| start_symmetric(&s, k))
        })),
        ("symmetric sum + final foldhash mix (start_symmetric_mixed)", Box::new(|seed| {
            let s = foldhash::fast::FixedState::with_seed(seed);
            Box::new(move |k| start_symmetric_mixed(&s, k))
        })),
        ("manual keyed fold (start_manual)", Box::new(|seed| {
            let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let secret = r.next();
            Box::new(move |k| start_manual(secret, k))
        })),
    ]
}

/// Realistic flow sets: sequential ephemeral ports to a few server ports, v4 and v6, and a busier
/// shape with many source addresses (gateway peer fronting a subnet).
fn flow_sets() -> Vec<(&'static str, Vec<FlowKey>)> {
    let mut seq = tcp_flows(256, false, 1);
    let mut one_port = tcp_flows(256, false, 2);
    for (i, k) in one_port.iter_mut().enumerate() {
        k.source_port = 40000 + i as u16;
        k.destination_port = 443;
    }
    let v6 = tcp_flows(256, true, 3);
    let mut many_hosts = tcp_flows(256, false, 4);
    for (i, k) in many_hosts.iter_mut().enumerate() {
        k.source = IpAddr::V4(Ipv4Addr::new(172, 16, (i / 250) as u8, (i % 250) as u8 + 1));
        k.source_port = 50000;
    }
    seq.truncate(256);
    vec![("seq ports, v4", seq), ("one dst port, ports +1", one_port), ("v6", v6), ("many source hosts", many_hosts)]
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() - 1) as f64 * p).round() as usize]
}

fn main() {
    let seeds = 2000u64;
    let sets = flow_sets();
    println!("## 1. probe length, 256 flows in 512 slots, {seeds} seeds (mean of means / p99 of max probe)\n");
    println!("| candidate | {} |", sets.iter().map(|s| s.0).collect::<Vec<_>>().join(" | "));
    println!("|---|{}", "---|".repeat(sets.len()));
    for (name, make) in candidates() {
        let mut cells = Vec::new();
        for (_, flows) in &sets {
            let (mut means, mut maxes) = (Vec::new(), Vec::new());
            for seed in 0..seeds {
                let f = make(seed);
                let (m, x) = probe_stats(flows, &*f);
                means.push(m);
                maxes.push(x as f64);
            }
            let mean = means.iter().sum::<f64>() / means.len() as f64;
            cells.push(format!("{mean:.3} / {:.0}", pct(&mut maxes, 0.99)));
        }
        println!("| {name} | {} |", cells.join(" | "));
    }

    println!("\n## 2. uniformity: chi-square of 512 buckets over 102,400 flows, {seeds} seeds (expect mean ~511, p99 ~590)\n");
    println!("| candidate | mean chi2 | p99 chi2 | max chi2 |\n|---|---:|---:|---:|");
    let mut r = Rng(0xC41);
    let flows: Vec<FlowKey> = (0..102_400)
        .map(|i| FlowKey {
            source: IpAddr::V4(mesh_v4((r.next() % 1000) as u32)),
            destination: IpAddr::V4(mesh_v4((r.next() % 1000) as u32)),
            source_port: if i % 2 == 0 { 32768 + (i / 2 % 28000) as u16 } else { r.next() as u16 },
            destination_port: [22u16, 80, 443, 8080][(r.next() % 4) as usize],
            protocol: 6,
        })
        .collect();
    for (name, make) in candidates() {
        let mut chis = Vec::new();
        for seed in 0..seeds / 10 {
            let f = make(seed);
            let mut c = vec![0u32; 512];
            for k in &flows {
                c[f(*k)] += 1;
            }
            let e = flows.len() as f64 / 512.0;
            chis.push(c.iter().map(|&o| (f64::from(o) - e).powi(2) / e).sum::<f64>());
        }
        let mean = chis.iter().sum::<f64>() / chis.len() as f64;
        let max = chis.iter().cloned().fold(0.0, f64::max);
        println!("| {name} | {mean:.1} | {:.1} | {max:.1} |", pct(&mut chis, 0.99));
    }

    println!("\n## 3. offline precomputation: 256 flows crafted to slot 0 under seed 0, placed under {seeds} other seeds\n");
    println!("| candidate | candidates tried | probe under seed 0 (mean / max) | under other seeds: mean of means | p99 of max |\n|---|---:|---|---:|---:|");
    for (name, make) in candidates() {
        let f0 = make(0);
        let mut found = Vec::new();
        let (mut tried, mut port, mut dport) = (0u64, 1024u32, 1u16);
        while found.len() < 256 {
            let k = FlowKey {
                source: IpAddr::V4(mesh_v4(0)),
                destination: IpAddr::V4(Ipv4Addr::from(0x0AFE_0002)),
                source_port: port as u16,
                destination_port: dport,
                protocol: 6,
            };
            tried += 1;
            if f0(k) == 0 {
                found.push(k);
            }
            port += 1;
            if port > 65535 {
                port = 1024;
                dport += 1;
            }
        }
        // sip13 with a random key cannot be attacked offline at all; its seed-0 closure is a
        // single random state, so the search above only "works" against that one instance.
        let (m0, x0) = probe_stats(&found, &*f0);
        let (mut means, mut maxes) = (Vec::new(), Vec::new());
        for seed in 1..=seeds {
            let f = make(seed);
            let (m, x) = probe_stats(&found, &*f);
            means.push(m);
            maxes.push(x as f64);
        }
        let mean = means.iter().sum::<f64>() / means.len() as f64;
        println!("| {name} | {tried} | {m0:.1} / {x0} | {mean:.3} | {:.0} |", pct(&mut maxes, 0.99));
    }
}
