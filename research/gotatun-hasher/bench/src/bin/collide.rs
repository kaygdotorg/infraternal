//! Crafted-collision probe (#260, J1204): how much worse can a peer make its own flow table?
//!
//! A peer chooses the inner 5-tuples of its flows. Against a hash whose function is known (today's
//! `DefaultHasher::new()` has fixed zero keys; Fx has no key at all) it can search offline for
//! tuples that all start at slot 0 and make every lookup walk the whole probe chain. This binary
//! does that search for 256 flows (one direction's quota), then reports the probe length of the
//! same tuples under each hasher family, the way `FlowShard::insert` places them. A keyed hasher
//! the attacker cannot see (a per-process random seed) leaves the crafted tuples spread out.

use hasher_bench::*;
use std::net::{IpAddr, Ipv4Addr};

/// Find `count` tuples (a peer's own address pair, varying source port) for which `start` is 0.
fn craft(count: usize, start: impl Fn(FlowKey) -> usize) -> (Vec<FlowKey>, u64) {
    let mut found = Vec::new();
    let mut tried = 0u64;
    let mut port = 1024u32;
    let mut dport = 1u16;
    while found.len() < count {
        let key = FlowKey {
            source: IpAddr::V4(mesh_v4(0)),
            destination: IpAddr::V4(Ipv4Addr::from(0x0AFE_0002)),
            source_port: port as u16,
            destination_port: dport,
            protocol: 6,
        };
        tried += 1;
        if start(key) == 0 {
            found.push(key);
        }
        port += 1;
        if port > 65535 {
            port = 1024;
            dport += 1;
        }
    }
    (found, tried)
}

fn main() {
    println!("crafting 256 tuples that all start at slot 0 of 512, against each known function");
    let targets: [(&str, Box<dyn Fn(FlowKey) -> usize>); 2] = [
        ("sip13_fixed (today)", Box::new(start_sip13_fixed)),
        ("fxhash (unkeyed)", Box::new(|k| start_with(&rustc_hash::FxBuildHasher, k))),
    ];
    for (name, f) in &targets {
        let (flows, tried) = craft(256, f);
        println!("\nattack tuples found against {name}: {tried} candidates tried");
        let report = |label: &str, g: &dyn Fn(FlowKey) -> usize| {
            let (mean, max) = probe_stats(&flows, g);
            println!("  placed with {label:<34} mean probe {mean:7.2}  max {max}");
        };
        report("sip13_fixed (today)", &|k| start_sip13_fixed(k));
        report("sip13 with a random key (RandomState)", &|k| start_with(&std::hash::RandomState::new(), k));
        report("foldhash fast (random seed)", &|k| start_with(&foldhash::fast::RandomState::default(), k));
        report("ahash (seeded 1,2,3,4)", &|k| start_with(&ahash::RandomState::with_seeds(1, 2, 3, 4), k));
        report("fxhash (unkeyed)", &|k| start_with(&rustc_hash::FxBuildHasher, k));
    }
}
