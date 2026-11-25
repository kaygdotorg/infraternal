//! Probe-length quality of each flow-table hash on realistic tuples (#260, J1204): how far
//! open addressing has to walk when 256 flows share one peer's 512-slot table. Prints one line
//! per candidate. A hash that clusters sequential ephemeral ports shows up as a long mean/max.

use hasher_bench::*;

fn main() {
    for (family, v6) in [("v4", false), ("v6", true)] {
        for (shape, flows) in [
            ("256 sequential ephemeral ports to 6 server ports", tcp_flows(256, v6, 1)),
            ("256 flows, 1 server port, ports +1", {
                let mut f = tcp_flows(256, v6, 2);
                for (i, k) in f.iter_mut().enumerate() {
                    k.source_port = 40000 + i as u16;
                    k.destination_port = 443;
                }
                f
            }),
        ] {
            println!("== {family}: {shape}");
            let report = |name: &str, f: &dyn Fn(FlowKey) -> usize| {
                let (mean, max) = probe_stats(&flows, f);
                println!("{name:<34} mean probe {mean:6.3}  max {max}");
            };
            report("sip13_fixed(current)", &|k| start_sip13_fixed(k));
            report("foldhash_fast", &|k| start_with(&foldhash::fast::RandomState::default(), k));
            report("foldhash_fast fixed seed", &|k| start_with(&foldhash::fast::FixedState::with_seed(7), k));
            report("foldhash_quality", &|k| start_with(&foldhash::quality::FixedState::with_seed(7), k));
            report("ahash fixed seeds", &|k| start_with(&ahash::RandomState::with_seeds(1, 2, 3, 4), k));
            report("fxhash", &|k| start_with(&rustc_hash::FxBuildHasher, k));
            report("fxhash+symmetric", &|k| start_symmetric(&rustc_hash::FxBuildHasher, k));
            report("foldhash_fast+symmetric", &|k| start_symmetric(&foldhash::fast::FixedState::with_seed(7), k));
            report("manual_fold", &|k| start_manual(0x9E37_79B9_7F4A_7C15, k));
        }
    }
}
