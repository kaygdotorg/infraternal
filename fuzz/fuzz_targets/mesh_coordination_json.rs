//! Fuzz the bounded peer-reply parsers used by mesh coordination [572, D391].
#![no_main]
#![forbid(unsafe_code)]

use infraternal_plugin_mesh::node_coordination;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, reply)) = data.split_first() else {
        return;
    };
    match selector % 4 {
        0 => {
            let _ = node_coordination::parse_candidates(reply);
        }
        1 => {
            let _ = node_coordination::parse_routes(reply);
        }
        2 => {
            let _ = node_coordination::parse_ipv6_state(reply);
        }
        _ => {
            let _ = node_coordination::parse_side_socket(reply);
        }
    }
});
