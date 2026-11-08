//! Fuzzes the DNS wire parser and response boundary used by the Linux mesh resolver [#266].
#![no_main]

pub use infraternal_mesh as policy;

#[allow(dead_code)]
#[path = "../../src/dataplane.rs"]
mod dataplane;
#[allow(dead_code)]
#[path = "../../src/dns.rs"]
mod dns;

use dataplane::{Config, DefaultPolicy};
use infraternal_mesh::model::{Addresses, NodeId};
use libfuzzer_sys::fuzz_target;
use std::{collections::BTreeMap, net::Ipv4Addr, sync::OnceLock};

/// The one configuration every fuzz input is answered against, built once.
static CONFIG: OnceLock<Config> = OnceLock::new();

/// A minimal node configuration: node 1 named `mesh-node`, suffix `internal`,
/// no peers.
fn config() -> Config {
    Config {
        authority_epoch: None,
        local_key: None,
        server: Some(NodeId(1)),
        node: NodeId(1),
        name: Some("mesh-node".to_owned()),
        dns_suffix: "internal".to_owned(),
        version: 1,
        addresses: Addresses {
            ipv4: Ipv4Addr::new(10, 254, 0, 1),
            ipv6: "fd66:6821:bc63:834e::1"
                .parse()
                .expect("valid fixture address"),
        },
        default_policy: DefaultPolicy::Allow,
        exposure: None,
        peers: BTreeMap::new(),
        peer_names: BTreeMap::new(),
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = dns::response(data, CONFIG.get_or_init(config));
});
