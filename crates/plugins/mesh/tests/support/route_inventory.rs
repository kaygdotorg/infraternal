//! Reads actual installed host routes for namespace proofs; allowed IPs alone cannot prove routing.

use std::{collections::BTreeSet, net::IpAddr, process::Command};

/// Return only protocol-250 IPv4 and IPv6 routes through the current mesh interface.
/// This observer queries the kernel independently of the product's repair and allowed-IP APIs.
pub(super) fn installed_routes() -> BTreeSet<IpAddr> {
    let mut routes = BTreeSet::new();
    for family in ["-4", "-6"] {
        let output = Command::new("ip")
            .args([
                "-j",
                family,
                "route",
                "show",
                "dev",
                "infraternal0",
                "proto",
                "250",
            ])
            .output()
            .expect("kernel route dump");
        assert!(output.status.success(), "kernel route dump failed");
        let entries: Vec<serde_json::Value> =
            serde_json::from_slice(&output.stdout).expect("route JSON");
        for entry in entries {
            let destination = entry["dst"].as_str().expect("route destination");
            let address = destination
                .split('/')
                .next()
                .expect("host prefix")
                .parse()
                .expect("IP route destination");
            assert!(routes.insert(address), "duplicate mesh destination");
        }
    }
    routes
}
