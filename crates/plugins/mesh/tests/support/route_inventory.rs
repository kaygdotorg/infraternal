//! Reads actual installed host routes for namespace proofs; allowed IPs alone cannot prove routing.

use std::{collections::BTreeSet, net::IpAddr, process::Command};

/// Return only protocol-250 IPv4 and IPv6 routes through the current mesh interface.
/// This observer queries the kernel independently of the product's repair and allowed-IP APIs.
pub(super) fn installed_routes() -> BTreeSet<IpAddr> {
    installed_routes_from(|family| {
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
        serde_json::from_slice(&output.stdout).expect("route JSON")
    })
}

/// Require a unique inventory, restarting an inconsistent dump at most twice during route changes.
/// No rows survive a retry; persistent duplicates fail with the complete offending family dump.
fn installed_routes_from(mut dump: impl FnMut(&str) -> Vec<serde_json::Value>) -> BTreeSet<IpAddr> {
    let mut attempt = 0;
    'snapshot: loop {
        attempt += 1;
        let mut routes = BTreeSet::new();
        for family in ["-4", "-6"] {
            let entries = dump(family);
            for entry in &entries {
                let destination = entry["dst"].as_str().expect("route destination");
                let address = destination
                    .split('/')
                    .next()
                    .expect("host prefix")
                    .parse()
                    .expect("IP route destination");
                if !routes.insert(address) {
                    let diagnostic = format!(
                        "duplicate mesh destination {address}; family={family}; raw={}",
                        serde_json::to_string(&entries).expect("parsed route dump serializes")
                    );
                    assert!(attempt < 3, "{diagnostic}");
                    eprintln!("retrying route inventory: {diagnostic}");
                    continue 'snapshot;
                }
            }
        }
        return routes;
    }
}

/// Protect snapshot acceptance without reading or modifying the host's network.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// One repeated row invalidates that attempt; the next complete unique snapshot is accepted.
    #[test]
    fn repeated_rows_require_a_fresh_unique_snapshot() {
        let mut calls = 0;
        let routes = installed_routes_from(|family| {
            calls += 1;
            if calls == 1 {
                vec![json!({"dst": "10.254.0.2"}), json!({"dst": "10.254.0.2"})]
            } else if family == "-4" {
                vec![json!({"dst": "10.254.0.2"})]
            } else {
                vec![json!({"dst": "fd01::2"})]
            }
        });
        assert_eq!(calls, 3);
        assert_eq!(
            routes,
            BTreeSet::from([
                "10.254.0.2".parse().expect("fixture IPv4"),
                "fd01::2".parse().expect("fixture IPv6"),
            ])
        );
    }

    /// A failed attempt cannot retain a destination that has disappeared from the successful dump.
    #[test]
    fn retried_snapshot_does_not_keep_disappeared_routes() {
        let mut calls = 0;
        let routes = installed_routes_from(|family| {
            calls += 1;
            if calls == 1 {
                vec![
                    json!({"dst": "10.254.0.9"}),
                    json!({"dst": "10.254.0.2"}),
                    json!({"dst": "10.254.0.2"}),
                ]
            } else if family == "-4" {
                vec![json!({"dst": "10.254.0.2"})]
            } else {
                vec![]
            }
        });
        assert_eq!(
            routes,
            BTreeSet::from(["10.254.0.2".parse().expect("fixture IPv4")])
        );
    }

    /// Persistent duplicate destinations remain a failure instead of becoming an accepted set.
    #[test]
    #[should_panic(expected = "duplicate mesh destination")]
    fn persistent_duplicate_routes_are_refused() {
        installed_routes_from(|_| vec![json!({"dst": "10.254.0.2"}), json!({"dst": "10.254.0.2"})]);
    }
}
