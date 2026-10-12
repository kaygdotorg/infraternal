//! Verifies that a retired TCP socket cannot resume through reverse connection-state recreation [242], #173.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use std::{path::PathBuf, process::Command};

fn check(fallback: bool, family: &str) {
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
    let fixture = std::env::var_os("MESH_REVIEW_FIXTURE")
        .map_or_else(|| target.join("debug/examples/kernel_node"), PathBuf::from);
    let evidence = target.join(format!(
        "reverse-{}-{fallback}-{family}",
        std::process::id()
    ));
    std::fs::create_dir_all(&evidence).unwrap();
    let output = Command::new("python3")
        .arg("-c")
        .arg(include_str!("review_reverse_recreation.py"))
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."))
        .arg(fixture)
        .arg(evidence)
        .arg(family)
        .arg(if fallback { "compatibility" } else { "nft" })
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "retired TCP socket resumed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "Run in a disposable user/network namespace with the kernel_node example built, #173."]
fn nft_ipv4_retired_tcp_stops_after_reverse_traffic() {
    check(false, "ipv4");
}

#[test]
#[ignore = "Run in a disposable user/network namespace with the kernel_node example built, #173."]
fn nft_ipv6_retired_tcp_stops_after_reverse_traffic() {
    check(false, "ipv6");
}

#[test]
#[ignore = "Run in a disposable user/network namespace with the kernel_node example built, #173."]
fn nf_tables_ipv4_retired_tcp_stops_after_reverse_traffic() {
    check(true, "ipv4");
}

#[test]
#[ignore = "Run in a disposable user/network namespace with the kernel_node example built, #173."]
fn nf_tables_ipv6_retired_tcp_stops_after_reverse_traffic() {
    check(true, "ipv6");
}
