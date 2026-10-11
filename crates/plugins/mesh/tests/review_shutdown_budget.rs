//! Checks the shipping Mesh shutdown budget at D170's 1,000-peer design point [167,198], #129.
#![cfg(all(feature = "agent", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

use std::{path::PathBuf, process::Command};

#[test]
#[ignore = "Run in a dedicated user/network namespace under CPUWeight=10000 with INFRATERNAL_BIN pointing to the shipping release binary."]
fn shipping_mesh_down_1000_peers_finishes_within_one_second() {
    let binary = std::env::var_os("INFRATERNAL_BIN").unwrap();
    let scratch = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap();
    let script =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/mesh-agent-scale.py");
    // Reuse the real daemon/control/CLI scale fixture. It verifies all 1,000
    // peers before timing down and confirms Off before reporting completion.
    let output = Command::new("python3")
        .arg(script)
        .arg("--binary")
        .arg(binary)
        .arg("--scratch")
        .arg(scratch)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "shipping scale fixture refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    println!("{report}");
    assert_eq!(report["peer_count"], 1000);
    // The orchestrator's #129 round-three follow-up sets this explicit budget.
    // No threshold is inferred from the current implementation's duration.
    assert!(
        report["down_us"].as_u64().unwrap() < 1_000_000,
        "Mesh down exceeds the one-second budget at 1,000 peers: {report}"
    );
}
