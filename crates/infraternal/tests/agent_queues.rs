//! Real-binary saturation and closed-shim isolation regression [13][41], issue #20.
#![allow(clippy::unwrap_used)]
use std::{path::PathBuf, process::Command};

#[test]
fn saturated_terminal_queues_preserve_every_byte_and_daemon_liveness() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("scripts/verify-agent-queues.py")
        .args(["--binary", env!("CARGO_BIN_EXE_infraternal")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "queue saturation oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
