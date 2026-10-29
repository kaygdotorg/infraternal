//! Verifies replay geometry across real infraternal agent, shim and PTY viewers (#257).
#![cfg(feature = "plugin-agent")]
#![allow(clippy::unwrap_used)]

use std::{path::PathBuf, process::Command};

#[test]
fn replay_fences_report_pre_resize_geometry_across_viewers() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("scripts/verify-agent-replay-size.py")
        .args(["--binary", env!("CARGO_BIN_EXE_infraternal")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "replay geometry check failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
