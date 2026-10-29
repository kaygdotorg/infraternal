//! Independent #257 checks pair replay geometry with real restart adoption and Snapshot recovery.
#![cfg(feature = "plugin-agent")]
#![allow(clippy::unwrap_used)]

use std::{path::PathBuf, process::Command};

#[test]
fn adopted_raw_and_snapshot_replays_keep_pre_resize_geometry() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("scripts/verify-agent-replay-size-review.py")
        .args(["--binary", env!("CARGO_BIN_EXE_infraternal")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "adopted replay geometry check failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
