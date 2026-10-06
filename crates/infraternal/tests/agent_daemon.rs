//! Exercise inherited leg B and randomized and barrier-controlled abrupt daemon stops/restarts through the real binary [9][13][41].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::{path::PathBuf, process::Command};

#[test]
fn real_binary_preserves_input_and_output_across_24_abrupt_stops() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("scripts/verify-agent.py")
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_infraternal"),
            "--functional",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "real-binary daemon oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
