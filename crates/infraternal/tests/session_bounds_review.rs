//! Independent real-shim regression for final output and exit after credit starvation [D13,D41,D178], #151.
#![allow(clippy::unwrap_used)]

use std::{path::PathBuf, process::Command};

#[test]
fn attached_window_recovers_final_output_and_exit_after_shim_link_detaches() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .env("INFRATERNAL_TEST_RTT", "0")
        .args([
            "scripts/verify-session-exit-credit.py",
            "--binary",
            env!("CARGO_BIN_EXE_infraternal"),
            "--exit-after-detach",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "final output and terminal.exited must reach the still-attached window:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
