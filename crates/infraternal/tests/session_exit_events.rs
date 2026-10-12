//! Real-daemon D81 idle canaries and unsolicited exit censuses after create/adopt [D13,D81], #168.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::{path::PathBuf, process::Command};

#[test]
fn idle_daemon_discovers_unattached_and_adopted_shim_exit_without_requests() {
    let output = Command::new("python3")
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .arg("scripts/verify-session-exit-events.py")
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_infraternal"),
            "--samples",
            "8",
        ])
        .env("INFRATERNAL_TEST_RTT", "0")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "idle/exit oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
