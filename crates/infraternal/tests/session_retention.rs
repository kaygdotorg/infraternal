//! Real-shim retention expiry and typed status after daemon restart [D13,D41,D218], #151.
#![allow(clippy::unwrap_used)]

#[test]
fn bounded_owned_exit_reconnects_as_ended_with_status() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("python3")
        .current_dir(root)
        .env("INFRATERNAL_TEST_RTT", "0")
        .args([
            "scripts/verify-session-retention.py",
            "--binary",
            env!("CARGO_BIN_EXE_infraternal"),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
