//! Keeps the real-file Start fresh and ownership oracles in the ordinary native gate (#189).
#![allow(clippy::expect_used)]

use std::process::Command;

#[allow(
    dead_code,
    reason = "This oracle needs only the shared runtime helper path."
)]
mod common;

#[test]
fn shared_ownership_shell_preserves_recovery_and_refusal_invariants() {
    let output = Command::new("python3")
        .env("INFRATERNAL_TEST_RUNTIME_HELPER", common::runtime_helper())
        .env("INFRATERNAL_TEST_STATE_ROOT", common::scratch())
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/previous_attempt_shell.py"
        ))
        .output()
        .expect("run ownership shell oracle");
    assert!(
        output.status.success(),
        "ownership shell oracle failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
