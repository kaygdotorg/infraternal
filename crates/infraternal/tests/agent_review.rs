//! Deterministic real-shim regressions for multiplexing, Snapshot credit and restart [13][41][81].
#![allow(clippy::unwrap_used)]
use std::{path::PathBuf, process::Command};

fn probe(script: &str) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg(script)
        .args(["--binary", env!("CARGO_BIN_EXE_infraternal")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{script}:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn retained_unwritten_input_survives_interleaved_ack_restart() {
    probe("scripts/verify-agent-resume.py");
}
#[test]
fn stalled_terminal_never_delays_control_or_sibling_dispatch() {
    probe("scripts/verify-agent-isolation.py");
}
#[test]
fn repeated_tiny_credit_pauses_preserve_shell_progress() {
    probe("scripts/verify-agent-snapshot.py");
}

#[test]
fn two_writers_keep_independent_ack_and_exact_input_after_restart() {
    probe("scripts/verify-agent-multi.py");
}

#[test]
fn last_typist_selects_its_own_real_pty_dimensions() {
    probe("scripts/verify-agent-writer-size.py");
}

#[test]
fn initial_attach_requires_explicit_credit_before_replay() {
    probe("scripts/verify-agent-attach-credit.py");
}
