//! Exercises real CLI refusal output without reading enrolled identity or CA material [202], #78.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::{
    path::PathBuf,
    process::{Command, Output},
};

fn binary() -> std::ffi::OsString {
    // An explicit opt-in also checks the stripped shipping executable, using the same assertions.
    std::env::var_os("INFRATERNAL_REMOTE_OUTPUT_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_infraternal").into())
}

fn missing_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.scratch")
        .join(format!("json-output-{}", uuid::Uuid::new_v4()))
}
fn refusal(output: &Output, action: &str) {
    assert!(!output.status.success());
    assert!(
        output.stderr.is_empty(),
        "JSON refusals must not mix human diagnostics into stderr"
    );
    let text = std::str::from_utf8(&output.stdout).unwrap();
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("each output line is JSON"))
        .collect();
    let final_record = records
        .last()
        .expect("a machine-readable refusal is emitted");
    assert_eq!(final_record["action"], action);
    assert_eq!(final_record["state"], "refused");
    assert_ne!(final_record["message"].as_str().unwrap(), "");
    assert_ne!(final_record["next"].as_str().unwrap(), "");
}

#[test]
fn json_remote_run_refuses_missing_identity_without_reflecting_its_path() {
    let root = missing_root();
    let output = Command::new(binary())
        .args(["agent", "--data"])
        .arg(&root)
        .args(["run", "--json"])
        .output()
        .unwrap();
    refusal(&output, "remote.host.run");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(root.to_str().unwrap()));
    assert!(!root.exists());
}

#[test]
fn json_remote_server_refuses_before_creating_storage_or_binding() {
    let root = missing_root();
    let output = Command::new(binary())
        .args(["server", "--data"])
        .arg(root.join("db"))
        .args(["--remote-listen", "10.69.69.125:7443", "--remote-ca-dir"])
        .arg(root.join("ca"))
        .arg("--json")
        .output()
        .unwrap();
    refusal(&output, "remote.server.serve");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(root.to_str().unwrap()));
    assert!(!root.exists());
}

#[test]
fn human_remote_refusal_has_sections_and_next_steps_without_color() {
    let root = missing_root();
    let output = Command::new(binary())
        .args(["agent", "--data"])
        .arg(&root)
        .arg("run")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = std::str::from_utf8(&output.stderr).unwrap();
    assert!(error.starts_with("Remote infraternal agent\n"));
    assert!(error.contains("  State   refused\n"));
    assert!(error.contains("  Next    "));
    assert!(!error.contains('\u{1b}'));
    assert!(!error.contains(root.to_str().unwrap()));
    assert!(!root.exists());
}
