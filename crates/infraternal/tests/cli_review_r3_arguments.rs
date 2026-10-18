//! Checks that inherited parser stubs preserve descriptor validation for operator commands (#239).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Stdio};

use serde_json::Value;

#[test]
fn inherited_fd_is_rejected_instead_of_ignored_by_remote_commands() {
    // The internal descriptor is incompatible with enrollment/reconnect. Losing its integer
    // parser makes try_get_one::<i64> discard it and lets a different operation start.
    let missing = std::env::temp_dir().join(format!(
        "infraternal-review-r3-missing-identity-{}",
        std::process::id()
    ));
    assert!(!missing.exists());
    for descriptor in ["999", "not-an-integer"] {
        for command in [vec!["run"], vec!["join", "https://example.invalid"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_infraternal"))
                .args(["--json", "agent"])
                .args(&command)
                .args(["--fd", descriptor, "--data"])
                .arg(&missing)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "{command:?} --fd {descriptor}: {envelope}"
            );
            assert_eq!(envelope["error"]["code"], "usage", "{envelope}");
        }
    }
    assert!(!missing.exists());
}
