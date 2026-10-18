//! Exercises the shipping CLI's key-free D244 diagnostic in fresh limited processes, #154.
#![cfg(feature = "remote")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

#[test]
fn diagnostic_requires_locked_pages_and_supports_json_without_public_help() {
    let binary = env!("CARGO_BIN_EXE_infraternal");
    let output = Command::new("prlimit")
        .args([
            "--memlock=8388608",
            "--",
            binary,
            "__key-memory-check",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "key memory refused under 8 MiB");
    assert_eq!(output.stderr, [] as [u8; 0]);
    let record: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["command"], "__key-memory-check");
    assert_eq!(record["ok"], true);
    assert_eq!(record["state"], "ready");
    assert_eq!(
        record["message"],
        "Key memory initialization=1; locked pages and dump exclusion enabled"
    );
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(
        !String::from_utf8(help.stdout)
            .unwrap()
            .contains("__key-memory-check")
    );

    // CAP_IPC_LOCK can override RLIMIT_MEMLOCK for privileged runners. The
    // ordinary user gate proves that partial protection is never accepted.
    if !nix::unistd::geteuid().is_root() {
        let refused = Command::new("prlimit")
            .args(["--memlock=0", "--", binary, "__key-memory-check", "--json"])
            .output()
            .unwrap();
        assert_eq!(refused.status.code(), Some(1));
        assert_eq!(refused.stderr, [] as [u8; 0]);
        let record: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
        assert_eq!(record["state"], "refused");
        assert_eq!(record["ok"], false);
        assert_eq!(record["error"]["code"], "failed");
        assert_eq!(record["message"], "Key memory refused");
    }
}
