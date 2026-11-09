//! Public C mouse encoder continuations against the built native adapter [13][40].
#![cfg(feature = "vt-test-input")]
#![allow(clippy::unwrap_used)]
use std::{fs, path::PathBuf, process::Command};

#[test]
fn faithful_snapshot_preserves_public_mouse_encoder_reports() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let evidence = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".cache/codex-scratch/infraternal-shim-tests/evidence")
        .join(format!("mouse-{}", std::process::id()));
    fs::create_dir_all(&evidence).unwrap();
    let output = Command::new("python3")
        .current_dir(&root)
        .args(["scripts/verify-vt-native.py", "mouse", "--evidence"])
        .arg(&evidence)
        // Match the exact native library linked by this feature build. A
        // newer default-feature archive must not hide feature-specific faults.
        .arg("--library")
        .arg(PathBuf::from(env!("OUT_DIR")).join("native/lib/libghostty-vt.a"))
        .output()
        .unwrap();
    fs::write(evidence.join("stdout.log"), output.stdout).unwrap();
    fs::write(evidence.join("stderr.log"), output.stderr).unwrap();
    assert!(
        output.status.success(),
        "public mouse encoder probe failed; see t2-gate-public"
    );
}
