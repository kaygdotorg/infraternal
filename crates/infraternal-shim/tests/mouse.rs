//! Public C mouse encoder continuations against the built native adapter [13][40].
#![allow(clippy::unwrap_used)]
use std::{fs, path::PathBuf, process::Command};

#[test]
fn faithful_snapshot_preserves_public_mouse_encoder_reports() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let evidence = root.join("target/review-vt3-fixes/t2-gate-public");
    fs::create_dir_all(&evidence).unwrap();
    let output = Command::new("python3")
        .current_dir(&root)
        .args(["scripts/verify-vt-native.py", "mouse", "--evidence"])
        .arg(&evidence)
        .output()
        .unwrap();
    fs::write(evidence.join("stdout.log"), output.stdout).unwrap();
    fs::write(evidence.join("stderr.log"), output.stderr).unwrap();
    assert!(
        output.status.success(),
        "public mouse encoder probe failed; see t2-gate-public"
    );
}
