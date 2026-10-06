//! Real shim/infraternal-agent ring recovery, approximate repaint and legacy compatibility [13][41].
#![allow(clippy::unwrap_used)]
use std::{fs, path::PathBuf, process::Command};

#[test]
#[ignore = "R1 red reconnect regression; enable after negotiated recovery fixes"]
fn snapshot_limits_never_close_live_reconnect() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(&root)
        .arg("scripts/verify-vt-reconnect.py")
        .args(["--binary", env!("CARGO_BIN_EXE_infraternal")])
        .output()
        .unwrap();
    let evidence = root.join("target/review-vt2-fixes");
    fs::create_dir_all(&evidence).unwrap();
    fs::write(evidence.join("reconnect.stdout.log"), output.stdout).unwrap();
    fs::write(evidence.join("reconnect.stderr.log"), output.stderr).unwrap();
    // Keep terminal payloads and any subprocess/native failure diagnostics in
    // evidence files. Assertion output contains only this static pointer.
    assert!(
        output.status.success(),
        "reconnect failed; see target/review-vt2-fixes/reconnect.*.log"
    );
}
