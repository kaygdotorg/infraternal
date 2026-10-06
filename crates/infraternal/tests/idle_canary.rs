//! Exercise the Linux scheduler wakeup observer with a real timed process.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{path::PathBuf, process::Command};

#[test]
fn one_hertz_wakeup_is_detected_past_the_legacy_half_second_window() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .current_dir(root)
        .arg("scripts/test-idle-canary.py")
        .output()
        .expect("launch scheduler wakeup fixture");
    assert!(
        output.status.success(),
        "scheduler wakeup canary failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
