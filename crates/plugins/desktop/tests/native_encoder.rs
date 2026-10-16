//! Exercise real hardware encoder callbacks and access-unit conversion across frames and session reconfiguration (#146).
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn hardware_encoder_delivers_repeated_frames_after_reconfiguration() {
    use std::{path::PathBuf, process::Command};
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR")
            .expect("set CARGO_TARGET_DIR to the job's scratch build directory"),
    );
    std::fs::create_dir_all(&target).unwrap();
    let binary = target.join(format!("desktop-encoder-test-{}", std::process::id()));
    let build = Command::new("swiftc")
        .arg("-O")
        .args([
            root.join("native/CaptureState.swift"),
            root.join("native/LowDelaySPS.swift"),
            root.join("native/Encoder.swift"),
            root.join("tests/fixtures/encoder-session-test.swift"),
        ])
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let result = Command::new(&binary).output();
    std::fs::remove_file(binary).unwrap();
    let result = result.unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
