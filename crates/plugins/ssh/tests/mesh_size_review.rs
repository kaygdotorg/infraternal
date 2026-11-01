//! Reproduce the declared static-size gate against a built submitted-head artifact.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
#[ignore = "Run after the submitted-head aarch64 static release build with CARGO_TARGET_DIR set"]
fn arm_shipping_artifact_matches_its_declared_size() {
    let target = std::env::var_os("CARGO_TARGET_DIR").expect("set the release artifact directory");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = std::process::Command::new("bash")
        .args([
            "-c",
            "source \"$1\"; rust_check_static_binary aarch64-unknown-linux-musl",
            "size-review",
        ])
        .arg(root.join("scripts/verify.d/rust.sh"))
        .current_dir(&root)
        .env("CARGO_TARGET_DIR", target)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "static size check refused the built artifact: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
