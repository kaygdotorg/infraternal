//! Verify Linux THP policy on real shim and shell processes (#24).
#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

#[test]
fn shim_disables_thp_without_changing_child_policy() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("python3")
        .current_dir(root)
        .args([
            "crates/infraternal-shim/tests/thp.py",
            env!("CARGO_BIN_EXE_infraternal"),
        ])
        .output()
        .expect("launch real shim THP check");
    assert!(
        output.status.success(),
        "THP policy check failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
