//! Runs the bounded Swift SPS parser against exact picture fixtures on the native helper toolchain [D204,D266], #146.

#[cfg(target_os = "macos")]
#[test]
fn swift_sps_preserves_all_picture_bytes_and_refuses_malformed_parameters() -> std::io::Result<()> {
    use std::{path::PathBuf, process::Command};
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").ok_or_else(|| {
        std::io::Error::other("set CARGO_TARGET_DIR to the job's scratch build directory")
    })?);
    std::fs::create_dir_all(&target)?;
    let binary = target.join(format!("desktop-sps-test-{}", std::process::id()));
    let build = Command::new("swiftc")
        .arg("-O")
        .arg(root.join("native/LowDelaySPS.swift"))
        .arg(root.join("tests/fixtures/sps-test.swift"))
        .arg("-o")
        .arg(&binary)
        .output()?;
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let result = Command::new(&binary)
        .arg(root.join("tests/fixtures"))
        .output();
    std::fs::remove_file(binary)?;
    let result = result?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
