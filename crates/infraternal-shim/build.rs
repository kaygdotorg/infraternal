//! Build the signed libghostty-vt archive and bounded state adapter [7][20][94].
use std::{env, path::PathBuf, process::Command};
/// Builds the pinned native terminal archive and emits its Rust link settings.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    // Linux and macOS shims own terminal state through the same pinned engine
    // (D94, #328); other targets have no session engine to link it into.
    if target_os != "linux" && target_os != "macos" {
        return Ok(());
    }
    let root =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("Cargo manifest directory missing")?);
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo output directory missing")?);
    for path in [
        "build.rs",
        "native/snapshot.zig",
        "native/memory.zig",
        "native/history.zig",
        "../../scripts/build-vt",
        "../../scripts/patch-libghostty-vt.py",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PROCESS_PER_USER");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_COMPACT_HISTORY");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_VT_TEST_INPUT");
    let status = Command::new(root.join("../../scripts/build-vt"))
        .arg(&output)
        .status()?;
    if !status.success() {
        return Err("pinned libghostty-vt build failed".into());
    }
    println!(
        "cargo:rustc-link-search=native={}/native/lib",
        output.display()
    );
    println!("cargo:rustc-link-lib=static=ghostty-vt");
    Ok(())
}
