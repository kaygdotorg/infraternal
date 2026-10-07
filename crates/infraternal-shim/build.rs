//! Build the pinned libghostty-vt archive and our read-only snapshot adapter [7][20][94].
use std::{env, path::PathBuf, process::Command};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("Cargo manifest directory missing")?);
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("Cargo output directory missing")?);
    for path in ["build.rs", "native/snapshot.zig", "../../scripts/build-vt"] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=TARGET");
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
