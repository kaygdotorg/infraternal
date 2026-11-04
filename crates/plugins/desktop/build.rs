//! Build the small AppKit-session companion only for the explicit macOS desktop feature [D198,D203].
//!
//! Only when the `desktop` feature is on and the target is macOS, this script
//! compiles the Swift sources in `native/` into one executable,
//! `infraternal-desktop-native` in `OUT_DIR`, and adds the linker settings the
//! Swift runtime needs. In every other build it does nothing. It needs the
//! macOS Swift toolchain (`xcrun`, `swiftc`) and panics with a short message
//! if that is missing.
use std::{env, path::PathBuf, process::Command};
/// Build-script entry point; see the module docs for what it does and when.
fn main() {
    println!("cargo:rerun-if-changed=native");
    if env::var_os("CARGO_FEATURE_DESKTOP").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
    {
        return;
    }
    // The wrapper's Swift bridge needs the system concurrency runtime when this
    // executable is launched outside Xcode or a Swift-generated app bundle.
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    // Debug/test links retain the wrapper's Swift compatibility archive; resolve
    // it from the selected toolchain instead of assuming a particular installation.
    let Ok(swift) = Command::new("xcrun").args(["--find", "swiftc"]).output() else {
        panic!("macOS toolchain lookup failed")
    };
    assert!(swift.status.success(), "macOS Swift toolchain unavailable");
    let Ok(swift_name) = String::from_utf8(swift.stdout) else {
        panic!("Invalid Swift toolchain path")
    };
    let swift_path = PathBuf::from(swift_name.trim());
    let Some(toolchain) = swift_path.parent().and_then(std::path::Path::parent) else {
        panic!("Invalid Swift toolchain layout")
    };
    println!(
        "cargo:rustc-link-search=native={}",
        toolchain.join("lib/swift/macosx").display()
    );
    println!("cargo:rustc-link-arg=-mmacosx-version-min=14.2");
    let Some(out) = env::var_os("OUT_DIR") else {
        return;
    };
    let path = PathBuf::from(out).join("infraternal-desktop-native");
    // Pin the companion to the deployment target the crate links with, instead
    // of the SDK default (the host OS), so Info.plist's minimum is honest.
    let arch = if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        "x86_64"
    } else {
        "arm64"
    };
    let status = Command::new("swiftc")
        .args([
            "-target",
            &format!("{arch}-apple-macos14.2"),
            "-O",
            "-whole-module-optimization",
            "native/ResponsibleLaunch.swift",
            "native/Permissions.swift",
            "native/CaptureState.swift",
            "native/FrameDamage.swift",
            "native/FramePixels.swift",
            "native/Inventory.swift",
            "native/Geometry.swift",
            "native/Input.swift",
            "native/LowDelaySPS.swift",
            "native/Encoder.swift",
            "native/SurfaceCapture.swift",
            "native/main.swift",
            "-o",
        ])
        .arg(&path)
        .status();
    assert!(
        status.is_ok_and(|s| s.success()),
        "The macOS desktop companion requires the macOS Swift toolchain."
    );
}
