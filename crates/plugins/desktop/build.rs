//! Build the small AppKit-session companion only for the explicit macOS desktop feature [D198,D203].
use std::{env, path::PathBuf, process::Command};
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
    let status = Command::new("swiftc")
        .args([
            "-O",
            "-whole-module-optimization",
            "native/CaptureState.swift",
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
    println!(
        "cargo:rustc-env=INFRATERNAL_DESKTOP_NATIVE={}",
        path.display()
    );
}
