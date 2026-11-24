//! Compacts relative relocations for the single Linux CLI, reducing loader-resident tables without changing profiles, protocol or the pinned linker [7][41][167], #78.

#[path = "relocations.rs"]
mod relocations;

/// Build-script entry point: links the compact-relocation settings for the `infraternal`
/// binary and, on Linux builds that include the stdin import adapter, the handoff note.
fn main() {
    handoff_note();
    macos_info_plist();
    machine_up_cfg();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=relocations.rs");
    relocations::emit("infraternal");
}

/// Adds the `handoff-note.ld` linker script to the link line.
///
/// Only Linux builds with the `remote` feature (the stdin import adapter) get it.
/// musl targets pass the script to the linker directly with `-T`; other targets go
/// through the compiler driver with `-Wl,-T,`. All other builds are left untouched.
fn handoff_note() {
    println!("cargo:rerun-if-changed=handoff-note.ld");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var_os("CARGO_FEATURE_REMOTE").is_some()
        && let Ok(directory) = std::env::var("CARGO_MANIFEST_DIR")
    {
        let flag = if std::env::var("TARGET").is_ok_and(|target| target.ends_with("musl")) {
            "-T"
        } else {
            "-Wl,-T,"
        };
        println!("cargo:rustc-link-arg={flag}{directory}/handoff-note.ld");
    }
}

/// Embeds `macos/Info.plist` in the macOS binary as its `__TEXT,__info_plist` section (#576).
///
/// A plain executable has no bundle, so this section is where macOS finds its bundle identifier
/// and `NSLocalNetworkUsageDescription`: the user-mode infraternal agent is a launchd agent,
/// which needs the person's Local Network permission, and the alert and the System Settings
/// entry name the program from it (Apple's TN3179). Only macOS targets are changed.
fn macos_info_plist() {
    println!("cargo:rerun-if-changed=macos/Info.plist");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
        && let Ok(directory) = std::env::var("CARGO_MANIFEST_DIR")
    {
        println!(
            "cargo:rustc-link-arg-bins=-Wl,-sectcreate,__TEXT,__info_plist,{directory}/macos/Info.plist"
        );
    }
}

/// Declares `cfg(machine_up)`: builds where `infraternal up` can install this
/// machine's system service (#263, #483).
///
/// That is a `remote` build on Linux (systemd), or on macOS with the mesh
/// plugin, because there the service is the mesh `LaunchDaemon`. One name keeps
/// the command's registration, dispatch and module in step; a long `cfg`
/// repeated in each place drifted once already.
fn machine_up_cfg() {
    println!("cargo::rustc-check-cfg=cfg(machine_up)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let remote = std::env::var_os("CARGO_FEATURE_REMOTE").is_some();
    let mesh = std::env::var_os("CARGO_FEATURE_PLUGIN_MESH").is_some();
    if remote && (os == "linux" || (os == "macos" && mesh)) {
        println!("cargo::rustc-cfg=machine_up");
    }
}
