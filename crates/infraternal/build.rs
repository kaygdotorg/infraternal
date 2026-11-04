//! Compacts relative relocations for the single Linux CLI, reducing loader-resident tables without changing profiles, protocol or the pinned linker [7][41][167], #78.

#[path = "relocations.rs"]
mod relocations;

/// Build-script entry point: links the compact-relocation settings for the `infraternal`
/// binary and, on Linux builds that include the stdin import adapter, the handoff note.
fn main() {
    handoff_note();
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
