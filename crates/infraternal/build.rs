//! Compacts relative relocations for the single Linux CLI, reducing loader-resident tables without changing profiles, protocol or the pinned linker [7][41][167], #78.

#[path = "relocations.rs"]
mod relocations;

fn main() {
    handoff_note();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=relocations.rs");
    relocations::emit("infraternal");
}

/// Emit a compatibility note only when the stdin import adapter is compiled.
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
