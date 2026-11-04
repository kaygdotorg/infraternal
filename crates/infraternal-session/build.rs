//! Shares the full executable's compact loader tables without changing session isolation [243][255].
#[path = "../infraternal/relocations.rs"]
mod relocations;

/// Emits the shared loader-relocation settings for the `infraternal-session`
/// target and re-runs only when this script or the shared table changes.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../infraternal/relocations.rs");
    relocations::emit("infraternal-session");
}
