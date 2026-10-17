//! Shares the full executable's compact loader tables without changing session isolation [243][255].
#[path = "../infraternal/relocations.rs"]
mod relocations;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../infraternal/relocations.rs");
    relocations::emit("infraternal-session");
}
