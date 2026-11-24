//! Generates the Swift and C glue for `src/lib.rs` into `generated/`.
/// Parses the bridge module and writes the generated files.
fn main() {
    let out = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("generated");
    println!("cargo:rerun-if-changed=src/lib.rs");
    swift_bridge_build::parse_bridges(vec!["src/lib.rs"])
        .write_all_concatenated(out, env!("CARGO_PKG_NAME"));
}
