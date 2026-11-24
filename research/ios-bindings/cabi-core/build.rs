//! Writes `include/cabi_core.h` from the `extern "C"` items in `src/lib.rs`.
/// Runs cbindgen over this crate.
fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rerun-if-changed=src/lib.rs");
    cbindgen::Builder::new()
        .with_crate(dir)
        .with_language(cbindgen::Language::C)
        .with_include_guard("CABI_CORE_H")
        .generate()
        .expect("cbindgen")
        .write_to_file(format!("{dir}/include/cabi_core.h"));
}
