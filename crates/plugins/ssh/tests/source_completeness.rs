//! Checks that the SSH plugin's declared public modules are present in the checkout (#87).
//! This dependency-free oracle also runs with rustc when an incomplete library prevents Cargo tests.

#[test]
fn declared_public_modules_have_committed_sources() {
    let source = include_str!("../src/lib.rs");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for line in source.lines() {
        if let Some(name) = line
            .strip_prefix("pub mod ")
            .and_then(|v| v.strip_suffix(';'))
        {
            assert!(
                root.join(format!("{name}.rs")).is_file()
                    || root.join(name).join("mod.rs").is_file(),
                "declared public module {name} has no source file"
            );
        }
    }
}
