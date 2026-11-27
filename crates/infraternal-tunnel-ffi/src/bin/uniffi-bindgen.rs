//! Runs the UniFFI generator from the same pinned version as this crate.

/// Run the version-matched UniFFI command-line generator.
fn main() {
    uniffi::uniffi_bindgen_main();
}
