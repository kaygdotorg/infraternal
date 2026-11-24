//! The UniFFI binding generator, built from the same UniFFI version as the
//! library so the generated Swift always matches the scaffolding.
/// Runs `uniffi-bindgen` with the process arguments.
fn main() {
    uniffi::uniffi_bindgen_main()
}
