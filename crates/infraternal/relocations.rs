//! Applies the existing loader-table compaction to Linux `x86_64` executables [167][243].

/// Emit the same linker recipe for a named binary; other architectures retain their defaults.
pub fn emit(binary: &str) {
    let platform = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let environment = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let architecture = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if platform != "linux" || architecture != "x86_64" {
        return;
    }
    match environment.as_str() {
        // GNU developer links need glibc >=2.36 for DT_RELR; the pinned
        // toolchain's existing CLI already requires GLIBC_2.38. GNU's driver
        // also emits the explicit GLIBC_ABI_DT_RELR dependency.
        "gnu" => println!("cargo:rustc-link-arg-bin={binary}=-Wl,-z,pack-relative-relocs"),
        // The pinned bundled musl CRT handles RELR before entering main, so
        // the shipped static PIE retains its independence from host libc.
        // Its configured linker is already LLD directly, not a compiler driver.
        "musl" => {
            println!("cargo:rustc-link-arg-bin={binary}=-z");
            println!("cargo:rustc-link-arg-bin={binary}=pack-relative-relocs");
        }
        _ => {}
    }
}
