//! Compacts relative relocations for the single Linux CLI, reducing loader-resident tables without changing profiles, protocol or the pinned linker [7][41][167], #78.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
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
        "gnu" => println!("cargo:rustc-link-arg-bin=infraternal=-Wl,-z,pack-relative-relocs"),
        // The pinned bundled musl CRT handles RELR before entering main, so
        // the shipped static PIE retains its independence from host libc.
        // Its configured linker is already LLD directly, not a compiler driver.
        "musl" => {
            println!("cargo:rustc-link-arg-bin=infraternal=-z");
            println!("cargo:rustc-link-arg-bin=infraternal=pack-relative-relocs");
        }
        _ => {}
    }
}
