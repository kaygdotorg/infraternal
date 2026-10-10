//! Tracks auth migrations and marks pipeline-built release binaries for safe payload fallback [225].

fn main() {
    // SQLx tracks existing migration files, but adding one must also rebuild the
    // migrate! invocation. Directory tracking keeps schema-only changes visible.
    println!("cargo:rerun-if-changed=migrations");
    // Release optimization is also used for local development; only the
    // explicit pipeline marker disables development payload fallback.
    println!("cargo:rerun-if-env-changed=INFRATERNAL_RELEASE_BUILD");
    let release = std::env::var("INFRATERNAL_RELEASE_BUILD").is_ok_and(|value| value == "1");
    println!(
        "cargo:rustc-env=INFRATERNAL_RELEASE_BUILD={}",
        if release { "1" } else { "0" }
    );
}
