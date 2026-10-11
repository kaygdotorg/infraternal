//! Stamps one build identity into every adapter and lockstep payload lookup [225,226].
#[path = "src/release_version.rs"]
mod release_version;

fn main() {
    println!("cargo:rerun-if-env-changed=INFRATERNAL_RELEASE_VERSION");
    println!("cargo:rerun-if-env-changed=INFRATERNAL_RELEASE_BUILD");
    println!("cargo:rerun-if-changed=src/release_version.rs");
    let version = std::env::var("INFRATERNAL_RELEASE_VERSION")
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_owned());
    assert!(
        release_version::channel(&version).is_some(),
        "invalid release version"
    );
    if std::env::var_os("INFRATERNAL_RELEASE_VERSION").is_some() {
        assert!(
            std::env::var("INFRATERNAL_RELEASE_BUILD").is_ok_and(|value| value == "1"),
            "release version stamping requires an explicit pipeline build"
        );
    }
    println!("cargo:rustc-env=INFRATERNAL_VERSION={version}");
}
