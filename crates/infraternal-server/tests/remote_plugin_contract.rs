//! Verifies that disabling core Cargo features removes remote transport dependencies [198], #78.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::{path::Path, process::Command};

#[test]
fn independent_review_core_build_without_features_omits_remote_transport() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut retained = Vec::new();
    for package in ["infraternal-agent", "infraternal-server"] {
        // Inspect the resolved normal graph rather than manifest spelling: an
        // indirect unconditional dependency also defeats build-time removal.
        // Offline metadata inspection neither builds nor contacts a registry.
        let output = Command::new("cargo")
            .current_dir(workspace)
            .args([
                "tree",
                "--offline",
                "--locked",
                "--no-default-features",
                "--package",
                package,
                "--edges",
                "normal",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ])
            .output()
            .expect("inspect resolved core dependency graph");
        assert!(output.status.success(), "dependency inspection failed");
        let graph = String::from_utf8(output.stdout).unwrap();
        if graph.lines().any(|line| line.starts_with("quinn ")) {
            retained.push(package);
        }
    }
    assert!(
        retained.is_empty(),
        "remote QUIC transport remains in core packages with all default features disabled: {retained:?}"
    );
}
