//! Verify Mesh can be removed from the core server dependency graph as required by D198 (#108).
#![allow(clippy::expect_used)] // Fail immediately when Cargo metadata cannot be read.
use serde_json::Value;

#[test]
fn review_mesh_dependency_is_removable_at_build_time() {
    let metadata = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--no-default-features",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("read workspace dependency metadata");
    assert!(metadata.status.success());
    let metadata: Value = serde_json::from_slice(&metadata.stdout).expect("valid Cargo metadata");
    let server = metadata["packages"]
        .as_array()
        .expect("workspace packages")
        .iter()
        .find(|package| package["name"] == "infraternal-server")
        .expect("server package");
    assert!(
        server["dependencies"]
            .as_array()
            .expect("server dependencies")
            .iter()
            .all(|dependency| dependency["name"] != "infraternal-mesh"),
        "core must not depend directly on Mesh policy implementation"
    );
    let mesh = server["dependencies"]
        .as_array()
        .expect("server dependencies")
        .iter()
        .find(|dependency| dependency["name"] == "infraternal-plugin-mesh")
        .expect("Mesh plugin dependency");
    assert_eq!(
        mesh["optional"], true,
        "a no-default-features server retains the mandatory Mesh dependency"
    );
}
