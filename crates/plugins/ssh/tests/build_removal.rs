//! Verifies that disabling compiled plugins removes SSH from the binary's dependency closure [198].
//! Inspects normal dependency closures independently of the test binary's own dev dependencies.
#![allow(clippy::unwrap_used)]

#[test]
fn build_without_default_plugins_excludes_ssh_dependency() {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    for package in ["infraternal", "infraternal-server"] {
        let output = std::process::Command::new("cargo")
            .current_dir(repository)
            .args([
                "tree",
                "--offline",
                "--locked",
                "--package",
                package,
                "--no-default-features",
                "--edges",
                "normal",
                "--prefix",
                "none",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "dependency inspection failed");
        let graph = String::from_utf8(output.stdout).unwrap();
        assert!(
            !graph
                .lines()
                .any(|line| line.starts_with("infraternal-plugin-ssh ")),
            "{package} retains SSH with all default features disabled"
        );
    }
}
