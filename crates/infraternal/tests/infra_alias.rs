//! Runs the real CLI through both names, including help and private role dispatch [349].
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

/// A temporary alias directory, cleaned even if a dispatch assertion fails.
struct Directory(std::path::PathBuf);

impl Drop for Directory {
    /// Remove only this invocation's links.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The invoked filename must not change parsing, canonical help, or private roles.
#[test]
fn infra_and_infraternal_have_identical_output_and_status() {
    let directory =
        Directory(std::env::temp_dir().join(format!("infra-cli-{}", uuid::Uuid::new_v4())));
    fs::create_dir(&directory.0).unwrap();
    let canonical = directory.0.join("infraternal");
    symlink(env!("CARGO_BIN_EXE_infraternal"), &canonical).unwrap();
    let alias = directory.0.join("infra");
    symlink("infraternal", &alias).unwrap();
    for args in [
        vec!["--help"],
        vec!["--version"],
        vec!["server", "--help"],
        vec!["unknown-command"],
        vec!["--json", "unknown-command"],
        vec!["__shim"],
    ] {
        let run = |binary: &Path| Command::new(binary).args(&args).output().unwrap();
        let expected = run(&canonical);
        let actual = run(&alias);
        assert_eq!(actual.status, expected.status, "{args:?}");
        assert_eq!(actual.stdout, expected.stdout, "{args:?}");
        assert_eq!(actual.stderr, expected.stderr, "{args:?}");
    }
}
