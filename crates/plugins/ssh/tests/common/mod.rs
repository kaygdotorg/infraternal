//! Gives every SSH fixture one job-specific HOME-cache root without changing HOME or using the shared RAM tmpfs.
#![allow(clippy::expect_used)]

use std::path::PathBuf;

pub fn scratch() -> PathBuf {
    let root = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").expect("HOME for test scratch"))
                .join(".cache/codex-scratch/ssh-bootstrap")
        },
        PathBuf::from,
    );
    std::fs::create_dir_all(&root).expect("prepare job scratch");
    root
}
