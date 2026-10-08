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

/// A foreground fake master owns a private socket for public-option tests only.
/// Real authentication, connection reuse and trust are tested by the sshd fixture.
#[allow(
    dead_code,
    reason = "Shared fixture is also compiled into tests without an SSH master."
)]
pub fn master_fixture(root: &std::path::Path) -> PathBuf {
    let path = root.join("master.py");
    std::fs::write(
        &path,
        r#""""Own a synthetic control socket until the test's process-group scope retires."""
import os
import socket
import sys
import time
path = sys.argv[sys.argv.index('-S') + 1]
listener = socket.socket(socket.AF_UNIX)
listener.bind(path)
os.chmod(path, 0o600)
listener.listen(1)
while True:
    time.sleep(3600)
"#,
    )
    .expect("write public-policy master fixture");
    path
}
