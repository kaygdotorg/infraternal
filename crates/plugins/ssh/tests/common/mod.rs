//! Gives SSH fixtures owned roots short enough for their longest Linux Unix-socket path.
#![allow(clippy::expect_used)]

use std::{ops::Deref, os::unix::ffi::OsStrExt, path::PathBuf};

const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;
const RECOVERY_SOCKET_SUFFIX_BYTES: usize = 72;

/// Must outlive fixture children; only a private fallback is removed on drop.
pub struct ScratchRoot {
    path: PathBuf,
    private: bool,
}

impl Deref for ScratchRoot {
    type Target = PathBuf;

    fn deref(&self) -> &PathBuf {
        &self.path
    }
}

impl AsRef<std::path::Path> for ScratchRoot {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

impl AsRef<std::ffi::OsStr> for ScratchRoot {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        if self.private {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

pub fn scratch() -> ScratchRoot {
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME for test scratch"));
    let process_id = format!("{:x}", std::process::id());
    let default_root = home.join(".cache").join(&process_id);
    let requested = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map(PathBuf::from);
    scratch_root(requested, default_root)
}

/// Gives the ownership fixtures a short runtime root while honoring their
/// dedicated override before the workspace-wide test root.
#[allow(
    dead_code,
    reason = "Used by the recovery-support integration fixture."
)]
pub fn recovery_scratch() -> ScratchRoot {
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME for test scratch"));
    let process_id = format!("{:x}", std::process::id());
    let default_root = home.join(".cache").join(&process_id);
    let requested = std::env::var_os("INFRATERNAL_SSH_TEST_STATE_ROOT")
        .or_else(|| std::env::var_os("INFRATERNAL_TEST_SOCKET_ROOT"))
        .or_else(|| std::env::var_os("INFRATERNAL_TEST_STATE_ROOT"))
        .or_else(|| std::env::var_os("XDG_RUNTIME_DIR"))
        .map(PathBuf::from);
    scratch_root(requested, default_root)
}

fn scratch_root(requested: Option<PathBuf>, default_root: PathBuf) -> ScratchRoot {
    let process_id = format!("{:x}", std::process::id());
    // The recovery socket adds a 72-byte suffix and a process-id/sequence
    // directory of at most eight bytes. Reserve one separator before the
    // Linux 107-byte pathname limit; the kernel adds the terminating NUL.
    let max_root_bytes =
        MAX_UNIX_SOCKET_PATH_BYTES - RECOVERY_SOCKET_SUFFIX_BYTES - 1 - process_id.len() - 2;
    let requested = requested.unwrap_or(default_root);
    let private = requested.as_os_str().as_bytes().len() > max_root_bytes;
    let root = if private {
        // The owner outlives each fixture, including any child using its paths.
        // HOME and TMPDIR cannot provide a bounded socket-path fallback.
        nix::unistd::mkdtemp("/tmp/is-XXXXXX").expect("create private SSH fixture root")
    } else {
        requested
    };
    assert!(
        root.as_os_str().as_bytes().len() <= max_root_bytes,
        "SSH test fallback root exceeds the Unix socket path budget"
    );
    std::fs::create_dir_all(&root).expect("prepare job scratch");
    ScratchRoot {
        path: root,
        private,
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn deep_scratch_fallback_is_private_short_and_owned() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};

    let deep = PathBuf::from("/unavailable").join("deep-worktree-".repeat(12));
    let scratch = scratch_root(Some(deep.clone()), deep);
    let path = scratch.path.clone();
    assert_eq!(path.parent().unwrap(), std::path::Path::new("/tmp"));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // Exercise the full reserved suffix, including the fixture's subdirectory.
    let socket = path.join("a".repeat(RECOVERY_SOCKET_SUFFIX_BYTES + 8));
    drop(UnixListener::bind(socket).unwrap());
    drop(scratch);
    assert!(!path.exists());
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
# Publish a private socket at bind; chmod afterwards can race the client's
# strict metadata check when the fixture is preempted on a loaded host.
os.umask(0o177)
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

/// The example compiles the shipping runtime guard, without a duplicate probe.
#[allow(dead_code, clippy::unwrap_used)]
pub fn runtime_helper() -> PathBuf {
    std::env::var_os("INFRATERNAL_TEST_RUNTIME_HELPER").map_or_else(
        || {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("examples/recovery-helper")
        },
        PathBuf::from,
    )
}
