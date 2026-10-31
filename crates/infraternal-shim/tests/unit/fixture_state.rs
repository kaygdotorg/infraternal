//! Short per-run socket state paths for native fixtures, independent of build and home paths.
use std::{
    fs::DirBuilder,
    ops::Deref,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// Retains the private parent while callers pass path copies to real sessions.
pub(crate) struct FixtureState {
    path: PathBuf,
    private_root: Option<PathBuf>,
}

impl Deref for FixtureState {
    type Target = PathBuf;

    fn deref(&self) -> &PathBuf {
        &self.path
    }
}

impl AsRef<std::path::Path> for FixtureState {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

impl AsRef<std::ffi::OsStr> for FixtureState {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }
}

impl Drop for FixtureState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
        if let Some(root) = &self.private_root {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

pub(crate) fn fixture_state() -> FixtureState {
    let default_root = PathBuf::from(std::env::var_os("HOME").expect("HOME for test scratch"))
        .join(".cache/codex-scratch/infraternal");
    let root = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or(default_root, PathBuf::from);
    fixture_state_in(&root)
}

fn fixture_state_in(root: &std::path::Path) -> FixtureState {
    let name = format!(
        "p{:x}-{:x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let fits = |root: &std::path::Path| {
        // Include the relay's longer suffix, just as the Python fixtures do.
        let socket = root
            .join(&name)
            .join("sessions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.upstream");
        nix::sys::socket::UnixAddr::new(&socket).is_ok()
    };
    // mkdtemp creates a private, unique parent atomically. Explicit /tmp keeps
    // the fallback independent of both HOME and TMPDIR, including deep builds.
    let private_root = (!fits(root)).then(|| {
        nix::unistd::mkdtemp("/tmp/if-XXXXXX").expect("create private socket fixture root")
    });
    let root = private_root.as_deref().unwrap_or(root);
    assert!(
        fits(root),
        "test state path is too long for an AF_UNIX socket after fallback: {}",
        root.join(&name).display()
    );
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)
        .expect("prepare test state parent directories");
    // Leave the state itself absent for startup-refusal tests. The session
    // constructor must still create and validate its own private directory.
    FixtureState {
        path: root.join(name),
        private_root,
    }
}

#[test]
fn deep_root_keeps_real_sockets_private_and_cleans_up_on_drop() {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};

    let fixture =
        fixture_state_in(&PathBuf::from("/unavailable").join("deep-worktree-".repeat(12)));
    let parent = fixture.parent().unwrap().to_path_buf();
    assert_eq!(parent.parent().unwrap(), std::path::Path::new("/tmp"));
    assert_eq!(
        std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(!fixture.exists(), "startup-refusal tests need absent state");
    std::fs::create_dir_all(fixture.join("sessions")).unwrap();
    for suffix in ["sock", "upstream"] {
        let path = fixture.join(format!("sessions/{}.{}", "a".repeat(32), suffix));
        drop(UnixListener::bind(path).unwrap());
    }
    drop(fixture);
    assert!(!parent.exists());
}
