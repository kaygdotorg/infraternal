//! Short per-run socket state paths for native fixtures, independent of build and home paths.
use std::{
    fs::DirBuilder,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) fn fixture_state() -> PathBuf {
    let fallback = PathBuf::from(std::env::var_os("HOME").expect("HOME for test scratch"))
        .join(".cache/codex-scratch/infraternal");
    let root = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT")
        .map_or_else(|| fallback.clone(), PathBuf::from);
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
    let root = if fits(&root) { root } else { fallback };
    assert!(
        fits(&root),
        "test state path is too long for an AF_UNIX socket after fallback: {}",
        root.join(&name).display()
    );
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root)
        .expect("prepare test state parent directories");
    // Leave the state itself absent for startup-refusal tests. The session
    // constructor must still create and validate its own private directory.
    root.join(name)
}
