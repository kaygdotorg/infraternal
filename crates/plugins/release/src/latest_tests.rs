//! Runtime cancellation must finish bounded verification before staging cleanup [198].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use crate::{
    latest::{DownloadError, ReleaseEngine, VerifiedLookup},
    service::ReleaseLookup,
};
use infraternal_plugin_api::Operation;
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

fn private_stage(state: &Path, suffix: &str, file_name: &str, mode: u32) -> PathBuf {
    let path = state.join(format!("release-check-{suffix}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path.join(file_name))
        .unwrap();
    file.write_all(b"partial metadata").unwrap();
    file.sync_all().unwrap();
    path
}

#[test]
fn startup_reclaims_only_owned_inactive_private_metadata() {
    use nix::fcntl::{Flock, FlockArg};
    use std::os::unix::fs::symlink;

    let state = PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join(format!("release-staging-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    let abandoned = private_stage(
        &state,
        &uuid::Uuid::new_v4().hyphenated().to_string(),
        "SHA256SUMS",
        0o600,
    );
    let active = private_stage(
        &state,
        &uuid::Uuid::new_v4().hyphenated().to_string(),
        "SHA256SUMS",
        0o600,
    );
    let active_lock = Flock::lock(
        std::fs::File::open(&active).unwrap(),
        FlockArg::LockExclusiveNonblock,
    )
    .unwrap();
    let unrelated = private_stage(&state, "not-a-uuid", "SHA256SUMS", 0o600);
    let linked = private_stage(
        &state,
        &uuid::Uuid::new_v4().hyphenated().to_string(),
        "SHA256SUMS",
        0o600,
    );
    std::fs::hard_link(linked.join("SHA256SUMS"), state.join("retained-link")).unwrap();
    let unsafe_mode = private_stage(
        &state,
        &uuid::Uuid::new_v4().hyphenated().to_string(),
        "SHA256SUMS",
        0o644,
    );
    let unknown = private_stage(
        &state,
        &uuid::Uuid::new_v4().hyphenated().to_string(),
        "unrelated",
        0o600,
    );
    let symlinked = state.join(format!(
        "release-check-{}",
        uuid::Uuid::new_v4().hyphenated()
    ));
    symlink(&active, &symlinked).unwrap();

    let _lookup = VerifiedLookup::new(
        state.clone(),
        "https://fixture.invalid".into(),
        Arc::new(Engine {
            running: Arc::new(AtomicBool::new(false)),
            started: Arc::new(tokio::sync::Notify::new()),
        }),
    );

    assert!(
        !abandoned.exists(),
        "owned abandoned metadata must be reclaimed"
    );
    for retained in [&active, &unrelated, &linked, &unsafe_mode, &unknown] {
        assert!(retained.exists(), "preserve {}", retained.display());
    }
    assert!(
        std::fs::symlink_metadata(&symlinked)
            .unwrap()
            .file_type()
            .is_symlink(),
        "a prefixed symlink must remain a symlink"
    );
    drop(active_lock);
    std::fs::remove_dir_all(state).unwrap();
}

struct Engine {
    running: Arc<AtomicBool>,
    started: Arc<tokio::sync::Notify>,
}
impl ReleaseEngine for Engine {
    fn download<'a>(
        &'a self,
        address: &'a str,
        destination: &'a Path,
        _max: u64,
    ) -> Operation<'a, Result<(), DownloadError>> {
        Box::pin(async move {
            let bytes = if address.ends_with("stable.json") {
                br#"{"version":"0.1.0"}"#.as_slice()
            } else if address.ends_with("VERSION") {
                b"0.1.0\n".as_slice()
            } else {
                b"fixture".as_slice()
            };
            std::fs::write(destination, bytes).unwrap();
            Ok(())
        })
    }
    fn verify_version(
        &self,
        _file: &std::fs::File,
        _sums: &[u8],
        _signature: &[u8],
    ) -> Result<(), &'static str> {
        self.running.store(true, Ordering::SeqCst);
        self.started.notify_one();
        std::thread::sleep(std::time::Duration::from_millis(250));
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_joins_verification() {
    let state = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
        .join(format!("release-cancel-{}", uuid::Uuid::new_v4()));
    // Staging requires its existing state parent to be service-private.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    let running = Arc::new(AtomicBool::new(false));
    let started = Arc::new(tokio::sync::Notify::new());
    let lookup = VerifiedLookup::new(
        state.clone(),
        "http://127.0.0.1".into(),
        Arc::new(Engine {
            running: running.clone(),
            started: started.clone(),
        }),
    );
    let mut task = tokio::spawn(async move { lookup.latest("stable").await });
    tokio::select! {
        biased;
        () = started.notified() => (),
        result = &mut task => panic!("lookup ended before verifier: {result:?}"),
    }
    task.abort();
    let _ = task.await;
    let detached = running.load(Ordering::SeqCst);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 0);
    std::fs::remove_dir(&state).unwrap();
    assert!(!detached, "verification outlived cancelled plugin task");
}
