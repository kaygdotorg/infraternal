//! Independently checks metadata staging retention across real process stops [198,226; #157].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_api::Operation;
use infraternal_plugin_release::{
    latest::{DownloadError, ReleaseEngine, VerifiedLookup},
    service::ReleaseLookup,
};
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

struct PartialEngine;
fn write_metadata(destination: &Path, bytes: &[u8]) {
    // Match the production downloader's private, newly created regular files,
    // so a safe restart collector can recognize this fixture as eligible.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
impl ReleaseEngine for PartialEngine {
    fn download<'a>(
        &'a self,
        address: &'a str,
        destination: &'a Path,
        _max: u64,
    ) -> Operation<'a, Result<(), DownloadError>> {
        Box::pin(async move {
            if address.ends_with("stable.json") {
                write_metadata(destination, br#"{"version":"0.1.0"}"#);
                return Ok(());
            }
            // A fully bounded body is on disk while the transport is still pending.
            // The parent stops this process, so Rust destructors cannot reclaim it.
            write_metadata(destination, &vec![b'x'; 65536]);
            std::future::pending().await
        })
    }
    fn verify_version(
        &self,
        _file: &std::fs::File,
        _sums: &[u8],
        _sig: &[u8],
    ) -> Result<(), &'static str> {
        unreachable!("partial metadata must never reach verification")
    }
}
struct EmptyEngine;
impl ReleaseEngine for EmptyEngine {
    fn download<'a>(
        &'a self,
        _address: &'a str,
        _destination: &'a Path,
        _max: u64,
    ) -> Operation<'a, Result<(), DownloadError>> {
        Box::pin(async { Err(DownloadError::Missing) })
    }
    fn verify_version(
        &self,
        _file: &std::fs::File,
        _sums: &[u8],
        _sig: &[u8],
    ) -> Result<(), &'static str> {
        unreachable!("an empty channel must never reach verification")
    }
}

#[test]
#[ignore = "subprocess helper for restricted-umask lookup verification"]
fn restricted_umask_lookup_child() {
    let state =
        PathBuf::from(std::env::var_os("REVIEW_UMASK_STATE").expect("state path must be supplied"));
    let lookup = VerifiedLookup::new(
        state,
        "https://fixture.invalid".into(),
        Arc::new(EmptyEngine),
    );
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(lookup.latest("stable"))
        .expect("private staging must be created under a restrictive umask");
}

#[test]
#[ignore = "subprocess helper for metadata restart verification"]
fn partial_metadata_restart_child() {
    let Some(state) = std::env::var_os("REVIEW_METADATA_STATE") else {
        return;
    };
    let lookup = VerifiedLookup::new(
        PathBuf::from(state),
        "https://fixture.invalid".into(),
        Arc::new(PartialEngine),
    );
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(lookup.latest("stable"))
        .unwrap();
}

struct State(PathBuf);
impl Drop for State {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn partial_paths(state: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(state)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("release-check-")
        })
        .filter(|entry| {
            std::fs::metadata(entry.path().join("SHA256SUMS"))
                .is_ok_and(|metadata| metadata.len() == 65536)
        })
        .map(|entry| entry.path())
        .collect()
}
fn partial_bytes(state: &Path) -> u64 {
    partial_paths(state)
        .iter()
        .map(|path| std::fs::metadata(path.join("SHA256SUMS")).map_or(0, |metadata| metadata.len()))
        .sum()
}

#[tokio::test]
async fn restarted_latest_reclaims_metadata_after_process_stop() {
    let state = State(
        PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
            .join(format!("review-metadata-{}", uuid::Uuid::new_v4())),
    );
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state.0)
        .unwrap();
    for stop in 1..=2 {
        let previous = partial_paths(&state.0);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "partial_metadata_restart_child", "--ignored"])
            .env("REVIEW_METADATA_STATE", &state.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !partial_paths(&state.0)
            .iter()
            .any(|path| !previous.contains(path))
        {
            assert!(
                child.try_wait().unwrap().is_none(),
                "metadata child stopped early"
            );
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("metadata did not reach its retained-byte boundary");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let retained = partial_paths(&state.0);
        assert_eq!(
            retained.len(),
            1,
            "each new lookup must reclaim metadata from the prior stopped process"
        );
        println!(
            "RELEASE_METADATA_STOP stop={stop} retained_paths={} retained_bytes={}",
            retained.len(),
            partial_bytes(&state.0)
        );
    }
    let before = partial_bytes(&state.0);
    assert_eq!(before, 65536);
    let restarted = VerifiedLookup::new(
        state.0.clone(),
        "https://fixture.invalid".into(),
        Arc::new(EmptyEngine),
    );
    assert_eq!(restarted.latest("stable").await.unwrap()["state"], "empty");
    let after = partial_bytes(&state.0);
    println!(
        "RELEASE_METADATA_RESTART abrupt_stops=2 retained_before_bytes={before} retained_after_bytes={after}"
    );
    assert_eq!(
        after, 0,
        "restarted lookup must reclaim abandoned metadata staging"
    );
}

#[tokio::test]
async fn lookup_creates_private_staging_under_owner_restrictive_umask() {
    let state = State(
        PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap())
            .join(format!("review-umask-{}", uuid::Uuid::new_v4())),
    );
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state.0)
        .unwrap();
    std::fs::set_permissions(&state.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new("sh")
        .args(["-c", "umask 0177; exec \"$@\"", "sh"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", "restricted_umask_lookup_child", "--ignored"])
        .env("REVIEW_UMASK_STATE", &state.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "lookup refused private staging under umask 0177 (exit {})",
        output.status
    );
}
