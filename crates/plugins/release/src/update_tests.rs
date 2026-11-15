//! Unit checks for the updater's version guard, backoff schedule, state file and
//! folder hygiene (#211 S3). Signed end-to-end staging is proven in the server crate
//! (`release_update_tests.rs`), where the real verifier and a loopback bucket exist.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

/// A private scratch folder under the test's TMPDIR, removed on drop.
struct Scratch(PathBuf);
impl Scratch {
    /// Create an empty private folder under TMPDIR.
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("upd-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The periodic guard stages only strictly newer releases on the running channel; explicit requests may go older or switch channels.
#[test]
fn forward_guard_stages_only_newer_releases_on_the_running_channel() {
    use Admission::{Explicit, Forward};
    let edge = "edge-20261114T000000Z";
    assert_eq!(
        guard(edge, "edge-20261114T000001Z", Forward),
        Ok(Verdict::Stage)
    );
    assert_eq!(guard(edge, edge, Forward), Ok(Verdict::Same));
    assert_eq!(guard(edge, edge, Explicit), Ok(Verdict::Same));
    assert_eq!(
        guard(edge, "edge-20261113T235959Z", Forward),
        Err("the release is older than the running version")
    );
    assert_eq!(
        guard(edge, "edge-20261113T235959Z", Explicit),
        Ok(Verdict::Stage)
    );
    // Stable numbers compare as numbers, not text.
    assert_eq!(guard("0.9.0", "0.10.0", Forward), Ok(Verdict::Stage));
    assert!(guard("0.10.0", "0.9.9", Forward).is_err());
    assert_eq!(guard("1.2.3", "01.2.3", Forward), Ok(Verdict::Same));
    assert_eq!(
        guard("1.0.0", "99999999999999999999999.0.0", Forward),
        Ok(Verdict::Stage)
    );
    // Never across channels without an explicit request.
    assert_eq!(
        guard("0.1.0", edge, Forward),
        Err("the release is on another channel; switching channels needs an explicit update")
    );
    assert!(guard(edge, "9.9.9", Forward).is_err());
    assert_eq!(guard("0.1.0", edge, Explicit), Ok(Verdict::Stage));
    for bad in ["", "1.2", "edge-2026", "../1.2.3", "1.2.3\n"] {
        assert_eq!(
            guard("0.1.0", bad, Explicit),
            Err("the release version is malformed")
        );
    }
}

/// The schedule is 15 minutes ±20 %, doubling per failure up to 6 hours.
#[test]
fn delay_is_fifteen_minutes_with_jitter_and_doubles_on_failure_up_to_six_hours() {
    let minutes = |failures, random| delay(failures, random).as_secs_f64() / 60.0;
    assert!((minutes(0, 200) - 15.0).abs() < 0.01);
    assert!((minutes(0, 0) - 12.0).abs() < 0.01);
    assert!((minutes(0, 400) - 18.0).abs() < 0.01);
    assert!((minutes(1, 200) - 30.0).abs() < 0.01);
    assert!((minutes(2, 200) - 60.0).abs() < 0.01);
    assert!((minutes(5, 200) - 360.0).abs() < 0.01);
    assert!((minutes(u32::MAX, 200) - 360.0).abs() < 0.01);
    for random in [0, 1, 400, 401, u64::MAX] {
        let wait = delay(0, random).as_secs();
        assert!((12 * 60..=18 * 60).contains(&wait), "{wait}");
    }
}

/// `state.json` is written privately and atomically, wakes subscribers, and always reports the running version.
#[test]
fn state_round_trips_privately_and_status_always_names_the_running_version() {
    let scratch = Scratch::new();
    let updates = scratch.0.join("updates");
    assert_eq!(
        status(&scratch.0, "edge-20261114T000000Z"),
        UpdateState {
            current: "edge-20261114T000000Z".into(),
            ..UpdateState::default()
        }
    );
    let lock = Locked::open(&updates).unwrap();
    let state = UpdateState {
        current: "edge-20261101T000000Z".into(),
        channel: "edge".into(),
        available: Some("edge-20261114T000000Z".into()),
        last_error: Some("the builds host could not be reached securely.".into()),
        failures: 2,
        ..UpdateState::default()
    };
    let mut seen = changes();
    seen.mark_unchanged();
    lock.write_state(&state).unwrap();
    assert!(seen.has_changed().unwrap());
    let file = std::fs::metadata(updates.join("state.json")).unwrap();
    assert_eq!(file.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        std::fs::metadata(&updates).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(!updates.join("state.json.tmp").exists());
    // After an update the file still holds the old version; status reports the running one.
    let read = status(&scratch.0, "edge-20261114T000000Z");
    assert_eq!(read.current, "edge-20261114T000000Z");
    assert_eq!(read.failures, 2);
    assert_eq!(read.available, state.available);
    // A corrupt or oversized file reads as a fresh state instead of failing.
    std::fs::write(updates.join("state.json"), vec![b' '; 5000]).unwrap();
    assert_eq!(status(&scratch.0, "0.1.0").failures, 0);
}

/// A group-readable folder or a symlink in place of `updates/` is refused.
#[test]
fn unsafe_update_folders_are_refused() {
    let scratch = Scratch::new();
    let updates = scratch.0.join("updates");
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(&updates)
        .unwrap();
    std::fs::set_permissions(&updates, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        Locked::open(&updates).err(),
        Some("the update folder is unsafe")
    );
    std::fs::remove_dir(&updates).unwrap();
    std::os::unix::fs::symlink(&scratch.0, &updates).unwrap();
    assert_eq!(
        Locked::open(&updates).err(),
        Some("the update folder is unsafe")
    );
}

/// The lock is exclusive, and the sweep deletes only our abandoned folders, never symlinks or foreign names.
#[test]
fn a_second_check_waits_for_the_lock_and_the_sweep_keeps_foreign_entries() {
    let scratch = Scratch::new();
    let updates = scratch.0.join("updates");
    let lock = Locked::open(&updates).unwrap();
    assert_eq!(
        Locked::try_open(&updates).err(),
        Some("an update check is already running")
    );
    let abandoned = updates.join(format!("download-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&abandoned)
        .unwrap();
    std::fs::write(abandoned.join("infraternal-x86_64-musl"), b"partial").unwrap();
    let retired = updates.join(format!("retired-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&retired)
        .unwrap();
    // Not ours: a non-canonical name and a symlink with an ours-looking name.
    let foreign = updates.join("download-not-a-uuid");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&foreign)
        .unwrap();
    let outside = scratch.0.join("outside");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&outside)
        .unwrap();
    std::fs::write(outside.join("keep"), b"keep").unwrap();
    let link = updates.join(format!("download-{}", uuid::Uuid::new_v4()));
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    lock.sweep().unwrap();
    assert!(!abandoned.exists() && !retired.exists());
    assert!(foreign.exists());
    assert!(std::fs::symlink_metadata(&link).is_ok());
    assert!(outside.join("keep").exists());
    drop(lock);
    assert!(Locked::try_open(&updates).is_ok());
}

/// Publishing replaces the staged release, leaving exactly one; an unpublished download removes itself.
#[test]
fn publishing_keeps_exactly_one_staged_release() {
    let scratch = Scratch::new();
    let updates = scratch.0.join("updates");
    let lock = Locked::open(&updates).unwrap();
    for version in ["edge-20261114T000000Z", "edge-20261115T000000Z"] {
        let download = lock.download().unwrap();
        std::fs::write(download.path.join("VERSION"), format!("{version}\n")).unwrap();
        lock.publish(download).unwrap();
        assert_eq!(staged_version(&updates).as_deref(), Some(version));
    }
    let names: Vec<_> = std::fs::read_dir(&updates)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["staged"]);
    assert_eq!(
        std::fs::metadata(updates.join("staged")).unwrap().uid(),
        nix::unistd::geteuid().as_raw()
    );
    // A dropped, unpublished download leaves nothing behind.
    let download = lock.download().unwrap();
    let path = download.path.clone();
    drop(download);
    assert!(!path.exists());
    lock.retire_staged().unwrap();
    assert_eq!(staged_version(&updates), None);
}
