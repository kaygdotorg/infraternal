//! Unit checks for S4's file side (#211): installing a confirmed stage, keeping the
//! previous release, the `pending.json` phases, the D295 database restore, commit and
//! undo. The warm exec and health check are proven in the server and CLI crates.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::update::{UpdateState, status_of};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

/// The image name used by these tests.
const IMAGE: &str = "infraternal-test-musl";
/// The running release (A).
const A: &str = "edge-20261115T000001Z";
/// The release being applied (B).
const B: &str = "edge-20261115T000002Z";

/// A private data folder under TMPDIR with a private `updates/`, removed on drop.
struct Data(PathBuf);
impl Data {
    /// Create `<tmp>/apply-<uuid>/updates/`, both 0700.
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("apply-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(path.join("updates"))
            .unwrap();
        Self(path)
    }
    /// `<data>/updates`.
    fn updates(&self) -> PathBuf {
        self.0.join("updates")
    }
    /// Plant a staged folder holding `bytes` as the image, as S3 leaves it.
    fn stage(&self, bytes: &[u8]) {
        let staged = self.updates().join("staged");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&staged)
            .unwrap();
        for (name, content) in [(IMAGE, bytes), ("VERSION", b"x\n".as_slice())] {
            write_file(&staged.join(name), content);
        }
    }
    /// The saved update state.
    fn state(&self) -> UpdateState {
        status_of(&self.updates(), "")
    }
    /// Write the marker as A would, in `phase`.
    fn mark(&self, phase: Phase) -> Pending {
        let pending = pending(phase);
        let lock = Locked::open(&self.updates()).unwrap();
        write_pending(&lock, &pending).unwrap();
        pending
    }
}
impl Drop for Data {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Write `bytes` as a private (0600) file.
fn write_file(path: &Path, bytes: &[u8]) {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// A marker for the A → B switch in `phase`; A's digest is "aa…", B's "bb…".
fn pending(phase: Phase) -> Pending {
    Pending {
        phase,
        from_version: A.into(),
        from_sha256: "aa".repeat(32),
        from_path: "/opt/a/infraternal".into(),
        to_version: B.into(),
        to_sha256: "bb".repeat(32),
        ca_warm: true,
        started: 1,
        reason: None,
        undo_attempts: 0,
    }
}

/// Install renames `staged/` into `releases/<v>/`: the open verified file is the
/// installed inode, it becomes executable, and the folder stays locked.
#[test]
fn install_keeps_the_verified_inode_and_the_lock() {
    let data = Data::new();
    data.stage(b"image-b");
    let confirmed = Confirmed::for_test(B, &data.updates(), IMAGE);
    let switch = install(confirmed, IMAGE).unwrap();
    assert!(!data.updates().join("staged").exists());
    let installed = data.updates().join("releases").join(B).join(IMAGE);
    assert_eq!(switch.path(), installed);
    let (open, on_disk) = (
        switch.file().metadata().unwrap(),
        installed.metadata().unwrap(),
    );
    assert_eq!((open.dev(), open.ino()), (on_disk.dev(), on_disk.ino()));
    assert_eq!(on_disk.mode() & 0o777, 0o700);
    assert!(
        Locked::try_open(&data.updates()).is_err(),
        "the switch holds the folder lock"
    );
    assert_eq!(switch.digest().unwrap(), apply_digest(b"image-b"));
    drop(switch);
    assert!(Locked::try_open(&data.updates()).is_ok());
}

/// SHA-256 of `bytes` as hex, the way [`digest`] reports it.
fn apply_digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The previous image is copied whole into `previous/`, replacing an older copy, and
/// its digest is returned; the database copy goes beside it.
#[test]
fn the_previous_release_is_kept_whole_with_its_digest() {
    let data = Data::new();
    let previous = data.updates().join("previous");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&previous)
        .unwrap();
    write_file(&previous.join("stale"), b"old");
    data.stage(b"image-b");
    let switch = install(Confirmed::for_test(B, &data.updates(), IMAGE), IMAGE).unwrap();
    let running = data.0.join("running");
    write_file(&running, &vec![7; 200_000]);
    let sha = switch
        .save_previous(&File::open(&running).unwrap(), IMAGE)
        .unwrap();
    assert_eq!(sha, apply_digest(&vec![7; 200_000]));
    assert_eq!(
        std::fs::read(previous.join(IMAGE)).unwrap(),
        vec![7; 200_000]
    );
    assert!(!previous.join("stale").exists());
    assert_eq!(switch.database_copy(), previous.join(DATABASE));
    switch.begin(&pending(Phase::Switching)).unwrap();
    assert_eq!(
        read_pending(&data.updates()),
        Some(pending(Phase::Switching))
    );
}

/// Without a marker a start is idle and never hashes its own image.
#[test]
fn a_normal_start_is_idle_and_hashes_nothing() {
    let data = Data::new();
    assert_eq!(
        resume(&data.0, A, || panic!("no marker, no hashing")),
        Ok(Resume::Idle)
    );
}

/// B's side: a fresh switch becomes a trial; a second start mid-trial is a failed trial;
/// a start after its own undo exec failed retries the undo a bounded number of times,
/// then keeps serving with the marker left for A's next cold start.
#[test]
fn the_new_release_moves_to_trial_and_a_restart_fails_it() {
    let data = Data::new();
    data.mark(Phase::Switching);
    let own = || Ok("bb".repeat(32));
    let Ok(Resume::Trial(trial)) = resume(&data.0, B, own) else {
        panic!("B starts its trial");
    };
    assert_eq!((trial.phase, trial.reason), (Phase::Trial, None));
    assert_eq!(read_pending(&data.updates()).unwrap().phase, Phase::Trial);
    let Ok(Resume::Trial(again)) = resume(&data.0, B, own) else {
        panic!("B restarted mid-trial");
    };
    assert_eq!(again.reason.as_deref(), Some(STOPPED_IN_TRIAL));
    let mut marker = data.mark(Phase::Rollback);
    marker.reason = Some(UNHEALTHY.into());
    write_pending(&Locked::open(&data.updates()).unwrap(), &marker).unwrap();
    for attempt in 1..=MAX_UNDO_ATTEMPTS {
        let Ok(Resume::Trial(retry)) = resume(&data.0, B, own) else {
            panic!("B retries its undo");
        };
        assert_eq!(
            (retry.undo_attempts, retry.reason.as_deref()),
            (attempt, Some(UNHEALTHY))
        );
    }
    assert_eq!(resume(&data.0, B, own), Ok(Resume::Finished(UNDO_FAILED)));
    assert_eq!(
        read_pending(&data.updates()).unwrap().phase,
        Phase::Rollback
    );
}

/// A's side after B ran: the database copy replaces the database (old WAL and SHM
/// files removed), B is paused and the undo is recorded, and the marker and B's
/// install are gone. `previous/` is kept.
#[test]
fn the_previous_release_restores_the_database_after_a_failed_trial() {
    for (phase, reason, expected) in [
        (Phase::Trial, None, STOPPED_IN_TRIAL),
        (Phase::Rollback, Some(UNHEALTHY), UNHEALTHY),
        (Phase::Rollback, Some(TIMED_OUT), TIMED_OUT),
        (Phase::Rollback, Some(FAILED_TO_START), FAILED_TO_START),
        // A marker is a file: an unknown reason is never copied into the state.
        (Phase::Rollback, Some("made up"), STOPPED_IN_TRIAL),
    ] {
        let data = Data::new();
        write_file(&data.0.join(DATABASE), b"written-by-b");
        write_file(&data.0.join(format!("{DATABASE}-wal")), b"b-wal");
        write_file(&data.0.join(format!("{DATABASE}-shm")), b"b-shm");
        let previous = data.updates().join("previous");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&previous)
            .unwrap();
        write_file(&previous.join(DATABASE), b"a-copy");
        let release = data.updates().join("releases").join(B);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&release)
            .unwrap();
        let mut marker = data.mark(phase);
        marker.reason = reason.map(str::to_owned);
        write_pending(&Locked::open(&data.updates()).unwrap(), &marker).unwrap();
        assert_eq!(
            resume(&data.0, A, || Ok("aa".repeat(32))),
            Ok(Resume::Finished(UNDONE))
        );
        assert_eq!(std::fs::read(data.0.join(DATABASE)).unwrap(), b"a-copy");
        assert_eq!(
            std::fs::metadata(data.0.join(DATABASE)).unwrap().mode() & 0o777,
            0o600
        );
        assert!(!data.0.join(format!("{DATABASE}-wal")).exists());
        assert!(!data.0.join(format!("{DATABASE}-shm")).exists());
        assert!(previous.join(DATABASE).exists(), "the copy is kept");
        assert!(!release.exists());
        assert!(!data.updates().join(PENDING).exists());
        let state = data.state();
        assert_eq!(state.paused.as_deref(), Some(B));
        let applied = state.applied.unwrap();
        assert_eq!(
            (applied.version.as_str(), applied.outcome.as_str()),
            (B, UNDONE)
        );
        assert_eq!(applied.reason.as_deref(), Some(expected));
    }
}

/// A's side when B's exec failed (B never ran): the database is left alone, B is paused.
#[test]
fn a_new_release_that_never_started_leaves_the_database_alone() {
    let data = Data::new();
    write_file(&data.0.join(DATABASE), b"a-live");
    data.mark(Phase::Switching);
    assert_eq!(
        resume(&data.0, A, || Ok("aa".repeat(32))),
        Ok(Resume::Finished(UNDONE))
    );
    assert_eq!(std::fs::read(data.0.join(DATABASE)).unwrap(), b"a-live");
    let state = data.state();
    assert_eq!(state.paused.as_deref(), Some(B));
    assert_eq!(
        state.applied.unwrap().reason.as_deref(),
        Some(DID_NOT_START)
    );
}

/// A marker naming neither side (another binary was deployed by hand) is dropped
/// without touching the database.
#[test]
fn a_marker_from_another_binary_is_dropped() {
    let data = Data::new();
    write_file(&data.0.join(DATABASE), b"live");
    data.mark(Phase::Trial);
    assert_eq!(
        resume(&data.0, A, || Ok("cc".repeat(32))),
        Ok(Resume::Finished(NOT_APPLIED))
    );
    assert_eq!(std::fs::read(data.0.join(DATABASE)).unwrap(), b"live");
    assert!(!data.updates().join(PENDING).exists());
    let state = data.state();
    assert_eq!(state.paused, None);
    assert_eq!(state.applied.unwrap().reason.as_deref(), Some(INTERRUPTED));
}

/// A commit points `current` at B, drops other installs, keeps `previous/`, removes
/// the marker and unpauses B; a marker changed under it refuses the commit.
#[test]
fn commit_moves_the_boot_pointer_only_for_the_running_trial() {
    let data = Data::new();
    for version in [A, B] {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(data.updates().join("releases").join(version))
            .unwrap();
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(data.updates().join("previous"))
        .unwrap();
    let lock = Locked::open(&data.updates()).unwrap();
    lock.write_state(&UpdateState {
        paused: Some(B.into()),
        ..UpdateState::default()
    })
    .unwrap();
    drop(lock);
    let trial = data.mark(Phase::Trial);
    let mut other = trial.clone();
    other.to_sha256 = "cc".repeat(32);
    assert!(commit(&data.0, &other).is_err());
    commit(&data.0, &trial).unwrap();
    assert_eq!(
        std::fs::read_link(data.updates().join("current")).unwrap(),
        Path::new("releases").join(B)
    );
    assert!(!data.updates().join("releases").join(A).exists());
    assert!(data.updates().join("previous").exists());
    assert!(!data.updates().join(PENDING).exists());
    let state = data.state();
    assert_eq!(state.applied.unwrap().outcome, APPLIED);
    assert_eq!(state.paused, None);
}

/// A failed trial marks the rollback with its reason and returns A's kept image, digest
/// and argv[0].
#[test]
fn a_rollback_names_the_kept_image_and_its_digest() {
    let data = Data::new();
    let trial = data.mark(Phase::Trial);
    let undo = begin_rollback(&data.0, &trial, IMAGE, UNHEALTHY).unwrap();
    assert_eq!(undo.image, data.updates().join("previous").join(IMAGE));
    assert_eq!(undo.sha256, "aa".repeat(32));
    assert_eq!(undo.path, Path::new("/opt/a/infraternal"));
    let saved = read_pending(&data.updates()).unwrap();
    assert_eq!(
        (saved.phase, saved.reason.as_deref()),
        (Phase::Rollback, Some(UNHEALTHY))
    );
}

/// Abandoning before the exec removes the marker and the install and records why.
#[test]
fn an_abandoned_switch_changes_nothing_that_ran() {
    let data = Data::new();
    data.stage(b"image-b");
    let switch = install(Confirmed::for_test(B, &data.updates(), IMAGE), IMAGE).unwrap();
    switch.begin(&pending(Phase::Switching)).unwrap();
    switch.abandon(A, "refused").unwrap();
    assert!(!data.updates().join(PENDING).exists());
    assert!(!data.updates().join("releases").join(B).exists());
    let applied = data.state().applied.unwrap();
    assert_eq!(
        (applied.outcome.as_str(), applied.reason.as_deref()),
        (NOT_APPLIED, Some("refused"))
    );
}

/// A marker with a version that is not a release name is ignored (it would become a
/// folder name), and a start then removes it as idle.
#[test]
fn a_marker_with_a_bad_version_is_ignored() {
    let data = Data::new();
    let mut bad = data.mark(Phase::Switching);
    bad.to_version = "../escape".into();
    write_pending(&Locked::open(&data.updates()).unwrap(), &bad).unwrap();
    assert_eq!(read_pending(&data.updates()), None);
    assert_eq!(
        resume(&data.0, A, || panic!("ignored before hashing")),
        Ok(Resume::Idle)
    );
    assert!(!data.updates().join(PENDING).exists());
}

/// A copy that cannot be restored (here: not private) never leaves B eligible: B is
/// paused and recorded, the marker stays, and the next start, once the copy is usable,
/// finishes the undo. Found on the root proof (#211 S4): `VACUUM INTO` wrote 0644.
#[test]
fn a_failed_restore_pauses_the_new_release_and_retries_at_the_next_start() {
    use std::os::unix::fs::PermissionsExt;
    let data = Data::new();
    write_file(&data.0.join(DATABASE), b"written-by-b");
    let previous = data.updates().join("previous");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&previous)
        .unwrap();
    write_file(&previous.join(DATABASE), b"a-copy");
    std::fs::set_permissions(
        previous.join(DATABASE),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    data.mark(Phase::Trial);
    assert!(in_flight(&data.0));
    assert!(resume(&data.0, A, || Ok("aa".repeat(32))).is_err());
    let state = data.state();
    assert_eq!(state.paused.as_deref(), Some(B));
    assert_eq!(
        state.applied.unwrap().reason.as_deref(),
        Some(RESTORE_PENDING)
    );
    assert!(in_flight(&data.0), "the marker stays for the retry");
    assert_eq!(
        std::fs::read(data.0.join(DATABASE)).unwrap(),
        b"written-by-b"
    );
    std::fs::set_permissions(
        previous.join(DATABASE),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(
        resume(&data.0, A, || Ok("aa".repeat(32))),
        Ok(Resume::Finished(UNDONE))
    );
    assert_eq!(std::fs::read(data.0.join(DATABASE)).unwrap(), b"a-copy");
    assert!(!in_flight(&data.0));
}

/// J1085 finding 2 (its experiment 2): once the previous release has served on the
/// un-restored database, a later start never restores the old copy over what was
/// written since. Serving settles the marker instead and records why.
#[test]
fn a_release_that_served_unrestored_never_restores_a_stale_copy_later() {
    use std::os::unix::fs::PermissionsExt;
    let data = Data::new();
    write_file(&data.0.join(DATABASE), b"written-by-b");
    let previous = data.updates().join("previous");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&previous)
        .unwrap();
    write_file(&previous.join(DATABASE), b"a-copy");
    // The restore fails once (the copy is not private), and A starts anyway.
    std::fs::set_permissions(
        previous.join(DATABASE),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    data.mark(Phase::Rollback);
    assert!(resume(&data.0, A, || Ok("aa".repeat(32))).is_err());
    // A serves, and its users write to the database it has.
    assert_eq!(
        settle_served(&data.0, A, || Ok("aa".repeat(32))),
        Ok(Some(NOT_RESTORED))
    );
    std::fs::write(data.0.join(DATABASE), b"written-by-a-later").unwrap();
    let state = data.state();
    assert_eq!(state.paused.as_deref(), Some(B));
    assert_eq!(state.applied.unwrap().reason.as_deref(), Some(NOT_RESTORED));
    assert!(!in_flight(&data.0), "the marker is settled");
    // Days later the copy is readable again; the next start must leave the data alone.
    std::fs::set_permissions(
        previous.join(DATABASE),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(resume(&data.0, A, || Ok("aa".repeat(32))), Ok(Resume::Idle));
    assert_eq!(
        std::fs::read(data.0.join(DATABASE)).unwrap(),
        b"written-by-a-later"
    );
}

/// J1085 finding 2, the other way in: B gave up undoing itself and serves; its
/// marker is settled as undo-failed, so the previous release's next start restores
/// nothing.
#[test]
fn a_new_release_that_gave_up_its_undo_settles_the_marker_when_it_serves() {
    let data = Data::new();
    let mut marker = pending(Phase::Rollback);
    marker.undo_attempts = MAX_UNDO_ATTEMPTS;
    let lock = Locked::open(&data.updates()).unwrap();
    write_pending(&lock, &marker).unwrap();
    drop(lock);
    assert_eq!(
        resume(&data.0, B, || Ok("bb".repeat(32))),
        Ok(Resume::Finished(UNDO_FAILED))
    );
    assert_eq!(
        settle_served(&data.0, B, || Ok("bb".repeat(32))),
        Ok(Some(UNDO_FAILED))
    );
    assert!(!in_flight(&data.0));
    // Nothing is left to settle on the next start.
    assert_eq!(settle_served(&data.0, B, || Ok("bb".repeat(32))), Ok(None));
}

/// J1085 finding 3 (its experiment 3): a new release that cannot record its trial
/// (here `pending.json.tmp` is blocked by a folder, as a full or failing disk would)
/// gets TRIAL_NOT_RECORDED, so its startup stays off the database.
#[test]
fn a_new_release_that_cannot_record_its_trial_is_told_so() {
    let data = Data::new();
    data.mark(Phase::Switching);
    let blocker = data.updates().join("pending.json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    std::fs::write(blocker.join("x"), b"x").unwrap();
    assert_eq!(
        resume(&data.0, B, || Ok("bb".repeat(32))),
        Err(TRIAL_NOT_RECORDED)
    );
    assert_eq!(
        read_pending(&data.updates()).unwrap().phase,
        Phase::Switching,
        "the marker still says B never ran, so A keeps its database"
    );
}
