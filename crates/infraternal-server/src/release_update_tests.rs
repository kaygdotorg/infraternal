//! End-to-end proof of the update check, download and staging (#211 S3) against a
//! throwaway loopback channel. Every release is signed by a fresh `ssh-keygen` key
//! that only this test trusts; real release keys are never used.
//!
//! Covered: a new release is staged; the same version does nothing; an older or
//! cross-channel release is refused (and allowed only by an explicit request);
//! tampered releases are refused; offline checks fail quietly with backoff; abandoned
//! and interrupted downloads are cleaned up; a full disk is refused before the
//! download; a newer release replaces the staged one; the timer stages on its own; the
//! state is visible through `release.update.status`; and a `staged/` found on disk is
//! re-verified (or removed) before use.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::release_payload::tests::{Bucket, Release};
use infraternal_plugin_release::update::{
    Admission, Outcome, REMOVED_UNVERIFIED, UpdateState, Updater, status,
};
use std::{os::unix::fs::PermissionsExt, sync::atomic::Ordering};

/// The running version in most cases: older than the published release.
const OLD: &str = "edge-20261101T000000Z";
/// The release the test channel publishes.
const NEW: &str = "edge-20261114T000000Z";
/// A later release, for replacement and tampering cases.
const NEWER: &str = "edge-20261115T000000Z";

/// The image name the fixture signs for this machine.
fn artifact() -> &'static str {
    infraternal_plugin_release::update::artifact_name()
        .expect("tests run on Linux x86_64 or aarch64")
}

/// A signed release `version` served from a loopback bucket whose edge pointer names it.
fn channel(version: &str) -> (Release, Bucket) {
    let release = Release::with_version(4096, version);
    let bucket = Bucket::new(release.files.clone());
    point(&bucket, version);
    (release, bucket)
}

/// Make the bucket's edge pointer announce `version`.
fn point(bucket: &Bucket, version: &str) {
    bucket.files.lock().unwrap().insert(
        "/releases/channels/edge.json".into(),
        format!("{{\"version\":\"{version}\"}}").into_bytes(),
    );
}

/// An updater for `release.root` running `current` on the edge channel, trusting only
/// the fixture key.
fn updater(release: &Release, origin: &str, current: &str) -> Updater {
    updater_with_trust(release, origin, current, &release.trust)
}

/// [`updater`] trusting `trust` instead of the fixture key, to prove a wrong key is refused.
fn updater_with_trust(release: &Release, origin: &str, current: &str, trust: &str) -> Updater {
    Updater::new(
        &release.root,
        origin.into(),
        current.into(),
        artifact().into(),
        Arc::new(Engine {
            trust: Some(trust.into()),
        }),
        Arc::new(|| Box::pin(async { Ok((true, "edge".to_owned())) })),
    )
}

/// The persisted update state, as a server running `current` reports it.
fn state(release: &Release, current: &str) -> UpdateState {
    status(&release.root, current)
}

/// Names left in `updates/`, sorted.
fn leftovers(release: &Release) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(release.root.join("updates"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// How many requests the bucket has answered (pointer, metadata and images).
fn image_requests(bucket: &Bucket) -> usize {
    bucket.requests.load(Ordering::Relaxed)
}

/// Create `<root>/updates` as the updater would (0700), for tests that plant files in it.
fn private_updates(release: &Release) -> std::path::PathBuf {
    let updates = release.root.join("updates");
    std::fs::create_dir(&updates).unwrap();
    std::fs::set_permissions(&updates, std::fs::Permissions::from_mode(0o700)).unwrap();
    updates
}

/// Write `bytes` to `path` as a private (0600) file, the way the downloader does.
fn write_private(path: &std::path::Path, bytes: &[u8]) {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

/// Wait (on state writes, never a fixed sleep) until the saved state satisfies `done`.
async fn wait_for_state(
    release: &Release,
    current: &str,
    changes: &mut tokio::sync::watch::Receiver<u64>,
    done: impl Fn(&UpdateState) -> bool,
) -> UpdateState {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let saved = state(release, current);
            if done(&saved) {
                break saved;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .expect("the state reached the expected shape")
}

/// A newer edge release is downloaded, verified and staged with private permissions, and a repeat check only re-reads metadata.
#[tokio::test]
async fn a_newer_release_is_verified_and_staged_privately() {
    let (release, bucket) = channel(NEW);
    let updater = updater(&release, &bucket.origin, OLD);
    assert_eq!(
        updater.check(None, Admission::Forward).await,
        Ok(Outcome::Staged(NEW.into()))
    );
    // Pointer, SHA256SUMS, SHA256SUMS.sig, VERSION, then the image.
    assert_eq!(image_requests(&bucket), 5);
    assert_eq!(leftovers(&release), ["staged", "state.json"]);
    let staged = release.root.join("updates/staged");
    let mut files: Vec<_> = std::fs::read_dir(&staged)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    let mut expected = vec![
        "SHA256SUMS",
        "SHA256SUMS.sig",
        "VERSION",
        "pointer.json",
        artifact(),
    ];
    expected.sort_unstable();
    assert_eq!(files, expected);
    assert_eq!(
        std::fs::read(staged.join(artifact())).unwrap(),
        release.files[&format!("/releases/{NEW}/{}", artifact())]
    );
    for entry in std::fs::read_dir(&staged).unwrap() {
        let mode = entry.unwrap().metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "staged files must be private");
    }
    let mode = std::fs::metadata(release.root.join("updates"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
    let saved = state(&release, OLD);
    assert_eq!(saved.available.as_deref(), Some(NEW));
    assert_eq!(saved.staged.as_deref(), Some(NEW));
    assert_eq!(saved.channel, "edge");
    assert_eq!(saved.last_error, None);
    assert!(saved.last_check.is_some());
    // A second check finds it already staged and downloads nothing more than metadata.
    assert_eq!(
        updater.check(None, Admission::Forward).await,
        Ok(Outcome::Staged(NEW.into()))
    );
    assert_eq!(image_requests(&bucket), 9);
}

/// A channel announcing the running version downloads no image and stages nothing.
#[tokio::test]
async fn the_running_version_is_left_alone() {
    let (release, bucket) = channel(NEW);
    let updater = updater(&release, &bucket.origin, NEW);
    assert_eq!(
        updater.check(None, Admission::Forward).await,
        Ok(Outcome::Current(NEW.into()))
    );
    assert_eq!(image_requests(&bucket), 4, "no image is downloaded");
    assert_eq!(leftovers(&release), ["state.json"]);
    assert_eq!(state(&release, NEW).staged, None);
}

/// An older release and another channel's release are refused by the periodic check; an explicit rollback stages the older one, and the next periodic check removes it.
#[tokio::test]
async fn older_and_cross_channel_releases_need_an_explicit_request() {
    let (release, bucket) = channel(OLD);
    let forward = updater(&release, &bucket.origin, NEW);
    assert_eq!(
        forward.check(None, Admission::Forward).await,
        Err("the release is older than the running version")
    );
    assert_eq!(image_requests(&bucket), 4, "no image is downloaded");
    assert_eq!(leftovers(&release), ["state.json"]);
    let saved = state(&release, NEW);
    assert_eq!(saved.staged, None);
    assert_eq!(
        saved.last_error.as_deref(),
        Some("the release is older than the running version")
    );
    // A stable server never takes an edge release on its own.
    let stable = updater(&release, &bucket.origin, "0.1.0");
    assert_eq!(
        stable.check(None, Admission::Forward).await,
        Err("the release is on another channel; switching channels needs an explicit update")
    );
    // An explicit rollback to the exact older version stages it, still verified.
    assert_eq!(
        forward.check(Some(OLD), Admission::Explicit).await,
        Ok(Outcome::Staged(OLD.into()))
    );
    // The next periodic check removes a staged release it would not have chosen.
    assert!(forward.check(None, Admission::Forward).await.is_err());
    assert_eq!(state(&release, NEW).staged, None);
    assert_eq!(leftovers(&release), ["state.json"]);
}

/// A flipped image byte, an untrusted signing key and a swapped VERSION are all refused, and no download is kept.
#[tokio::test]
async fn tampered_or_wrongly_signed_releases_are_refused_and_nothing_is_kept() {
    let (release, bucket) = channel(NEW);
    let image = format!("/releases/{NEW}/{}", artifact());
    bucket.files.lock().unwrap().get_mut(&image).unwrap()[0] ^= 1;
    let updater = updater(&release, &bucket.origin, OLD);
    assert_eq!(
        updater.check(None, Admission::Forward).await,
        Err("the release does not match its signed checksums")
    );
    assert_eq!(leftovers(&release), ["state.json"]);
    bucket
        .files
        .lock()
        .unwrap()
        .insert(image.clone(), release.files[&image].clone());
    // Same files, but a server that trusts another key.
    let stranger = Release::with_version(16, NEW);
    let distrusting = updater_with_trust(&release, &bucket.origin, OLD, &stranger.trust);
    assert_eq!(
        distrusting.check(None, Admission::Forward).await,
        Err("release VERSION could not be verified")
    );
    assert_eq!(leftovers(&release), ["state.json"]);
    // A signed VERSION swapped for a newer one is refused before any image download.
    bucket.files.lock().unwrap().insert(
        format!("/releases/{NEW}/VERSION"),
        format!("{NEWER}\n").into_bytes(),
    );
    let before = image_requests(&bucket);
    assert!(updater.check(None, Admission::Forward).await.is_err());
    assert_eq!(image_requests(&bucket), before + 4);
    assert_eq!(state(&release, OLD).staged, None);
}

/// An unreachable builds host fails with a fixed reason, counts consecutive failures, and one clean check resets them.
#[tokio::test]
async fn offline_checks_fail_quietly_and_count_failures() {
    let (release, bucket) = channel(NEW);
    // A port nothing listens on: bind, read the port, close.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let updater = updater(&release, &closed, OLD);
    for failures in 1..=2 {
        assert_eq!(
            updater.check(None, Admission::Forward).await,
            Err("the builds host could not be reached securely.")
        );
        let saved = state(&release, OLD);
        assert_eq!(saved.failures, failures);
        assert_eq!(saved.staged, None);
    }
    assert_eq!(leftovers(&release), ["state.json"]);
    // Back online: one clean check resets the count.
    let online = self::updater(&release, &bucket.origin, OLD);
    assert!(online.check(None, Admission::Forward).await.is_ok());
    let saved = state(&release, OLD);
    assert_eq!((saved.failures, saved.last_error), (0, None));
}

/// A crash-abandoned download folder and a download cut off midway are both removed; the next check downloads from the start.
#[tokio::test]
async fn abandoned_and_interrupted_downloads_are_cleaned_up() {
    let (release, bucket) = channel(NEW);
    let updates = release.root.join("updates");
    std::fs::create_dir(&updates).unwrap();
    std::fs::set_permissions(&updates, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A crash mid-download left a partial image behind.
    let abandoned = updates.join(format!("download-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&abandoned).unwrap();
    std::fs::write(abandoned.join(artifact()), b"partial").unwrap();
    // A download cut off midway: the image exceeds the bound after a few bytes.
    let cut = updater(&release, &bucket.origin, OLD).with_limits(0, 100);
    assert_eq!(
        cut.check(None, Admission::Forward).await,
        Err("the release file exceeds its size limit.")
    );
    assert_eq!(leftovers(&release), ["state.json"]);
    // The next full check starts the download again from the beginning.
    assert_eq!(
        updater(&release, &bucket.origin, OLD)
            .check(None, Admission::Forward)
            .await,
        Ok(Outcome::Staged(NEW.into()))
    );
    assert_eq!(leftovers(&release), ["staged", "state.json"]);
}

/// Too little free space refuses the update before the image is requested.
#[tokio::test]
async fn a_full_disk_is_refused_before_the_image_download() {
    let (release, bucket) = channel(NEW);
    let full = updater(&release, &bucket.origin, OLD).with_limits(u64::MAX, 128 << 20);
    assert_eq!(
        full.check(None, Admission::Forward).await,
        Err("there is not enough free disk space to stage the update")
    );
    assert_eq!(image_requests(&bucket), 4, "no image is downloaded");
    assert_eq!(leftovers(&release), ["state.json"]);
}

/// A newer release replaces the staged one, so only one release is ever staged.
#[tokio::test]
async fn a_newer_release_replaces_the_staged_one() {
    let (release, bucket) = channel(NEW);
    let updater = updater(&release, &bucket.origin, OLD);
    assert!(updater.check(None, Admission::Forward).await.is_ok());
    // NEWER comes from a sibling fixture with its own throwaway key; the updater
    // trusts both keys, as production trusts the signing key and its spare (D224).
    let newer = Release::with_version(4096, NEWER);
    bucket.files.lock().unwrap().extend(newer.files.clone());
    point(&bucket, NEWER);
    let both = updater_with_trust(
        &release,
        &bucket.origin,
        OLD,
        &format!("{}{}", release.trust, newer.trust),
    );
    assert_eq!(
        both.check(None, Admission::Forward).await,
        Ok(Outcome::Staged(NEWER.into()))
    );
    assert_eq!(leftovers(&release), ["staged", "state.json"]);
    assert_eq!(state(&release, OLD).staged.as_deref(), Some(NEWER));
}

/// The timer runs a check on its own, records the next check about 15 minutes out, and the status action shows the staged release.
#[tokio::test]
async fn the_timer_stages_on_its_own_and_status_reports_it() {
    let (release, bucket) = channel(NEW);
    let mut changes = infraternal_plugin_release::update::changes();
    let task =
        Arc::new(updater(&release, &bucket.origin, OLD)).spawn_after(std::time::Duration::ZERO);
    // Wait on state writes (no fixed sleep); the first write is the next-check note.
    let staged = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            changes.changed().await.unwrap();
            if let Some(staged) = state(&release, OLD).staged {
                break staged;
            }
        }
    })
    .await
    .expect("the timer staged the release");
    assert_eq!(staged, NEW);
    // The timer then records its next check, about 15 minutes away.
    let next = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let saved = state(&release, OLD);
            if let (Some(next), Some(last)) = (saved.next_check, saved.last_check)
                && next > last
            {
                break next - last;
            }
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!((11 * 60..=19 * 60).contains(&next), "{next}");
    task.abort();
    // The plugin's status action reads the same state for S5.
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE plugin_settings(role TEXT,plugin TEXT,enabled INTEGER,settings TEXT NOT NULL DEFAULT '{}',PRIMARY KEY(role,plugin)); INSERT INTO plugin_settings VALUES('server','release',1,'{\"channel\":\"edge\"}');")
        .execute(&pool)
        .await
        .unwrap();
    let service = release_service(pool, &release.root);
    let shown = service
        .call("release.update.status", b"{}", None)
        .await
        .unwrap();
    assert_eq!(shown["staged"], NEW);
    assert_eq!(shown["available"], NEW);
    assert_eq!(shown["channel"], "edge");
    assert_eq!(shown["current"], infraternal_plugin_api::VERSION);
}

/// A `staged/` found on disk is re-verified before use, never taken on its word (J725
/// P3-1): a planted folder with the right VERSION but an unsigned image is removed and
/// the real release is downloaded and verified instead.
#[tokio::test]
async fn a_found_staged_folder_is_reverified_before_use() {
    let (release, bucket) = channel(NEW);
    let planted = private_updates(&release).join("staged");
    std::fs::create_dir(&planted).unwrap();
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o700)).unwrap();
    write_private(&planted.join("VERSION"), format!("{NEW}\n").as_bytes());
    write_private(&planted.join(artifact()), b"not a signed image");
    let updater = updater(&release, &bucket.origin, OLD);
    assert_eq!(
        updater.check(None, Admission::Forward).await,
        Ok(Outcome::Staged(NEW.into()))
    );
    assert_eq!(
        image_requests(&bucket),
        5,
        "the image was fetched and verified"
    );
    assert_eq!(
        std::fs::read(planted.join(artifact())).unwrap(),
        release.files[&format!("/releases/{NEW}/{}", artifact())]
    );
    assert_eq!(state(&release, OLD).staged.as_deref(), Some(NEW));
}

/// When the timer starts it removes a symlinked or shared `staged/` without following it,
/// and records why (J725 P3-1).
#[tokio::test]
async fn unsafe_staged_folders_are_removed_at_start_without_being_followed() {
    let (release, bucket) = channel(NEW);
    let updater = Arc::new(updater(&release, &bucket.origin, OLD));
    assert!(updater.check(None, Admission::Forward).await.is_ok());
    let folder = release.root.join("updates");
    // A genuine, verified release, but reached through a symlink.
    let elsewhere = release.root.join("elsewhere");
    std::fs::rename(folder.join("staged"), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, folder.join("staged")).unwrap();
    let mut changes = infraternal_plugin_release::update::changes();
    let task = Arc::clone(&updater).spawn_after(std::time::Duration::from_secs(3600));
    let saved = wait_for_state(&release, OLD, &mut changes, |saved| saved.removed.is_some()).await;
    task.abort();
    assert_eq!(saved.staged, None);
    assert_eq!(saved.removed.unwrap().reason, REMOVED_UNVERIFIED);
    assert!(std::fs::symlink_metadata(folder.join("staged")).is_err());
    assert!(
        elsewhere.join(artifact()).exists(),
        "the link target is untouched"
    );
    // The same release in place but group-readable is removed as well.
    std::fs::rename(&elsewhere, folder.join("staged")).unwrap();
    assert!(updater.check(None, Admission::Forward).await.is_ok());
    assert_eq!(state(&release, OLD).staged.as_deref(), Some(NEW));
    std::fs::set_permissions(
        folder.join("staged"),
        std::fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    let task = Arc::clone(&updater).spawn_after(std::time::Duration::from_secs(3600));
    let saved = wait_for_state(&release, OLD, &mut changes, |saved| saved.staged.is_none()).await;
    task.abort();
    assert_eq!(saved.removed.unwrap().reason, REMOVED_UNVERIFIED);
    assert_eq!(leftovers(&release), ["state.json"]);
}
