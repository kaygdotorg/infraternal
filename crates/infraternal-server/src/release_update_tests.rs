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
//! re-verified (or removed) before use; and a release the channel withdraws is removed,
//! both by the periodic check and by S4's apply-time confirmation; policy refusals and
//! "updates off" never back off the timer; and an explicit rollback holds until it is
//! applied or cancelled; and the status says when updates are off on this host, and why;
//! and the owner controls (#211 S5) check, stage, apply, cancel and list history only for an
//! owner with a fresh session, through the applier seam.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::release_payload::tests::{Bucket, Release};
use infraternal_plugin_release::update::{
    Admission, NOTHING_STAGED, Outcome, REMOVED_UNVERIFIED, REMOVED_WITHDRAWN, UPDATES_OFF,
    UpdateState, Updater, status,
};
use serde_json::json;
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

/// Names left in `updates/`, sorted, without `history.json` (S5's record, which tests of the
/// folder's hygiene do not care about).
fn leftovers(release: &Release) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(release.root.join("updates"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "history.json")
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

/// An older release and another channel's release are refused by the periodic check (a normal answer, not a failure); an explicit rollback stages the older one, and the next periodic check removes it.
#[tokio::test]
async fn older_and_cross_channel_releases_need_an_explicit_request() {
    let (release, bucket) = channel(OLD);
    let forward = updater(&release, &bucket.origin, NEW);
    assert_eq!(
        forward.check(None, Admission::Forward).await,
        Ok(Outcome::Refused(
            "the release is older than the running version"
        ))
    );
    assert_eq!(image_requests(&bucket), 4, "no image is downloaded");
    assert_eq!(leftovers(&release), ["state.json"]);
    let saved = state(&release, NEW);
    assert_eq!(saved.staged, None);
    assert_eq!(
        saved.refused.as_deref(),
        Some("the release is older than the running version")
    );
    assert_eq!((saved.last_error, saved.failures), (None, 0));
    // A stable server never takes an edge release on its own.
    let stable = updater(&release, &bucket.origin, "0.1.0");
    assert_eq!(
        stable.check(None, Admission::Forward).await,
        Ok(Outcome::Refused(
            "the release is on another channel; switching channels needs an explicit update"
        ))
    );
    // An explicit rollback to the exact older version stages it, still verified.
    assert_eq!(
        forward.check(Some(OLD), Admission::Explicit).await,
        Ok(Outcome::Staged(OLD.into()))
    );
    assert_eq!(state(&release, NEW).hold.as_deref(), Some(OLD));
}

/// An explicit rollback holds until it is applied or cancelled; periodic checks never
/// wipe it (J725 P3-3).
#[tokio::test]
async fn an_explicit_rollback_holds_until_applied_or_cancelled() {
    let (release, bucket) = channel(NEW);
    let old = Release::with_version(4096, OLD);
    bucket.files.lock().unwrap().extend(old.files.clone());
    let trust = format!("{}{}", release.trust, old.trust);
    let running_new = updater_with_trust(&release, &bucket.origin, NEW, &trust);
    assert_eq!(
        running_new.check(Some(OLD), Admission::Explicit).await,
        Ok(Outcome::Staged(OLD.into()))
    );
    // Several periodic checks later it is still staged, untouched and offline-free.
    let requests = image_requests(&bucket);
    for _ in 0..3 {
        assert_eq!(
            running_new.check(None, Admission::Forward).await,
            Ok(Outcome::Held(OLD.into()))
        );
    }
    assert_eq!(
        image_requests(&bucket),
        requests,
        "a held stage asks nothing"
    );
    let saved = state(&release, NEW);
    assert_eq!(
        (saved.staged.as_deref(), saved.hold.as_deref()),
        (Some(OLD), Some(OLD))
    );
    // S4's confirmation applies the held release, though the channel points elsewhere.
    assert_eq!(running_new.confirm_staged().await.unwrap().version(), OLD);
    // Cancelled: removed with the reason, and periodic checks resume.
    running_new.cancel_hold().await.unwrap();
    let saved = state(&release, NEW);
    assert_eq!((saved.staged, saved.hold), (None, None));
    assert_eq!(
        saved.removed.unwrap().reason,
        infraternal_plugin_release::update::REMOVED_CANCELLED
    );
    assert_eq!(
        running_new.check(None, Admission::Forward).await,
        Ok(Outcome::Current(NEW.into()))
    );
    // Held again, then applied: once the server runs OLD the hold ends by itself.
    assert!(
        running_new
            .check(Some(OLD), Admission::Explicit)
            .await
            .is_ok()
    );
    let running_old = updater_with_trust(&release, &bucket.origin, OLD, &trust);
    assert_eq!(
        running_old.check(None, Admission::Forward).await,
        Ok(Outcome::Staged(NEW.into()))
    );
    let saved = state(&release, OLD);
    assert_eq!((saved.staged.as_deref(), saved.hold), (Some(NEW), None));
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
    // It says plainly whether this host updates itself, and why not (J725 P3-4). Test
    // binaries are development builds or run unprivileged, so this host reports off.
    match infraternal_plugin_release::update::availability(super::release_build()) {
        Ok(_) => {
            assert_eq!(shown["mode"], "auto");
            assert!(shown["reason"].is_null());
        }
        Err(reason) => {
            assert_eq!(shown["mode"], "off");
            assert_eq!(shown["reason"], reason);
        }
    }
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

/// A release the channel withdraws is removed, never kept for S4 (J725 P2-1): the edge
/// pointer moves back to the running version (a yanked build), then to nothing.
#[tokio::test]
async fn a_withdrawn_release_is_removed_and_the_state_says_why() {
    let (release, bucket) = channel(NEW);
    let old = Release::with_version(4096, OLD);
    bucket.files.lock().unwrap().extend(old.files.clone());
    let updater = updater_with_trust(
        &release,
        &bucket.origin,
        OLD,
        &format!("{}{}", release.trust, old.trust),
    );
    assert_eq!(
        updater.check(None, Admission::Forward).await,
        Ok(Outcome::Staged(NEW.into()))
    );
    // The owner yanks NEW: the pointer names the running version again.
    point(&bucket, OLD);
    assert_eq!(
        updater.check(None, Admission::Forward).await,
        Ok(Outcome::Current(OLD.into()))
    );
    let saved = state(&release, OLD);
    assert_eq!(saved.staged, None);
    assert_eq!(saved.available.as_deref(), Some(OLD));
    let removed = saved.removed.unwrap();
    assert_eq!(
        (removed.version.as_deref(), removed.reason.as_str()),
        (Some(NEW), REMOVED_WITHDRAWN)
    );
    assert_eq!(leftovers(&release), ["state.json"]);
    // Staged again, then the channel stops announcing anything at all.
    point(&bucket, NEW);
    assert!(updater.check(None, Admission::Forward).await.is_ok());
    bucket
        .files
        .lock()
        .unwrap()
        .remove("/releases/channels/edge.json");
    assert_eq!(
        updater.check(None, Admission::Forward).await,
        Ok(Outcome::Empty)
    );
    assert_eq!(state(&release, OLD).staged, None);
    assert_eq!(leftovers(&release), ["state.json"]);
}

/// S4's apply-time check confirms only a staged release the channel still announces,
/// and removes one it withdrew even before a periodic check noticed (J725 P2-1).
#[tokio::test]
async fn apply_time_confirmation_refuses_a_withdrawn_release() {
    let (release, bucket) = channel(NEW);
    // OLD is published too, so the pointer can move back to a verifiable release.
    let old = Release::with_version(4096, OLD);
    bucket.files.lock().unwrap().extend(old.files.clone());
    let updater = updater_with_trust(
        &release,
        &bucket.origin,
        OLD,
        &format!("{}{}", release.trust, old.trust),
    );
    assert_eq!(updater.confirm_staged().await.err(), Some(NOTHING_STAGED));
    assert!(updater.check(None, Admission::Forward).await.is_ok());
    {
        let confirmed = updater.confirm_staged().await.unwrap();
        assert_eq!(confirmed.version(), NEW);
        assert_eq!(
            std::fs::read(confirmed.image()).unwrap(),
            release.files[&format!("/releases/{NEW}/{}", artifact())]
        );
        // While S4 holds the confirmation no check can touch staged/.
        let racing = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            updater.check(None, Admission::Forward),
        )
        .await;
        assert!(racing.is_err(), "a check waits for the confirmation's lock");
    }
    // Withdrawn between the last periodic check and the apply.
    point(&bucket, OLD);
    assert_eq!(
        updater.confirm_staged().await.err(),
        Some("the channel no longer offers the staged release")
    );
    let saved = state(&release, OLD);
    assert_eq!(saved.staged, None);
    assert_eq!(saved.removed.unwrap().reason, REMOVED_WITHDRAWN);
    assert_eq!(leftovers(&release), ["state.json"]);
}

/// Policy refusals and switched-off updates are not failures (J725 P3-2): repeated
/// refusals keep `failures` at 0 and the timer at its normal 15-minute pace, while an
/// explicit request still gets the refusal as an error.
#[tokio::test]
async fn refusals_and_disabled_updates_never_back_off() {
    let (release, bucket) = channel(NEW);
    // An edge build on a server whose setting is stable once stable publishes.
    let stable = Release::with_version(4096, "0.2.0");
    bucket.files.lock().unwrap().extend(stable.files.clone());
    bucket.files.lock().unwrap().insert(
        "/releases/channels/stable.json".into(),
        b"{\"version\":\"0.2.0\"}".to_vec(),
    );
    let on_stable = Updater::new(
        &release.root,
        bucket.origin.clone(),
        OLD.into(),
        artifact().into(),
        Arc::new(Engine {
            trust: Some(format!("{}{}", release.trust, stable.trust)),
        }),
        Arc::new(|| Box::pin(async { Ok((true, "stable".to_owned())) })),
    );
    for _ in 0..3 {
        assert!(matches!(
            on_stable.check(None, Admission::Forward).await,
            Ok(Outcome::Refused(_))
        ));
    }
    let saved = state(&release, OLD);
    assert_eq!((saved.failures, saved.last_error), (0, None));
    assert!(saved.refused.is_some());
    // The timer keeps its normal pace after a refusal: wait for the note it writes after
    // its own check (times are whole seconds, so compare the gap, not the stamps).
    let mut changes = infraternal_plugin_release::update::changes();
    let task = Arc::new(on_stable).spawn_after(std::time::Duration::ZERO);
    let saved = wait_for_state(&release, OLD, &mut changes, |saved| {
        saved
            .next_check
            .zip(saved.last_check)
            .is_some_and(|(next, last)| next > last + 60)
    })
    .await;
    task.abort();
    let wait = saved.next_check.unwrap() - saved.last_check.unwrap();
    assert!((11 * 60..=19 * 60).contains(&wait), "{wait}");
    assert_eq!(saved.failures, 0);
    // An explicit request still reports the refusal to its caller, uncounted.
    let explicit = updater(&release, &bucket.origin, NEW);
    assert_eq!(
        explicit
            .check(Some("not-a-version"), Admission::Explicit)
            .await,
        Err("the release version is malformed")
    );
    assert_eq!(state(&release, NEW).failures, 0);
    // Updates switched off: a refusal, nothing touched, nothing counted.
    let off = Updater::new(
        &release.root,
        bucket.origin.clone(),
        OLD.into(),
        artifact().into(),
        Arc::new(Engine {
            trust: Some(release.trust.clone()),
        }),
        Arc::new(|| Box::pin(async { Ok((false, "edge".to_owned())) })),
    );
    let requests = image_requests(&bucket);
    assert_eq!(
        off.check(None, Admission::Forward).await,
        Ok(Outcome::Refused(UPDATES_OFF))
    );
    assert_eq!(image_requests(&bucket), requests, "no request while off");
    assert_eq!(state(&release, OLD).failures, 0);
}

/// A signed-in owner's socket in the owner-controls test.
struct OwnerHost;
impl infraternal_plugin_api::SocketHost for OwnerHost {
    fn user_id(&self) -> &'static str {
        "owner"
    }
    fn token_hash(&self) -> &'static str {
        "session-hash"
    }
    fn authorized<'a>(
        &'a self,
        op: infraternal_plugin_api::Operation<'a, Result<(), ()>>,
    ) -> infraternal_plugin_api::Operation<'a, Result<(), ()>> {
        op
    }
    fn fresh(&self, _now: i64) -> infraternal_plugin_api::Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn live(&self) -> infraternal_plugin_api::Operation<'_, bool> {
        Box::pin(async { true })
    }
    fn may_configure(&self) -> infraternal_plugin_api::Operation<'_, bool> {
        Box::pin(async { true })
    }
}

/// An applier that only records which release it was handed, standing in for S4.
struct Recorder(std::sync::Mutex<Vec<String>>);
impl infraternal_plugin_release::applier::UpdateApplier for Recorder {
    fn apply(
        &self,
        release: infraternal_plugin_release::update::Confirmed,
    ) -> infraternal_plugin_api::Operation<
        '_,
        Result<infraternal_plugin_release::applier::Started, &'static str>,
    > {
        self.0.lock().unwrap().push(release.version().to_owned());
        let to = release.version().to_owned();
        Box::pin(async move {
            Ok(infraternal_plugin_release::applier::Started {
                to,
                lost_since: None,
            })
        })
    }
    fn rollback(
        &self,
    ) -> infraternal_plugin_api::Operation<
        '_,
        Result<infraternal_plugin_release::applier::Started, &'static str>,
    > {
        self.0.lock().unwrap().push("rollback".into());
        Box::pin(async {
            Ok(infraternal_plugin_release::applier::Started {
                to: OLD.into(),
                lost_since: Some(1_700_000_000),
            })
        })
    }
    fn rollback_plan(&self) -> Option<infraternal_plugin_release::applier::RollbackPlan> {
        Some(infraternal_plugin_release::applier::RollbackPlan {
            to: OLD.into(),
            copy_taken_at: 1_700_000_000,
        })
    }
}

/// The owner controls (#211 S5): everything that changes what the server runs needs an owner
/// with a fresh session; a plain check needs only the owner; apply refuses a release other than
/// the one the owner saw; cancel and settings work; history lists newest first; and status
/// carries the quiet window and the rollback plan (what going back restores).
#[tokio::test]
async fn owner_controls_need_a_fresh_owner_and_reach_the_applier() {
    let (release, bucket) = channel(NEW);
    let old = Release::with_version(4096, OLD);
    bucket.files.lock().unwrap().extend(old.files.clone());
    let trust = format!("{}{}", release.trust, old.trust);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql("CREATE TABLE plugin_settings(role TEXT,plugin TEXT,enabled INTEGER,settings TEXT NOT NULL DEFAULT '{}',PRIMARY KEY(role,plugin)); CREATE TABLE users(id TEXT,owner INTEGER); CREATE TABLE sessions(token_hash TEXT,user_id TEXT,unlocked INTEGER,expires INTEGER,fresh INTEGER); INSERT INTO users VALUES('owner',1); INSERT INTO plugin_settings VALUES('server','release',1,'{\"channel\":\"edge\"}');")
        .execute(&pool)
        .await
        .unwrap();
    let lookup = infraternal_plugin_release::latest::VerifiedLookup::new(
        release.root.clone(),
        bucket.origin.clone(),
        Arc::new(Engine {
            trust: Some(trust.clone()),
        }),
    )
    .with_updates(Ok(()))
    .with_updater(Arc::new(updater_with_trust(
        &release,
        &bucket.origin,
        NEW,
        &trust,
    )));
    let recorder = Arc::new(Recorder(std::sync::Mutex::default()));
    let service =
        infraternal_plugin_release::service::ReleaseService::new(pool.clone(), Arc::new(lookup))
            .with_applier(recorder.clone());
    let host: Option<&dyn infraternal_plugin_api::SocketHost> = Some(&OwnerHost);
    let call = |action: &'static str, input: &'static [u8]| {
        let service = service.clone();
        async move { service.call(action, input, host).await }
    };
    // An owner whose session is not fresh may check the channel, and nothing else.
    assert_eq!(
        call("release.update.check", b"{}").await.unwrap()["outcome"],
        "current"
    );
    for (action, input) in [
        ("release.update.check", format!("{{\"version\":\"{OLD}\"}}")),
        ("release.update.apply", "{}".into()),
        ("release.update.rollback", "{}".into()),
        ("release.update.cancel", "{}".into()),
        ("release.update.settings", "{\"quiet_minutes\":30}".into()),
    ] {
        let input: &'static [u8] = Box::leak(input.into_bytes().into_boxed_slice());
        assert_eq!(call(action, input).await, Err("not permitted"), "{action}");
    }
    assert!(recorder.0.lock().unwrap().is_empty());
    // A non-owner is refused even the plain check.
    sqlx::query("UPDATE users SET owner=0")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call("release.update.check", b"{}").await,
        Err("not permitted")
    );
    sqlx::query("UPDATE users SET owner=1")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sessions VALUES('session-hash','owner',1,unixepoch()+600,unixepoch())",
    )
    .execute(&pool)
    .await
    .unwrap();
    // Stage the older release by version: held, listed in the status.
    let input: &'static [u8] = Box::leak(
        format!("{{\"version\":\"{OLD}\"}}")
            .into_bytes()
            .into_boxed_slice(),
    );
    let staged = call("release.update.check", input).await.unwrap();
    assert_eq!(
        (&staged["outcome"], &staged["version"]),
        (&json!("staged"), &json!(OLD))
    );
    assert_eq!(staged["state"]["hold"], OLD);
    // Apply refuses a release other than the one named, then applies the staged one.
    let wrong: &'static [u8] = Box::leak(
        format!("{{\"version\":\"{NEWER}\"}}")
            .into_bytes()
            .into_boxed_slice(),
    );
    assert_eq!(
        call("release.update.apply", wrong).await,
        Err("a different release is staged")
    );
    assert!(recorder.0.lock().unwrap().is_empty());
    let started = call("release.update.apply", input).await.unwrap();
    assert_eq!(started["to"], OLD);
    assert_eq!(recorder.0.lock().unwrap().as_slice(), [OLD]);
    // Status: quiet window default, then saved; rollback plan; invalid windows refused.
    let shown = call("release.update.status", b"{}").await.unwrap();
    assert_eq!(shown["quiet_minutes"], 5);
    assert_eq!(
        shown["rollback"],
        json!({"to":OLD,"copy_taken_at":1_700_000_000})
    );
    let shown = call("release.update.settings", b"{\"quiet_minutes\":30}")
        .await
        .unwrap();
    assert_eq!(
        (&shown["quiet_minutes"], &shown["channel"]),
        (&json!(30), &json!("edge"))
    );
    for bad in [
        b"{\"quiet_minutes\":0}".as_slice(),
        b"{\"quiet_minutes\":1441}",
        b"{\"quiet_minutes\":-1}",
        b"{}",
    ] {
        assert_eq!(
            call("release.update.settings", bad).await,
            Err("invalid input")
        );
    }
    // Rollback reaches the applier and says which data is lost.
    let back = call("release.update.rollback", b"{}").await.unwrap();
    assert_eq!(back["lost_since"], 1_700_000_000);
    // Cancel removes the hold; history lists newest first.
    let cancelled = call("release.update.cancel", b"{}").await.unwrap();
    assert!(cancelled["hold"].is_null() && cancelled["staged"].is_null());
    let history = call("release.update.history", b"{}").await.unwrap();
    let kinds: Vec<_> = history["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["removed", "staged"]);
    assert_eq!(history["entries"][0]["version"], OLD);
}

/// Updates switched off win over a held explicit stage (J734 P3-a): the owner turned
/// the release plugin off after staging a rollback, so the apply-time confirmation
/// refuses it and nothing applies. The stage itself is kept for when updates return.
#[tokio::test]
async fn switched_off_updates_refuse_even_a_held_stage() {
    let (release, bucket) = channel(NEW);
    let old = Release::with_version(4096, OLD);
    bucket.files.lock().unwrap().extend(old.files.clone());
    let enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let switch = Arc::clone(&enabled);
    let running_new = Updater::new(
        &release.root,
        bucket.origin.clone(),
        NEW.into(),
        artifact().into(),
        Arc::new(Engine {
            trust: Some(format!("{}{}", release.trust, old.trust)),
        }),
        Arc::new(move || {
            let on = switch.load(Ordering::Relaxed);
            Box::pin(async move { Ok((on, "edge".to_owned())) })
        }),
    );
    assert_eq!(
        running_new.check(Some(OLD), Admission::Explicit).await,
        Ok(Outcome::Staged(OLD.into()))
    );
    enabled.store(false, Ordering::Relaxed);
    assert_eq!(running_new.confirm_staged().await.err(), Some(UPDATES_OFF));
    let saved = state(&release, NEW);
    assert_eq!(
        (saved.staged.as_deref(), saved.hold.as_deref()),
        (Some(OLD), Some(OLD))
    );
    enabled.store(true, Ordering::Relaxed);
    assert_eq!(running_new.confirm_staged().await.unwrap().version(), OLD);
}

/// A pointer that moves on to a newer release keeps the staged one until the newer one
/// is staged (J734 P3-c). Here the newer release's signed metadata is published but its
/// image is not there yet, so the check verifies the pointer, then fails the download:
/// the older release stays staged and nothing calls it withdrawn. At apply time the
/// confirmation refuses it, because the channel now offers something newer, but keeps
/// it; once the newer image arrives it replaces the staged one.
#[tokio::test]
async fn a_superseded_release_stays_staged_until_its_successor_is_ready() {
    use infraternal_plugin_release::update::SUPERSEDED;
    let (release, bucket) = channel(NEW);
    // NEWER is signed by its own fixture key; the updater trusts both (D224 spare key).
    let newer = Release::with_version(4096, NEWER);
    let updater = updater_with_trust(
        &release,
        &bucket.origin,
        OLD,
        &format!("{}{}", release.trust, newer.trust),
    );
    assert!(updater.check(None, Admission::Forward).await.is_ok());
    let image = format!("/releases/{NEWER}/{}", artifact());
    bucket.files.lock().unwrap().extend(
        newer
            .files
            .iter()
            .filter(|(path, _)| **path != image)
            .map(|(path, bytes)| (path.clone(), bytes.clone())),
    );
    point(&bucket, NEWER);
    assert!(updater.check(None, Admission::Forward).await.is_err());
    let saved = state(&release, OLD);
    assert_eq!(saved.available.as_deref(), Some(NEWER));
    assert_eq!((saved.staged.as_deref(), saved.removed), (Some(NEW), None));
    assert_eq!(updater.confirm_staged().await.err(), Some(SUPERSEDED));
    let saved = state(&release, OLD);
    assert_eq!((saved.staged.as_deref(), saved.removed), (Some(NEW), None));
    // NEWER's image arrives: it replaces NEW.
    bucket
        .files
        .lock()
        .unwrap()
        .insert(image.clone(), newer.files[&image].clone());
    assert_eq!(
        updater.check(None, Admission::Forward).await,
        Ok(Outcome::Staged(NEWER.into()))
    );
    assert_eq!(state(&release, OLD).removed, None);
}
