//! Switching to a staged release and undoing a failed one (#211 S4; D251, D295, D217).
//!
//! S3 ([`crate::update`]) keeps one verified release staged. This module holds the
//! file side of applying it. The server ties it to its quiet window, its health
//! check and the warm handoff:
//!
//! 1. **Install.** [`install`] turns a [`Confirmed`] stage into `releases/<version>/`
//!    by renaming the folder, so the open image the verifier hashed stays the same
//!    inode (J734 P3-b). The folder lock stays held until the process execs.
//! 2. **Keep the previous release.** [`Switch::save_previous`] copies the running image
//!    into `previous/`, and the server writes its D295 database copy beside it
//!    (`VACUUM INTO` [`Switch::database_copy`]).
//! 3. **Mark the switch.** [`Switch::begin`] writes `pending.json` in phase
//!    [`Phase::Switching`] just before the warm exec. It names both releases by the
//!    SHA-256 of their images, so a process can tell at startup which side it is.
//! 4. **Startup.** Every server start calls [`resume`] before it opens the database:
//!    - The new release (B) moves the phase to [`Phase::Trial`] and runs its health
//!      check. Then it calls [`commit`] or [`begin_rollback`].
//!    - The previous release (A), when it finds that B ran (phase `trial` or
//!      `rollback`), puts the database copy back before anything opens it. It records
//!      the update as undone and pauses B.
//!
//! **The boot pointer.** `current` is a symlink to `releases/<version>`. It changes
//! only in [`commit`], after the health check passed, so a crash or kill of B during
//! its trial starts A again (D295: "the previous version stays the one that starts on
//! any restart until the new one passes its health check"). A service that should
//! follow updates across cold starts runs `updates/current/<image>` (S6 points the
//! production unit there).
//!
//! **One live server.** Every switch, forward or back, is a same-PID exec, so two
//! server processes never run at once. The mesh identity is never lost: it lives in
//! `<data>/mesh/` (#489), and the switch mirrors it to the legacy runtime path for a
//! previous build, which an undo requires before it starts.
//!
//! Layout inside `<data>/updates/` (all of it root-only, under the S3 folder lock):
//!
//! ```text
//! current -> releases/<v>     the release that starts (after its health check)
//! releases/<v>/               VERSION, SHA256SUMS, SHA256SUMS.sig and the image (0700)
//! previous/                   the image that ran before the last switch, and
//!                             database.sqlite, its D295 database copy
//! pending.json                the switch in flight (see [`Pending`])
//! ```
use crate::update::{
    APPLIED, Applied, Confirmed, Locked, NOT_APPLIED, UNDONE, now, open_private, status_of,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// The marker of a switch in flight, inside `updates/`.
pub const PENDING: &str = "pending.json";
/// The database file every server keeps in its data folder.
pub const DATABASE: &str = "infraternal.sqlite";
/// The largest `pending.json` accepted.
const MAX_PENDING: u64 = 8192;

/// Why B undid itself when its health check did not pass in time.
pub const UNHEALTHY: &str = "the new release failed its health check";
/// Why A undid B when B stopped during its trial (a crash, a kill or a reboot).
pub const STOPPED_IN_TRIAL: &str = "the new release stopped during its health check";
/// Why A paused B when B's exec failed and A came back without B running.
pub const DID_NOT_START: &str = "the new release could not start";
/// Why a marker that names neither the running image nor its predecessor was dropped.
pub const INTERRUPTED: &str = "the update was interrupted by a different server binary";

/// Where a switch is (see the module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// A is about to exec B; B has not started yet.
    Switching,
    /// B started and runs its health check.
    Trial,
    /// B failed and is execing A.
    Rollback,
}

/// The switch in flight, written by A before the exec and updated by B (`pending.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// Where the switch is.
    pub phase: Phase,
    /// A's release version (its compiled version).
    pub from_version: String,
    /// SHA-256 of A's image, as hex. B admits `previous/` only with these bytes.
    pub from_sha256: String,
    /// A's own executable path (argv\[0\]), given back to A when B undoes the switch.
    pub from_path: PathBuf,
    /// B's release version.
    pub to_version: String,
    /// SHA-256 of B's image, as hex.
    pub to_sha256: String,
    /// Whether A had the CA unlocked. B must too, or its health check fails (D217).
    pub ca_warm: bool,
    /// When A began the switch, in Unix seconds.
    pub started: i64,
    /// Why B is being undone, once it is.
    pub reason: Option<String>,
    /// How many times B came back after its undo exec failed (see [`MAX_UNDO_ATTEMPTS`]).
    #[serde(default)]
    pub undo_attempts: u32,
}

/// How often B retries the warm undo when its exec of A keeps failing. After that B keeps
/// serving and the marker stays in phase `rollback`, so A's next cold start still
/// restores its database copy. B never exits on its own: an exit is a cold start that
/// locks the CA (D168), and its service manager may clear the runtime directory.
pub const MAX_UNDO_ATTEMPTS: u32 = 3;
/// The [`Resume::Finished`] outcome once B gave up undoing itself.
pub const UNDO_FAILED: &str = "undo-failed";

/// A confirmed release installed as `releases/<version>/` and ready to switch to.
///
/// It owns the folder lock and the verified image file until the process execs (both
/// are close-on-exec, so the exec releases them) or the switch is given up with
/// [`Switch::abandon`].
pub struct Switch {
    /// The release version.
    version: String,
    /// The open, verified image, now at [`Switch::path`].
    image: File,
    /// `updates/releases/<version>/<artifact>`.
    path: PathBuf,
    /// The S3 folder lock.
    lock: Locked,
}

/// Install the confirmed release as `releases/<version>/` and keep it locked.
///
/// The staged folder is renamed, never copied, so the open verified image stays the
/// file that runs. The image is made executable (0700) so `current/<image>` can be a
/// service's executable after [`commit`]. The installed image is still checked against
/// its signature on a sealed copy before the exec; see the server's switch.
/// # Errors
/// The folder could not be renamed or saved.
pub fn install(confirmed: Confirmed, artifact: &str) -> Result<Switch, &'static str> {
    let saved = "the update could not be installed";
    let (version, image, lock) = confirmed.into_parts();
    let updates = lock.directory().to_owned();
    lock.sweep()?;
    let releases = updates.join("releases");
    private_folder(&releases).map_err(|()| saved)?;
    let target = releases.join(&version);
    remove_entry(&lock, &target)?;
    std::fs::rename(updates.join("staged"), &target).map_err(|_| saved)?;
    image
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(|_| saved)?;
    sync(&releases).map_err(|()| saved)?;
    lock.sync()?;
    Ok(Switch {
        path: target.join(artifact),
        version,
        image,
        lock,
    })
}

impl Switch {
    /// The release version being switched to.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The verified image file. Switch from this file, never by reopening [`Self::path`].
    #[must_use]
    pub fn file(&self) -> &File {
        &self.image
    }

    /// Where the image is installed: the new process's argv\[0\], and the folder whose
    /// signed metadata the switch re-checks.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// SHA-256 of the image to switch to, as hex. Reads the open verified file.
    /// # Errors
    /// The image could not be read.
    pub fn digest(&self) -> Result<String, &'static str> {
        digest(&self.image)
    }

    /// Replace `previous/` with a copy of the running image (read from `running`, the
    /// kernel's handle on it) and return its SHA-256 as hex.
    ///
    /// The copy is written into a fresh `download-*` folder (swept if abandoned) and
    /// renamed into place, so `previous/` is always whole.
    /// # Errors
    /// The copy could not be written or saved.
    pub fn save_previous(&self, running: &File, artifact: &str) -> Result<String, &'static str> {
        let saved = "the previous release could not be kept";
        let mut folder = self.lock.download()?;
        let mut copy = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(folder.path.join(artifact))
            .map_err(|_| saved)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1 << 16];
        let mut offset = 0u64;
        loop {
            // Positional reads leave the shared offset of the caller's handle alone.
            let count = std::os::unix::fs::FileExt::read_at(running, &mut buffer, offset)
                .map_err(|_| saved)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            copy.write_all(&buffer[..count]).map_err(|_| saved)?;
            offset += count as u64;
        }
        copy.sync_all().map_err(|_| saved)?;
        sync(&folder.path).map_err(|()| saved)?;
        let previous = self.lock.directory().join("previous");
        remove_entry(&self.lock, &previous)?;
        std::fs::rename(&folder.path, &previous).map_err(|_| saved)?;
        folder.published = true;
        self.lock.sync()?;
        Ok(hex(&hasher.finalize()))
    }

    /// Where the server writes its D295 database copy (`VACUUM INTO`), after
    /// [`Switch::save_previous`]. The file does not exist yet.
    #[must_use]
    pub fn database_copy(&self) -> PathBuf {
        self.lock.directory().join("previous").join(DATABASE)
    }

    /// Write `pending.json` (phase [`Phase::Switching`]): the last step before the exec.
    /// # Errors
    /// The marker could not be saved.
    pub fn begin(&self, pending: &Pending) -> Result<(), &'static str> {
        write_pending(&self.lock, pending)
    }

    /// Give the switch up before the exec: remove the marker and the installed release,
    /// and record `reason`. Nothing that ran is changed.
    /// # Errors
    /// The update folder could not be cleaned up.
    pub fn abandon(self, current: &str, reason: &'static str) -> Result<(), &'static str> {
        let updates = self.lock.directory().to_owned();
        remove_pending(&self.lock)?;
        remove_entry(&self.lock, &updates.join("releases").join(&self.version))?;
        let mut state = status_of(&updates, current);
        state.applied = Some(record(&self.version, NOT_APPLIED, Some(reason)));
        self.lock.write_state(&state)
    }
}

/// What a starting server must do about a switch in flight; see [`resume`].
#[derive(Debug, PartialEq, Eq)]
pub enum Resume {
    /// Nothing is in flight.
    Idle,
    /// This process is the new release on trial: run the health check, then [`commit`]
    /// or [`begin_rollback`]. A marker that already carries a `reason` means B started
    /// again mid-trial, or came back after its undo exec failed: the trial has failed
    /// and B undoes itself again.
    Trial(Pending),
    /// The switch was finished at this start (as the previous release), or B gave up
    /// undoing itself ([`UNDO_FAILED`]); the outcome is recorded.
    Finished(&'static str),
}

/// Decide, before the database opens, what this starting server does about a switch
/// in flight, and do the previous release's part of an undo.
///
/// `data` is the data folder, `current` this process's version, and `own` returns the
/// SHA-256 of this process's image (only called when a marker exists, so a normal
/// start never hashes anything). As the previous release after B ran, this restores
/// `previous/database.sqlite` over the database (removing its WAL and shared-memory
/// files first) before returning, then records the update as undone and pauses B.
/// # Errors
/// The update folder is unsafe, or the marker or database could not be handled. The
/// caller then keeps the marker and starts anyway: a failed undo must never block
/// the server from serving.
pub fn resume(
    data: &Path,
    current: &str,
    own: impl FnOnce() -> Result<String, &'static str>,
) -> Result<Resume, &'static str> {
    let updates = data.join("updates");
    if std::fs::symlink_metadata(updates.join(PENDING)).is_err() {
        return Ok(Resume::Idle);
    }
    let lock = Locked::open(&updates)?;
    let Some(mut pending) = read_pending(&updates) else {
        remove_pending(&lock)?;
        return Ok(Resume::Idle);
    };
    let own = own()?;
    if own == pending.to_sha256 {
        return match pending.phase {
            Phase::Switching => {
                pending.phase = Phase::Trial;
                write_pending(&lock, &pending)?;
                Ok(Resume::Trial(pending))
            }
            // B started again mid-trial (a reload or a restart into B): it is not
            // healthy as far as anyone can tell, so its trial fails.
            Phase::Trial => {
                pending.reason = Some(STOPPED_IN_TRIAL.to_owned());
                Ok(Resume::Trial(pending))
            }
            // The exec of A failed and the late-exec recovery brought B back.
            Phase::Rollback if pending.undo_attempts < MAX_UNDO_ATTEMPTS => {
                pending.undo_attempts += 1;
                write_pending(&lock, &pending)?;
                Ok(Resume::Trial(pending))
            }
            Phase::Rollback => Ok(Resume::Finished(UNDO_FAILED)),
        };
    }
    let mut state = status_of(&updates, current);
    let outcome = if own == pending.from_sha256 {
        let reason = match pending.phase {
            Phase::Switching => DID_NOT_START,
            Phase::Trial => STOPPED_IN_TRIAL,
            Phase::Rollback => match pending.reason.as_deref() {
                Some(UNHEALTHY) => UNHEALTHY,
                _ => STOPPED_IN_TRIAL,
            },
        };
        // B never ran after a failed exec, so the database is still A's own.
        if pending.phase != Phase::Switching {
            restore_database(data, &updates.join("previous").join(DATABASE))?;
        }
        remove_entry(&lock, &updates.join("releases").join(&pending.to_version))?;
        state.applied = Some(record(&pending.to_version, UNDONE, Some(reason)));
        state.paused = Some(pending.to_version.clone());
        UNDONE
    } else {
        state.applied = Some(record(&pending.to_version, NOT_APPLIED, Some(INTERRUPTED)));
        NOT_APPLIED
    };
    remove_pending(&lock)?;
    lock.write_state(&state)?;
    Ok(Resume::Finished(outcome))
}

/// Make B the release that starts (its health check passed): point `current` at
/// `releases/<B>`, drop other installed releases, remove the marker and record it.
///
/// `previous/` (A and the database copy) is kept until the next update (D295), for a
/// manual roll back.
/// # Errors
/// The marker no longer describes this trial, or the pointer could not be saved.
pub fn commit(data: &Path, trial: &Pending) -> Result<(), &'static str> {
    let saved = "the update could not be committed";
    let updates = data.join("updates");
    let lock = Locked::open(&updates)?;
    if read_pending(&updates).as_ref() != Some(trial) {
        return Err("the update marker changed during the health check");
    }
    let temporary = updates.join("current.tmp");
    let _ = std::fs::remove_file(&temporary);
    std::os::unix::fs::symlink(Path::new("releases").join(&trial.to_version), &temporary)
        .map_err(|_| saved)?;
    std::fs::rename(&temporary, updates.join("current")).map_err(|_| saved)?;
    lock.sync()?;
    let releases = updates.join("releases");
    if let Ok(entries) = std::fs::read_dir(&releases) {
        for entry in entries.flatten() {
            if entry.file_name() != trial.to_version.as_str() {
                remove_entry(&lock, &entry.path())?;
            }
        }
    }
    remove_pending(&lock)?;
    let mut state = status_of(&updates, &trial.to_version);
    state.applied = Some(record(&trial.to_version, APPLIED, None));
    if state.paused.as_deref() == Some(trial.to_version.as_str()) {
        state.paused = None;
    }
    lock.write_state(&state)
}

/// What B needs to exec A again: the kept image, its expected SHA-256 and A's argv\[0\].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Undo {
    /// `updates/previous/<artifact>`.
    pub image: PathBuf,
    /// The SHA-256 A recorded for its own image; anything else is refused.
    pub sha256: String,
    /// A's executable path, restored as argv\[0\].
    pub path: PathBuf,
}

/// Mark the trial as failed (phase [`Phase::Rollback`], with `reason`) and return what
/// B needs to exec A. A finishes the undo in [`resume`].
/// # Errors
/// The marker no longer describes this trial, or could not be saved.
pub fn begin_rollback(
    data: &Path,
    trial: &Pending,
    artifact: &str,
    reason: &'static str,
) -> Result<Undo, &'static str> {
    let updates = data.join("updates");
    let lock = Locked::open(&updates)?;
    let mut pending = read_pending(&updates)
        .filter(|pending| pending.to_sha256 == trial.to_sha256)
        .ok_or("the update marker changed during the health check")?;
    pending.phase = Phase::Rollback;
    pending.reason = Some(reason.to_owned());
    write_pending(&lock, &pending)?;
    Ok(Undo {
        image: updates.join("previous").join(artifact),
        sha256: pending.from_sha256,
        path: pending.from_path,
    })
}

/// SHA-256 of everything in `file`, as lowercase hex, read with positional reads.
/// # Errors
/// The file could not be read.
pub fn digest(file: &File) -> Result<String, &'static str> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 16];
    let mut offset = 0u64;
    loop {
        let count = std::os::unix::fs::FileExt::read_at(file, &mut buffer, offset)
            .map_err(|_| "the release image could not be read")?;
        if count == 0 {
            return Ok(hex(&hasher.finalize()));
        }
        hasher.update(&buffer[..count]);
        offset += count as u64;
    }
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// An [`Applied`] record stamped now.
fn record(version: &str, outcome: &str, reason: Option<&str>) -> Applied {
    Applied {
        version: version.to_owned(),
        outcome: outcome.to_owned(),
        reason: reason.map(str::to_owned),
        at: now(),
    }
}

/// Read `pending.json`: a private regular file of ours, bounded; `None` if absent or bad.
fn read_pending(updates: &Path) -> Option<Pending> {
    let file = open_private(&updates.join(PENDING)).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_PENDING + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_PENDING {
        return None;
    }
    let pending: Pending = serde_json::from_slice(&bytes).ok()?;
    // Versions become folder names: only the release grammar (no separators) is accepted.
    let valid = |version: &str| infraternal_plugin_api::release_version::channel(version).is_some();
    (valid(&pending.from_version) && valid(&pending.to_version)).then_some(pending)
}

/// Replace `pending.json` atomically (private temporary file, flush, rename, flush folder).
fn write_pending(lock: &Locked, pending: &Pending) -> Result<(), &'static str> {
    let saved = "the update marker could not be saved";
    let updates = lock.directory();
    let temporary = updates.join("pending.json.tmp");
    let _ = std::fs::remove_file(&temporary);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| saved)?;
    let bytes = serde_json::to_vec(pending).map_err(|_| saved)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| saved)?;
    std::fs::rename(&temporary, updates.join(PENDING)).map_err(|_| saved)?;
    lock.sync()
}

/// Remove `pending.json` (if present) and flush the folder.
fn remove_pending(lock: &Locked) -> Result<(), &'static str> {
    match std::fs::remove_file(lock.directory().join(PENDING)) {
        Ok(()) => lock.sync(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("the update marker could not be removed"),
    }
}

/// Put the D295 database copy back as the server's database, before anything opens it.
///
/// The copy is written to a private temporary file, flushed and renamed over the
/// database; the old WAL and shared-memory files are removed first, since they belong
/// to the database being replaced. The copy itself is kept (a later manual roll back,
/// or a second failure, can use it again).
fn restore_database(data: &Path, copy: &Path) -> Result<(), &'static str> {
    let failed = "the database copy could not be restored";
    let mut source = open_private(copy).map_err(|_| failed)?;
    let temporary = data.join("infraternal.sqlite.restore");
    let _ = std::fs::remove_file(&temporary);
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| failed)?;
    std::io::copy(&mut source, &mut target).map_err(|_| failed)?;
    target.sync_all().map_err(|_| failed)?;
    for suffix in ["-wal", "-shm"] {
        match std::fs::remove_file(data.join(format!("{DATABASE}{suffix}"))) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(failed),
        }
    }
    std::fs::rename(&temporary, data.join(DATABASE)).map_err(|_| failed)?;
    sync(data).map_err(|()| failed)
}

/// Create `path` as a private (0700) folder if it is missing, and check it is one.
#[allow(clippy::verbose_bit_mask)]
fn private_folder(path: &Path) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(()),
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    (metadata.is_dir()
        && metadata.uid() == nix::unistd::geteuid().as_raw()
        && metadata.mode() & 0o077 == 0)
        .then_some(())
        .ok_or(())
}

/// Remove `path` without following it: moved aside to a `retired-*` name first (which
/// the S3 sweep deletes if this is interrupted), then deleted.
fn remove_entry(lock: &Locked, path: &Path) -> Result<(), &'static str> {
    let failed = "an old release could not be removed";
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    let retired = lock
        .directory()
        .join(format!("retired-{}", uuid::Uuid::new_v4().hyphenated()));
    std::fs::rename(path, &retired).map_err(|_| failed)?;
    let removed = if metadata.is_dir() {
        std::fs::remove_dir_all(&retired)
    } else {
        std::fs::remove_file(&retired)
    };
    removed.map_err(|_| failed)?;
    lock.sync()
}

/// Flush the folder `path` so renames inside it survive a crash.
fn sync(path: &Path) -> Result<(), ()> {
    File::open(path)
        .and_then(|folder| folder.sync_all())
        .map_err(|_| ())
}

/// Unit tests for install, the marker, resume, commit and undo.
#[cfg(test)]
#[path = "apply_tests.rs"]
mod tests;
