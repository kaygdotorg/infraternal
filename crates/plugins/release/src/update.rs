//! The server's own update check, download and staging (#211 S3; D185, D251, D295, D396).
//!
//! A running server asks its release channel (stable or edge, the `release` plugin's
//! `channel` setting) whether a newer release exists. When one does, it downloads that
//! release's image for this machine, verifies it with the one signed-release verifier
//! (S1: `SHA256SUMS`, `SHA256SUMS.sig` and the signed `VERSION`), and keeps it staged,
//! ready for S4 to apply. Nothing here applies, executes or switches anything.
//!
//! **Timing (D81).** [`Updater::spawn`] starts one task that sleeps on a timer between
//! checks: about 2 minutes after start, then every 15 minutes with ±20 % jitter, doubling
//! after each failed check up to 6 hours. A sleeping timer costs no CPU; there is no
//! polling loop. Offline or refused checks only record the reason in the update state
//! and log at debug level, so an offline server stays quiet.
//!
//! **Guard (J685 P3-3).** The periodic check ([`Admission::Forward`]) stages only a
//! strictly newer version on the running version's own channel. The same version does
//! nothing; an older version or another channel's release is refused. Only an explicit
//! request ([`Admission::Explicit`], for a D295 rollback or a deliberate channel switch
//! by S4/S5) may stage those. No admission ever skips the signature check.
//!
//! **Layout.** Everything lives in `<data>/updates/`, a directory owned by the server's
//! user with no group or other access (the timer only runs for root, so it is
//! root-only in production):
//!
//! ```text
//! updates/
//!   state.json         UpdateState, 0600, replaced atomically
//!   staged/            at most one verified release: VERSION, SHA256SUMS,
//!                      SHA256SUMS.sig and infraternal-<arch>-musl
//!   download-<uuid>/   one check in progress
//!   retired-<uuid>/    the previous staged release while it is being replaced
//! ```
//!
//! Every check holds an exclusive `flock` on `updates/` for its whole run, so only one
//! check (timer or explicit) touches the directory at a time. Under that lock every
//! `download-*` or `retired-*` folder is abandoned work, which the check deletes first.
//! Partial downloads are cleaned up, not resumed: release images are a few tens of
//! megabytes, and a restarted download is simpler to prove correct than a resumed one.
//!
//! **State.** [`UpdateState`] lives in `state.json` rather than the database because
//! S4's D295 undo restores the pre-update database copy, and that restore must not
//! erase the record of the update that was undone. Readers see either the old or the
//! new file, never a torn one. Every write bumps [`changes`], which wakes the plugin's
//! `release.update` subscribers.
use crate::latest::ReleaseEngine;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    time::Duration,
};

/// The largest release image the updater downloads (128 MiB), the same bound the
/// add-host payload resolver uses. Current images are about 30 MB.
pub const MAX_IMAGE: u64 = 128 * 1024 * 1024;
/// Free space that must remain on the data disk after the largest image is written,
/// so staging an update can never be what fills the server's disk.
pub const RESERVE: u64 = 64 * 1024 * 1024;
/// Longest one whole check may take, downloads included. Each network step also has
/// the downloader's own 30 s inactivity bound.
const CHECK_LIMIT: Duration = Duration::from_mins(10);
/// The largest `state.json` the status reader accepts.
const MAX_STATE: u64 = 4096;

/// Who asked for a release to be staged, which decides what the guard allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The periodic check: only a strictly newer release on the running channel.
    Forward,
    /// An explicit owner request (D295 rollback or a channel switch, S4/S5): an older
    /// version or another channel is allowed. The signature is still required.
    Explicit,
}

/// What the guard concluded about a candidate release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The candidate is the running version: nothing to do.
    Same,
    /// The candidate may be staged.
    Stage,
}

/// Decide whether `candidate` may be staged on a server running `current`.
///
/// Both are release versions in the D226 grammar (`1.2.3` for stable,
/// `edge-YYYYMMDDTHHMMSSZ` for edge); the channel is derived from each version.
/// # Errors
/// Refuses a malformed version, and for [`Admission::Forward`] an older version or a
/// release from another channel.
pub fn guard(
    current: &str,
    candidate: &str,
    admission: Admission,
) -> Result<Verdict, &'static str> {
    use infraternal_plugin_api::release_version::channel;
    let (Some(running), Some(offered)) = (channel(current), channel(candidate)) else {
        return Err("the release version is malformed");
    };
    if running != offered {
        return match admission {
            Admission::Explicit => Ok(Verdict::Stage),
            Admission::Forward => Err(
                "the release is on another channel; switching channels needs an explicit update",
            ),
        };
    }
    match compare(current, candidate) {
        Ordering::Equal => Ok(Verdict::Same),
        Ordering::Less => Ok(Verdict::Stage),
        Ordering::Greater => match admission {
            Admission::Explicit => Ok(Verdict::Stage),
            Admission::Forward => Err("the release is older than the running version"),
        },
    }
}

/// Order two versions of the same channel. Edge stamps are fixed-width UTC times, so
/// they order as text. Stable versions order by their three numbers, compared as
/// decimal strings so no number is too large and leading zeros do not matter.
fn compare(a: &str, b: &str) -> Ordering {
    if a.starts_with("edge-") {
        return a.cmp(b);
    }
    let number = |part: &str| {
        let digits = part.trim_start_matches('0');
        (digits.len(), digits.to_owned())
    };
    a.split('.').map(number).cmp(b.split('.').map(number))
}

/// The update state the server keeps and shows (S5's Updates row reads it).
///
/// Times are Unix seconds. Unknown fields from a newer server are ignored, and missing
/// ones take their defaults, so the file survives upgrades and downgrades.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateState {
    /// The version this server is running.
    pub current: String,
    /// The channel the last check asked (`stable` or `edge`).
    pub channel: String,
    /// The newest verified version the channel announced at the last check.
    pub available: Option<String>,
    /// The verified release waiting in `updates/staged/`, if any.
    pub staged: Option<String>,
    /// When the last check finished, successful or not.
    pub last_check: Option<i64>,
    /// When the timer will check next.
    pub next_check: Option<i64>,
    /// Why the last check failed or what it refused; `None` after a clean check.
    pub last_error: Option<String>,
    /// Failed checks in a row; drives the backoff.
    pub failures: u32,
}

/// One counter for every updater in this process. Each state write bumps it, and
/// subscribers re-read their own server's `state.json`, so a change in another
/// server (tests run several) only costs a cheap re-read.
static CHANGES: LazyLock<tokio::sync::watch::Sender<u64>> =
    LazyLock::new(|| tokio::sync::watch::channel(0).0);

/// Subscribe to update-state changes; see [`CHANGES`].
#[must_use]
pub fn changes() -> tokio::sync::watch::Receiver<u64> {
    CHANGES.subscribe()
}

/// Read the persisted update state of the server whose data folder is `data`.
///
/// A server that never checked reports its running version and nothing else. The
/// result always names the running version, even if `state.json` was written by an
/// older one. Reading takes no lock: `state.json` is replaced atomically.
#[must_use]
pub fn status(data: &Path, current: &str) -> UpdateState {
    status_of(&data.join("updates"), current)
}

/// Read and parse `state.json` at `path`; `None` if it is missing, not a regular file, oversized or malformed.
fn read_state(path: &Path) -> Option<UpdateState> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_STATE + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_STATE {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// The release image name for this machine, as the release signer lists it and
/// `restart --binary` admits it. `None` where no server image is published.
#[must_use]
pub fn artifact_name() -> Option<&'static str> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => Some("infraternal-x86_64-musl"),
        ("aarch64", "linux") => Some("infraternal-aarch64-musl"),
        _ => None,
    }
}

/// Reads the `release` plugin's switch and channel, the same way the plugin's actions do.
pub type Settings = Arc<
    dyn Fn() -> infraternal_plugin_api::Operation<'static, Result<(bool, String), &'static str>>
        + Send
        + Sync,
>;

/// The server's update checker. Construction does nothing; [`Updater::check`] runs one
/// check and [`Updater::spawn`] starts the timer.
pub struct Updater {
    /// `<data>/updates`.
    directory: PathBuf,
    /// The builds host, for example `https://builds.infraternal.com`.
    origin: String,
    /// The running version.
    current: String,
    /// The image to stage, for example `infraternal-x86_64-musl`.
    artifact: String,
    engine: Arc<dyn ReleaseEngine>,
    settings: Settings,
    /// Free space required before the image download: the image bound plus the reserve.
    /// Tests raise it to prove the disk-full refusal.
    required_space: u64,
    /// The largest image accepted. Tests lower it to cut a download off midway.
    max_image: u64,
}

/// How a check ended, for the caller and the state file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The channel has published nothing yet.
    Empty,
    /// The channel's release is the running version.
    Current(String),
    /// This release is staged (now, or already by an earlier check).
    Staged(String),
}

impl Updater {
    /// Bind an updater to the data folder `data`; start nothing.
    ///
    /// `current` is the running version, `artifact` the image name for this machine
    /// (see [`artifact_name`]), `engine` the server's downloader and verifier, and
    /// `settings` reads the release plugin's switch and channel.
    #[must_use]
    pub fn new(
        data: &Path,
        origin: String,
        current: String,
        artifact: String,
        engine: Arc<dyn ReleaseEngine>,
        settings: Settings,
    ) -> Self {
        Self {
            directory: data.join("updates"),
            origin,
            current,
            artifact,
            engine,
            settings,
            required_space: MAX_IMAGE + RESERVE,
            max_image: MAX_IMAGE,
        }
    }

    /// Change the free-space requirement and the image bound (tests only use this to
    /// simulate a full disk and an oversized download).
    #[must_use]
    pub fn with_limits(mut self, required_space: u64, max_image: u64) -> Self {
        self.required_space = required_space;
        self.max_image = max_image;
        self
    }

    /// Run one check and record it in the update state.
    ///
    /// `target` asks for one exact version instead of the channel's newest (an explicit
    /// rollback); `admission` decides what the guard allows. Returns what happened.
    /// # Errors
    /// A fixed public reason: the plugin is off, the state folder is unsafe, the
    /// network or builds host failed, the release is refused by the guard or the
    /// verifier, or the disk is too full. The same reason is saved as `last_error`.
    pub async fn check(
        &self,
        target: Option<&str>,
        admission: Admission,
    ) -> Result<Outcome, &'static str> {
        let (enabled, channel) = (self.settings)().await?;
        if !enabled {
            return Err("release unavailable");
        }
        let lock = Locked::open(&self.directory)?;
        let mut state = status_of(&self.directory, &self.current);
        channel.clone_into(&mut state.channel);
        let result = tokio::time::timeout(
            CHECK_LIMIT,
            self.check_locked(&lock, &channel, target, admission, &mut state),
        )
        .await
        .unwrap_or(Err("the update check exceeded its time limit"));
        state.last_check = Some(now());
        state.staged = staged_version(&self.directory);
        match &result {
            Ok(_) => {
                state.last_error = None;
                state.failures = 0;
            }
            Err(reason) => {
                state.last_error = Some((*reason).to_owned());
                state.failures = state.failures.saturating_add(1);
            }
        }
        lock.write_state(&state)?;
        result
    }

    /// The body of [`Updater::check`], run while holding the folder lock: sweep leftovers, fetch and guard the release, check space, download, verify and publish.
    async fn check_locked(
        &self,
        lock: &Locked,
        channel: &str,
        target: Option<&str>,
        admission: Admission,
        state: &mut UpdateState,
    ) -> Result<Outcome, &'static str> {
        lock.sweep()?;
        // A staged release the periodic guard would no longer admit (it is the running
        // version after an update, or the server moved past it) is removed.
        if admission == Admission::Forward
            && let Some(staged) = staged_version(&self.directory)
            && guard(&self.current, &staged, Admission::Forward) != Ok(Verdict::Stage)
        {
            lock.retire_staged()?;
        }
        let download = lock.download()?;
        let version = if let Some(version) = target {
            if infraternal_plugin_api::release_version::channel(version).is_none() {
                return Err("the release version is malformed");
            }
            crate::latest::fetch_signed(
                self.engine.as_ref(),
                &self.origin,
                &download.path,
                version,
            )
            .await?;
            version.to_owned()
        } else {
            let Some(version) = crate::latest::fetch_metadata(
                self.engine.as_ref(),
                &self.origin,
                &download.path,
                channel,
            )
            .await?
            else {
                state.available = None;
                return Ok(Outcome::Empty);
            };
            state.available = Some(version.clone());
            version
        };
        if guard(&self.current, &version, admission)? == Verdict::Same {
            return Ok(Outcome::Current(version));
        }
        if staged_version(&self.directory).as_deref() == Some(version.as_str()) {
            return Ok(Outcome::Staged(version));
        }
        if free_space(&self.directory)? < self.required_space {
            return Err("there is not enough free disk space to stage the update");
        }
        self.engine
            .download(
                &format!("{}/releases/{version}/{}", self.origin, self.artifact),
                &download.path.join(&self.artifact),
                self.max_image,
            )
            .await
            .map_err(|error| error.reason())?;
        // Hashing a ~30 MB image takes tens of milliseconds; keep it off the async
        // workers that serve terminals. The files stay open in the blocking task, so a
        // cancelled check that deletes the folder cannot change what it verifies.
        let (engine, path, artifact) = (
            Arc::clone(&self.engine),
            download.path.clone(),
            self.artifact.clone(),
        );
        let signed =
            tokio::task::spawn_blocking(move || verify_staged(engine.as_ref(), &path, &artifact))
                .await
                .map_err(|_| "release verification could not finish")??;
        if signed != version {
            return Err("the signed release version does not match the requested one");
        }
        lock.publish(download)?;
        Ok(Outcome::Staged(version))
    }

    /// Start the periodic check: one task that sleeps between checks (no polling).
    ///
    /// The first check runs 1–3 minutes after start, then every 15 minutes ±20 %,
    /// doubling after each failure up to 6 hours (see [`delay`]). Aborting the returned
    /// handle stops it; dropping the handle lets it run for the life of the process.
    /// Each wait is recorded as `next_check`.
    #[must_use = "abort the handle to stop the timer, or drop it to let it run"]
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.spawn_after(Duration::from_secs(60) + jitter(Duration::from_secs(120)))
    }

    /// [`Updater::spawn`] with a chosen first delay; later delays follow [`delay`].
    #[must_use = "abort the handle to stop the timer, or drop it to let it run"]
    pub fn spawn_after(self: Arc<Self>, first: Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut wait = first;
            loop {
                self.record_next(wait);
                tokio::time::sleep(wait).await;
                let failures = match self.check(None, Admission::Forward).await {
                    Ok(outcome) => {
                        tracing::debug!(?outcome, "update check finished");
                        0
                    }
                    Err(reason) => {
                        // Offline and refused checks are expected; keep them out of warnings.
                        tracing::debug!(reason, "update check did not stage a release");
                        status_of(&self.directory, &self.current).failures.max(1)
                    }
                };
                wait = delay(failures, random());
            }
        })
    }

    /// Save when the next check runs; best effort, since a missed note only hides the time.
    fn record_next(&self, wait: Duration) {
        let Ok(lock) = Locked::try_open(&self.directory) else {
            return;
        };
        let mut state = status_of(&self.directory, &self.current);
        state.next_check =
            Some(now().saturating_add(i64::try_from(wait.as_secs()).unwrap_or(i64::MAX)));
        let _ = lock.write_state(&state);
    }
}

/// The wait before the next check after `failures` failed checks in a row:
/// 15 minutes doubled per failure, capped at 6 hours, then spread by ±20 % using
/// `random` so many servers never check in step.
#[must_use]
pub fn delay(failures: u32, random: u64) -> Duration {
    const BASE: u64 = 15 * 60;
    const CAP: u64 = 6 * 60 * 60;
    let base = BASE.saturating_mul(1u64 << failures.min(10)).min(CAP);
    // random % 401 picks a point in -20 %..=+20 % in steps of 0.1 %.
    let spread = random % 401;
    Duration::from_millis(base * (800 + spread))
}

/// A random wait in `0..range`, so servers started together do not check together.
fn jitter(range: Duration) -> Duration {
    let millis = u64::try_from(range.as_millis()).unwrap_or(u64::MAX).max(1);
    Duration::from_millis(random() % millis)
}

/// A random number for jitter only (never for anything secret).
fn random() -> u64 {
    // Truncation keeps the low 64 random bits of the v4 UUID.
    #[allow(clippy::cast_possible_truncation)]
    let value = uuid::Uuid::new_v4().as_u128() as u64;
    value
}

/// The current time in Unix seconds (0 if the clock is before 1970).
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The state saved in the updates folder `directory`, reporting `current` as the running version.
fn status_of(directory: &Path, current: &str) -> UpdateState {
    let mut state = read_state(&directory.join("state.json")).unwrap_or_default();
    current.clone_into(&mut state.current);
    state
}

/// The version in `staged/VERSION`, if a staged release is there. It was verified when
/// it was staged; S4 verifies it again before using it.
fn staged_version(directory: &Path) -> Option<String> {
    let bytes = std::fs::read(directory.join("staged").join("VERSION")).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?.strip_suffix('\n')?;
    infraternal_plugin_api::release_version::channel(text)?;
    Some(text.to_owned())
}

/// Bytes free for an unprivileged writer on the file system holding `directory`.
// The block counters are u64 on 64-bit Linux but narrower on macOS, where the
// release plugin also compiles; the conversion is only a no-op on Linux.
#[allow(clippy::useless_conversion)]
fn free_space(directory: &Path) -> Result<u64, &'static str> {
    let stat =
        nix::sys::statvfs::statvfs(directory).map_err(|_| "the update folder is unavailable")?;
    // `f_bavail` counts blocks an unprivileged writer may use; root may use a little
    // more, so this errs on the safe side.
    Ok(u64::from(stat.blocks_available()).saturating_mul(u64::from(stat.fragment_size())))
}

/// Verify a downloaded release folder with the one signed-release verifier and return
/// its signed version. Files must be private regular files owned by this user.
fn verify_staged(
    engine: &dyn ReleaseEngine,
    directory: &Path,
    artifact: &str,
) -> Result<String, &'static str> {
    let read = |name: &str, limit: u64| -> Result<Vec<u8>, &'static str> {
        use std::io::Read;
        let file = open_private(&directory.join(name))?;
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "the downloaded release could not be read")?;
        if bytes.len() as u64 > limit {
            return Err("the downloaded release is oversized");
        }
        Ok(bytes)
    };
    let sums = read("SHA256SUMS", 65_536)?;
    let signature = read("SHA256SUMS.sig", 1024)?;
    let version = open_private(&directory.join("VERSION"))?;
    let image = open_private(&directory.join(artifact))?;
    engine.verify_image(&version, &image, artifact, &sums, &signature)
}

/// Open `path` without following symlinks and check it is a private, single-link regular file owned by this user.
#[allow(clippy::verbose_bit_mask)]
fn open_private(path: &Path) -> Result<std::fs::File, &'static str> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "the downloaded release is incomplete")?;
    if !file.metadata().is_ok_and(|m| {
        m.is_file()
            && m.uid() == nix::unistd::geteuid().as_raw()
            && m.mode() & 0o077 == 0
            && m.nlink() == 1
    }) {
        return Err("the downloaded release is unsafe");
    }
    Ok(file)
}

/// An exclusive lock on `updates/`, held for one whole check.
struct Locked {
    directory: PathBuf,
    _lock: nix::fcntl::Flock<std::fs::File>,
}

/// A `download-<uuid>/` folder. Dropping it deletes the folder, so a failed or
/// cancelled check never leaves a partial download behind, unless it was published.
struct Download {
    path: PathBuf,
    published: bool,
}
impl Drop for Download {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

impl Locked {
    /// Create `updates/` if needed (0700), check it is private and ours, and lock it,
    /// waiting for another check to finish.
    fn open(directory: &Path) -> Result<Self, &'static str> {
        Self::lock(directory, nix::fcntl::FlockArg::LockExclusive)
    }

    /// Like [`Locked::open`] but gives up at once if a check holds the lock.
    fn try_open(directory: &Path) -> Result<Self, &'static str> {
        Self::lock(directory, nix::fcntl::FlockArg::LockExclusiveNonblock)
    }

    /// Create, check and lock `directory` with `mode` (blocking or not).
    #[allow(clippy::verbose_bit_mask)]
    fn lock(directory: &Path, mode: nix::fcntl::FlockArg) -> Result<Self, &'static str> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
        let unsafe_folder = "the update folder is unsafe";
        match std::fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err("the update folder is unavailable"),
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
            .open(directory)
            .map_err(|_| unsafe_folder)?;
        // Check the opened folder itself, never a pathname that could be swapped.
        if !file.metadata().is_ok_and(|m| {
            m.is_dir() && m.uid() == nix::unistd::geteuid().as_raw() && m.mode() & 0o077 == 0
        }) {
            return Err(unsafe_folder);
        }
        let lock = nix::fcntl::Flock::lock(file, mode)
            .map_err(|_| "an update check is already running")?;
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
        })
    }

    /// Delete abandoned `download-*` and `retired-*` folders. Holding the lock means no
    /// live check owns them. Symlinks and other entries are never followed or removed.
    fn sweep(&self) -> Result<(), &'static str> {
        let entries =
            std::fs::read_dir(&self.directory).map_err(|_| "the update folder is unavailable")?;
        for entry in entries {
            let entry = entry.map_err(|_| "the update folder is unavailable")?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(id) = name
                .strip_prefix("download-")
                .or_else(|| name.strip_prefix("retired-"))
            else {
                continue;
            };
            if !uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id)
                || !entry.file_type().is_ok_and(|kind| kind.is_dir())
            {
                continue;
            }
            std::fs::remove_dir_all(entry.path())
                .map_err(|_| "an abandoned download could not be removed")?;
        }
        Ok(())
    }

    /// Make a fresh private `download-<uuid>/` folder.
    fn download(&self) -> Result<Download, &'static str> {
        use std::os::unix::fs::DirBuilderExt;
        let path = self
            .directory
            .join(format!("download-{}", uuid::Uuid::new_v4().hyphenated()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| "the update folder is unavailable")?;
        Ok(Download {
            path,
            published: false,
        })
    }

    /// Move `staged/` out of the way and delete it.
    fn retire_staged(&self) -> Result<(), &'static str> {
        let staged = self.directory.join("staged");
        if std::fs::symlink_metadata(&staged).is_err() {
            return Ok(());
        }
        let retired = self
            .directory
            .join(format!("retired-{}", uuid::Uuid::new_v4().hyphenated()));
        std::fs::rename(&staged, &retired)
            .map_err(|_| "the staged release could not be replaced")?;
        self.sync()?;
        std::fs::remove_dir_all(&retired).map_err(|_| "the staged release could not be removed")
    }

    /// Replace `staged/` with a verified download, keeping only one staged release.
    /// A crash at any point leaves either the old or the new release staged, or none
    /// (plus a `retired-*`/`download-*` folder the next check deletes).
    fn publish(&self, mut download: Download) -> Result<(), &'static str> {
        let saved = "the staged release could not be saved";
        std::fs::File::open(&download.path)
            .and_then(|folder| folder.sync_all())
            .map_err(|_| saved)?;
        self.retire_staged()?;
        std::fs::rename(&download.path, self.directory.join("staged")).map_err(|_| saved)?;
        // The folder is now `staged/`; its guard must not delete it.
        download.published = true;
        self.sync()
    }

    /// Replace `state.json` atomically: write a private temporary file, flush it,
    /// rename it over the old one and flush the folder. Then wake subscribers.
    fn write_state(&self, state: &UpdateState) -> Result<(), &'static str> {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let saved = "the update state could not be saved";
        let temporary = self.directory.join("state.json.tmp");
        let _ = std::fs::remove_file(&temporary);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| saved)?;
        let bytes = serde_json::to_vec(state).map_err(|_| saved)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| saved)?;
        std::fs::rename(&temporary, self.directory.join("state.json")).map_err(|_| saved)?;
        self.sync()?;
        CHANGES.send_modify(|count| *count = count.wrapping_add(1));
        Ok(())
    }

    /// Flush `updates/` itself so renames inside it survive a crash.
    fn sync(&self) -> Result<(), &'static str> {
        std::fs::File::open(&self.directory)
            .and_then(|folder| folder.sync_all())
            .map_err(|_| "the update folder could not be saved")
    }
}

/// Unit tests for the guard, backoff, state file and folder safety.
#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
