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
//! **Faults and refusals (J725 P3-2).** Only faults back off: the network or builds
//! host failing, the disk, and a release that fails verification. A policy refusal (the
//! guard refuses an older or another channel's release, or updates are switched off) is
//! a normal answer: it is recorded in [`UpdateState::refused`], leaves `last_error` and
//! `failures` alone, and the next check stays 15 minutes away. A server on the stable
//! setting running an edge build therefore keeps checking at the normal pace.
//!
//! **Guard (J685 P3-3).** The periodic check ([`Admission::Forward`]) stages only a
//! strictly newer version on the running version's own channel. The same version does
//! nothing; an older version or another channel's release is refused. Only an explicit
//! request ([`Admission::Explicit`], for a D295 rollback or a deliberate channel switch
//! by S4/S5) may stage those. No admission ever skips the signature check.
//!
//! **Explicit stages hold (J725 P3-3).** A release staged by an explicit request is
//! recorded as [`UpdateState::hold`]. Periodic checks leave it alone (they answer
//! [`Outcome::Held`] without touching the network or `staged/`) until it is applied
//! (the server runs that version) or cancelled ([`Updater::cancel_hold`]). It is still
//! re-verified on every check, and a held folder that fails verification is removed.
//!
//! **Withdrawn releases (J725 P2-1).** A staged release is kept only while the channel
//! still announces it. When a periodic check finds the pointer naming anything else
//! (the running version again after a yanked build, another version, or nothing), the
//! staged release is removed and [`UpdateState::removed`] says why. A yanked build is
//! still validly signed, so the signature alone can never decide this. S4 must apply
//! only what [`Updater::confirm_staged`] returns: it repeats this check against the
//! pointer at apply time and holds the folder lock until the switch is done.
//!
//! **Layout.** Everything lives in `<data>/updates/`, a directory owned by the server's
//! user with no group or other access (the timer only runs for root, so it is
//! root-only in production):
//!
//! ```text
//! updates/
//!   state.json         UpdateState, 0600, replaced atomically
//!   staged/            at most one verified release: VERSION, SHA256SUMS,
//!                      SHA256SUMS.sig, the server image `infraternal` (never
//!                      an `infraternal-<arch>-musl` add-host payload) and, when
//!                      the signed list names it, infraternal-web.tar (#211 S6)
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
//! **`staged/` is never trusted as found (J725 P3-1).** Before any use (every check,
//! and once when the timer starts) the folder must be a real directory owned by this
//! user with no group or other access, and its files must pass the same signed-release
//! verification that admitted them. Anything else is removed and the reason recorded
//! in [`UpdateState::removed`]. Re-hashing a ~30 MB image costs tens of milliseconds
//! once per check, off the async workers.
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Why the last check failed (a fault: network, disk or verification); `None` after
    /// a check that reached an answer.
    pub last_error: Option<String>,
    /// What the guard refused at the last check (an older or another channel's release);
    /// a normal answer, never counted as a failure.
    pub refused: Option<String>,
    /// Failed checks in a row; drives the backoff. Refusals never count.
    pub failures: u32,
    /// The last staged release the updater removed without applying it, and why.
    pub removed: Option<Removed>,
    /// A release staged by an explicit request (a D295 rollback or a channel switch).
    /// Periodic checks keep it staged until it is applied or cancelled.
    pub hold: Option<String>,
    /// How the last switch to a staged release ended (#211 S4; S5 shows it).
    pub applied: Option<Applied>,
    /// A release that failed here (its health check, its start, or it stopped during its
    /// trial) and was undone (D295). Periodic checks never stage it again; a newer
    /// release, or an explicit request, replaces it.
    pub paused: Option<String>,
    /// Whether the server applies a staged release by itself in the quiet window (owner
    /// setting, J1130). Off still checks and stages on schedule, so the status shows what is
    /// available, but only an explicit `release.update.apply` switches. On by default.
    pub automatic: bool,
}

impl Default for UpdateState {
    /// An empty state: nothing staged or applied, and automatic apply on (the default for
    /// everyone who never set it; a derived `Default` would have turned it off).
    fn default() -> Self {
        Self {
            current: String::new(),
            channel: String::new(),
            available: None,
            staged: None,
            last_check: None,
            next_check: None,
            last_error: None,
            refused: None,
            failures: 0,
            removed: None,
            hold: None,
            applied: None,
            paused: None,
            automatic: true,
        }
    }
}

/// The outcome of one switch to a staged release (#211 S4, D295).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Applied {
    /// The release the server switched to (or tried to).
    pub version: String,
    /// [`APPLIED`], [`UNDONE`] or [`NOT_APPLIED`].
    pub outcome: String,
    /// A fixed public reason when it was undone or not applied.
    pub reason: Option<String>,
    /// When the switch ended, in Unix seconds.
    pub at: i64,
}

/// The new release passed its health check and is now the one that starts.
pub const APPLIED: &str = "applied";
/// The new release failed and the previous release and database copy came back (D295).
pub const UNDONE: &str = "undone";
/// The switch was refused before the new release ran; nothing changed.
pub const NOT_APPLIED: &str = "not-applied";
/// The periodic check's refusal for a release that failed here before.
pub const PAUSED: &str = "this release failed on this server and was undone; it stays paused";

/// A staged release the updater threw away, kept in the state so the owner can see why
/// (S5 shows it). Cleared when another release is staged.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Removed {
    /// The version the staged folder claimed, when it could be read. A folder that
    /// failed verification reports its unverified claim here, only as a label.
    pub version: Option<String>,
    /// A fixed public reason, for example that it failed verification.
    pub reason: String,
    /// When it was removed, in Unix seconds.
    pub at: i64,
}

/// Why a staged folder that failed its re-check was removed.
pub const REMOVED_UNVERIFIED: &str = "the staged release failed verification";
/// Why a staged release the periodic guard would no longer stage was removed.
pub const REMOVED_NOT_NEWER: &str =
    "the staged release is no longer newer than the running version";
/// Why a held explicit stage was removed by [`Updater::cancel_hold`].
pub const REMOVED_CANCELLED: &str = "the explicit update was cancelled";
/// Why a staged release was removed when its channel stopped announcing it.
pub const REMOVED_WITHDRAWN: &str = "the channel no longer offers this release";
/// [`Updater::confirm_staged`]'s refusal when the channel now offers a newer release
/// than the staged one; the next check stages the newer one.
pub const SUPERSEDED: &str = "the channel offers a newer release than the staged one";
/// The refusal when the release plugin is switched off (or its channel setting is
/// unusable): the check does nothing and the timer keeps its normal pace.
pub const UPDATES_OFF: &str = "updates are turned off in the release settings";
/// [`Updater::confirm_staged`]'s refusal when nothing verified is staged.
pub const NOTHING_STAGED: &str = "no verified release is staged";

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

/// Wake every [`changes`] subscriber after an update state or setting write.
///
/// Called both when `state.json` is replaced and when `release.update.settings` saves a
/// new `quiet_minutes` value in SQLite, so the apply loop and `release.update` subscribers
/// re-read immediately without polling.
pub fn notify_changed() {
    CHANGES.send_modify(|count| *count = count.wrapping_add(1));
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

/// The file name of the server image in every release bundle.
///
/// `scripts/package-release` installs the full server build as `infraternal`. The
/// `infraternal-<arch>-musl` files beside it are the add-host payloads: smaller builds
/// without the `server` command, which cannot run a server. Staging, the switch, the
/// boot pointer and `server update adopt` all use this name; only the add-host payload
/// code uses the `-musl` names (J1134: S3 to S6 once staged the `x86_64` host payload).
pub const SERVER_IMAGE: &str = "infraternal";

/// The server image the updater stages on this machine, or `None` where releases publish
/// no server image for it.
///
/// A release bundle carries one server image, [`SERVER_IMAGE`], built for `x86_64` Linux
/// (`scripts/release/build` pins that architecture, because the name does not carry
/// one). An aarch64 server would download an `x86_64` binary under the same name, so
/// updates are off there until the pipeline publishes an aarch64 server image under
/// its own name.
#[must_use]
pub fn server_image() -> Option<&'static str> {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => Some(SERVER_IMAGE),
        _ => None,
    }
}

/// Why updates are off on a machine the releases publish no server image for.
pub const OFF_PLATFORM: &str =
    "auto-update runs only on x86_64 Linux servers, the only server image releases publish";
/// Why a check stops when the release's signed list does not name the server image
/// (J1134): only add-host payloads would be left to download, and they cannot run a server.
pub const NO_SERVER_IMAGE: &str = "the release does not publish a server image for this machine";
/// Why updates are off in a development build, whose version is not a signed release.
pub const OFF_DEVELOPMENT: &str =
    "this is a development build; only signed release builds update themselves";
/// Why updates are off on a server that does not run as root.
pub const OFF_NOT_ROOT: &str =
    "the server is not running as root, so it cannot replace its own binary";

/// Whether this process may run the update check, and if not, why (J725 P3-4).
///
/// `release_build` is whether this binary is a pipeline release build (the server's
/// `INFRATERNAL_RELEASE_BUILD`). The check runs only where an update could ever be
/// applied: a release build, on a platform with a published image, as root (the D295
/// switch replaces a root-owned binary). Returns the image name to stage.
/// # Errors
/// [`OFF_PLATFORM`], [`OFF_DEVELOPMENT`] or [`OFF_NOT_ROOT`], in that order.
pub fn availability(release_build: bool) -> Result<&'static str, &'static str> {
    let artifact = server_image().ok_or(OFF_PLATFORM)?;
    if !release_build {
        return Err(OFF_DEVELOPMENT);
    }
    if !nix::unistd::geteuid().is_root() {
        return Err(OFF_NOT_ROOT);
    }
    Ok(artifact)
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
    /// The release site origin, for example `https://infraternal.com`.
    origin: String,
    /// The running version.
    current: String,
    /// The server image to stage, [`SERVER_IMAGE`] (see [`server_image`]).
    artifact: String,
    engine: Arc<dyn ReleaseEngine>,
    settings: Settings,
    /// Free space required before the image download: the image and web build bounds
    /// plus the reserve.
    /// Tests raise it to prove the disk-full refusal.
    required_space: u64,
    /// The largest image accepted. Tests lower it to cut a download off midway.
    max_image: u64,
    /// The check period before backoff (15 minutes; see [`Updater::with_period`]).
    period: Duration,
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
    /// An explicitly staged release is held; the periodic check left it alone.
    Held(String),
    /// The periodic check reached an answer the policy refuses (the guard refused the
    /// release, or updates are off). Not a failure: it never backs off the timer.
    Refused(&'static str),
}

/// Why a check stopped without an [`Outcome`], which decides whether it backs off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// The network, builds host, disk or verifier failed: counts toward the backoff.
    Fault(&'static str),
    /// The policy said no (the guard, a malformed request): never counts.
    Refusal(&'static str),
}

/// Every plain reason from the I/O and verify helpers is a fault.
impl From<&'static str> for Stop {
    fn from(reason: &'static str) -> Self {
        Self::Fault(reason)
    }
}

impl Updater {
    /// Bind an updater to the data folder `data`; start nothing.
    ///
    /// `current` is the running version, `artifact` the server image name for this
    /// machine (see [`server_image`]), `engine` the server's downloader and verifier, and
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
            required_space: MAX_IMAGE + crate::web::MAX_ARCHIVE + RESERVE,
            max_image: MAX_IMAGE,
            period: PERIOD,
        }
    }

    /// Check every `period` instead of every 15 minutes (the backoff still doubles it).
    /// Only the server's `staging-trust` hook uses this, so a root staging proof does
    /// not wait a quarter of an hour per step.
    #[must_use]
    pub fn with_period(mut self, period: Duration) -> Self {
        self.period = period;
        self
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
    /// rollback); `admission` decides what the guard allows. Returns what happened. A
    /// periodic ([`Admission::Forward`]) check that the policy refuses, or that finds
    /// updates switched off, returns [`Outcome::Refused`], not an error.
    /// # Errors
    /// A fixed public reason: the state folder is unsafe, the network or builds host
    /// failed, the verifier refused the release, or the disk is too full (saved as
    /// `last_error`, counted in `failures`); and for an explicit request, a refusal by
    /// the guard or the switch (saved as `refused`, never counted).
    pub async fn check(
        &self,
        target: Option<&str>,
        admission: Admission,
    ) -> Result<Outcome, &'static str> {
        let refuse = |reason| match admission {
            Admission::Forward => Ok(Outcome::Refused(reason)),
            Admission::Explicit => Err(reason),
        };
        let (enabled, channel) = match (self.settings)().await {
            Ok(settings) => settings,
            Err(reason) => return refuse(reason),
        };
        if !enabled {
            return refuse(UPDATES_OFF);
        }
        let lock = Locked::wait(&self.directory).await?;
        let mut state = status_of(&self.directory, &self.current);
        channel.clone_into(&mut state.channel);
        let result = tokio::time::timeout(
            CHECK_LIMIT,
            self.check_locked(&lock, &channel, target, admission, &mut state),
        )
        .await
        .unwrap_or(Err(Stop::Fault("the update check exceeded its time limit")));
        state.last_check = Some(now());
        match result {
            Ok(_) => {
                state.last_error = None;
                state.refused = None;
                state.failures = 0;
            }
            Err(Stop::Fault(reason)) => {
                state.last_error = Some(reason.to_owned());
                state.failures = state.failures.saturating_add(1);
            }
            Err(Stop::Refusal(reason)) => {
                // The builds host answered: the transport is fine, so the backoff resets.
                state.last_error = None;
                state.refused = Some(reason.to_owned());
                state.failures = 0;
            }
        }
        lock.write_state(&state)?;
        match result {
            Ok(outcome) => Ok(outcome),
            Err(Stop::Fault(reason)) => Err(reason),
            Err(Stop::Refusal(reason)) => refuse(reason),
        }
    }

    /// The body of [`Updater::check`], run while holding the folder lock: sweep leftovers, fetch and guard the release, check space, download, verify and publish.
    async fn check_locked(
        &self,
        lock: &Locked,
        channel: &str,
        target: Option<&str>,
        admission: Admission,
        state: &mut UpdateState,
    ) -> Result<Outcome, Stop> {
        lock.sweep()?;
        let mut staged = self.inspect_staged(lock, state).await?;
        if let Some(held) = state.hold.clone() {
            if staged.as_deref() != Some(held.as_str())
                || guard(&self.current, &held, Admission::Explicit) == Ok(Verdict::Same)
            {
                // The held release is gone (it failed re-verification or was replaced),
                // or it was applied and is now running: the hold has ended.
                state.hold = None;
            } else if admission == Admission::Forward {
                return Ok(Outcome::Held(held));
            }
        }
        // A staged release the periodic guard would no longer admit (it is the running
        // version after an update, or the server moved past it) is removed.
        if admission == Admission::Forward
            && let Some(version) = staged.take_if(|version| {
                guard(&self.current, version, Admission::Forward) != Ok(Verdict::Stage)
            })
        {
            retire(lock, state, Some(version), REMOVED_NOT_NEWER)?;
        }
        let download = lock.download()?;
        let version = if let Some(version) = target {
            if infraternal_plugin_api::release_version::channel(version).is_none() {
                return Err(Stop::Refusal("the release version is malformed"));
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
                if let Some(withdrawn) = staged.take() {
                    retire(lock, state, Some(withdrawn), REMOVED_WITHDRAWN)?;
                }
                return Ok(Outcome::Empty);
            };
            state.available = Some(version.clone());
            // The channel is authoritative: a staged release it no longer announces
            // (yanked, or the pointer moved back or across) must never be applied. One
            // it only overtook with a newer release stays until that one is published
            // below, which replaces it (J734 P3-c): a failed download of the newer
            // release must not leave nothing staged under a "withdrawn" label.
            if admission == Admission::Forward
                && let Some(withdrawn) =
                    staged.take_if(|staged| *staged != version && !overtaken(staged, &version))
            {
                retire(lock, state, Some(withdrawn), REMOVED_WITHDRAWN)?;
            }
            version
        };
        if guard(&self.current, &version, admission).map_err(Stop::Refusal)? == Verdict::Same {
            return Ok(Outcome::Current(version));
        }
        // A release undone here (D295) is not offered again by the timer; only a newer
        // release or an explicit request moves on.
        if admission == Admission::Forward && state.paused.as_deref() == Some(version.as_str()) {
            if let Some(paused) = staged.take() {
                retire(lock, state, Some(paused), PAUSED)?;
            }
            return Err(Stop::Refusal(PAUSED));
        }
        if admission == Admission::Explicit {
            // Set before the download: a failed attempt leaves no staged match, so the
            // next check ends the hold; a successful one keeps it.
            state.hold = Some(version.clone());
        }
        if staged.as_deref() == Some(version.as_str()) {
            return Ok(Outcome::Staged(version));
        }
        // The signed list (verified by the metadata fetch above) must name the server
        // image. A release without one is refused before any image download (J1134).
        if !lists(&signed_list(&download.path)?, &self.artifact) {
            return Err(Stop::Fault(NO_SERVER_IMAGE));
        }
        if free_space(&self.directory)? < self.required_space {
            return Err(Stop::Fault(
                "there is not enough free disk space to stage the update",
            ));
        }
        self.engine
            .download(
                &format!("{}/releases/{version}/{}", self.origin, self.artifact),
                &download.path.join(&self.artifact),
                self.max_image,
            )
            .await
            .map_err(|error| error.reason())?;
        // The web build the release carries (#211 S6). A release whose signed list names
        // one must have it; older releases without one still stage.
        if crate::web::listed(&signed_list(&download.path)?) {
            self.engine
                .download(
                    &format!("{}/releases/{version}/{}", self.origin, crate::web::ARCHIVE),
                    &download.path.join(crate::web::ARCHIVE),
                    crate::web::MAX_ARCHIVE,
                )
                .await
                .map_err(|error| error.reason())?;
        }
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
            return Err(Stop::Fault(
                "the signed release version does not match the requested one",
            ));
        }
        lock.publish(download)?;
        state.staged = Some(version.clone());
        state.removed = None;
        Ok(Outcome::Staged(version))
    }

    /// Re-check `staged/` before anything uses it (J725 P3-1) and return its verified
    /// version, recording it as `state.staged`.
    ///
    /// The folder must be a real directory (never a symlink) owned by this user with
    /// no group or other access, and its files must pass [`verify_staged`], which
    /// opens each one without following links and checks owner, mode and link count.
    /// A folder that fails is removed and recorded in `state.removed`. The caller
    /// holds the folder lock, and `updates/` is private, so nothing can swap `staged/`
    /// between this check and its use.
    /// # Errors
    /// The verifier task could not finish, or a failed folder could not be removed.
    async fn inspect_staged(
        &self,
        lock: &Locked,
        state: &mut UpdateState,
    ) -> Result<Option<String>, &'static str> {
        Ok(self
            .inspect_staged_image(lock, state)
            .await?
            .map(|(version, _)| version))
    }

    /// [`Updater::inspect_staged`], also returning the open image whose bytes were just
    /// hashed (J734 P3-b), so S4 switches from exactly what was verified.
    async fn inspect_staged_image(
        &self,
        lock: &Locked,
        state: &mut UpdateState,
    ) -> Result<Option<(String, std::fs::File)>, &'static str> {
        let path = self.directory.join("staged");
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            state.staged = None;
            return Ok(None);
        };
        let verified = if private_directory(&metadata) {
            let (engine, artifact) = (Arc::clone(&self.engine), self.artifact.clone());
            let folder = path.clone();
            tokio::task::spawn_blocking(move || {
                verify_staged_image(engine.as_ref(), &folder, &artifact)
            })
            .await
            .map_err(|_| "release verification could not finish")?
            .ok()
        } else {
            None
        };
        if verified.is_none() {
            let claimed = staged_version(&self.directory);
            retire(lock, state, claimed, REMOVED_UNVERIFIED)?;
        }
        state.staged = verified.as_ref().map(|(version, _)| version.clone());
        Ok(verified)
    }

    /// Re-check `staged/` once when the timer starts, so a folder left by an older
    /// server or planted while the server was down is never shown as ready. Skipped
    /// when a check already holds the lock, since that check re-checks it anyway.
    async fn inspect_at_start(&self) {
        let Ok(lock) = Locked::try_open(&self.directory) else {
            return;
        };
        let mut state = status_of(&self.directory, &self.current);
        let before = state.clone();
        if self.inspect_staged(&lock, &mut state).await.is_ok() && state != before {
            let _ = lock.write_state(&state);
        }
    }

    /// The apply-time re-check S4 must use (J725 P2-1): confirm that the staged release
    /// is still verified and still the one the channel announces, and keep the folder
    /// locked until the returned [`Confirmed`] is dropped.
    ///
    /// S4 applies only `confirmed.image()`, and only while it holds `confirmed`, so no
    /// periodic check can replace or remove `staged/` between this check and the
    /// switch. A release the channel withdrew is removed here as well, with the reason
    /// recorded, even if a periodic check has not seen the withdrawal yet.
    /// # Errors
    /// [`NOTHING_STAGED`] when no verified release is staged; the release plugin is
    /// off; the pointer cannot be fetched or verified; or `"the channel no longer offers
    /// the staged release"`.
    pub async fn confirm_staged(&self) -> Result<Confirmed, &'static str> {
        let lock = Locked::wait(&self.directory).await?;
        let mut state = status_of(&self.directory, &self.current);
        let result = tokio::time::timeout(CHECK_LIMIT, self.confirm_locked(&lock, &mut state))
            .await
            .unwrap_or(Err("the update check exceeded its time limit"));
        lock.write_state(&state)?;
        let (version, image) = result?;
        Ok(Confirmed {
            path: self.directory.join("staged").join(&self.artifact),
            image,
            version,
            lock,
        })
    }

    /// The body of [`Updater::confirm_staged`], run under the folder lock.
    async fn confirm_locked(
        &self,
        lock: &Locked,
        state: &mut UpdateState,
    ) -> Result<(String, std::fs::File), &'static str> {
        // The switch comes first (J734 P3-a): with updates off nothing applies, not even
        // a held explicit stage. The stage and its hold are kept for when they return.
        let (enabled, channel) = (self.settings)().await?;
        if !enabled {
            return Err(UPDATES_OFF);
        }
        let Some((staged, image)) = self.inspect_staged_image(lock, state).await? else {
            state.hold = None;
            return Err(NOTHING_STAGED);
        };
        // An explicit stage (S5 gates it behind the owner and a fresh passkey) was chosen
        // by the owner, not the channel: it is applied as held, without the pointer.
        if state.hold.as_deref() == Some(staged.as_str())
            && guard(&self.current, &staged, Admission::Explicit) == Ok(Verdict::Stage)
        {
            return Ok((staged, image));
        }
        state.hold = None;
        let download = lock.download()?;
        let announced = crate::latest::fetch_metadata(
            self.engine.as_ref(),
            &self.origin,
            &download.path,
            &channel,
        )
        .await?;
        state.available.clone_from(&announced);
        if announced.as_deref() == Some(staged.as_str())
            && guard(&self.current, &staged, Admission::Forward) == Ok(Verdict::Stage)
        {
            return Ok((staged, image));
        }
        // Overtaken, not withdrawn (J734 P3-c): never applied, but kept until the next
        // check publishes the newer release over it.
        if announced
            .as_deref()
            .is_some_and(|announced| overtaken(&staged, announced))
        {
            return Err(SUPERSEDED);
        }
        retire(lock, state, Some(staged), REMOVED_WITHDRAWN)?;
        Err("the channel no longer offers the staged release")
    }

    /// Cancel a held explicit stage (a D295 rollback or a channel switch) before S4
    /// applies it: the staged release is removed, the reason recorded and periodic
    /// checks resume. Does nothing when no explicit stage is held.
    /// # Errors
    /// The update folder is unsafe or the staged release could not be removed.
    pub async fn cancel_hold(&self) -> Result<(), &'static str> {
        let lock = Locked::wait(&self.directory).await?;
        let mut state = status_of(&self.directory, &self.current);
        let Some(held) = state.hold.take() else {
            return Ok(());
        };
        retire(&lock, &mut state, Some(held), REMOVED_CANCELLED)?;
        lock.write_state(&state)
    }

    /// Turn automatic apply on or off (owner setting, J1130). It lives in `state.json`, beside
    /// the update's other durable facts, so the D295 database restore of an undone update never
    /// takes the owner's choice back.
    /// # Errors
    /// The update folder is unsafe or the state could not be saved.
    pub async fn set_automatic(&self, automatic: bool) -> Result<(), &'static str> {
        let lock = Locked::wait(&self.directory).await?;
        let mut state = status_of(&self.directory, &self.current);
        state.automatic = automatic;
        lock.write_state(&state)
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
            self.inspect_at_start().await;
            let mut wait = first;
            loop {
                self.record_next(wait);
                tokio::time::sleep(wait).await;
                // Refusals and "updates off" are `Ok(Refused)`: they keep the normal pace.
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
                wait = delay_from(self.period, failures, random());
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
    delay_from(PERIOD, failures, random)
}

/// The normal check period.
const PERIOD: Duration = Duration::from_mins(15);

/// [`delay`] with another base period (see [`Updater::with_period`]).
fn delay_from(period: Duration, failures: u32, random: u64) -> Duration {
    const CAP: u64 = 6 * 60 * 60;
    let base = period
        .as_secs()
        .saturating_mul(1u64 << failures.min(10))
        .min(CAP);
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
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The state saved in the updates folder `directory`, reporting `current` as the running version.
pub(crate) fn status_of(directory: &Path, current: &str) -> UpdateState {
    let mut state = read_state(&directory.join("state.json")).unwrap_or_default();
    current.clone_into(&mut state.current);
    state
}

/// The version `staged/VERSION` claims, unverified: only a label for the state and
/// tests. Anything that acts on the staged release uses [`Updater::inspect_staged`].
/// A `staged/` that is not a private directory of ours, or a VERSION that is not a
/// private regular file, reads as `None`.
fn staged_version(directory: &Path) -> Option<String> {
    use std::io::Read;
    let folder = directory.join("staged");
    if !std::fs::symlink_metadata(&folder).is_ok_and(|m| private_directory(&m)) {
        return None;
    }
    let mut bytes = Vec::new();
    open_private(&folder.join("VERSION"))
        .ok()?
        .take(129)
        .read_to_end(&mut bytes)
        .ok()?;
    let text = std::str::from_utf8(&bytes).ok()?.strip_suffix('\n')?;
    infraternal_plugin_api::release_version::channel(text)?;
    Some(text.to_owned())
}

/// Whether `metadata` (from `lstat`, so a symlink is never a directory) is a directory
/// owned by this user with no group or other access.
#[allow(clippy::verbose_bit_mask)]
fn private_directory(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_dir()
        && metadata.uid() == nix::unistd::geteuid().as_raw()
        && metadata.mode() & 0o077 == 0
}

/// Remove `staged/` under `lock` and record what was removed and why in `state`.
fn retire(
    lock: &Locked,
    state: &mut UpdateState,
    version: Option<String>,
    reason: &'static str,
) -> Result<(), &'static str> {
    lock.retire_staged()?;
    state.staged = None;
    state.removed = Some(Removed {
        version,
        reason: reason.to_owned(),
        at: now(),
    });
    Ok(())
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
    verify_staged_image(engine, directory, artifact).map(|(version, _)| version)
}

/// [`verify_staged`], also returning the open image file whose bytes were verified.
fn verify_staged_image(
    engine: &dyn ReleaseEngine,
    directory: &Path,
    artifact: &str,
) -> Result<(String, std::fs::File), &'static str> {
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
    let signed = open_private(&directory.join("VERSION"))?;
    let image = open_private(&directory.join(artifact))?;
    let version = engine.verify_image(&signed, &image, artifact, &sums, &signature)?;
    // A release that lists a web build is verified with it (#211 S6): a staged folder
    // whose archive is missing or changed fails as a whole.
    if crate::web::listed(&sums) {
        let archive = open_private(&directory.join(crate::web::ARCHIVE))?;
        engine.verify_image(&signed, &archive, crate::web::ARCHIVE, &sums, &signature)?;
    }
    Ok((version, image))
}

/// The downloaded `SHA256SUMS` in `directory` (bounded, private), before it is verified:
/// only used to see whether the release lists a web build, which verification then checks.
fn signed_list(directory: &Path) -> Result<Vec<u8>, &'static str> {
    use std::io::Read;
    let mut bytes = Vec::new();
    open_private(&directory.join("SHA256SUMS"))?
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| "the downloaded release could not be read")?;
    if bytes.len() > 65_536 {
        return Err("the downloaded release is oversized");
    }
    Ok(bytes)
}

/// Whether the signed list `sums` names the file `name`.
///
/// `sha256sum` writes "<hex>  <name>" (text) or "<hex> *<name>" (binary). This only looks
/// for the name; the file itself is still verified against the signature before use.
fn lists(sums: &[u8], name: &str) -> bool {
    let name = name.as_bytes();
    sums.split(|byte| *byte == b'\n').any(|line| {
        line.get(64..).is_some_and(|rest| {
            rest.strip_prefix(b"  ")
                .or_else(|| rest.strip_prefix(b" *"))
                .is_some_and(|listed| listed == name)
        })
    })
}

/// Whether `announced` is a newer release than `staged` on the same channel, so the
/// staged release was only overtaken, not withdrawn (J734 P3-c).
fn overtaken(staged: &str, announced: &str) -> bool {
    guard(staged, announced, Admission::Forward) == Ok(Verdict::Stage)
}

/// Open `path` without following symlinks and check it is a private, single-link regular file owned by this user.
#[allow(clippy::verbose_bit_mask)]
pub(crate) fn open_private(path: &Path) -> Result<std::fs::File, &'static str> {
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

/// A staged release [`Updater::confirm_staged`] just re-verified against the channel.
/// While it lives, the update folder stays locked, so the staged files cannot change.
///
/// It also keeps the image file whose bytes the verifier hashed (J734 P3-b). S4 switches
/// from that open file, never by opening a path again, so what runs is what was checked.
/// The lock is a close-on-exec descriptor: the exec that switches releases it.
pub struct Confirmed {
    /// The confirmed version.
    version: String,
    /// `updates/staged/<image>`, verified under the lock this value holds.
    path: PathBuf,
    /// The open, verified image (the same inode as `path` while the lock is held).
    image: std::fs::File,
    /// Held until the caller has switched (or given up).
    lock: Locked,
}

impl Confirmed {
    /// The confirmed release version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Where the verified image is staged (for reading only; switch from [`Self::file`]).
    #[must_use]
    pub fn image(&self) -> &Path {
        &self.path
    }

    /// The open image file the verifier hashed.
    #[must_use]
    pub fn file(&self) -> &std::fs::File {
        &self.image
    }

    /// A confirmation built directly from its parts, for [`crate::apply`]'s unit tests.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(crate) fn for_test(version: &str, directory: &Path, artifact: &str) -> Self {
        let path = directory.join("staged").join(artifact);
        Self {
            version: version.to_owned(),
            image: std::fs::File::open(&path).unwrap(),
            path,
            lock: Locked::open(directory).unwrap(),
        }
    }

    /// Take the parts S4's [`crate::apply`] needs: version, image file and the lock.
    pub(crate) fn into_parts(self) -> (String, std::fs::File, Locked) {
        (self.version, self.image, self.lock)
    }
}

/// The lock error while another check or a switch holds `updates/`.
const BUSY: &str = "an update check is already running";
/// How often [`Locked::wait`] retries a busy lock.
const LOCK_RETRY: Duration = Duration::from_millis(100);

/// An exclusive lock on `updates/`, held for one whole check.
pub(crate) struct Locked {
    directory: PathBuf,
    _lock: nix::fcntl::Flock<std::fs::File>,
}

/// A `download-<uuid>/` folder. Dropping it deletes the folder, so a failed or
/// cancelled check never leaves a partial download behind, unless it was published.
pub(crate) struct Download {
    pub(crate) path: PathBuf,
    pub(crate) published: bool,
}
impl Drop for Download {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

impl Locked {
    /// The locked `updates/` folder.
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    /// Create `updates/` if needed (0700), check it is private and ours, and lock it,
    /// waiting for another check to finish.
    pub(crate) fn open(directory: &Path) -> Result<Self, &'static str> {
        Self::lock(directory, nix::fcntl::FlockArg::LockExclusive)
    }

    /// Take the lock, waiting while another check (or S4, which holds it until its exec)
    /// has it.
    ///
    /// It retries a non-blocking lock every [`LOCK_RETRY`] on the async timer instead of
    /// parking a thread in a blocking `flock` (#211 S4): a blocked thread cannot be
    /// cancelled, and the switch's runtime shutdown waited its full 4 s for one, which
    /// added 4 s of downtime to every update whose switch met a periodic check. Waits
    /// are rare and short (a check or a switch), so the retry costs nothing measurable.
    async fn wait(directory: &Path) -> Result<Self, &'static str> {
        loop {
            match Self::try_open(directory) {
                Err(BUSY) => tokio::time::sleep(LOCK_RETRY).await,
                locked => return locked,
            }
        }
    }

    /// Like [`Locked::open`] but gives up at once if a check holds the lock.
    pub(crate) fn try_open(directory: &Path) -> Result<Self, &'static str> {
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
        let lock = nix::fcntl::Flock::lock(file, mode).map_err(|_| BUSY)?;
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
        })
    }

    /// Delete abandoned `download-*` and `retired-*` folders. Holding the lock means no
    /// live check owns them. Symlinks and other entries are never followed or removed.
    pub(crate) fn sweep(&self) -> Result<(), &'static str> {
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
    pub(crate) fn download(&self) -> Result<Download, &'static str> {
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
        // A planted `staged` may be a file or a symlink: remove the entry itself and never
        // follow it (`remove_dir_all` also removes a symlink without following it).
        let removed = if std::fs::symlink_metadata(&retired).is_ok_and(|m| m.is_dir()) {
            std::fs::remove_dir_all(&retired)
        } else {
            std::fs::remove_file(&retired)
        };
        removed.map_err(|_| "the staged release could not be removed")
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
    pub(crate) fn write_state(&self, state: &UpdateState) -> Result<(), &'static str> {
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
        let before = read_state(&self.directory.join("state.json"));
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| saved)?;
        std::fs::rename(&temporary, self.directory.join("state.json")).map_err(|_| saved)?;
        self.sync()?;
        self.record_changes(before.as_ref(), state);
        notify_changed();
        Ok(())
    }

    /// Add to the history what this write changed: a release newly staged, a staged
    /// release newly removed, or a new last-switch outcome (applied, undone, not applied).
    /// Doing it where the state is written covers every path that stages, retires or
    /// switches a release, so none can forget to say so (#211 S5, J1130). Every path that
    /// ends a switch writes a fresh [`Applied`] (it carries its own timestamp) exactly once
    /// and removes the marker, so the warm restart and the cold-start undo each record the
    /// switch once. A state rewrite that leaves `applied` as it was records nothing.
    fn record_changes(&self, before: Option<&UpdateState>, after: &UpdateState) {
        use crate::history::{Entry, Kind, append, now};
        if let Some(version) = &after.staged
            && before.and_then(|b| b.staged.as_ref()) != Some(version)
        {
            append(
                &self.directory,
                Entry {
                    at: now(),
                    kind: Kind::Staged,
                    version: Some(version.clone()),
                    detail: None,
                },
            );
        }
        if let Some(applied) = &after.applied
            && before.and_then(|b| b.applied.as_ref()) != Some(applied)
            // "restore pending" is an interim note: the marker stays and the retry (or the
            // settle once serving) records the switch's final outcome, so skip it here.
            && applied.reason.as_deref() != Some(crate::apply::RESTORE_PENDING)
        {
            use crate::history::Kind;
            let kind = match applied.outcome.as_str() {
                APPLIED => Kind::Applied,
                UNDONE => Kind::RolledBack,
                _ => Kind::Failed,
            };
            append(
                &self.directory,
                Entry {
                    at: applied.at,
                    kind,
                    version: Some(applied.version.clone()),
                    detail: applied.reason.clone(),
                },
            );
        }
        if let Some(removed) = &after.removed
            && before.and_then(|b| b.removed.as_ref()) != Some(removed)
        {
            append(
                &self.directory,
                Entry {
                    at: removed.at,
                    kind: Kind::Removed,
                    version: removed.version.clone(),
                    detail: Some(removed.reason.clone()),
                },
            );
        }
    }

    /// Flush `updates/` itself so renames inside it survive a crash.
    pub(crate) fn sync(&self) -> Result<(), &'static str> {
        std::fs::File::open(&self.directory)
            .and_then(|folder| folder.sync_all())
            .map_err(|_| "the update folder could not be saved")
    }
}

/// Unit tests for the guard, backoff, state file and folder safety.
#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
