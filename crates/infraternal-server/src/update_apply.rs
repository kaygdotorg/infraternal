//! Applies a staged release in a quiet window and undoes it if it is unhealthy (#211 S4).
//!
//! The file side (layout, the `pending.json` phases, the D295 database restore and the
//! boot pointer) lives in `infraternal_plugin_release::apply`. This module ties it to
//! the running server:
//!
//! - **Startup.** [`startup`] runs before anything opens the database. It lets the
//!   previous release finish an undo, or marks the new release's trial.
//! - **Quiet window.** A task waits for a staged release. Once nothing has been typed
//!   or attached for [`QUIET`] ([`crate::update_activity`]), it confirms the stage
//!   against the channel (S3), installs it, keeps the previous image and a
//!   `VACUUM INTO` database copy, writes the marker, and hands the verified image to
//!   the CLI's restart loop as a [`SwitchRequest`]. The loop does the warm exec (the
//!   CA stays unlocked, D217). An update never interrupts typing (D251), so there is
//!   no deadline that would force it.
//! - **Trial.** The new release checks itself within [`TRIAL_LIMIT`]: `/healthz`
//!   answers 200 on its own listener, a write transaction commits, the CA is
//!   unlocked if it was before, its embedded infraternal agent can publish a login
//!   image, and it lists every live
//!   session the previous release recorded in the marker, except those whose shim
//!   exited meanwhile (owner, 2026-11-21). On a pass it commits the boot pointer. Otherwise it
//!   asks the loop to exec the previous release warm, which restores the database
//!   copy at its own startup (D295).
//! - **A new release that cannot start.** If the server fails to start serving while
//!   it is on trial (a database migration error, for example), the CLI asks
//!   [`failed_start_undo`] for the same warm undo instead of exiting. An exit would
//!   bring the previous release back cold, which costs a passkey unlock (D217).
//!
//! The quiet-window task and the trial run only where the S3 check runs: a root,
//! signed release build on Linux.
//!
//! **Staging hooks.** These are compiled only with the non-default `staging-trust`
//! feature, which production builds refuse (`check-production-trust.py`).
//! `INFRATERNAL_STAGING_UPDATE_SECONDS` shortens the first check, the check period and
//! the quiet window. `INFRATERNAL_STAGING_FAULTS` gives named releases one fault each
//! (see [`StagingFault`]). Together they let a real root server prove every rollback
//! path without publishing anything.
use infraternal_plugin_release::{
    apply::{self, Pending, Phase, Resume, Switch, Undo},
    cli_link,
    update::{self, Updater},
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

/// How long nothing may be typed or attached before a staged update applies (D251:
/// "idle for a few minutes"; 5 minutes, J645 plan).
pub const QUIET: Duration = Duration::from_mins(5);
/// How long the new release has to pass its health check (D295: "within about 2 minutes").
pub const TRIAL_LIMIT: Duration = Duration::from_mins(2);
/// The wait after an apply attempt failed (for example the channel could not be read),
/// so a failure never turns into a tight retry loop.
const RETRY: Duration = Duration::from_mins(5);

/// A switch the CLI's restart loop must perform with the warm in-memory handoff.
pub enum SwitchRequest {
    /// Exec the installed release B from its verified file (forward).
    Apply {
        /// The installed release, its verified file and the folder lock.
        switch: Switch,
        /// `Ok` once the exec is about to happen; the switch back if it was refused.
        reply: oneshot::Sender<Result<(), Switch>>,
    },
    /// Exec the previous release A again (D295 undo).
    Undo {
        /// A's kept image, its digest and argv\[0\].
        undo: Undo,
        /// `Ok` once the exec is about to happen; `Err` if A's image was refused.
        reply: oneshot::Sender<Result<(), ()>>,
    },
}

/// Set when the owner asks to apply now (#211 S5): the next attempt skips the quiet window.
static FORCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Wakes the quiet-window task when [`FORCE`] is set.
static NOW: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// The restart loop's inbox; `None` until the CLI registers with [`switch_requests`].
static SWITCHES: Mutex<Option<mpsc::Sender<SwitchRequest>>> = Mutex::new(None);
/// The trial [`startup`] found, for [`start`] to run once the server serves. It stays
/// set until the trial commits, so [`failed_start_undo`] can still find it if serving
/// fails after the trial began.
static TRIAL: Mutex<Option<Pending>> = Mutex::new(None);
/// `true` while this process is a new release whose trial has not committed: browser
/// sockets wait in [`terminals_admitted`] until then (J1085).
static TRIAL_OPEN: std::sync::LazyLock<tokio::sync::watch::Sender<bool>> =
    std::sync::LazyLock::new(|| tokio::sync::watch::channel(false).0);

/// Wait until this process may serve terminals: at once, unless it is a new release on
/// trial, which takes no terminal traffic until its trial commits (J1085).
///
/// Every terminal write during a trial would be lost by an undo, which restores the
/// database copy taken before the switch while the shims keep their newer cursors,
/// and a session opened in the trial would be missing from that copy. Browsers
/// reconnect after every switch anyway; during a trial their upgrade simply waits,
/// about 0.2 s for a good release. On an undo the process execs the previous release
/// and the waiting connections drop, so the browsers reconnect to it. If the undo is
/// refused and this release keeps serving, the wait ends too.
pub(crate) async fn terminals_admitted() {
    let mut open = TRIAL_OPEN.subscribe();
    let _ = open.wait_for(|open| !*open).await;
}

/// The embedded infraternal agent's live session census, registered by the WebSocket
/// state when the server starts (see [`set_session_inventory`]).
static INVENTORY: Mutex<
    Option<tokio::sync::watch::Receiver<crate::embedded::SessionInventoryState>>,
> = Mutex::new(None);
/// How many recorded sessions the trial is still waiting for B to list; read when the
/// trial limit passes, to say why it failed.
static SESSIONS_WAITING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Register the embedded infraternal agent's session census: a switch records the live
/// sessions from it, and a trial requires them back from it.
pub(crate) fn set_session_inventory(
    inventory: tokio::sync::watch::Receiver<crate::embedded::SessionInventoryState>,
) {
    *INVENTORY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(inventory);
}

/// The registered census, if the WebSocket state has registered one.
fn registered_inventory()
-> Option<tokio::sync::watch::Receiver<crate::embedded::SessionInventoryState>> {
    INVENTORY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The live sessions in the latest complete census of `inventory`, or `None` when there
/// is none yet (or the infraternal agent link is down).
fn live_sessions(
    inventory: Option<&tokio::sync::watch::Receiver<crate::embedded::SessionInventoryState>>,
) -> Option<Vec<[u8; 16]>> {
    match &*inventory?.borrow() {
        crate::embedded::SessionInventoryState::Available(ids) => Some(ids.to_vec()),
        _ => None,
    }
}

/// Whether the shim of session `id` is still running: its socket is still there and
/// it has not sealed an exit record. Only the files are read; the shim is never
/// contacted, so this check cannot disturb a session.
fn shim_alive(sessions: Option<&Path>, id: &[u8; 16]) -> bool {
    let Some(sessions) = sessions else {
        return true;
    };
    let socket = sessions.join(format!("{}.sock", uuid::Uuid::from_bytes(*id).simple()));
    match std::fs::symlink_metadata(&socket) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
        Ok(_) => !matches!(infraternal_shim::ended::read(&socket), Ok(Some(_))),
    }
}

/// Wait until this release lists every session in `expected` (simple-form UUIDs, from
/// the marker) whose shim is still alive in the shim folder `folder`. A session that
/// exited during the trial is not required (owner, 2026-11-21). Returns only once they
/// are all listed; the trial limit bounds the wait.
///
/// The census and the missing-session counter are arguments, not read from the
/// process-wide statics here, so a test gives itself its own and cannot race another
/// test in the same binary that registers a census (J1130; the production caller
/// passes [`registered_inventory`] and [`SESSIONS_WAITING`]).
async fn sessions_listed(
    expected: &[String],
    folder: Option<&Path>,
    inventory: Option<tokio::sync::watch::Receiver<crate::embedded::SessionInventoryState>>,
    waiting: &std::sync::atomic::AtomicUsize,
) {
    let expected: Vec<[u8; 16]> = expected
        .iter()
        .filter_map(|id| uuid::Uuid::parse_str(id).ok())
        .map(uuid::Uuid::into_bytes)
        .collect();
    loop {
        let listed = live_sessions(inventory.as_ref()).unwrap_or_default();
        #[cfg(feature = "staging-trust")]
        let listed =
            if staging_fault(infraternal_plugin_api::VERSION) == Some(StagingFault::Unlisted) {
                Vec::new()
            } else {
                listed
            };
        let missing = expected
            .iter()
            .filter(|id| !listed.contains(id) && shim_alive(folder, id))
            .count();
        waiting.store(missing, std::sync::atomic::Ordering::Relaxed);
        if missing == 0 {
            return;
        }
        // sleep: the census refreshes as the infraternal agent reattaches each shim.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The owner controls' way into S4 (#211 S5): "Update now" and "Roll back" ask the same tasks and the
/// same restart loop that the quiet-window update and the failed-trial undo use, so there is one switch
/// path and one warm handoff (the CA stays unlocked, D217).
pub struct ServerApplier {
    /// The data folder.
    data: PathBuf,
    /// The server image's file name inside a release folder.
    artifact: &'static str,
}

impl ServerApplier {
    /// An applier for the data folder `data` on a platform whose server image is `artifact`.
    #[must_use]
    pub fn new(data: &Path, artifact: &'static str) -> Self {
        Self {
            data: data.to_owned(),
            artifact,
        }
    }
}

impl infraternal_plugin_release::applier::UpdateApplier for ServerApplier {
    /// Wakes the quiet-window task and tells it to skip the quiet window for the staged release. The
    /// task confirms the stage again (the channel may have withdrawn it) and does the whole switch, so
    /// `release` is dropped here to free the folder lock for it. The answer means "started": a switch
    /// that fails afterwards is recorded in the history and shown in the state, not returned here.
    fn apply(
        &self,
        release: update::Confirmed,
    ) -> infraternal_plugin_api::Operation<
        '_,
        Result<infraternal_plugin_release::applier::Started, &'static str>,
    > {
        Box::pin(async move {
            if apply::in_flight(&self.data) {
                return Err("an earlier update switch has not finished");
            }
            let to = release.version().to_owned();
            drop(release);
            FORCE.store(true, std::sync::atomic::Ordering::SeqCst);
            NOW.notify_one();
            Ok(infraternal_plugin_release::applier::Started {
                to,
                lost_since: None,
            })
        })
    }

    /// D295 by hand: the previous image and the database copy kept at the last update come back through
    /// the same warm undo a failed health check uses (`apply::begin_manual_rollback`, then
    /// [`SwitchRequest::Undo`]). No passkey is needed because the CA frame travels with the exec.
    fn rollback(
        &self,
    ) -> infraternal_plugin_api::Operation<
        '_,
        Result<infraternal_plugin_release::applier::Started, &'static str>,
    > {
        Box::pin(async move {
            let plan = infraternal_plugin_release::apply::rollback_plan(
                &self.data,
                infraternal_plugin_api::VERSION,
                self.artifact,
            )
            .ok_or("there is no earlier version to go back to")?;
            let (data, artifact) = (self.data.clone(), self.artifact);
            let undo = tokio::task::spawn_blocking(move || {
                let running = std::fs::File::open("/proc/self/exe")
                    .map_err(|_| "the running image could not be read")?;
                let own = apply::digest(&running)?;
                let undo = apply::begin_manual_rollback(
                    &data,
                    artifact,
                    infraternal_plugin_api::VERSION,
                    &own,
                )?;
                restore_cli_link(&data, artifact);
                Ok::<_, &'static str>(undo)
            })
            .await
            .map_err(|_| "the roll back could not be prepared")??;
            let sender = SWITCHES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let Some(sender) = sender else {
                cancel_manual_rollback_with_cli(self.data.clone(), self.artifact).await;
                return Err("the restart control refused the roll back");
            };
            // Nothing new may be acknowledged to a shim between the copy and the exec (J1085).
            crate::update_activity::freeze(true);
            let (reply, answer) = oneshot::channel();
            if sender
                .send(SwitchRequest::Undo { undo, reply })
                .await
                .is_err()
                || !matches!(answer.await, Ok(Ok(())))
            {
                crate::update_activity::freeze(false);
                cancel_manual_rollback_with_cli(self.data.clone(), self.artifact).await;
                return Err("the restart control refused the roll back");
            }
            Ok(infraternal_plugin_release::applier::Started {
                to: plan.to_version,
                lost_since: Some(plan.copy_taken_at),
            })
        })
    }

    fn rollback_plan(&self) -> Option<infraternal_plugin_release::applier::RollbackPlan> {
        apply::rollback_plan(&self.data, infraternal_plugin_api::VERSION, self.artifact).map(
            |plan| infraternal_plugin_release::applier::RollbackPlan {
                to: plan.to_version,
                copy_taken_at: plan.copy_taken_at,
            },
        )
    }
}

/// Answers whether the CA is unlocked right now; see [`set_ca_probe`].
type CaProbe = Box<dyn Fn() -> bool + Send + Sync>;
/// The registered [`CaProbe`]; `None` (treated as locked) until the CLI registers one.
static CA_PROBE: Mutex<Option<CaProbe>> = Mutex::new(None);

/// Register the CLI's restart loop as the one place switches happen, and return its
/// inbox. Call once, when the restart control endpoint is up; a server without one
/// never applies updates (the apply task finds no inbox and records why).
#[must_use]
pub fn switch_requests() -> mpsc::Receiver<SwitchRequest> {
    let (sender, receiver) = mpsc::channel(1);
    *SWITCHES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sender);
    receiver
}

/// Register how to ask whether the CA is unlocked right now (D217).
///
/// It must reflect the live state, not the startup: a server that started cold and was
/// later unlocked with a passkey holds the CA too, and its updates must keep it.
pub fn set_ca_probe(probe: CaProbe) {
    *CA_PROBE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(probe);
}

/// Whether this process holds the unlocked CA now; a switch that would lose it is
/// refused, and a new release that did not receive it fails its health check.
#[must_use]
pub fn ca_warm() -> bool {
    CA_PROBE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .is_some_and(|probe| probe())
}

/// SHA-256 of `file` as hex, for the CLI to admit A's kept image on an undo.
/// # Errors
/// The file could not be read.
pub fn image_digest(file: &std::fs::File) -> Result<String, &'static str> {
    apply::digest(file)
}

/// Handle a switch in flight before the database opens; see the module docs.
///
/// Call it first thing in server startup, before the database or the CA are touched.
/// Only root release builds do anything here. Errors are logged and never stop the
/// server (a failed undo must not take it offline), with one exception: a new
/// release that cannot record its trial returns `Err` and must not open the
/// database. The caller stops; the service manager then starts the boot pointer, the
/// previous release, which finds the switch never ran and keeps its database (J1085).
/// # Errors
/// [`apply::TRIAL_NOT_RECORDED`]: this process is the new release, untried.
pub fn startup(data: &Path) -> Result<(), &'static str> {
    // A server that came back in-process after both execs failed admits terminals again.
    crate::update_activity::freeze(false);
    if update::availability(crate::release_latest::release_build()).is_err() {
        return Ok(());
    }
    // Live shims keep the rolled-back release's writer cursors, so fresh attachments after
    // a roll back must never reuse writer IDs the rolled-back release allocated (#211).
    // The floor is read from the live database and written into the restored copy inside
    // the restore itself, before the copy is renamed over it (J1180 F5): only an undo that
    // restores opens the database, and a crash cannot lose the floor between the two steps.
    let resumed = apply::resume_with(
        data,
        infraternal_plugin_api::VERSION,
        || {
            std::fs::File::open("/proc/self/exe")
                .map_err(|_| "the running image could not be read")
                .and_then(|file| apply::digest(&file))
        },
        |live, restored| {
            let Some(floor) = crate::update_writer_clock::read_high_water(live) else {
                return;
            };
            match crate::update_writer_clock::advance_to_at_least(restored, floor) {
                Ok(()) => tracing::info!(
                    writer_floor = floor,
                    "update_rollback_writer_clock_preserved"
                ),
                Err(reason) => tracing::warn!(
                    reason,
                    writer_floor = floor,
                    "update_rollback_writer_clock_failed"
                ),
            }
        },
    );
    match resumed {
        Ok(Resume::Idle) => {}
        Ok(Resume::Trial(pending)) => {
            tracing::info!(
                from = pending.from_version,
                to = pending.to_version,
                "update_trial_started"
            );
            *TRIAL
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(pending);
            TRIAL_OPEN.send_replace(true);
        }
        Ok(Resume::Finished(outcome)) => {
            tracing::warn!(outcome, "update_switch_finished");
        }
        Err(apply::TRIAL_NOT_RECORDED) => {
            tracing::error!(
                reason = apply::TRIAL_NOT_RECORDED,
                "update_switch_resume_failed"
            );
            return Err(apply::TRIAL_NOT_RECORDED);
        }
        Err(reason) => tracing::error!(reason, "update_switch_resume_failed"),
    }
    Ok(())
}

/// Start S4 next to the S3 check: run the trial if this process is one, then watch for
/// a staged release to apply in a quiet window.
pub(crate) fn start(
    updater: Arc<Updater>,
    pool: sqlx::SqlitePool,
    data: PathBuf,
    listen: SocketAddr,
    artifact: &'static str,
    executable: PathBuf,
) {
    let trial = TRIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let timing = Timing::from_environment();
    tokio::spawn(async move {
        if trial.is_none() {
            settle_served(&data).await;
        }
        if let Some(trial) = trial {
            // A trial ends in an exec (undo) or a commit; only after a commit does this
            // release go on to apply later updates.
            if !run_trial(&trial, &pool, &data, listen, artifact, &executable).await {
                return;
            }
        }
        quiet_window(&updater, &pool, &data, artifact, timing.quiet).await;
    });
}

/// This release serves and is not on trial: settle any marker its start could not
/// finish, so no later start restores a stale database copy (J1085).
async fn settle_served(data: &Path) {
    let data = data.to_owned();
    let settled = tokio::task::spawn_blocking(move || {
        apply::settle_served(&data, infraternal_plugin_api::VERSION, || {
            std::fs::File::open("/proc/self/exe")
                .map_err(|_| "the running image could not be read")
                .and_then(|file| apply::digest(&file))
        })
    })
    .await;
    match settled {
        Ok(Ok(Some(outcome))) => tracing::warn!(outcome, "update_switch_settled"),
        Ok(Ok(None)) => {}
        Ok(Err(reason)) => tracing::error!(reason, "update_switch_settle_failed"),
        Err(_) => tracing::error!("update_switch_settle_failed"),
    }
}

/// The warm undo for a new release on trial that could not start serving (#211 S4).
///
/// The CLI calls this when the server's serving future returns an error. If this
/// process is a release on trial, the marker moves to phase `rollback` with
/// [`apply::FAILED_TO_START`], and the returned [`Undo`] is what the restart loop
/// needs to exec the previous release warm, exactly like a failed health check. The
/// previous release then restores its database copy before opening the database
/// (D295). Returns `None` when this process is not on trial (the error then ends the
/// process as before) or the marker could not be updated.
#[must_use]
pub fn failed_start_undo(data: &Path) -> Option<Undo> {
    let trial = TRIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()?;
    let artifact = update::availability(crate::release_latest::release_build()).ok()?;
    tracing::warn!(
        version = trial.to_version,
        reason = apply::FAILED_TO_START,
        "update_trial_failed"
    );
    apply::begin_rollback(data, &trial, artifact, apply::FAILED_TO_START)
        .inspect_err(|reason| tracing::error!(reason, "update_undo_not_marked"))
        .ok()
}

/// A fault the staging proof gives one release, named in `INFRATERNAL_STAGING_FAULTS`
/// as space-separated `<version>=<fault>` entries (`staging-trust` builds only).
#[cfg(any(test, feature = "staging-trust"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagingFault {
    /// `unhealthy`: the release's health check fails at once.
    Unhealthy,
    /// `timeout`: the release's health check never answers, so the trial limit ends it.
    Timeout,
    /// `migration`: the release's database migration fails at startup.
    Migration,
    /// `exec`: the running release's exec of this release is refused, so the late-exec
    /// recovery brings the running release back.
    Exec,
    /// `unlisted`: the release's trial sees no live sessions, as if its infraternal
    /// agent could not reattach any shim.
    Unlisted,
}

/// The fault `list` (the `INFRATERNAL_STAGING_FAULTS` format) gives `version`, if any.
/// Unknown fault names are ignored.
#[cfg(any(test, feature = "staging-trust"))]
fn parse_fault(list: &str, version: &str) -> Option<StagingFault> {
    list.split_whitespace().find_map(|entry| {
        let (named, fault) = entry.split_once('=')?;
        if named != version {
            return None;
        }
        match fault {
            "unhealthy" => Some(StagingFault::Unhealthy),
            "timeout" => Some(StagingFault::Timeout),
            "migration" => Some(StagingFault::Migration),
            "exec" => Some(StagingFault::Exec),
            "unlisted" => Some(StagingFault::Unlisted),
            _ => None,
        }
    })
}

/// The fault the staging proof gives release `version`, from `INFRATERNAL_STAGING_FAULTS`.
#[cfg(feature = "staging-trust")]
#[must_use]
pub fn staging_fault(version: &str) -> Option<StagingFault> {
    parse_fault(&std::env::var("INFRATERNAL_STAGING_FAULTS").ok()?, version)
}

/// Whether this process is a release on trial with the staging `migration` fault: its
/// startup then fails the way a broken migration does.
#[cfg(feature = "staging-trust")]
pub(crate) fn staging_migration_fails() -> bool {
    staging_fault(infraternal_plugin_api::VERSION) == Some(StagingFault::Migration)
        && TRIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
}

/// The quiet window and the check timing, shortened only by the staging hook.
#[derive(Clone, Copy)]
pub(crate) struct Timing {
    /// Override for the quiet window before an apply (`staging-trust` only); `None` reads
    /// the saved `quiet_minutes` setting on each decision, falling back to [`QUIET`].
    pub(crate) quiet: Option<Duration>,
    /// The first check after start and the period between checks, when overridden.
    pub(crate) checks: Option<Duration>,
}

impl Timing {
    /// Production timing, or the `staging-trust` override.
    pub(crate) fn from_environment() -> Self {
        #[cfg(feature = "staging-trust")]
        if let Some(seconds) = std::env::var("INFRATERNAL_STAGING_UPDATE_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| (1..=3600).contains(seconds))
        {
            let seconds = Duration::from_secs(seconds);
            return Self {
                quiet: Some(seconds),
                checks: Some(seconds),
            };
        }
        Self {
            quiet: None,
            checks: None,
        }
    }
}

/// Resolve the quiet window for one apply decision: the test/staging override when set,
/// otherwise the owner's saved `quiet_minutes` setting (falling back to [`QUIET`] when
/// none is saved or the saved value is out of range).
async fn effective_quiet(pool: &sqlx::SqlitePool, quiet_override: Option<Duration>) -> Duration {
    if let Some(quiet) = quiet_override {
        return quiet;
    }
    let minutes = infraternal_plugin_release::service::quiet_minutes(pool).await;
    Duration::from_mins(u64::from(minutes))
}

/// Wait for a staged release and a quiet window, then switch. Returns only if the
/// update state can no longer be watched.
async fn quiet_window(
    updater: &Updater,
    pool: &sqlx::SqlitePool,
    data: &Path,
    artifact: &'static str,
    quiet_override: Option<Duration>,
) {
    quiet_window_with(
        data,
        || effective_quiet(pool, quiet_override),
        crate::update_activity::idle_for,
        |window| switch_once(updater, pool, data, artifact, window),
    )
    .await;
}

/// The quiet-window apply loop, parameterized on the quiet-window reader, the idle clock,
/// and the switch step so unit tests can drive it under Tokio's paused clock without
/// touching process-wide activity statics or background SQLite worker threads.
async fn quiet_window_with<Q, QFut, F, Fut>(
    data: &Path,
    mut read_quiet: Q,
    idle_for: impl Fn() -> Duration,
    mut attempt: F,
) where
    Q: FnMut() -> QFut,
    QFut: std::future::Future<Output = Duration>,
    F: FnMut(Duration) -> Fut,
    Fut: std::future::Future<Output = Result<(), Retry>>,
{
    let mut changes = update::changes();
    loop {
        let state = update::status(data, infraternal_plugin_api::VERSION);
        let forced = FORCE.load(std::sync::atomic::Ordering::SeqCst);
        if !may_apply(&state, forced) {
            // Nothing to apply, or automatic apply is off and nobody asked: wait for a change
            // of state or for the owner's explicit apply (J1130).
            tokio::select! {
                result = changes.changed() => if result.is_err() { return },
                () = NOW.notified() => {}
            }
            continue;
        }
        let window = if forced {
            Duration::ZERO
        } else {
            let quiet = read_quiet().await;
            let idle = idle_for();
            if idle < quiet {
                // Sleep until the window could close; typing meanwhile only moves it. A state
                // or setting change wakes the wait so a shorter quiet window takes effect
                // without waiting out the previous sleep, and "Update now" ends the wait at once.
                tokio::select! {
                    () = tokio::time::sleep(quiet.saturating_sub(idle)) => {}
                    result = changes.changed() => if result.is_err() { return },
                    () = NOW.notified() => {}
                }
                continue;
            }
            quiet
        };
        // The owner's request skips the quiet window for this one attempt (an update never
        // waits for it when the owner asked for it by name); a failure is not forced again.
        let outcome = attempt(window).await;
        FORCE.store(false, std::sync::atomic::Ordering::SeqCst);
        match outcome {
            // The restart loop is about to exec the new release.
            Ok(()) => return std::future::pending().await,
            Err(Retry::Soon) => {}
            Err(Retry::Later(reason)) => {
                tracing::info!(reason, "update_not_applied");
                tokio::time::sleep(RETRY).await;
            }
        }
    }
}

/// Whether the quiet-window task may start a switch: a release is staged and not paused,
/// and either the owner asked for it by name (`forced`) or automatic apply is on (J1130).
/// With automatic apply off the server still checks and stages, but never switches alone.
fn may_apply(state: &update::UpdateState, forced: bool) -> bool {
    let ready = state
        .staged
        .as_ref()
        .is_some_and(|staged| state.paused.as_ref() != Some(staged));
    ready && (state.automatic || forced)
}

/// Why one apply attempt stopped.
enum Retry {
    /// Someone typed during the confirmation: try again after the next quiet window.
    Soon,
    /// The attempt failed: wait [`RETRY`] first.
    Later(&'static str),
}

/// One apply attempt: confirm, install, keep A and the database copy, mark, hand off.
async fn switch_once(
    updater: &Updater,
    pool: &sqlx::SqlitePool,
    data: &Path,
    artifact: &'static str,
    quiet: Duration,
) -> Result<(), Retry> {
    // One switch at a time: a marker left by an unfinished undo keeps everything else
    // waiting, so a failure can never turn into a loop of switches.
    if apply::in_flight(data) {
        return Err(Retry::Later("an earlier update switch has not finished"));
    }
    let confirmed = updater.confirm_staged().await.map_err(Retry::Later)?;
    if crate::update_activity::idle_for() < quiet {
        return Err(Retry::Soon);
    }
    let to_version = confirmed.version().to_owned();
    // The running release's own web build, kept with its image so a manual roll back
    // serves it again (#211 S6). Resolved before install, which may replace `current`.
    let running_web = infraternal_plugin_release::web::release_web(&running_path(), data);
    let prepared = tokio::task::spawn_blocking(move || {
        let switch = apply::install(confirmed, artifact)?;
        let running = std::fs::File::open("/proc/self/exe")
            .map_err(|_| "the running image could not be read")?;
        let from_sha256 = switch.save_previous(&running, artifact)?;
        // Only a later manual roll back needs it, so a failure never blocks the update:
        // that roll back would then serve `--web-root` (or no web build).
        if let Err(reason) = switch.save_previous_web(running_web.as_deref()) {
            tracing::warn!(reason, outcome = "previous_web_not_kept", "update_prepare");
        }
        let to_sha256 = switch.digest()?;
        Ok::<_, &'static str>((switch, from_sha256, to_sha256))
    })
    .await
    .map_err(|_| Retry::Later("the update could not be prepared"))?;
    let (switch, from_sha256, to_sha256) = prepared.map_err(Retry::Later)?;
    let give_up = |switch: Switch, reason: &'static str| {
        let _ = switch.abandon(infraternal_plugin_api::VERSION, reason);
        crate::update_activity::freeze(false);
        Retry::Later(reason)
    };
    // The new release must list these again before it commits (owner, 2026-11-21).
    let Some(sessions) = live_sessions(registered_inventory().as_ref()) else {
        return Err(give_up(switch, "the live sessions could not be listed"));
    };
    // From the copy to the exec no terminal input is taken, so nothing the copy lacks
    // is acknowledged to a shim (J1085); a refused switch admits it again.
    crate::update_activity::freeze(true);
    // D295: one online copy of the database, right before the switch.
    if let Err(reason) = copy_database(pool, &switch.database_copy()).await {
        return Err(give_up(switch, reason));
    }
    let pending = Pending {
        phase: Phase::Switching,
        from_version: infraternal_plugin_api::VERSION.to_owned(),
        from_sha256,
        from_path: running_path(),
        to_version: to_version.clone(),
        to_sha256,
        ca_warm: ca_warm(),
        started: now(),
        reason: None,
        undo_attempts: 0,
        sessions: sessions
            .iter()
            .map(|id| uuid::Uuid::from_bytes(*id).simple().to_string())
            .collect(),
    };
    if let Err(reason) = switch.begin(&pending) {
        return Err(give_up(switch, reason));
    }
    let sender = SWITCHES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(sender) = sender else {
        return Err(give_up(
            switch,
            "this server has no restart control to switch with",
        ));
    };
    tracing::info!(
        from = pending.from_version,
        to = to_version,
        "update_switch_requested"
    );
    let (reply, answer) = oneshot::channel();
    if let Err(mpsc::error::SendError(request)) =
        sender.send(SwitchRequest::Apply { switch, reply }).await
    {
        let SwitchRequest::Apply { switch, .. } = request else {
            unreachable!("the request sent was an apply");
        };
        return Err(give_up(switch, "the restart control is not running"));
    }
    match answer.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(switch)) => Err(give_up(
            switch,
            "the new release was refused for the switch",
        )),
        Err(_) => {
            crate::update_activity::freeze(false);
            Err(Retry::Later("the restart control dropped the switch"))
        }
    }
}

/// Write the D295 database copy to `path` with `VACUUM INTO`, make it private (0600)
/// and durable.
///
/// SQLite creates the file with the process umask, but the copy holds everything the
/// database holds, and the undo restores only a private file. Its folder (`previous/`,
/// 0700) keeps it unreachable to anyone else in between.
///
/// The copy and its folder entry are flushed to disk before this returns, because the
/// marker written next is: after a power loss during the trial, a durable marker
/// would make the previous release restore whatever part of the copy had reached the
/// disk. SQLite does not promise that `VACUUM INTO` output is synced.
/// # Errors
/// The path is not text, or the copy could not be written, made private or synced.
pub(crate) async fn copy_database(
    pool: &sqlx::SqlitePool,
    path: &Path,
) -> Result<(), &'static str> {
    use std::os::unix::fs::PermissionsExt;
    let text = path.to_str().ok_or("the database copy path is not text")?;
    sqlx::query("VACUUM INTO ?")
        .bind(text)
        .execute(pool)
        .await
        .map_err(|_| "the database copy could not be written")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| "the database copy could not be made private")?;
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        std::fs::File::open(&path)?.sync_all()?;
        let folder = path.parent().ok_or(std::io::ErrorKind::NotFound)?;
        std::fs::File::open(folder)?.sync_all()
    })
    .await
    .ok()
    .and_then(Result::ok)
    .ok_or("the database copy could not be synced")
}

/// The new release's trial: health within [`TRIAL_LIMIT`], then commit or undo.
/// Returns `true` after a commit (the server goes on as the new release).
async fn run_trial(
    trial: &Pending,
    pool: &sqlx::SqlitePool,
    data: &Path,
    listen: SocketAddr,
    artifact: &'static str,
    executable: &Path,
) -> bool {
    // A marker with a reason means B started again mid-trial or after a failed undo
    // exec: undo again, keeping the reason.
    let verdict = if trial.reason.is_some() {
        Err(apply::undo_reason(trial.reason.as_deref()))
    } else {
        let check = async {
            healthy(pool, listen, trial).await.map_err(|reason| {
                tracing::warn!(reason, "update_health_failed");
                apply::UNHEALTHY
            })?;
            #[cfg(target_os = "linux")]
            infraternal_agent::logins::check_login_image(executable)
                .await
                .map_err(|error| {
                    tracing::warn!(%error, "update_login_image_failed");
                    apply::LOGIN_IMAGE_FAILED
                })?;
            #[cfg(not(target_os = "linux"))]
            let _ = executable;
            Ok(())
        };
        match tokio::time::timeout(TRIAL_LIMIT, check).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(reason)) => Err(reason),
            Err(_) => {
                let missing = SESSIONS_WAITING.load(std::sync::atomic::Ordering::Relaxed);
                let reason = if missing > 0 {
                    apply::SESSIONS_MISSING
                } else {
                    apply::TIMED_OUT
                };
                tracing::warn!(reason, missing_sessions = missing, "update_health_failed");
                Err(reason)
            }
        }
    };
    let data = data.to_owned();
    match verdict {
        Ok(()) => {
            let committed = {
                let (data, trial) = (data.clone(), trial.clone());
                tokio::task::spawn_blocking(move || {
                    apply::commit(&data, &trial)?;
                    publish_cli_link(&data, &trial.to_version, artifact);
                    Ok::<_, &'static str>(())
                })
                .await
            };
            match committed {
                Ok(Ok(())) => {
                    tracing::info!(version = trial.to_version, "update_applied");
                    *TRIAL
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                    TRIAL_OPEN.send_replace(false);
                    true
                }
                Ok(Err(reason)) => {
                    tracing::error!(reason, "update_commit_failed");
                    TRIAL_OPEN.send_replace(false);
                    false
                }
                Err(_) => {
                    TRIAL_OPEN.send_replace(false);
                    false
                }
            }
        }
        Err(reason) => {
            tracing::warn!(reason, version = trial.to_version, "update_trial_failed");
            undo(trial, &data, artifact, reason).await;
            // Still here: the undo was refused, and this release keeps serving.
            TRIAL_OPEN.send_replace(false);
            false
        }
    }
}

/// Ask the restart loop to exec the previous release (D295). If that is impossible this
/// release keeps serving: the marker stays in phase `rollback`, so the next cold start
/// of the previous release still restores its database copy.
async fn undo(trial: &Pending, data: &Path, artifact: &'static str, reason: &'static str) {
    let marked = {
        let (data, trial) = (data.to_owned(), trial.clone());
        tokio::task::spawn_blocking(move || apply::begin_rollback(&data, &trial, artifact, reason))
            .await
    };
    let Ok(Ok(undo)) = marked else {
        tracing::error!("update_undo_not_marked");
        return;
    };
    let sender = SWITCHES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(sender) = sender else {
        tracing::error!("update_undo_without_restart_control");
        return;
    };
    let (reply, answer) = oneshot::channel();
    if sender
        .send(SwitchRequest::Undo { undo, reply })
        .await
        .is_err()
        || !matches!(answer.await, Ok(Ok(())))
    {
        tracing::error!("update_undo_refused");
    }
}

/// The trial's health check: `/healthz` answers 200 on this server's own listener, a
/// write transaction commits, and the CA is unlocked if the previous release had it
/// unlocked (an update must never lock the CA, D217).
async fn healthy(
    pool: &sqlx::SqlitePool,
    listen: SocketAddr,
    trial: &Pending,
) -> Result<(), &'static str> {
    if trial.ca_warm && !ca_warm() {
        return Err("the new release did not receive the unlocked CA");
    }
    #[cfg(feature = "staging-trust")]
    match staging_fault(infraternal_plugin_api::VERSION) {
        Some(StagingFault::Unhealthy) => {
            return Err("staging: this version is set to fail its health check");
        }
        // Never answer, so the trial limit decides (the real 2 minutes).
        Some(StagingFault::Timeout) => std::future::pending::<()>().await,
        _ => {}
    }
    let address = loopback(listen);
    loop {
        if healthz(address).await {
            break;
        }
        // sleep: the listener is still starting; poll it four times a second.
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let mut connection = pool
        .acquire()
        .await
        .map_err(|_| "the database is not available")?;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await
        .map_err(|_| "the database cannot take a write")?;
    sqlx::query("COMMIT")
        .execute(&mut *connection)
        .await
        .map_err(|_| "the database cannot take a write")?;
    let folder = infraternal_agent::sessions::state_path(None)
        .ok()
        .map(|state| state.join("sessions"));
    sessions_listed(
        &trial.sessions,
        folder.as_deref(),
        registered_inventory(),
        &SESSIONS_WAITING,
    )
    .await;
    Ok(())
}

/// The listener's own address on loopback (a wildcard listener is reached on loopback).
fn loopback(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        ip if !ip.is_unspecified() => ip,
        std::net::IpAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
        std::net::IpAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
    };
    SocketAddr::new(ip, listen.port())
}

/// Whether `GET /healthz` on `address` answers 200 within a few seconds. The listener
/// speaks plain HTTP behind the proxy or TLS when standalone; both are tried.
async fn healthz(address: SocketAddr) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    /// Send the request on `stream` and read the status line.
    async fn ask<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut stream: S) -> bool {
        let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        if stream.write_all(request).await.is_err() {
            return false;
        }
        let mut head = [0; 12];
        stream.read_exact(&mut head).await.is_ok() && head.ends_with(b" 200")
    }
    let attempt = async {
        let Ok(socket) = tokio::net::TcpStream::connect(address).await else {
            return false;
        };
        if ask(socket).await {
            return true;
        }
        // A standalone TLS listener: the check is to our own loopback socket, so the
        // certificate is not what is being tested here.
        let Ok(socket) = tokio::net::TcpStream::connect(address).await else {
            return false;
        };
        let Ok(mut builder) =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())
        else {
            return false;
        };
        builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
        let Ok(ssl) = builder
            .build()
            .configure()
            .and_then(|config| config.verify_hostname(false).into_ssl("localhost"))
        else {
            return false;
        };
        let Ok(mut stream) = tokio_openssl::SslStream::new(ssl, socket) else {
            return false;
        };
        if std::pin::Pin::new(&mut stream).connect().await.is_err() {
            return false;
        }
        ask(stream).await
    };
    tokio::time::timeout(Duration::from_secs(5), attempt)
        .await
        .unwrap_or(false)
}

/// The trial's `/healthz` probe, for the root staging proof's own readiness waits.
#[cfg(test)]
pub(crate) async fn healthz_for_tests(address: SocketAddr) -> bool {
    healthz(address).await
}

/// This process's executable path as the service started it, given back to it on an
/// undo. After an earlier warm switch the kernel names the image a memfd, so the
/// configured argv\[0\] is used then, the same rule the restart reload follows.
fn running_path() -> PathBuf {
    let configured = || {
        std::env::args_os().next().map(PathBuf::from).map(|path| {
            if path.is_absolute() {
                path
            } else {
                std::env::current_dir().unwrap_or_default().join(path)
            }
        })
    };
    match std::env::current_exe() {
        Ok(path)
            if !path.to_string_lossy().ends_with(" (deleted)")
                && !path.to_string_lossy().starts_with("/memfd:") =>
        {
            path
        }
        _ => configured().unwrap_or_default(),
    }
}

/// Undo a manual rollback whose exec was refused, moving both the boot pointer and the
/// world-executable CLI copy back to the still-running release off the async runtime (P2, #211).
async fn cancel_manual_rollback_with_cli(data: PathBuf, artifact: &'static str) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = apply::cancel_manual_rollback(&data, infraternal_plugin_api::VERSION);
        publish_cli_link(&data, infraternal_plugin_api::VERSION, artifact);
    })
    .await;
}

/// Publish the committed release's world-executable CLI copy and `/usr/local/bin/infraternal` link (#211).
///
/// Runs inside the root server process right after `apply::commit` (or when a manual rollback is
/// cancelled) so automatic quiet-window updates, Web UI updates and `--no-wait` CLI updates all
/// keep the CLI on `PATH` in sync. A foreign `/usr/local/bin/infraternal` is refused loudly in the
/// server log and never overwritten; it does not roll back a healthy committed server.
fn publish_cli_link(data: &Path, version: &str, artifact: &str) {
    let source = data.join("updates/releases").join(version).join(artifact);
    let paths = cli_link::CliPaths::system();
    match cli_link::publish(
        &source,
        &paths,
        infraternal_agent::exec_label::executable_label,
    ) {
        Ok(outcome) => tracing::info!(
            version,
            path = %paths.active().display(),
            link = %paths.path_link.display(),
            ?outcome,
            "update_cli_link_published"
        ),
        Err(error) => tracing::error!(
            version,
            error = %error,
            "update_cli_link_refused"
        ),
    }
}

/// Restore the previous release's world-executable CLI copy during a manual rollback (#211).
///
/// Falls back to `<data>/updates/previous/<artifact>` when `infraternal.previous` has not been
/// populated yet (such as rolling back the first update after upgrading from a pre-J1147 server).
fn restore_cli_link(data: &Path, artifact: &str) {
    let fallback = data.join("updates/previous").join(artifact);
    let paths = cli_link::CliPaths::system();
    match cli_link::restore(
        &paths,
        Some(&fallback),
        infraternal_agent::exec_label::executable_label,
    ) {
        Ok(outcome) => tracing::info!(
            path = %paths.active().display(),
            link = %paths.path_link.display(),
            ?outcome,
            "update_cli_link_restored"
        ),
        Err(error) => tracing::error!(
            error = %error,
            "update_cli_link_restore_refused"
        ),
    }
}

/// The current time in Unix seconds.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Unit checks for the health probe and the loopback address rule.
#[cfg(test)]
#[path = "update_apply_tests.rs"]
mod tests;
