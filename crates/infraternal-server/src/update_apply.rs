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
//!   answers 200 on its own listener, a write transaction commits, and the CA is
//!   unlocked if it was before. On a pass it commits the boot pointer. Otherwise it
//!   asks the loop to exec the previous release warm, which restores the database
//!   copy at its own startup (D295).
//!
//! The quiet-window task and the trial run only where the S3 check runs: a root,
//! signed release build on Linux.
//!
//! **Staging hooks.** These are compiled only with the non-default `staging-trust`
//! feature, which production builds refuse (`check-production-trust.py`).
//! `INFRATERNAL_STAGING_UPDATE_SECONDS` shortens the first check, the check period and
//! the quiet window, and `INFRATERNAL_STAGING_UNHEALTHY_VERSION` fails the health check
//! of that one version. Together they let a real root server prove the rollback
//! without publishing anything.
use infraternal_plugin_release::{
    apply::{self, Pending, Phase, Resume, Switch, Undo},
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

/// The restart loop's inbox; `None` until the CLI registers with [`switch_requests`].
static SWITCHES: Mutex<Option<mpsc::Sender<SwitchRequest>>> = Mutex::new(None);
/// The trial [`startup`] found, for [`start`] to run once the server serves.
static TRIAL: Mutex<Option<Pending>> = Mutex::new(None);
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
/// server: a failed undo must not take it offline.
pub fn startup(data: &Path) {
    if update::availability(crate::release_latest::release_build()).is_err() {
        return;
    }
    let resumed = apply::resume(data, infraternal_plugin_api::VERSION, || {
        std::fs::File::open("/proc/self/exe")
            .map_err(|_| "the running image could not be read")
            .and_then(|file| apply::digest(&file))
    });
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
        }
        Ok(Resume::Finished(outcome)) => tracing::warn!(outcome, "update_switch_finished"),
        Err(reason) => tracing::error!(reason, "update_switch_resume_failed"),
    }
}

/// Start S4 next to the S3 check: run the trial if this process is one, then watch for
/// a staged release to apply in a quiet window.
pub(crate) fn start(
    updater: Arc<Updater>,
    pool: sqlx::SqlitePool,
    data: PathBuf,
    listen: SocketAddr,
    artifact: &'static str,
) {
    let trial = TRIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let timing = Timing::from_environment();
    tokio::spawn(async move {
        if let Some(trial) = trial {
            // A trial ends in an exec (undo) or a commit; only after a commit does this
            // release go on to apply later updates.
            if !run_trial(&trial, &pool, &data, listen, artifact).await {
                return;
            }
        }
        quiet_window(&updater, &pool, &data, artifact, timing.quiet).await;
    });
}

/// The quiet window and the check timing, shortened only by the staging hook.
#[derive(Clone, Copy)]
pub(crate) struct Timing {
    /// The quiet window before an apply.
    pub(crate) quiet: Duration,
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
                quiet: seconds,
                checks: Some(seconds),
            };
        }
        Self {
            quiet: QUIET,
            checks: None,
        }
    }
}

/// Wait for a staged release and a quiet window, then switch. Returns only if the
/// update state can no longer be watched.
async fn quiet_window(
    updater: &Updater,
    pool: &sqlx::SqlitePool,
    data: &Path,
    artifact: &'static str,
    quiet: Duration,
) {
    let mut changes = update::changes();
    loop {
        let state = update::status(data, infraternal_plugin_api::VERSION);
        let ready = state
            .staged
            .as_ref()
            .is_some_and(|staged| state.paused.as_ref() != Some(staged));
        if !ready {
            if changes.changed().await.is_err() {
                return;
            }
            continue;
        }
        let idle = crate::update_activity::idle_for();
        if idle < quiet {
            // Sleep until the window could close; typing meanwhile only moves it.
            tokio::time::sleep(quiet.saturating_sub(idle)).await;
            continue;
        }
        match switch_once(updater, pool, data, artifact, quiet).await {
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
    let prepared = tokio::task::spawn_blocking(move || {
        let switch = apply::install(confirmed, artifact)?;
        let running = std::fs::File::open("/proc/self/exe")
            .map_err(|_| "the running image could not be read")?;
        let from_sha256 = switch.save_previous(&running, artifact)?;
        let to_sha256 = switch.digest()?;
        Ok::<_, &'static str>((switch, from_sha256, to_sha256))
    })
    .await
    .map_err(|_| Retry::Later("the update could not be prepared"))?;
    let (switch, from_sha256, to_sha256) = prepared.map_err(Retry::Later)?;
    let give_up = |switch: Switch, reason: &'static str| {
        let _ = switch.abandon(infraternal_plugin_api::VERSION, reason);
        Retry::Later(reason)
    };
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
        Err(_) => Err(Retry::Later("the restart control dropped the switch")),
    }
}

/// Write the D295 database copy to `path` with `VACUUM INTO`, then make it private (0600).
///
/// SQLite creates the file with the process umask, but the copy holds everything the
/// database holds, and the undo restores only a private file. Its folder (`previous/`,
/// 0700) keeps it unreachable to anyone else in between.
/// # Errors
/// The path is not text, or the copy could not be written or made private.
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
        .map_err(|_| "the database copy could not be made private")
}

/// The new release's trial: health within [`TRIAL_LIMIT`], then commit or undo.
/// Returns `true` after a commit (the server goes on as the new release).
async fn run_trial(
    trial: &Pending,
    pool: &sqlx::SqlitePool,
    data: &Path,
    listen: SocketAddr,
    artifact: &'static str,
) -> bool {
    // A marker with a reason means B started again mid-trial or after a failed undo
    // exec: undo again, keeping the reason.
    let verdict = if trial.reason.is_some() {
        Err(if trial.reason.as_deref() == Some(apply::UNHEALTHY) {
            apply::UNHEALTHY
        } else {
            apply::STOPPED_IN_TRIAL
        })
    } else {
        tokio::time::timeout(TRIAL_LIMIT, healthy(pool, listen, trial.ca_warm))
            .await
            .unwrap_or(Err("the health check did not pass in time"))
            .map_err(|reason| {
                tracing::warn!(reason, "update_health_failed");
                apply::UNHEALTHY
            })
    };
    let data = data.to_owned();
    match verdict {
        Ok(()) => {
            let committed = {
                let (data, trial) = (data.clone(), trial.clone());
                tokio::task::spawn_blocking(move || apply::commit(&data, &trial)).await
            };
            match committed {
                Ok(Ok(())) => {
                    tracing::info!(version = trial.to_version, "update_applied");
                    true
                }
                Ok(Err(reason)) => {
                    tracing::error!(reason, "update_commit_failed");
                    false
                }
                Err(_) => false,
            }
        }
        Err(reason) => {
            tracing::warn!(reason, version = trial.to_version, "update_trial_failed");
            undo(trial, &data, artifact, reason).await;
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
    ca_was_warm: bool,
) -> Result<(), &'static str> {
    if ca_was_warm && !ca_warm() {
        return Err("the new release did not receive the unlocked CA");
    }
    #[cfg(feature = "staging-trust")]
    if std::env::var("INFRATERNAL_STAGING_UNHEALTHY_VERSION")
        .is_ok_and(|version| version == infraternal_plugin_api::VERSION)
    {
        return Err("staging: this version is set to fail its health check");
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
