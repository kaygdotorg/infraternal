//! Unit checks for S4's health probe (#211): loopback addressing, the `/healthz` status
//! line, the database write and the rule that an update must keep the CA unlocked.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serve one HTTP status line `status` to every connection on a loopback port.
async fn answering(status: &'static str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = [0; 256];
            let _ = socket.read(&mut request).await;
            let _ = socket
                .write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .await;
        }
    });
    address
}

/// A wildcard listener is probed on loopback; a specific address is kept.
#[test]
fn the_probe_uses_loopback_for_wildcard_listeners() {
    assert_eq!(
        loopback("0.0.0.0:8080".parse().unwrap()),
        "127.0.0.1:8080".parse().unwrap()
    );
    assert_eq!(
        loopback("[::]:8080".parse().unwrap()),
        "[::1]:8080".parse().unwrap()
    );
    assert_eq!(
        loopback("10.1.2.3:8080".parse().unwrap()),
        "10.1.2.3:8080".parse().unwrap()
    );
}

/// Only a 200 counts; a 503 and a closed port do not.
#[tokio::test]
async fn only_a_200_from_healthz_counts() {
    assert!(healthz(answering("200 OK").await).await);
    assert!(!healthz(answering("503 Service Unavailable").await).await);
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    assert!(!healthz(address).await);
}

/// A trial marker whose previous release held the CA unlocked or not, with no sessions.
fn trial(ca_warm: bool) -> Pending {
    Pending {
        phase: Phase::Trial,
        from_version: "edge-20261121T000001Z".into(),
        from_sha256: "aa".repeat(32),
        from_path: "/opt/a/infraternal".into(),
        to_version: "edge-20261121T000002Z".into(),
        to_sha256: "bb".repeat(32),
        ca_warm,
        started: 1,
        reason: None,
        undo_attempts: 0,
        sessions: Vec::new(),
    }
}

/// A healthy listener and a writable database pass; losing the unlocked CA fails at
/// once, before anything is probed.
#[tokio::test]
async fn health_needs_the_listener_a_write_and_the_ca() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let address = answering("200 OK").await;
    let unlocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let probe = Arc::clone(&unlocked);
    set_ca_probe(Box::new(move || {
        probe.load(std::sync::atomic::Ordering::Relaxed)
    }));
    assert_eq!(healthy(&pool, address, &trial(false)).await, Ok(()));
    assert_eq!(
        healthy(&pool, address, &trial(true)).await,
        Err("the new release did not receive the unlocked CA")
    );
    // Unlocked later (a passkey after a cold start) counts the same as a handoff.
    unlocked.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(healthy(&pool, address, &trial(true)).await, Ok(()));
}

/// A database whose write lock is held elsewhere fails the write step.
#[tokio::test]
async fn a_database_that_cannot_take_a_write_fails() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let file = std::env::temp_dir().join(format!("health-{}.sqlite", uuid::Uuid::new_v4()));
    let options = SqliteConnectOptions::new()
        .filename(&file)
        .create_if_missing(true)
        .busy_timeout(Duration::ZERO);
    let holder = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();
    let mut held = holder.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *held)
        .await
        .unwrap();
    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .unwrap();
    let address = answering("200 OK").await;
    assert_eq!(
        healthy(&pool, address, &trial(false)).await,
        Err("the database cannot take a write")
    );
    drop(held);
    let _ = std::fs::remove_file(&file);
}

/// The running path is absolute and names this test binary, never a memfd label.
#[test]
fn the_running_path_is_the_configured_executable() {
    let path = running_path();
    assert!(path.is_absolute());
    assert!(!path.to_string_lossy().starts_with("/memfd:"));
}

/// The D295 copy is a private (0600) file that holds the database's rows, whatever the
/// umask; the undo only restores a private copy (found on the root proof, #211 S4).
#[tokio::test]
async fn the_database_copy_is_private_and_complete() {
    use std::os::unix::fs::PermissionsExt;
    // A file database on one connection, as the server's own: each pooled in-memory
    // connection would be a separate, empty database.
    let source = std::env::temp_dir().join(format!("source-{}.sqlite", uuid::Uuid::new_v4()));
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&source)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    sqlx::query("CREATE TABLE t(x TEXT)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO t VALUES('kept')")
        .execute(&pool)
        .await
        .unwrap();
    let folder = std::env::temp_dir().join(format!("copy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&folder).unwrap();
    let copy = folder.join("database.sqlite");
    copy_database(&pool, &copy).await.unwrap();
    assert_eq!(
        std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let copied =
        sqlx::SqlitePool::connect_with(sqlx::sqlite::SqliteConnectOptions::new().filename(&copy))
            .await
            .unwrap();
    let (value,): (String,) = sqlx::query_as("SELECT x FROM t")
        .fetch_one(&copied)
        .await
        .unwrap();
    assert_eq!(value, "kept");
    copied.close().await;
    pool.close().await;
    let _ = std::fs::remove_dir_all(&folder);
    let _ = std::fs::remove_file(&source);
}

/// The staging fault list names one fault per release; other releases, unknown fault
/// names and malformed entries get none.
#[test]
fn a_staging_fault_applies_only_to_the_release_it_names() {
    let list = "edge-1=unhealthy edge-2=timeout edge-3=migration edge-4=exec edge-5=melt bare";
    assert_eq!(parse_fault(list, "edge-1"), Some(StagingFault::Unhealthy));
    assert_eq!(parse_fault(list, "edge-2"), Some(StagingFault::Timeout));
    assert_eq!(parse_fault(list, "edge-3"), Some(StagingFault::Migration));
    assert_eq!(parse_fault(list, "edge-4"), Some(StagingFault::Exec));
    assert_eq!(parse_fault(list, "edge-5"), None);
    assert_eq!(parse_fault(list, "edge-9"), None);
    assert_eq!(parse_fault(list, "bare"), None);
    assert_eq!(parse_fault("", "edge-1"), None);
}

/// A server that is not a release on trial never asks for an undo when serving fails:
/// its error ends the process as before.
#[test]
fn a_failed_start_outside_a_trial_asks_for_no_undo() {
    let data = std::env::temp_dir().join(format!("s4-failed-start-{}", std::process::id()));
    assert!(failed_start_undo(&data).is_none());
}

/// J1085 finding 1: a new release on trial holds browser sockets until the trial
/// settles, and lets them in at once otherwise.
#[tokio::test]
async fn sockets_wait_while_the_new_release_is_on_trial() {
    // Not on trial: no wait.
    tokio::time::timeout(Duration::from_secs(1), terminals_admitted())
        .await
        .expect("admitted at once outside a trial");
    TRIAL_OPEN.send_replace(true);
    let waiting = tokio::spawn(terminals_admitted());
    // sleep: give the waiting socket a chance to (wrongly) get through.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!waiting.is_finished(), "held during the trial");
    TRIAL_OPEN.send_replace(false);
    tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .expect("admitted once the trial commits")
        .unwrap();
}

/// Owner decision 2026-11-21 (J1085 F4): the trial waits until the new release lists
/// every recorded session whose shim is still alive. A recorded session whose shim
/// has gone (exited during the trial) is not required. Before this check a release
/// that listed no session at all passed at once.
#[tokio::test]
async fn the_trial_waits_for_every_live_recorded_session() {
    use crate::embedded::SessionInventoryState;
    let folder = std::env::temp_dir().join(format!("s4-shims-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir(&folder).unwrap();
    let (alive, exited) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    // A live shim is a socket in the folder; the exited one left nothing behind.
    let _shim =
        std::os::unix::net::UnixListener::bind(folder.join(format!("{}.sock", alive.simple())))
            .unwrap();
    let (census, inventory) = tokio::sync::watch::channel(SessionInventoryState::Available(
        Vec::<[u8; 16]>::new().into(),
    ));
    let waiting_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let expected = vec![alive.simple().to_string(), exited.simple().to_string()];
    let waiting = {
        let (expected, folder) = (expected.clone(), folder.clone());
        let (inventory, count) = (inventory, waiting_count.clone());
        tokio::spawn(async move {
            sessions_listed(&expected, Some(&folder), Some(inventory), &count).await;
        })
    };
    // sleep: the new release lists nothing yet; give the trial time to (wrongly) pass.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!waiting.is_finished(), "a live recorded session is missing");
    assert_eq!(waiting_count.load(std::sync::atomic::Ordering::Relaxed), 1);
    census.send_replace(SessionInventoryState::Available(
        vec![*alive.as_bytes()].into(),
    ));
    tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("passes once every live recorded session is listed")
        .unwrap();
    let _ = std::fs::remove_dir_all(&folder);
}

/// J1130: with automatic apply off a staged release is never switched to by the quiet window,
/// only by the owner's explicit apply; with it on (the default) the quiet window applies as before.
#[test]
fn automatic_apply_off_waits_for_an_explicit_apply() {
    let staged = update::UpdateState {
        staged: Some("edge-20261122T000000Z".into()),
        ..update::UpdateState::default()
    };
    assert!(staged.automatic, "on by default");
    assert!(may_apply(&staged, false), "on: the quiet window applies");
    let manual = update::UpdateState {
        automatic: false,
        ..staged.clone()
    };
    assert!(!may_apply(&manual, false), "off: nothing applies alone");
    assert!(may_apply(&manual, true), "off: an explicit apply switches");
    let paused = update::UpdateState {
        paused: staged.staged.clone(),
        ..manual
    };
    assert!(
        !may_apply(&paused, true),
        "a paused release is never applied"
    );
    assert!(
        !may_apply(&update::UpdateState::default(), true),
        "nothing staged"
    );
}

/// Create a temp data folder whose `updates/state.json` has a staged release ready for
/// automatic apply.
fn staged_data_dir() -> PathBuf {
    let data = std::env::temp_dir().join(format!("s4-quiet-{}", uuid::Uuid::new_v4().simple()));
    let updates = data.join("updates");
    std::fs::create_dir_all(&updates).unwrap();
    let state = update::UpdateState {
        staged: Some("edge-20261124T000000Z".into()),
        ..update::UpdateState::default()
    };
    std::fs::write(
        updates.join("state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    data
}

/// Create an in-memory SQLite pool with `plugin_settings` for quiet-window storage checks.
async fn quiet_settings_pool() -> sqlx::SqlitePool {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE plugin_settings(role TEXT,plugin TEXT,enabled INTEGER,settings TEXT NOT NULL DEFAULT '{}',PRIMARY KEY(role,plugin))",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool
}

/// Save raw JSON `settings` for the `release` server plugin row.
async fn save_release_settings(pool: &sqlx::SqlitePool, settings: &str) {
    sqlx::query(
        "INSERT INTO plugin_settings(role,plugin,enabled,settings) VALUES('server','release',1,?) ON CONFLICT(role,plugin) DO UPDATE SET settings=excluded.settings",
    )
    .bind(settings)
    .execute(pool)
    .await
    .unwrap();
}

/// Advance Tokio's paused clock by `duration` and let spawned tasks run to quiescence.
async fn advance_and_settle(duration: Duration) {
    tokio::time::advance(duration).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}

/// J1145 (#211): `effective_quiet` reads `quiet_minutes` from `plugin_settings` on every
/// call, falls back to the 5-minute default when unset or out of range, and respects the
/// test/staging timing override when set.
#[tokio::test]
async fn effective_quiet_reads_saved_minutes_falls_back_to_default_and_honors_override() {
    let pool = quiet_settings_pool().await;
    // Nothing saved: default 5-minute quiet window applies.
    assert_eq!(effective_quiet(&pool, None).await, QUIET);

    // Saved N minutes is read immediately on the next call.
    save_release_settings(&pool, r#"{"quiet_minutes":12}"#).await;
    assert_eq!(effective_quiet(&pool, None).await, Duration::from_mins(12));

    // Changing the saved value takes effect on the next call without a restart.
    save_release_settings(&pool, r#"{"quiet_minutes":2}"#).await;
    assert_eq!(effective_quiet(&pool, None).await, Duration::from_mins(2));

    // Out-of-range and malformed values fall back to the 5-minute default.
    for raw in [
        r#"{"quiet_minutes":0}"#,
        r#"{"quiet_minutes":-5}"#,
        r#"{"quiet_minutes":1441}"#,
        r#"{"quiet_minutes":"ten"}"#,
    ] {
        save_release_settings(&pool, raw).await;
        assert_eq!(
            effective_quiet(&pool, None).await,
            QUIET,
            "out-of-range {raw} must fall back to default"
        );
    }

    // The test/staging timing override still takes precedence over a saved quiet window.
    save_release_settings(&pool, r#"{"quiet_minutes":60}"#).await;
    assert_eq!(
        effective_quiet(&pool, Some(Duration::from_secs(7))).await,
        Duration::from_secs(7)
    );
}

/// J1145 (#211): a saved quiet window of N minutes delays automatic apply until N minutes
/// pass without terminal activity, rather than applying at the 5-minute default.
#[tokio::test(start_paused = true)]
async fn saved_quiet_window_delays_apply_until_n_minutes_without_activity() {
    let data = staged_data_dir();
    let saved = Arc::new(Mutex::new(Duration::from_mins(12)));
    let last_activity = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let (tx, mut rx) = mpsc::channel(4);
    let task = {
        let (data, saved, last_activity) =
            (data.clone(), Arc::clone(&saved), Arc::clone(&last_activity));
        tokio::spawn(async move {
            quiet_window_with(
                &data,
                move || {
                    let quiet = *saved.lock().unwrap();
                    async move { quiet }
                },
                move || last_activity.lock().unwrap().elapsed(),
                |window| {
                    let tx = tx.clone();
                    async move {
                        let _ = tx.send(window).await;
                        Ok(())
                    }
                },
            )
            .await;
        })
    };

    // Past the old 5-minute default and still short of 12 minutes: must not apply.
    advance_and_settle(Duration::from_mins(5)).await;
    assert!(rx.try_recv().is_err(), "must not apply at 5-minute default");
    advance_and_settle(Duration::from_mins(6)).await;
    assert!(rx.try_recv().is_err(), "still under 12 minutes");

    // Activity at minute 11 resets the quiet window.
    *last_activity.lock().unwrap() = tokio::time::Instant::now();
    advance_and_settle(Duration::from_mins(11)).await;
    assert!(rx.try_recv().is_err(), "activity reset the 12-minute wait");

    // One more quiet minute completes the full 12-minute window.
    advance_and_settle(Duration::from_mins(1)).await;
    assert_eq!(rx.try_recv().ok(), Some(Duration::from_mins(12)));

    task.abort();
    let _ = std::fs::remove_dir_all(&data);
}

/// J1145 (#211): changing `quiet_minutes` takes effect on the next decision without a
/// restart, both when lengthening and when shortening an active wait.
#[tokio::test(start_paused = true)]
async fn changing_quiet_window_takes_effect_on_next_decision() {
    // Lengthening: 3 minutes raised to 10 minutes before apply delays until 10 minutes.
    let data = staged_data_dir();
    let saved = Arc::new(Mutex::new(Duration::from_mins(3)));
    let last_activity = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let (tx, mut rx) = mpsc::channel(4);
    let task = {
        let (data, saved, last_activity) =
            (data.clone(), Arc::clone(&saved), Arc::clone(&last_activity));
        tokio::spawn(async move {
            quiet_window_with(
                &data,
                move || {
                    let quiet = *saved.lock().unwrap();
                    async move { quiet }
                },
                move || last_activity.lock().unwrap().elapsed(),
                |window| {
                    let tx = tx.clone();
                    async move {
                        let _ = tx.send(window).await;
                        Ok(())
                    }
                },
            )
            .await;
        })
    };

    advance_and_settle(Duration::from_mins(2)).await;
    assert!(rx.try_recv().is_err());
    *saved.lock().unwrap() = Duration::from_mins(10);
    update::notify_changed();
    advance_and_settle(Duration::from_mins(2)).await;
    assert!(
        rx.try_recv().is_err(),
        "lengthened to 10 minutes; must not apply at 4 minutes"
    );
    advance_and_settle(Duration::from_mins(6)).await;
    assert_eq!(rx.try_recv().ok(), Some(Duration::from_mins(10)));
    task.abort();
    let _ = std::fs::remove_dir_all(&data);

    // Shortening: 30 minutes lowered to 2 minutes while sleeping applies once 2 minutes idle.
    let data = staged_data_dir();
    let saved = Arc::new(Mutex::new(Duration::from_mins(30)));
    let last_activity = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let (tx, mut rx) = mpsc::channel(4);
    let task = {
        let (data, saved, last_activity) =
            (data.clone(), Arc::clone(&saved), Arc::clone(&last_activity));
        tokio::spawn(async move {
            quiet_window_with(
                &data,
                move || {
                    let quiet = *saved.lock().unwrap();
                    async move { quiet }
                },
                move || last_activity.lock().unwrap().elapsed(),
                |window| {
                    let tx = tx.clone();
                    async move {
                        let _ = tx.send(window).await;
                        Ok(())
                    }
                },
            )
            .await;
        })
    };

    advance_and_settle(Duration::from_mins(2)).await;
    assert!(rx.try_recv().is_err());
    *saved.lock().unwrap() = Duration::from_mins(2);
    update::notify_changed();
    advance_and_settle(Duration::ZERO).await;
    assert_eq!(
        rx.try_recv().ok(),
        Some(Duration::from_mins(2)),
        "shortening wakes the wait and applies immediately"
    );
    task.abort();
    let _ = std::fs::remove_dir_all(&data);
}

/// J1145 (#211): when nothing is saved the 5-minute default applies in the quiet-window loop.
#[tokio::test(start_paused = true)]
async fn default_quiet_window_applies_at_five_minutes() {
    let data = staged_data_dir();
    let last_activity = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let (tx, mut rx) = mpsc::channel(4);
    let task = {
        let (data, last_activity) = (data.clone(), Arc::clone(&last_activity));
        tokio::spawn(async move {
            quiet_window_with(
                &data,
                || async { QUIET },
                move || last_activity.lock().unwrap().elapsed(),
                |window| {
                    let tx = tx.clone();
                    async move {
                        let _ = tx.send(window).await;
                        Ok(())
                    }
                },
            )
            .await;
        })
    };

    advance_and_settle(Duration::from_mins(4)).await;
    assert!(rx.try_recv().is_err(), "default is 5 minutes");
    advance_and_settle(Duration::from_mins(1)).await;
    assert_eq!(rx.try_recv().ok(), Some(QUIET));
    task.abort();
    let _ = std::fs::remove_dir_all(&data);
}
