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
            sessions_listed(&expected, Some(&folder), Some(inventory), &count).await
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
