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
    assert_eq!(healthy(&pool, address, false).await, Ok(()));
    assert_eq!(
        healthy(&pool, address, true).await,
        Err("the new release did not receive the unlocked CA")
    );
    // Unlocked later (a passkey after a cold start) counts the same as a handoff.
    unlocked.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(healthy(&pool, address, true).await, Ok(()));
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
        healthy(&pool, address, false).await,
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
