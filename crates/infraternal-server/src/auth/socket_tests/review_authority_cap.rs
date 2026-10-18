//! Break-it delta review of the server-wide authority cap (#240, round 2).
//! `read_expiry` documents that each attempt holds one of `AUTHORITY_READS`
//! places, "so however many sockets retry at once they hold at most that many
//! connections". The place is a semaphore permit inside the attempt future.
//! When an attempt misses its deadline the future is dropped and the permit
//! returns at once, but a statement already running keeps its pooled
//! connection until SQLite returns (the pool pings a dropped connection before
//! reuse, and that ping queues behind the running statement). So the cap
//! bounds attempts waiting for a connection, not connections in use.
use super::*;
use sqlx::Connection;
use sqlx::sqlite::{SqliteConnection, SqliteJournalMode};

fn call(call_id: u32) -> Frame<'static> {
    Frame::Call {
        call_id,
        action_id: "test.not.an.action",
        input_json: b"{}",
    }
}

/// A store where the SELECT itself waits: here a rollback-journal file whose
/// lock another connection holds. In production (WAL) the same happens when a
/// read is slow in SQLite rather than in the pool queue (slow I/O). One
/// socket alone retrying its read must stay within the four places the
/// rest of the server was promised it can never lose.
#[tokio::test]
async fn retries_whose_select_waits_stay_within_the_authority_cap() {
    let _guard = SERIAL.lock().await;
    let dir = std::env::temp_dir().join(format!(
        "infraternal-review240-r2-{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let options = SqliteConnectOptions::new()
        .filename(dir.join("infraternal.sqlite"))
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Delete)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .min_connections(8)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(options.clone())
        .await
        .unwrap();
    let (auth, token) = empty_with_pool(pool).await;
    let f = fixture_with_bootstrap(auth, token).await;
    let (f, address, server) =
        socket_fixture_from_fixture(f, Some(Duration::from_millis(25))).await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "select stall",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    // Let the pool settle at eight idle connections.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut locker = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&mut locker)
        .await
        .unwrap();
    client_ws_send(&mut socket, 0, &call(1)).await;
    // About eight attempts start in the first 600 ms (5 ms doubling pauses
    // plus the 25 ms attempt deadline); each SELECT waits on the busy timeout.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let (size, idle) = (f.auth.pool.size(), f.auth.pool.num_idle());
    sqlx::query("ROLLBACK").execute(&mut locker).await.unwrap();
    server.abort();
    let busy = size as usize - idle;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        busy <= 4,
        "one socket's abandoned authority reads hold {busy} of {size} pool connections; \
         the cap promises at most 4"
    );
}
