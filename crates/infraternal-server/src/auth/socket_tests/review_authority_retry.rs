//! Break-it review of the bounded authority wait (#240). Each test states a
//! property the retry must keep and fails while it does not.
use super::*;
use sqlx::Connection;
use sqlx::sqlite::{SqliteConnection, SqliteJournalMode, SqliteSynchronous};

fn call(call_id: u32) -> Frame<'static> {
    Frame::Call {
        call_id,
        action_id: "test.not.an.action",
        input_json: b"{}",
    }
}

type Browser =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn welcome(address: SocketAddr, f: &Fixture, label: &str) -> Browser {
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
            client_info: label,
        },
    )
    .await;
    read_welcome(&mut socket).await;
    socket
}

async fn next_reply(socket: &mut Browser) -> Option<u32> {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), socket.next()).await {
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                if let Frame::Result { call_id, .. } = decode_muxed_frame(&bytes).unwrap().frame {
                    return Some(call_id);
                }
            }
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            _ => return None,
        }
    }
}

fn wall() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
}

/// A session that expires while its frame waits on a busy store is dead. The
/// retried read must not find it live against the frame's old clock, renew it
/// for a full session and then run the frame after the session's end.
#[tokio::test]
async fn session_expiring_during_the_wait_is_not_revived_or_served() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) =
        socket_fixture_from_fixture(fixture().await, Some(Duration::from_millis(25))).await;
    let mut socket = welcome(address, &f, "expiry during wait").await;
    // Start 0.2-0.3 s into a wall second, so the session's last second ends
    // well inside the one-second wait.
    while !(200..300).contains(&wall().subsec_millis()) {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let ends = i64::try_from(wall().as_secs()).unwrap() + 1;
    sqlx::query("UPDATE sessions SET expires=? WHERE user_id=?")
        .bind(ends)
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let held = f.auth.pool.acquire().await.unwrap();
    client_ws_send(&mut socket, 0, &call(1)).await;
    // Release the store 100 ms after the session ended, under 1 s after the frame.
    let end = Duration::from_secs(u64::try_from(ends).unwrap()) + Duration::from_millis(100);
    tokio::time::sleep(end.saturating_sub(wall())).await;
    assert!(wall().as_secs() >= u64::try_from(ends).unwrap());
    drop(held);
    let reply = next_reply(&mut socket).await;
    let expires: i64 = sqlx::query_scalar("SELECT expires FROM sessions WHERE user_id=?")
        .bind(&f.user)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    server.abort();
    assert!(
        expires <= ends,
        "an expired session was renewed by a retried read: expires {expires}, ended {ends}"
    );
    assert_eq!(reply, None, "a frame ran after its session expired");
}

/// Production pool shape: a file database in WAL mode, eight connections, a
/// 5 s busy timeout. Another writer holds SQLite's write lock (a checkpoint, a
/// long transaction). WAL readers are not blocked by it, so the rest of the
/// server must keep its pool. One renewing socket must not use it all up by
/// abandoning a blocked UPDATE on a fresh connection every retry.
#[tokio::test]
async fn renewing_retries_do_not_drain_the_pool_during_a_write_stall() {
    let _guard = SERIAL.lock().await;
    let dir = std::env::temp_dir().join(format!("infraternal-review240-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let options = SqliteConnectOptions::new()
        .filename(dir.join("infraternal.sqlite"))
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(options.clone())
        .await
        .unwrap();
    let (auth, token) = empty_with_pool(pool).await;
    let f = fixture_with_bootstrap(auth, token).await;
    let (f, address, server) =
        socket_fixture_from_fixture(f, Some(Duration::from_millis(25))).await;
    let mut socket = welcome(address, &f, "write stall").await;
    // Due for its once-a-minute renewal: the next frame's read is an UPDATE.
    sqlx::query("UPDATE sessions SET expires=unixepoch()+600 WHERE user_id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let mut writer = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut writer)
        .await
        .unwrap();
    client_ws_send(&mut socket, 0, &call(1)).await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let started = tokio::time::Instant::now();
    let read = tokio::time::timeout(
        Duration::from_millis(250),
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sessions").fetch_one(&f.auth.pool),
    )
    .await;
    let (size, idle) = (f.auth.pool.size(), f.auth.pool.num_idle());
    sqlx::query("ROLLBACK").execute(&mut writer).await.unwrap();
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        read.is_ok(),
        "one renewing socket drained the pool during a write stall: a WAL read waited {:?} \
         (pool size {size}, idle {idle})",
        started.elapsed()
    );
}
