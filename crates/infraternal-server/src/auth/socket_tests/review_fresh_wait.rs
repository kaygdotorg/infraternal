//! Verify destructive Mesh authority at the write boundary after a real WAL writer wait [D28, #108].
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // Keep the real writer wait and post-expiry state evidence together.
async fn review_mesh_delete_refused_when_freshness_expires_during_writer_wait() {
    let _guard = SERIAL.lock().await;
    let root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || std::path::PathBuf::from("target"),
        std::path::PathBuf::from,
    );
    let path = root.join(format!("mesh-fresh-wait-{}.sqlite", Uuid::new_v4()));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    let (auth, token) = empty_with_pool(pool).await;
    let f = fixture_with_bootstrap(auth, token).await;
    let (f, address, server) = socket_fixture_from_fixture(f, Some(Duration::from_secs(2))).await;
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key) VALUES (1,'protected-host',?)")
        .bind([1_u8; 32].as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();
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
            client_info: "mesh-fresh-wait-review",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    let now = crate::websocket::now_seconds().unwrap();
    // Two seconds before the browser's admin window (D333) closes.
    let age = infraternal_plugin_api::ADMIN_WINDOW_SECONDS - 2;
    sqlx::query("UPDATE sessions SET fresh=?,expires=?")
        .bind(now - age)
        .bind(now + 30 * 86400)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert!(f.auth.fresh_session(&f.session, now).await.is_ok());
    let mut writer = f.auth.pool.begin().await.unwrap();
    sqlx::query("UPDATE mesh_state SET revision=revision WHERE singleton=1")
        .execute(&mut *writer)
        .await
        .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 901,
            action_id: "mesh.node.delete",
            input_json: br#"{"node_id":1}"#,
        },
    )
    .await;
    // Freshness expires while SQLite refuses all writers. Independent WAL
    // readers remain available, so the socket retains ordinary authority.
    while crate::websocket::now_seconds().unwrap() <= now + 2 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    writer.rollback().await.unwrap();
    let wire = read_client_frame(&mut socket).await;
    let Frame::Result {
        call_id: 901,
        ok,
        json,
    } = decode_muxed_frame(&wire).unwrap().frame
    else {
        panic!("missing destructive call result");
    };
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_nodes")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_audit")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    let completed = crate::websocket::now_seconds().unwrap();
    assert!(f.auth.fresh_session(&f.session, completed).await.is_err());
    println!(
        "fresh_age_at_admission_s={age} fresh_age_at_completion_s={} ok={ok} result={} remaining={remaining} revision={revision} audits={audits}",
        completed - (now - age),
        String::from_utf8_lossy(json)
    );
    server.abort();
    f.auth.pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    assert!(
        !ok,
        "fresh authority expired before the destructive edit committed"
    );
    assert_eq!(
        serde_json::from_slice::<Value>(json).unwrap()["error"],
        "confirm with your passkey again"
    );
    assert_eq!((remaining, revision, audits), (1, 0, 0));
}
