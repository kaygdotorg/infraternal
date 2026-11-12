//! Independent shared-socket control progress check while a Mesh writer waits on SQLite [D11, D41, #108].
use super::*;

/// Control frames remain responsive while a real SQLite writer is held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_pending_mesh_write_keeps_control_dispatch_available() {
    let _guard = SERIAL.lock().await;
    // Live SQLite data must not contend with compiler artifacts on the build disk.
    let root = std::env::temp_dir();
    let path = root.join(format!("mesh-control-{}.sqlite", Uuid::new_v4()));
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
            client_info: "mesh-control-review",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    // The fixture first proves that control is usable on this same socket.
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 1,
            sent_us: 0,
        },
    )
    .await;
    let before = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&before).unwrap().frame,
        Frame::Pong { nonce: 1, .. }
    ));

    // WAL readers (including authority checks) remain available. Only Mesh's
    // writer is blocked, so the pending mutation must not park control dispatch.
    let mut writer = f.auth.pool.begin().await.unwrap();
    sqlx::query("UPDATE mesh_state SET revision=revision WHERE singleton=1")
        .execute(&mut *writer)
        .await
        .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 11,
            sent_us: 0,
        },
    )
    .await;
    let under_lock = read_client_frame(&mut socket).await;
    assert!(
        matches!(
            decode_muxed_frame(&under_lock).unwrap().frame,
            Frame::Pong { nonce: 11, .. }
        ),
        "fixture control must progress while the writer lock is held"
    );
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 91,
            action_id: "mesh.tag.create",
            input_json: br#"{"name":"queued"}"#,
        },
    )
    .await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 2,
            sent_us: 0,
        },
    )
    .await;
    let started = Instant::now();
    let early = tokio::time::timeout(Duration::from_millis(250), socket.next()).await;
    let pong_while_pending = matches!(early, Ok(Some(Ok(Message::Binary(ref bytes))))
        if matches!(decode_muxed_frame(bytes).unwrap().frame, Frame::Pong { nonce: 2, .. }));
    let pending_ms = started.elapsed().as_millis();
    writer.rollback().await.unwrap();
    if !pong_while_pending {
        let result = read_client_frame(&mut socket).await;
        assert!(matches!(
            decode_muxed_frame(&result).unwrap().frame,
            Frame::Result {
                call_id: 91,
                ok: true,
                ..
            }
        ));
        let pong = read_client_frame(&mut socket).await;
        assert!(matches!(
            decode_muxed_frame(&pong).unwrap().frame,
            Frame::Pong { nonce: 2, .. }
        ));
    }
    if pong_while_pending {
        let result = read_client_frame(&mut socket).await;
        assert!(matches!(
            decode_muxed_frame(&result).unwrap().frame,
            Frame::Result {
                call_id: 91,
                ok: true,
                ..
            }
        ));
    }
    println!(
        "writer_wait_ms={pending_ms} pong_while_mesh_pending={pong_while_pending} wal_connections=8 load={}",
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    server.abort();
    let _ = server.await;
    f.auth.pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(file));
    }
    assert!(
        pong_while_pending,
        "pending Mesh write stops shared-socket control dispatch"
    );
}

/// Multiple waiting writers must leave SQLite slots for shared control authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_mesh_writers_preserve_authority_pool_capacity() {
    let _guard = SERIAL.lock().await;
    // Live SQLite data must not contend with compiler artifacts on the build disk.
    let root = std::env::temp_dir();
    let path = root.join(format!("mesh-control-{}.sqlite", Uuid::new_v4()));
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
    let cookie = format!("__Host-infraternal={}", f.session);
    let mut sockets = Vec::new();
    for _ in 0..8 {
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
                client_info: "mesh-pool-review",
            },
        )
        .await;
        read_welcome(&mut socket).await;
        sockets.push(socket);
    }
    let mut writer = f.auth.pool.begin().await.unwrap();
    sqlx::query("UPDATE mesh_state SET revision=revision WHERE singleton=1")
        .execute(&mut *writer)
        .await
        .unwrap();
    for (index, socket) in sockets.iter_mut().enumerate() {
        let input = serde_json::to_vec(&json!({"name":format!("queued-{index}")})).unwrap();
        client_ws_send(
            socket,
            0,
            &Frame::Call {
                call_id: 91,
                action_id: "mesh.tag.create",
                input_json: &input,
            },
        )
        .await;
    }
    // Allow the writers to reach SQLite; this is a contention fixture, not load generation.
    tokio::time::sleep(Duration::from_millis(100)).await;
    client_ws_send(
        &mut sockets[0],
        0,
        &Frame::Ping {
            nonce: 2,
            sent_us: 0,
        },
    )
    .await;
    let started = Instant::now();
    let early = tokio::time::timeout(Duration::from_millis(250), sockets[0].next()).await;
    let pong_while_pending = matches!(early, Ok(Some(Ok(Message::Binary(ref bytes))))
        if matches!(decode_muxed_frame(bytes).unwrap().frame, Frame::Pong { nonce: 2, .. }));
    writer.rollback().await.unwrap();
    println!(
        "mesh_sockets=8 pool_connections=8 control_ms={} pong_while_mesh_pending={pong_while_pending}",
        started.elapsed().as_millis()
    );
    assert!(
        pong_while_pending,
        "Mesh writers exhaust shared authority pool"
    );
    for socket in &mut sockets {
        let wire = read_client_frame(socket).await;
        assert!(matches!(
            decode_muxed_frame(&wire).unwrap().frame,
            Frame::Result {
                call_id: 91,
                ok: true,
                ..
            }
        ));
        socket.close(None).await.unwrap();
    }
    server.abort();
    let _ = server.await;
    f.auth.pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(file));
    }
}
