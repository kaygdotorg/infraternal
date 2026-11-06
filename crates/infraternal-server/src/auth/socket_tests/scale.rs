//! Reproduce an unsendable Mesh subscription at D170's ten-thousand-node headroom scale.
use super::*;

#[tokio::test(start_paused = true)]
async fn review_mesh_headroom_snapshot_does_not_close_shared_socket() {
    let _guard = SERIAL.lock().await;
    // Pagination correctness must not spend runtime authority while real
    // SQLite workers and the shared socket await a loaded host.
    let clock = FrozenSocketTime::new().await;
    // The auth unit fixture has one connection. A long inventory transaction
    // would monopolize it and park the independent authority watchdog. Use a
    // real disk-backed eight-connection pool, matching the deployed runtime.
    let root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || std::path::PathBuf::from("target"),
        std::path::PathBuf::from,
    );
    let path = root.join(format!("mesh-headroom-{}.sqlite", Uuid::new_v4()));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
        )
        .await
        .unwrap();
    let (auth, token) = empty_with_pool(pool).await;
    let f = fixture_with_bootstrap(auth, token).await;
    // Inventory correctness is independent of loaded-host authority-read latency.
    let (f, address, server) = socket_fixture_from_fixture(f, Some(Duration::from_secs(2))).await;
    clock.progress();
    // Retain the author's measured design-point ratios: three named grants per node.
    sqlx::query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<10000) INSERT INTO mesh_nodes(id,name,public_key,last_seen,last_rtt_us) SELECT i,printf('node-%05d',i),CAST(printf('%032d',i) AS BLOB),unixepoch(),1000 FROM n")
        .execute(&f.auth.pool).await.unwrap();
    clock.progress();
    sqlx::query("WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<30000) INSERT INTO mesh_grants(name,from_kind,from_value,to_kind,to_value,both_ways,ports_json) SELECT printf('grant-%05d',i),'node',CAST((i-1)%10000+1 AS TEXT),'node',CAST(i%10000+1 AS TEXT),0,'\"All\"' FROM n")
        .execute(&f.auth.pool).await.unwrap();
    clock.progress();
    let owner: String = sqlx::query_scalar("SELECT id FROM users WHERE owner=1")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    let service = crate::mesh_api::MeshService::new(f.auth.pool.clone());
    let snapshot = service
        .list(
            &owner,
            crate::mesh_api::MeshFilter::default(),
            1_800_000_000,
        )
        .await
        .unwrap();
    clock.progress();
    let event = serde_json::to_vec(&json!({"type":"snapshot","snapshot":snapshot})).unwrap();
    println!(
        "nodes=10000 grants=30000 snapshot_event_bytes={} frame_limit={} load={}",
        event.len(),
        infraternal_protocol::MAX_FRAME_LEN,
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
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
            client_info: "review-mesh",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 82,
            filter_json: br#"{"topic":"mesh"}"#,
        },
    )
    .await;
    let mut wire = read_client_frame(&mut socket).await;
    let Frame::Event {
        sub_id: 82,
        event_json: payload,
    } = decode_muxed_frame(&wire).unwrap().frame
    else {
        panic!(
            "missing bounded snapshot event: frame_type={} bytes={}",
            wire.get(5).copied().unwrap_or_default(),
            wire.len()
        )
    };
    let event: serde_json::Value = serde_json::from_slice(payload).unwrap();
    let mut page = event["snapshot"].clone();
    assert!(page.get("next_cursor").is_some());
    let mut nodes = Vec::new();
    let mut grants = Vec::new();
    let mut pages = 0;
    let mut max_frame = 0;
    let mut total_bytes = 0;
    let mut expirations = 0;
    loop {
        clock.progress();
        assert!(wire.len() <= 65_536);
        max_frame = max_frame.max(wire.len());
        total_bytes += wire.len();
        pages += 1;
        assert_eq!(page["revision"].as_u64(), Some(snapshot.revision));
        nodes.extend(
            page["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|node| node["node"]["id"].as_u64().unwrap()),
        );
        grants.extend(
            page["grants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|grant| grant["arrow"]["id"].as_u64().unwrap()),
        );
        let Some(cursor) = page.get("next_cursor") else {
            break;
        };
        let input = serde_json::to_vec(&json!({"cursor":cursor})).unwrap();
        client_ws_send(
            &mut socket,
            0,
            &Frame::Call {
                call_id: 83,
                action_id: "mesh.list",
                input_json: &input,
            },
        )
        .await;
        wire = read_scale_reply(&mut socket, &mut expirations).await;
        let Frame::Result {
            call_id: 83,
            ok: true,
            json: payload,
        } = decode_muxed_frame(&wire).unwrap().frame
        else {
            panic!("missing bounded list continuation")
        };
        page = serde_json::from_slice(payload).unwrap();
        assert!(pages < 128);
    }
    assert_eq!(nodes, (1..=10000).collect::<Vec<_>>());
    assert_eq!(grants, (1..=30000).collect::<Vec<_>>());
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 42,
            sent_us: 0,
        },
    )
    .await;
    let pong = read_scale_reply(&mut socket, &mut expirations).await;
    assert!(matches!(
        decode_muxed_frame(&pong).unwrap().frame,
        Frame::Pong { nonce: 42, .. }
    ));
    println!(
        "assembled_nodes={} assembled_grants={} pages={pages} max_frame_bytes={max_frame} total_frame_bytes={total_bytes} shared_socket_pong=true",
        nodes.len(),
        grants.len()
    );
    server.abort();
    let _ = server.await;
    f.auth.pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(file));
    }
}

/// Liveness can expire during a long manual pagination exchange. Validate that
/// asynchronous resync instead of confusing it with the outstanding Call result.
async fn read_scale_reply<S>(socket: &mut S, expirations: &mut usize) -> Bytes
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    loop {
        let wire = read_client_frame(socket).await;
        if let Frame::Event {
            sub_id: 82,
            event_json,
        } = decode_muxed_frame(&wire).unwrap().frame
        {
            assert!(wire.len() <= 65_536);
            let event: Value = serde_json::from_slice(event_json).unwrap();
            assert_eq!(event["type"], "resync");
            assert_eq!(event["snapshot"]["revision"], 0);
            assert!(
                event["snapshot"]["nodes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|node| node["live"] == false)
            );
            *expirations += 1;
            println!(
                "liveness_resyncs={expirations} expiry_frame_bytes={}",
                wire.len()
            );
        } else {
            return wire;
        }
    }
}
