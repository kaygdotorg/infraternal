//! Reconcile persisted embedded terminal rows against each fresh shim census [13][50], #168.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn database() -> (SqlitePool, String) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    Auth::new(
        pool.clone(),
        "sessions.example.test",
        "https://sessions.example.test",
    )
    .await
    .unwrap();
    let user = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES (?,'sessions','sessions','Sessions',1,'unused-test-hash')")
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    (pool, user)
}

/// Supply a stable full census for tests that do not exercise publication races.
async fn reconcile_embedded_sessions(
    pool: &SqlitePool,
    ids: &[[u8; 16]],
) -> Result<(), sqlx::Error> {
    let (_, inventory) = watch::channel(SessionInventoryState::Available(Arc::from(ids)));
    reconcile_embedded_inventory(pool, &inventory).await
}

#[tokio::test]
async fn reconciliation_before_saved_exit_keeps_the_authoritative_exit_status() {
    let (pool, user) = database().await;
    let session = [169; 16];
    let token = "inventory-review-session-fixture";
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES(?,?,'fixture',unixepoch()+3600,unixepoch(),1)")
        .bind(crate::auth::hash(token))
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(session.as_slice())
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    reconcile_embedded_sessions(&pool, &[]).await.unwrap();
    let event = serde_json::to_vec(&json!({
        "type":"terminal.exited", "session_id":uuid::Uuid::from_bytes(session),
        "status":7, "final_seq":42, "retired":true,
    }))
    .unwrap();
    let recorded = crate::terminal_exit::record(&pool, &user, token, &session, 0, &event).await;
    let status: Option<i32> =
        sqlx::query_scalar("SELECT exit_status FROM terminal_sessions WHERE id=?")
            .bind(session.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        status,
        Some(7),
        "census closure refused the later saved exit: {recorded:?}"
    );
}

#[tokio::test]
async fn restart_reconciliation_keeps_live_rows_and_closes_missing_rows() {
    let (pool, user) = database().await;
    let live = [1; 16];
    let stale = [2; 16];
    let previously_closed = [3; 16];
    for (id, closed) in [
        (live, None),
        (stale, None),
        (previously_closed, Some(7_i64)),
    ] {
        sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,closed_at) VALUES (?,?,1,1,?)")
            .bind(id.as_slice())
            .bind(&user)
            .bind(closed)
            .execute(&pool)
            .await
            .unwrap();
    }

    reconcile_embedded_sessions(&pool, &[live]).await.unwrap();
    let live_closed: bool =
        sqlx::query_scalar("SELECT closed_at IS NOT NULL FROM terminal_sessions WHERE id=?")
            .bind(live.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    let stale_closed: bool =
        sqlx::query_scalar("SELECT closed_at IS NOT NULL FROM terminal_sessions WHERE id=?")
            .bind(stale.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    let original_close: Option<i64> =
        sqlx::query_scalar("SELECT closed_at FROM terminal_sessions WHERE id=?")
            .bind(previously_closed.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !live_closed,
        "a surviving shim remains attachable after restart"
    );
    assert!(
        stale_closed,
        "a row without a discovered shim is closed at startup"
    );
    assert_eq!(
        original_close,
        Some(7),
        "reconciliation preserves final state"
    );

    reconcile_embedded_sessions(&pool, &[]).await.unwrap();
    let live_closed_after_next_restart: bool =
        sqlx::query_scalar("SELECT closed_at IS NOT NULL FROM terminal_sessions WHERE id=?")
            .bind(live.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        live_closed_after_next_restart,
        "a formerly live row closes when the next census no longer contains its shim"
    );
}

#[tokio::test]
async fn pending_agent_inventory_hides_cached_rows_until_the_first_census() {
    let (pool, user) = database().await;
    let auth = Auth::new(
        pool.clone(),
        "sessions.example.test",
        "https://sessions.example.test",
    )
    .await
    .unwrap();
    let (agent_socket, _agent_peer) = tokio::net::UnixStream::pair().unwrap();
    let agent = EmbeddedAgent::from_test_socket(agent_socket);
    let state = WebSocketState::new(auth, pool, agent).await.unwrap();

    let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink_messages = messages.clone();
    let mut sink = futures_util::sink::unfold(sink_messages, |messages, message: Message| {
        messages.lock().unwrap().push(message);
        std::future::ready(Ok::<_, axum::Error>(messages))
    });
    let mut encode = Vec::new();
    send_terminal_sessions_snapshot(&state, &user, 7, &mut sink, &mut encode)
        .await
        .unwrap();

    let messages = messages.lock().unwrap();
    let Message::Binary(wire) = &messages[0] else {
        panic!("session availability must use the control event frame");
    };
    let decoded = decode_muxed_frame(wire).unwrap();
    assert_eq!(decoded.stream_id, CONTROL_STREAM);
    let Frame::Event { sub_id, event_json } = decoded.frame else {
        panic!("session availability must use an Event frame");
    };
    assert_eq!(sub_id, 7);
    let event: serde_json::Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(event["topic"], "terminal.sessions");
    assert_eq!(event["type"], "terminal.sessions.unavailable");
}

#[tokio::test]
async fn available_snapshot_reports_live_rows_and_bounded_saved_exit_statuses() {
    let (pool, user) = database().await;
    let auth = Auth::new(
        pool.clone(),
        "sessions.example.test",
        "https://sessions.example.test",
    )
    .await
    .unwrap();
    let live = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)")
        .bind(&live.as_bytes()[..])
        .bind(&user)
        .execute(&pool)
        .await
        .unwrap();
    let mut newest = uuid::Uuid::nil();
    for status in 0..130_i64 {
        let id = uuid::Uuid::new_v4();
        if status == 129 {
            newest = id;
        }
        sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,closed_at,exit_status) VALUES(?,?,1,1,?,?)")
            .bind(&id.as_bytes()[..])
            .bind(&user)
            .bind(status + 1)
            .bind(status)
            .execute(&pool)
            .await
            .unwrap();
    }
    // Every complete browser snapshot reads recent saved exits; the partial index bounds that scan to exited rows.
    let plan = sqlx::query("EXPLAIN QUERY PLAN SELECT id,exit_status FROM terminal_sessions WHERE user_id=? AND remote_host_id IS NULL AND closed_at IS NOT NULL AND exit_status IS NOT NULL ORDER BY closed_at DESC,id DESC LIMIT 128")
        .bind(&user)
        .fetch_all(&pool)
        .await
        .unwrap();
    let plan_details = plan
        .iter()
        .map(|row| row.get::<String, _>("detail"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        plan_details.contains("terminal_sessions_closed_exit_user"),
        "bounded exit lookup must use its partial index: {plan_details}"
    );
    assert!(
        !plan_details.contains("USE TEMP B-TREE"),
        "bounded exit lookup must not sort matching terminal history: {plan_details}"
    );

    let (agent_socket, mut agent_peer) = tokio::net::UnixStream::pair().unwrap();
    let agent = EmbeddedAgent::from_test_socket(agent_socket);
    let mut inventory = agent.session_inventory();
    let state = WebSocketState::new(auth, pool, agent).await.unwrap();
    let mut receive = BytesMut::with_capacity(4096);
    let mut scratch = [0; 4096];
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let read = agent_peer.read(&mut scratch).await.unwrap();
            assert_ne!(read, 0, "actor closed before greeting");
            receive.extend_from_slice(&scratch[..read]);
            if let Ok(decoded) = decode_muxed_frame(&receive)
                && matches!(decoded.frame, Frame::Hello { version: 1, .. })
            {
                break;
            }
        }
    })
    .await
    .unwrap();
    let mut greeting = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "session inventory fixture",
        },
        &mut greeting,
    )
    .unwrap();
    agent_peer.write_all(&greeting).await.unwrap();
    let census = serde_json::to_vec(&json!({
        "type": "terminal.sessions.snapshot",
        "session_ids": [live],
    }))
    .unwrap();
    let mut census_wire = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Event {
            sub_id: 0,
            event_json: &census,
        },
        &mut census_wire,
    )
    .unwrap();
    agent_peer.write_all(&census_wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), inventory.changed())
        .await
        .unwrap()
        .unwrap();

    let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink_messages = messages.clone();
    let mut sink = futures_util::sink::unfold(sink_messages, |messages, message: Message| {
        messages.lock().unwrap().push(message);
        std::future::ready(Ok::<_, axum::Error>(messages))
    });
    send_terminal_sessions_snapshot(&state, &user, 8, &mut sink, &mut Vec::new())
        .await
        .unwrap();

    let messages = messages.lock().unwrap();
    let Message::Binary(wire) = &messages[0] else {
        panic!("session inventory must use a control event frame");
    };
    let decoded = decode_muxed_frame(wire).unwrap();
    let Frame::Event { sub_id, event_json } = decoded.frame else {
        panic!("session inventory must use an Event frame");
    };
    let event: serde_json::Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(sub_id, 8);
    assert_eq!(event["session_ids"], json!([live.to_string()]));
    assert_eq!(event["ended_sessions"].as_array().unwrap().len(), 128);
    assert_eq!(
        event["ended_sessions"][0],
        json!({"session_id": newest.to_string(), "status": 129})
    );
}

#[tokio::test]
async fn census_waiting_for_database_does_not_close_a_newly_created_live_session() {
    let (pool, user) = database().await;
    let session = [168; 16];
    let mut writer = pool.acquire().await.unwrap();
    let reconcile_pool = pool.clone();
    let (published, inventory) = watch::channel(SessionInventoryState::Available(Arc::from([])));
    let (waiting, started) = tokio::sync::oneshot::channel();
    let reconciliation = tokio::spawn(async move {
        // The watch task already copied an empty census. Poll until it parks
        // behind another database operation, as can happen during an open.
        let future = reconcile_embedded_inventory(&reconcile_pool, &inventory);
        tokio::pin!(future);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(future.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        waiting.send(()).unwrap();
        future.await.unwrap();
    });
    started.await.unwrap();
    // On the ordered leg-B lane, this live census arrives before the open Result
    // can persist its row. An old copied census is still parked behind storage.
    published.send_replace(SessionInventoryState::Available(Arc::from([session])));
    sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,unixepoch(),unixepoch())")
        .bind(session.as_slice())
        .bind(&user)
        .execute(&mut *writer)
        .await
        .unwrap();
    drop(writer);
    reconciliation.await.unwrap();
    // The next full census includes the new shim. A delayed older census must
    // not leave it permanently closed after this authoritative update.
    reconcile_embedded_sessions(&pool, &[session])
        .await
        .unwrap();
    let closed: bool =
        sqlx::query_scalar("SELECT closed_at IS NOT NULL FROM terminal_sessions WHERE id=?")
            .bind(session.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !closed,
        "an earlier census closed a newly created live session"
    );
}

/// Measure the newly introduced reconciliation write path at the D170 server design point.
#[tokio::test]
#[ignore = "independent scale diagnostic; run in a weighted scope"]
async fn inventory_reconciliation_at_200_sessions_and_50_accounts() {
    let (pool, owner) = database().await;
    let mut users = vec![owner];
    for index in 1..50 {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES(?,?,?, ?,0,'unused-test-hash')")
            .bind(&id)
            .bind(format!("review-{index}"))
            .bind(format!("review-{index}"))
            .bind(format!("Review {index}"))
            .execute(&pool)
            .await
            .unwrap();
        users.push(id);
    }
    let mut live = Vec::new();
    for index in 0..200 {
        let id = *uuid::Uuid::new_v4().as_bytes();
        sqlx::query(
            "INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,1,1)",
        )
        .bind(id.as_slice())
        .bind(&users[index % users.len()])
        .execute(&pool)
        .await
        .unwrap();
        live.push(id);
    }
    let mut samples = Vec::new();
    for _ in 0..100 {
        let started = std::time::Instant::now();
        reconcile_embedded_sessions(&pool, &live).await.unwrap();
        samples.push(started.elapsed().as_micros());
    }
    samples.sort_unstable();
    let started = std::time::Instant::now();
    reconcile_embedded_sessions(&pool, &[]).await.unwrap();
    let close_us = started.elapsed().as_micros();
    let closed: i64 =
        sqlx::query_scalar("SELECT count(*) FROM terminal_sessions WHERE closed_at IS NOT NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(closed, 200);
    println!(
        "inventory_reconciliation: sessions=200 accounts=50 sqlite=memory n=100 p50_us={} p99_us={} close_200_us={close_us} arch={} cores={} load={}",
        samples[50],
        samples[98],
        std::env::consts::ARCH,
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
    );
}
