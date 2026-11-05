//! Independent review: a live host that becomes visible to a watch must still expire there [D164, #108].
use super::*;

#[tokio::test(start_paused = true)]
async fn claude_review_watch_expires_host_made_visible_by_membership_edit() {
    let _guard = SERIAL.lock().await;
    let clock = FrozenSocketTime::new().await;
    let (f, address, server) =
        socket_fixture_from_fixture(fixture().await, Some(Duration::from_secs(2))).await;
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,last_seen) VALUES (1,'late-host',?,unixepoch()-20)")
        .bind([1_u8; 32].as_slice()).execute(&f.auth.pool).await.unwrap();
    sqlx::query("INSERT INTO mesh_tags(name,created_at) VALUES ('edge',unixepoch())")
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
            client_info: "mesh-visible-liveness-review",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    // The watched tag is empty: the snapshot has no live host, so no expiry is armed.
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 903,
            filter_json: br#"{"topic":"mesh","tag":"edge"}"#,
        },
    )
    .await;
    let initial = tokio::time::timeout(Duration::from_secs(20), read_client_frame(&mut socket))
        .await
        .expect("initial snapshot");
    let Frame::Event { event_json, .. } = decode_muxed_frame(&initial).unwrap().frame else {
        panic!("missing initial snapshot");
    };
    let initial: Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(initial["type"], "snapshot", "initial event: {initial}");
    assert_eq!(initial["snapshot"]["nodes"].as_array().unwrap().len(), 0);
    // The host's last heartbeat leaves ~8 s of its live window; it sends no more.
    sqlx::query("UPDATE mesh_nodes SET last_seen=unixepoch()-22")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 904,
            action_id: "mesh.tag.member.add",
            input_json: br#"{"tag":"edge","node_id":1}"#,
        },
    )
    .await;
    let mut saw_result = false;
    let mut saw_changed = false;
    while !(saw_result && saw_changed) {
        let wire = tokio::time::timeout(Duration::from_secs(20), read_client_frame(&mut socket))
            .await
            .unwrap_or_else(|_| {
                panic!("membership edit: result={saw_result} changed={saw_changed}")
            });
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Result {
                call_id: 904, ok, ..
            } => {
                assert!(ok);
                saw_result = true;
            }
            Frame::Event {
                sub_id: 903,
                event_json,
            } => {
                let event: Value = serde_json::from_slice(event_json).unwrap();
                assert_eq!(event["type"], "changed");
                saw_changed = true;
            }
            other => panic!("unexpected frame {other:?}"),
        }
    }
    // The client reloads the filtered list on `changed`, as the contract says.
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 905,
            action_id: "mesh.list",
            input_json: br#"{"tag":"edge"}"#,
        },
    )
    .await;
    let wire = tokio::time::timeout(Duration::from_secs(20), read_client_frame(&mut socket))
        .await
        .expect("list reply");
    let Frame::Result {
        call_id: 905,
        ok: true,
        json,
    } = decode_muxed_frame(&wire).unwrap().frame
    else {
        panic!("missing list result");
    };
    let listed: Value = serde_json::from_slice(json).unwrap();
    assert_eq!(listed["nodes"][0]["live"], true);
    // The stored observation uses SQLite wall time, while Tokio controls all
    // pool, authority and expiry timers. Wait for exactly that observation's
    // first offline second, then drive the armed timer with the existing frozen
    // runtime clock. Real SQLite/network I/O cannot consume timeout authority.
    let offline_at: i64 = sqlx::query_scalar("SELECT last_seen+31 FROM mesh_nodes WHERE id=1")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    clock.reach_wall_deadline(offline_at).await;
    tokio::time::advance(Duration::from_secs(31)).await;
    // No membership edit or heartbeat wakes the watch after the live list.
    let expiry_event = tokio::time::timeout(Duration::from_secs(25), socket.next()).await;
    let still_live: bool =
        sqlx::query_scalar("SELECT last_seen >= unixepoch()-30 FROM mesh_nodes WHERE id=1")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    println!(
        "listed_live=true db_live_now={still_live} expiry_event_received={}",
        expiry_event.is_ok()
    );
    server.abort();
    assert!(!still_live, "fixture observation must have expired");
    let Ok(Some(Ok(Message::Binary(wire)))) = expiry_event else {
        panic!("watch never reported the newly visible host offline after its live window ended");
    };
    let Frame::Event { event_json, .. } = decode_muxed_frame(&wire).unwrap().frame else {
        panic!("expiry must publish a watch event");
    };
    let event: Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(event["type"], "resync", "expiry event: {event}");
    assert_eq!(event["snapshot"]["nodes"][0]["live"], false);
}
