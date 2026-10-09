//! Verify a watched host becomes offline when its observation expires without another edit [D164, #108].
use super::*;

#[tokio::test]
async fn review_mesh_watch_reports_liveness_expiry_without_another_edit() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) =
        socket_fixture_from_fixture(fixture().await, Some(Duration::from_secs(2))).await;
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,last_seen) VALUES (1,'observed-host',?,unixepoch()-20)")
        .bind([1_u8; 32].as_slice()).execute(&f.auth.pool).await.unwrap();
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
            client_info: "mesh-liveness-review",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    // Start the live window after the handshake so host scheduling does not
    // consume the observation before the initial subscription is admitted.
    sqlx::query("UPDATE mesh_nodes SET last_seen=unixepoch()-20")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 902,
            filter_json: br#"{"topic":"mesh"}"#,
        },
    )
    .await;
    let initial = read_client_frame(&mut socket).await;
    let Frame::Event {
        sub_id: 902,
        event_json,
    } = decode_muxed_frame(&initial).unwrap().frame
    else {
        panic!("missing initial snapshot");
    };
    let initial: Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(initial["snapshot"]["nodes"][0]["live"], true);
    let expiry_event = tokio::time::timeout(Duration::from_secs(12), socket.next()).await;
    let owner: String = sqlx::query_scalar("SELECT id FROM users WHERE owner=1")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    let current = crate::mesh_api::MeshService::new(f.auth.pool.clone())
        .list(
            &owner,
            crate::mesh_api::MeshFilter::default(),
            crate::websocket::now_seconds().unwrap(),
        )
        .await
        .unwrap();
    assert!(
        !current.nodes[0].live,
        "the fixture observation must have expired"
    );
    println!(
        "initial_live=true current_live=false revision={} expiry_event_received={}",
        current.revision,
        expiry_event.is_ok()
    );
    server.abort();
    assert!(
        expiry_event.is_ok(),
        "watched liveness remained online after observation expiry without another edit"
    );
}
