//! Exercises canvas discovery, canonical events and runtime withdrawal on the real authenticated WebSocket [16,183,198,202,248].
use super::*;

#[tokio::test(start_paused = true)]
#[allow(clippy::too_many_lines)]
async fn canvas_real_socket_commits_and_runtime_disable_preserve_control() {
    assert!(
        crate::compiled_plugins()
            .iter()
            .any(|descriptor| descriptor.id == "canvas"),
        "canvas is missing from the compiled action catalog"
    );
    let _guard = SERIAL.lock().await;
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (pipe, _peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(pipe),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_secs(2));
    let runtime = state.plugins.clone();
    assert_eq!(runtime.active_workers("canvas"), 0);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, crate::websocket::router(state)).into_future());
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
            client_info: "canvas-test",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    // Refuse before admission, including absent labels and a different authenticated lifetime.
    for label in [
        None,
        Some(crate::auth::session_incarnation(
            "replacement-fixture-session",
        )),
    ] {
        let mut input = json!({"op_id":"refused", "document":{"format":"infraternal.canvas","version":1,"revision":0,"views":[]}});
        if let Some(label) = label {
            input["session_incarnation"] = label.into();
        }
        let (ok, result) = plugin_lifecycle::exchange(
            &mut socket,
            100,
            "canvas.layout.initialize",
            &serde_json::to_vec(&input).unwrap(),
        )
        .await;
        assert!(!ok);
        assert_eq!(result["reason"], "layout_session_changed");
    }
    let input=serde_json::to_vec(&json!({"session_incarnation": crate::auth::session_incarnation(&f.session),"op_id":"init","document":{"format":"infraternal.canvas","version":1,"revision":0,"views":[]}})).unwrap();
    let (ok, result) =
        plugin_lifecycle::exchange(&mut socket, 1, "canvas.layout.initialize", &input).await;
    assert!(ok);
    assert_eq!(result["revision"], 1);
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 9,
            filter_json: br#"{"topic":"canvas.layout"}"#,
        },
    )
    .await;
    let wire = read_client_frame(&mut socket).await;
    let Frame::Event {
        sub_id: 9,
        event_json,
    } = decode_muxed_frame(&wire).unwrap().frame
    else {
        panic!("canvas snapshot missing")
    };
    let event: Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(event["revision"], 1);
    assert_eq!(event["initialized"], true);
    let intent = json!({"type":"view.add","view":{"id":"console","kind":"console","name":"Console","cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":[]}}});
    let apply =
        serde_json::to_vec(&json!({"session_incarnation": crate::auth::session_incarnation(&f.session),"op_id":"view","base_revision":0,"intent":intent})).unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 2,
            action_id: "canvas.layout.apply",
            input_json: &apply,
        },
    )
    .await;
    let mut result_seen = false;
    let mut event_seen = false;
    while !result_seen || !event_seen {
        let wire = read_client_frame(&mut socket).await;
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Result {
                call_id: 2,
                ok: true,
                json,
            } => {
                let result: Value = serde_json::from_slice(json).unwrap();
                assert_eq!(result["revision"], 2);
                result_seen = true;
            }
            Frame::Event {
                sub_id: 9,
                event_json,
            } => {
                let event: Value = serde_json::from_slice(event_json).unwrap();
                assert_eq!(event["revision"], 2);
                assert_eq!(event["noop"], false);
                event_seen = true;
            }
            _ => panic!("unexpected canvas control frame"),
        }
    }
    let (ok,_)=plugin_lifecycle::exchange(&mut socket,3,"canvas.layout.apply",br#"{"op_id":"foreign","base_revision":2,"intent":{"type":"close","window_id":"w"},"account":"other"}"#).await;
    assert!(!ok);
    sqlx::query("UPDATE sessions SET fresh=unixepoch()")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (ok, _) = plugin_lifecycle::exchange(
        &mut socket,
        4,
        "plugins.set_enabled",
        br#"{"plugin":"canvas","enabled":false}"#,
    )
    .await;
    assert!(ok);
    assert_eq!(runtime.active_workers("canvas"), 0);
    let (ok, _) = plugin_lifecycle::exchange(&mut socket, 5, "canvas.layout.apply", &apply).await;
    assert!(!ok);
    let (ok, _) = plugin_lifecycle::exchange(
        &mut socket,
        6,
        "plugins.set_enabled",
        br#"{"plugin":"canvas","enabled":true}"#,
    )
    .await;
    assert!(ok);
    let (ok, result) =
        plugin_lifecycle::exchange(&mut socket, 7, "canvas.layout.apply", &apply).await;
    assert!(ok);
    assert_eq!(
        result["revision"], 2,
        "reenabling preserves durable retry receipts"
    );
    socket.close(None).await.unwrap();
    server.abort();
}
