//! Exercise discovered coordinator features on real SQLite and browser sockets [28,198,201].
use super::*;

pub(super) async fn exchange<S>(
    socket: &mut S,
    call_id: u32,
    action: &str,
    input: &[u8],
) -> (bool, Value)
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    client_ws_send(
        socket,
        0,
        &Frame::Call {
            call_id,
            action_id: action,
            input_json: input,
        },
    )
    .await;
    loop {
        let wire = read_client_frame(socket).await;
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Result {
                call_id: received,
                ok,
                json,
            } => {
                assert_eq!(received, call_id);
                return (ok, serde_json::from_slice(json).unwrap());
            }
            // An active subscription can publish between the request and its
            // response. Its independent sub_id does not identify this call.
            Frame::Event { .. } => {}
            _ => panic!("unexpected control reply"),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn mesh_plugin_discovery_disable_and_restart_preserve_control_socket() {
    let _guard = SERIAL.lock().await;
    // Functional discovery/lifecycle checks must not spend their authority-read
    // deadline while real SQLite and socket I/O await the shared build host.
    let _clock = FrozenSocketTime::new().await;
    let f = fixture().await;
    let (socket, _peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_secs(2));
    let runtime = state.plugins.clone();
    assert_eq!(
        runtime.active_workers("mesh"),
        0,
        "declarations start no work"
    );
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
            client_info: "plugin-lifecycle",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    let (ok, discovery) = exchange(&mut socket, 1, "plugins.list", b"{}").await;
    assert!(ok);
    let malformed: &[(&str, &[u8])] = &[
        ("plugins.list", br#"{"extra":true}"#),
        ("plugins.list", b"[]"),
        ("plugins.set_enabled", br#"["mesh",false]"#),
        (
            "plugins.set_enabled",
            br#"{"plugin":"mesh","enabled":false,"enabled":true}"#,
        ),
        (
            "plugins.set_enabled",
            br#"{"plugin":"mesh","enabled":"false"}"#,
        ),
        (
            "plugins.set_enabled",
            br#"{"plugin":"mesh","enabled":false,"extra":true}"#,
        ),
    ];
    for (call_id, &(action, input)) in (20..).zip(malformed) {
        let (ok, reply) = exchange(&mut socket, call_id, action, input).await;
        assert!(!ok);
        assert_eq!(reply["error"], "invalid input");
    }
    let oversized = vec![b' '; 2048];
    let (ok, reply) = exchange(&mut socket, 30, "plugins.list", &oversized).await;
    assert!(!ok);
    assert_eq!(reply["error"], "plugin unavailable");
    assert_eq!(runtime.active_workers("mesh"), 0);
    let descriptor = &discovery["plugins"]
        .as_array()
        .unwrap()
        .iter()
        .find(|plugin| plugin["descriptor"]["id"] == "mesh")
        .expect("compiled mesh feature is missing")["descriptor"];
    assert_eq!(descriptor["id"], "mesh");
    assert_eq!(descriptor["actions"].as_array().unwrap().len(), 19);
    assert_eq!(descriptor["roles"][0]["requires"], json!(["server"]));
    for action in descriptor["actions"].as_array().unwrap() {
        assert_ne!(action["summary"].as_str().unwrap(), "");
        assert_ne!(
            action["instructions"].as_array().unwrap().as_slice(),
            &[] as &[Value]
        );
        assert_ne!(action["input"].as_str().unwrap(), "");
    }
    assert_eq!(runtime.active_workers("mesh"), 0, "discovery is pure");
    assert_eq!(
        descriptor["settings"]["properties"]["enabled"]["default"],
        true
    );
    let (ok, invalid) = exchange(&mut socket, 9, "mesh.unknown", b"{}").await;
    assert!(!ok);
    assert_eq!(invalid["error"], "invalid input");
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,last_seen) VALUES(1,'live-host',zeroblob(32),unixepoch())").execute(&f.auth.pool).await.unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 77,
            filter_json: br#"{"topic":"mesh"}"#,
        },
    )
    .await;
    let initial = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&initial).unwrap().frame,
        Frame::Event { sub_id: 77, .. }
    ));
    assert_eq!(runtime.active_workers("mesh"), 1);
    sqlx::query("UPDATE sessions SET fresh=0")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let (ok, _) = exchange(
        &mut socket,
        2,
        "plugins.set_enabled",
        br#"{"plugin":"mesh","enabled":false}"#,
    )
    .await;
    assert!(!ok, "stale authority cannot change features");
    assert_eq!(runtime.active_workers("mesh"), 1);
    sqlx::query("UPDATE sessions SET fresh=unixepoch()")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 3,
            action_id: "plugins.set_enabled",
            input_json: br#"{"plugin":"mesh","enabled":false}"#,
        },
    )
    .await;
    let mut ended = false;
    let mut switched = false;
    for _ in 0..2 {
        let wire = read_client_frame(&mut socket).await;
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Result {
                call_id: 3,
                ok: true,
                ..
            } => switched = true,
            Frame::Event {
                sub_id: 77,
                event_json,
            } => {
                assert_eq!(
                    serde_json::from_slice::<Value>(event_json).unwrap()["error"],
                    "forbidden"
                );
                ended = true;
            }
            _ => panic!("unexpected disable reply"),
        }
    }
    assert!(ended && switched);
    assert_eq!(
        runtime.active_workers("mesh"),
        0,
        "disable joined every worker and its timer"
    );
    let (ok, _) = exchange(&mut socket, 4, "mesh.list", b"{}").await;
    assert!(!ok);
    assert_eq!(runtime.active_workers("mesh"), 0);
    let (ok, _) = exchange(
        &mut socket,
        5,
        "plugins.set_enabled",
        br#"{"plugin":"mesh","enabled":true}"#,
    )
    .await;
    assert!(ok);
    assert_eq!(
        runtime.active_workers("mesh"),
        0,
        "enable starts no idle work"
    );
    let (ok, _) = exchange(&mut socket, 6, "mesh.list", b"{}").await;
    assert!(ok);
    assert_eq!(runtime.active_workers("mesh"), 1);
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 123,
            sent_us: 0,
        },
    )
    .await;
    let pong = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&pong).unwrap().frame,
        Frame::Pong { nonce: 123, .. }
    ));
    runtime.set_enabled("mesh", false).await.unwrap();
    assert_eq!(runtime.active_workers("mesh"), 0);
    println!(
        "plugins=1 discovered_actions=19 workers_constructor=0 workers_watch=1 workers_disabled=0 workers_lazy_enable=0 same_socket_restart=true pong=true"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabling_mesh_joins_pending_writer_and_refuses_nonowner_switches() {
    let _guard = SERIAL.lock().await;
    let root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || std::path::PathBuf::from("target"),
        std::path::PathBuf::from,
    );
    let path = root.join(format!("mesh-plugin-pending-{}.sqlite", Uuid::new_v4()));
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
    let (agent_socket, _peer) = UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        EmbeddedAgent::from_test_socket(agent_socket),
    )
    .await
    .unwrap()
    .with_authority_read_timeout(Duration::from_secs(2));
    let runtime = state.plugins.clone();
    let app = crate::websocket::router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,last_seen) VALUES(1,'protected-host',zeroblob(32),unixepoch())").execute(&f.auth.pool).await.unwrap();
    sqlx::query("UPDATE sessions SET fresh=unixepoch()")
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
            client_info: "plugin-pending-writer",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    assert!(exchange(&mut socket, 1, "mesh.list", b"{}").await.0);
    sqlx::query("UPDATE users SET owner=0")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    assert!(
        !exchange(
            &mut socket,
            2,
            "plugins.set_enabled",
            br#"{"plugin":"mesh","enabled":false}"#
        )
        .await
        .0,
        "fresh nonowner cannot configure features"
    );
    sqlx::query("UPDATE users SET owner=1")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let mut writer = f.auth.pool.begin().await.unwrap();
    sqlx::query("UPDATE mesh_state SET revision=revision")
        .execute(&mut *writer)
        .await
        .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 3,
            action_id: "mesh.node.delete",
            input_json: br#"{"node_id":1}"#,
        },
    )
    .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), socket.next())
            .await
            .is_err(),
        "writer did not remain pending"
    );
    assert_eq!(runtime.active_workers("mesh"), 1);
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 4,
            action_id: "plugins.set_enabled",
            input_json: br#"{"plugin":"mesh","enabled":false}"#,
        },
    )
    .await;
    let mut switched = false;
    loop {
        let wire = tokio::time::timeout(Duration::from_secs(20), read_client_frame(&mut socket))
            .await
            .unwrap();
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Result {
                call_id: 3,
                ok: false,
                ..
            } => break,
            Frame::Result {
                call_id: 4,
                ok: true,
                ..
            } => switched = true,
            other => panic!("unexpected cancellation reply {other:?}"),
        }
    }
    assert_eq!(runtime.active_workers("mesh"), 0);
    // Releasing the writer after cancellation lets a durable switch commit;
    // the cancelled node edit must never run when that lock becomes available.
    writer.rollback().await.unwrap();
    if !switched {
        let wire = tokio::time::timeout(Duration::from_secs(20), read_client_frame(&mut socket))
            .await
            .unwrap();
        assert!(matches!(
            decode_muxed_frame(&wire).unwrap().frame,
            Frame::Result {
                call_id: 4,
                ok: true,
                ..
            }
        ));
    }
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 555,
            sent_us: 0,
        },
    )
    .await;
    let wire = read_client_frame(&mut socket).await;
    assert!(
        matches!(
            decode_muxed_frame(&wire).unwrap().frame,
            Frame::Pong { nonce: 555, .. }
        ),
        "disabled generation leaked a delayed result"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_nodes")
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
    assert_eq!((count, revision, audits), (1, 0, 0));
    println!(
        "writer_pending_before_disable=true workers_after_disable=0 remaining={count} revision={revision} audits={audits} cancelled_result=true stale_success=false pong=true fresh_nonowner_refused=true"
    );
    server.abort();
    f.auth.pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

fn dispatch_hosted(hub: &mut crate::plugins::SocketPlugins, frame: &Frame<'_>) {
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(0, frame, &mut wire).unwrap();
    assert!(matches!(
        hub.dispatch(&bytes::Bytes::from(wire), &mut Vec::new()),
        crate::plugins::Dispatch::Queued
    ));
}
async fn next_hosted(hub: &mut crate::plugins::SocketPlugins) -> bytes::Bytes {
    loop {
        let reply = tokio::time::timeout(Duration::from_secs(2), hub.recv())
            .await
            .unwrap()
            .unwrap();
        if let Some(wire) = hub.accept(reply, &mut Vec::new()) {
            return wire;
        }
    }
}
#[tokio::test]
async fn mesh_lifecycle_withdrawals_survive_calls_but_never_end_a_replacement() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let owner: String = sqlx::query_scalar("SELECT id FROM users WHERE owner=1")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    let state = std::sync::Arc::new(
        crate::websocket::WebSocketState::new(
            f.auth.clone(),
            f.auth.pool.clone(),
            EmbeddedAgent::from_test_socket(socket),
        )
        .await
        .unwrap()
        .with_authority_read_timeout(Duration::from_secs(2)),
    );
    let runtime = state.plugins.clone();
    let mut hub = state.plugin_socket(&owner, &f.session);
    let subscription = Frame::Subscribe {
        sub_id: 77,
        filter_json: br#"{"topic":"mesh"}"#,
    };
    dispatch_hosted(&mut hub, &subscription);
    next_hosted(&mut hub).await;
    runtime.set_enabled("mesh", false).await.unwrap();
    runtime.set_enabled("mesh", true).await.unwrap();
    // An unrelated call lazily recreates the worker before the host sees the
    // switch notification. It must still end the old browser view.
    dispatch_hosted(
        &mut hub,
        &Frame::Call {
            call_id: 8,
            action_id: "mesh.list",
            input_json: b"{}",
        },
    );
    let ended = next_hosted(&mut hub).await;
    let Frame::Event {
        sub_id: 77,
        event_json,
    } = decode_muxed_frame(&ended).unwrap().frame
    else {
        panic!("old view did not end");
    };
    assert_eq!(
        serde_json::from_slice::<Value>(event_json).unwrap()["error"],
        "forbidden"
    );
    let result = next_hosted(&mut hub).await;
    assert!(matches!(
        decode_muxed_frame(&result).unwrap().frame,
        Frame::Result {
            call_id: 8,
            ok: true,
            ..
        }
    ));
    dispatch_hosted(&mut hub, &subscription);
    next_hosted(&mut hub).await;
    runtime.set_enabled("mesh", false).await.unwrap();
    runtime.set_enabled("mesh", true).await.unwrap();
    let old_end = hub.recv().await.unwrap();
    dispatch_hosted(&mut hub, &subscription);
    assert!(
        hub.accept(old_end, &mut Vec::new()).is_none(),
        "old lifecycle event ended the replacement"
    );
    let replacement = next_hosted(&mut hub).await;
    let Frame::Event {
        sub_id: 77,
        event_json,
    } = decode_muxed_frame(&replacement).unwrap().frame
    else {
        panic!("replacement snapshot missing");
    };
    assert_eq!(
        serde_json::from_slice::<Value>(event_json).unwrap()["type"],
        "snapshot"
    );
    // Runtime retains join ownership when the socket disappears first.
    drop(hub);
    runtime.set_enabled("mesh", false).await.unwrap();
    assert_eq!(runtime.active_workers("mesh"), 0);
    println!(
        "old_view_ended_after_call_restart=true stale_end_dropped_on_replacement=true replacement_snapshot=true workers_after_disconnect_disable=0"
    );
}

#[tokio::test]
async fn mesh_coordinator_requires_an_existing_server_role() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let plugin: std::sync::Arc<dyn infraternal_plugin_api::Plugin> = std::sync::Arc::new(
        infraternal_plugin_mesh::MeshPlugin::new(f.auth.pool.clone()),
    );
    let runtime = crate::plugins::PluginRuntime::new(vec![plugin], "node");
    assert_eq!(runtime.list()["plugins"][0]["enabled"], false);
    assert_eq!(
        runtime.set_enabled("mesh", true).await,
        Err(crate::plugins::PluginError::RoleUnavailable)
    );
    assert_eq!(runtime.active_workers("mesh"), 0);
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(
        users, 1,
        "feature construction must not initialize another server"
    );
}
#[test]
fn mesh_destructive_metadata_matches_frozen_confirmation_requirements() {
    let mut destructive: Vec<_> = infraternal_plugin_mesh::descriptor::ACTIONS
        .iter()
        .filter(|action| action.effect == infraternal_plugin_api::Effect::Destructive)
        .map(|action| action.id)
        .collect();
    destructive.sort_unstable();
    assert_eq!(
        destructive,
        vec![
            "mesh.default.set",
            "mesh.grant.delete",
            "mesh.grant.move",
            "mesh.node.delete",
            "mesh.role.assign",
            "mesh.role.define",
            "mesh.tag.delete",
            "mesh.tag.member.remove"
        ]
    );
    let Some(infraternal_plugin_api::Permission::Any(permissions)) =
        infraternal_plugin_mesh::descriptor::ACTIONS
            .iter()
            .find(|action| action.id == "mesh.list")
            .map(|action| &action.permission)
    else {
        panic!("list visibility must follow any management role");
    };
    assert_eq!(
        *permissions,
        [
            "mesh.manage_nodes",
            "mesh.manage_tags",
            "mesh.manage_grants",
            "mesh.manage_roles"
        ]
    );
}

/// Subscription snapshots may precede the result of a call on the shared control stream.
#[tokio::test]
async fn plugin_exchange_correlates_results_after_subscription_events() {
    use tokio_tungstenite::{WebSocketStream, tungstenite::protocol::Role};
    let (client, peer) = tokio::io::duplex(4096);
    let mut client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
    let mut peer = WebSocketStream::from_raw_socket(peer, Role::Server, None).await;
    let sender = tokio::spawn(async move {
        let call = read_client_frame(&mut peer).await;
        assert!(matches!(
            decode_muxed_frame(&call).unwrap().frame,
            Frame::Call {
                call_id: 1,
                action_id: "plugins.list",
                ..
            }
        ));
        client_ws_send(
            &mut peer,
            0,
            &Frame::Event {
                sub_id: 77,
                event_json: br#"{"nodes":[]}"#,
            },
        )
        .await;
        client_ws_send(
            &mut peer,
            0,
            &Frame::Result {
                call_id: 1,
                ok: true,
                json: br#"{"plugins":[]}"#,
            },
        )
        .await;
    });
    assert_eq!(
        exchange(&mut client, 1, "plugins.list", b"{}").await,
        (true, json!({"plugins": []}))
    );
    sender.await.unwrap();
}
