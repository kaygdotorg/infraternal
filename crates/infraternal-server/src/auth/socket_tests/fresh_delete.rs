//! Reproduce destructive Mesh deletion through an unlocked browser session without a fresh passkey tap [D28].
use super::*;

#[tokio::test]
async fn review_mesh_delete_requires_fresh_passkey_tap() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    sqlx::query("UPDATE sessions SET fresh=0")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO mesh_nodes(id,name,public_key) VALUES (1,'protected-host',?)")
        .bind([1_u8; 32].as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    assert!(f.auth.fresh_session(&f.session, now).await.is_err());
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
        &Frame::Call {
            call_id: 81,
            action_id: "mesh.node.delete",
            input_json: br#"{"node_id":1}"#,
        },
    )
    .await;
    let wire = read_client_frame(&mut socket).await;
    let Frame::Result {
        call_id: 81,
        ok,
        json,
    } = decode_muxed_frame(&wire).unwrap().frame
    else {
        panic!("missing delete result")
    };
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_nodes")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    println!(
        "fresh_session=denied; mesh.node.delete ok={ok}, result={}; remaining_nodes={remaining}",
        String::from_utf8_lossy(json)
    );
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_audit")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!((revision, audits), (0, 0));
    for (action, input) in [
        ("mesh.tag.delete", json!({"name":"prod"})),
        ("mesh.tag.member.remove", json!({"tag":"prod","node_id":1})),
        (
            "mesh.grant.move",
            json!({"name":"web","side":"to","endpoint":{"Node":1}}),
        ),
        ("mesh.grant.delete", json!({"name":"web"})),
        (
            "mesh.role.define",
            json!({"name":"editor","actions":["mesh.manage_nodes"]}),
        ),
        (
            "mesh.role.assign",
            json!({"user_id":"member","role":"editor"}),
        ),
    ] {
        let input = serde_json::to_vec(&input).unwrap();
        client_ws_send(
            &mut socket,
            0,
            &Frame::Call {
                call_id: 82,
                action_id: action,
                input_json: &input,
            },
        )
        .await;
        let wire = read_client_frame(&mut socket).await;
        let Frame::Result {
            ok: false, json, ..
        } = decode_muxed_frame(&wire).unwrap().frame
        else {
            panic!("fresh confirmation must be required")
        };
        assert_eq!(json, br#"{"error":"confirm with your passkey again"}"#);
    }
    // A refusal leaves the shared socket usable; a new passkey timestamp permits the edit.
    sqlx::query("UPDATE sessions SET fresh=unixepoch()")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 83,
            action_id: "mesh.node.delete",
            input_json: br#"{"node_id":1}"#,
        },
    )
    .await;
    let wire = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&wire).unwrap().frame,
        Frame::Result {
            call_id: 83,
            ok: true,
            ..
        }
    ));
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_nodes")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(after, 0);
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 84,
            sent_us: 0,
        },
    )
    .await;
    let wire = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&wire).unwrap().frame,
        Frame::Pong { nonce: 84, .. }
    ));
    server.abort();
    assert!(
        !ok && remaining == 1,
        "D28 requires fresh passkey authority before deleting an enrolled host"
    );
}
