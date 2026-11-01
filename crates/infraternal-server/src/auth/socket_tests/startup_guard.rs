//! A browser may change only its own startup hints and must confirm every file change [D315].
use super::*;

#[tokio::test]
async fn startup_guard_refuses_unowned_sessions_and_unconfirmed_edits() {
    let _serial = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES('startup-other','startup-other',0,'fixture')").execute(&f.auth.pool).await.unwrap();
    let own = uuid::Uuid::new_v4();
    let other = uuid::Uuid::new_v4();
    for (id, user) in [(own, f.user.as_str()), (other, "startup-other")] {
        sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen) VALUES(?,?,unixepoch(),unixepoch())").bind(id.as_bytes().as_slice()).bind(user).execute(&f.auth.pool).await.unwrap();
    }
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
            client_info: "startup-guard",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    let requests = [
        (false, json!({"op":"inspect","session":other})),
        (
            false,
            json!({"op":"apply","session":other,"proposal":{},"confirmed":true}),
        ),
        (
            false,
            json!({"op":"apply","session":own,"proposal":{},"confirmed":false}),
        ),
        (
            false,
            json!({"op":"undo","session":own,"proposal":{},"confirmed":false}),
        ),
        (false, json!({"op":"set","global":true,"enabled":null})),
        (false, json!({"op":"get","uid":0})),
        (false, json!({"op":"get","host_id":uuid::Uuid::new_v4()})),
        (true, json!({"op":"set","global":true,"enabled":false})),
        (true, json!({"op":"inspect","session":own})),
        (true, json!({"op":"get"})),
    ];
    for (index, (expected, request)) in requests.into_iter().enumerate() {
        let call_id = u32::try_from(index + 1).unwrap();
        let input = serde_json::to_vec(&request).unwrap();
        client_ws_send(
            &mut socket,
            0,
            &Frame::Call {
                call_id,
                action_id: "terminal.startup",
                input_json: &input,
            },
        )
        .await;
        loop {
            let wire = read_client_frame(&mut socket).await;
            if let Frame::Result {
                call_id: returned,
                ok,
                json,
            } = decode_muxed_frame(&wire).unwrap().frame
            {
                assert_eq!(returned, call_id);
                assert_eq!(ok, expected, "request {index}");
                if index == 9 {
                    let result: Value = serde_json::from_slice(json).unwrap();
                    assert_eq!(result["global_enabled"], false);
                }
                break;
            }
        }
    }
    assert_eq!(
        crate::terminal_startup::preferences(&f.auth.pool, "startup-other", "local")
            .await
            .unwrap(),
        (true, None)
    );
    server.abort();
}
