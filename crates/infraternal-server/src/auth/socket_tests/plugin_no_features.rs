//! Verify generic discovery and control on the real socket when no Mesh code is compiled [198].
use super::*;

#[tokio::test]
async fn feature_free_socket_discovers_no_plugins_and_keeps_pong() {
    let _guard = SERIAL.lock().await;
    let (f, address, server) = socket_fixture().await;
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
            client_info: "feature-free",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 1,
            action_id: "plugins.list",
            input_json: b"{}",
        },
    )
    .await;
    let wire = read_client_frame(&mut socket).await;
    let Frame::Result {
        call_id: 1,
        ok: true,
        json,
    } = decode_muxed_frame(&wire).unwrap().frame
    else {
        panic!("generic discovery was not available");
    };
    let inventory: Value = serde_json::from_slice(json).unwrap();
    assert_eq!(inventory["plugins"], json!([]));
    assert_eq!(inventory["actions"].as_array().unwrap().len(), 2);
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 6,
            sent_us: 0,
        },
    )
    .await;
    let wire = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&wire).unwrap().frame,
        Frame::Pong { nonce: 6, .. }
    ));
    println!("feature_free_plugin_inventory plugins=0 shared_socket_pong=true");
    server.abort();
}
