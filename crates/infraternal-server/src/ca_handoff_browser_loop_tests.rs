//! Verifies independent shipping-client probe replies, retained data and teardown [D265, #199].

use super::*;

#[tokio::test]
async fn probes_are_answered_without_assertion_reads_and_drop_closes_the_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (answered, proof) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Ping {
                nonce: 17,
                sent_us: 29,
            },
            &mut encoded,
        )
        .unwrap();
        socket
            .send(Message::Binary(Bytes::copy_from_slice(&encoded)))
            .await
            .unwrap();
        let Message::Binary(reply) = socket.next().await.unwrap().unwrap() else {
            panic!("missing binary probe response");
        };
        let decoded = decode_muxed_frame(&reply).unwrap();
        assert_eq!(decoded.stream_id, 0);
        assert!(matches!(
            decoded.frame,
            Frame::Pong {
                nonce: 17,
                sent_us: 29
            }
        ));
        socket
            .send(Message::Ping(Bytes::from_static(b"transport-probe")))
            .await
            .unwrap();
        assert!(
            matches!(socket.next().await.unwrap().unwrap(), Message::Pong(bytes) if bytes == b"transport-probe"[..])
        );
        encode_muxed_frame_into(3, &Frame::Ack { in_seq_acked: 42 }, &mut encoded).unwrap();
        socket
            .send(Message::Binary(Bytes::copy_from_slice(&encoded)))
            .await
            .unwrap();
        answered.send(()).unwrap();
        // Browser owns its pump: dropping it must release the actual socket even
        // though the server and caller never requested graceful WebSocket closure.
        loop {
            match socket.next().await {
                None | Some(Err(_) | Ok(Message::Close(_))) => break,
                Some(Ok(Message::Pong(_))) => {}
                _ => panic!("fixture drop left the browser socket active"),
            }
        }
    });
    let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
        .await
        .unwrap();
    let mut browser = Browser::new(socket);
    // The server proof arrives before the caller's first read. Pull-based Pong
    // handling deadlocks here, so timeout is a functional guard, not a budget.
    tokio::time::timeout(std::time::Duration::from_secs(5), proof)
        .await
        .unwrap()
        .unwrap();
    let bytes = browser.read().await;
    let decoded = decode_muxed_frame(&bytes).unwrap();
    assert_eq!(decoded.stream_id, 3);
    assert!(matches!(decoded.frame, Frame::Ack { in_seq_acked: 42 }));
    drop(browser);
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
}
