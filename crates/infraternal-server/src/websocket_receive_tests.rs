//! Buffered control traffic must leave a turn for route proofs in the same task [D265, #199].

use super::*;
use std::cell::Cell;

#[tokio::test]
async fn buffered_control_frames_cannot_monopolize_a_transport_turn() {
    let mut encoded = Vec::new();
    assert!(
        encode_muxed_frame_into(
            0,
            &Frame::Pong {
                nonce: 1,
                sent_us: 1,
            },
            &mut encoded,
        )
        .is_ok()
    );
    let mut buffered = BytesMut::new();
    for _ in 0..4096 {
        buffered.extend_from_slice(&encoded);
    }
    let mut source = futures_util::stream::pending::<Result<Message, axum::Error>>();
    let mut deadline = None;
    let received = Cell::new(0);
    let receive_all = async {
        for _ in 0..4096 {
            assert!(matches!(
                receive_wire(&mut source, &mut buffered, &mut deadline).await,
                Ok(Some(Inbound::Frame(_)))
            ));
            received.set(received.get() + 1);
        }
    };
    // Prefer the reader deliberately: readiness in a different future must
    // still get polled before a buffered burst has exhausted the whole turn.
    tokio::select! {
        biased;
        () = receive_all => panic!("buffered controls starved the independent proof future"),
        () = tokio::task::yield_now() => {},
    }
    assert!(received.get() < 4096);
}

#[tokio::test]
async fn browser_websocket_close_keeps_its_code_and_discards_unknown_reason_text() {
    let close = Message::Close(Some(axum::extract::ws::CloseFrame {
        code: 4001,
        reason: "private terminal contents".into(),
    }));
    let mut source = futures_util::stream::iter([Ok::<_, axum::Error>(close)]);
    let mut buffered = BytesMut::new();
    let mut deadline = None;
    assert!(matches!(
        receive_wire(&mut source, &mut buffered, &mut deadline).await,
        Ok(Some(Inbound::SocketClose {
            code: Some(4001),
            reason: Some("other"),
        }))
    ));
}

#[tokio::test(start_paused = true)]
async fn receive_failures_keep_protocol_size_and_idle_classifications() {
    let mut deadline = None;
    let mut buffered = BytesMut::new();
    let mut text = futures_util::stream::iter([Ok::<_, axum::Error>(Message::Text(
        "unexpected text frame".into(),
    ))]);
    assert!(matches!(
        receive_wire(&mut text, &mut buffered, &mut deadline).await,
        Ok(Some(Inbound::Failure(ReceiveFailure::Protocol)))
    ));

    let mut oversized = BytesMut::from(&[0_u8, 0x81, 0x80, 0x80, 0x08][..]);
    let mut source = futures_util::stream::pending::<Result<Message, axum::Error>>();
    assert!(matches!(
        receive_wire(&mut source, &mut oversized, &mut deadline).await,
        Ok(Some(Inbound::Failure(ReceiveFailure::SizeLimit)))
    ));

    buffered.clear();
    deadline = Some(tokio::time::Instant::now());
    assert!(matches!(
        receive_wire(&mut source, &mut buffered, &mut deadline).await,
        Ok(Some(Inbound::Failure(ReceiveFailure::IdleTimeout)))
    ));
}
