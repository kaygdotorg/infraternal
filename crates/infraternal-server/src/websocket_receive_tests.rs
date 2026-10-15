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
