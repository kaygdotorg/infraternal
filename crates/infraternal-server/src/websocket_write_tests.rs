//! Check control-write grouping, message order and whole-group backpressure bounds [D81,D265,#199].
use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Default)]
struct Capture {
    messages: Vec<Message>,
    flushes: usize,
    stalled: bool,
}

impl futures_util::Sink<Message> for Capture {
    type Error = axum::Error;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn start_send(mut self: Pin<&mut Self>, message: Message) -> Result<(), Self::Error> {
        self.messages.push(message);
        Ok(())
    }
    fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.flushes += 1;
        if self.stalled {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn ready_proofs_keep_message_boundaries_and_order_with_one_flush() {
    let mut sink = Capture::default();
    let mut messages = Vec::new();
    for nonce in 0..65 {
        let mut encoded = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Pong {
                nonce,
                sent_us: nonce,
            },
            &mut encoded,
        )
        .unwrap();
        messages.push(Message::Binary(Bytes::from(encoded)));
    }
    send_messages(&mut sink, messages).await.unwrap();
    assert_eq!(sink.flushes, 1);
    assert_eq!(sink.messages.len(), 65);
    for (nonce, message) in sink.messages.iter().enumerate() {
        let Message::Binary(bytes) = message else {
            panic!("proof message type changed");
        };
        let decoded = decode_muxed_frame(bytes).unwrap();
        assert_eq!(
            decoded.wire_len,
            bytes.len(),
            "one mux frame per WebSocket message"
        );
        assert!(
            matches!(decoded.frame, Frame::Pong { nonce: value, sent_us } if value == nonce as u64 && sent_us == value)
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_stalled_group_has_one_absolute_write_budget() {
    let mut sink = Capture {
        stalled: true,
        ..Capture::default()
    };
    let start = tokio::time::Instant::now();
    let result = send_messages(
        &mut sink,
        [Message::Pong(Bytes::new()), Message::Ping(Bytes::new())],
    )
    .await;
    assert!(result.is_err());
    assert_eq!(start.elapsed(), WRITE_TIMEOUT);
}
