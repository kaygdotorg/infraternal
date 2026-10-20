//! Verifies browser reply ordering and independent keyboard reservations across both forwarding hops [307], #244.
#![allow(clippy::unwrap_used)]

use super::*;

/// Leave the host actor receiver under test control while using the real forwarding tasks.
fn handle() -> (
    AttachmentHandle,
    mpsc::Receiver<Command>,
    tokio::task::JoinHandle<()>,
) {
    let (commands, received) = mpsc::channel(COMMAND_CAPACITY);
    let (input, pending_input) = mpsc::channel(INPUT_CAPACITY);
    let (_credit, input_acked) = watch::channel(0);
    let handle = AttachmentHandle(Arc::new(AttachmentHandleInner {
        id: 1,
        stream_id: 2,
        input,
        input_acked,
        commands: commands.clone(),
    }));
    let forwarding = tokio::spawn(forward_inputs(1, pending_input, commands));
    (handle, received, forwarding)
}

fn input_wire(sequence: u64, bytes: &[u8]) -> Bytes {
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Input {
            in_seq: sequence,
            bytes,
        },
        &mut wire,
    )
    .unwrap();
    wire.into()
}

#[tokio::test(flavor = "current_thread")]
async fn browser_reply_follows_typing_across_both_forwarding_tasks() {
    let (handle, mut received, forwarding) = handle();
    let (output, _events) = mpsc::channel(8);
    let queue = crate::websocket_input::InputQueue::new(handle, 1, output);
    // Admit both frames before either forwarding task runs, as one browser message can do.
    queue.enqueue(input_wire(0, b"A")).unwrap();
    assert!(queue.reply(
        42,
        Bytes::from_static(b"\x1b[1;1R"),
        std::time::Instant::now() + Duration::from_secs(10),
    ));
    let first = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .unwrap()
        .unwrap();
    let Command::Input { frame, .. } = first else {
        panic!("browser typing must reach the host command FIFO before its following reply");
    };
    assert_eq!(
        decode_muxed_frame(&frame).unwrap().frame,
        Frame::Input {
            in_seq: 0,
            bytes: b"A",
        }
    );
    let second = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(second, Command::Reply { query_seq: 42, bytes, .. } if bytes.as_ref() == b"\x1b[1;1R")
    );
    drop(queue);
    forwarding.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn full_reply_reservations_preserve_keyboard_bytes_and_all_eight_slots() {
    let (handle, _received, forwarding) = handle();
    let (output, _events) = mpsc::channel(8);
    let queue = crate::websocket_input::InputQueue::new(handle, 1, output);
    let expires = std::time::Instant::now() + Duration::from_secs(10);
    let reply = Bytes::from(vec![b'r'; 1024]);
    for query in 0..crate::terminal_queries::POSITIONS {
        assert!(queue.reply(query as u64, reply.clone(), expires));
    }
    assert!(!queue.reply(u64::MAX, reply, expires));
    // One near-maximum frame plus seven small frames must retain the original keyboard budget.
    let bytes = vec![b'x'; MAX_FRAME_LEN - 32];
    queue.enqueue(input_wire(0, &bytes)).unwrap();
    for offset in 0..7 {
        queue
            .enqueue(input_wire(bytes.len() as u64 + offset, b"z"))
            .unwrap();
    }
    assert!(
        queue
            .enqueue(input_wire(bytes.len() as u64 + 7, b"z"))
            .is_err()
    );
    drop(queue);
    forwarding.abort();
}
