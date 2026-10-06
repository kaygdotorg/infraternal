//! Actor isolation, restart-credit and stream-retirement regressions using real Unix sockets.
use super::*;

fn connection() -> (AgentConnection, UnixStream) {
    let (socket, peer) = UnixStream::pair().unwrap();
    let (reader, writer) = socket.into_split();
    (
        AgentConnection {
            reader,
            writer,
            pid: None,
            receive: BytesMut::new(),
            scratch: vec![0; 4096],
            encode: Vec::new(),
            next_call_id: 1,
            next_stream_id: 2,
        },
        peer,
    )
}

fn attachment(output: mpsc::Sender<TerminalOutput>) -> AttachmentState {
    AttachmentState {
        session_id: [1; 16],
        stream_id: 2,
        last_out_seq: 0,
        last_in_seq: 0,
        last_input_end: 0,
        output,
    }
}

#[tokio::test]
async fn full_output_queue_must_not_block_shared_actor() {
    let (mut link, _peer) = connection();
    let (tx, _rx) = mpsc::channel(1);
    tx.send(TerminalOutput::Ack { in_seq_acked: 0 })
        .await
        .unwrap();
    let mut attachments = HashMap::from([(1, attachment(tx))]);
    let mut routes = HashMap::from([(2, 1)]);
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        process_incoming(
            Incoming::Output {
                stream_id: 2,
                out_seq: 0,
                bytes: Bytes::from_static(b"x"),
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new(),
        ),
    )
    .await;
    assert!(
        result.is_ok(),
        "slow reader blocked the shared actor for 100ms"
    );
    assert!(result.unwrap(), "slow reader restarted unrelated streams");
    // Healthy stream traffic still completes in the same actor with the stalled receiver retained.
    let (tx, mut rx) = mpsc::channel(1);
    attachments.insert(
        3,
        AttachmentState {
            stream_id: 4,
            ..attachment(tx)
        },
    );
    routes.insert(4, 3);
    assert!(
        process_incoming(
            Incoming::Output {
                stream_id: 4,
                out_seq: 0,
                bytes: Bytes::from_static(b"y")
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new()
        )
        .await
    );
    assert!(
        matches!(rx.recv().await, Some(TerminalOutput::Output { bytes, .. }) if bytes == b"y"[..])
    );
}

#[tokio::test]
async fn healthy_streams_progress_at_user_attachment_capacity() {
    let (mut link, _peer) = connection();
    let (slow, _held) = mpsc::channel(4);
    for _ in 0..4 {
        slow.try_send(TerminalOutput::Ack { in_seq_acked: 0 })
            .unwrap();
    }
    let mut attachments = HashMap::from([(1, attachment(slow))]);
    let mut routes = HashMap::from([(2, 1)]);
    assert!(
        process_incoming(
            Incoming::Output {
                stream_id: 2,
                out_seq: 0,
                bytes: Bytes::from_static(b"s")
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new()
        )
        .await
    );
    let mut readers = Vec::new();
    for stream in (4..=1024).step_by(2) {
        let (tx, rx) = mpsc::channel(4);
        attachments.insert(
            u64::from(stream),
            AttachmentState {
                stream_id: stream,
                ..attachment(tx)
            },
        );
        routes.insert(stream, u64::from(stream));
        readers.push((stream, rx));
    }
    let mut pending = HashMap::new();
    let mut samples = Vec::new();
    for out_seq in 0..200 {
        for (stream_id, rx) in &mut readers {
            let start = std::time::Instant::now();
            assert!(
                process_incoming(
                    Incoming::Output {
                        stream_id: *stream_id,
                        out_seq,
                        bytes: Bytes::from_static(b"x")
                    },
                    &mut link,
                    &mut attachments,
                    &mut routes,
                    &mut pending
                )
                .await
            );
            assert!(matches!(rx.try_recv(), Ok(TerminalOutput::Output { .. })));
            samples.push(start.elapsed());
        }
    }
    samples.sort_unstable();
    println!(
        "actor isolation: stalled=1 healthy=511 output_bytes=1 n={} p50={}us p99={}us load={}",
        samples.len(),
        samples[samples.len() / 2].as_micros(),
        samples[(samples.len() * 99).div_ceil(100) - 1].as_micros(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
