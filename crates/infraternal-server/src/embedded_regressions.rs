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
        credit: 0,
        awaiting_ack: false,
        output,
    }
}

/// Output fixtures include the native credit grant; control-only fixtures remain unfunded.
fn funded_attachment(output: mpsc::Sender<TerminalOutput>) -> AttachmentState {
    AttachmentState {
        credit: 1024 * 1024,
        ..attachment(output)
    }
}

#[tokio::test]
async fn full_output_queue_must_not_block_shared_actor() {
    let (mut link, _peer) = connection();
    let (tx, _rx) = mpsc::channel(1);
    tx.send(TerminalOutput::Ack { in_seq_acked: 0 })
        .await
        .unwrap();
    let mut attachments = HashMap::from([(1, funded_attachment(tx))]);
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
            ..funded_attachment(tx)
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
    let mut attachments = HashMap::from([(1, funded_attachment(slow))]);
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
                ..funded_attachment(tx)
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

#[tokio::test]
async fn reattach_must_restore_output_credit() {
    let (mut old, mut old_peer) = connection();
    let (tx, _rx) = mpsc::channel(4);
    let mut attachments = HashMap::from([(1, attachment(tx))]);
    let mut routes = HashMap::from([(2, 1)]);
    let mut wire = Vec::new();
    encode_muxed_frame_into(1, &Frame::Credit { bytes: 1024 }, &mut wire).unwrap();
    assert!(
        process_command(
            Command::Input {
                attachment_id: 1,
                frame: Bytes::from(wire)
            },
            &mut old,
            &mut attachments,
            &mut routes,
            &mut HashMap::new(),
        )
        .await
    );
    let mut discard = [0; 64];
    assert!(old_peer.read(&mut discard).await.unwrap() > 0);
    let (mut replacement, mut peer) = connection();
    routes.clear();
    assert!(reattach_all(&mut replacement, &mut attachments, &mut routes).await);
    let mut bytes = [0; 256];
    let length = peer.read(&mut bytes).await.unwrap();
    let first = decode_muxed_frame(&bytes[..length]).unwrap();
    assert_eq!(
        first.stream_id, 2,
        "supervision changed durable writer identity"
    );
    assert!(matches!(first.frame, Frame::AttachTerm { .. }));
    let next = decode_muxed_frame(&bytes[first.wire_len..length]);
    assert!(
        matches!(next.map(|f| f.frame), Ok(Frame::Credit { bytes: 1024 })),
        "restart reattached without remaining browser credit"
    );
}

/// Snapshot repaint bytes consume credit without advancing the output byte offset.
#[tokio::test]
async fn output_and_snapshot_spend_remaining_restart_credit() {
    let (mut link, _peer) = connection();
    let (tx, mut rx) = mpsc::channel(4);
    let mut state = attachment(tx);
    state.credit = 1024;
    let mut attachments = HashMap::from([(1, state)]);
    let mut routes = HashMap::from([(2, 1)]);
    let mut pending = HashMap::new();
    assert!(
        process_incoming(
            Incoming::Output {
                stream_id: 2,
                out_seq: 0,
                bytes: Bytes::from_static(b"abc")
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut pending
        )
        .await
    );
    rx.try_recv().unwrap();
    assert!(
        process_incoming(
            Incoming::Snapshot {
                stream_id: 2,
                out_seq: 3,
                bytes: Bytes::from_static(b"repaint")
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut pending
        )
        .await
    );
    rx.try_recv().unwrap();
    assert_eq!(attachments[&1].credit, 1014);
    assert_eq!(attachments[&1].last_out_seq, 3);
}

#[tokio::test]
async fn stream_close_must_not_restart_all_sessions() {
    let (mut link, _peer) = connection();
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    let mut attachments = HashMap::from([(1, attachment(tx))]);
    let mut routes = HashMap::from([(2, 1)]);
    assert!(
        process_incoming(
            Incoming::Close {
                stream_id: 2,
                code: 1000
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new()
        )
        .await,
        "retiring a dropped receiver restarted every session"
    );
    assert!(attachments.is_empty());
    assert!(routes.is_empty());
}

#[tokio::test]
async fn real_agent_open_uses_uid_and_character_dimensions() {
    let (mut link, mut peer) = connection();
    let (reply, _result) = oneshot::channel();
    assert!(
        process_command(
            Command::Open {
                size: TerminalSize {
                    cols: 80,
                    rows: 24,
                    px_w: 800,
                    px_h: 600
                },
                reply
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut HashMap::new(),
        )
        .await
    );
    let mut bytes = [0; 4096];
    let count = peer.read(&mut bytes).await.unwrap();
    let decoded = decode_muxed_frame(&bytes[..count]).unwrap();
    let Frame::Call {
        action_id,
        input_json,
        ..
    } = decoded.frame
    else {
        panic!("missing open Call");
    };
    assert_eq!(action_id, "terminal.open");
    let input: serde_json::Value = serde_json::from_slice(input_json).unwrap();
    assert_eq!(
        input,
        serde_json::json!({"uid":nix::unistd::Uid::effective().as_raw(),"cols":80,"rows":24})
    );
}

#[tokio::test]
async fn real_agent_canonical_uuid_result_is_accepted() {
    let (mut link, _peer) = connection();
    let (reply, result) = oneshot::channel();
    let mut pending = HashMap::from([(
        1,
        PendingCall {
            reply: PendingReply::Open(reply),
        },
    )]);
    assert!(
        process_incoming(
            Incoming::Result {
                call_id: 1,
                ok: true,
                json: br#"{"session_id":"01010101-0101-0101-0101-010101010101"}"#.to_vec()
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending,
        )
        .await
    );
    assert_eq!(result.await.unwrap(), Ok([1; 16]));
}

/// Recovery notices are ordered terminal traffic, so they cannot retire leg B.
#[tokio::test]
async fn recovery_event_then_snapshot_keeps_embedded_connection_live() {
    use tokio::io::AsyncWriteExt;
    let (mut link, mut peer) = connection();
    let json = serde_json::to_vec(&serde_json::json!({
        "type": "terminal.snapshot", "session_id": uuid::Uuid::from_bytes([1; 16]),
        "seq": 17, "approximate": true
    }))
    .unwrap();
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        2,
        &Frame::Event {
            sub_id: 0,
            event_json: &json,
        },
        &mut wire,
    )
    .unwrap();
    peer.write_all(&wire).await.unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(1), read_incoming(&mut link))
        .await
        .unwrap();
    assert!(
        incoming.is_some(),
        "ordered recovery Event retired the embedded connection"
    );
    wire.clear();
    encode_muxed_frame_into(
        2,
        &Frame::Snapshot {
            out_seq: 17,
            bytes: b"repaint",
        },
        &mut wire,
    )
    .unwrap();
    peer.write_all(&wire).await.unwrap();
    assert!(matches!(
        read_incoming(&mut link).await,
        Some(Incoming::Snapshot { out_seq: 17, .. })
    ));
}

/// Immediately-ready native output must give the healthy bounded receiver a turn.
#[tokio::test]
async fn healthy_receiver_survives_ready_native_output_burst() {
    let (mut link, _peer) = connection();
    let (tx, mut rx) = mpsc::channel(4);
    let mut attachments = HashMap::from([(1, funded_attachment(tx))]);
    let mut routes = HashMap::from([(2, 1)]);
    let received = tokio::spawn(async move {
        let mut count = 0;
        while let Some(event) = rx.recv().await {
            if matches!(event, TerminalOutput::Output { .. }) {
                count += 1;
            }
        }
        count
    });
    for out_seq in 0..128 {
        assert!(
            process_incoming(
                Incoming::Output {
                    stream_id: 2,
                    out_seq,
                    bytes: Bytes::from_static(b"x")
                },
                &mut link,
                &mut attachments,
                &mut routes,
                &mut HashMap::new()
            )
            .await
        );
    }
    drop(attachments);
    assert_eq!(
        received.await.unwrap(),
        128,
        "healthy native viewer was retired during an immediately-ready burst"
    );
}

#[tokio::test]
async fn recovery_notices_preserve_order_credit_and_session_isolation() {
    let (mut link, _peer) = connection();
    let (tx, mut rx) = mpsc::channel(4);
    let mut attachments = HashMap::from([(1, attachment(tx))]);
    let mut routes = HashMap::from([(2, 1)]);
    let json = |session: [u8; 16]| {
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "type":"terminal.snapshot", "session_id":uuid::Uuid::from_bytes(session),
                "seq":17, "approximate":true
            }))
            .unwrap(),
        )
    };
    assert!(
        !process_incoming(
            Incoming::Event {
                stream_id: 2,
                event_json: json([2; 16])
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new()
        )
        .await
    );
    assert!(rx.try_recv().is_err());
    assert!(
        process_incoming(
            Incoming::Event {
                stream_id: 2,
                event_json: json([1; 16])
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new()
        )
        .await
    );
    assert_eq!(attachments[&1].last_out_seq, 0);
    assert_eq!(attachments[&1].credit, 0);
    attachments.get_mut(&1).unwrap().credit = 7;
    assert!(
        process_incoming(
            Incoming::Snapshot {
                stream_id: 2,
                out_seq: 17,
                bytes: Bytes::from_static(b"repaint")
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new()
        )
        .await
    );
    assert!(matches!(
        rx.recv().await,
        Some(TerminalOutput::Event { .. })
    ));
    assert!(matches!(
        rx.recv().await,
        Some(TerminalOutput::Snapshot { out_seq: 17, .. })
    ));
    assert_eq!(attachments[&1].last_out_seq, 17);
    let (tx, _held) = mpsc::channel(1);
    tx.try_send(TerminalOutput::Ack { in_seq_acked: 0 })
        .unwrap();
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
            Incoming::Event {
                stream_id: 4,
                event_json: json([1; 16])
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new()
        )
        .await
    );
    assert!(!routes.contains_key(&4));
    assert!(routes.contains_key(&2));
}

/// One credited bulk window must survive a forwarder briefly awaiting authenticated I/O.
#[tokio::test]
async fn credited_bulk_output_survives_forwarder_io_pause() {
    let (mut link, _peer) = connection();
    let (tx, mut rx) = mpsc::channel(OUTPUT_CAPACITY);
    let mut state = attachment(tx);
    state.credit = 1024 * 1024;
    let mut attachments = HashMap::from([(1, state)]);
    let mut routes = HashMap::from([(2, 1)]);
    for chunk in 0..256 {
        assert!(
            process_incoming(
                Incoming::Output {
                    stream_id: 2,
                    out_seq: chunk * 4096,
                    bytes: Bytes::from(vec![120; 4096]),
                },
                &mut link,
                &mut attachments,
                &mut routes,
                &mut HashMap::new()
            )
            .await
        );
    }
    assert_eq!(
        rx.len(),
        256,
        "credited bulk window retired a healthy I/O-paused viewer"
    );
    assert!(routes.contains_key(&2));
    assert_eq!(attachments[&1].credit, 0);
    for chunk in 0..256 {
        assert!(
            matches!(rx.try_recv(),Ok(TerminalOutput::Output {out_seq,bytes})
            if out_seq == chunk*4096 && bytes.len()==4096)
        );
    }
}

/// Credit is a byte bound even when the downstream frame queue has spare slots.
#[tokio::test]
async fn uncredited_output_or_repaint_is_rejected_before_queueing() {
    for incoming in [
        Incoming::Output {
            stream_id: 2,
            out_seq: 0,
            bytes: Bytes::from_static(b"x"),
        },
        Incoming::Snapshot {
            stream_id: 2,
            out_seq: 17,
            bytes: Bytes::from_static(b"x"),
        },
    ] {
        let (mut link, _peer) = connection();
        let (tx, mut rx) = mpsc::channel(4);
        let mut attachments = HashMap::from([(1, attachment(tx))]);
        let mut routes = HashMap::from([(2, 1)]);
        assert!(
            !process_incoming(
                incoming,
                &mut link,
                &mut attachments,
                &mut routes,
                &mut HashMap::new()
            )
            .await,
            "embedded peer exceeded granted output bytes"
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(attachments[&1].credit, 0);
        assert_eq!(attachments[&1].last_out_seq, 0);
    }
}

/// Quantify the default credited output burst at the deployed 128-stream ceiling.
#[tokio::test]
#[ignore = "debug actor memory/scheduling measurement; run without concurrent builds"]
async fn credited_output_queue_at_stream_capacity() {
    fn resident_kib() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find(|line| line.starts_with("VmRSS:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    }
    let baseline = resident_kib();
    let (mut link, _peer) = connection();
    let mut attachments = HashMap::new();
    let mut routes = HashMap::new();
    let mut receivers = Vec::new();
    for id in 1..=128_u64 {
        let (tx, rx) = mpsc::channel(OUTPUT_CAPACITY);
        let stream_id = u32::try_from(id).unwrap() * 2;
        attachments.insert(
            id,
            AttachmentState {
                stream_id,
                credit: 1024 * 1024,
                ..attachment(tx)
            },
        );
        routes.insert(stream_id, id);
        receivers.push(rx);
    }
    let idle = resident_kib();
    let mut samples = Vec::with_capacity(32768);
    // Unique buffers make the measured payload cost real rather than shared test storage.
    for chunk in 0..256 {
        for id in 1..=128_u64 {
            let started = std::time::Instant::now();
            assert!(
                process_incoming(
                    Incoming::Output {
                        stream_id: u32::try_from(id).unwrap() * 2,
                        out_seq: chunk * 4096,
                        bytes: Bytes::from(vec![120; 4096])
                    },
                    &mut link,
                    &mut attachments,
                    &mut routes,
                    &mut HashMap::new()
                )
                .await
            );
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
        }
    }
    assert_eq!(routes.len(), 128);
    assert!(receivers.iter().all(|rx| rx.len() == 256));
    assert!(attachments.values().all(|state| state.credit == 0));
    let full = resident_kib();
    samples.sort_by(f64::total_cmp);
    println!(
        "debug actor scale: streams=128 frames=32768 payload_bytes=134217728 baseline_RSS_KiB={baseline} idle_queues_RSS_KiB={idle} full_queues_RSS_KiB={full} dispatch_p99_ms={:.6} CPUs={} load={}",
        samples[samples.len() * 99 / 100],
        std::thread::available_parallelism().unwrap().get(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
