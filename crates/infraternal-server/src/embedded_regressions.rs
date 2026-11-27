//! Actor isolation, restart-credit and stream-retirement regressions using real Unix sockets.
use super::*;

/// A greeted local connection over a fresh socketpair, with no child process, and the peer end
/// that plays the infraternal agent.
fn connection() -> (AgentConnection, UnixStream) {
    let (socket, peer) = UnixStream::pair().unwrap();
    let (reader, writer) = socket.into_split();
    (
        AgentConnection {
            #[cfg(feature = "remote")]
            wire_jobs: tokio::task::JoinSet::new(),
            peer: Peer::Local { reader, writer },
            execution_uid: nix::unistd::Uid::effective().as_raw(),
            pid: None,
            _child_slot: None,
            receive: BytesMut::new(),
            scratch: vec![0; 4096],
            encode: Vec::new(),
            next_call_id: 1,
            #[cfg(feature = "remote")]
            owned_control: None,
            #[cfg(feature = "remote")]
            owned_cleanup: None,
        },
        peer,
    )
}

/// A retirement whose caller has gone away is still sent to the host, so the cleanup survives.
#[cfg(feature = "remote")]
#[tokio::test]
async fn canceled_retirement_recipient_does_not_cancel_host_cleanup() {
    let (mut connection, mut peer) = connection();
    let (reply, result) = oneshot::channel();
    drop(result);
    let mut pending = HashMap::new();
    assert!(
        process_command(
            Command::RevokeLogin {
                person: uuid::Uuid::new_v4(),
                report: true,
                reply
            },
            &mut connection,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending
        )
        .await
    );
    let mut bytes = BytesMut::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if decode_muxed_frame(&bytes).is_ok() {
                break;
            }
            assert_ne!(peer.read_buf(&mut bytes).await.unwrap(), 0);
        }
    })
    .await
    .unwrap();
    let frame = decode_muxed_frame(&bytes).unwrap();
    let Frame::Call {
        call_id,
        action_id: "terminal.login.revoke",
        ..
    } = frame.frame
    else {
        panic!("canceled recipient prevented host cleanup submission");
    };
    assert_eq!(call_id & BACKGROUND_CALL_BITS, RETIREMENT_CALL_BIT);
    assert!(pending.is_empty());
    // The host may finish after caller timeout. Its marked late proof must
    // leave ordinary protocol errors strict and keep sibling streams alive.
    assert!(
        process_incoming(
            Incoming::Result {
                call_id,
                ok: true,
                json: b"{}".to_vec()
            },
            &mut connection,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending
        )
        .await
    );
    assert!(
        !process_incoming(
            Incoming::Result {
                call_id: 99,
                ok: true,
                json: b"{}".to_vec()
            },
            &mut connection,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending
        )
        .await
    );
}

/// Retirements have their own mailbox: a full ordinary command queue never blocks them.
#[cfg(feature = "remote")]
#[tokio::test]
async fn retirement_mailbox_bypasses_a_full_ordinary_command_queue() {
    let (sender, mut commands) = mpsc::channel(1);
    let (reply, _result) = oneshot::channel();
    assert!(
        sender
            .try_send(Command::Call {
                action_id: "review.pending".into(),
                input_json: b"{}".to_vec(),
                reply
            })
            .is_ok()
    );
    let (cleanup, mut retirement) = mpsc::unbounded_channel();
    for _ in 0..96 {
        let (reply, _result) = oneshot::channel();
        assert!(
            cleanup
                .send(Retirement {
                    person: uuid::Uuid::new_v4(),
                    report: true,
                    reply
                })
                .is_ok()
        );
    }
    for _ in 0..96 {
        assert!(matches!(
            next_command(&mut commands, false, &mut retirement).await,
            Some(Command::RevokeLogin { .. })
        ));
        assert_eq!(commands.len(), 1);
    }
    drop(cleanup);
    assert!(matches!(
        next_command(&mut commands, true, &mut retirement).await,
        Some(Command::Call { .. })
    ));
}

/// An unfunded, settled attachment on stream 2 whose output goes to the given channel.
fn attachment(output: mpsc::Sender<TerminalOutput>) -> AttachmentState {
    AttachmentState {
        session_id: [1; 16],
        stream_id: 2,
        last_out_seq: 0,
        last_in_seq: 0,
        last_input_end: 0,
        unacknowledged: BytesMut::new(),
        input_credit: watch::channel(0).0,
        credit: 0,
        awaiting_ack: false,
        replaying: false,
        output: output.into(),
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
async fn replay_complete_notices_preserve_optional_geometry_through_server() {
    let (mut link, _peer) = connection();
    let (tx, mut rx) = mpsc::channel(2);
    let mut attachments = HashMap::from([(1, attachment(tx))]);
    let mut routes = HashMap::from([(2, 1)]);
    for size in [None, Some((120, 40))] {
        let mut notice = serde_json::json!({
            "type": "terminal.replay_complete",
            "session_id": uuid::Uuid::from_bytes([1; 16]),
            "out_seq": "18446744073709551615",
        });
        if let Some((cols, rows)) = size {
            notice["cols"] = serde_json::json!(cols);
            notice["rows"] = serde_json::json!(rows);
        }
        let json = Bytes::from(serde_json::to_vec(&notice).unwrap());
        assert!(
            process_incoming(
                Incoming::Event {
                    stream_id: 2,
                    event_json: json.clone()
                },
                &mut link,
                &mut attachments,
                &mut routes,
                &mut HashMap::new(),
            )
            .await
        );
        let Some(TerminalOutput::Event { event_json }) = rx.recv().await else {
            panic!("missing replay notice");
        };
        assert_eq!(event_json, json);
    }
}

#[test]
fn replay_geometry_rejects_values_outside_u16() {
    for value in [
        serde_json::json!(-1),
        serde_json::json!(65536),
        serde_json::json!("80"),
    ] {
        let notice = serde_json::json!({
            "type": "terminal.replay_complete",
            "session_id": uuid::Uuid::from_bytes([1; 16]),
            "out_seq": "0", "cols": value, "rows": 24,
        });
        assert!(serde_json::from_value::<TerminalNotice>(notice).is_err());
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

/// A resumed browser can reclaim a writer before its previous handle drops.
#[tokio::test]
async fn resumed_writer_closes_previous_route_before_shared_stream_reuse() {
    let (mut link, mut peer) = connection();
    let (old_output, _old_receiver) = mpsc::channel(4);
    let mut attachments = HashMap::from([(1, attachment(old_output))]);
    let mut routes = HashMap::from([(2, 1)]);
    let (output, _receiver) = mpsc::channel(4);
    let (reply, result) = oneshot::channel();
    assert!(
        process_command(
            Command::Attach {
                id: 2,
                session_id: [1; 16],
                stream_id: 2,
                last_out_seq: 11,
                last_in_seq: 7,
                output,
                input_credit: watch::channel(7).0,
                reply,
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new(),
        )
        .await
    );
    assert_eq!(result.await.unwrap().unwrap(), (2, 2));
    assert!(!attachments.contains_key(&1));
    assert_eq!(routes.get(&2), Some(&2));
    let mut bytes = [0; 256];
    let count = peer.read(&mut bytes).await.unwrap();
    let closed = decode_muxed_frame(&bytes[..count]).unwrap();
    assert_eq!(closed.stream_id, 2);
    assert!(
        matches!(closed.frame, Frame::Close { .. }),
        "reclaiming a live shared writer must retire its previous remote route"
    );
    let attached = decode_muxed_frame(&bytes[closed.wire_len..count]).unwrap();
    assert_eq!(attached.stream_id, 2);
    assert!(matches!(
        attached.frame,
        Frame::AttachTerm { session_id, last_out_seq: 11, last_in_seq: 7 } if session_id == &[1; 16]
    ));
}

/// Writer reuse cannot retire a different session's existing attachment.
#[tokio::test]
async fn resumed_writer_for_other_session_preserves_live_route() {
    let (mut link, peer) = connection();
    let (old_output, _old_receiver) = mpsc::channel(4);
    let mut attachments = HashMap::from([(1, attachment(old_output))]);
    let mut routes = HashMap::from([(2, 1)]);
    let (output, _receiver) = mpsc::channel(4);
    let (reply, result) = oneshot::channel();
    assert!(
        process_command(
            Command::Attach {
                id: 2,
                session_id: [2; 16],
                stream_id: 2,
                last_out_seq: 0,
                last_in_seq: 0,
                output,
                input_credit: watch::channel(0).0,
                reply,
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new(),
        )
        .await
    );
    assert!(matches!(result.await.unwrap(), Err(AgentError::Protocol)));
    assert!(attachments.contains_key(&1));
    assert_eq!(routes.get(&2), Some(&1));
    let mut peer = peer.into_std().unwrap();
    assert_eq!(
        std::io::Read::read(&mut peer, &mut [0; 1])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock,
        "a rejected session cannot send a Close for the live writer"
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
                code: 1000,
                reason: "detached",
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
                login: None,
                readiness: false,
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
    let mut pending = HashMap::from([(1, PendingCall::Open(reply))]);
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
    assert_eq!(result.await.unwrap().unwrap().session_id, [1; 16]);
}

#[tokio::test]
async fn agent_link_loss_invalidates_the_last_live_session_snapshot() {
    let (server, mut agent_peer) = UnixStream::pair().unwrap();
    let agent = EmbeddedAgent::from_test_socket(server);
    let mut inventory = agent.session_inventory();

    let mut receive = BytesMut::with_capacity(4096);
    let mut scratch = [0; 4096];
    let greeting_seen = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let read = agent_peer.read(&mut scratch).await.unwrap();
            assert_ne!(read, 0, "actor closed before greeting");
            receive.extend_from_slice(&scratch[..read]);
            if let Ok(decoded) = decode_muxed_frame(&receive)
                && matches!(decoded.frame, Frame::Hello { version: 1, .. })
            {
                break true;
            }
        }
    })
    .await
    .unwrap();
    assert!(greeting_seen);

    let mut greeting = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "inventory fixture",
        },
        &mut greeting,
    )
    .unwrap();
    agent_peer.write_all(&greeting).await.unwrap();

    let session = uuid::Uuid::new_v4();
    let event = serde_json::to_vec(&serde_json::json!({
        "type": "terminal.sessions.snapshot",
        "session_ids": [session],
    }))
    .unwrap();
    let mut snapshot = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Event {
            sub_id: 0,
            event_json: &event,
        },
        &mut snapshot,
    )
    .unwrap();
    agent_peer.write_all(&snapshot).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), inventory.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        &*inventory.borrow(),
        SessionInventoryState::Available(ids) if ids.as_ref() == [*session.as_bytes()]
    ));

    // Capability changes have their own watch and must leave the live census intact.
    let mut changes = agent.changes();
    let mut plugin_frame = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Event {
            sub_id: 0,
            event_json: br#"{"type":"plugin.event","id":"plugins.disabled"}"#,
        },
        &mut plugin_frame,
    )
    .unwrap();
    agent_peer.write_all(&plugin_frame).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), changes.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        &*inventory.borrow(),
        SessionInventoryState::Available(ids) if ids.as_ref() == [*session.as_bytes()]
    ));

    // Preserve forward compatibility for unrelated control Events: only this
    // event type is an inventory, and it must not retire the agent link.
    let future_event = serde_json::to_vec(&serde_json::json!({
        "type": "future.control.notice",
    }))
    .unwrap();
    let mut future_frame = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Event {
            sub_id: 0,
            event_json: &future_event,
        },
        &mut future_frame,
    )
    .unwrap();
    let next_session = uuid::Uuid::new_v4();
    let next_event = serde_json::to_vec(&serde_json::json!({
        "type": "terminal.sessions.snapshot",
        "session_ids": [next_session],
    }))
    .unwrap();
    let mut next_frame = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Event {
            sub_id: 0,
            event_json: &next_event,
        },
        &mut next_frame,
    )
    .unwrap();
    future_frame.extend_from_slice(&next_frame);
    agent_peer.write_all(&future_frame).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), inventory.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        &*inventory.borrow(),
        SessionInventoryState::Available(ids) if ids.as_ref() == [*next_session.as_bytes()]
    ));

    drop(agent_peer);
    let invalidated = tokio::time::timeout(Duration::from_millis(100), inventory.changed()).await;
    assert!(
        invalidated.is_ok(),
        "agent link loss must invalidate the previously live snapshot"
    );
    assert_eq!(*inventory.borrow(), SessionInventoryState::Unavailable);
    drop(agent);
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
    let (tx, mut rx) = mpsc::channel(OUTPUT_QUEUE_SLOTS);
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

/// The opening grant now carries a 64 KiB repaint reserve beside the 1 MiB bulk window; a healthy
/// viewer that is briefly slow must not be retired when that whole grant arrives as 4 KiB frames (#477).
#[tokio::test]
async fn full_opening_grant_with_repaint_reserve_survives_forwarder_io_pause() {
    const GRANT: u64 = 1024 * 1024 + 64 * 1024;
    let (mut link, _peer) = connection();
    let (tx, rx) = mpsc::channel(OUTPUT_QUEUE_SLOTS);
    let mut state = attachment(tx);
    state.credit = GRANT;
    let mut attachments = HashMap::from([(1, state)]);
    let mut routes = HashMap::from([(2, 1)]);
    for chunk in 0..GRANT / 4096 {
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
    assert!(
        routes.contains_key(&2),
        "the full credited grant retired a healthy I/O-paused viewer"
    );
    assert_eq!(rx.len() as u64, GRANT / 4096);
    assert_eq!(attachments[&1].credit, 0);
}

/// The output channel a production attachment gets, so the queue-bound tests below exercise the shipped bound.
fn production_output() -> (mpsc::Sender<TerminalOutput>, mpsc::Receiver<TerminalOutput>) {
    mpsc::channel(OUTPUT_QUEUE_SLOTS)
}

/// Offers one raw Output frame to the relay exactly as the host link would deliver it.
/// Returns whether the shared link survives; the caller checks `routes` to see whether the stream did.
async fn offer_output(
    link: &mut AgentConnection,
    attachments: &mut HashMap<u64, AttachmentState>,
    routes: &mut HashMap<u32, u64>,
    out_seq: u64,
    bytes: Bytes,
) -> bool {
    process_incoming(
        Incoming::Output {
            stream_id: 2,
            out_seq,
            bytes,
        },
        link,
        attachments,
        routes,
        &mut HashMap::new(),
    )
    .await
}

/// A viewer that respects credit is never retired, however small the frames are (#477, D381).
///
/// Under a flood the host forwards whatever each PTY read returned, about 1 KiB on average, so the
/// full opening grant (1 MiB bulk + 64 KiB repaint reserve) arrives as thousands of frames while the
/// forwarder briefly awaits browser I/O. The bound that matters is bytes, and credit already holds
/// queued bytes to the grant. The second half drains part of the queue, re-grants exactly what was
/// drained, and refills, so a bound that forgot drained bytes would retire the stream here.
#[tokio::test]
async fn small_frames_within_credit_never_retire_a_paused_viewer() {
    const GRANT: u64 = 1024 * 1024 + 64 * 1024;
    const FRAME_LEN: usize = 256;
    const FRAME: u64 = FRAME_LEN as u64;
    let (mut link, _peer) = connection();
    let (tx, mut rx) = production_output();
    let mut state = attachment(tx);
    state.credit = GRANT;
    let mut attachments = HashMap::from([(1, state)]);
    let mut routes = HashMap::from([(2, 1)]);
    let mut out_seq = 0;
    for _ in 0..GRANT / FRAME {
        assert!(
            offer_output(
                &mut link,
                &mut attachments,
                &mut routes,
                out_seq,
                Bytes::from(vec![b'y'; FRAME_LEN])
            )
            .await
        );
        out_seq += FRAME;
    }
    assert!(
        routes.contains_key(&2),
        "small credited frames retired a healthy I/O-paused viewer"
    );
    assert_eq!(rx.len() as u64, GRANT / FRAME);
    assert_eq!(attachments[&1].credit, 0);
    // The viewer consumes half its queue and returns that credit; the relay must count it as gone.
    let drained = GRANT / FRAME / 2;
    for _ in 0..drained {
        assert!(matches!(rx.try_recv(), Ok(TerminalOutput::Output { .. })));
    }
    for round in 0..4 {
        attachments.get_mut(&1).unwrap().credit = drained * FRAME;
        for _ in 0..drained {
            assert!(
                offer_output(
                    &mut link,
                    &mut attachments,
                    &mut routes,
                    out_seq,
                    Bytes::from(vec![b'y'; FRAME_LEN])
                )
                .await
            );
            out_seq += FRAME;
        }
        assert!(
            routes.contains_key(&2),
            "refill round {round} retired a viewer whose queue never exceeded its grant"
        );
        for _ in 0..drained {
            assert!(matches!(rx.try_recv(), Ok(TerminalOutput::Output { .. })));
        }
    }
}

/// A browser that keeps granting credit without reading its socket still hits a hard per-stream cap.
///
/// Credit alone cannot bound the queue against a peer that ignores it: the relay cannot tell a
/// re-grant from real consumption. Each frame here is 1 MiB, well under the 4 MiB wire limit, so a
/// bound counted in frames would let hundreds of MiB queue for one stream. The stream must be
/// retired (1013, reattach replays from the last offset) before its queue holds more than the
/// 8 MiB credit ceiling plus 1 MiB of headroom, and the shared host link must survive.
#[tokio::test]
async fn ignoring_credit_hits_the_hard_queue_cap() {
    const FRAME_LEN: usize = 1024 * 1024;
    const FRAME: u64 = FRAME_LEN as u64;
    const CAP: u64 = 9 * 1024 * 1024;
    let (mut link, _peer) = connection();
    let (tx, rx) = production_output();
    let mut attachments = HashMap::from([(1, attachment(tx))]);
    let mut routes = HashMap::from([(2, 1)]);
    let payload = Bytes::from(vec![b'y'; FRAME_LEN]);
    let mut out_seq = 0;
    for _ in 0..64 {
        if !routes.contains_key(&2) {
            break;
        }
        // The dishonest viewer tops credit back up before every frame and never reads.
        attachments.get_mut(&1).unwrap().credit = MAX_OUTPUT_CREDIT;
        assert!(
            offer_output(
                &mut link,
                &mut attachments,
                &mut routes,
                out_seq,
                payload.clone()
            )
            .await,
            "retiring one stream must not drop the shared host link"
        );
        out_seq += FRAME;
    }
    assert!(
        !routes.contains_key(&2),
        "a peer ignoring credit queued 64 MiB on one stream"
    );
    assert!(
        rx.len() as u64 * FRAME <= CAP,
        "{} MiB queued before retirement",
        rx.len()
    );
}

/// Items that spend no credit (key acknowledgments, notices) cannot grow a paused queue without bound.
///
/// Every queued item is charged a fixed overhead on top of its payload, so a host that floods a
/// paused viewer with empty-payload items reaches the same byte cap and only that stream retires.
#[tokio::test]
async fn uncredited_items_cannot_grow_a_paused_queue_without_bound() {
    let (mut link, _peer) = connection();
    let (tx, rx) = production_output();
    let mut state = attachment(tx);
    state.last_input_end = u64::MAX / 2;
    let mut attachments = HashMap::from([(1, state)]);
    let mut routes = HashMap::from([(2, 1)]);
    let mut acked = 0;
    while routes.contains_key(&2) && acked < 1_000_000 {
        acked += 1;
        assert!(
            process_incoming(
                Incoming::Ack {
                    stream_id: 2,
                    in_seq_acked: acked,
                },
                &mut link,
                &mut attachments,
                &mut routes,
                &mut HashMap::new()
            )
            .await
        );
    }
    assert!(
        !routes.contains_key(&2),
        "a million uncredited items never filled the queue"
    );
    // 64 bytes charged per item against the 9 MiB cap.
    assert!(
        rx.len() <= 9 * 1024 * 1024 / 64,
        "{} items queued",
        rx.len()
    );
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
        let (tx, rx) = mpsc::channel(OUTPUT_QUEUE_SLOTS);
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

#[test]
fn child_spawn_disposes_inherited_stdin() {
    use std::{
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    const NAME: &str = "embedded::regressions::child_spawn_disposes_inherited_stdin";
    if std::env::var_os("INFRATERNAL_STDIN_CHILD_TEST").is_some() {
        let directory = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/ca-handoff")
            .join(format!("stdin-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&directory).unwrap();
        let script = directory.join("child");
        std::fs::write(&script, b"#!/bin/sh\nreadlink /proc/self/fd/0 >&3\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (mut channel, pid) = spawn_socketpair_agent(&script).unwrap();
            let mut reply = String::new();
            tokio::io::AsyncReadExt::read_to_string(&mut channel, &mut reply)
                .await
                .unwrap();
            nix::sys::wait::waitpid(pid.unwrap(), None).unwrap();
            assert_eq!(
                reply.trim(),
                "/dev/null",
                "the infraternal agent inherited stdin"
            );
        });
        std::fs::remove_dir_all(directory).unwrap();
        return;
    }
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(sender);
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_STDIN_CHILD_TEST", "1")
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(receiver)))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn unresponsive_child_is_killed_and_reaped_within_the_shutdown_bound() {
    use std::io::Read;
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "trap '' TERM; printf ready; exec sleep 60"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = [0; 5];
    child.stdout.take().unwrap().read_exact(&mut ready).unwrap();
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
    let result = tokio::time::timeout(Duration::from_secs(4), stop_child(pid)).await;
    if result.is_err() {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    }
    // stop_child normally reaps through waitpid; Child::wait then returns ECHILD.
    // The failure path also waits, releasing the original blocking waiter.
    let _ = child.wait();
    assert!(
        result.is_ok(),
        "SIGTERM-resistant child must be SIGKILLed and reaped within the bound"
    );
}

/// Reaps an embedded child when Tokio cancels its actor during server shutdown.
#[test]
fn runtime_shutdown_reaps_embedded_child_before_returning() {
    use std::io::Read;

    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "printf ready; exec sleep 60"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start a child that stays alive until signaled");
    let mut ready = [0; 5];
    child
        .stdout
        .take()
        .expect("child readiness pipe")
        .read_exact(&mut ready)
        .expect("wait for child readiness");
    let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("child PID"));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime for the embedded actor");
    let (started, ready) = tokio::sync::oneshot::channel();
    runtime.block_on(async move {
        let (mut connection, _peer) = connection();
        connection.pid = Some(pid);
        tokio::spawn(async move {
            let _connection = connection;
            let _ = started.send(());
            std::future::pending::<()>().await;
        });
        ready.await.expect("embedded actor entered its task");
    });
    runtime.shutdown_timeout(Duration::from_secs(4));

    let result = nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG));
    let reaped = matches!(
        result,
        Err(nix::errno::Errno::ECHILD)
            | Ok(nix::sys::wait::WaitStatus::Exited(..) | nix::sys::wait::WaitStatus::Signaled(..),)
    );
    if !reaped {
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(pid, None);
    }
    let _ = child.wait();
    assert!(
        reaped,
        "server runtime shutdown must stop and reap the embedded process before handoff"
    );
}

#[test]
fn server_reload_mask_is_not_inherited_by_embedded_children() {
    use std::{
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };
    const NAME: &str =
        "embedded::regressions::server_reload_mask_is_not_inherited_by_embedded_children";
    if std::env::var_os("INFRATERNAL_CHILD_MASK_TEST").is_some() {
        let mut mask = nix::sys::signal::SigSet::empty();
        mask.add(nix::sys::signal::Signal::SIGHUP);
        nix::sys::signal::sigprocmask(nix::sys::signal::SigmaskHow::SIG_BLOCK, Some(&mask), None)
            .unwrap();
        let directory = std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/ca-handoff")
            .join(format!("mask-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&directory).unwrap();
        let script = directory.join("child");
        std::fs::write(&script, b"#!/usr/bin/python3\nimport os\nvalue=next(line.split()[1] for line in open('/proc/self/status') if line.startswith('SigBlk:'))\nos.write(3,(value+'\\n').encode())\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let blocked = runtime.block_on(async {
            let (mut channel, pid) = spawn_socketpair_agent(&script).unwrap();
            let mut reply = String::new();
            tokio::io::AsyncReadExt::read_to_string(&mut channel, &mut reply)
                .await
                .unwrap();
            nix::sys::wait::waitpid(pid.unwrap(), None).unwrap();
            u64::from_str_radix(reply.trim(), 16).unwrap()
        });
        std::fs::remove_dir_all(directory).unwrap();
        assert_eq!(
            blocked & 1,
            0,
            "server reload mask must not leak into child signal policy"
        );
        return;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_CHILD_MASK_TEST", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn trusted_person_account_and_fallback_metadata_cross_real_socket() {
    let (mut link, mut peer) = connection();
    link.execution_uid = 0;
    let person = uuid::Uuid::new_v4();
    let (reply, result) = oneshot::channel();
    let mut pending = HashMap::new();
    assert!(
        process_command(
            Command::Open {
                size: TerminalSize {
                    cols: 80,
                    rows: 24,
                    px_w: 0,
                    px_h: 0
                },
                login: Some(PersonLogin {
                    person,
                    account: Some("alice".into()),
                    grant: LoginGrant::default(),
                }),
                readiness: false,
                reply
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending
        )
        .await
    );
    let mut bytes = [0; 1024];
    let length = peer.read(&mut bytes).await.unwrap();
    let decoded = decode_muxed_frame(&bytes[..length]).unwrap();
    let Frame::Call {
        call_id,
        action_id,
        input_json,
    } = decoded.frame
    else {
        panic!("expected login open");
    };
    assert_eq!(action_id, "terminal.open");
    let input: serde_json::Value = serde_json::from_slice(input_json).unwrap();
    assert_eq!(input["uid"], 0);
    assert_eq!(input["person"], person.to_string());
    assert_eq!(input["account"], "alice");
    // The host checks the account it opens against this grant (D235 Q14).
    assert_eq!(
        input["grant"],
        serde_json::json!({"any_account": false, "accounts": [], "own_username": null})
    );
    let json = serde_json::to_vec(&serde_json::json!({"session_id":"01010101010101010101010101010101", "account":"root","requested_account":"alice","fallback":true,"note":"No user alice here, opened as root"})).unwrap();
    assert!(
        process_incoming(
            Incoming::Result {
                call_id,
                ok: true,
                json
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending
        )
        .await
    );
    let opened = result.await.unwrap().unwrap();
    assert_eq!(opened.session_id, [1; 16]);
    assert_eq!(opened.account.as_deref(), Some("root"));
    assert_eq!(opened.requested_account.as_deref(), Some("alice"));
    assert!(opened.fallback);
    assert_eq!(
        opened.note.as_deref(),
        Some("No user alice here, opened as root")
    );
}

#[tokio::test]
async fn prepare_uses_connection_uid_and_authenticated_person_without_terminal() {
    let (mut link, mut peer) = connection();
    link.execution_uid = 1001;
    let person = uuid::Uuid::new_v4();
    let (reply, _result) = oneshot::channel();
    assert!(
        process_command(
            Command::PrepareLogin {
                login: PersonLogin {
                    person,
                    account: Some("alice".into()),
                    grant: LoginGrant::default(),
                },
                reply
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut HashMap::new()
        )
        .await
    );
    let mut bytes = [0; 1024];
    let length = peer.read(&mut bytes).await.unwrap();
    let decoded = decode_muxed_frame(&bytes[..length]).unwrap();
    let Frame::Call {
        action_id,
        input_json,
        ..
    } = decoded.frame
    else {
        panic!("expected preparation");
    };
    assert_eq!(action_id, "terminal.login.prepare");
    let input: serde_json::Value = serde_json::from_slice(input_json).unwrap();
    assert_eq!(input["uid"], 1001);
    assert_eq!(input["person"], person.to_string());
    assert_eq!(input["account"], "alice");
}

#[tokio::test]
async fn canceled_preparations_release_control_capacity_and_late_replies_preserve_open() {
    let (mut link, mut peer) = connection();
    let mut pending = HashMap::new();
    let mut first_preparation = None;
    for _ in 0..=COMMAND_CAPACITY {
        let (reply, result) = oneshot::channel();
        assert!(
            process_command(
                Command::PrepareLogin {
                    login: PersonLogin {
                        person: uuid::Uuid::new_v4(),
                        account: Some("alice".into()),
                        grant: LoginGrant::default(),
                    },
                    reply
                },
                &mut link,
                &mut HashMap::new(),
                &mut HashMap::new(),
                &mut pending
            )
            .await
        );
        if first_preparation.is_none() {
            let mut wire = [0; 1024];
            let length = peer.read(&mut wire).await.unwrap();
            let decoded = decode_muxed_frame(&wire[..length]).unwrap();
            let Frame::Call { call_id, .. } = decoded.frame else {
                panic!("expected preparation");
            };
            first_preparation = Some(call_id);
        }
        // The websocket's bounded preparation timeout drops this receiver.
        drop(result);
    }
    let (reply, mut result) = oneshot::channel();
    assert!(
        process_command(
            Command::Open {
                size: TerminalSize {
                    cols: 80,
                    rows: 24,
                    px_w: 0,
                    px_h: 0
                },
                login: None,
                readiness: false,
                reply
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending
        )
        .await
    );
    assert!(
        matches!(result.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
        "canceled preparation exhausted ordinary control admission"
    );
    assert_eq!(
        pending.len(),
        1,
        "canceled preparation entries were retained"
    );
    let open_call = *pending.keys().next().unwrap();
    assert!(
        process_incoming(
            Incoming::Result {
                call_id: first_preparation.unwrap(),
                ok: true,
                json: b"{}".to_vec()
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending
        )
        .await,
        "late preparation reply restarted the shared connection"
    );
    assert!(pending.contains_key(&open_call));
    assert!(
        process_incoming(
            Incoming::Result {
                call_id: open_call,
                ok: true,
                json: br#"{"session_id":"01010101-0101-0101-0101-010101010101"}"#.to_vec()
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending
        )
        .await
    );
    assert_eq!(result.await.unwrap().unwrap().session_id, [1; 16]);
}

#[tokio::test]
async fn unknown_ordinary_result_remains_a_protocol_failure() {
    let (mut link, _peer) = connection();
    assert!(
        !process_incoming(
            Incoming::Result {
                call_id: 1,
                ok: true,
                json: b"{}".to_vec()
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut HashMap::new()
        )
        .await
    );
}

/// A revocation that carries D353's warning ("background programs of this
/// host account may still be running") is a completed revocation: the server
/// confirms it, instead of reading a protocol error and retrying forever
/// (#355). An unknown field is still refused.
#[cfg(feature = "remote")]
#[tokio::test]
async fn a_revocation_with_the_d353_warning_confirms_cleanup() {
    let (mut link, _peer) = connection();
    let (reply, result) = oneshot::channel();
    let mut pending = HashMap::from([(1, PendingCall::Revoke(reply))]);
    assert!(
        process_incoming(
            Incoming::Result {
                call_id: 1,
                ok: true,
                json: br#"{"revoked":true,"warning":"Background programs of this host account may still be running."}"#.to_vec()
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut pending
        )
        .await
    );
    assert!(
        result.await.unwrap().is_ok(),
        "a revocation with the D353 warning was not confirmed"
    );
}

/// A revocation carrying D356's `access` report is confirmed like any
/// other; an unknown field (the old `changed`) or a malformed report is
/// still a protocol error.
#[cfg(feature = "remote")]
#[tokio::test]
async fn a_revocation_with_changed_access_files_confirms_cleanup() {
    for (json, confirmed) in [
        (br#"{"revoked":true,"access":{"state":"changed","accounts":[{"account":"deploy","state":"changed","files":[{"path":"~/.ssh/authorized_keys","change":"changed","lines":["ssh-ed25519 AAAA left"]}],"truncated":false,"unscanned":[],"omitted_files":0}]}}"#.as_slice(), true),
        (br#"{"revoked":true,"changed":{"files":[],"truncated":false}}"#.as_slice(), false),
        (br#"{"revoked":true,"access":{"state":"bogus","accounts":[]}}"#.as_slice(), false),
    ] {
        let (mut link, _peer) = connection();
        let (reply, result) = oneshot::channel();
        let mut pending = HashMap::from([(1, PendingCall::Revoke(reply))]);
        assert!(
            process_incoming(
                Incoming::Result { call_id: 1, ok: true, json: json.to_vec() },
                &mut link,
                &mut HashMap::new(),
                &mut HashMap::new(),
                &mut pending
            )
            .await
        );
        assert_eq!(result.await.unwrap().is_ok(), confirmed, "{}", String::from_utf8_lossy(json));
    }
}

#[cfg(feature = "remote")]
#[tokio::test]
async fn invalid_login_revocation_ack_never_confirms_cleanup() {
    let (mut link, _peer) = connection();
    for json in [
        br#"{"revoked":false}"#.as_slice(),
        br"{}",
        br"[true]",
        br#"{"revoked":"true"}"#,
        br#"{"revoked":true,"extra":1}"#,
    ] {
        let (reply, result) = oneshot::channel();
        let mut pending = HashMap::from([(1, PendingCall::Revoke(reply))]);
        assert!(
            process_incoming(
                Incoming::Result {
                    call_id: 1,
                    ok: true,
                    json: json.to_vec()
                },
                &mut link,
                &mut HashMap::new(),
                &mut HashMap::new(),
                &mut pending
            )
            .await
        );
        assert!(
            result.await.unwrap().is_err(),
            "invalid cleanup acknowledgement confirmed retirement"
        );
    }
}
/// Plugin invalidations must survive the control-event census decoder during integration.
#[tokio::test]
async fn plugin_control_notice_preserves_capability_invalidation() {
    use tokio::io::AsyncWriteExt;
    for kind in ["plugin.event", "plugins.resync"] {
        let (mut link, mut peer) = connection();
        let event = serde_json::to_vec(&serde_json::json!({"type": kind})).unwrap();
        let mut wire = Vec::new();
        encode_muxed_frame_into(
            CONTROL_STREAM,
            &Frame::Event {
                sub_id: 0,
                event_json: &event,
            },
            &mut wire,
        )
        .unwrap();
        peer.write_all(&wire).await.unwrap();
        let incoming = read_incoming(&mut link).await;
        // A generic future notice may be discarded, but these notices must reach
        // the capability watch rather than silently retaining stale action grants.
        assert!(
            matches!(
                incoming,
                Some(Incoming::Event {
                    stream_id: CONTROL_STREAM,
                    ..
                })
            ),
            "plugin capability notice was discarded"
        );
    }
}

/// A successful greeting cannot erase earlier short-lived failures; this tests scheduling policy, not host latency.
#[tokio::test(start_paused = true)]
async fn greeted_links_that_die_young_escalate_the_actor_retry_delay() {
    let (attempts, mut observed) = mpsc::unbounded_channel();
    let mut connections = std::collections::VecDeque::new();
    for _ in 0..3 {
        let (mut link, _peer) = connection();
        let mut wire = Vec::new();
        encode_muxed_frame_into(
            CONTROL_STREAM,
            &Frame::Close {
                code: 1006,
                reason: "fixture link ended",
            },
            &mut wire,
        )
        .unwrap();
        link.receive.extend_from_slice(&wire);
        connections.push_back(link);
    }
    let (_commands, receiver) = mpsc::channel(1);
    let (changes, _notice) = watch::channel(());
    let (restarts, _restart_notice) = watch::channel(());
    let (inventory, _snapshot) = watch::channel(SessionInventoryState::Pending);
    let actor = tokio::spawn(run_actor(
        Source::Fixture {
            connections,
            attempts,
        },
        receiver,
        #[cfg(feature = "remote")]
        mpsc::unbounded_channel().1,
        changes,
        restarts,
        inventory,
    ));
    let first = observed.recv().await.unwrap();
    let second = observed.recv().await.unwrap();
    let third = observed.recv().await.unwrap();
    actor.await.unwrap();
    assert_eq!(second.duration_since(first), RECONNECT_FLOOR * 2);
    assert_eq!(third.duration_since(second), RECONNECT_FLOOR * 4);
}

/// The embedded actor reports a replacement process after its first connection is lost.
#[tokio::test(start_paused = true)]
async fn embedded_actor_notifies_when_the_infraternal_agent_reconnects() {
    use tokio::io::AsyncWriteExt;

    let (first, mut first_peer) = connection();
    let (second, _second_peer) = connection();
    let (attempts, _observed_attempts) = mpsc::unbounded_channel();
    let (_commands, receiver) = mpsc::channel(1);
    let (changes, mut connected) = watch::channel(());
    let (restarts, mut restart_notice) = watch::channel(());
    let (inventory, _snapshot) = watch::channel(SessionInventoryState::Pending);
    let actor = tokio::spawn(run_actor(
        Source::Fixture {
            connections: std::collections::VecDeque::from([first, second]),
            attempts,
        },
        receiver,
        #[cfg(feature = "remote")]
        mpsc::unbounded_channel().1,
        changes,
        restarts,
        inventory,
    ));

    tokio::time::timeout(Duration::from_secs(1), connected.changed())
        .await
        .expect("first infraternal agent connection starts")
        .expect("connection observer remains connected");
    assert!(
        !restart_notice
            .has_changed()
            .expect("restart observer remains connected"),
        "the initial connection is not a replacement"
    );

    let mut wire = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Close {
            code: 1006,
            reason: "fixture infraternal agent stopped",
        },
        &mut wire,
    )
    .expect("encode the first process closing");
    first_peer
        .write_all(&wire)
        .await
        .expect("close the first process connection");

    tokio::time::timeout(Duration::from_secs(1), restart_notice.changed())
        .await
        .expect("replacement notification arrives")
        .expect("restart observer remains connected");
    actor.abort();
    let _ = actor.await;
}

/// A replacement embedded infraternal agent starts only after the retired one is reaped (#562).
///
/// J1034 (compute01, load ~60) saw every respawn fail with `address in use`: the retired child
/// still answered on its per-user `plugins.sock` while its replacement started 200–800 ms later.
/// The fixture child stands in for that socket with a pid file: a child that finds its
/// predecessor alive records a collision and exits, as the real one does. The first child greets,
/// drops its link with a Close, and then ignores SIGTERM, the way a starved child holds its
/// sockets through the whole 2 s grace. The replacement must greet without any collision.
#[tokio::test]
async fn replacement_child_waits_for_the_retired_child_to_be_reaped() {
    use std::os::unix::fs::PermissionsExt;
    let directory = std::env::temp_dir().join(format!(
        "j562-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    std::fs::create_dir(&directory).unwrap();
    let mut hello = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "fixture",
        },
        &mut hello,
    )
    .unwrap();
    std::fs::write(directory.join("hello"), hello).unwrap();
    let mut close = Vec::new();
    encode_muxed_frame_into(
        CONTROL_STREAM,
        &Frame::Close {
            code: 1006,
            reason: "fixture link ended",
        },
        &mut close,
    )
    .unwrap();
    std::fs::write(directory.join("close"), close).unwrap();
    let script = directory.join("agent");
    // `kill -0` also succeeds for an unreaped zombie, so a predecessor counts as gone only once
    // the server has reaped it. Every child exits on its own after 6 s.
    let body = format!(
        "#!/bin/sh\n\
         cd '{}' || exit 2\n\
         trap '' TERM\n\
         if [ -s live ] && kill -0 \"$(cat live)\" 2>/dev/null; then echo \"$$ $(cat live)\" >> collisions; exit 1; fi\n\
         echo $$ > live\n\
         echo $$ >> started\n\
         cat hello >&3\n\
         if [ ! -e dropped ]; then : > dropped; cat close >&3; fi\n\
         exec sleep 6\n",
        directory.display()
    );
    std::fs::write(&script, body).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

    let started = std::time::Instant::now();
    let agent = EmbeddedAgent::spawn(script);
    let mut restarts = agent.restarts();
    let replaced = tokio::time::timeout(Duration::from_secs(15), restarts.changed()).await;
    let elapsed = started.elapsed();
    let collisions = std::fs::read_to_string(directory.join("collisions")).unwrap_or_default();
    let children = std::fs::read_to_string(directory.join("started")).unwrap_or_default();
    drop(agent);
    // The actor stops and reaps its current child before it returns, and it owns the `restarts`
    // sender, so `changed` fails only after that reap. Waiting for it keeps the directory
    // unchanged while a child is still starting; otherwise the child creates files after
    // `remove_dir_all` has listed the directory (J1162: DirectoryNotEmpty under load).
    while restarts.changed().await.is_ok() {}
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(
        replaced.is_ok_and(|changed| changed.is_ok()),
        "the replacement infraternal agent never greeted (children: {children:?})"
    );
    assert_eq!(
        collisions, "",
        "a replacement started while its predecessor was alive (`new old` pids)"
    );
    assert_eq!(
        children.lines().count(),
        2,
        "one retired child and one replacement"
    );
    // The replacement waits for the 2 s grace and the reap, not for extra backoff.
    assert!(
        elapsed < Duration::from_secs(8),
        "replacement took {elapsed:?}"
    );
}

#[path = "embedded_path_tests.rs"]
mod path_tests;

#[path = "liveness_doubt_breakit_tests.rs"]
mod liveness_doubt_breakit_tests;

#[path = "embedded_credit_tests.rs"]
mod credit_tests;
#[tokio::test]
async fn half_open_infraternal_agent_route_loses_inventory_without_eof() {
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let agent = EmbeddedAgent::from_test_socket(socket);
    let mut inventory = agent.session_inventory();
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "liveness fixture",
        },
        &mut wire,
    )
    .unwrap();
    peer.write_all(&wire).await.unwrap();
    encode_muxed_frame_into(0, &Frame::Event { sub_id: 0, event_json: br#"{"type":"terminal.sessions.snapshot","session_ids":["01010101-0101-0101-0101-010101010101"]}"# }, &mut wire).unwrap();
    peer.write_all(&wire).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), inventory.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        *inventory.borrow_and_update(),
        SessionInventoryState::Available(_)
    ));
    let _attachment = agent.attach([1; 16], 0, 0, 2).await.unwrap();
    // The peer is held open and its kernel buffers accept probes, but it never answers.
    tokio::time::timeout(Duration::from_secs(3), inventory.changed())
        .await
        .expect("half-open upstream must expire without EOF")
        .unwrap();
    assert_eq!(*inventory.borrow(), SessionInventoryState::Unavailable);
    drop(peer);
}

/// A link that already carries the most terminal streams refuses the next attach at once, with its own
/// error, instead of sending it to a host that will not answer (#562). The bound itself is unchanged
/// (D214), and a stream already attached may still be re-attached.
#[tokio::test]
async fn attach_past_the_stream_limit_is_refused_at_once() {
    let limit = infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS;
    let (socket, mut peer) = UnixStream::pair().unwrap();
    let agent = EmbeddedAgent::from_test_socket(socket);
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "stream limit fixture",
        },
        &mut wire,
    )
    .unwrap();
    peer.write_all(&wire).await.unwrap();
    let mut attached = Vec::new();
    for index in 0..limit {
        let stream = 2 + 2 * u32::try_from(index).unwrap();
        attached.push(
            agent
                .attach([1; 16], 0, 0, stream)
                .await
                .unwrap_or_else(|error| panic!("stream {index} of {limit}: {error:?}")),
        );
    }
    let next = 2 + 2 * u32::try_from(limit).unwrap();
    let started = std::time::Instant::now();
    let refused = tokio::time::timeout(Duration::from_secs(1), agent.attach([2; 16], 0, 0, next))
        .await
        .expect("a full link answers at once, not after the client's timeout");
    assert!(matches!(refused, Err(AgentError::StreamLimit)));
    assert!(started.elapsed() < Duration::from_millis(500));
    // The same session on a stream already routed is a reattach, not a new stream.
    agent
        .attach([1; 16], 0, 0, 2)
        .await
        .expect("a reattach of an attached stream passes the bound");
    drop(attached);
}

/// Control replies may be skipped when the bounded FIFO is full; the peer's
/// correlated reply deadline, rather than local admission, decides liveness.
#[cfg(feature = "remote")]
#[tokio::test]
async fn saturated_control_pong_does_not_retire_connection() {
    let (mut link, _peer) = connection();
    let (sender, mut receiver) = mpsc::channel(1);
    sender.try_send(Bytes::from_static(b"queued")).unwrap();
    link.owned_control = Some(sender);
    assert!(
        process_incoming(
            Incoming::Ping {
                nonce: 7,
                sent_us: 9
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut HashMap::new(),
        )
        .await,
        "Pong admission must not retire the primary"
    );
    assert_eq!(
        receiver.recv().await.unwrap(),
        Bytes::from_static(b"queued")
    );
    assert!(
        process_incoming(
            Incoming::Ping {
                nonce: 8,
                sent_us: 10
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut HashMap::new(),
        )
        .await
    );
    let encoded = receiver.recv().await.unwrap();
    assert_eq!(
        infraternal_protocol::decode_frame(&encoded).unwrap().frame,
        Frame::Pong {
            nonce: 8,
            sent_us: 10
        }
    );
    drop(receiver);
    assert!(
        !process_incoming(
            Incoming::Ping {
                nonce: 9,
                sent_us: 11
            },
            &mut link,
            &mut HashMap::new(),
            &mut HashMap::new(),
            &mut HashMap::new(),
        )
        .await,
        "a closed writer remains a connection failure"
    );
}

#[path = "liveness_doubt_breakit_r2_tests.rs"]
mod liveness_doubt_breakit_r2_tests;

#[test]
fn query_reply_compatibility_notice_is_strict_and_session_bound() {
    let id = uuid::Uuid::from_bytes([1; 16]).to_string();
    let json = serde_json::json!({"type":"terminal.query_replies_unavailable", "session_id":id});
    let notice: TerminalNotice = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(notice.session_id(), id);
    let mut extra = json;
    extra["bytes"] = serde_json::json!("unexpected");
    assert!(serde_json::from_value::<TerminalNotice>(extra).is_err());
}

/// An open refusal with a reason this server does not know (from a newer
/// infraternal agent) reads as "could not start a shell, try again", not as
/// an offline host. Known reasons pass through, and non-refusal replies stay
/// protocol errors (J308 P3-3, #355).
#[test]
fn an_unknown_refusal_reason_reads_as_could_not_start_a_shell() {
    use infraternal_plugin_api::admission::OpenRefusal;
    assert_eq!(
        super::refused_open(br#"{"error":"terminal unavailable","reason":"some_future_reason"}"#),
        AgentError::OpenRefused(OpenRefusal::ResourceUnavailable)
    );
    assert_eq!(
        super::refused_open(br#"{"error":"terminal unavailable","reason":"invalid"}"#),
        AgentError::OpenRefused(OpenRefusal::Invalid)
    );
    assert_eq!(super::refused_open(b"not json"), AgentError::Rejected);
    assert_eq!(
        super::refused_open(br#"{"ok":false}"#),
        AgentError::Rejected
    );
}

/// A fresh lease on the same host transport never accepts a delayed old Pong.
#[tokio::test(start_paused = true)]
async fn j1264_fresh_host_lease_keeps_nonce_sequence_and_rejects_stale_pong() {
    let mut liveness = Liveness::host_link();
    let mut doubted = vec![17];
    let old_probe = liveness.ping();

    fresh_host_lease(&mut liveness, &mut doubted);

    assert!(doubted.is_empty());
    let new_probe = liveness.ping();
    assert!(
        new_probe.0 > old_probe.0,
        "host probe ids must not be reused"
    );
    assert!(
        !liveness.pong(old_probe.0, old_probe.1),
        "a delayed Pong from before the lease restart must be ignored"
    );
    assert!(liveness.pong(new_probe.0, new_probe.1));
}
