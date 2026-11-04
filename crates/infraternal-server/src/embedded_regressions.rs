//! Actor isolation, restart-credit and stream-retirement regressions using real Unix sockets.
use super::*;

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
        route: None,
        proof_rebind_pending: false,
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
async fn idle_route_proofs_do_not_queue_payload_notifications_at_capacity() {
    let (mut link, mut peer) = connection();
    let mut attachments = HashMap::new();
    let mut routes = HashMap::new();
    let mut readers = Vec::new();
    let mut pending = HashMap::new();
    for id in 1..=128_u32 {
        let stream = id * 2;
        let (output, reader) = mpsc::channel(4);
        attachments.insert(
            u64::from(id),
            AttachmentState {
                stream_id: stream,
                route: Some(Liveness::new()),
                ..attachment(output)
            },
        );
        routes.insert(stream, u64::from(id));
        readers.push(reader);
        let mut wire = Vec::new();
        encode_muxed_frame_into(
            1,
            &Frame::Ping {
                nonce: u64::from(id),
                sent_us: u64::from(id),
            },
            &mut wire,
        )
        .unwrap();
        assert!(
            process_command(
                Command::Input {
                    attachment_id: u64::from(id),
                    frame: Bytes::copy_from_slice(&wire),
                },
                &mut link,
                &mut attachments,
                &mut routes,
                &mut pending,
            )
            .await
        );
        let mut request = vec![0; 64];
        let count = peer.read(&mut request).await.unwrap();
        let decoded = decode_muxed_frame(&request[..count]).unwrap();
        assert_eq!(decoded.stream_id, stream);
        assert!(matches!(decoded.frame, Frame::Ping { .. }));
        encode_muxed_frame_into(
            stream,
            &Frame::Pong {
                nonce: u64::from(id),
                sent_us: u64::from(id),
            },
            &mut wire,
        )
        .unwrap();
        peer.write_all(&wire).await.unwrap();
        let incoming = read_incoming(&mut link).await.unwrap();
        assert!(
            process_incoming(
                incoming,
                &mut link,
                &mut attachments,
                &mut routes,
                &mut pending,
            )
            .await
        );
    }
    // Proofs are content-free bookkeeping. Delivering one through every payload
    // queue wakes every attachment forwarder and browser loop on every probe tick.
    assert!(
        readers.iter().all(mpsc::Receiver::is_empty),
        "idle proofs woke per-session payload consumers"
    );
}

#[tokio::test]
async fn actor_batch_probes_every_ready_route_without_payload_notifications() {
    let (mut link, mut peer) = connection();
    let mut attachments = HashMap::new();
    let mut routes = HashMap::new();
    let mut readers = Vec::new();
    for id in 1..=128_u32 {
        let (output, reader) = mpsc::channel(4);
        attachments.insert(
            u64::from(id),
            AttachmentState {
                stream_id: id * 2,
                route: Some(Liveness::new()),
                awaiting_ack: id == 128,
                ..attachment(output)
            },
        );
        routes.insert(id * 2, u64::from(id));
        readers.push(reader);
    }
    let mut queued = std::collections::VecDeque::from([999, 128]);
    assert!(
        route_proofs::tick(
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new(),
            true,
            &mut queued,
        )
        .await
    );
    assert!(
        queued.is_empty(),
        "stale and awaiting-ack probes must be pruned"
    );
    let mut wire = vec![0; 4096];
    let count = peer.read(&mut wire).await.unwrap();
    let mut offset = 0;
    let mut seen = std::collections::HashSet::new();
    while offset < count {
        let decoded = decode_muxed_frame(&wire[offset..count]).unwrap();
        let Frame::Ping { nonce, sent_us } = decoded.frame else {
            panic!("batch must contain only route probes");
        };
        assert!(seen.insert(decoded.stream_id));
        assert!(
            process_incoming(
                Incoming::Pong {
                    stream_id: decoded.stream_id,
                    nonce,
                    sent_us,
                },
                &mut link,
                &mut attachments,
                &mut routes,
                &mut HashMap::new(),
            )
            .await
        );
        offset += decoded.wire_len;
    }
    assert_eq!(seen.len(), 127, "the unacknowledged writer must not probe");
    assert!(!seen.contains(&256));
    assert!(readers.iter().all(mpsc::Receiver::is_empty));
    assert!(
        attachments
            .values()
            .all(|a| !a.route.as_ref().unwrap().expired())
    );
}

/// Route probes cross the shim fence even when native input has its own bounded writer.
#[cfg(feature = "remote")]
#[test]
fn native_input_retention_leaves_terminal_probes_to_the_route() {
    let (output, _receiver) = mpsc::channel(4);
    let mut attachments = HashMap::from([(1, attachment(output))]);
    let mut routes = HashMap::from([(2, 1)]);
    let mut writes = writes::State::default();
    writes.enable(&attachments);
    let mut frame = Vec::new();
    encode_muxed_frame_into(
        1,
        &Frame::Ping {
            nonce: 7,
            sent_us: 7,
        },
        &mut frame,
    )
    .unwrap();
    let command = Command::Input {
        attachment_id: 1,
        frame: Bytes::from(frame),
    };
    assert_eq!(
        retain_owned_input(&command, &mut attachments, &mut routes, &mut writes),
        None
    );
    assert_eq!(attachments.len(), 1);
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
                monitored: false,
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
                monitored: false,
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
#[allow(clippy::too_many_lines)]
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
        inventory,
    ));
    let first = observed.recv().await.unwrap();
    let second = observed.recv().await.unwrap();
    let third = observed.recv().await.unwrap();
    actor.await.unwrap();
    assert_eq!(second.duration_since(first), RECONNECT_FLOOR * 2);
    assert_eq!(third.duration_since(second), RECONNECT_FLOOR * 4);
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

/// An expired browser route must wait for authenticated consumer admission before backend work.
#[tokio::test(start_paused = true)]
async fn expired_route_waits_for_browser_authority_before_rebind() {
    let (mut link, mut peer) = connection();
    let (output, mut reader) = mpsc::channel(4);
    let mut lease = Liveness::new();
    lease.ping();
    tokio::time::advance(Duration::from_secs(3)).await;
    let mut attachments = HashMap::from([(
        1,
        AttachmentState {
            route: Some(lease),
            unacknowledged: BytesMut::from(&b"retained"[..]),
            ..attachment(output)
        },
    )]);
    let mut routes = HashMap::from([(2, 1)]);
    assert!(
        route_proofs::tick(
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new(),
            true,
            &mut std::collections::VecDeque::new()
        )
        .await
    );
    assert!(
        reader.try_recv().is_ok(),
        "consumer must observe the transition"
    );
    let mut wire = [0; 256];
    assert!(
        tokio::time::timeout(Duration::from_millis(1), peer.read(&mut wire))
            .await
            .is_err(),
        "expiry performed backend work before browser authority"
    );
}

/// A full consumer cannot lose the readiness transition and retain a live backend route.
#[tokio::test(start_paused = true)]
async fn expired_route_retires_full_consumer() {
    let (mut link, mut peer) = connection();
    let (output, _reader) = mpsc::channel(1);
    output.try_send(TerminalOutput::Reconnecting).unwrap();
    let mut lease = Liveness::new();
    lease.ping();
    tokio::time::advance(Duration::from_secs(3)).await;
    let mut attachments = HashMap::from([(
        1,
        AttachmentState {
            route: Some(lease),
            ..attachment(output)
        },
    )]);
    let mut routes = HashMap::from([(2, 1)]);
    assert!(
        route_proofs::tick(
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new(),
            true,
            &mut std::collections::VecDeque::new()
        )
        .await
    );
    assert!(attachments.is_empty());
    assert!(routes.is_empty());
    let mut wire = [0; 256];
    let count = peer.read(&mut wire).await.unwrap();
    assert!(matches!(
        decode_muxed_frame(&wire[..count]).unwrap().frame,
        Frame::Close { code: 1000, .. }
    ));
}

/// A queued expiry notice must not rebind a route already restored by shared recovery.
#[tokio::test(start_paused = true)]
async fn recovered_route_ignores_stale_browser_rebind() {
    let (mut link, mut peer) = connection();
    let (output, _reader) = mpsc::channel(4);
    let mut attachments = HashMap::from([(
        1,
        AttachmentState {
            route: Some(Liveness::new()),
            ..attachment(output)
        },
    )]);
    assert!(
        process_command(
            Command::Reconnect { attachment_id: 1 },
            &mut link,
            &mut attachments,
            &mut HashMap::from([(2, 1)]),
            &mut HashMap::new()
        )
        .await
    );
    let mut wire = [0; 256];
    assert!(
        tokio::time::timeout(Duration::from_millis(1), peer.read(&mut wire))
            .await
            .is_err()
    );
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
