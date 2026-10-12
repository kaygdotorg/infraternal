//! Exercises outstanding input across leg-B replacement using real Unix sockets and authoritative shim Acks [128,215].
use super::*;

fn input_command(sequence: u64, bytes: &[u8]) -> Command {
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(
        1,
        &Frame::Input {
            in_seq: sequence,
            bytes,
        },
        &mut wire,
    )
    .unwrap();
    Command::Input {
        attachment_id: 1,
        frame: Bytes::from(wire),
    }
}

async fn receive(peer: &mut UnixStream) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    let count = tokio::time::timeout(Duration::from_secs(2), peer.read(&mut bytes))
        .await
        .expect("frame before deadline")
        .unwrap();
    bytes.truncate(count);
    bytes
}

#[tokio::test]
async fn replacement_replays_only_the_unacknowledged_suffix_and_queued_input() {
    let (mut old, mut old_peer) = connection();
    let (tx, _output) = mpsc::channel(8);
    let mut attachments = HashMap::from([(1, attachment(tx))]);
    let mut routes = HashMap::from([(2, 1)]);
    let mut pending = HashMap::new();
    assert!(
        process_command(
            input_command(0, b"abcdef"),
            &mut old,
            &mut attachments,
            &mut routes,
            &mut pending
        )
        .await
    );
    let wire = receive(&mut old_peer).await;
    assert!(matches!(
        decode_muxed_frame(&wire).unwrap().frame,
        Frame::Input {
            in_seq: 0,
            bytes: b"abcdef"
        }
    ));
    connection_lost(old, &mut attachments, &mut routes, &mut pending).await;
    let (mut new, mut new_peer) = connection();
    assert!(reattach_all(&mut new, &mut attachments, &mut routes).await);
    let wire = receive(&mut new_peer).await;
    assert!(matches!(
        decode_muxed_frame(&wire).unwrap().frame,
        Frame::AttachTerm { last_in_seq: 0, .. }
    ));
    // The consumer stays connected while leg B moves. New input must wait for
    // the shim's Ack, because only the shim knows how far old input reached.
    assert!(
        process_command(
            input_command(6, b"ghi"),
            &mut new,
            &mut attachments,
            &mut routes,
            &mut pending
        )
        .await
    );
    assert!(
        process_incoming(
            Incoming::Ack {
                stream_id: 2,
                in_seq_acked: 3
            },
            &mut new,
            &mut attachments,
            &mut routes,
            &mut pending
        )
        .await
    );
    let wire = receive(&mut new_peer).await;
    assert_eq!(
        decode_muxed_frame(&wire).unwrap().frame,
        Frame::Input {
            in_seq: 3,
            bytes: b"defghi"
        }
    );
    assert_eq!(attachments[&1].last_input_end, 9);
}

#[tokio::test]
async fn full_ack_releases_retention_and_duplicate_input_is_not_replayed() {
    let (mut link, mut peer) = connection();
    let (tx, _output) = mpsc::channel(8);
    let mut attachments = HashMap::from([(1, attachment(tx))]);
    let mut routes = HashMap::from([(2, 1)]);
    let mut pending = HashMap::new();
    assert!(
        process_command(
            input_command(0, b"abc"),
            &mut link,
            &mut attachments,
            &mut routes,
            &mut pending
        )
        .await
    );
    let _ = receive(&mut peer).await;
    assert!(
        process_incoming(
            Incoming::Ack {
                stream_id: 2,
                in_seq_acked: 3
            },
            &mut link,
            &mut attachments,
            &mut routes,
            &mut pending
        )
        .await
    );
    assert_eq!(attachments[&1].unacknowledged.capacity(), 0);
    assert!(
        process_command(
            input_command(0, b"abc"),
            &mut link,
            &mut attachments,
            &mut routes,
            &mut pending
        )
        .await
    );
    assert!(attachments[&1].unacknowledged.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(25), peer.read(&mut [0; 64]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn input_retention_refuses_excess_before_advancing_the_cursor() {
    let (mut link, _peer) = connection();
    let (tx, _output) = mpsc::channel(8);
    let mut state = attachment(tx);
    state.awaiting_ack = true;
    state.replaying = true;
    let mut attachments = HashMap::from([(1, state)]);
    let mut routes = HashMap::from([(2, 1)]);
    let mut pending = HashMap::new();
    let bytes = vec![b'x'; MAX_FRAME_LEN / 2];
    for sequence in [0, (MAX_FRAME_LEN / 2) as u64] {
        assert!(
            process_command(
                input_command(sequence, &bytes),
                &mut link,
                &mut attachments,
                &mut routes,
                &mut pending
            )
            .await
        );
    }
    assert!(
        process_command(
            input_command(MAX_FRAME_LEN as u64, b"x"),
            &mut link,
            &mut attachments,
            &mut routes,
            &mut pending
        )
        .await
    );
    assert!(!attachments.contains_key(&1));
    assert!(!routes.contains_key(&2));
}

#[tokio::test]
async fn initial_attachment_keeps_input_cut_through_before_its_first_ack() {
    let (mut link, mut peer) = connection();
    let (tx, _output) = mpsc::channel(8);
    let mut state = attachment(tx);
    state.awaiting_ack = true;
    let mut attachments = HashMap::from([(1, state)]);
    let mut routes = HashMap::from([(2, 1)]);
    assert!(
        process_command(
            input_command(0, b"abc"),
            &mut link,
            &mut attachments,
            &mut routes,
            &mut HashMap::new()
        )
        .await
    );
    let wire = receive(&mut peer).await;
    assert_eq!(
        decode_muxed_frame(&wire).unwrap().frame,
        Frame::Input {
            in_seq: 0,
            bytes: b"abc"
        }
    );
}

#[tokio::test]
#[ignore = "Run alone on the perf VM under the shared benchmark lock."]
async fn input_retention_cost_at_200_terminals() {
    let mut terminals = Vec::new();
    for _ in 0..200 {
        let (connection, peer) = connection();
        let (tx, output) = mpsc::channel(8);
        terminals.push((
            connection,
            peer,
            HashMap::from([(1, attachment(tx))]),
            HashMap::from([(2, 1)]),
            output,
        ));
    }
    let mut samples = Vec::new();
    let mut peak_retained = 0;
    for sequence in 0..31 {
        for (link, peer, attachments, routes, _) in &mut terminals {
            let started = std::time::Instant::now();
            assert!(
                process_command(
                    input_command(sequence, b"x"),
                    link,
                    attachments,
                    routes,
                    &mut HashMap::new()
                )
                .await
            );
            samples.push(started.elapsed().as_nanos());
            let wire = receive(peer).await;
            assert_eq!(
                decode_muxed_frame(&wire).unwrap().frame,
                Frame::Input {
                    in_seq: sequence,
                    bytes: b"x"
                }
            );
        }
        peak_retained = peak_retained.max(
            terminals
                .iter()
                .map(|(_, _, state, _, _)| state[&1].unacknowledged.capacity())
                .sum::<usize>(),
        );
        for (link, _, attachments, routes, output) in &mut terminals {
            assert!(
                process_incoming(
                    Incoming::Ack {
                        stream_id: 2,
                        in_seq_acked: sequence + 1
                    },
                    link,
                    attachments,
                    routes,
                    &mut HashMap::new()
                )
                .await
            );
            assert!(output.recv().await.is_some());
        }
    }
    samples.sort_unstable();
    let retained: usize = terminals
        .iter()
        .map(|(_, _, state, _, _)| state[&1].unacknowledged.capacity())
        .sum();
    assert_eq!(retained, 0);
    println!(
        "METRIC input_retention machine={} terminals=200 samples={} write_p50_ns={} write_p99_ns={} peak_buffer_bytes={} full_ack_buffer_bytes={} state_bytes_per_terminal={} max_buffer_bytes_per_terminal={} load={}",
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        samples.len(),
        samples[samples.len() / 2],
        samples[samples.len() * 99 / 100],
        peak_retained,
        retained,
        std::mem::size_of::<AttachmentState>(),
        MAX_FRAME_LEN,
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}

#[tokio::test]
async fn full_retention_replays_as_legal_frames_with_contiguous_offsets() {
    let (mut link, mut peer) = connection();
    let (tx, _output) = mpsc::channel(8);
    let mut state = attachment(tx);
    state.awaiting_ack = true;
    state.replaying = true;
    let mut attachments = HashMap::from([(1, state)]);
    let mut routes = HashMap::from([(2, 1)]);
    let mut pending = HashMap::new();
    let bytes = vec![b'x'; MAX_FRAME_LEN / 2];
    for sequence in [0, (MAX_FRAME_LEN / 2) as u64] {
        assert!(
            process_command(
                input_command(sequence, &bytes),
                &mut link,
                &mut attachments,
                &mut routes,
                &mut pending
            )
            .await
        );
    }
    let reader = tokio::spawn(async move {
        let mut wire = Vec::new();
        peer.read_to_end(&mut wire).await.unwrap();
        wire
    });
    let replayed = process_incoming(
        Incoming::Ack {
            stream_id: 2,
            in_seq_acked: 0,
        },
        &mut link,
        &mut attachments,
        &mut routes,
        &mut pending,
    )
    .await;
    drop(link);
    let wire = reader.await.unwrap();
    assert!(
        replayed,
        "retained aggregate must not exceed a single frame payload limit"
    );
    let mut remaining = wire.as_slice();
    let mut offset = 0;
    while !remaining.is_empty() {
        let decoded = decode_muxed_frame(remaining).unwrap();
        assert_eq!(decoded.stream_id, 2);
        let Frame::Input { in_seq, bytes } = decoded.frame else {
            panic!("input frame required");
        };
        assert_eq!(in_seq, offset);
        assert!(bytes.iter().all(|byte| *byte == b'x'));
        offset += bytes.len() as u64;
        remaining = &remaining[decoded.wire_len..];
    }
    assert_eq!(offset, MAX_FRAME_LEN as u64);
    assert_eq!(attachments[&1].unacknowledged.len(), MAX_FRAME_LEN);
}

/// Resource exhaustion on one writer must preserve other people's attachments
/// on the same infraternal host transport (wire contract section 6).
#[tokio::test]
async fn review_pending_input_limit_retires_only_its_attachment() {
    let (mut link, _peer) = connection();
    let (tx, _output) = mpsc::channel(8);
    let (sibling_tx, _sibling_output) = mpsc::channel(8);
    let mut first = attachment(tx);
    first.awaiting_ack = true;
    first.replaying = true;
    let mut sibling = attachment(sibling_tx);
    sibling.stream_id = 4;
    let mut attachments = HashMap::from([(1, first), (2, sibling)]);
    let mut routes = HashMap::from([(2, 1), (4, 2)]);
    let mut pending = HashMap::new();
    let bytes = vec![b'x'; MAX_FRAME_LEN / 2];
    for sequence in [0, (MAX_FRAME_LEN / 2) as u64] {
        assert!(
            process_command(
                input_command(sequence, &bytes),
                &mut link,
                &mut attachments,
                &mut routes,
                &mut pending,
            )
            .await
        );
    }
    let healthy = process_command(
        input_command(MAX_FRAME_LEN as u64, b"x"),
        &mut link,
        &mut attachments,
        &mut routes,
        &mut pending,
    )
    .await;
    assert!(
        healthy,
        "pending-input exhaustion must keep the shared host transport live"
    );
    assert!(
        !attachments.contains_key(&1),
        "the full writer must be retired"
    );
    assert!(
        attachments.contains_key(&2),
        "the sibling writer must remain attached"
    );
    assert_eq!(routes.get(&4), Some(&2));
}
