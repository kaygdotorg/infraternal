//! Exercises per-writer retained-input credit with the real actor/socket, including sibling progress and exact resumption [128,215], #129.
use super::*;

fn wire(stream: u32, frame: &Frame<'_>) -> Bytes {
    let mut bytes = Vec::new();
    encode_muxed_frame_into(stream, frame, &mut bytes).unwrap();
    Bytes::from(bytes)
}

async fn next_wire(peer: &mut UnixStream, buffered: &mut BytesMut) -> Bytes {
    loop {
        if let Ok(decoded) = decode_muxed_frame(buffered) {
            return buffered.split_to(decoded.wire_len).freeze();
        }
        assert_ne!(peer.read_buf(buffered).await.unwrap(), 0);
    }
}

struct Fixture {
    records: mpsc::Receiver<(u32, u64, usize, u8)>,
    ack: mpsc::Sender<(u32, u64)>,
    task: tokio::task::JoinHandle<()>,
}

fn fixture(mut peer: UnixStream) -> Fixture {
    let (observed, records) = mpsc::channel(16);
    let (ack, mut acknowledgements) = mpsc::channel::<(u32, u64)>(4);
    let fixture = tokio::spawn(async move {
        let mut buffered = BytesMut::with_capacity(4096);
        let hello = next_wire(&mut peer, &mut buffered).await;
        assert!(matches!(
            decode_muxed_frame(&hello).unwrap().frame,
            Frame::Hello { .. }
        ));
        peer.write_all(&wire(
            0,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "fixture",
            },
        ))
        .await
        .unwrap();
        loop {
            tokio::select! {
                frame = next_wire(&mut peer, &mut buffered) => {
                    let decoded = decode_muxed_frame(&frame).unwrap();
                    match decoded.frame {
                        Frame::AttachTerm { .. } => {
                            peer.write_all(&wire(decoded.stream_id, &Frame::Ack { in_seq_acked: 0 })).await.unwrap();
                        }
                        Frame::Input { in_seq, bytes } => {
                            observed.send((decoded.stream_id, in_seq, bytes.len(), bytes[0])).await.unwrap();
                        }
                        _ => {}
                    }
                }
                Some((stream, sequence)) = acknowledgements.recv() => {
                    peer.write_all(&wire(stream, &Frame::Ack { in_seq_acked: sequence })).await.unwrap();
                }
            }
        }
    });
    Fixture {
        records,
        ack,
        task: fixture,
    }
}

#[tokio::test]
async fn retained_input_credit_parks_only_the_full_writer_until_its_ack() {
    let (socket, peer) = UnixStream::pair().unwrap();
    let actor = EmbeddedAgent::from_test_socket(socket);
    let Fixture {
        mut records,
        ack,
        task: fixture,
    } = fixture(peer);
    let first = actor.attach([1; 16], 0, 0, 2).await.unwrap();
    let sibling = actor.attach([2; 16], 0, 0, 4).await.unwrap();
    let (first, _output) = first.split();
    let (sibling, _sibling_output) = sibling.split();
    let bytes = vec![b'x'; MAX_FRAME_LEN / 2];
    for sequence in [0, (MAX_FRAME_LEN / 2) as u64] {
        first
            .send_frame(wire(
                1,
                &Frame::Input {
                    in_seq: sequence,
                    bytes: &bytes,
                },
            ))
            .await
            .unwrap();
        assert_eq!(
            records.recv().await.unwrap(),
            (2, sequence, bytes.len(), b'x')
        );
    }
    let input = first.clone();
    let blocked = tokio::spawn(async move {
        input
            .send_frame(wire(
                1,
                &Frame::Input {
                    in_seq: MAX_FRAME_LEN as u64,
                    bytes: b"z",
                },
            ))
            .await
    });
    // Credit is exhausted even though the ordinary frame-count queue is empty.
    // Keep the task alive after the timeout: its byte must resume exactly once.
    let mut blocked = blocked;
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut blocked)
            .await
            .is_err(),
        "a full writer must wait for retained-byte credit"
    );
    sibling
        .send_frame(wire(
            3,
            &Frame::Input {
                in_seq: 0,
                bytes: b"s",
            },
        ))
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), records.recv())
            .await
            .unwrap()
            .unwrap(),
        (4, 0, 1, b's')
    );
    ack.send((2, 1)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), blocked)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        records.recv().await.unwrap(),
        (2, MAX_FRAME_LEN as u64, 1, b'z')
    );
    ack.send((2, MAX_FRAME_LEN as u64 + 1)).await.unwrap();
    fixture.abort();
    let _ = fixture.await;
}
