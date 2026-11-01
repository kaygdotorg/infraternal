//! Frame regression and measurement harness, separated from production code [40].
use super::*;

#[cfg(feature = "process-per-user")]
#[test]
fn borrowed_output_keeps_frozen_bytes_and_refuses_before_batch_mutation() {
    let frozen = [12, 0, 0, 0, 0x11, 42, 0, 0, 0, 0, 0, 0, 0, b'a', b'b', b'c'];
    let mut wire = Vec::new();
    Frame::output_slices_into::<false>(42, b"a", b"bc", &mut wire).unwrap();
    assert_eq!(wire, frozen);
    Frame::output_slices_into::<true>(42, b"ab", b"c", &mut wire).unwrap();
    assert_eq!(wire, [frozen, frozen].concat());
    let before = wire.clone();
    let oversized = vec![0; MAX_FRAME];
    assert!(Frame::output_slices_into::<true>(0, &oversized, &[], &mut wire).is_err());
    assert_eq!(wire, before);
    assert!(Frame::output_slices_into::<false>(0, &[], &oversized, &mut wire).is_err());
    assert_eq!(wire, before);
}
#[cfg(test)]
mod tests {
    //! Exercises frame invariants against real data and frozen expectations.
    use super::*;
    #[cfg(feature = "process-per-user")]
    #[test]
    fn batch_append_preserves_prefix_and_refuses_invalid_frames() {
        let state = Frame::InputState(17, 19);
        let output = Frame::Output(42, b"reply".to_vec());
        let mut wire = state.encode().unwrap();
        Frame::output_slices_into::<true>(42, b"reply", &[], &mut wire).unwrap();
        let mut expected = state.encode().unwrap();
        expected.extend(output.encode().unwrap());
        assert_eq!(wire, expected);
        let before = wire.clone();
        assert!(
            Frame::Input(vec![0; MAX_FRAME])
                .encode_into(&mut wire)
                .is_err()
        );
        assert_eq!(wire, before);
        assert!(
            Frame::SnapshotWithFlags(0, 2, vec![])
                .encode_into(&mut wire)
                .is_err()
        );
        assert_eq!(wire, before);
    }
    #[test]
    fn golden_and_fragmented() {
        let fixtures = [
            (
                Frame::Attach(0x0102),
                vec![9, 0, 0, 0, 2, 2, 1, 0, 0, 0, 0, 0, 0],
            ),
            (
                Frame::Input(b"hi".to_vec()),
                vec![3, 0, 0, 0, 0x10, b'h', b'i'],
            ),
            (
                Frame::Resize {
                    cols: 200,
                    rows: 60,
                    px_w: 0,
                    px_h: 0,
                },
                vec![9, 0, 0, 0, 0x12, 200, 0, 60, 0, 0, 0, 0, 0],
            ),
            (
                Frame::Exited(-9, 1),
                vec![
                    13, 0, 0, 0, 0x20, 247, 255, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0,
                ],
            ),
            (Frame::CloseSession, vec![1, 0, 0, 0, 0x1f]),
            (Frame::ExitAck, vec![1, 0, 0, 0, 0x21]),
            (Frame::StopShell, vec![1, 0, 0, 0, 0x22]),
            (Frame::ShellStopped, vec![1, 0, 0, 0, 0x23]),
        ];
        for (frame, wire) in fixtures {
            assert_eq!(frame.encode().unwrap(), wire);
            for split in 0..wire.len() {
                let mut decoder = Decoder::default();
                let mut messages = decoder.feed(&wire[..split]).unwrap();
                messages.extend(decoder.feed(&wire[split..]).unwrap());
                assert_eq!(messages, vec![frame.clone()]);
            }
        }
    }
    #[test]
    fn invalid_lengths_types_and_utf8() {
        for bytes in [
            &[0, 0, 0, 0][..],
            &[1, 0, 16, 0][..],
            &[1, 0, 0, 0, 3][..],
            &[2, 0, 0, 0, 0x21, 0][..],
            &[2, 0, 0, 0, 0x1f, 0][..],
            &[4, 0, 0, 0, 0x7f, 0, 0, 255][..],
        ] {
            assert!(Decoder::default().feed(bytes).is_err());
        }
    }
}

#[cfg(test)]
mod golden {
    //! Exercises frame invariants against real data and frozen expectations.
    use super::*;
    #[test]
    fn every_frozen_message() {
        let fixtures = [
            (
                Frame::Hello {
                    version: 1,
                    caps: 0,
                    session: [1; 16],
                    pid: 42,
                    cols: 80,
                    rows: 24,
                    created: 2,
                    head: 9,
                    start: 5,
                },
                "3b0000000101000000000000000000010101010101010101010101010101012a00000050001800020000000000000009000000000000000500000000000000",
            ),
            (Frame::Attach(0), "09000000020000000000000000"),
            (Frame::Input(vec![]), "0100000010"),
            (
                Frame::Output(1, b"hi".to_vec()),
                "0b0000001101000000000000006869",
            ),
            (
                Frame::Resize {
                    cols: 80,
                    rows: 24,
                    px_w: 640,
                    px_h: 480,
                },
                "0900000012500018008002e001",
            ),
            (Frame::ReadFrom(1), "09000000130100000000000000"),
            (Frame::SnapshotRequest, "0100000014"),
            (
                Frame::Snapshot(1, b"\x1bc".to_vec()),
                "0b0000001501000000000000001b63",
            ),
            (Frame::Signal(9), "020000001609"),
            (Frame::Exited(7, 1), "0d00000020070000000100000000000000"),
            (Frame::ExitAck, "0100000021"),
            (Frame::Error(1, "bad".into()), "060000007f0100626164"),
        ];
        for (frame, hex) in fixtures {
            let expected: Vec<u8> = hex
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(frame.encode().unwrap(), expected);
            assert_eq!(Decoder::default().feed(&expected).unwrap(), vec![frame]);
        }
    }
    #[test]
    fn exact_maximum_and_coalesced_frames() {
        let maximum = Frame::Input(vec![0; MAX_FRAME - 1]);
        let wire = maximum.encode().unwrap();
        assert_eq!(Decoder::default().feed(&wire).unwrap(), vec![maximum]);
        assert!(Frame::Input(vec![0; MAX_FRAME]).encode().is_err());
        let mut bytes = Frame::Attach(0).encode().unwrap();
        bytes.extend(Frame::ReadFrom(0).encode().unwrap());
        assert_eq!(
            Decoder::default().feed(&bytes).unwrap(),
            vec![Frame::Attach(0), Frame::ReadFrom(0)]
        );
    }
}

#[test]
fn borrowed_and_owned_decoders_agree_at_every_fragment_boundary() {
    use super::{Decoder, Frame, FrameRef, MAX_FRAME};
    for frame in [
        Frame::Input(vec![1; 100]),
        Frame::SequencedInput(3, vec![2; 100]),
        Frame::Output(4, vec![3; 100]),
        Frame::Snapshot(5, vec![4; 100]),
        Frame::InputState(6, 7),
        Frame::Error(1, "reason".into()),
    ] {
        let wire = frame.encode().unwrap();
        assert_eq!(FrameRef::decode(&wire[4..]).unwrap().into_owned(), frame);
        for split in 0..=wire.len() {
            let mut decoder = Decoder::default();
            let mut frames = Vec::new();
            for part in [&wire[..split], &wire[split..]] {
                decoder
                    .feed_with(part, |f| {
                        frames.push(f.into_owned());
                        Ok(())
                    })
                    .unwrap();
            }
            assert_eq!(frames, vec![frame.clone()]);
        }
    }
    for body in [&[][..], &[0x11], &[0x17, 1, 2], &[0x1a, 0], &[0xff]] {
        assert_eq!(
            FrameRef::decode(body).is_err(),
            Frame::decode(body).is_err()
        );
    }
    assert!(FrameRef::decode(&vec![0x10; MAX_FRAME + 1]).is_err());
    let body = Frame::SequencedInput(0, vec![42; 100]).encode().unwrap();
    let borrowed = FrameRef::decode(&body[4..]).unwrap();
    let (_, bytes) = borrowed.input().unwrap();
    assert_eq!(bytes.as_ptr(), body[13..].as_ptr());
    let mut decoder = Decoder::default();
    let mut calls = 0;
    let mut doubled = body.clone();
    doubled.extend_from_slice(&body);
    decoder
        .feed_with(&doubled, |_| {
            calls += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(calls, 2);
}

#[test]
fn deferred_frame_keeps_its_borrowed_storage_and_ordered_trailing_bytes() {
    let first = Frame::SequencedInput(3, vec![7; 100]);
    let second = Frame::InputStateRequest;
    let mut wire = first.encode().unwrap();
    let boundary = wire.len();
    wire.extend(second.encode().unwrap());
    let mut decoder = Decoder::default();
    assert_eq!(decoder.feed_until(&wire, |_| Ok(false)).unwrap(), boundary);
    let mut seen = Vec::new();
    assert_eq!(
        decoder
            .feed_until(&[], |frame| {
                seen.push(frame.into_owned());
                Ok(true)
            })
            .unwrap(),
        0
    );
    decoder
        .feed_until(&wire[boundary..], |frame| {
            seen.push(frame.into_owned());
            Ok(true)
        })
        .unwrap();
    assert_eq!(seen, vec![first, second]);
}

#[test]
fn maximum_deferred_frame_retries_without_growing_storage() {
    let wire = Frame::SequencedInput(0, vec![0; MAX_FRAME - 9])
        .encode()
        .unwrap();
    let mut decoder = Decoder::default();
    for chunk in wire.chunks(16 * 1024) {
        assert_eq!(
            decoder.feed_until(chunk, |_| Ok(false)).unwrap(),
            chunk.len()
        );
    }
    let capacity = decoder.bytes.capacity();
    assert_eq!(decoder.bytes.len(), MAX_FRAME + 4);
    assert!(capacity <= 2 * (MAX_FRAME + 4));
    for _ in 0..32 {
        assert_eq!(decoder.feed_until(&[], |_| Ok(false)).unwrap(), 0);
        assert_eq!(decoder.bytes.capacity(), capacity);
    }
    eprintln!(
        "METRIC deferred_decoder_capacity_per_peer={capacity} peers=32 aggregate_decoder_bytes={} trailing_wire_max_per_peer=16384 aggregate_trailing_wire_max=524288",
        32 * capacity
    );
    decoder.feed_until(&[], |_| Ok(true)).unwrap();
    assert_eq!(decoder.bytes, []);
}

#[test]
#[ignore = "release codec and allocation-path measurement"]
fn codec_reuse_measurement() {
    use super::{Decoder, Frame, FrameRef};
    use std::{hint::black_box, time::Instant};
    let frame = Frame::Output(7, vec![42; 16_384]);
    let wire = frame.encode().unwrap();
    let n = 100_000;
    for round in 0..7 {
        for (label, reuse) in [("encode-owned", false), ("encode-reused", true)] {
            let mut scratch = Vec::new();
            let start = Instant::now();
            for _ in 0..n {
                if reuse {
                    frame.encode_into(&mut scratch).unwrap();
                    black_box(&scratch);
                } else {
                    black_box(frame.encode().unwrap());
                }
            }
            println!(
                "{label}: round={round} n={n} ns/frame={:.1}",
                start.elapsed().as_secs_f64() * 1e9 / f64::from(n)
            );
        }
        for (label, borrowed) in [("decode-owned", false), ("decode-borrowed", true)] {
            let start = Instant::now();
            for _ in 0..n {
                if borrowed {
                    black_box(FrameRef::decode(black_box(&wire[4..])).unwrap());
                } else {
                    black_box(Frame::decode(black_box(&wire[4..])).unwrap());
                }
            }
            println!(
                "{label}: round={round} n={n} ns/frame={:.1}",
                start.elapsed().as_secs_f64() * 1e9 / f64::from(n)
            );
        }
        for (label, borrowed) in [("feed-owned", false), ("feed-borrowed", true)] {
            let mut decoder = Decoder::default();
            let start = Instant::now();
            for _ in 0..n {
                if borrowed {
                    decoder
                        .feed_with(&wire, |f| {
                            black_box(f);
                            Ok(())
                        })
                        .unwrap();
                } else {
                    black_box(decoder.feed(&wire).unwrap());
                }
            }
            println!(
                "{label}: round={round} n={n} ns/frame={:.1}",
                start.elapsed().as_secs_f64() * 1e9 / f64::from(n)
            );
        }
    }
}

#[test]
fn approximate_snapshot_codec_is_bounded_and_canonical() {
    let mut body = vec![0x1c];
    body.extend_from_slice(&42_u64.to_le_bytes());
    body.push(1);
    body.extend_from_slice(b"repaint");
    let frame_value = Frame::decode(&body).expect("negotiated additive Snapshot must decode");
    let wire = frame_value.encode().unwrap();
    assert!(
        wire[4..] == body,
        "additive frame roundtrip must preserve payload"
    );
    for split in 0..wire.len() {
        let mut decoder = Decoder::default();
        let mut frames = decoder.feed(&wire[..split]).unwrap();
        frames.extend(decoder.feed(&wire[split..]).unwrap());
        assert_eq!(frames.len(), 1, "fragmented additive frame");
    }
    body[9] = 2;
    assert!(Frame::decode(&body).is_err(), "reserved flags must reject");
    assert!(
        Frame::decode(&body[..9]).is_err(),
        "missing flags must reject"
    );
    let mut maximum = vec![b'x'; MAX_FRAME];
    maximum[0] = 0x1c;
    maximum[1..9].copy_from_slice(&42_u64.to_le_bytes());
    maximum[9] = 1;
    assert!(Frame::decode(&maximum).is_ok(), "maximum additive payload");
    maximum.push(b'x');
    assert!(
        Frame::decode(&maximum).is_err(),
        "overflowing additive frame"
    );
}

#[test]
fn cleanup_frames_reject_payloads_and_preserve_borrowed_decode() {
    for (kind, frame) in [(0x22, Frame::StopShell), (0x23, Frame::ShellStopped)] {
        assert_eq!(Frame::decode(&[kind]).unwrap(), frame);
        assert_eq!(FrameRef::decode(&[kind]).unwrap().into_owned(), frame);
        assert!(Frame::decode(&[kind, 0]).is_err());
    }
}

#[test]
fn shared_writer_selector_is_fixed_length_and_fragment_safe() {
    let wire = [5, 0, 0, 0, 0x1d, 4, 3, 2, 1];
    let frame = Frame::decode(&wire[4..]).expect("additive shared writer selection");
    assert_eq!(frame.encode().unwrap(), wire);
    assert_eq!(FrameRef::decode(&wire[4..]).unwrap().into_owned(), frame);
    for split in 0..=wire.len() {
        let mut decoder = Decoder::default();
        let mut frames = decoder.feed(&wire[..split]).unwrap();
        frames.extend(decoder.feed(&wire[split..]).unwrap());
        assert_eq!(frames, vec![frame.clone()]);
    }
    for body in [&[0x1d][..], &[0x1d, 1, 2, 3], &[0x1d, 1, 2, 3, 4, 5]] {
        assert!(Frame::decode(body).is_err());
        assert!(FrameRef::decode(body).is_err());
    }
}

#[test]
fn query_reply_extension_is_bounded_and_fragment_safe() {
    let frame = Frame::QueryReply(b"\x1b[1;1R".to_vec());
    let wire = frame.encode().unwrap();
    assert_eq!(wire, [7, 0, 0, 0, 0x1e, 27, b'[', b'1', b';', b'1', b'R']);
    assert_eq!(FrameRef::decode(&wire[4..]).unwrap().into_owned(), frame);
    for split in 0..=wire.len() {
        let mut decoder = Decoder::default();
        let mut frames = decoder.feed(&wire[..split]).unwrap();
        frames.extend(decoder.feed(&wire[split..]).unwrap());
        assert_eq!(frames, vec![frame.clone()]);
    }
    assert!(Frame::QueryReply(Vec::new()).encode().is_err());
    assert!(Frame::QueryReply(vec![0; 1025]).encode().is_err());
    assert!(Frame::decode(&[0x1e]).is_err());
    assert!(FrameRef::decode(&[vec![0x1e], vec![0; 1025]].concat()).is_err());
    assert!(Frame::QueryReply(vec![0; 1024]).encode().is_ok());
}

#[test]
fn capability_bits_are_distinct() {
    use crate::frame::{
        APPROXIMATE_SNAPSHOT, CLOSE_SESSION, MULTI_WRITER, QUERY_REPLIES, SEQUENCED_INPUT,
        SESSION_OWNER, SHARED_WRITER, SHELL_CLEANUP,
    };
    let capabilities = [
        SEQUENCED_INPUT,
        MULTI_WRITER,
        APPROXIMATE_SNAPSHOT,
        SESSION_OWNER,
        SHARED_WRITER,
        QUERY_REPLIES,
        CLOSE_SESSION,
        SHELL_CLEANUP,
    ];
    for (index, capability) in capabilities.iter().enumerate() {
        assert_eq!(
            (*capability).count_ones(),
            1,
            "capability must use one bit"
        );
        for other in &capabilities[index + 1..] {
            assert_eq!(*capability & *other, 0, "capability bits must not overlap");
        }
    }
    assert_eq!(SHARED_WRITER, 16, "preserve the shipped shared-writer bit");
    assert_eq!(QUERY_REPLIES, 32, "preserve the shipped query-reply bit");
    assert_eq!(CLOSE_SESSION, 64, "preserve the shipped close-session bit");
    assert_eq!(SHELL_CLEANUP, 128, "keep cleanup on the next free bit");
}
