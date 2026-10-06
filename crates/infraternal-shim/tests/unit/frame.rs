//! Frame regression and measurement harness, separated from production code [40].
use super::*;
#[cfg(test)]
mod tests {
    //! Exercises frame invariants against real data and frozen expectations.
    use super::*;
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
            (Frame::ExitAck, vec![1, 0, 0, 0, 0x21]),
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
