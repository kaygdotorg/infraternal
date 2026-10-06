//! Protects partial-header boundaries, frame order and validated size limits.
use crate::{Frame, MAX_FRAME_LEN, MuxStreamDecoder, decode_muxed_frame, encode_muxed_frame_into};

#[test]
fn split_mux_header_preserves_trailing_close() {
    let bytes = [0, 3, 15, 0, 0, 0, 3, 15, 0, 0];
    let mut decoder = MuxStreamDecoder::new();
    let mut seen = Vec::new();
    for chunk in [&bytes[..1], &bytes[1..]] {
        decoder
            .feed(chunk, |id, frame| {
                assert_eq!(id, 0);
                assert_eq!(
                    frame,
                    Frame::Close {
                        code: 0,
                        reason: ""
                    }
                );
                seen.push(id);
            })
            .unwrap();
    }
    assert_eq!(seen.len(), 2);
    assert_eq!(decoder.buffered_len(), 0);
}

#[test]
fn all_short_frame_splits_match_direct_decoding() {
    for id in [0, 127, 128, 16_384, 2_097_152, 268_435_456, u32::MAX] {
        let frames = [
            Frame::Close {
                code: 0,
                reason: "",
            },
            Frame::Credit { bytes: 1 },
            Frame::Close {
                code: 42,
                reason: "end",
            },
        ];
        let mut bytes = Vec::new();
        for frame in &frames {
            let mut wire = Vec::new();
            encode_muxed_frame_into(id, frame, &mut wire).unwrap();
            bytes.extend(wire);
        }
        for split in 0..=bytes.len() {
            let mut decoder = MuxStreamDecoder::new();
            let mut count = 0;
            let mut consumed = 0;
            for chunk in [&[][..], &bytes[..split], &[][..], &bytes[split..], &[][..]] {
                decoder
                    .feed(chunk, |stream, frame| {
                        let direct = decode_muxed_frame(&bytes[consumed..]).unwrap();
                        assert_eq!(stream, direct.stream_id);
                        assert_eq!(frame, direct.frame);
                        consumed += direct.wire_len;
                        count += 1;
                    })
                    .unwrap();
            }
            assert_eq!(count, frames.len());
            assert_eq!(consumed, bytes.len());
            assert_eq!(decoder.buffered_len(), 0);
        }
    }
}

#[test]
fn maximum_sized_fragmented_frame_is_not_rejected() {
    let payload = vec![0; MAX_FRAME_LEN - 9];
    let mut bytes = Vec::new();
    encode_muxed_frame_into(
        u32::MAX,
        &Frame::Output {
            out_seq: 0,
            bytes: &payload,
        },
        &mut bytes,
    )
    .unwrap();
    let mut decoder = MuxStreamDecoder::new();
    let mut count = 0;
    for chunk in [&bytes[..1], &bytes[1..7], &bytes[7..]] {
        decoder
            .feed(chunk, |id, frame| {
                assert_eq!(id, u32::MAX);
                assert_eq!(
                    frame,
                    Frame::Output {
                        out_seq: 0,
                        bytes: &payload
                    }
                );
                count += 1;
            })
            .unwrap();
    }
    assert_eq!(count, 1);
    assert_eq!(decoder.buffered_len(), 0);
}
