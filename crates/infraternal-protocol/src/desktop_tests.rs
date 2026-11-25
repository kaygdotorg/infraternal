//! Desktop wire boundaries and arbitrary mux chunk schedules protect the borrowed binary extension [D12,D232].
use crate::{
    Frame, MuxStreamDecoder, decode_frame,
    desktop::{Delivery, Input, MAX_VIDEO_BYTES, Message},
    encode_frame_into, encode_muxed_frame_into,
};
/// Every desktop message, including `VideoPressure` (0x46), survives encoding and decoding at every
/// stream split, and fixed-size bodies refuse trailing bytes.
#[test]
fn desktop_messages_roundtrip_at_every_split_and_reject_trailing_fixed_fields() {
    let id = [7; 16];
    let video = [0, 0, 0, 1, 0x65, 42];
    let cases = [
        Message::Input(Input::Release),
        Message::Input(Input::Control { active: true }),
        Message::Input(Input::Control { active: false }),
        Message::Input(Input::Text {
            scalar: 0x0001_f600,
        }),
        Message::Attach {
            session_id: &id,
            delivery: Delivery::Datagram,
        },
        Message::Video {
            sequence: u64::MAX,
            capture_ns: u64::MAX,
            keyframe: true,
            bytes: &video,
        },
        Message::Size {
            width: 1920,
            height: 1080,
            density_milli: 2000,
        },
        Message::Input(Input::Mouse {
            x: 1_000_000,
            y: 1,
            button: 2,
            state: 2,
            modifiers: 15,
        }),
        Message::Input(Input::Scroll {
            x: 1,
            y: 2,
            dx: i32::MIN,
            dy: i32::MAX,
            modifiers: 15,
        }),
        Message::Input(Input::Key {
            keycode: 127,
            down: true,
            modifiers: 15,
        }),
        Message::Repair {
            last_sequence: u64::MAX,
        },
        Message::Pressure {
            waited_ms: 65_535,
            kbit_s: u32::MAX,
        },
        Message::Fragment {
            session_id: &id,
            sequence: 1,
            capture_ns: 2,
            keyframe: true,
            total: 6,
            offset: 0,
            bytes: &video,
        },
    ];
    for message in cases {
        let mut encoded = Vec::new();
        encode_frame_into(&Frame::Desktop(message), &mut encoded).unwrap();
        assert_eq!(
            decode_frame(&encoded).unwrap().frame,
            Frame::Desktop(message)
        );
        let mut mux = Vec::new();
        encode_muxed_frame_into(0xffff_ffff, &Frame::Desktop(message), &mut mux).unwrap();
        for split in 0..=mux.len() {
            let mut decoder = MuxStreamDecoder::new();
            let mut seen = 0;
            for chunk in [&mux[..split], &mux[split..]] {
                decoder
                    .feed(chunk, |id, frame| {
                        assert_eq!(id, u32::MAX);
                        assert_eq!(frame, Frame::Desktop(message));
                        seen += 1;
                    })
                    .unwrap();
            }
            assert_eq!(seen, 1);
            assert_eq!(decoder.buffered_len(), 0);
        }
        if !matches!(message, Message::Video { .. } | Message::Fragment { .. }) {
            let mut malformed = encoded.clone();
            assert!(malformed[0] < 127);
            malformed[0] += 1;
            malformed.push(0);
            assert!(decode_frame(&malformed).is_err());
        }
    }
}
#[test]
fn desktop_field_bounds_and_invalid_flags_are_rejected() {
    for message in [
        Message::Size {
            width: 3,
            height: 600,
            density_milli: 2000,
        },
        Message::Size {
            width: 4096,
            height: 4096,
            density_milli: 2000,
        },
        Message::Input(Input::Mouse {
            x: 1_000_001,
            y: 0,
            button: 0,
            state: 0,
            modifiers: 0,
        }),
        Message::Input(Input::Key {
            keycode: 128,
            down: true,
            modifiers: 0,
        }),
        Message::Input(Input::Scroll {
            x: 0,
            y: 0,
            dx: 0,
            dy: 0,
            modifiers: 16,
        }),
        Message::Video {
            sequence: 0,
            capture_ns: 0,
            keyframe: false,
            bytes: &[1],
        },
    ] {
        assert!(message.validate().is_err());
        assert!(encode_frame_into(&Frame::Desktop(message), &mut Vec::new()).is_err());
    }
    // Frame length 18, tag Video, keyframe byte2 is not a boolean.
    let mut bad = vec![18, 0x41];
    bad.extend_from_slice(&1u64.to_le_bytes());
    bad.extend_from_slice(&0u64.to_le_bytes());
    bad.extend_from_slice(&[2]);
    assert!(decode_frame(&bad).is_err());
    let mut truncated = vec![6, 0x43, 2, 0, 0, 2, 0];
    assert!(decode_frame(&truncated).is_err());
    truncated[5] = 1;
    assert!(decode_frame(&truncated).is_ok());
}
#[test]
fn desktop_maximum_access_unit_is_bounded_and_fragment_offset_cannot_overflow() {
    let bytes = vec![1; MAX_VIDEO_BYTES];
    let mut wire = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Video {
            sequence: 1,
            capture_ns: 0,
            keyframe: true,
            bytes: &bytes,
        }),
        &mut wire,
    )
    .unwrap();
    assert!(decode_frame(&wire).is_ok());
    let id = [1; 16];
    let overflow = Message::Fragment {
        session_id: &id,
        sequence: 1,
        capture_ns: 0,
        keyframe: true,
        total: u32::try_from(MAX_VIDEO_BYTES).unwrap(),
        offset: u32::MAX,
        bytes: &[1],
    };
    assert!(overflow.validate().is_err());
    let oversize = vec![1; MAX_VIDEO_BYTES + 1];
    assert!(
        Message::Video {
            sequence: 1,
            capture_ns: 0,
            keyframe: true,
            bytes: &oversize
        }
        .validate()
        .is_err()
    );
}

#[test]
fn scatter_video_prefix_is_identical_to_contiguous_encoding_at_all_length_boundaries() {
    for length in [
        1,
        109,
        110,
        127,
        128,
        1024,
        16365,
        16366,
        65536,
        crate::desktop::MAX_VIDEO_BYTES,
    ] {
        let payload = vec![7; length];
        let message = crate::desktop::Message::Video {
            sequence: u64::MAX,
            capture_ns: u64::MAX,
            keyframe: true,
            bytes: &payload,
        };
        let mut contiguous = Vec::new();
        encode_frame_into(&Frame::Desktop(message), &mut contiguous).unwrap();
        let mut header = Vec::new();
        crate::desktop::encode_video_prefix_into(u64::MAX, u64::MAX, true, &payload, &mut header)
            .unwrap();
        assert!(header.len() <= 22);
        header.extend_from_slice(&payload);
        assert_eq!(header, contiguous);
    }
    assert!(crate::desktop::encode_video_prefix_into(0, 0, false, &[7], &mut Vec::new()).is_err());
    assert!(crate::desktop::encode_video_prefix_into(1, 0, false, &[], &mut Vec::new()).is_err());
}

#[test]
fn committed_text_refuses_surrogates_controls_and_extra_bytes() {
    for scalar in [0, 31, 127, 159, 0xd800, 0xdfff, 0x0011_0000, u32::MAX] {
        assert!(Message::Input(Input::Text { scalar }).validate().is_err());
        let mut body = vec![4];
        body.extend_from_slice(&scalar.to_le_bytes());
        assert!(crate::desktop::decode(0x43, &body).is_err());
    }
    for scalar in [32, 0xe9, 0x0001_f600, 0x0010_ffff] {
        let message = Message::Input(Input::Text { scalar });
        let mut bytes = Vec::new();
        encode_frame_into(&Frame::Desktop(message), &mut bytes).unwrap();
        assert_eq!(decode_frame(&bytes).unwrap().frame, Frame::Desktop(message));
    }
}

/// An end-of-session reason rides in the final `Close` frame's code: it roundtrips through the codec,
/// every known code maps back to itself, and anything else (an unknown code, an unknown helper word)
/// is not a reason or falls to the safe default instead of inventing a message [#146].
#[test]
fn an_end_reason_roundtrips_as_a_close_code_and_unknown_values_are_safe() {
    use crate::desktop::{CONSOLE_USER_CHANGED, EndReason, WINDOW_CLOSED};
    for reason in [EndReason::WindowClosed, EndReason::ConsoleUserChanged] {
        let mut wire = Vec::new();
        encode_frame_into(
            &Frame::Close {
                code: reason.close_code(),
                reason: reason.close_text(),
            },
            &mut wire,
        )
        .unwrap();
        let Frame::Close { code, reason: text } = decode_frame(&wire).unwrap().frame else {
            panic!("not a close");
        };
        assert_eq!(EndReason::from_close_code(code), Some(reason));
        assert_eq!(text, reason.close_text());
        assert_eq!(
            EndReason::from_helper_word(Some(reason.helper_word())),
            reason
        );
    }
    assert_eq!(WINDOW_CLOSED, 4410);
    assert_eq!(CONSOLE_USER_CHANGED, 4411);
    for code in [0, 4403, 4404, 4409, 4412, u16::MAX] {
        assert_eq!(EndReason::from_close_code(code), None);
    }
    for word in [
        None,
        Some(""),
        Some("window_closed"),
        Some("CONSOLE_USER_CHANGED"),
        Some("<script>"),
    ] {
        assert_eq!(EndReason::from_helper_word(word), EndReason::WindowClosed);
    }
}

/// A `VideoPressure` body from a server that does not measure throughput (2 bytes) still decodes,
/// as "no measurement", and any other length is refused.
#[test]
fn pressure_without_a_throughput_field_decodes_as_unknown() {
    // Frame: one length byte (the tag plus the body), the tag, the body.
    let frame = |body_len: u8| {
        let mut frame = vec![body_len + 1, 0x46];
        frame.extend((0..body_len).map(|i| if i == 0 { 60 } else { 0 }));
        frame
    };
    assert_eq!(
        decode_frame(&frame(2)).unwrap().frame,
        Frame::Desktop(Message::Pressure {
            waited_ms: 60,
            kbit_s: 0
        })
    );
    for length in [0, 1, 3, 4, 5, 7] {
        assert!(decode_frame(&frame(length)).is_err(), "{length} bytes");
    }
}
