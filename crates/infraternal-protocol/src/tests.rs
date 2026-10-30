//! Exercises wire codec invariants and both implementations' committed golden frames.

use std::path::Path;

use serde_json::Value;

use crate::{
    DecodeError, EncodeError, Frame, FrameStreamDecoder, MAX_FRAME_LEN, MuxStreamDecoder,
    decode_frame, decode_muxed_frame, encode_frame_into, encode_muxed_frame_into,
};

#[derive(Debug)]
struct GoldenVector {
    name: String,
    file: String,
    frame: OwnedFrame,
}

#[derive(Debug)]
enum OwnedFrame {
    Hello {
        version: u16,
        caps: u64,
        client_info: String,
    },
    Welcome {
        connection_id: Vec<u8>,
        resume_token: Vec<u8>,
        resume_window_seconds: u32,
        session_incarnation: Option<String>,
    },
    Resume {
        connection_id: Vec<u8>,
        resume_token: Vec<u8>,
    },
    Ping {
        nonce: u64,
        sent_us: u64,
    },
    Pong {
        nonce: u64,
        sent_us: u64,
    },
    Close {
        code: u16,
        reason: String,
    },
    Input {
        in_seq: u64,
        bytes: Vec<u8>,
    },
    InputReply {
        query_seq: u64,
        bytes: Vec<u8>,
    },
    Output {
        out_seq: u64,
        bytes: Vec<u8>,
    },
    Resize {
        cols: u16,
        rows: u16,
        px_w: u16,
        px_h: u16,
    },
    Ack {
        in_seq_acked: u64,
    },
    Credit {
        bytes: u32,
    },
    Snapshot {
        out_seq: u64,
        bytes: Vec<u8>,
    },
    AttachTerm {
        session_id: Vec<u8>,
        last_out_seq: u64,
        last_in_seq: u64,
    },
    Call {
        call_id: u32,
        action_id: String,
        input_json: Vec<u8>,
    },
    Result {
        call_id: u32,
        ok: bool,
        json: Vec<u8>,
    },
    Subscribe {
        sub_id: u32,
        filter_json: Vec<u8>,
    },
    Event {
        sub_id: u32,
        event_json: Vec<u8>,
    },
}

impl OwnedFrame {
    // Keep the golden manifest's 17 variants in one exhaustive conversion table.
    #[allow(clippy::too_many_lines)]
    fn borrowed(&self) -> Frame<'_> {
        match self {
            Self::Hello {
                version,
                caps,
                client_info,
            } => Frame::Hello {
                version: *version,
                caps: *caps,
                client_info,
            },
            Self::Welcome {
                connection_id,
                resume_token,
                resume_window_seconds,
                session_incarnation,
            } => Frame::Welcome {
                connection_id: connection_id.as_slice().try_into().expect("16-byte id"),
                resume_token: resume_token.as_slice().try_into().expect("32-byte token"),
                resume_window_seconds: *resume_window_seconds,
                session_incarnation: session_incarnation.as_deref(),
            },
            Self::Resume {
                connection_id,
                resume_token,
            } => Frame::Resume {
                connection_id: connection_id.as_slice().try_into().expect("16-byte id"),
                resume_token: resume_token.as_slice().try_into().expect("32-byte token"),
            },
            Self::Ping { nonce, sent_us } => Frame::Ping {
                nonce: *nonce,
                sent_us: *sent_us,
            },
            Self::Pong { nonce, sent_us } => Frame::Pong {
                nonce: *nonce,
                sent_us: *sent_us,
            },
            Self::Close { code, reason } => Frame::Close {
                code: *code,
                reason,
            },
            Self::Input { in_seq, bytes } => Frame::Input {
                in_seq: *in_seq,
                bytes,
            },
            Self::InputReply { query_seq, bytes } => Frame::InputReply {
                query_seq: *query_seq,
                bytes,
            },
            Self::Output { out_seq, bytes } => Frame::Output {
                out_seq: *out_seq,
                bytes,
            },
            Self::Resize {
                cols,
                rows,
                px_w,
                px_h,
            } => Frame::Resize {
                cols: *cols,
                rows: *rows,
                px_w: *px_w,
                px_h: *px_h,
            },
            Self::Ack { in_seq_acked } => Frame::Ack {
                in_seq_acked: *in_seq_acked,
            },
            Self::Credit { bytes } => Frame::Credit { bytes: *bytes },
            Self::Snapshot { out_seq, bytes } => Frame::Snapshot {
                out_seq: *out_seq,
                bytes,
            },
            Self::AttachTerm {
                session_id,
                last_out_seq,
                last_in_seq,
            } => Frame::AttachTerm {
                session_id: session_id
                    .as_slice()
                    .try_into()
                    .expect("16-byte session id"),
                last_out_seq: *last_out_seq,
                last_in_seq: *last_in_seq,
            },
            Self::Call {
                call_id,
                action_id,
                input_json,
            } => Frame::Call {
                call_id: *call_id,
                action_id,
                input_json,
            },
            Self::Result { call_id, ok, json } => Frame::Result {
                call_id: *call_id,
                ok: *ok,
                json,
            },
            Self::Subscribe {
                sub_id,
                filter_json,
            } => Frame::Subscribe {
                sub_id: *sub_id,
                filter_json,
            },
            Self::Event { sub_id, event_json } => Frame::Event {
                sub_id: *sub_id,
                event_json,
            },
        }
    }
}

#[test]
fn golden_vectors_encode_and_decode_every_contract_frame() {
    let vector_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/vectors/wire");
    for vector in read_vectors() {
        let expected_frame = vector.frame.borrowed();
        let encoded = std::fs::read(vector_dir.join(&vector.file))
            .unwrap_or_else(|error| panic!("{}: {error}", vector.file));

        let mut output = Vec::with_capacity(encoded.len());
        encode_frame_into(&expected_frame, &mut output)
            .unwrap_or_else(|error| panic!("{} encode: {error:?}", vector.name));
        assert_eq!(output, encoded, "{} encoded bytes", vector.name);

        let decoded = decode_frame(&encoded)
            .unwrap_or_else(|error| panic!("{} decode: {error:?}", vector.name));
        assert_eq!(
            decoded.frame, expected_frame,
            "{} decoded fields",
            vector.name
        );
        assert_eq!(
            decoded.wire_len,
            encoded.len(),
            "{} byte length",
            vector.name
        );
    }
}

#[test]
fn mux_round_trip_and_incremental_decoders_preserve_frame_order() {
    let input = Frame::Input {
        in_seq: 9,
        bytes: b"abc",
    };
    let output = Frame::Output {
        out_seq: 12,
        bytes: b"xyz",
    };
    let mut encoded = Vec::with_capacity(64);
    encode_muxed_frame_into(3, &input, &mut encoded).expect("encode client stream");
    let input_len = encoded.len();
    let mut second = Vec::with_capacity(64);
    encode_muxed_frame_into(4, &output, &mut second).expect("encode server stream");
    encoded.extend_from_slice(&second);

    let first = decode_muxed_frame(&encoded).expect("decode first mux envelope");
    assert_eq!(first.stream_id, 3);
    assert_eq!(first.frame, input);
    assert_eq!(first.wire_len, input_len);

    let mut mux_decoder = MuxStreamDecoder::new();
    let mut decoded_frames = Vec::new();
    for chunk in encoded.chunks(2) {
        mux_decoder
            .feed(chunk, |stream_id, frame| match frame {
                Frame::Input { in_seq, bytes } => {
                    decoded_frames.push((stream_id, in_seq, bytes.to_vec()));
                }
                Frame::Output { out_seq, bytes } => {
                    decoded_frames.push((stream_id, out_seq, bytes.to_vec()));
                }
                _ => panic!("unexpected frame in mux stream test"),
            })
            .expect("stream decode");
    }
    assert_eq!(
        decoded_frames,
        vec![(3, 9, b"abc".to_vec()), (4, 12, b"xyz".to_vec())]
    );
    assert_eq!(mux_decoder.buffered_len(), 0);

    let mut frame_bytes = Vec::new();
    encode_frame_into(&input, &mut frame_bytes).expect("encode unwrapped frame");
    let mut frame_decoder = FrameStreamDecoder::new();
    let mut seen = 0;
    for byte in &frame_bytes {
        frame_decoder
            .feed(std::slice::from_ref(byte), |frame| {
                assert_eq!(frame, input);
                seen += 1;
            })
            .expect("unwrapped stream decode");
    }
    assert_eq!(seen, 1);
    assert_eq!(frame_decoder.buffered_len(), 0);
}

#[test]
fn rejects_oversized_noncanonical_and_malformed_frames_before_buffering_body() {
    let oversized = [0x81, 0x80, 0x80, 0x02];
    assert_eq!(
        decode_frame(&oversized),
        Err(DecodeError::FrameTooLarge {
            length: u32::try_from(MAX_FRAME_LEN + 1).expect("length fits u32"),
        })
    );
    assert_eq!(
        decode_frame(&[0x81, 0x00]),
        Err(DecodeError::NonCanonicalVarint)
    );
    assert!(matches!(
        decode_frame(&[0x01, 0xff]),
        Err(DecodeError::UnknownType(0xff))
    ));
    assert!(matches!(
        decode_frame(&[0x01, 0x08]),
        Err(DecodeError::InvalidBody {
            frame_type: 0x08,
            ..
        })
    ));

    let mut stream = FrameStreamDecoder::new();
    assert_eq!(
        stream.feed(&oversized, |_| {}),
        Err(DecodeError::FrameTooLarge {
            length: u32::try_from(MAX_FRAME_LEN + 1).expect("length fits u32"),
        })
    );
    assert_eq!(stream.buffered_len(), 0);
    assert_eq!(stream.inner.buffer.capacity(), 0);

    let mut maximum_size_frame = FrameStreamDecoder::new();
    maximum_size_frame
        .feed(&[0x80, 0x80, 0x80, 0x02], |_| {})
        .expect("maximum permitted frame length is accepted");
    assert_eq!(maximum_size_frame.buffered_len(), 4);
    assert!(maximum_size_frame.inner.buffer.capacity() <= MAX_FRAME_LEN + 5);
}

#[test]
fn oversized_encode_keeps_the_reusable_output_unchanged() {
    let large_payload = vec![0_u8; MAX_FRAME_LEN];
    let frame = Frame::Input {
        in_seq: 0,
        bytes: &large_payload,
    };
    let mut output = vec![0xaa, 0xbb];
    assert!(matches!(
        encode_frame_into(&frame, &mut output),
        Err(EncodeError::FrameTooLarge { .. })
    ));
    assert_eq!(output, [0xaa, 0xbb]);
}

fn read_vectors() -> Vec<GoldenVector> {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../contracts/vectors/wire/manifest.json"
    ))
    .expect("valid golden vector manifest");
    manifest["vectors"]
        .as_array()
        .expect("vectors array")
        .iter()
        .map(|entry| {
            let frame = &entry["frame"];
            GoldenVector {
                name: string(entry, "name").to_owned(),
                file: string(entry, "file").to_owned(),
                frame: read_frame(frame),
            }
        })
        .collect()
}

fn read_frame(frame: &Value) -> OwnedFrame {
    match string(frame, "type") {
        "Hello" => OwnedFrame::Hello {
            version: number(frame, "version"),
            caps: decimal(frame, "caps"),
            client_info: string(frame, "clientInfo").to_owned(),
        },
        "Welcome" => OwnedFrame::Welcome {
            connection_id: hex(frame, "connectionId"),
            resume_token: hex(frame, "resumeToken"),
            resume_window_seconds: number(frame, "resumeWindowSeconds"),
            session_incarnation: frame
                .get("sessionIncarnation")
                .and_then(Value::as_str)
                .map(str::to_owned),
        },
        "Resume" => OwnedFrame::Resume {
            connection_id: hex(frame, "connectionId"),
            resume_token: hex(frame, "resumeToken"),
        },
        "Ping" => OwnedFrame::Ping {
            nonce: decimal(frame, "nonce"),
            sent_us: decimal(frame, "sentUs"),
        },
        "Pong" => OwnedFrame::Pong {
            nonce: decimal(frame, "nonce"),
            sent_us: decimal(frame, "sentUs"),
        },
        "Close" => OwnedFrame::Close {
            code: number(frame, "code"),
            reason: string(frame, "reason").to_owned(),
        },
        "Input" if frame.get("replyTo").is_some() => OwnedFrame::InputReply {
            query_seq: decimal(frame, "replyTo"),
            bytes: hex(frame, "bytesHex"),
        },
        "Input" => OwnedFrame::Input {
            in_seq: decimal(frame, "inSeq"),
            bytes: hex(frame, "bytesHex"),
        },
        "Output" => OwnedFrame::Output {
            out_seq: decimal(frame, "outSeq"),
            bytes: hex(frame, "bytesHex"),
        },
        "Resize" => OwnedFrame::Resize {
            cols: number(frame, "cols"),
            rows: number(frame, "rows"),
            px_w: number(frame, "pxW"),
            px_h: number(frame, "pxH"),
        },
        "Ack" => OwnedFrame::Ack {
            in_seq_acked: decimal(frame, "inSeqAcked"),
        },
        "Credit" => OwnedFrame::Credit {
            bytes: number(frame, "bytes"),
        },
        "Snapshot" => OwnedFrame::Snapshot {
            out_seq: decimal(frame, "outSeq"),
            bytes: hex(frame, "bytesHex"),
        },
        "AttachTerm" => OwnedFrame::AttachTerm {
            session_id: hex(frame, "sessionId"),
            last_out_seq: decimal(frame, "lastOutSeq"),
            last_in_seq: decimal(frame, "lastInSeq"),
        },
        "Call" => OwnedFrame::Call {
            call_id: number(frame, "callId"),
            action_id: string(frame, "actionId").to_owned(),
            input_json: string(frame, "inputJson").as_bytes().to_vec(),
        },
        "Result" => OwnedFrame::Result {
            call_id: number(frame, "callId"),
            ok: frame["ok"].as_bool().expect("boolean ok field"),
            json: string(frame, "json").as_bytes().to_vec(),
        },
        "Subscribe" => OwnedFrame::Subscribe {
            sub_id: number(frame, "subId"),
            filter_json: string(frame, "filterJson").as_bytes().to_vec(),
        },
        "Event" => OwnedFrame::Event {
            sub_id: number(frame, "subId"),
            event_json: string(frame, "eventJson").as_bytes().to_vec(),
        },
        unknown => panic!("unknown golden frame type: {unknown}"),
    }
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().expect("string field")
}

fn number<T>(value: &Value, key: &str) -> T
where
    T: TryFrom<u64>,
    <T as TryFrom<u64>>::Error: std::fmt::Debug,
{
    T::try_from(value[key].as_u64().expect("unsigned number field")).expect("number field in range")
}

fn decimal(value: &Value, key: &str) -> u64 {
    string(value, key).parse().expect("decimal u64 string")
}

fn hex(value: &Value, key: &str) -> Vec<u8> {
    let text = string(value, key);
    assert_eq!(text.len() % 2, 0, "hex field has an even number of digits");
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    assert_eq!(remainder, &[] as &[u8]);
    pairs
        .iter()
        .map(|chunk| {
            let digits = std::str::from_utf8(chunk).expect("hex is ASCII");
            u8::from_str_radix(digits, 16).expect("valid hex byte")
        })
        .collect()
}

#[test]
fn marked_input_preserves_legacy_bytes_and_bounds_reply_body() {
    let legacy = Frame::Input {
        in_seq: 9,
        bytes: b"typing",
    };
    let marked = Frame::InputReply {
        query_seq: 42,
        bytes: b"\x1b[1;1R",
    };
    for frame in [legacy, marked] {
        let mut encoded = Vec::new();
        encode_frame_into(&frame, &mut encoded).unwrap();
        assert_eq!(decode_frame(&encoded).unwrap().frame, frame);
    }
    let oversized = vec![b'x'; 1025];
    assert!(
        encode_frame_into(
            &Frame::InputReply {
                query_seq: 0,
                bytes: &oversized
            },
            &mut Vec::new()
        )
        .is_err()
    );
}
