//! Line-oriented test bridge comparing Rust stream fields with the browser codec.
//! Scalar u64 fields are decimal strings so JSON preserves every wire bit.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_protocol::{Frame, MuxStreamDecoder, decode_muxed_frame, encode_muxed_frame_into};
use serde_json::{Value, json};
use std::io::{self, BufRead};

fn fields(frame: &Frame<'_>) -> Value {
    match frame {
        Frame::InputReply { query_seq, bytes } => {
            json!({ "type": "Input", "inSeq": "0", "replyTo": query_seq.to_string(), "bytes": bytes })
        }
        Frame::Hello {
            version,
            caps,
            client_info,
        } => {
            json!({ "type": "Hello", "version": version, "caps": caps.to_string(), "clientInfo": client_info })
        }
        Frame::Welcome {
            connection_id,
            resume_token,
            resume_window_seconds,
            session_incarnation,
        } => {
            let mut value = json!({ "type": "Welcome", "connectionId": connection_id, "resumeToken": resume_token, "resumeWindowSeconds": resume_window_seconds });
            if let Some(incarnation) = session_incarnation {
                value["sessionIncarnation"] = json!(incarnation);
            }
            value
        }
        Frame::Resume {
            connection_id,
            resume_token,
        } => {
            json!({ "type": "Resume", "connectionId": connection_id, "resumeToken": resume_token })
        }
        Frame::Ping { nonce, sent_us } => {
            json!({ "type": "Ping", "nonce": nonce.to_string(), "sentUs": sent_us.to_string() })
        }
        Frame::Pong { nonce, sent_us } => {
            json!({ "type": "Pong", "nonce": nonce.to_string(), "sentUs": sent_us.to_string() })
        }
        Frame::Close { code, reason } => json!({ "type": "Close", "code": code, "reason": reason }),
        Frame::Input { in_seq, bytes } => {
            json!({ "type": "Input", "inSeq": in_seq.to_string(), "bytes": bytes })
        }
        Frame::Output { out_seq, bytes } => {
            json!({ "type": "Output", "outSeq": out_seq.to_string(), "bytes": bytes })
        }
        Frame::Resize {
            cols,
            rows,
            px_w,
            px_h,
        } => json!({ "type": "Resize", "cols": cols, "rows": rows, "pxW": px_w, "pxH": px_h }),
        Frame::Ack { in_seq_acked } => {
            json!({ "type": "Ack", "inSeqAcked": in_seq_acked.to_string() })
        }
        Frame::Credit { bytes } => json!({ "type": "Credit", "bytes": bytes }),
        Frame::Snapshot { out_seq, bytes } => {
            json!({ "type": "Snapshot", "outSeq": out_seq.to_string(), "bytes": bytes })
        }
        Frame::AttachTerm {
            session_id,
            last_out_seq,
            last_in_seq,
        } => {
            json!({ "type": "AttachTerm", "sessionId": session_id, "lastOutSeq": last_out_seq.to_string(), "lastInSeq": last_in_seq.to_string() })
        }
        Frame::Call {
            call_id,
            action_id,
            input_json,
        } => {
            json!({ "type": "Call", "callId": call_id, "actionId": action_id, "inputJson": input_json })
        }
        Frame::Result { call_id, ok, json } => {
            json!({ "type": "Result", "callId": call_id, "ok": ok, "json": json })
        }
        Frame::Subscribe {
            sub_id,
            filter_json,
        } => json!({ "type": "Subscribe", "subId": sub_id, "filterJson": filter_json }),
        Frame::Event { sub_id, event_json } => {
            json!({ "type": "Event", "subId": sub_id, "eventJson": event_json })
        }
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let request: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let bytes: Vec<u8> = serde_json::from_value(request["bytes"].clone()).unwrap();
        let chunks: Vec<usize> = serde_json::from_value(request["chunks"].clone()).unwrap();
        let mut expected = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let decoded = decode_muxed_frame(&bytes[offset..]).unwrap();
            expected.push(json!({"streamId": decoded.stream_id, "frame": fields(&decoded.frame)}));
            offset += decoded.wire_len;
        }
        let mut decoder = MuxStreamDecoder::new();
        let mut frames = Vec::new();
        let mut encoded = Vec::new();
        offset = 0;
        for size in chunks {
            decoder
                .feed(&bytes[offset..offset + size], |id, frame| {
                    let mut wire = Vec::new();
                    encode_muxed_frame_into(id, &frame, &mut wire).unwrap();
                    encoded.extend_from_slice(&wire);
                    frames.push(json!({"streamId": id, "frame": fields(&frame)}));
                })
                .unwrap();
            offset += size;
        }
        assert_eq!(offset, bytes.len());
        assert_eq!(frames, expected);
        assert_eq!(encoded, bytes);
        assert_eq!(decoder.buffered_len(), 0);
        println!(
            "{}",
            json!({"frames": frames, "buffered": decoder.buffered_len()})
        );
    }
}
