//! Fuzz entry point for the browser terminal stream's receive path (leg A, D63).
//!
//! The browser's WebSocket delivers terminal stream frames inside Binary
//! messages of any size, mixed with Ping, Pong, Text and Close messages.
//! [`receive_wire`] reassembles those messages into whole mux frames.
//! [`verify_receive_wire_sample`] turns one fuzz input into such a message
//! sequence and checks, against an independent replay of the same bytes
//! through `decode_muxed_frame`:
//!
//! - every frame handed on is exactly one whole mux frame, in order, and the
//!   frames together are a prefix of the Binary bytes received;
//! - the receive buffer never grows past [`MAX_SOCKET_BUFFER`];
//! - a protocol failure is reported only for bytes the decoder itself
//!   refuses, Text messages are always refused, and a Close keeps only an
//!   allow-listed reason (`safe_websocket_reason`);
//! - the end of the stream leaves at most one unfinished frame behind.
//!
//! The same input also drives the two JSON bodies a browser sends to open a
//! terminal (`TerminalOpen` and the startup-hint `Request`), which must never
//! panic and must accept only in-range sizes.
//!
//! Only built for tests and the `parser-checks` feature (the fuzz harness).

use super::{
    BrowserTerminalOpen, Inbound, MAX_SOCKET_BUFFER, ReceiveFailure, TerminalOpen, receive_wire,
};
use axum::extract::ws::Message;
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use infraternal_protocol::{DecodeError, decode_muxed_frame};

/// Close reasons `safe_websocket_reason` may hand on; anything else a
/// browser sends must come out as one of these.
const ALLOWED_REASONS: [&str; 8] = [
    "",
    "connection unresponsive",
    "tracer connection rotation",
    "tracer resume probe",
    "window closed",
    "connection closed",
    "connection ended",
    "other",
];

/// Split one fuzz input into WebSocket messages.
///
/// Each message starts with a tag byte: the low three bits pick the kind
/// (mostly Binary, so frames actually get reassembled), and the next two
/// bytes are a big-endian length for its payload, cut to what is left.
fn messages(data: &[u8]) -> Vec<Message> {
    let mut out = Vec::new();
    let mut rest = data;
    while let [tag, high, low, tail @ ..] = rest {
        let len = usize::from(u16::from_be_bytes([*high, *low])).min(tail.len());
        let (payload, tail) = tail.split_at(len);
        rest = tail;
        let payload = Bytes::copy_from_slice(payload);
        out.push(match tag & 7 {
            0..=3 => Message::Binary(payload),
            4 => Message::Ping(payload),
            5 => Message::Pong(payload),
            6 => Message::Text(String::from_utf8_lossy(&payload).into_owned().into()),
            _ => Message::Close(Some(axum::extract::ws::CloseFrame {
                code: u16::from_be_bytes([*high, *low]),
                reason: String::from_utf8_lossy(&payload).into_owned().into(),
            })),
        });
        if out.len() == 256 {
            break;
        }
    }
    out
}

/// Fuzz the terminal stream receive path with one input; panics when an
/// invariant above breaks, as libFuzzer expects.
#[doc(hidden)]
pub fn verify_receive_wire_sample(data: &[u8]) {
    let Some((&selector, data)) = data.split_first() else {
        return;
    };
    if selector & 0x80 != 0 {
        check_open_bodies(data);
        return;
    }
    let messages = messages(data);
    let binary: Vec<u8> = messages
        .iter()
        .filter_map(|message| match message {
            Message::Binary(bytes) => Some(bytes.as_ref()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect();
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    else {
        panic!("a current-thread runtime");
    };
    // Whether the message read last was Text, the one refusal that does not
    // come from the frame decoder.
    let last_text = std::cell::Cell::new(false);
    runtime.block_on(async {
        let mut source = futures_util::stream::iter(messages.into_iter().map(Ok::<_, axum::Error>))
            .inspect(|message| last_text.set(matches!(message, Ok(Message::Text(_)))));
        let mut receive = BytesMut::new();
        let mut deadline = None;
        let mut delivered = 0;
        loop {
            let inbound = receive_wire(&mut source, &mut receive, &mut deadline).await;
            assert!(
                receive.len() <= MAX_SOCKET_BUFFER,
                "receive buffer over its cap"
            );
            match inbound {
                Ok(Some(Inbound::Frame(frame))) => {
                    let Ok(decoded) = decode_muxed_frame(&frame) else {
                        panic!("a handed-on frame does not decode");
                    };
                    assert_eq!(decoded.wire_len, frame.len(), "exactly one whole frame");
                    let end = delivered + frame.len();
                    assert_eq!(
                        binary.get(delivered..end),
                        Some(frame.as_ref()),
                        "frames out of order"
                    );
                    delivered = end;
                    if receive.is_empty() {
                        assert!(
                            deadline.is_none(),
                            "an empty buffer keeps a partial-frame deadline"
                        );
                    }
                }
                Ok(Some(Inbound::TransportPing(_) | Inbound::TransportPong(_))) => {}
                Ok(Some(Inbound::SocketClose { reason, .. })) => {
                    assert!(reason.is_none_or(|reason| ALLOWED_REASONS.contains(&reason)));
                    break;
                }
                Ok(Some(Inbound::Failure(failure))) => {
                    if let ReceiveFailure::Protocol = failure {
                        // Either a Text message arrived, or the decoder itself
                        // refuses the buffered bytes.
                        assert!(
                            last_text.get()
                                || !matches!(
                                    decode_muxed_frame(&receive),
                                    Ok(_) | Err(DecodeError::Incomplete)
                                ),
                            "a protocol failure for bytes the decoder accepts"
                        );
                    }
                    break;
                }
                Ok(None) => {
                    // Whatever is left is the start of one unfinished frame.
                    assert!(
                        receive.is_empty()
                            || matches!(decode_muxed_frame(&receive), Err(DecodeError::Incomplete)),
                        "a complete or refused frame was left behind at end of stream"
                    );
                    assert_eq!(delivered + receive.len(), binary.len());
                    break;
                }
                Err(()) => panic!("receive_wire has no error path of its own"),
            }
        }
    });
}

/// Feed the bytes to the two terminal-open JSON bodies; accepted sizes must be in range.
fn check_open_bodies(data: &[u8]) {
    if let Ok(open) = serde_json::from_slice::<TerminalOpen>(data)
        && open.valid()
    {
        assert!((1..=500).contains(&open.cols) && (1..=300).contains(&open.rows));
    }
    let _ = serde_json::from_slice::<BrowserTerminalOpen>(data);
    let _ = crate::terminal_startup::Request::parse(data);
}

/// Replays the committed seed corpus through the fuzz entry point, so the
/// ordinary test run exercises it on the stable toolchain (ENGINEERING P5).
#[cfg(test)]
mod seed_corpus {
    /// Every committed seed runs through the entry point without a panic.
    #[test]
    fn every_seed_replays_without_breaking_an_invariant() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fuzz/corpus/terminal_stream_receive"
        );
        let mut seeds = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            super::verify_receive_wire_sample(&std::fs::read(entry.unwrap().path()).unwrap());
            seeds += 1;
        }
        assert!(seeds > 0, "no seeds in {dir}");
    }
}
