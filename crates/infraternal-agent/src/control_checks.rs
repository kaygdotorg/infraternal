//! Fuzz entry point for what local callers and the server send the infraternal agent.
//!
//! [`verify_control_message_sample`] covers three small parsers of untrusted
//! bytes, picked by the first input byte:
//!
//! - the local control socket's framing (`plugin_control::read_one`) fed in
//!   input-chosen read sizes: an accepted message is exactly one whole
//!   stream-0 mux frame, a prefix of what was sent, within
//!   `LOCAL_WIRE_BYTES`; for a `sessions.*` call (Linux), the verb's
//!   argument check `automation::validate` must not panic on any JSON;
//! - the saved session-names file and the CLI's reply envelope, which must
//!   refuse or return only well-formed rows, and whose accepted replies
//!   survive a serialise and decode round trip unchanged;
//! - the Hello's `client_info` OS token (`host_os::reported_os`): it names an
//!   OS only for the exact `infraternal agent os=<token>` form.
//!
//! Only built for tests and the `parser-checks` feature (the fuzz harness).

use crate::plugin_control::{LOCAL_WIRE_BYTES, read_one};
use infraternal_protocol::{Frame, decode_muxed_frame};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

/// A reader that returns the input in chunks whose sizes come from a schedule.
struct Scheduled<'a> {
    remaining: &'a [u8],
    schedule: &'a [u8],
    step: usize,
}

impl AsyncRead for Scheduled<'_> {
    /// Hand out the next chunk: 1 byte, a small size, or everything left.
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let selector = self
            .schedule
            .get(self.step % self.schedule.len().max(1))
            .copied()
            .unwrap_or(u8::MAX);
        self.step = self.step.wrapping_add(1);
        let size = match selector % 3 {
            0 => 1,
            1 => usize::from(selector),
            _ => usize::MAX,
        };
        let count = size.min(self.remaining.len()).min(buf.remaining());
        let (bytes, rest) = self.remaining.split_at(count);
        buf.put_slice(bytes);
        self.remaining = rest;
        Poll::Ready(Ok(()))
    }
}

/// Fuzz the infraternal agent's local message parsers with one input; panics
/// when an invariant above breaks, as libFuzzer expects.
#[doc(hidden)]
pub fn verify_control_message_sample(data: &[u8]) {
    let [selector, rest @ ..] = data else {
        return;
    };
    match selector % 4 {
        0 => check_control_socket(rest),
        1 => {
            #[cfg(target_os = "linux")]
            crate::automation::check_names_sample(rest);
        }
        2 => check_reply(rest),
        _ => check_hello_os(rest),
    }
}

/// One local control-socket request: framing first, then the verb's arguments.
fn check_control_socket(data: &[u8]) {
    let [schedule_len, rest @ ..] = data else {
        return;
    };
    let (schedule, wire) = rest.split_at(usize::from(*schedule_len).min(rest.len()));
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread().build() else {
        panic!("a current-thread runtime");
    };
    let mut reader = Scheduled {
        remaining: wire,
        schedule,
        step: 0,
    };
    let Ok(accepted) = runtime.block_on(read_one(&mut reader)) else {
        return;
    };
    assert!(accepted.len() <= LOCAL_WIRE_BYTES);
    assert!(
        wire.starts_with(&accepted),
        "the accepted message is not what was sent"
    );
    let Ok(decoded) = decode_muxed_frame(&accepted) else {
        panic!("an accepted control message does not decode");
    };
    assert_eq!(decoded.stream_id, 0);
    assert_eq!(
        decoded.wire_len,
        accepted.len(),
        "trailing bytes were accepted"
    );
    #[cfg(target_os = "linux")]
    if let Frame::Call {
        action_id,
        input_json,
        ..
    } = decoded.frame
        && let Some(verb) = action_id.strip_prefix("sessions.")
        && let Ok(input) = serde_json::from_slice::<serde_json::Value>(input_json)
    {
        let _ = crate::automation::validate(verb, &input);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = decoded.frame;
}

/// The CLI's reply envelope: an accepted reply round-trips unchanged.
fn check_reply(data: &[u8]) {
    #[cfg(target_os = "linux")]
    if let Ok(reply) = crate::automation::Reply::decode(data) {
        let Ok(encoded) = serde_json::to_vec(&reply) else {
            panic!("a decoded reply does not serialise");
        };
        let Ok(again) = crate::automation::Reply::decode(&encoded) else {
            panic!("a re-encoded reply is refused");
        };
        assert_eq!(
            (again.code, &again.message, &again.next, &again.data),
            (reply.code, &reply.message, &reply.next, &reply.data)
        );
    }
    #[cfg(not(target_os = "linux"))]
    let _ = data;
}

/// The Hello OS token: only the exact form names an OS, and it names it the same way every time.
fn check_hello_os(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    if let Some(name) = crate::host_os::reported_os(&text) {
        let Some(token) = text.strip_prefix("infraternal agent os=") else {
            panic!("an OS was named without the exact Hello prefix");
        };
        assert!(
            !token.is_empty()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        );
        assert!(!name.is_empty() && name.len() <= 32);
        assert_eq!(
            crate::host_os::reported_os(&format!("infraternal agent os={token}")),
            Some(name)
        );
    }
    // The same text arriving inside a real Hello frame takes the same path on the server.
    let mut wire = Vec::new();
    let hello = Frame::Hello {
        version: 1,
        caps: 0,
        client_info: &text,
    };
    if infraternal_protocol::encode_muxed_frame_into(0, &hello, &mut wire).is_ok()
        && let Ok(decoded) = decode_muxed_frame(&wire)
        && let Frame::Hello { client_info, .. } = decoded.frame
    {
        assert_eq!(
            crate::host_os::reported_os(client_info),
            crate::host_os::reported_os(&text)
        );
    }
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
            "/../../fuzz/corpus/agent_control_messages"
        );
        let mut seeds = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            super::verify_control_message_sample(&std::fs::read(entry.unwrap().path()).unwrap());
            seeds += 1;
        }
        assert!(seeds > 0, "no seeds in {dir}");
    }
}
