//! Fuzz entry point for the buffered SSH packet reader (#538).
//!
//! Since #538 the receive half reads through a 256-byte `BufReader`, so bytes
//! of the next packet sit in the read-ahead, still encrypted, while the
//! current packet's key is in use. This hook drives that exact path
//! (`SshRead::read_ssh_id`, `SshRead::split` and [`read`]) with input-chosen
//! cipher modes, read sizes and payloads, and checks two things:
//!
//! - every packet sealed by the matching key comes back byte for byte, in
//!   order, across a key change at an input-chosen packet (the bytes that were
//!   read ahead before the change must open under the new key);
//! - arbitrary bytes after those packets, or in place of the identification
//!   line, end in an error or end of input, never a panic, and a failed read
//!   never leaves a half-consumed sequence number behind.
//!
//! It is only compiled with the `fuzz-hooks` feature, which the workspace's
//! fuzz harness crate enables; no shipping binary turns it on.

use std::io;
use std::num::Wrapping;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf, join, sink};

use super::*;
use crate::mac::{_HMAC_SHA256, _HMAC_SHA256_ETM, _NONE};
use crate::ssh_read::SshRead;

/// A transport that hands out input-chosen chunk sizes and yields once before
/// each chunk, so a packet can span many polls of the buffered reader.
struct ScheduledInput<'a> {
    remaining: &'a [u8],
    schedule: &'a [u8],
    step: usize,
    yield_next: bool,
}

impl AsyncRead for ScheduledInput<'_> {
    /// Return the next chunk of at most the scheduled size, or end of input.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.yield_next {
            self.yield_next = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let selector = self
            .schedule
            .get(self.step % self.schedule.len().max(1))
            .copied()
            .unwrap_or(0);
        self.step = self.step.wrapping_add(1);
        // Small reads split prefixes and tags; the last class lets one read
        // fill the whole read-ahead (and bypass it for large bodies).
        let size = match selector % 4 {
            0 => 1,
            1 => usize::from(selector >> 2) + 1,
            2 => 255 + usize::from(selector >> 6),
            _ => usize::MAX,
        };
        let count = size.min(self.remaining.len()).min(buf.remaining());
        let (bytes, remaining) = self.remaining.split_at(count);
        buf.put_slice(bytes);
        self.remaining = remaining;
        self.yield_next = selector & 1 == 1;
        Poll::Ready(Ok(()))
    }
}

/// The receive modes the hook can pick: clear (before the first NEWKEYS),
/// both MAC orders of a block cipher, and both AEAD length layouts.
const MODES: [(&dyn Cipher, &dyn MacAlgorithm); 5] = [
    (&_CLEAR, &_NONE),
    (&_AES_128_CTR, &_HMAC_SHA256_ETM),
    (&_AES_128_CTR, &_HMAC_SHA256),
    (&_AES_256_GCM, &_NONE),
    (&_CHACHA20_POLY1305, &_NONE),
];

/// Derive a matching opening and sealing key from fixed per-epoch material.
fn keys(
    (cipher, mac): (&dyn Cipher, &dyn MacAlgorithm),
    epoch: u8,
) -> (Box<dyn OpeningKey + Send>, Box<dyn SealingKey + Send>) {
    let key = vec![epoch; cipher.key_len()];
    let nonce = vec![epoch.wrapping_add(1); cipher.nonce_len()];
    let mac_key = vec![epoch.wrapping_add(2); mac.key_len()];
    (
        cipher.make_opening_key(&key, &nonce, &mac_key, mac),
        cipher.make_sealing_key(&key, &nonce, &mac_key, mac),
    )
}

/// Poll a future that only ever waits on [`ScheduledInput`], which wakes
/// itself, to completion on the current thread.
fn run<F: std::future::Future>(future: F) -> F::Output {
    futures::executor::block_on(future)
}

/// Fuzz the buffered SSH packet reader with one input; panics on a broken
/// invariant, as libFuzzer expects.
///
/// Layout: byte 0 picks the first and second cipher mode and whether the
/// identification line is a fixed valid one or taken from the input; byte 1
/// is the packet index of the key change; byte 2 is the length of the read
/// schedule that follows. Then up to 16 payloads, each a length byte and that
/// many bytes, then a `0xFF` marker, and everything after it is raw trailing
/// input appended after the sealed packets.
pub fn check_packet_reads(data: &[u8]) {
    let [mode, change, schedule_len, rest @ ..] = data else {
        return;
    };
    let first = MODES[usize::from(*mode) % MODES.len()];
    let second = MODES[usize::from(*mode / 5) % MODES.len()];
    let fuzz_banner = mode & 0x80 != 0;
    let (schedule, mut rest) = rest.split_at(usize::from(*schedule_len).min(rest.len()));

    let mut payloads: Vec<&[u8]> = Vec::new();
    while let [len, tail @ ..] = rest {
        if *len == 0xFF || payloads.len() == 16 {
            rest = tail;
            break;
        }
        let (payload, tail) = tail.split_at(usize::from(*len).min(tail.len()));
        payloads.push(payload);
        rest = tail;
    }
    let trailing = rest;
    let change = usize::from(*change).min(payloads.len());

    let (mut open_old, mut seal_old) = keys(first, 1);
    let (mut open_new, mut seal_new) = keys(second, 4);
    let mut wire = SSHBuffer::new();
    if fuzz_banner {
        // The identification line itself is attacker-chosen here; the
        // trailing bytes stand in for it and no packets are expected.
        wire.buffer.extend_from_slice(trailing);
    } else {
        wire.buffer.extend_from_slice(b"SSH-2.0-fuzz\r\n");
        for (index, payload) in payloads.iter().enumerate() {
            if index < change {
                seal_old.write(payload, &mut wire);
            } else {
                seal_new.write(payload, &mut wire);
            }
        }
        wire.buffer.extend_from_slice(trailing);
    }

    let source = ScheduledInput {
        remaining: &wire.buffer,
        schedule,
        step: 0,
        yield_next: false,
    };
    run(async {
        let mut stream = SshRead::new(join(source, sink()));
        let id_ok = if mode & 0x40 != 0 {
            stream.read_client_ssh_id().await.is_ok()
        } else {
            stream.read_ssh_id().await.is_ok()
        };
        if !fuzz_banner {
            assert!(id_ok, "the fixed identification line must be accepted");
        }
        if !id_ok {
            return;
        }
        let (mut reader, _) = stream.split();
        let mut buffer = SSHBuffer::new();
        if !fuzz_banner {
            for (index, payload) in payloads.iter().enumerate() {
                let key = if index < change {
                    open_old.as_mut()
                } else {
                    open_new.as_mut()
                };
                let end = match read(&mut reader, &mut buffer, key).await {
                    Ok(end) => end,
                    Err(error) => panic!("sealed packet {index} failed to open: {error:?}"),
                };
                assert_eq!(buffer.buffer.get(5..end), Some(*payload), "packet {index}");
                assert_eq!(buffer.len, 0);
                assert_eq!(buffer.seqn, Wrapping(index as u32 + 1));
            }
        }
        // Whatever follows is hostile: read until the first error or EOF.
        // Each read consumes at least one byte or fails, so this terminates.
        let key = if change < payloads.len() || fuzz_banner {
            open_new.as_mut()
        } else {
            open_old.as_mut()
        };
        for _ in 0..=trailing.len() {
            let seqn = buffer.seqn;
            match read(&mut reader, &mut buffer, key).await {
                Ok(end) => {
                    assert!(end >= 4 && end <= buffer.buffer.len());
                    assert_eq!(buffer.len, 0);
                    assert_eq!(buffer.seqn, seqn + Wrapping(1));
                }
                Err(_) => {
                    assert_eq!(
                        buffer.seqn, seqn,
                        "a failed read consumed a sequence number"
                    );
                    break;
                }
            }
        }
    });
}
