//! Packet fixtures for buffered receive across read boundaries and key changes.

use std::io;
use std::num::Wrapping;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf, join, sink};

use super::*;
use crate::mac::{_HMAC_SHA256, _HMAC_SHA256_ETM, _NONE};
use crate::ssh_read::SshRead;

/// A transport that returns at most one chunk per read and yields between chunks.
struct SplitInput<'a> {
    remaining: &'a [u8],
    chunk: usize,
    yield_first: bool,
}

impl AsyncRead for SplitInput<'_> {
    /// Pause once before each chunk so a packet can span multiple polls.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.yield_first {
            self.yield_first = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let count = self.chunk.min(self.remaining.len()).min(buf.remaining());
        let (bytes, remaining) = self.remaining.split_at(count);
        buf.put_slice(bytes);
        self.remaining = remaining;
        self.yield_first = true;
        Poll::Ready(Ok(()))
    }
}

/// Return receive and send keys derived from fixed material for one test epoch.
fn keys(
    cipher: &dyn Cipher,
    mac: &dyn MacAlgorithm,
    epoch: u8,
) -> (Box<dyn OpeningKey + Send>, Box<dyn SealingKey + Send>) {
    let key = vec![epoch; cipher.key_len()];
    let nonce = vec![epoch + 1; cipher.nonce_len()];
    let mac_key = vec![epoch + 2; mac.key_len()];
    (
        cipher.make_opening_key(&key, &nonce, &mac_key, mac),
        cipher.make_sealing_key(&key, &nonce, &mac_key, mac),
    )
}

/// Include both MAC orders and both ways AEAD ciphers handle the length field.
const CIPHER_MODES: [(&dyn Cipher, &dyn MacAlgorithm); 4] = [
    (&_AES_128_CTR, &_HMAC_SHA256_ETM),
    (&_AES_128_CTR, &_HMAC_SHA256),
    (&_AES_256_GCM, &_NONE),
    (&_CHACHA20_POLY1305, &_NONE),
];

/// Check the packet payload and confirm that a completed read clears its length.
async fn expect_packet(
    reader: &mut (impl AsyncRead + Unpin),
    buffer: &mut SSHBuffer,
    key: &mut (dyn OpeningKey + Send),
    expected: &[u8],
) {
    let n = read(reader, buffer, key).await.unwrap();
    assert_eq!(buffer.buffer.get(5..n), Some(expected));
    assert_eq!(buffer.len, 0);
}

/// Read a clear packet and two encrypted epochs through one buffered transport.
#[tokio::test]
async fn packets_survive_split_reads_and_coalesced_rekeys() {
    use crate::msg::{IGNORE, NEWKEYS};

    let banner = b"SSH-2.0-read-test\r\n";
    let before: &[&[u8]] = &[&[IGNORE; 7], &[NEWKEYS]];
    let after: &[&[u8]] = &[&[IGNORE; 3], &[IGNORE; 9], &[IGNORE; 5]];

    for ((cipher, mac), (next_cipher, next_mac)) in CIPHER_MODES
        .into_iter()
        .zip(CIPHER_MODES.into_iter().cycle().skip(1))
    {
        for chunk in (1..=32).chain([63, 127, 255, 256, 257, usize::MAX]) {
            for strict in [false, true] {
                let (mut old_open, mut old_seal) = keys(cipher, mac, 1);
                let (mut new_open, mut new_seal) = keys(next_cipher, next_mac, 4);
                let mut wire = SSHBuffer::new();
                wire.buffer.extend_from_slice(banner);
                clear::Key.write(&[NEWKEYS], &mut wire);
                if strict {
                    wire.seqn = Wrapping(0);
                }
                for payload in before {
                    old_seal.write(payload, &mut wire);
                }
                if strict {
                    wire.seqn = Wrapping(0);
                }
                let new_start = wire.buffer.len();
                for payload in after.iter().take(2) {
                    new_seal.write(payload, &mut wire);
                }
                let second_new_end = wire.buffer.len();
                new_seal.write(after.last().unwrap(), &mut wire);

                let source = SplitInput {
                    remaining: &wire.buffer,
                    chunk,
                    yield_first: true,
                };
                let mut stream = SshRead::new(join(source, sink()));
                assert_eq!(stream.read_ssh_id().await.unwrap(), b"SSH-2.0-read-test");
                let (mut reader, _) = stream.split();
                let mut buffer = SSHBuffer::new();
                expect_packet(&mut reader, &mut buffer, &mut clear::Key, &[NEWKEYS]).await;
                if strict {
                    buffer.seqn = Wrapping(0);
                }
                for payload in before {
                    expect_packet(&mut reader, &mut buffer, old_open.as_mut(), payload).await;
                }
                if chunk == usize::MAX {
                    // At least two new packets were fetched before selecting their key.
                    let buffered_end = new_start + reader.buffer().len();
                    assert!(buffered_end >= second_new_end);
                    assert_eq!(
                        Some(reader.buffer()),
                        wire.buffer.get(new_start..buffered_end)
                    );
                }
                if strict {
                    buffer.seqn = Wrapping(0);
                }
                for payload in after {
                    expect_packet(&mut reader, &mut buffer, new_open.as_mut(), payload).await;
                }
                assert!(matches!(
                    read(&mut reader, &mut buffer, new_open.as_mut()).await,
                    Err(Error::IO(e)) if e.kind() == io::ErrorKind::UnexpectedEof
                ));
            }
        }
    }
}

/// A large body can drain the read-ahead and bypass it without losing the next packet.
#[tokio::test]
async fn near_limit_packets_leave_the_following_packet_intact() {
    let large = vec![37; MAXIMUM_PACKET_LEN - MAXIMUM_PADDING_LEN - PADDING_LENGTH_LEN];
    for (cipher, mac) in CIPHER_MODES {
        let (mut open, mut seal) = keys(cipher, mac, 1);
        let mut wire = SSHBuffer::new();
        seal.write(&large, &mut wire);
        let body_len = wire.buffer.len() - PACKET_LENGTH_LEN - seal.tag_len();
        // Each cipher has its own alignment, so a legal frame can end below the cap.
        assert!((MAXIMUM_PACKET_LEN - 15..=MAXIMUM_PACKET_LEN).contains(&body_len));
        seal.write(b"tail", &mut wire);

        let (mut reader, _) = SshRead::new(join(wire.buffer.as_slice(), sink())).split();
        let mut buffer = SSHBuffer::new();
        expect_packet(&mut reader, &mut buffer, open.as_mut(), &large).await;
        expect_packet(&mut reader, &mut buffer, open.as_mut(), b"tail").await;
    }
}

/// A close anywhere in the next prefix, body or tag leaves its sequence unconsumed.
#[tokio::test]
async fn truncated_packets_leave_the_sequence_unconsumed() {
    for (cipher, mac) in CIPHER_MODES {
        let (_, mut seal) = keys(cipher, mac, 1);
        let mut wire = SSHBuffer::new();
        seal.write(b"first", &mut wire);
        let next_start = wire.buffer.len();
        seal.write(b"second packet with a longer body", &mut wire);
        for cut in next_start..wire.buffer.len() {
            let (mut open, _) = keys(cipher, mac, 1);
            let bytes = wire.buffer.get(..cut).unwrap();
            let (mut reader, _) = SshRead::new(join(bytes, sink())).split();
            let mut buffer = SSHBuffer::new();
            expect_packet(&mut reader, &mut buffer, open.as_mut(), b"first").await;
            assert!(matches!(
                read(&mut reader, &mut buffer, open.as_mut()).await,
                Err(Error::IO(e)) if e.kind() == io::ErrorKind::UnexpectedEof
            ));
            assert_eq!(buffer.seqn, Wrapping(1));
            assert_eq!(buffer.bytes, b"first".len());
        }
    }
}
