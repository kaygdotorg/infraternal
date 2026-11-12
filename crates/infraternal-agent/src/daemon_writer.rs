//! Shares bounded control-first output and deferred effect ordering across supported node platforms [D198,D232].
//!
//! A bounded priority lane carries shim-confirmed key acknowledgments and
//! relay-authorized key Snapshots. The writer drops or trims only queued raw
//! Output covered by that stream's acknowledged or Snapshot cursor; later bytes
//! and every other stream's bytes are preserved. The lane stays separate from
//! the bulk FIFO so it can pass already-queued output, and its FIFO order keeps
//! each key acknowledgment before the repaint that contains its echo. The relay
//! has authorized every Snapshot against its credit ledger before it reaches
//! this writer; this lane never grants or changes credit. Only a wholly
//! unstarted raw frame can be crossed, and only bytes through that stream's
//! captured cursor are removed. Partial frames, later bytes and sibling streams
//! keep their wire order. Its two-message bound prevents key spam from building
//! an unbounded repaint queue.
use crate::{channel::Channel, transport::Transmit};
use infraternal_protocol::Frame;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use infraternal_shim::frame::Frame as Shim;
use std::{
    collections::HashMap,
    io,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::sync::mpsc;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::sync::oneshot;

/// The pre-sent QUIC greeting and daemon greeting must serialize identically:
/// the control adapter consumes the daemon's greeting only after exact comparison.
pub(crate) fn hello_capabilities(native: bool, renewal: bool, identity_rotation: bool) -> u64 {
    infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS
        | if native {
            infraternal_plugin_api::channel::REMOTE_WRITER_BINDING
                | infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS
                | infraternal_plugin_api::channel::REMOTE_PATH_BACKUP
                | infraternal_plugin_api::channel::REMOTE_PATH_PROOF
        } else {
            0
        }
        | if renewal {
            infraternal_plugin_api::channel::LIVE_RENEWAL
        } else {
            0
        }
        | if identity_rotation {
            infraternal_plugin_api::channel::LIVE_IDENTITY_ROTATION
        } else {
            0
        }
}

/// Process-wide count of approximate repaints written to the leg-B socket.
/// Constant-space and content-free; metrics adapters can export this value.
static APPROXIMATE_SNAPSHOTS: AtomicU64 = AtomicU64::new(0);

/// Monotonic approximation counter for the infraternal agent metrics adapter.
#[must_use]
pub fn approximate_snapshots_total() -> u64 {
    APPROXIMATE_SNAPSHOTS.load(Ordering::Relaxed)
}
pub(crate) enum Message {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Shim(u32, Shim),
    Result(u32, u32, bool, Vec<u8>),
    Deferred(u32, u32, infraternal_plugin_api::ActionReply),
    Event(u32, Vec<u8>),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Exited(u32, Vec<u8>, oneshot::Sender<()>),
    Pong(u32, u64, u64),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Close(u32, &'static str),
    /// The session's shim is gone: a final stream close, never retried (wire §4).
    Ended(u32),
}

/// A bounded writer message that may pass bulk output after relay authorization.
/// Only the trusted terminal relay constructs these messages from shim replies.
pub(crate) enum PriorityMessage {
    /// A shim-confirmed input acknowledgment and the last raw output cursor already queued.
    InputAck {
        /// Mux stream whose queued output may be replaced.
        stream: u32,
        /// Input sequence confirmed by the shim.
        seq: u64,
        /// Exclusive output cursor through which a key repaint will catch up.
        output_cursor: u64,
    },
    /// A credit-authorized key repaint and its optional notice, emitted together in order.
    Snapshot {
        /// Mux stream that owns this repaint.
        stream: u32,
        /// Exclusive output cursor captured by the shim.
        seq: u64,
        /// Faithful or approximate terminal bytes captured by the shim.
        bytes: Vec<u8>,
        /// Whether the shim had to approximate this terminal capture.
        approximate: bool,
        /// Optional notice that must be written before the repaint frame.
        notice: Option<Vec<u8>>,
    },
}

/// Two slots keep one acknowledgment and one full repaint bounded in flight.
pub(crate) const PRIORITY_CAPACITY: usize = 2;

/// Identifies which bounded lane supplied the next writer item.
enum WriterInput {
    /// Existing control replies retain their end-of-channel behavior.
    Control(Option<Message>),
    /// Key acknowledgments and repaints use a separate, bounded lane.
    Priority(Option<PriorityMessage>),
    /// Ordinary output and events keep their existing FIFO order.
    Bulk(Option<Message>),
}
// A failed or cancelled write drops the continuation without starting its effect.
pub(crate) async fn deferred_reply(
    tx: &mut Transmit,
    socket: &impl Channel,
    stream: u32,
    call_id: u32,
    reply: infraternal_plugin_api::ActionReply,
) -> io::Result<()> {
    tx.send(
        socket,
        stream,
        &Frame::Result {
            call_id,
            ok: true,
            json: &reply.json,
        },
    )
    .await?;
    if let Some(after_write) = reply.after_write {
        after_write();
    }
    Ok(())
}

/// Whether this connection offers host identity rotation (#285). Shared by the Linux and portable daemons.
#[cfg(feature = "remote")]
pub(crate) fn supports_identity_rotation(
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
) -> bool {
    renewal.is_some_and(crate::remote_renewal::RenewalIdentity::supports_identity_rotation)
}

/// Builds without the remote client never rotate a host identity.
#[cfg(not(feature = "remote"))]
pub(crate) const fn supports_identity_rotation(_: Option<&()>) -> bool {
    false
}
/// Write the Hello, then every queued message to `socket`, control replies first, until the queues close.
pub(crate) async fn writer(
    socket: &impl Channel,
    mut messages: mpsc::Receiver<Message>,
    mut control: Option<mpsc::Receiver<Message>>,
    mut priority: Option<mpsc::Receiver<PriorityMessage>>,
    greeting: bool,
    renewal: bool,
    identity_rotation: bool,
    wire_caps: u64,
) -> io::Result<()> {
    let mut tx = Transmit::default();
    if greeting {
        tx.send(
            socket,
            0,
            &Frame::Hello {
                version: 1,
                caps: crate::daemon::hello_capabilities(
                    socket.native_stream_id().is_some(),
                    renewal,
                    identity_rotation,
                ) & !infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS
                    | if socket.native_stream_id().is_some() {
                        wire_caps
                    } else {
                        wire_caps & infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS
                    },
                client_info: "infraternal agent",
            },
        )
        .await?;
    }
    let mut replace_through = HashMap::new();
    loop {
        let incoming = tokio::select! {
            biased;
            message = async {
                match control.as_mut() {
                    Some(receiver) => receiver.recv().await,
                    None => std::future::pending().await,
                }
            } => WriterInput::Control(message),
            message = async {
                match priority.as_mut() {
                    Some(receiver) => receiver.recv().await,
                    None => std::future::pending().await,
                }
            } => WriterInput::Priority(message),
            message = messages.recv() => WriterInput::Bulk(message),
        };
        match incoming {
            // The control sender is the existing end-of-channel signal.
            WriterInput::Control(None) | WriterInput::Bulk(None) => break,
            WriterInput::Priority(Some(message)) => {
                write_priority(&mut tx, socket, message, &mut replace_through).await?;
            }
            // A bound terminal closes its priority sender before the bulk queue
            // drains its final messages; disable only this select branch.
            WriterInput::Priority(None) => priority = None,
            WriterInput::Control(Some(message)) | WriterInput::Bulk(Some(message)) => {
                write_message(&mut tx, socket, message, &mut replace_through).await?;
            }
        }
    }
    Ok(())
}

/// Apply a trusted key acknowledgment or repaint without changing relay credit.
async fn write_priority(
    tx: &mut Transmit,
    socket: &impl Channel,
    message: PriorityMessage,
    replace_through: &mut HashMap<u32, u64>,
) -> io::Result<()> {
    match message {
        PriorityMessage::InputAck {
            stream,
            seq,
            output_cursor,
        } => {
            replace_through
                .entry(stream)
                .and_modify(|cursor| *cursor = (*cursor).max(output_cursor))
                .or_insert(output_cursor);
            tx.send(socket, stream, &Frame::Ack { in_seq_acked: seq })
                .await
        }
        PriorityMessage::Snapshot {
            stream,
            seq,
            bytes,
            approximate,
            notice,
        } => {
            replace_through
                .entry(stream)
                .and_modify(|cursor| *cursor = (*cursor).max(seq))
                .or_insert(seq);
            if let Some(notice) = notice {
                write_event(tx, socket, stream, &notice).await?;
            }
            tx.send(
                socket,
                stream,
                &Frame::Snapshot {
                    out_seq: seq,
                    bytes: &bytes,
                },
            )
            .await?;
            if approximate {
                APPROXIMATE_SNAPSHOTS.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        }
    }
}

/// Write an ordinary message, trimming only raw bytes covered by a key repaint.
async fn write_message(
    tx: &mut Transmit,
    socket: &impl Channel,
    message: Message,
    replace_through: &mut HashMap<u32, u64>,
) -> io::Result<()> {
    match message {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Message::Shim(stream, frame) => {
            let Some(frame) = filter_replaced_output(stream, frame, replace_through)? else {
                return Ok(());
            };
            let wire = match &frame {
                Shim::Output(seq, bytes) => Frame::Output {
                    out_seq: *seq,
                    bytes,
                },
                Shim::Snapshot(seq, bytes) | Shim::SnapshotWithFlags(seq, _, bytes) => {
                    Frame::Snapshot {
                        out_seq: *seq,
                        bytes,
                    }
                }
                Shim::InputAck(seq) => Frame::Ack { in_seq_acked: *seq },
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid relay message",
                    ));
                }
            };
            tx.send(socket, stream, &wire).await?;
            if matches!(frame, Shim::SnapshotWithFlags(_, flags, _) if flags & 1 != 0) {
                APPROXIMATE_SNAPSHOTS.fetch_add(1, Ordering::Relaxed);
            }
        }
        Message::Result(stream, call_id, ok, json) => {
            tx.send(
                socket,
                stream,
                &Frame::Result {
                    call_id,
                    ok,
                    json: &json,
                },
            )
            .await?;
        }
        Message::Deferred(stream, call_id, reply) => {
            deferred_reply(tx, socket, stream, call_id, reply).await?;
        }
        Message::Event(stream, json) => write_event(tx, socket, stream, &json).await?,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Message::Exited(stream, json, delivered) => {
            write_event(tx, socket, stream, &json).await?;
            let _ = delivered.send(());
        }
        Message::Pong(stream, nonce, sent_us) => {
            tx.send(socket, stream, &Frame::Pong { nonce, sent_us })
                .await?;
        }
        Message::Ended(stream) => {
            replace_through.remove(&stream);
            tx.send(
                socket,
                stream,
                &Frame::Close {
                    code: infraternal_protocol::CLOSE_SESSION_GONE,
                    reason: infraternal_protocol::SESSION_GONE_REASON,
                },
            )
            .await?;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Message::Close(stream, reason) => {
            replace_through.remove(&stream);
            tx.send(socket, stream, &Frame::Close { code: 1, reason })
                .await?;
        }
    }
    Ok(())
}

/// Drop covered output bytes and retain any suffix that follows the repaint cursor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn filter_replaced_output(
    stream: u32,
    frame: Shim,
    replace_through: &HashMap<u32, u64>,
) -> io::Result<Option<Shim>> {
    let Shim::Output(seq, bytes) = frame else {
        return Ok(Some(frame));
    };
    let Some(through) = replace_through.get(&stream).copied() else {
        return Ok(Some(Shim::Output(seq, bytes)));
    };
    let length = u64::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    let end = seq.checked_add(length).ok_or(io::ErrorKind::InvalidData)?;
    if end <= through {
        return Ok(None);
    }
    if seq < through {
        let prefix = usize::try_from(through - seq).map_err(|_| io::ErrorKind::InvalidData)?;
        return Ok(Some(Shim::Output(through, bytes[prefix..].to_vec())));
    }
    Ok(Some(Shim::Output(seq, bytes)))
}
/// Keep startup inventories, ordinary events and acknowledged exits on one ordered wire path.
async fn write_event(
    tx: &mut Transmit,
    socket: &impl Channel,
    stream: u32,
    json: &[u8],
) -> io::Result<()> {
    tx.send(
        socket,
        stream,
        &Frame::Event {
            sub_id: 0,
            event_json: json,
        },
    )
    .await
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
/// Verify the production writer preserves stream-local order around key repaints.
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::{sync::Semaphore, task::JoinHandle};

    /// The live writer fixture and its wire observations.
    type HeldWriterParts = (
        Arc<HeldWriter>,
        mpsc::Sender<Message>,
        mpsc::Sender<PriorityMessage>,
        mpsc::UnboundedReceiver<Vec<u8>>,
        JoinHandle<io::Result<()>>,
    );

    /// Capture complete production writer frames and hold its first write at a frame boundary.
    struct HeldWriter {
        first_write: AtomicBool,
        started: Semaphore,
        release: Semaphore,
        frames: mpsc::UnboundedSender<Vec<u8>>,
    }

    impl Channel for HeldWriter {
        async fn read(&self, _: &mut [u8]) -> io::Result<usize> {
            std::future::pending().await
        }

        async fn write(&self, bytes: &[u8]) -> io::Result<()> {
            if self.first_write.swap(false, Ordering::Relaxed) {
                self.started.add_permits(1);
                self.release
                    .acquire()
                    .await
                    .map_err(|_| io::ErrorKind::BrokenPipe)?
                    .forget();
            }
            self.frames
                .send(bytes.to_vec())
                .map_err(|_| io::ErrorKind::BrokenPipe.into())
        }
    }

    /// Start the real writer with a channel that holds its first protocol frame.
    fn held_writer() -> HeldWriterParts {
        let (frames, frames_rx) = mpsc::unbounded_channel();
        let channel = Arc::new(HeldWriter {
            first_write: AtomicBool::new(true),
            started: Semaphore::new(0),
            release: Semaphore::new(0),
            frames,
        });
        let (messages_tx, messages_rx) = mpsc::channel(8);
        let (priority_tx, priority_rx) = mpsc::channel(PRIORITY_CAPACITY);
        let writer_channel = channel.clone();
        let task = tokio::spawn(async move {
            writer(
                writer_channel.as_ref(),
                messages_rx,
                None,
                Some(priority_rx),
                false,
                false,
                false,
                0,
            )
            .await
        });
        (channel, messages_tx, priority_tx, frames_rx, task)
    }

    /// Decode one captured mux frame so the test checks the real writer's wire order.
    fn decoded(bytes: &[u8]) -> (u32, infraternal_protocol::Frame<'_>) {
        let frame = infraternal_protocol::decode_muxed_frame(bytes).unwrap();
        (frame.stream_id, frame.frame)
    }

    /// Let an `InputAck` overtake only unstarted flood Output queued for its stream.
    #[tokio::test]
    async fn input_ack_passes_queued_same_stream_output_at_a_frame_boundary() {
        let (channel, messages, priority, mut frames, task) = held_writer();
        messages
            .send(Message::Shim(1, Shim::Output(0, b"first".to_vec())))
            .await
            .unwrap();
        channel.started.acquire().await.unwrap().forget();
        messages
            .send(Message::Shim(1, Shim::Output(5, b"queued".to_vec())))
            .await
            .unwrap();
        priority
            .send(PriorityMessage::InputAck {
                stream: 1,
                seq: 1,
                output_cursor: 5,
            })
            .await
            .unwrap();
        channel.release.add_permits(1);

        let first = frames.recv().await.unwrap();
        assert!(matches!(
            decoded(&first),
            (1, infraternal_protocol::Frame::Output { out_seq: 0, bytes }) if bytes == b"first"
        ));
        let second = frames.recv().await.unwrap();
        assert!(matches!(
            decoded(&second),
            (1, infraternal_protocol::Frame::Ack { in_seq_acked: 1 })
        ));
        let third = frames.recv().await.unwrap();
        assert!(matches!(
            decoded(&third),
            (1, infraternal_protocol::Frame::Output { out_seq: 5, bytes }) if bytes == b"queued"
        ));

        drop(messages);
        task.await.unwrap().unwrap();
    }

    /// Let a repaint replace only covered raw bytes from its stream and keep later output intact.
    #[tokio::test]
    async fn snapshot_drops_covered_same_stream_output_without_touching_siblings() {
        let (channel, messages, priority, mut frames, task) = held_writer();
        messages
            .send(Message::Shim(1, Shim::Output(0, b"prefix".to_vec())))
            .await
            .unwrap();
        channel.started.acquire().await.unwrap().forget();
        messages
            .send(Message::Shim(1, Shim::Output(6, b"oldnew".to_vec())))
            .await
            .unwrap();
        messages
            .send(Message::Shim(1, Shim::Output(12, b"later".to_vec())))
            .await
            .unwrap();
        messages
            .send(Message::Shim(2, Shim::Output(0, b"other".to_vec())))
            .await
            .unwrap();
        priority
            .send(PriorityMessage::InputAck {
                stream: 1,
                seq: 1,
                output_cursor: 6,
            })
            .await
            .unwrap();
        priority
            .send(PriorityMessage::Snapshot {
                stream: 1,
                seq: 9,
                bytes: b"screen".to_vec(),
                approximate: false,
                notice: None,
            })
            .await
            .unwrap();
        channel.release.add_permits(1);

        let first = frames.recv().await.unwrap();
        assert!(matches!(
            decoded(&first),
            (1, infraternal_protocol::Frame::Output { out_seq: 0, bytes }) if bytes == b"prefix"
        ));
        let second = frames.recv().await.unwrap();
        assert!(matches!(
            decoded(&second),
            (1, infraternal_protocol::Frame::Ack { in_seq_acked: 1 })
        ));
        let third = frames.recv().await.unwrap();
        assert!(matches!(
            decoded(&third),
            (1, infraternal_protocol::Frame::Snapshot { out_seq: 9, bytes }) if bytes == b"screen"
        ));
        let mut trailing = Vec::new();
        for _ in 0..3 {
            let frame = frames.recv().await.unwrap();
            match decoded(&frame) {
                (stream, infraternal_protocol::Frame::Output { out_seq, bytes }) => {
                    trailing.push((stream, out_seq, bytes.to_vec()));
                }
                (_, frame) => panic!("expected retained output after repaint, got {frame:?}"),
            }
        }
        trailing.sort_unstable_by_key(|(stream, seq, _)| (*stream, *seq));
        assert_eq!(
            trailing,
            vec![
                (1, 9, b"new".to_vec()),
                (1, 12, b"later".to_vec()),
                (2, 0, b"other".to_vec()),
            ],
            "the repaint trims only its own covered bytes; later and sibling output remain intact"
        );

        drop(messages);
        task.await.unwrap().unwrap();
    }
}

// Shared dispatch must never await the capacity consumed by a stalled writer.
// Unacknowledged input remains with the shim and can be replayed on reconnect.
pub(crate) fn reply(tx: &mpsc::Sender<Message>, message: Message) -> io::Result<()> {
    tx.try_send(message).map_err(|error| match error {
        mpsc::error::TrySendError::Full(_) => {
            io::Error::new(io::ErrorKind::WouldBlock, "control reply queue full")
        }
        mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe.into(),
    })
}
