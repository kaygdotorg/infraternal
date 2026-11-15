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
/// One item for the agent's leg-B writer, in the order it must reach the wire.
///
/// Relays, dispatch and control replies queue these; the writer turns each into
/// protocol frames for its stream (or, for [`Message::Attached`], only updates
/// its own per-stream state).
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
    /// A relay started a new attachment on this stream, or rewound its output
    /// cursor, under the given attachment id (see [`next_attachment`]). Nothing
    /// is written to the wire. It travels on the ordered bulk lane, so raw
    /// output queued before it may still be trimmed by an earlier key repaint,
    /// while output queued after it never is: the server reuses a writer's
    /// stream id when a browser resumes, and the new attachment's replay must
    /// start exactly at the cursor the browser asked for (#477).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Attached(u32, u64),
}

/// Source of attachment ids. Starts at 1, so 0 never names a real attachment.
static NEXT_ATTACHMENT: AtomicU64 = AtomicU64::new(1);

/// A fresh, process-unique id for one relay attachment (or one cursor rewind).
///
/// A relay announces it with [`Message::Attached`] before its first frame and
/// stamps it on every [`PriorityMessage`]. The writer then ignores priority
/// messages from an attachment that has already been replaced, such as a
/// cancelled relay task that raced one last repaint into the priority lane.
pub(crate) fn next_attachment() -> u64 {
    NEXT_ATTACHMENT.fetch_add(1, Ordering::Relaxed)
}

/// A bounded writer message that may pass bulk output after relay authorization.
/// Only the trusted terminal relay constructs these messages from shim replies.
pub(crate) enum PriorityMessage {
    /// A shim-confirmed input acknowledgment and the last raw output cursor already queued.
    InputAck {
        /// Mux stream whose queued output may be replaced.
        stream: u32,
        /// The relay attachment that sent it ([`next_attachment`]).
        attachment: u64,
        /// Input sequence confirmed by the shim.
        seq: u64,
        /// Exclusive output cursor through which a key repaint will catch up.
        output_cursor: u64,
    },
    /// A credit-authorized key repaint and its optional notice, emitted together in order.
    Snapshot {
        /// Mux stream that owns this repaint.
        stream: u32,
        /// The relay attachment that sent it ([`next_attachment`]).
        attachment: u64,
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
    let mut replace_through = ReplaceCursors::default();
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
    replace_through: &mut ReplaceCursors,
) -> io::Result<()> {
    match message {
        PriorityMessage::InputAck {
            stream,
            attachment,
            seq,
            output_cursor,
        } => {
            if !replace_through.cover(stream, attachment, output_cursor) {
                return Ok(());
            }
            tx.send(socket, stream, &Frame::Ack { in_seq_acked: seq })
                .await
        }
        PriorityMessage::Snapshot {
            stream,
            attachment,
            seq,
            bytes,
            approximate,
            notice,
        } => {
            if !replace_through.cover(stream, attachment, seq) {
                return Ok(());
            }
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
    replace_through: &mut ReplaceCursors,
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
            replace_through.forget(stream);
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
            replace_through.forget(stream);
            tx.send(socket, stream, &Frame::Close { code: 1, reason })
                .await?;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Message::Attached(stream, attachment) => replace_through.attach(stream, attachment),
    }
    Ok(())
}

/// Per-stream "raw output below this cursor is already covered by a key repaint"
/// state for one writer, scoped to the relay attachment that set it (#477).
///
/// A key's Ack or repaint overtakes queued raw output on the priority lane, so
/// the writer drops the raw bytes that repaint already covers. That cursor is
/// only true for the attachment that produced it: when the server closes a
/// stream and a resumed browser reattaches the same stream id, the new relay
/// replays from the browser's cursor, which is usually far below the old one.
/// [`Message::Attached`] therefore starts a clean slate, and priority messages
/// from an older attachment neither move the cursor nor reach the wire. A
/// newer attachment's priority message starts that clean slate itself when it
/// overtakes its own marker.
#[derive(Default)]
struct ReplaceCursors {
    /// Stream id to (current attachment id, exclusive covered cursor if any).
    streams: HashMap<u32, (u64, Option<u64>)>,
}

impl ReplaceCursors {
    /// A new attachment (or cursor rewind) owns `stream` from here on, with nothing covered yet.
    ///
    /// The marker rides the bulk FIFO, so the same attachment's priority frames may already
    /// have reached the writer and adopted it (see [`Self::cover`]). Attachment ids only grow,
    /// so an entry that already holds this id or a newer one is kept with its covered cursor:
    /// resetting it would let the rewound replay queued behind the marker reach the wire after
    /// a Snapshot that already covers it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn attach(&mut self, stream: u32, attachment: u64) {
        let entry = self.streams.entry(stream).or_insert((attachment, None));
        if entry.0 < attachment {
            *entry = (attachment, None);
        }
    }

    /// The stream closed: drop its state so a later stream with the same id starts clean.
    fn forget(&mut self, stream: u32) {
        self.streams.remove(&stream);
    }

    /// Record that `attachment` covered `stream`'s raw output below `through`.
    ///
    /// Returns false for a stale (older) attachment: its frame must not be
    /// written, because the browser is now attached through a different relay
    /// whose credit and cursor it knows nothing about. A stream with no recorded
    /// attachment adopts this one (writers fed without markers, such as tests
    /// and the native bound relay before its first marker).
    ///
    /// A newer attachment than the recorded one also adopts the stream. Its
    /// `Attached` marker is still queued behind earlier bulk output (#477, J730):
    /// the relay has already charged credit for this frame and moved its cursor,
    /// so dropping it would lose the key's echo and leak credit. Ids come from
    /// [`next_attachment`], which only grows, so "newer" means "the live one".
    fn cover(&mut self, stream: u32, attachment: u64, through: u64) -> bool {
        let entry = self.streams.entry(stream).or_insert((attachment, None));
        if entry.0 > attachment {
            return false;
        }
        if entry.0 < attachment {
            *entry = (attachment, None);
        }
        entry.1 = Some(entry.1.map_or(through, |cursor| cursor.max(through)));
        true
    }

    /// The covered cursor for `stream`'s current attachment, if a repaint set one.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn through(&self, stream: u32) -> Option<u64> {
        self.streams.get(&stream).and_then(|entry| entry.1)
    }
}

/// Drop covered output bytes and retain any suffix that follows the repaint cursor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn filter_replaced_output(
    stream: u32,
    frame: Shim,
    replace_through: &ReplaceCursors,
) -> io::Result<Option<Shim>> {
    let Shim::Output(seq, bytes) = frame else {
        return Ok(Some(frame));
    };
    let Some(through) = replace_through.through(stream) else {
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

    /// Start the real writer and let its first frame through at once, for tests about content, not timing.
    async fn open_writer(
        first: Message,
    ) -> (
        mpsc::Sender<Message>,
        mpsc::Sender<PriorityMessage>,
        mpsc::UnboundedReceiver<Vec<u8>>,
        JoinHandle<io::Result<()>>,
    ) {
        let (channel, messages, priority, mut frames, task) = held_writer();
        messages.send(first).await.unwrap();
        channel.started.acquire().await.unwrap().forget();
        channel.release.add_permits(1);
        frames.recv().await.unwrap();
        (messages, priority, frames, task)
    }

    /// Every Output frame the writer put on the wire, as `(stream, out_seq, length)`.
    fn outputs(frames: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<(u32, u64, usize)> {
        let mut seen = vec![];
        while let Ok(frame) = frames.try_recv() {
            if let (stream, infraternal_protocol::Frame::Output { out_seq, bytes }) =
                decoded(&frame)
            {
                seen.push((stream, out_seq, bytes.len()));
            }
        }
        seen
    }

    /// A resumed browser reuses its writer stream id; the new attachment's replay must
    /// start at the browser's cursor, not where the old attachment's key repaint ended (#477, J693).
    #[tokio::test]
    async fn a_new_attachment_on_a_reused_stream_keeps_its_replayed_raw_output() {
        let (messages, priority, mut frames, task) =
            open_writer(Message::Shim(9, Shim::Output(0, b"sibling".to_vec()))).await;
        messages.send(Message::Attached(4, 1)).await.unwrap();
        priority
            .send(PriorityMessage::InputAck {
                stream: 4,
                attachment: 1,
                seq: 1,
                output_cursor: 4096,
            })
            .await
            .unwrap();
        // The server closed the stream and the browser resumed it at 1024.
        messages.send(Message::Attached(4, 2)).await.unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(1024, vec![b'r'; 1024])))
            .await
            .unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(2048, vec![b's'; 4096])))
            .await
            .unwrap();
        drop(messages);
        drop(priority);
        task.await.unwrap().unwrap();
        assert_eq!(outputs(&mut frames), vec![(4, 1024, 1024), (4, 2048, 4096)]);
    }

    /// A cancelled relay's last repaint, racing in after its stream was reattached, neither
    /// reaches the wire nor trims the new attachment's output (#477).
    #[tokio::test]
    async fn a_replaced_attachments_late_repaint_is_dropped() {
        let (messages, priority, mut frames, task) =
            open_writer(Message::Shim(9, Shim::Output(0, b"sibling".to_vec()))).await;
        messages.send(Message::Attached(4, 7)).await.unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(0, vec![b'a'; 100])))
            .await
            .unwrap();
        // The marker has been applied once the Output after it is on the wire.
        frames.recv().await.unwrap();
        priority
            .send(PriorityMessage::Snapshot {
                stream: 4,
                attachment: 6,
                seq: 9000,
                bytes: b"old screen".to_vec(),
                approximate: false,
                notice: None,
            })
            .await
            .unwrap();
        priority
            .send(PriorityMessage::InputAck {
                stream: 4,
                attachment: 7,
                seq: 3,
                output_cursor: 150,
            })
            .await
            .unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(100, vec![b'b'; 100])))
            .await
            .unwrap();
        drop(messages);
        drop(priority);
        task.await.unwrap().unwrap();
        let mut kinds = vec![];
        while let Ok(frame) = frames.try_recv() {
            kinds.push(match decoded(&frame) {
                (4, infraternal_protocol::Frame::Snapshot { .. }) => "snapshot".to_string(),
                (4, infraternal_protocol::Frame::Ack { in_seq_acked }) => {
                    format!("ack {in_seq_acked}")
                }
                (4, infraternal_protocol::Frame::Output { out_seq, bytes }) => {
                    format!("output {out_seq}+{}", bytes.len())
                }
                (stream, _) => format!("other {stream}"),
            });
        }
        // The current attachment's Ack covers through 150, so only its tail of the later Output remains.
        assert_eq!(
            kinds,
            vec!["ack 3".to_string(), "output 150+50".to_string()]
        );
    }

    /// A cursor rewind's `Attached` marker waits in the bulk FIFO behind earlier output, while
    /// the same (live, newer) attachment's key Ack and Snapshot overtake it on the priority lane.
    /// The relay has already charged credit for that Snapshot and moved its cursor to its `seq`,
    /// so both frames must reach the wire, and the marker must not undo their covered cursor
    /// (#477, J730 review P2).
    #[tokio::test]
    async fn a_live_attachments_repaint_survives_overtaking_its_own_marker() {
        let (channel, messages, priority, mut frames, task) = held_writer();
        // Attachment 1 owns stream 4 and its first Output is being written (held).
        messages.send(Message::Attached(4, 1)).await.unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(0, vec![b'a'; 100])))
            .await
            .unwrap();
        channel.started.acquire().await.unwrap().forget();
        // Still queued in the bulk FIFO: a sibling's flood, the rewind's marker, and the
        // rewound replay, which the live repaint below already covers.
        messages
            .send(Message::Shim(9, Shim::Output(0, b"sibling flood".to_vec())))
            .await
            .unwrap();
        messages.send(Message::Attached(4, 2)).await.unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(50, vec![b'r'; 200])))
            .await
            .unwrap();
        // Attachment 2 (the live one) commits a key repaint before its marker is applied.
        priority
            .send(PriorityMessage::InputAck {
                stream: 4,
                attachment: 2,
                seq: 7,
                output_cursor: 250,
            })
            .await
            .unwrap();
        priority
            .send(PriorityMessage::Snapshot {
                stream: 4,
                attachment: 2,
                seq: 250,
                bytes: b"screen".to_vec(),
                approximate: false,
                notice: None,
            })
            .await
            .unwrap();
        channel.release.add_permits(1);
        drop(messages);
        drop(priority);
        task.await.unwrap().unwrap();
        let mut kinds = vec![];
        while let Ok(frame) = frames.try_recv() {
            kinds.push(match decoded(&frame) {
                (4, infraternal_protocol::Frame::Snapshot { out_seq, .. }) => {
                    format!("snapshot {out_seq}")
                }
                (4, infraternal_protocol::Frame::Ack { in_seq_acked }) => {
                    format!("ack {in_seq_acked}")
                }
                (4, infraternal_protocol::Frame::Output { out_seq, bytes }) => {
                    format!("output {out_seq}+{}", bytes.len())
                }
                (stream, _) => format!("other {stream}"),
            });
        }
        // The rewound replay ends at 250, inside the Snapshot, so it is trimmed away rather
        // than sent behind the Snapshot as an output gap.
        assert_eq!(
            kinds,
            vec![
                "output 0+100".to_string(),
                "ack 7".to_string(),
                "snapshot 250".to_string(),
                "other 9".to_string(),
            ]
        );
    }

    /// The marker of an attachment whose priority frames already adopted the stream keeps
    /// their covered cursor, and an older marker never takes the stream back (#477, J730).
    #[test]
    fn a_late_marker_keeps_the_cursor_its_own_attachment_covered() {
        let mut cursors = ReplaceCursors::default();
        cursors.attach(4, 1);
        assert!(cursors.cover(4, 2, 250));
        cursors.attach(4, 2);
        assert_eq!(cursors.through(4), Some(250));
        cursors.attach(4, 1);
        assert_eq!(cursors.through(4), Some(250));
        assert!(
            !cursors.cover(4, 1, 900),
            "an older attachment's frame was written"
        );
        cursors.attach(4, 3);
        assert_eq!(cursors.through(4), None);
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
                attachment: 1,
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
                attachment: 1,
                seq: 1,
                output_cursor: 6,
            })
            .await
            .unwrap();
        priority
            .send(PriorityMessage::Snapshot {
                stream: 1,
                attachment: 1,
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
