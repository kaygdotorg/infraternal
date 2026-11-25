//! Shares bounded control-first output and deferred effect ordering across supported node platforms [D198,D232].
//!
//! A bounded priority lane carries shim-confirmed key acknowledgments and
//! relay-authorized key Snapshots. They may pass queued raw Output of their own
//! stream; later bytes and every other stream's bytes keep their order. The
//! lane stays separate from the bulk FIFO so it can pass already-queued output,
//! and its FIFO order keeps each key acknowledgment before the repaint that
//! contains its echo. The relay has authorized every Snapshot against its
//! credit ledger before it reaches this writer. Only a wholly unstarted raw
//! frame can be crossed, and only bytes through that stream's captured cursor
//! are affected. Partial frames, later bytes and sibling streams keep their
//! wire order. Its two-message bound prevents key spam from building an
//! unbounded repaint queue.
//!
//! What happens to the raw output a key passes (#477, J799):
//!
//! - A key's acknowledgment only *holds* the raw output below its cursor: the
//!   frames wait in the writer, off the wire, so the repaint that follows is
//!   not stuck behind them. The relay has charged them to the client's credit.
//! - The key's Snapshot *commits* the cover. Held and later-dequeued raw bytes
//!   below its cursor are dropped, because the Snapshot replaces them. Their
//!   credit goes back to the relay that charged them through its [`Refunds`]
//!   cell: the client never receives those bytes, so it can never return it.
//! - If the relay abandons the repaint instead (the shim cannot capture, the
//!   starvation timer fires, or the program exits), it sends
//!   [`PriorityMessage::Release`] and the held frames are written in order. The
//!   client then holds every byte up to the relay's cursor, so the relay's
//!   recovery replay continues without a gap.
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
    ///
    /// The marker also carries the relay's [`Refunds`] cell for this
    /// attachment: raw bytes of it that the writer drops under a key repaint
    /// are refunded there (#477, J799).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Attached(u32, u64, Refunds),
    /// The server closed this stream, so the writer drops its per-stream state
    /// for every attachment older than the given floor (see `Stream::retire` in
    /// the shared dispatcher). Nothing is written: the server already knows.
    /// Without it, a long-lived link keeps one entry per stream id it ever used
    /// (#477, J730 P3).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Forget(u32, u64),
    /// The server closed this stream: raw output the old relay still has queued must never
    /// reach the wire. Dispatch sends it on the control lane, which the writer serves ahead
    /// of the bulk FIFO, at the moment it retires the relay (see `Stream::retire`); the
    /// floor is the same fresh attachment id the relay's [`Message::Forget`] carries.
    ///
    /// The writer marks the stream's cover retired at that floor and drops every raw
    /// `Output` that reaches it until a newer attachment's [`Message::Attached`] arrives.
    /// Frames carry no attachment id, but FIFO order makes this exact: everything the old
    /// relay queued sits ahead of the new relay's marker, everything after the marker is the
    /// new attachment's own. Without it the server reuses the stream id on a resume and gets
    /// old frames ahead of the new replay, whose sequence numbers it then rejects
    /// ("reader fell behind; reattach", #583). Dropped bytes are not refunded: the relay
    /// they were charged to is gone with its credit.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Retire(u32, u64),
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
    /// The relay gave up its pending key repaint: write the raw output the key's
    /// acknowledgment held, in order, before anything that follows (#477, J799).
    ///
    /// Without it those bytes would never reach the client although the relay
    /// counted them as sent, so its recovery replay would resume after a gap.
    Release {
        /// Mux stream whose held output is written.
        stream: u32,
        /// The relay attachment that sent it ([`next_attachment`]).
        attachment: u64,
    },
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// The writer's side of a relay's refund cell: credit for charged raw bytes the
/// writer dropped (#477, J799).
///
/// The relay charges raw Output to the client's credit when it queues it. When
/// a key's Snapshot replaces queued output, the writer drops those frames, and
/// the client, which never receives them, can never return their credit. The
/// writer adds their length here instead, and the relay applies it as if the
/// client had returned it. Adding never blocks and never allocates; the
/// one-slot doorbell only wakes the relay. Cloning shares the same cell.
#[derive(Clone)]
pub(crate) struct Refunds {
    /// Bytes refunded and not yet taken by the relay.
    bytes: std::sync::Arc<AtomicU64>,
    /// Wakes the relay; a full slot already means "look again".
    bell: mpsc::Sender<()>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// The relay's side of its refund cell (see [`Refunds`]).
pub(crate) struct RefundReceiver {
    /// Bytes refunded and not yet taken.
    bytes: std::sync::Arc<AtomicU64>,
    /// Rings after each refund.
    bell: mpsc::Receiver<()>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
/// A fresh refund cell for one relay ledger.
///
/// A relay makes one when it attaches and another when a trusted cursor rewind
/// resets its ledger: bytes dropped from before the rewind must not be refunded
/// into the reissued credit, which already excludes them.
pub(crate) fn refunds() -> (Refunds, RefundReceiver) {
    let bytes = std::sync::Arc::new(AtomicU64::new(0));
    let (bell, ring) = mpsc::channel(1);
    (
        Refunds {
            bytes: bytes.clone(),
            bell,
        },
        RefundReceiver { bytes, bell: ring },
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Refunds {
    /// Refund `bytes` to the relay. A relay that has gone away just never reads it.
    fn add(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.bytes.fetch_add(bytes, Ordering::AcqRel);
        let _ = self.bell.try_send(());
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RefundReceiver {
    /// Wait for refunded bytes and take them, at most `u32::MAX` at a time (the
    /// size of one Credit grant); any rest stays for the next call.
    ///
    /// Cancel-safe: bytes are taken only in the same poll that returns them.
    /// Once every [`Refunds`] clone is gone it waits forever, so a select arm on
    /// it simply never fires.
    pub(crate) async fn next(&mut self) -> u32 {
        loop {
            // The relay is the only taker, so what it loads is still there to take.
            let bytes = self.bytes.load(Ordering::Acquire);
            if bytes > 0 {
                let grant = u32::try_from(bytes).unwrap_or(u32::MAX);
                self.bytes.fetch_sub(u64::from(grant), Ordering::AcqRel);
                return grant;
            }
            if self.bell.recv().await.is_none() {
                return std::future::pending().await;
            }
        }
    }
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
                client_info: crate::host_os::client_info(),
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
        #[cfg(test)]
        let _ =
            TRACKED_STREAMS.try_with(|count| count.store(replace_through.len(), Ordering::Relaxed));
    }
    Ok(())
}

#[cfg(test)]
tokio::task_local! {
    /// Test-only window into a writer: how many streams its [`ReplaceCursors`] holds after
    /// each item. A test runs a whole channel inside `TRACKED_STREAMS.scope(..)` to watch it;
    /// task-local, so tests running in parallel never see each other's writers.
    pub(crate) static TRACKED_STREAMS: std::sync::Arc<std::sync::atomic::AtomicUsize>;
}

/// Apply a trusted key acknowledgment, repaint or release.
///
/// None of these spends credit; the relay has already charged every frame. A
/// committed repaint refunds the raw bytes it makes the writer drop (see the
/// module docs).
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
            if !replace_through.hold(stream, attachment, output_cursor) {
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
            if !replace_through.commit(stream, attachment, seq) {
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
            // Held raw output below `seq` is now dropped and refunded; anything
            // after it follows the repaint, still ahead of later output.
            write_held(tx, socket, stream, replace_through).await
        }
        PriorityMessage::Release { stream, attachment } => {
            if replace_through.release(stream, attachment) {
                write_held(tx, socket, stream, replace_through).await?;
            }
            Ok(())
        }
    }
}

/// Write the raw frames `stream` holds, in order, through its current cover:
/// committed bytes are dropped and refunded, and the rest is written unless a
/// still-pending acknowledgment holds it again.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn write_held(
    tx: &mut Transmit,
    socket: &impl Channel,
    stream: u32,
    replace_through: &mut ReplaceCursors,
) -> io::Result<()> {
    for (seq, bytes) in replace_through.take_held(stream) {
        if let Some(frame) = replace_through.admit(stream, seq, bytes)? {
            write_shim(tx, socket, stream, frame).await?;
        }
    }
    Ok(())
}

/// Non-terminal builds never hold raw output.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn write_held(
    _: &mut Transmit,
    _: &impl Channel,
    _: u32,
    _: &mut ReplaceCursors,
) -> io::Result<()> {
    Ok(())
}

/// Write one shim frame of `stream` as its protocol frame.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn write_shim(
    tx: &mut Transmit,
    socket: &impl Channel,
    stream: u32,
    frame: Shim,
) -> io::Result<()> {
    let wire = match &frame {
        Shim::Output(seq, bytes) => Frame::Output {
            out_seq: *seq,
            bytes,
        },
        Shim::Snapshot(seq, bytes) | Shim::SnapshotWithFlags(seq, _, bytes) => Frame::Snapshot {
            out_seq: *seq,
            bytes,
        },
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
    Ok(())
}

/// Write an ordinary message, dropping or holding only raw bytes a key passed.
async fn write_message(
    tx: &mut Transmit,
    socket: &impl Channel,
    message: Message,
    replace_through: &mut ReplaceCursors,
) -> io::Result<()> {
    match message {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Message::Shim(stream, Shim::Output(seq, bytes)) => {
            if let Some(frame) = replace_through.admit(stream, seq, bytes)? {
                write_shim(tx, socket, stream, frame).await?;
            } else if replace_through.over_held_limit(stream) {
                // Unreachable while the relay keeps its side (see `Cover::held`):
                // degrade to writing in order instead of growing.
                replace_through.release_any(stream);
                write_held(tx, socket, stream, replace_through).await?;
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Message::Shim(stream, frame) => write_shim(tx, socket, stream, frame).await?,
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
        Message::Attached(stream, attachment, refunds) => {
            replace_through.attach(stream, attachment, refunds);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Message::Forget(stream, floor) => replace_through.forget_before(stream, floor),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Message::Retire(stream, floor) => replace_through.retire(stream, floor),
    }
    Ok(())
}

/// More raw frames than one stream can ever hold (see [`Cover::held`]); past it
/// the writer stops holding and writes them in order, so a misbehaving relay
/// costs a skipped repaint shortcut, never unbounded memory.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const HELD_LIMIT: usize = 64;

/// One stream's key-repaint cover, scoped to the relay attachment that set it (#477).
#[derive(Default)]
struct Cover {
    /// The relay attachment this cover belongs to ([`next_attachment`]).
    attachment: u64,
    /// Exclusive cursor of the latest committed key Snapshot: raw output below
    /// it is replaced, so it is dropped (and refunded) instead of written.
    through: Option<u64>,
    /// Exclusive cursor of a key acknowledgment whose Snapshot has not come
    /// yet: raw output below it waits in `held`.
    pending: Option<u64>,
    /// Raw frames waiting for this stream's Snapshot or release, in FIFO order.
    ///
    /// Bounded twice over: the relay forwards no raw output while a key repaint
    /// is pending, so only what already sat in the FIFO when the acknowledgment
    /// passed it can be held (at most its eight slots), and every held byte is
    /// charged and unreturned, so at most one credit window. [`HELD_LIMIT`]
    /// guards the first bound.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    held: Vec<(u64, Vec<u8>)>,
    /// The server closed the stream and no newer attachment has announced itself yet:
    /// raw output is dropped, not written (see [`Message::Retire`]).
    retired: bool,
    /// Where dropped bytes of this attachment are refunded. `None` until the
    /// attachment's own marker arrives: frames queued before the marker belong
    /// to an older ledger that must not be refunded.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    refunds: Option<Refunds>,
}

impl Cover {
    /// A clean cover for `attachment`, with nothing held or covered.
    fn new(attachment: u64) -> Self {
        Self {
            attachment,
            ..Self::default()
        }
    }

    /// Drop the bytes of one raw frame that the committed Snapshot replaces and
    /// refund them; return what is left, if anything.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn trim(&self, seq: u64, bytes: Vec<u8>) -> io::Result<Option<(u64, Vec<u8>)>> {
        let Some(through) = self.through else {
            return Ok(Some((seq, bytes)));
        };
        let length = u64::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidData)?;
        let end = seq.checked_add(length).ok_or(io::ErrorKind::InvalidData)?;
        if end <= through {
            self.refund(length);
            return Ok(None);
        }
        if seq < through {
            let prefix = usize::try_from(through - seq).map_err(|_| io::ErrorKind::InvalidData)?;
            self.refund(through - seq);
            return Ok(Some((through, bytes[prefix..].to_vec())));
        }
        Ok(Some((seq, bytes)))
    }

    /// Hand `bytes` of dropped output back to this attachment's relay.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn refund(&self, bytes: u64) {
        if let Some(refunds) = &self.refunds {
            refunds.add(bytes);
        }
    }
}

/// Per-stream key-repaint covers for one writer, each scoped to the relay
/// attachment that set it (#477).
///
/// A key's Ack or repaint overtakes queued raw output on the priority lane, so
/// the writer holds, and once the repaint commits drops, the raw bytes that
/// repaint covers (see the module docs). That cursor is only true for the
/// attachment that produced it: when the server closes a stream and a resumed
/// browser reattaches the same stream id, the new relay replays from the
/// browser's cursor, which is usually far below the old one.
/// [`Message::Attached`] therefore starts a clean slate, and priority messages
/// from an older attachment neither move the cursor nor reach the wire. A
/// newer attachment's priority message starts that clean slate itself when it
/// overtakes its own marker.
#[derive(Default)]
struct ReplaceCursors {
    /// Stream id to its current cover.
    streams: HashMap<u32, Cover>,
}

impl ReplaceCursors {
    /// A new attachment (or cursor rewind) owns `stream` from here on, with nothing covered yet;
    /// its dropped bytes are refunded to `refunds`.
    ///
    /// The marker rides the bulk FIFO, so the same attachment's priority frames may already
    /// have reached the writer and adopted it (see [`Self::adopt`]). Attachment ids only grow,
    /// so an entry that already holds this id keeps its cursors and only gains the refund
    /// cell, and an entry with a newer id ignores the marker: resetting it would let the
    /// rewound replay queued behind the marker reach the wire after a Snapshot that already
    /// covers it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn attach(&mut self, stream: u32, attachment: u64, refunds: Refunds) {
        let entry = self
            .streams
            .entry(stream)
            .or_insert_with(|| Cover::new(attachment));
        if entry.attachment < attachment {
            *entry = Cover::new(attachment);
        }
        if entry.attachment == attachment {
            entry.refunds = Some(refunds);
        }
    }

    /// The server closed `stream`: stop writing raw output the old relay queued, until a
    /// relay newer than `floor` announces itself with its marker.
    ///
    /// The cover takes the floor as its attachment id, so the old relay's own stale marker
    /// and priority messages are ignored, and a newer attachment replaces it cleanly. A
    /// newer attachment that already owns the stream (it overtook this message) is left alone.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn retire(&mut self, stream: u32, floor: u64) {
        let entry = self
            .streams
            .entry(stream)
            .or_insert_with(|| Cover::new(floor));
        if entry.attachment < floor {
            *entry = Cover::new(floor);
        }
        if entry.attachment == floor {
            entry.retired = true;
        }
    }

    /// The stream closed: drop its state so a later stream with the same id starts clean.
    fn forget(&mut self, stream: u32) {
        self.streams.remove(&stream);
    }

    /// The server closed `stream`: drop its state unless a relay that attached after
    /// the close (an id above `floor`) already owns it. A retired cover (id == `floor`) goes too.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn forget_before(&mut self, stream: u32, floor: u64) {
        if self
            .streams
            .get(&stream)
            .is_some_and(|entry| entry.attachment <= floor)
        {
            self.streams.remove(&stream);
        }
    }

    /// How many streams currently hold state; the close tests check it returns to zero.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.streams.len()
    }

    /// The cover of `stream` for a priority message from `attachment`, or `None` for a stale
    /// (older) attachment.
    ///
    /// A stale frame must not be written, because the browser is now attached through a
    /// different relay whose credit and cursor it knows nothing about. A stream with no
    /// recorded attachment adopts this one (writers fed without markers, such as tests and
    /// the native bound relay before its first marker).
    ///
    /// A newer attachment than the recorded one also adopts the stream. Its `Attached`
    /// marker is still queued behind earlier bulk output (#477, J730): the relay has already
    /// charged credit for this frame and moved its cursor, so dropping it would lose the
    /// key's echo and leak credit. Ids come from [`next_attachment`], which only grows, so
    /// "newer" means "the live one". Output the older attachment queued is not this ledger's
    /// to refund, so the adopted cover refunds nothing until its own marker arrives.
    fn adopt(&mut self, stream: u32, attachment: u64) -> Option<&mut Cover> {
        let entry = self
            .streams
            .entry(stream)
            .or_insert_with(|| Cover::new(attachment));
        if entry.attachment > attachment {
            return None;
        }
        if entry.attachment < attachment {
            *entry = Cover::new(attachment);
        }
        Some(entry)
    }

    /// A key acknowledgment from `attachment` holds `stream`'s raw output below `through`
    /// until its Snapshot commits or the relay releases it. Returns false for a stale
    /// attachment, whose Ack is not written.
    fn hold(&mut self, stream: u32, attachment: u64, through: u64) -> bool {
        let Some(entry) = self.adopt(stream, attachment) else {
            return false;
        };
        entry.pending = Some(entry.pending.map_or(through, |cursor| cursor.max(through)));
        true
    }

    /// A key Snapshot from `attachment` replaces `stream`'s raw output below `through`.
    /// Returns false for a stale attachment, whose Snapshot is not written. Raw frames held
    /// so far are then settled by [`write_held`].
    fn commit(&mut self, stream: u32, attachment: u64, through: u64) -> bool {
        let Some(entry) = self.adopt(stream, attachment) else {
            return false;
        };
        let through = entry.through.map_or(through, |cursor| cursor.max(through));
        entry.through = Some(through);
        // A repaint always captures at or past its key's acknowledged cursor.
        entry.pending = entry.pending.filter(|pending| *pending > through);
        true
    }

    /// The relay of `attachment` abandoned its key repaint: stop holding `stream`'s raw output.
    /// Returns whether there may be held frames to write now.
    fn release(&mut self, stream: u32, attachment: u64) -> bool {
        match self.streams.get_mut(&stream) {
            Some(entry) if entry.attachment == attachment => {
                entry.pending = None;
                true
            }
            _ => false,
        }
    }

    /// Take `stream`'s held raw frames, oldest first, to write them through [`Self::admit`].
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn take_held(&mut self, stream: u32) -> Vec<(u64, Vec<u8>)> {
        self.streams
            .get_mut(&stream)
            .map(|entry| std::mem::take(&mut entry.held))
            .unwrap_or_default()
    }

    /// Decide what happens to one raw Output frame of `stream`: the part to write now, or
    /// `None` when a committed repaint replaced it all (refunded) or a pending
    /// acknowledgment holds it.
    ///
    /// A stream with no cover, the steady state of a flood, costs the same single map
    /// lookup as before holding existed.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn admit(&mut self, stream: u32, seq: u64, bytes: Vec<u8>) -> io::Result<Option<Shim>> {
        let Some(entry) = self.streams.get_mut(&stream) else {
            return Ok(Some(Shim::Output(seq, bytes)));
        };
        if entry.retired {
            return Ok(None);
        }
        let Some((seq, bytes)) = entry.trim(seq, bytes)? else {
            return Ok(None);
        };
        // Once one frame is held, later ones queue behind it to keep their order.
        if entry.pending.is_some_and(|pending| seq < pending) || !entry.held.is_empty() {
            entry.held.push((seq, bytes));
            return Ok(None);
        }
        Ok(Some(Shim::Output(seq, bytes)))
    }

    /// Whether `stream` holds more raw frames than [`HELD_LIMIT`].
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn over_held_limit(&self, stream: u32) -> bool {
        self.streams
            .get(&stream)
            .is_some_and(|entry| entry.held.len() > HELD_LIMIT)
    }

    /// Stop holding `stream`'s raw output, whichever attachment holds it.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn release_any(&mut self, stream: u32) {
        if let Some(entry) = self.streams.get_mut(&stream) {
            entry.pending = None;
        }
    }

    /// The committed cursor for `stream`'s current attachment, if a repaint set one.
    #[cfg(test)]
    fn through(&self, stream: u32) -> Option<u64> {
        self.streams.get(&stream).and_then(|entry| entry.through)
    }
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
        messages
            .send(Message::Attached(4, 1, no_refunds()))
            .await
            .unwrap();
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
        messages
            .send(Message::Attached(4, 2, no_refunds()))
            .await
            .unwrap();
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
        let (refunds, mut refunded) = refunds();
        messages
            .send(Message::Attached(4, 7, refunds))
            .await
            .unwrap();
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
        // The current attachment's repaint commits the Ack's cover.
        priority
            .send(PriorityMessage::Snapshot {
                stream: 4,
                attachment: 7,
                seq: 150,
                bytes: b"new screen".to_vec(),
                approximate: false,
                notice: None,
            })
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
        // The current attachment's repaint covers through 150, so only its tail of the later
        // Output remains, and the 50 bytes it replaced go back to that attachment's relay.
        assert_eq!(
            kinds,
            vec![
                "ack 3".to_string(),
                "snapshot".to_string(),
                "output 150+50".to_string()
            ]
        );
        assert_eq!(refunded_within_a_moment(&mut refunded).await, 50);
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
        messages
            .send(Message::Attached(4, 1, no_refunds()))
            .await
            .unwrap();
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
        messages
            .send(Message::Attached(4, 2, no_refunds()))
            .await
            .unwrap();
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

    /// The Close/reattach race of #583, forced deterministically: the old relay still has raw
    /// output queued in the bulk FIFO when the server closes the stream and reattaches the
    /// same stream id. The retire notice rides the control lane, which the writer serves ahead
    /// of the FIFO, so none of the old output may reach the wire, a control reply sent after
    /// the close (the fence) still comes before everything, and the new attachment's replay
    /// from a lower cursor passes untouched.
    #[tokio::test]
    async fn output_queued_by_a_closed_relay_never_reaches_the_wire() {
        let (frames, mut frames_rx) = mpsc::unbounded_channel();
        let channel = Arc::new(HeldWriter {
            first_write: AtomicBool::new(true),
            started: Semaphore::new(0),
            release: Semaphore::new(0),
            frames,
        });
        let (messages, messages_rx) = mpsc::channel(16);
        let (control, control_rx) = mpsc::channel(8);
        let writer_channel = channel.clone();
        let task = tokio::spawn(async move {
            writer(
                writer_channel.as_ref(),
                messages_rx,
                Some(control_rx),
                None,
                false,
                false,
                false,
                0,
            )
            .await
        });
        // The old relay (attachment 1) has its first frame mid-write; three more wait behind it.
        messages
            .send(Message::Attached(4, 1, no_refunds()))
            .await
            .unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(0, vec![b'a'; 100])))
            .await
            .unwrap();
        channel.started.acquire().await.unwrap().forget();
        for seq in [100, 200, 300] {
            messages
                .send(Message::Shim(4, Shim::Output(seq, vec![b'o'; 100])))
                .await
                .unwrap();
        }
        // The server closes the stream (retire + fence), then reattaches the same stream id
        // at a lower cursor: marker plus replay queue behind the old output.
        control.send(Message::Retire(4, 5)).await.unwrap();
        control.send(Message::Pong(4, 1, 0)).await.unwrap();
        messages.send(Message::Forget(4, 5)).await.unwrap();
        messages
            .send(Message::Attached(4, 6, no_refunds()))
            .await
            .unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(50, vec![b'n'; 10])))
            .await
            .unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(60, vec![b'n'; 10])))
            .await
            .unwrap();
        channel.release.add_permits(1);
        // Closing the bulk queue ends the writer once it is drained; closing the control
        // sender first would end it at once (it is the end-of-channel signal), so keep it.
        drop(messages);
        task.await.unwrap().unwrap();
        drop(control);
        let mut kinds = vec![];
        while let Ok(frame) = frames_rx.try_recv() {
            kinds.push(match decoded(&frame) {
                (4, infraternal_protocol::Frame::Output { out_seq, bytes }) => {
                    format!("output {out_seq}+{}", bytes.len())
                }
                (4, infraternal_protocol::Frame::Pong { .. }) => "pong".to_string(),
                (stream, _) => format!("other {stream}"),
            });
        }
        assert_eq!(
            kinds,
            vec!["output 0+100", "pong", "output 50+10", "output 60+10"],
            "frames of the closed relay leaked past the close"
        );
    }

    /// A retired cover is cleaned by the relay's own Forget, spares a replacement that already
    /// announced itself, and ignores the old relay's stale marker (#583).
    #[test]
    fn a_retired_stream_drops_only_the_old_relays_output() {
        let mut cursors = ReplaceCursors::default();
        cursors.attach(4, 1, no_refunds());
        cursors.retire(4, 5);
        // The old relay's stale marker cannot revive the stream.
        cursors.attach(4, 2, no_refunds());
        assert!(cursors.admit(4, 0, vec![1; 10]).unwrap().is_none());
        // A newer attachment's marker reopens it.
        cursors.attach(4, 6, no_refunds());
        assert!(cursors.admit(4, 0, vec![1; 10]).unwrap().is_some());
        // A retire that arrives after the replacement's marker leaves it alone.
        cursors.retire(4, 5);
        assert!(cursors.admit(4, 10, vec![1; 10]).unwrap().is_some());
        // Retire with no earlier state, then the relay's Forget, leaves nothing behind.
        cursors.retire(8, 7);
        assert!(cursors.admit(8, 0, vec![1; 10]).unwrap().is_none());
        cursors.forget_before(8, 7);
        assert!(cursors.admit(8, 0, vec![1; 10]).unwrap().is_some());
        assert_eq!(cursors.len(), 1);
    }

    /// A stream the server closed leaves no writer state behind, but a relay that
    /// reattached the same stream id after the close keeps its own (#477, J730 P3).
    #[test]
    fn forgetting_a_closed_stream_spares_its_replacement() {
        let mut cursors = ReplaceCursors::default();
        cursors.attach(4, 3, no_refunds());
        assert!(cursors.commit(4, 3, 100));
        cursors.attach(6, 4, no_refunds());
        cursors.forget_before(4, 5);
        assert_eq!(cursors.len(), 1, "stream 4's closed attachment was kept");
        cursors.attach(6, 7, no_refunds());
        cursors.forget_before(6, 6);
        assert_eq!(cursors.through(6), None);
        assert_eq!(cursors.len(), 1, "the replacement attachment 7 was dropped");
    }

    /// Bytes a committed repaint drops are refunded only to the ledger that charged them: output
    /// queued before a newer attachment's marker belongs to the older ledger, which a rewind
    /// reset or a gone relay no longer counts, so nobody gets it back (#477, J799).
    #[test]
    fn refunds_go_only_to_the_ledger_that_charged_the_bytes() {
        let mut cursors = ReplaceCursors::default();
        let (old, old_refunds) = refunds();
        let (new, new_refunds) = refunds();
        cursors.attach(4, 1, old);
        // Attachment 2's repaint overtakes its marker and adopts the stream.
        assert!(cursors.commit(4, 2, 250));
        // Attachment 1's queued output, ahead of attachment 2's marker.
        assert!(cursors.admit(4, 100, vec![b'o'; 100]).unwrap().is_none());
        cursors.attach(4, 2, new);
        // Attachment 2's own rewound replay, behind its marker.
        assert!(cursors.admit(4, 50, vec![b'r'; 200]).unwrap().is_none());
        // Its tail past the repaint is written, and only the covered part is refunded.
        assert!(matches!(
            cursors.admit(4, 250, vec![b't'; 10]).unwrap(),
            Some(Shim::Output(250, bytes)) if bytes.len() == 10
        ));
        assert_eq!(old_refunds.bytes.load(Ordering::Acquire), 0);
        assert_eq!(new_refunds.bytes.load(Ordering::Acquire), 200);
    }

    /// Start a writer whose stream 4 (attachment 1, refunded to the returned cell) has a key
    /// Ack holding its raw output below 300, and hold three frames there: `0+100`, `100+100`
    /// and `200+200`. A sibling frame written after them proves the writer has taken them.
    async fn writer_holding_three_frames() -> (
        mpsc::Sender<Message>,
        mpsc::Sender<PriorityMessage>,
        mpsc::UnboundedReceiver<Vec<u8>>,
        JoinHandle<io::Result<()>>,
        RefundReceiver,
    ) {
        let (messages, priority, mut frames, task) =
            open_writer(Message::Shim(9, Shim::Output(0, b"sibling".to_vec()))).await;
        let (cell, refunded) = refunds();
        messages.send(Message::Attached(4, 1, cell)).await.unwrap();
        priority
            .send(PriorityMessage::InputAck {
                stream: 4,
                attachment: 1,
                seq: 1,
                output_cursor: 300,
            })
            .await
            .unwrap();
        assert!(matches!(
            decoded(&frames.recv().await.unwrap()),
            (4, infraternal_protocol::Frame::Ack { in_seq_acked: 1 })
        ));
        for (seq, length) in [(0, 100), (100, 100), (200, 200)] {
            messages
                .send(Message::Shim(4, Shim::Output(seq, vec![b'h'; length])))
                .await
                .unwrap();
        }
        messages
            .send(Message::Shim(9, Shim::Output(7, b"later".to_vec())))
            .await
            .unwrap();
        assert!(matches!(
            decoded(&frames.recv().await.unwrap()),
            (9, infraternal_protocol::Frame::Output { out_seq: 7, .. })
        ));
        (messages, priority, frames, task, refunded)
    }

    /// The key's Snapshot settles what its Ack held: covered bytes are dropped and refunded
    /// (including a covered prefix), and the uncovered rest follows the Snapshot (#477, J799).
    #[tokio::test]
    async fn a_committed_repaint_settles_the_output_its_ack_held() {
        let (messages, priority, mut frames, task, mut refunded) =
            writer_holding_three_frames().await;
        priority
            .send(PriorityMessage::Snapshot {
                stream: 4,
                attachment: 1,
                seq: 300,
                bytes: b"screen".to_vec(),
                approximate: false,
                notice: None,
            })
            .await
            .unwrap();
        assert!(matches!(
            decoded(&frames.recv().await.unwrap()),
            (
                4,
                infraternal_protocol::Frame::Snapshot { out_seq: 300, .. }
            )
        ));
        drop(messages);
        drop(priority);
        task.await.unwrap().unwrap();
        assert_eq!(outputs(&mut frames), vec![(4, 300, 100)]);
        assert_eq!(refunded_within_a_moment(&mut refunded).await, 300);
    }

    /// A relay that abandons its key repaint releases what the key's Ack held: every frame is
    /// written, in order, ahead of later output, and nothing is refunded (#477, J799).
    #[tokio::test]
    async fn a_released_cover_writes_the_held_output_in_order() {
        let (messages, priority, mut frames, task, refunded) = writer_holding_three_frames().await;
        priority
            .send(PriorityMessage::Release {
                stream: 4,
                attachment: 1,
            })
            .await
            .unwrap();
        messages
            .send(Message::Shim(4, Shim::Output(400, vec![b'n'; 50])))
            .await
            .unwrap();
        drop(messages);
        drop(priority);
        task.await.unwrap().unwrap();
        assert_eq!(
            outputs(&mut frames),
            vec![(4, 0, 100), (4, 100, 100), (4, 200, 200), (4, 400, 50)]
        );
        assert_eq!(refunded.bytes.load(Ordering::Acquire), 0);
    }

    /// A stream never holds more than [`HELD_LIMIT`] raw frames: past it the writer gives up the
    /// pending cover and writes them all, in order (#477, J799).
    #[tokio::test]
    async fn held_output_past_its_limit_is_written_in_order() {
        let (messages, priority, mut frames, task) =
            open_writer(Message::Shim(9, Shim::Output(0, b"sibling".to_vec()))).await;
        messages
            .send(Message::Attached(4, 1, no_refunds()))
            .await
            .unwrap();
        priority
            .send(PriorityMessage::InputAck {
                stream: 4,
                attachment: 1,
                seq: 1,
                output_cursor: 1_000_000,
            })
            .await
            .unwrap();
        frames.recv().await.unwrap();
        let count = HELD_LIMIT + 2;
        for frame in 0..count {
            messages
                .send(Message::Shim(
                    4,
                    Shim::Output(frame as u64 * 10, vec![b'h'; 10]),
                ))
                .await
                .unwrap();
        }
        drop(messages);
        drop(priority);
        task.await.unwrap().unwrap();
        let expected: Vec<_> = (0..count).map(|frame| (4, frame as u64 * 10, 10)).collect();
        assert_eq!(outputs(&mut frames), expected);
    }

    /// The marker of an attachment whose priority frames already adopted the stream keeps
    /// their covered cursor, and an older marker never takes the stream back (#477, J730).
    #[test]
    fn a_late_marker_keeps_the_cursor_its_own_attachment_covered() {
        let mut cursors = ReplaceCursors::default();
        cursors.attach(4, 1, no_refunds());
        assert!(cursors.commit(4, 2, 250));
        cursors.attach(4, 2, no_refunds());
        assert_eq!(cursors.through(4), Some(250));
        cursors.attach(4, 1, no_refunds());
        assert_eq!(cursors.through(4), Some(250));
        assert!(
            !cursors.commit(4, 1, 900),
            "an older attachment's frame was written"
        );
        cursors.attach(4, 3, no_refunds());
        assert_eq!(cursors.through(4), None);
    }

    /// The bytes refunded so far, or 0 if none arrive within a generous moment; a test that
    /// waits for a refund must fail, not hang, when there is none.
    async fn refunded_within_a_moment(refunded: &mut RefundReceiver) -> u32 {
        tokio::time::timeout(std::time::Duration::from_secs(1), refunded.next())
            .await
            .unwrap_or(0)
    }

    /// A refund cell whose relay is gone, for writers whose credit a test does not watch.
    fn no_refunds() -> Refunds {
        refunds().0
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
