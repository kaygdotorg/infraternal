//! Shares bounded control-first output and deferred effect ordering across supported node platforms [D198,D232].
use crate::{channel::Channel, transport::Transmit};
use infraternal_protocol::Frame;
#[cfg(target_os = "linux")]
use infraternal_shim::frame::Frame as Shim;
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
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
    #[cfg(target_os = "linux")]
    Shim(u32, Shim),
    Result(u32, u32, bool, Vec<u8>),
    Deferred(u32, u32, infraternal_plugin_api::ActionReply),
    Event(u32, Vec<u8>),
    #[cfg(target_os = "linux")]
    Exited(u32, Vec<u8>, oneshot::Sender<()>),
    Pong(u32, u64, u64),
    #[cfg(target_os = "linux")]
    Close(u32, &'static str),
    /// The session's shim is gone: a final stream close, never retried (wire §4).
    Ended(u32),
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

#[allow(clippy::too_many_lines)]
pub(crate) async fn writer(
    socket: &impl Channel,
    mut messages: mpsc::Receiver<Message>,
    mut control: Option<mpsc::Receiver<Message>>,
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
    // Only dispatch owns the control sender. Its closure ends this channel;
    // bulk events retain their FIFO order, including notice before Snapshot.
    while let Some(message) = tokio::select! {
        biased;
        message = async {
            match control.as_mut() {
                Some(receiver) => receiver.recv().await,
                None => std::future::pending().await,
            }
        } => message,
        message = messages.recv() => message,
    } {
        match message {
            #[cfg(target_os = "linux")]
            Message::Shim(stream, frame) => {
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
                deferred_reply(&mut tx, socket, stream, call_id, reply).await?;
            }
            Message::Event(stream, json) => write_event(&mut tx, socket, stream, &json).await?,
            #[cfg(target_os = "linux")]
            Message::Exited(stream, json, delivered) => {
                write_event(&mut tx, socket, stream, &json).await?;
                let _ = delivered.send(());
            }
            Message::Pong(stream, nonce, sent_us) => {
                tx.send(socket, stream, &Frame::Pong { nonce, sent_us })
                    .await?;
            }
            Message::Ended(stream) => {
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
            #[cfg(target_os = "linux")]
            Message::Close(stream, reason) => {
                tx.send(socket, stream, &Frame::Close { code: 1, reason })
                    .await?;
            }
        }
    }
    Ok(())
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
