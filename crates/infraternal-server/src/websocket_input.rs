//! Owns each browser terminal's cancellable Input/Resize/reply FIFO while durable input credit is parked [128][215][307].

use crate::{
    embedded::{AttachmentHandle, TerminalOutput},
    stream_close::CloseWho,
};
use bytes::Bytes;
use std::sync::Arc;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinHandle,
};

// Count the executing request as well as queued requests. Wire bytes include
// mux/header overhead; a single maximum legal Input must fit without a copy.
/// Most requests in flight per terminal: the one being sent plus those queued behind it.
const REQUESTS: usize = 8;
/// Wire bytes one terminal may hold in its queue. Room for one maximum-size legal Input frame plus multiplexing overhead.
const WIRE_BYTES: usize = infraternal_protocol::MAX_FRAME_LEN + 128;
// Reply claims are already bounded per session. Separate reservations keep
// those small best-effort frames from spending keyboard capacity.
/// Reply slots per terminal, separate from keyboard slots so small terminal-query replies never use up input capacity.
const REPLY_REQUESTS: usize = crate::terminal_queries::POSITIONS;

/// An item waiting to be sent to the host.
enum QueuedFrame {
    /// An ordinary encoded frame (Input or Resize).
    Wire(Bytes),
    /// An answer to a terminal query. It is dropped, not delayed, once `expires` passes.
    Reply {
        query_seq: u64,
        bytes: Bytes,
        expires: std::time::Instant,
    },
}

/// One queued frame plus the permits it holds. The permits are released when it is dropped, after forwarding finishes.
struct Request {
    frame: QueuedFrame,
    _bytes: Option<OwnedSemaphorePermit>,
    _slot: OwnedSemaphorePermit,
}

/// Dropping the attachment cancels its pending send and releases all FIFO storage.
pub(super) struct InputQueue {
    sender: mpsc::Sender<Request>,
    bytes: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    reply_slots: Arc<Semaphore>,
    worker: JoinHandle<()>,
}

impl InputQueue {
    /// Starts the worker task that sends queued frames to `handle` in order for terminal `stream`.
    /// If sending fails, it reports a server-initiated close (code 1013) on `output` and stops.
    pub(super) fn new(
        handle: AttachmentHandle,
        stream: u32,
        output: mpsc::Sender<(u32, TerminalOutput)>,
    ) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Request>(REQUESTS + REPLY_REQUESTS);
        let worker = tokio::spawn(async move {
            let mut frames_need_fence = false;
            while let Some(request) = receiver.recv().await {
                let failed = match &request.frame {
                    QueuedFrame::Wire(wire) => {
                        let failed = handle.send_frame(wire.clone()).await.is_err();
                        frames_need_fence = true;
                        failed
                    }
                    QueuedFrame::Reply {
                        query_seq,
                        bytes,
                        expires,
                    } => {
                        let delivered = if std::time::Instant::now() >= *expires {
                            false
                        } else if frames_need_fence {
                            handle
                                .reply_after_queued_input(*query_seq, bytes.clone(), *expires)
                                .await
                        } else {
                            handle.reply(*query_seq, bytes.clone(), *expires)
                        };
                        if delivered {
                            // Consecutive replies reuse the publication fence;
                            // only another ordinary frame needs a new one.
                            frames_need_fence = false;
                        } else {
                            crate::terminal_queries::record_drop();
                        }
                        false
                    }
                };
                if failed {
                    let _ = output
                        .send((
                            stream,
                            TerminalOutput::Closed {
                                who: CloseWho::Server,
                                code: 1013,
                                reason: "remote stream unavailable",
                            },
                        ))
                        .await;
                    return;
                }
                // Keep both reservations until forwarding finishes, including
                // the durable-Ack wait. Buffered Bytes clones share storage.
                drop(request);
            }
        });
        Self {
            sender,
            bytes: Arc::new(Semaphore::new(WIRE_BYTES)),
            slots: Arc::new(Semaphore::new(REQUESTS)),
            reply_slots: Arc::new(Semaphore::new(REPLY_REQUESTS)),
            worker,
        }
    }

    /// Admission never waits: only this terminal is retired on overload.
    pub(super) fn enqueue(&self, wire: Bytes) -> Result<(), ()> {
        let length = u32::try_from(wire.len()).map_err(|_| ())?;
        let bytes = self
            .bytes
            .clone()
            .try_acquire_many_owned(length)
            .map_err(|_| ())?;
        let slot = self.slots.clone().try_acquire_owned().map_err(|_| ())?;
        self.sender
            .try_send(Request {
                frame: QueuedFrame::Wire(wire),
                _bytes: Some(bytes),
                _slot: slot,
            })
            .map_err(|_| ())
    }

    /// Replies retain their wire position without using keyboard bytes or slots.
    /// Expired or full reply admission is a drop, never a writer retirement.
    pub(super) fn reply(&self, query_seq: u64, bytes: Bytes, expires: std::time::Instant) -> bool {
        if bytes.is_empty() || bytes.len() > 1024 || std::time::Instant::now() >= expires {
            return false;
        }
        let Ok(slot) = self.reply_slots.clone().try_acquire_owned() else {
            return false;
        };
        self.sender
            .try_send(Request {
                frame: QueuedFrame::Reply {
                    query_seq,
                    bytes,
                    expires,
                },
                _bytes: None,
                _slot: slot,
            })
            .is_ok()
    }
}

impl Drop for InputQueue {
    /// Stops the worker. Anything still queued is discarded.
    fn drop(&mut self) {
        self.worker.abort();
    }
}
