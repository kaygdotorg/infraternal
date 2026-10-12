//! Owns each browser terminal's cancellable Input/Resize FIFO while durable input credit is parked [128][215].

use crate::embedded::{AttachmentHandle, TerminalOutput};
use bytes::Bytes;
use std::sync::Arc;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinHandle,
};

// Count the executing request as well as queued requests. Wire bytes include
// mux/header overhead; a single maximum legal Input must fit without a copy.
const REQUESTS: usize = 8;
const WIRE_BYTES: usize = infraternal_protocol::MAX_FRAME_LEN + 128;

struct Request {
    wire: Bytes,
    _bytes: OwnedSemaphorePermit,
    _slot: OwnedSemaphorePermit,
}

/// Dropping the attachment cancels its pending send and releases all FIFO storage.
pub(super) struct InputQueue {
    sender: mpsc::Sender<Request>,
    bytes: Arc<Semaphore>,
    slots: Arc<Semaphore>,
    worker: JoinHandle<()>,
}

impl InputQueue {
    pub(super) fn new(
        handle: AttachmentHandle,
        stream: u32,
        output: mpsc::Sender<(u32, TerminalOutput)>,
    ) -> Self {
        let (sender, mut receiver) = mpsc::channel::<Request>(REQUESTS);
        let worker = tokio::spawn(async move {
            while let Some(request) = receiver.recv().await {
                if handle.send_frame(request.wire.clone()).await.is_err() {
                    let _ = output
                        .send((stream, TerminalOutput::Closed { code: 1013 }))
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
                wire,
                _bytes: bytes,
                _slot: slot,
            })
            .map_err(|_| ())
    }
}

impl Drop for InputQueue {
    fn drop(&mut self) {
        self.worker.abort();
    }
}
