//! Bounds SSH input by receive credit while keeping runtime I/O off callbacks.
//!
//! One input worker per channel returns credit only after a successful downstream
//! write. A byte queue bounds tiny packets as well as full packets. Output uses
//! the engine's peer-window-aware writer; `Handle::data` must not bypass it.

use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    sync::Notify,
};

/// Per-channel byte budget, allocated lazily; 500 active inputs use at most
/// 32 MiB of queued/in-flight input, independent of peer packet fragmentation.
pub const RECEIVE_WINDOW: u32 = 64 * 1024;
/// Both directions split transfers into bounded work units.
pub const PACKET_BYTES: usize = 16 * 1024;

/// Queue contents shared between the SSH callback and the input worker.
#[derive(Default)]
struct State {
    /// Received bytes not yet handed to the downstream writer.
    bytes: VecDeque<u8>,
    /// The peer sent EOF; no more bytes will be accepted after this.
    eof: bool,
}

/// The SSH callback only copies bytes and wakes the sole input worker.
#[derive(Clone, Default)]
pub struct Ingress {
    /// The queue, behind a short-held lock (never held across an await).
    state: Arc<Mutex<State>>,
    /// Wakes the worker when bytes or EOF arrive.
    ready: Arc<Notify>,
}

impl Ingress {
    /// Enqueue without waiting for the runtime. Engine receive credit bounds
    /// queue plus in-flight bytes; the extra bound refuses inconsistent peers.
    /// # Errors
    /// Refuses data after EOF, overflow or an unavailable queue.
    pub fn push(&self, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| io::ErrorKind::BrokenPipe)?;
        if state.eof || bytes.len() > RECEIVE_WINDOW as usize - state.bytes.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        state.bytes.extend(bytes);
        drop(state);
        self.ready.notify_one();
        Ok(())
    }

    /// EOF is ordered after the queued bytes, rather than a separate input task.
    /// # Errors
    /// Refuses an unavailable queue.
    pub fn eof(&self) -> io::Result<()> {
        self.state
            .lock()
            .map_err(|_| io::ErrorKind::BrokenPipe)?
            .eof = true;
        self.ready.notify_one();
        Ok(())
    }

    /// Wait for queued bytes and move up to `output.len()` of them into `output`.
    /// Returns the count; `0` means EOF with an empty queue.
    async fn next(&self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            let ready = self.ready.notified();
            tokio::pin!(ready);
            // Register before checking the queue to avoid a lost wake between
            // the empty check and the producer's notification.
            ready.as_mut().enable();
            {
                let mut state = self.state.lock().map_err(|_| io::ErrorKind::BrokenPipe)?;
                let count = output.len().min(state.bytes.len());
                for byte in &mut output[..count] {
                    *byte = state.bytes.pop_front().ok_or(io::ErrorKind::InvalidData)?;
                }
                if count > 0 || state.eof {
                    return Ok(count);
                }
            }
            ready.await;
        }
    }

    /// Run the single consumer. Batch only accepted bytes into half-window
    /// credit updates, flushing a short remainder at EOF. Updates stay serialized
    /// to bound the engine queue; no timer or idle polling is needed.
    /// # Errors
    /// Returns downstream I/O or credit-accounting failure; callers retire the
    /// attachment instead of silently losing bytes.
    pub async fn forward<W, F, R>(&self, mut writer: W, mut consumed: F) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(u32) -> R,
        R: Future<Output = io::Result<()>>,
    {
        let mut buffer = vec![0; PACKET_BYTES];
        let mut credit = 0;
        loop {
            let count = self.next(&mut buffer).await?;
            if count == 0 {
                if credit > 0 {
                    consumed(credit).await?;
                }
                return writer.shutdown().await;
            }
            let mut remaining = &buffer[..count];
            while !remaining.is_empty() {
                let written = writer.write(remaining).await?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                remaining = remaining.get(written..).ok_or(io::ErrorKind::InvalidData)?;
                credit += u32::try_from(written).map_err(|_| io::ErrorKind::InvalidData)?;
                // Half-window batches avoid an acknowledged engine message per
                // tiny downstream write. Credit still names only accepted bytes;
                // pending credit is below half a window plus one bounded chunk.
                if credit >= RECEIVE_WINDOW / 2 {
                    consumed(credit).await?;
                    credit = 0;
                }
            }
        }
    }
}
