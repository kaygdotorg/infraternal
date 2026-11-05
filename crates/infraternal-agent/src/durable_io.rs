//! Bounded disk work for login authority, terminal records and image publication.
//!
//! Reserve admission before opening a fence. At most two ordinary jobs enter Tokio's
//! blocking pool; sixteen others may wait cooperatively. Cancellation removes
//! an unstarted payload immediately. Once a worker takes it, the write and its
//! fences live through completion, even if the caller disappears. Revocation
//! has one additional operation and execution slot ordinary saves cannot consume;
//! its bounded intent queue lives in `logins::revocations`.
use std::{
    io,
    sync::{Arc, Mutex},
};
use tokio::sync::{Semaphore, SemaphorePermit};

/// Keep durable writes from exhausting the shared blocking worker pool.
pub(crate) const WORKERS: usize = 2;
/// Bound futures and their owned fences while they await execution capacity.
pub(crate) const WAITING: usize = 16;
/// Admission includes both submitted work and cooperative waiters.
static ADMISSIONS: Semaphore = Semaphore::const_new(WORKERS + WAITING);
/// A submitted job retains its execution slot until Tokio consumes it.
static EXECUTIONS: Semaphore = Semaphore::const_new(WORKERS);
/// One security operation retains its permit through marker sync and cleanup.
static SECURITY_ADMISSION: Semaphore = Semaphore::const_new(1);
/// Ordinary disk submissions cannot occupy the revocation execution slot.
static SECURITY_EXECUTION: Semaphore = Semaphore::const_new(1);

/// An admitted operation may retain one fence through several durable stages.
#[derive(Debug)]
pub(crate) struct Admission {
    /// Returned only after the operation, including any pending disk work, ends.
    _slot: SemaphorePermit<'static>,
    /// Each lane waits only for its own submitted-work capacity.
    execution: &'static Semaphore,
}

/// Reject overload before acquiring descriptors or copying owned request data.
pub(crate) fn admit() -> io::Result<Admission> {
    ADMISSIONS
        .try_acquire()
        .map(|slot| Admission {
            _slot: slot,
            execution: &EXECUTIONS,
        })
        .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "durable write queue is busy"))
}

/// Wait for reserved security capacity without opening a fence or refusing intent.
/// The bounded revocation owner retains denial while this permit is unavailable.
pub(crate) async fn security() -> io::Result<Admission> {
    SECURITY_ADMISSION
        .acquire()
        .await
        .map(|slot| Admission {
            _slot: slot,
            execution: &SECURITY_EXECUTION,
        })
        .map_err(io::Error::other)
}

/// Only the worker or the caller's cancellation guard may take this payload.
struct Pending<F>(Arc<Mutex<Option<F>>>);

impl<F> Drop for Pending<F> {
    /// Close queued fences synchronously; a started write has already taken them.
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

impl Admission {
    /// Wait cooperatively for a worker and return admission for any next stage.
    /// Cancelled Tokio placeholders retain their lane's execution/admission slots
    /// until consumed, but no payload or descriptors. This prevents repeated
    /// cancellation from growing even the shared pool's internal task queue.
    pub(crate) async fn run<F, R>(self, work: F) -> io::Result<(R, Self)>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let execution = self.execution.acquire().await.map_err(io::Error::other)?;
        let pending = Pending(Arc::new(Mutex::new(Some(work))));
        let payload = pending.0.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _execution = execution;
            let work = payload
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            work.map(|work| (work(), self))
        })
        .await
        .map_err(io::Error::other)?;
        drop(pending);
        result.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Interrupted,
                "durable write cancelled before starting",
            )
        })
    }
}

#[cfg(test)]
#[path = "durable_io_tests.rs"]
mod tests;
