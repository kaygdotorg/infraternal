//! Keeps the privileged installation under rollback when its process receives a termination signal.
use std::{
    future::Future,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::signal::unix::{SignalKind, signal};

/// Abort the signal listener when the installation finishes, including on an error or panic.
struct Monitor(
    /// The listener owns no install paths; cancellation always drops them on the installing thread.
    tokio::task::JoinHandle<()>,
);

impl Drop for Monitor {
    /// Do not retain a listener after its installation scope has returned.
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Explain interruption without exposing private enrollment input.
pub(super) fn interrupted() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "Machine installation interrupted; rolling back this run.",
    )
}

/// Register termination handling before the operation creates any installation paths.
///
/// Dropping an asynchronous enrollment unwinds its transaction. A dedicated runtime
/// worker also records signals during synchronous file and service-manager calls;
/// activation checks that flag before committing. Manager calls finish before rollback
/// starts so a delayed enable cannot race the rollback's stop and path removal.
pub(super) fn run<F: Future>(
    operation: impl FnOnce(Arc<AtomicBool>) -> F,
) -> io::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut hangup = signal(SignalKind::hangup())?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&cancelled);
        let mut monitor = Monitor(tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {},
                _ = interrupt.recv() => {},
                _ = hangup.recv() => {},
            }
            observed.store(true, Ordering::Release);
        }));
        tokio::select! {
            biased;
            _ = &mut monitor.0 => Err(interrupted()),
            result = operation(cancelled) => Ok(result),
        }
    })
}
