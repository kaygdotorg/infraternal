//! Explicit socket-test time, held stationary across real SQLite and network I/O (#118).

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

/// Keep production deadlines intact while the test controls when they expire.
pub(super) struct FrozenSocketTime {
    release: mpsc::Sender<()>,
    timed_out: Arc<AtomicBool>,
}

impl FrozenSocketTime {
    // Call from a start_paused test: the runtime's timer epoch and clock then
    // share an exact origin, without sub-millisecond rounding at boundaries.
    pub(super) async fn new() -> Self {
        let (release, wait) = mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let timed_out = Arc::new(AtomicBool::new(false));
        let watchdog = timed_out.clone();
        // Tokio inhibits automatic time advancement while a blocking task runs.
        // Otherwise a real SQLite worker or loopback read could still be pending
        // when the paused runtime jumps straight to an authority-read deadline.
        tokio::task::spawn_blocking(move || {
            let _ = started.send(());
            // Only a hang bound: on expiry automatic advancement resumes and
            // the test's ordinary timeouts fail. No assertion uses this duration.
            watchdog.store(
                wait.recv_timeout(Duration::from_secs(90)).is_err(),
                Ordering::Relaxed,
            );
        });
        ready.await.unwrap();
        Self { release, timed_out }
    }
}

impl Drop for FrozenSocketTime {
    fn drop(&mut self) {
        tokio::time::resume();
        let _ = self.release.send(());
        if !std::thread::panicking() {
            assert!(
                !self.timed_out.load(Ordering::Relaxed),
                "socket test stopped before its observed event"
            );
        }
    }
}
