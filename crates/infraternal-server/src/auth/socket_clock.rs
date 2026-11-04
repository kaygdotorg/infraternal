//! Explicit socket-test time, held stationary across real SQLite and network I/O (#118).

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};

/// Messages to the watchdog thread that holds Tokio's paused clock still.
enum ClockMessage {
    /// The test saw real I/O progress; restart the hang timer.
    Progress,
    /// The test is finished; let the watchdog thread exit.
    Release,
}

/// Keep production deadlines intact while the test controls when they expire.
pub(crate) struct FrozenSocketTime {
    release: mpsc::Sender<ClockMessage>,
    timed_out: Arc<AtomicBool>,
}

impl FrozenSocketTime {
    // Call from a start_paused test: the runtime's timer epoch and clock then
    // share an exact origin, without sub-millisecond rounding at boundaries.
    /// Freezes the paused Tokio clock until the value is dropped. Needs a `start_paused` test.
    pub(crate) async fn new() -> Self {
        let (release, wait) = mpsc::channel::<ClockMessage>();
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
                loop {
                    match wait.recv_timeout(Duration::from_secs(90)) {
                        Ok(ClockMessage::Release) => break false,
                        Ok(ClockMessage::Progress) => {}
                        Err(_) => break true,
                    }
                },
                Ordering::Relaxed,
            );
        });
        ready.await.unwrap();
        Self { release, timed_out }
    }

    /// Renew only the hang bound after observed real I/O progress. Runtime
    /// deadlines stay stationary; each stalled operation still has 90 seconds.
    pub(super) fn progress(&self) {
        self.release.send(ClockMessage::Progress).unwrap();
    }

    /// Synchronize a SQLite observation with paused runtime time, without slack.
    /// The blocking waiter leaves Tokio time stationary during real I/O; it
    /// waits only until the exact first offline wall-clock second, never a
    /// scheduling cushion. The caller explicitly advances its runtime timer.
    pub(super) async fn reach_wall_deadline(&self, unix_seconds: i64) {
        let deadline =
            std::time::UNIX_EPOCH + Duration::from_secs(u64::try_from(unix_seconds).unwrap());
        tokio::task::spawn_blocking(move || {
            while let Ok(remaining) = deadline.duration_since(std::time::SystemTime::now()) {
                std::thread::sleep(remaining);
            }
        })
        .await
        .unwrap();
    }
}

impl Drop for FrozenSocketTime {
    /// Resumes time and stops the watchdog. Panics if the hang bound expired, unless already panicking.
    fn drop(&mut self) {
        tokio::time::resume();
        let _ = self.release.send(ClockMessage::Release);
        if !std::thread::panicking() {
            assert!(
                !self.timed_out.load(Ordering::Relaxed),
                "socket test stopped before its observed event"
            );
        }
    }
}
