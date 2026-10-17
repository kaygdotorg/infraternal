//! Keeps the enrolled server link retrying and cancels stalled offline attempts without an idle heartbeat [128,168,215], #225.
use std::{future::Future, io, time::Duration};
use tokio::sync::watch;

const OFFLINE_LIMIT: Duration = Duration::from_mins(5);
pub(super) const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Rate limit for repeated server-link close lines: the first line of a window
/// prints at once, later ones are only counted and summarised in the next
/// window's first line. Runs once per link end (never per frame), so the cost is
/// one clock read per reconnect, which is already bounded by the retry backoff.
pub(super) struct LinkNotes {
    window_start: Option<tokio::time::Instant>,
    suppressed: u64,
}

pub(super) const LINK_NOTE_WINDOW: Duration = Duration::from_secs(60);

impl LinkNotes {
    pub(super) const fn new() -> Self {
        Self {
            window_start: None,
            suppressed: 0,
        }
    }

    /// Returns the line to print, if this event is not suppressed. `line` is only
    /// built for printed events.
    pub(super) fn note(
        &mut self,
        now: tokio::time::Instant,
        line: impl FnOnce() -> String,
    ) -> Option<String> {
        match self.window_start {
            Some(start) if now.duration_since(start) < LINK_NOTE_WINDOW => {
                self.suppressed = self.suppressed.saturating_add(1);
                None
            }
            _ => {
                let repeats = std::mem::take(&mut self.suppressed);
                self.window_start = Some(now);
                let line = line();
                Some(if repeats > 0 {
                    format!(
                        "{line}; {repeats} more link closes in the previous {} s",
                        LINK_NOTE_WINDOW.as_secs()
                    )
                } else {
                    line
                })
            }
        }
    }
}

#[cfg(test)]
tokio::task_local! {
    /// Exercise real worker/filesystem ordering without a five-minute wall wait.
    pub(crate) static TEST_OFFLINE_LIMIT: Duration;
}

/// Failed work consumes the interval; only its remaining wait gains jitter.
pub(super) fn retry_delay(backoff: Duration, elapsed: Duration) -> Duration {
    let jitter = Duration::from_millis(u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % 100);
    backoff.saturating_sub(elapsed) + jitter
}

/// A healthy link has no watchdog timer. Only an uninterrupted offline interval
/// can cancel its owner; losing probes and their sockets leave scope together.
async fn offline(mut connected: watch::Receiver<bool>) {
    loop {
        let live = *connected.borrow_and_update();
        if live {
            if connected.changed().await.is_err() {
                return;
            }
        } else {
            let limit = OFFLINE_LIMIT;
            #[cfg(test)]
            let limit = TEST_OFFLINE_LIMIT.try_with(|value| *value).unwrap_or(limit);
            tokio::select! {
                () = tokio::time::sleep(limit) => return,
                changed = connected.changed() => {
                    if changed.is_err() { return; }
                }
            }
        }
    }
}

/// Retry all returned errors, including local resource and credential failures.
/// `PermissionDenied` alone is not proof of revocation: TLS configuration,
/// expired certificates and unavailable publication can all use that kind.
/// Authenticated host removal retains its existing uninstall/stop path [134].
pub(super) async fn run<F, Attempt>(mut attempt: F) -> io::Result<()>
where
    F: FnMut(watch::Sender<bool>) -> Attempt,
    Attempt: Future<Output = io::Result<()>>,
{
    let mut backoff = Duration::from_millis(200);
    loop {
        let (connected, status) = watch::channel(false);
        let retrying = async {
            loop {
                let started = tokio::time::Instant::now();
                let result = attempt(connected.clone()).await;
                // Repeated failures must not reset the continuous offline guard.
                connected.send_if_modified(|live| {
                    let changed = *live;
                    *live = false;
                    changed
                });
                // Never format arbitrary adapter errors, which can carry private
                // context. A returned success is unexpected too: keep retrying.
                eprintln!(
                    "Infraternal agent server link ended ({:?}); retrying",
                    result.err().map(|error| error.kind())
                );
                let elapsed = started.elapsed();
                if elapsed >= Duration::from_secs(10) {
                    backoff = Duration::from_millis(200);
                }
                tokio::time::sleep(retry_delay(backoff, elapsed)).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        };
        tokio::select! {
            result = retrying => return result,
            () = offline(status) => {
                eprintln!("Infraternal agent has had no server link for 5 minutes; restarting its link");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[tokio::test(start_paused = true)]
    async fn link_close_notes_print_once_per_window_and_summarise_repeats() {
        let mut notes = LinkNotes::new();
        let start = tokio::time::Instant::now();
        let mut printed = 0;
        for i in 0..500 {
            let at = start + Duration::from_millis(i * 100);
            if notes.note(at, || "closed".to_owned()).is_some() {
                printed += 1;
            }
        }
        assert_eq!(printed, 1, "500 closes in 50 s print one line");
        let next = notes
            .note(start + LINK_NOTE_WINDOW, || "closed".to_owned())
            .unwrap();
        assert_eq!(next, "closed; 499 more link closes in the previous 60 s");
    }

    #[tokio::test(start_paused = true)]
    async fn every_error_kind_and_successful_return_retries() {
        let count = Arc::new(AtomicUsize::new(0));
        let attempts = count.clone();
        let task = tokio::spawn(run(move |_| {
            let index = attempts.fetch_add(1, Ordering::Relaxed);
            async move {
                match index % 4 {
                    0 => Err(io::ErrorKind::PermissionDenied.into()),
                    1 => Err(io::ErrorKind::BrokenPipe.into()),
                    2 => Err(io::ErrorKind::Other.into()),
                    _ => Ok(()),
                }
            }
        }));
        for _ in 0..120 {
            tokio::time::advance(Duration::from_secs(31)).await;
        }
        assert!(count.load(Ordering::Relaxed) >= 60);
        assert!(!task.is_finished());
        task.abort();
        let _ = task.await;
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_restarts_a_stalled_offline_attempt() {
        let count = Arc::new(AtomicUsize::new(0));
        let attempts = count.clone();
        let task = tokio::spawn(run(move |_status| {
            attempts.fetch_add(1, Ordering::Relaxed);
            std::future::pending::<io::Result<()>>()
        }));
        tokio::task::yield_now().await;
        tokio::time::advance(OFFLINE_LIMIT).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(count.load(Ordering::Relaxed), 2);
        task.abort();
        let _ = task.await;
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_link_has_no_watchdog_deadline() {
        let (status, receiver) = watch::channel(true);
        let watchdog = tokio::spawn(offline(receiver));
        tokio::time::advance(OFFLINE_LIMIT * 10).await;
        assert!(!watchdog.is_finished());
        status.send_replace(false);
        tokio::task::yield_now().await;
        tokio::time::advance(OFFLINE_LIMIT).await;
        watchdog.await.unwrap();
    }

    /// Handshake work is part of the reconnect interval, not extra waiting time.
    #[tokio::test(start_paused = true)]
    async fn failed_attempt_cost_does_not_extend_the_retry_period() {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let recorded = starts.clone();
        let result = tokio::time::timeout(
            Duration::from_secs(600),
            run(move |_| {
                recorded.lock().unwrap().push(tokio::time::Instant::now());
                async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    Err(io::ErrorKind::ConnectionRefused.into())
                }
            }),
        )
        .await;
        assert!(result.is_err());
        let starts = starts.lock().unwrap();
        assert!(starts.len() > 10);
        let maximum = starts
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .max()
            .unwrap();
        assert!(
            maximum <= Duration::from_millis(30_100),
            "retry period exceeded its cap: {maximum:?}"
        );
    }
}

#[cfg(test)]
#[path = "remote_supervisor_review_tests.rs"]
mod review_tests;
