//! Keeps the enrolled server link retrying and cancels stalled offline attempts without an idle heartbeat [128,168,215], #225.
use std::{future::Future, io, time::Duration};
use tokio::sync::watch;

const OFFLINE_LIMIT: Duration = Duration::from_mins(5);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

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
            tokio::select! {
                () = tokio::time::sleep(OFFLINE_LIMIT) => return,
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
                if started.elapsed() >= Duration::from_secs(10) {
                    backoff = Duration::from_millis(200);
                }
                let jitter =
                    Duration::from_millis(u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % 100);
                tokio::time::sleep(backoff + jitter).await;
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
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

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
}
