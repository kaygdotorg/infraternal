//! Resource accounting for cancelled disk work, independent of allocator caches.
use super::*;
use std::{
    future::Future as _,
    sync::atomic::{AtomicUsize, Ordering},
    task::Context,
};

/// Owned bytes model a queued write's memory; dropping the payload releases them.
struct Payload {
    bytes: Vec<u8>,
    live: Arc<AtomicUsize>,
}

impl Payload {
    /// Allocate a known amount so retained queue memory can be counted exactly.
    fn new(live: &Arc<AtomicUsize>) -> Self {
        live.fetch_add(64 * 1024, Ordering::SeqCst);
        Self {
            bytes: vec![0; 64 * 1024],
            live: live.clone(),
        }
    }
}

impl Drop for Payload {
    /// Account for actual owned allocations, without an RSS or timing threshold.
    fn drop(&mut self) {
        self.live.fetch_sub(self.bytes.len(), Ordering::SeqCst);
    }
}

/// A saturated shared pool cannot retain cancelled payloads or grow its queue.
/// A subprocess isolates global admission from other concurrently running tests.
#[test]
fn cancelled_flood_bounds_owned_memory() {
    const CHILD: &str = "INFRATERNAL_DURABLE_MEMORY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "durable_io::tests::cancelled_flood_bounds_owned_memory",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        eprint!(
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut releases = Vec::new();
        let mut blockers = Vec::new();
        for _ in 0..2 {
            let (release, wait) = std::sync::mpsc::channel();
            let (entered, ready) = tokio::sync::oneshot::channel();
            blockers.push(tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                let _ = wait.recv();
            }));
            ready.await.unwrap();
            releases.push(release);
        }
        let live = Arc::new(AtomicUsize::new(0));
        let mut peak = 0;
        for _ in 0..4 {
            let mut calls: Vec<_> = (0..1024)
                .map(|_| {
                    let live = live.clone();
                    Box::pin(async move {
                        let admission = admit()?;
                        let payload = Payload::new(&live);
                        admission.run(move || drop(payload)).await
                    })
                })
                .collect();
            let mut context = Context::from_waker(std::task::Waker::noop());
            for call in &mut calls {
                let _ = call.as_mut().poll(&mut context);
            }
            peak = peak.max(live.load(Ordering::SeqCst));
            assert_eq!(admit().unwrap_err().kind(), io::ErrorKind::WouldBlock);
            drop(calls);
            assert_eq!(
                live.load(Ordering::SeqCst),
                0,
                "unstarted cancelled work retained owned memory"
            );
        }
        assert!(peak <= (WORKERS + WAITING) * 64 * 1024);
        for release in releases {
            release.send(()).unwrap();
        }
        for blocker in blockers {
            blocker.await.unwrap();
        }
        // This completion follows both cancelled placeholders through the
        // execution semaphore; no sleep guesses when their permits are freed.
        let _ = admit().unwrap().run(|| ()).await.unwrap();
        eprintln!(
            "flood=4096 peak_owned_bytes={peak} retained_owned_bytes={}",
            live.load(Ordering::SeqCst)
        );
    });
}
