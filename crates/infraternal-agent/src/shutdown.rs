//! Runs components' stop hooks when an infraternal agent process ends [#221].
//!
//! Components that change host state hand the agent a stop hook
//! ([`infraternal_plugin_api::stop_hook`]); mesh SSH, for example, owns
//! firewall rules that redirect a mesh address's TCP/22. The registry that
//! owns them is never dropped at exit, so [`run_then_stop`] runs every live
//! hook on both ways an agent process ends:
//!
//! - its work returns (the server closed an embedded agent's socket, or a
//!   remote agent's service loop finished);
//! - it receives SIGTERM (`systemctl stop`, or the server stopping its
//!   embedded agent). The hooks run, then SIGTERM is re-raised with its
//!   default action, so the service manager still records a stop by signal.
//!
//! Invariants: hooks get at most [`STOP_BOUND`] in total, inside the server's
//! two-second grace before it kills its embedded agent; a hook that does not
//! finish in time is abandoned, and restart recovery handles what it left
//! (`contracts/mesh-ssh.md`). SIGTERM is caught only while `work` runs, and
//! `work` is kept alive until the hooks finished (see [`stop_after`]).

use std::{future::Future, io, time::Duration};

/// The most time the hooks get, all together.
pub const STOP_BOUND: Duration = Duration::from_millis(1500);

/// Run `work` until it returns or SIGTERM arrives, then run the stop hooks.
/// On SIGTERM this never returns: the process ends by the signal.
///
/// # Errors
/// Returns `work`'s own error after the hooks ran.
pub async fn run_then_stop(work: impl Future<Output = io::Result<()>>) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Without a handler (registration refused) SIGTERM keeps its default
        // action; the normal-return path still runs the hooks.
        let terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        let terminated = async move {
            match terminate {
                Some(mut terminate) => {
                    terminate.recv().await;
                }
                None => std::future::pending().await,
            }
        };
        match stop_after(work, terminated).await {
            Some(result) => result,
            None => infraternal_shim::terminate_by_default(),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        stop_after(work, std::future::pending())
            .await
            .unwrap_or(Ok(()))
    }
}

/// Run `work` until it returns or `terminate` resolves, then run the stop
/// hooks. Returns `None` when `terminate` won.
///
/// Invariant (measured on compute01, #221): `work` stays alive, unpolled,
/// until every hook has finished. Dropping it first tears down the plugin
/// registry while the hooks run, which ended mesh SSH's runtime in the middle
/// of removing its redirect table and left the table behind.
async fn stop_after(
    work: impl Future<Output = io::Result<()>>,
    terminate: impl Future<Output = ()>,
) -> Option<io::Result<()>> {
    let mut work = std::pin::pin!(work);
    let result = tokio::select! {
        result = &mut work => Some(result),
        () = terminate => None,
    };
    crate::plugins::stop_components(STOP_BOUND).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use infraternal_plugin_api::stop_hook::Stop;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    /// The hook list is process-wide: these tests take turns with it.
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Counts how often it was stopped.
    struct Counter(AtomicUsize);
    impl Stop for Counter {
        fn stop(&self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    /// A daemon whose work returns still runs every live hook once, and keeps
    /// the work's own result; a finished component's hook is simply skipped.
    #[tokio::test]
    async fn returning_work_runs_live_hooks_once() {
        let _serial = SERIAL.lock().await;
        let live: Arc<Counter> = Arc::new(Counter(AtomicUsize::new(0)));
        let hook: Arc<dyn Stop> = live.clone();
        crate::plugins::remember_stop_hook(Arc::downgrade(&hook));
        let gone: Arc<dyn Stop> = Arc::new(Counter(AtomicUsize::new(0)));
        crate::plugins::remember_stop_hook(Arc::downgrade(&gone));
        drop(gone);
        let result = run_then_stop(async { Err(io::Error::other("ended")) }).await;
        assert_eq!(result.unwrap_err().to_string(), "ended");
        assert_eq!(live.0.load(Ordering::SeqCst), 1);
        // The list was emptied: a second shutdown does not stop it again.
        crate::plugins::stop_components(STOP_BOUND).await;
        assert_eq!(live.0.load(Ordering::SeqCst), 1);
    }

    /// Set when the work it lives in is dropped.
    struct DroppedFlag(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DroppedFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Records whether the work was already dropped when the hook ran.
    struct SeesWork(Arc<std::sync::atomic::AtomicBool>, AtomicUsize);
    impl Stop for SeesWork {
        fn stop(&self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                if !self.0.load(Ordering::SeqCst) {
                    self.1.fetch_add(1, Ordering::SeqCst);
                }
            })
        }
    }

    /// Measured on compute01 (#221): dropping the work on SIGTERM tore the
    /// registry down while the hooks ran, so the component's runtime ended
    /// mid-cleanup and its redirect table stayed. The work must stay alive
    /// until every hook has finished.
    #[tokio::test]
    async fn on_terminate_hooks_finish_before_the_work_is_dropped() {
        let _serial = SERIAL.lock().await;
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook = Arc::new(SeesWork(Arc::clone(&dropped), AtomicUsize::new(0)));
        let erased: Arc<dyn Stop> = hook.clone();
        crate::plugins::remember_stop_hook(Arc::downgrade(&erased));
        let flag = DroppedFlag(Arc::clone(&dropped));
        let work = async move {
            let _flag = flag;
            std::future::pending::<io::Result<()>>().await
        };
        assert!(stop_after(work, async {}).await.is_none(), "terminated");
        assert_eq!(
            hook.1.load(Ordering::SeqCst),
            1,
            "the hook ran while the work was alive"
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "the work is dropped afterwards"
        );
    }
}
