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
//! (`contracts/mesh-ssh.md`). SIGTERM is caught only while `work` runs.

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
        // action; the normal-return path below still runs the hooks.
        let terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        let result = match terminate {
            Some(mut terminate) => tokio::select! {
                result = work => Some(result),
                _ = terminate.recv() => None,
            },
            None => Some(work.await),
        };
        crate::plugins::stop_components(STOP_BOUND).await;
        match result {
            Some(result) => result,
            None => infraternal_shim::terminate_by_default(),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let result = work.await;
        crate::plugins::stop_components(STOP_BOUND).await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use infraternal_plugin_api::stop_hook::Stop;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

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
}
