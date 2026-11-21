//! The plugin calls of one browser socket: a few run at once, the rest wait their turn (#556).
//!
//! A socket answers at most [`MAX_RUNNING`] calls at the same time, because each running call can hold a
//! database connection or a remote login. Refusing every call past that bound made a person who opened several
//! windows at once see "offline or cannot reach this server" for windows that were fine, since each new window
//! sends a terminal open and a startup inspection that stay pending for a while. A call that arrives while the
//! socket is full now waits in a bounded queue and starts as soon as a running call finishes; only a full queue
//! refuses. The queue holds at most [`MAX_WAITING`] calls and every call input is at most
//! `MAX_ACTION_BYTES` (8 KiB), so a socket keeps at most about 512 KiB of waiting input, and the queue dies with
//! the socket.
//!
//! Waiting calls start in arrival order, except that urgent ones (opening a terminal, which a person is
//! staring at) go before the others (inspections, listings), so a window never waits behind background reads.
//! A waiting call has not started yet, so its own time limit counts from when it starts, not from when it arrived.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use tokio::task::{JoinError, JoinSet};

/// Calls running at once on one socket (the bound the server always had).
pub(crate) const MAX_RUNNING: usize = 4;
/// Calls that may wait for a running slot on one socket.
pub(crate) const MAX_WAITING: usize = 64;

/// Work that has not started: boxed so waiting calls of different shapes share one queue.
type Work<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A call that has not started: its work (nothing polled yet) and whether it goes first.
struct Waiting<T> {
    urgent: bool,
    work: Work<T>,
}

/// Running calls plus the bounded queue of waiting ones; `T` is what a finished call yields.
pub(crate) struct PluginCalls<T: Send + 'static> {
    running: JoinSet<T>,
    waiting: VecDeque<Waiting<T>>,
}

impl<T: Send + 'static> PluginCalls<T> {
    /// An empty set: nothing running, nothing waiting.
    pub(crate) fn new() -> Self {
        Self {
            running: JoinSet::new(),
            waiting: VecDeque::new(),
        }
    }

    /// Whether [`submit`](Self::submit) would accept another call: a slot is free or the queue has room.
    pub(crate) fn has_room(&self) -> bool {
        self.running.len() < MAX_RUNNING || self.waiting.len() < MAX_WAITING
    }

    /// Starts `work` now when a slot is free, else queues it. Call only after `has_room()` said yes; a call
    /// past the bound is dropped unstarted, and the caller answers it as refused.
    pub(crate) fn submit(
        &mut self,
        urgent: bool,
        work: impl Future<Output = T> + Send + 'static,
    ) -> bool {
        if self.running.len() < MAX_RUNNING {
            self.running.spawn(work);
            true
        } else if self.waiting.len() < MAX_WAITING {
            self.waiting.push_back(Waiting {
                urgent,
                work: Box::pin(work),
            });
            true
        } else {
            false
        }
    }

    /// True when nothing is running; waiting calls only exist while every slot is busy.
    pub(crate) fn is_empty(&self) -> bool {
        self.running.is_empty()
    }

    /// Calls running now.
    #[cfg(test)]
    pub(crate) fn running(&self) -> usize {
        self.running.len()
    }

    /// Calls waiting for a slot.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// The next finished call. Its slot goes to the first urgent waiting call, else the oldest waiting one.
    pub(crate) async fn join_next(&mut self) -> Option<Result<T, JoinError>> {
        let done = self.running.join_next().await;
        while self.running.len() < MAX_RUNNING {
            let next =
                self.waiting
                    .iter()
                    .position(|call| call.urgent)
                    .or(if self.waiting.is_empty() {
                        None
                    } else {
                        Some(0)
                    });
            let Some(call) = next.and_then(|at| self.waiting.remove(at)) else {
                break;
            };
            self.running.spawn(call.work);
        }
        done
    }

    /// Aborts and joins every running call and drops the waiting ones.
    pub(crate) async fn shutdown(&mut self) {
        self.waiting.clear();
        self.running.shutdown().await;
    }
}

/// Tests for the queue's three promises: calls wait and then run, the queue is bounded, urgent goes first.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Notify;

    /// A call that finishes when released and yields its label.
    fn held(label: u32, gate: &Arc<Notify>) -> impl Future<Output = u32> + Send + 'static {
        let gate = gate.clone();
        async move {
            gate.notified().await;
            label
        }
    }

    /// Ten calls on a four-call socket all finish; six had to wait.
    #[tokio::test]
    async fn calls_past_the_running_bound_wait_and_then_run() {
        let mut calls = PluginCalls::<u32>::new();
        for label in 0..10u32 {
            assert!(calls.has_room());
            assert!(calls.submit(false, async move { label }));
        }
        assert_eq!((calls.running(), calls.waiting()), (MAX_RUNNING, 6));
        let mut done = Vec::new();
        while !calls.is_empty() {
            if let Some(Ok(label)) = calls.join_next().await {
                done.push(label);
            }
        }
        done.sort_unstable();
        assert_eq!(done, (0..10).collect::<Vec<_>>());
    }

    /// Past running plus waiting, a call is refused, and shutdown empties both.
    #[tokio::test]
    async fn the_queue_is_bounded() {
        let gate = Arc::new(Notify::new());
        let mut calls = PluginCalls::<u32>::new();
        for label in 0..u32::try_from(MAX_RUNNING + MAX_WAITING).unwrap() {
            assert!(calls.submit(false, held(label, &gate)));
        }
        assert!(!calls.has_room());
        assert!(!calls.submit(false, held(999, &gate)));
        calls.shutdown().await;
        assert_eq!((calls.running(), calls.waiting()), (0, 0));
    }

    /// A freed slot goes to a waiting urgent call before an older ordinary one.
    #[tokio::test]
    async fn urgent_calls_start_before_older_ordinary_ones() {
        let mut calls = PluginCalls::<u32>::new();
        let release: Vec<Arc<Notify>> = (0..8).map(|_| Arc::new(Notify::new())).collect();
        for (label, gate) in release.iter().enumerate().take(MAX_RUNNING) {
            calls.submit(false, held(u32::try_from(label).unwrap(), gate));
        }
        calls.submit(false, held(4, &release[4]));
        calls.submit(true, held(5, &release[5]));
        // Finishing call 0 frees one slot: the urgent call 5 takes it, not the older call 4.
        release[0].notify_one();
        tokio::task::yield_now().await;
        assert_eq!(calls.join_next().await.unwrap().unwrap(), 0);
        release[5].notify_one();
        tokio::task::yield_now().await;
        let finished = tokio::time::timeout(std::time::Duration::from_secs(5), calls.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(finished, 5, "the urgent call ran ahead of call 4");
        calls.shutdown().await;
    }
}
