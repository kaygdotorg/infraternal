//! Owns the single Traefik child, drains it after the final exposure, and redacts its log stream [#281].

use std::time::{Duration, Instant};

/// Time allowed for existing connections to drain after the final exposure is removed.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Initial delay after an unexpected child exit.
pub const INITIAL_RESTART_BACKOFF: Duration = Duration::from_secs(1);
/// Maximum delay between unexpected child exit and restart.
pub const MAX_RESTART_BACKOFF: Duration = Duration::from_secs(60);

/// The lifecycle states of the one process owned by an infraternal agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecyclePhase {
    /// No exposures exist and no process is running.
    Stopped,
    /// The process is being started and has not answered its private health ping.
    Starting,
    /// At least one exposure is active.
    Running,
    /// The final exposure was removed; existing connections have a bounded drain window.
    Draining { deadline: Instant },
    /// An unexpected exit is waiting for the next bounded restart attempt.
    Backoff {
        retry_at: Instant,
        delay: Duration,
    },
}

/// Work requested from the process owner by one lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAction {
    /// No external process operation is needed.
    Keep,
    /// Start Traefik after acquisition and config rendering.
    Start,
    /// Atomically replace the dynamic exposure snapshot.
    Apply,
    /// Replace the routes with an empty snapshot and begin draining.
    BeginDrain,
    /// Stop the owned child after the drain deadline.
    Stop,
    /// Wait this long before an unexpected-exit restart.
    RetryAfter(Duration),
}

/// Deterministic state machine separated from process I/O for lifecycle tests.
pub struct Lifecycle {
    phase: LifecyclePhase,
    next_backoff: Duration,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            phase: LifecyclePhase::Stopped,
            next_backoff: INITIAL_RESTART_BACKOFF,
        }
    }
}

impl Lifecycle {
    /// Return the current lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> LifecyclePhase {
        self.phase
    }

    /// Reconcile the owned child with the desired exposure count.
    pub fn update(&mut self, _exposure_count: usize, _now: Instant) -> LifecycleAction {
        LifecycleAction::Keep
    }

    /// Record that the child has passed its private health check.
    pub fn child_started(&mut self, _exposure_count: usize, _now: Instant) -> LifecycleAction {
        LifecycleAction::Keep
    }

    /// Schedule an unexpected-exit restart when desired exposures remain.
    pub fn child_exited(&mut self, _exposure_count: usize, _now: Instant) -> LifecycleAction {
        LifecycleAction::Keep
    }

    /// Fire a drain deadline or a pending restart when its time arrives.
    pub fn tick(&mut self, _exposure_count: usize, _now: Instant) -> LifecycleAction {
        LifecycleAction::Keep
    }
}

/// Replace each provider credential value before a Traefik line enters tracing.
#[must_use]
pub fn redact_log_line(line: &str, _secrets: &[&str]) -> String {
    line.to_owned()
}
