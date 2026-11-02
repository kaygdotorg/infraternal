//! Tracks whether wall time is close enough to monotonic time for trust deadlines (#285).

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const SAMPLE_PERIOD: Duration = Duration::from_secs(1);
const MAX_SAMPLE_GAP: Duration = Duration::from_secs(5);
const MAX_DRIFT: Duration = Duration::from_millis(250);

#[derive(Default)]
struct Samples {
    previous: Option<(SystemTime, Instant)>,
    consecutive: u8,
}

/// A process-local clock-health signal shared by certificate status and recovery.
pub struct ClockHealth {
    samples: Mutex<Samples>,
    healthy: AtomicBool,
    monitor_started: AtomicBool,
}

impl Default for ClockHealth {
    fn default() -> Self {
        Self {
            samples: Mutex::new(Samples::default()),
            healthy: AtomicBool::new(false),
            monitor_started: AtomicBool::new(false),
        }
    }
}

impl ClockHealth {
    /// Begin one lightweight one-second sampler for this server process.
    pub fn start_monitor(self: &Arc<Self>) {
        if self
            .monitor_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let health = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SAMPLE_PERIOD);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                health.observe(SystemTime::now(), Instant::now());
            }
        });
    }

    /// Whether three consecutive samples have established a trustworthy clock.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Return server wall time only while it remains close to the last monotonic sample.
    #[must_use]
    pub fn current_epoch(&self) -> Option<i64> {
        let wall = SystemTime::now();
        let monotonic = Instant::now();
        let seconds = wall.duration_since(UNIX_EPOCH).ok()?.as_secs();
        let epoch = i64::try_from(seconds).ok()?;
        let mut samples = self
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (old_wall, old_monotonic) = samples.previous?;
        let wall_delta = wall.duration_since(old_wall);
        let monotonic_delta = monotonic.checked_duration_since(old_monotonic);
        let valid = match (wall_delta, monotonic_delta) {
            (Ok(wall_delta), Some(monotonic_delta)) => {
                monotonic_delta <= MAX_SAMPLE_GAP
                    && duration_difference(wall_delta, monotonic_delta) <= MAX_DRIFT
            }
            _ => false,
        };
        if !valid {
            samples.previous = Some((wall, monotonic));
            samples.consecutive = 0;
            self.healthy.store(false, Ordering::Release);
            return None;
        }
        self.healthy.load(Ordering::Acquire).then_some(epoch)
    }

    fn observe(&self, wall: SystemTime, monotonic: Instant) {
        let mut samples = self
            .samples
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let valid_wall = wall.duration_since(UNIX_EPOCH).is_ok();
        let accepted = valid_wall
            && samples
                .previous
                .and_then(|(old_wall, old_monotonic)| {
                    let wall_delta = wall.duration_since(old_wall).ok()?;
                    let monotonic_delta = monotonic.checked_duration_since(old_monotonic)?;
                    let drift = duration_difference(wall_delta, monotonic_delta);
                    (monotonic_delta >= SAMPLE_PERIOD.saturating_sub(MAX_DRIFT)
                        && monotonic_delta <= SAMPLE_PERIOD + MAX_DRIFT
                        && monotonic_delta <= MAX_SAMPLE_GAP
                        && drift <= MAX_DRIFT)
                        .then_some(())
                })
                .is_some();

        samples.consecutive = if accepted {
            samples.consecutive.saturating_add(1)
        } else {
            0
        };
        samples.previous = valid_wall.then_some((wall, monotonic));
        self.healthy
            .store(samples.consecutive >= 3, Ordering::Release);
    }
}

fn duration_difference(left: Duration, right: Duration) -> Duration {
    left.abs_diff(right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_starts_unknown_and_needs_three_stable_samples() {
        let health = ClockHealth::default();
        let wall = UNIX_EPOCH + Duration::from_hours(500_000);
        let monotonic = Instant::now();
        assert!(!health.is_healthy());
        for second in 0..4 {
            health.observe(
                wall + Duration::from_secs(second),
                monotonic + Duration::from_secs(second),
            );
            assert_eq!(health.is_healthy(), second >= 3);
        }
    }

    #[test]
    fn backwards_wall_time_and_long_sample_gaps_return_to_unknown() {
        let health = ClockHealth::default();
        let wall = UNIX_EPOCH + Duration::from_hours(500_000);
        let monotonic = Instant::now();
        for second in 0..4 {
            health.observe(
                wall + Duration::from_secs(second),
                monotonic + Duration::from_secs(second),
            );
        }
        assert!(health.is_healthy());

        health.observe(
            wall + Duration::from_secs(2),
            monotonic + Duration::from_secs(4),
        );
        assert!(!health.is_healthy());
        health.observe(
            wall + Duration::from_secs(20),
            monotonic + Duration::from_secs(20),
        );
        assert!(!health.is_healthy());
    }
}
