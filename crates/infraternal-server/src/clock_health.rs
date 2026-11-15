//! Tracks whether wall time is close enough to monotonic time for trust deadlines (#285).

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// The clock is sampled once a second.
const SAMPLE_PERIOD: Duration = Duration::from_secs(1);
/// A longer gap between samples (a stalled or suspended process) resets health.
///
/// A shorter late sample does not: a busy runtime can run the sampler a few hundred
/// milliseconds late, and that says nothing about the wall clock (#525).
const MAX_SAMPLE_GAP: Duration = Duration::from_secs(5);
/// How far the wall clock may move apart from the monotonic clock per sample.
const MAX_DRIFT: Duration = Duration::from_millis(250);

/// The previous sample and how many stable samples followed it.
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

    /// Accept a sample only if the wall clock moved forward by the same monotonic time, within [`MAX_DRIFT`], at
    /// least about one sample period after the previous sample and at most [`MAX_SAMPLE_GAP`] after it. Three stable
    /// samples in a row mark the clock healthy; any unstable one resets the count.
    ///
    /// Only the two clocks' agreement and the gap bound judge the clock. A sample the runtime ran late (a loaded host,
    /// a busy single-threaded runtime) is still stable when both clocks moved alike: rejecting it used to mark the
    /// clock untrusted for the next three seconds, and every certificate recovery in that window was denied (#525).
    /// The lower bound stays, so three samples always span at least about two seconds of observation.
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

/// The absolute difference between two durations.
fn duration_difference(left: Duration, right: Duration) -> Duration {
    left.abs_diff(right)
}

/// Startup, stability and regression checks for clock health.
#[cfg(test)]
mod tests {
    use super::*;

    /// The clock starts untrusted and needs three stable samples.
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

    /// A backwards wall step or a long sample gap makes the clock untrusted again.
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

    /// A sampler tick the runtime ran late keeps a healthy clock healthy when both clocks moved alike (#525), but a
    /// late tick whose wall time disagrees with monotonic time still resets it.
    #[test]
    fn a_late_sample_with_agreeing_clocks_keeps_the_clock_trusted() {
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
        // 1.6 s instead of 1 s since the last sample, with both clocks agreeing.
        let late = Duration::from_millis(4_600);
        health.observe(wall + late, monotonic + late);
        assert!(
            health.is_healthy(),
            "a late but consistent sample reset trust"
        );
        // The next tick comes one period after the late one, as the sampler's
        // delayed interval schedules it.
        let next = late + Duration::from_secs(1);
        health.observe(wall + next, monotonic + next);
        assert!(health.is_healthy());
        // Late and inconsistent: the wall clock moved 400 ms less than monotonic time.
        let later = next + Duration::from_millis(1_600);
        health.observe(wall + later - Duration::from_millis(400), monotonic + later);
        assert!(!health.is_healthy());
    }
}
