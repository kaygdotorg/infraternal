//! Which path a mesh pair should use, from measured round trips (D185, D197 M5, D233, D313 Q5).
//!
//! This is the "#201 selector": one rule for every choice between paths of the same pair,
//! relay against relay and, once a direct-path sample source exists, direct against relay.
//! The module owns no socket and no timer. The runtime records round-trip samples per path
//! with its own monotonic clock (a [`Duration`] since any fixed instant) and asks
//! [`Selector::choose`] whether to move.
//!
//! The rule, with D313 Q5's numbers:
//! - A path is judged only on a *sustained* window: its last [`SAMPLES`] samples, spanning at
//!   least [`SPAN`], the oldest no older than [`FRESH`]. Fewer, bunched or old samples never move
//!   a pair, so one lucky probe or a stale history from an idle hour ago cannot cause a switch.
//! - The margin is `max(5 ms, 15 %)` of the current path's median ([`band`]).
//! - A relay (or any non-direct path) takes over only when both windows agree that it is
//!   faster by at least the margin: **every** challenger sample beats the current path's
//!   median, and the challenger's median beats the current path's **best** sample. One check
//!   alone is not enough under jitter (numbers below).
//! - **Direct wins inside the band:** while on a relay, a direct path takes over when the same
//!   two comparisons show it slower by *less* than the margin; while on direct, a relay needs
//!   the full margin. For steady paths the two conditions exclude each other, so a pair does
//!   not oscillate between direct and a relay of nearly the same speed.
//! - **The first measured choice** ([`first_choice`]) has no incumbent measurement to defend,
//!   so it needs one sample per path, not a sustained window: the fastest path takes over if
//!   it beats the unmeasured default by the margin. Later moves follow the sustained rule.
//! - At most one preference switch per [`DWELL`]. A path that is *gone* is not a preference:
//!   the runtime moves away from it at once with [`Selector::install`], which also restarts the
//!   dwell so the replacement is not swapped again straight after a failure.
//!
//! Measured choice (J1105, a one-hour simulation of two equal 40 ms paths sampled once a
//! second, five seeds, switches per hour at 10 / 20 / 30 % normal jitter; a 100 ms path
//! against a 70 ms one is detected after 5–7 s by all three):
//! - medians only: frequent trading of places, not usable;
//! - every challenger sample against the current median: 0.4 / 15 / 32;
//! - that plus the challenger's median against the current's best sample (this rule):
//!   0 / 2.4 / 6.8;
//! - every challenger sample against the current's best sample: 0 / 0 / 1, but a 100 → 70 ms
//!   win under 20 % jitter waited up to 45 s and a 50 → 40 ms one up to 95 s.
//!
//! An exponentially weighted mean was rejected too: it hides how sustained a win is, which
//! D313 asks for explicitly.

use std::time::Duration;

/// Samples per path in one judgement window (D313 Q5: five samples).
pub const SAMPLES: usize = 5;
/// The window's samples must span at least this long (D313 Q5: three seconds).
pub const SPAN: Duration = Duration::from_secs(3);
/// The oldest sample of a window may be at most this old when it is judged. A pair that was
/// idle keeps no probe traffic, so its history goes stale rather than deciding later.
pub const FRESH: Duration = Duration::from_secs(30);
/// Least time between two preference switches (D313 Q5: ten seconds).
pub const DWELL: Duration = Duration::from_secs(10);
/// The margin's floor (D313 Q5: 5 ms).
pub const MIN_SAVING: Duration = Duration::from_millis(5);
/// The margin's share of the current path's median, in percent (D313 Q5: 15 %).
pub const SAVING_PERCENT: u32 = 15;

/// One way a pair's packets can travel.
///
/// The order is the tie-break order: direct first, then relays by their configured index,
/// so both ends of a pair break ties the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Path {
    /// Peer to peer over the underlay.
    Direct,
    /// Through the relay at this index of the node's shared relay list.
    Relay(usize),
}

/// The last [`SAMPLES`] round trips measured on one path, oldest first once full.
///
/// Recording is O(1) and allocation-free; a full window drops its oldest sample.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Samples {
    /// `(taken at, round trip)` pairs in a ring; `next` is the slot written next.
    ring: [(Duration, Duration); SAMPLES],
    len: usize,
    next: usize,
}

impl Samples {
    /// Record one round trip `rtt` measured at monotonic time `at`.
    pub fn record(&mut self, at: Duration, rtt: Duration) {
        self.ring[self.next] = (at, rtt);
        self.next = (self.next + 1) % SAMPLES;
        self.len = (self.len + 1).min(SAMPLES);
    }

    /// Forget every sample, for a path whose meaning changed (a new link or relay connection).
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// How many samples are held, at most [`SAMPLES`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no sample is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The held samples' round trips, in no particular order.
    fn rtts(&self) -> impl Iterator<Item = Duration> + '_ {
        self.ring[..self.len].iter().map(|&(_, rtt)| rtt)
    }

    /// The median of the held round trips (the lower middle one for an even count).
    #[must_use]
    pub fn median(&self) -> Option<Duration> {
        if self.len == 0 {
            return None;
        }
        let mut sorted = [Duration::ZERO; SAMPLES];
        for (slot, rtt) in sorted.iter_mut().zip(self.rtts()) {
            *slot = rtt;
        }
        let sorted = &mut sorted[..self.len];
        sorted.sort_unstable();
        Some(sorted[(self.len - 1) / 2])
    }

    /// The most recently recorded round trip, if any.
    #[must_use]
    pub fn newest(&self) -> Option<Duration> {
        (self.len > 0).then(|| self.ring[(self.next + SAMPLES - 1) % SAMPLES].1)
    }

    /// The slowest held round trip.
    #[must_use]
    pub fn worst(&self) -> Option<Duration> {
        self.rtts().max()
    }

    /// The fastest held round trip.
    #[must_use]
    pub fn best(&self) -> Option<Duration> {
        self.rtts().min()
    }

    /// Whether the window is full, spans at least [`SPAN`], and its oldest sample is at most
    /// [`FRESH`] old at `now`. Only such a window may move a pair.
    #[must_use]
    pub fn sustained(&self, now: Duration) -> bool {
        if self.len < SAMPLES {
            return false;
        }
        let times = self.ring.iter().map(|&(at, _)| at);
        let (Some(oldest), Some(newest)) = (times.clone().min(), times.max()) else {
            return false;
        };
        newest.saturating_sub(oldest) >= SPAN && now.saturating_sub(oldest) <= FRESH
    }
}

/// The margin a challenger must clear against a current path whose median is `current`:
/// `max(MIN_SAVING, SAVING_PERCENT % of current)`.
#[must_use]
pub fn band(current: Duration) -> Duration {
    (current * SAVING_PERCENT / 100).max(MIN_SAVING)
}

/// Whether `challenger` should replace `current`, judged on their sample windows at `now`.
///
/// Both windows must be [`Samples::sustained`]. The direct-path preference applies only when
/// the challenger is [`Path::Direct`] and the current path is not.
#[must_use]
pub fn beats(
    challenger: Path,
    challenger_samples: &Samples,
    current: Path,
    current_samples: &Samples,
    now: Duration,
) -> bool {
    if challenger == current
        || !challenger_samples.sustained(now)
        || !current_samples.sustained(now)
    {
        return false;
    }
    let (Some(median), Some(best), Some(worst), Some(typical)) = (
        current_samples.median(),
        current_samples.best(),
        challenger_samples.worst(),
        challenger_samples.median(),
    ) else {
        return false;
    };
    let margin = band(median);
    if challenger == Path::Direct {
        // Direct wins inside the band: it may be slower, but by less than the margin.
        worst < median + margin && typical < best + margin
    } else {
        // Faster by the margin on every sample, and typically faster than the current's best.
        worst + margin <= median && typical + margin <= best
    }
}

/// Whether a pair on an unmeasured default should take `challenger` as its first measured
/// path, judged on one round trip each: the challenger must beat `current` by [`band`], or,
/// for [`Path::Direct`], be slower by less than it. Equal paths therefore keep the default,
/// so both ends of a pair stay where their shared default put them.
#[must_use]
pub fn first_choice(challenger: Path, challenger_rtt: Duration, current_rtt: Duration) -> bool {
    let margin = band(current_rtt);
    if challenger == Path::Direct {
        challenger_rtt < current_rtt + margin
    } else {
        challenger_rtt + margin <= current_rtt
    }
}

/// One pair's current path and when it last changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Selector {
    current: Option<Path>,
    /// Monotonic time of the last switch of either kind; `None` before the first.
    switched_at: Option<Duration>,
}

impl Selector {
    /// The path in use, if any.
    #[must_use]
    pub fn current(&self) -> Option<Path> {
        self.current
    }

    /// Use `path` as an unmeasured default, with no dwell: the runtime's choice while nothing
    /// has been measured yet (for relays, the lowest list index). Moving between such defaults
    /// is setup, not a switch, so it must not delay the first measured choice.
    pub fn start(&mut self, path: Option<Path>) {
        self.current = path;
        self.switched_at = None;
    }

    /// Use `path` now, without any comparison: the first path that works, or the replacement
    /// for a path that is gone. `None` records that no path is usable.
    ///
    /// Replacing a path restarts the dwell, so a failover target is not swapped again at once.
    /// The first path a pair gets does not: a badly placed first relay is left as soon as a
    /// better one has a sustained window, about five seconds of traffic, not after a dwell.
    pub fn install(&mut self, path: Option<Path>, now: Duration) {
        if self.current != path {
            if self.current.is_some() {
                self.switched_at = Some(now);
            }
            self.current = path;
        }
    }

    /// Decide whether to move to a measurably faster path, and move if so.
    ///
    /// `paths` lists every usable path with its samples, the current one included. Returns the
    /// new path when this call switched, `None` when the pair stays. Among several qualifying
    /// challengers the lowest median wins, ties broken by [`Path`] order. Nothing moves within
    /// [`DWELL`] of the last switch, or while the current path has no sustained window.
    pub fn choose<'a>(
        &mut self,
        now: Duration,
        paths: impl IntoIterator<Item = (Path, &'a Samples)> + Clone,
    ) -> Option<Path> {
        let current = self.current?;
        if self
            .switched_at
            .is_some_and(|at| now.saturating_sub(at) < DWELL)
        {
            return None;
        }
        let current_samples = paths
            .clone()
            .into_iter()
            .find_map(|(path, samples)| (path == current).then_some(samples))?;
        let winner = paths
            .into_iter()
            .filter(|&(path, samples)| beats(path, samples, current, current_samples, now))
            .min_by_key(|&(path, samples)| (samples.median(), path))
            .map(|(path, _)| path)?;
        self.current = Some(winner);
        self.switched_at = Some(now);
        Some(winner)
    }
}

#[cfg(test)]
mod tests {
    //! The D313 Q5 numbers, the direct preference and flapping under jitter.
    use super::*;

    /// `value` milliseconds, to keep the tables of round trips short.
    const fn ms(value: u64) -> Duration {
        Duration::from_millis(value)
    }

    /// A window of `rtts` taken one second apart, the last at `end`.
    fn window(end: Duration, rtts: &[u64]) -> Samples {
        let mut samples = Samples::default();
        let count = u32::try_from(rtts.len()).unwrap_or(u32::MAX);
        for (index, &rtt) in (0..count).zip(rtts) {
            samples.record(
                end.saturating_sub(Duration::from_secs(u64::from(count - 1 - index))),
                ms(rtt),
            );
        }
        samples
    }

    /// The margin is 5 ms on fast paths and 15 % on slow ones.
    #[test]
    fn the_margin_is_five_milliseconds_or_fifteen_percent() {
        assert_eq!(band(ms(1)), ms(5));
        assert_eq!(band(ms(33)), ms(5));
        assert_eq!(band(ms(100)), ms(15));
        assert_eq!(band(ms(300)), ms(45));
    }

    /// Five samples over at least three seconds, recent enough, or nothing moves.
    #[test]
    fn only_a_full_spread_recent_window_is_sustained() {
        let now = Duration::from_secs(100);
        assert!(window(now, &[10; 5]).sustained(now));
        assert!(!window(now, &[10; 4]).sustained(now), "four samples");
        let mut bunched = Samples::default();
        for step in 0..5 {
            bunched.record(now.saturating_sub(ms(step * 100)), ms(10));
        }
        assert!(!bunched.sustained(now), "five samples within 0.4 s");
        assert!(
            !window(now, &[10; 5]).sustained(now + FRESH),
            "an idle pair's old window"
        );
    }

    /// A relay must win on every sample by the margin; one slow sample keeps the pair put.
    #[test]
    fn a_relay_must_save_the_margin_on_every_sample() {
        let now = Duration::from_secs(50);
        let current = window(now, &[300, 300, 300, 300, 300]);
        assert!(beats(
            Path::Relay(1),
            &window(now, &[30, 31, 29, 30, 32]),
            Path::Relay(0),
            &current,
            now
        ));
        // 255 = 300 - 45: exactly the margin still counts.
        assert!(beats(
            Path::Relay(1),
            &window(now, &[255; 5]),
            Path::Relay(0),
            &current,
            now
        ));
        assert!(!beats(
            Path::Relay(1),
            &window(now, &[256; 5]),
            Path::Relay(0),
            &current,
            now
        ));
        assert!(
            !beats(
                Path::Relay(1),
                &window(now, &[30, 30, 30, 30, 290]),
                Path::Relay(0),
                &current,
                now
            ),
            "one sample within the margin"
        );
    }

    /// The challenger's median must also beat the current path's best sample: a current path
    /// whose window shows it can be as fast keeps the pair, as a jittery equal path would.
    #[test]
    fn the_challenger_must_also_beat_the_current_best_sample() {
        let now = Duration::from_secs(50);
        let challenger = window(now, &[100; 5]);
        let current = window(now, &[300, 300, 300, 300, 120]);
        assert!(!beats(
            Path::Relay(1),
            &challenger,
            Path::Relay(0),
            &current,
            now
        ));
        let current = window(now, &[300, 300, 300, 300, 145]);
        assert!(beats(
            Path::Relay(1),
            &challenger,
            Path::Relay(0),
            &current,
            now
        ));
    }

    /// Direct takes over from a relay of nearly the same speed; a relay needs the full margin.
    #[test]
    fn direct_wins_inside_the_band() {
        let now = Duration::from_secs(50);
        let relay = window(now, &[100; 5]);
        let direct = window(now, &[110; 5]);
        assert!(
            beats(Path::Direct, &direct, Path::Relay(0), &relay, now),
            "10 ms slower is inside 15 ms"
        );
        assert!(
            !beats(Path::Relay(0), &relay, Path::Direct, &direct, now),
            "10 ms faster is not enough"
        );
        assert!(
            !beats(
                Path::Direct,
                &window(now, &[115; 5]),
                Path::Relay(0),
                &relay,
                now
            ),
            "at the margin"
        );
    }

    /// The dwell blocks a switch soon after a failover or another switch.
    #[test]
    fn switches_respect_the_dwell() {
        let mut selector = Selector::default();
        selector.install(Some(Path::Relay(3)), Duration::ZERO);
        selector.install(Some(Path::Relay(0)), Duration::ZERO);
        let now = Duration::from_secs(9);
        let slow = window(now, &[200; 5]);
        let fast = window(now, &[20; 5]);
        let paths = [(Path::Relay(0), &slow), (Path::Relay(1), &fast)];
        assert_eq!(selector.choose(now, paths), None, "inside the dwell");
        let later = Duration::from_secs(10);
        assert_eq!(selector.choose(later, paths), Some(Path::Relay(1)));
        assert_eq!(selector.current(), Some(Path::Relay(1)));
        let paths = [(Path::Relay(1), &slow), (Path::Relay(0), &fast)];
        assert_eq!(
            selector.choose(later + ms(1), paths),
            None,
            "dwell after a switch"
        );
        selector.install(Some(Path::Relay(0)), Duration::from_secs(30));
        assert_eq!(
            selector.choose(Duration::from_secs(35), paths),
            None,
            "dwell after a failure"
        );
    }

    /// The first measured choice takes a clear win at once and leaves equal paths alone; an
    /// unmeasured default starts no dwell.
    #[test]
    fn the_first_measured_choice_needs_one_clear_sample() {
        assert!(first_choice(Path::Relay(1), ms(30), ms(300)));
        assert!(!first_choice(Path::Relay(1), ms(38), ms(40)), "within 5 ms");
        assert!(
            first_choice(Path::Direct, ms(44), ms(40)),
            "direct wins inside the band"
        );
        let mut selector = Selector::default();
        selector.start(Some(Path::Relay(1)));
        selector.start(Some(Path::Relay(0)));
        let now = Duration::from_secs(6);
        let slow = window(now, &[300; 5]);
        let fast = window(now, &[30; 5]);
        assert_eq!(
            selector.choose(now, [(Path::Relay(0), &slow), (Path::Relay(1), &fast)]),
            Some(Path::Relay(1)),
            "setup moves start no dwell"
        );
    }

    /// The fastest qualifying challenger wins, ties going to direct and then the lower index.
    #[test]
    fn the_fastest_qualifying_path_wins_with_a_stable_tie_break() {
        let now = Duration::from_secs(60);
        let mut selector = Selector::default();
        selector.install(Some(Path::Relay(2)), Duration::ZERO);
        let slow = window(now, &[300; 5]);
        let fast = window(now, &[40; 5]);
        let faster = window(now, &[20; 5]);
        assert_eq!(
            selector.choose(
                now,
                [
                    (Path::Relay(2), &slow),
                    (Path::Relay(1), &fast),
                    (Path::Relay(3), &faster)
                ]
            ),
            Some(Path::Relay(3))
        );
        let mut selector = Selector::default();
        selector.install(Some(Path::Relay(2)), Duration::ZERO);
        assert_eq!(
            selector.choose(
                now,
                [
                    (Path::Relay(2), &slow),
                    (Path::Relay(1), &fast),
                    (Path::Direct, &fast)
                ]
            ),
            Some(Path::Direct)
        );
    }

    /// Without a measured current path nothing moves, whatever the challengers show.
    #[test]
    fn an_unmeasured_current_path_stays() {
        let now = Duration::from_secs(60);
        let mut selector = Selector::default();
        selector.install(Some(Path::Relay(0)), Duration::ZERO);
        let fast = window(now, &[1; 5]);
        assert_eq!(selector.choose(now, [(Path::Relay(1), &fast)]), None);
        assert_eq!(
            selector.choose(
                now,
                [
                    (Path::Relay(0), &Samples::default()),
                    (Path::Relay(1), &fast)
                ]
            ),
            None
        );
    }

    /// A small deterministic generator, so the jitter test needs no dependency and never flakes.
    struct Lcg(u64);

    impl Lcg {
        /// A value in `0..1` from the top bits of a 64-bit linear congruential step.
        fn unit(&mut self) -> f64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            f64::from(u32::try_from(self.0 >> 40).unwrap_or(0)) / f64::from(1_u32 << 24)
        }

        /// An approximately normal value with mean 0 and spread 1 (sum of twelve uniforms).
        fn normal(&mut self) -> f64 {
            (0..12).map(|_| self.unit()).sum::<f64>() - 6.0
        }
    }

    /// Simulate two paths sampled once a second for `seconds`, and count switches.
    fn switches(base: [f64; 2], jitter: f64, seconds: u64, seed: u64) -> usize {
        let mut random = Lcg(seed);
        let mut samples = [Samples::default(); 2];
        let mut selector = Selector::default();
        selector.install(Some(Path::Relay(0)), Duration::ZERO);
        let mut count = 0;
        for second in 1..=seconds {
            let now = Duration::from_secs(second);
            for (index, path) in samples.iter_mut().enumerate() {
                let rtt = (base[index] * (1.0 + jitter * random.normal())).max(0.1);
                path.record(now, Duration::from_secs_f64(rtt / 1000.0));
            }
            let paths = [(Path::Relay(0), &samples[0]), (Path::Relay(1), &samples[1])];
            if selector.choose(now, paths).is_some() {
                count += 1;
            }
        }
        count
    }

    /// Two equal relays under 10–30 % normal jitter: an hour of samples, few switches. With
    /// this generator and seeds the rule makes 0 / at most 5 / at most 10 switches per hour;
    /// the limits leave room for rounding, not for a weaker rule (every-sample-against-median
    /// alone makes about 15 and 32 at 20 and 30 %).
    #[test]
    fn equal_paths_under_jitter_do_not_flap() {
        for (jitter, limit) in [(0.10, 1), (0.20, 7), (0.30, 13)] {
            for seed in 1..=5 {
                let count = switches([40.0, 40.0], jitter, 3_600, seed);
                assert!(
                    count <= limit,
                    "jitter {jitter}: {count} switches in an hour (seed {seed})"
                );
            }
        }
    }

    /// A real win is still taken through the same jitter, within the first sustained window.
    #[test]
    fn a_clear_win_survives_jitter() {
        for seed in 1..=5 {
            let mut random = Lcg(seed);
            let mut samples = [Samples::default(); 2];
            let mut selector = Selector::default();
            selector.install(Some(Path::Relay(0)), Duration::ZERO);
            let mut switched = None;
            for second in 1..=60 {
                let now = Duration::from_secs(second);
                for (index, base) in [300.0, 30.0].into_iter().enumerate() {
                    let rtt = base * (1.0 + 0.3 * random.normal());
                    samples[index].record(now, Duration::from_secs_f64(rtt.max(0.1) / 1000.0));
                }
                let paths = [(Path::Relay(0), &samples[0]), (Path::Relay(1), &samples[1])];
                if selector.choose(now, paths).is_some() {
                    switched = Some(second);
                    break;
                }
            }
            // The first window is sustained after five samples (four seconds apart from the first).
            assert!(
                switched.is_some_and(|second| second <= 7),
                "seed {seed}: {switched:?}"
            );
        }
    }
}
