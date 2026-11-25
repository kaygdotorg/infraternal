//! Measures how fast a viewer's connection drains while video is backed up [#146].
//!
//! The server's socket for a viewer keeps at most a small, fixed amount of unsent data in the
//! kernel (`TCP_NOTSENT_LOWAT`, see the server's `send_queue` module). Once the link cannot keep
//! up, that queue stays full, and the viewer's video writes spend nearly all their time inside
//! the write call, waiting for the kernel to take more. In that state the kernel takes bytes
//! exactly as fast as the link carries them. [`LinkRate`] watches the writes and, when the viewer
//! has been busy writing for almost the whole of the last second, reports the bytes it handed to
//! the kernel in that second as the link rate. The host's encoder can then cut straight to that
//! rate (`VideoPressure`) instead of stepping down and overshooting into keyframe repairs.
//!
//! The busy test is what makes the count trustworthy. The kernel holds a little unsent data
//! (the bound, plus up to one burst of segments) that is counted as handed over but not yet
//! carried. If the viewer was busy the whole second, that amount is about the same at both ends
//! of it and cancels; if the viewer idled or the queue was filling or draining, it does not,
//! so there is no reading (`None`) and the encoder takes its usual smaller step. A viewer that
//! keeps up is never busy for a second, so it never reports a rate: an encoder only needs to
//! hear about the link when the link is the limit.
//!
//! The type holds no lock or timer; the viewer owns one, feeds it each finished write and asks
//! when it reports pressure. Time is passed in as [`Instant`]s, so tests can drive it.
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// How far back the reading looks.
const WINDOW: Duration = Duration::from_secs(1);
/// The share of [`WINDOW`], in percent, the viewer must have spent inside write calls for the
/// bytes to count as the link rate.
const BUSY_PERCENT: u32 = 85;
/// Most writes kept; at 120 frames per second a full window is about 120.
const MAX_WRITES: usize = 512;

/// One finished write.
#[derive(Clone, Copy)]
struct Write {
    /// When the write call began.
    began: Instant,
    /// When it returned.
    ended: Instant,
    /// How many bytes it handed to the kernel.
    bytes: usize,
}

/// Estimates the link rate of one viewer from its video write timings.
///
/// Feed every finished video write to [`LinkRate::record`]; read the rate with
/// [`LinkRate::estimate`] when the viewer reports pressure.
#[derive(Default)]
pub struct LinkRate {
    /// The writes that ended within the last [`WINDOW`] and a little more, oldest first.
    writes: VecDeque<Write>,
}

impl LinkRate {
    /// Records a finished write of `bytes` that began at `began` and returned at `ended`.
    pub fn record(&mut self, bytes: usize, began: Instant, ended: Instant) {
        self.writes.push_back(Write {
            began,
            ended,
            bytes,
        });
        while self.writes.len() > MAX_WRITES
            || self
                .writes
                .front()
                .is_some_and(|first| ended.saturating_duration_since(first.ended) > 2 * WINDOW)
        {
            self.writes.pop_front();
        }
    }

    /// The link rate in kilobits per second over the second before `now`, or `None` when the
    /// viewer was not busy writing for nearly all of it. Never returns 0.
    ///
    /// A write that straddles the start of the second counts the share of its bytes that fell in it.
    #[must_use]
    pub fn estimate(&self, now: Instant) -> Option<u32> {
        let from = now.checked_sub(WINDOW)?;
        // Microseconds spent inside write calls, and bytes handed over, within the window.
        let (mut busy_us, mut bytes) = (0_u128, 0_u128);
        for write in &self.writes {
            let (began, ended) = (write.began.max(from), write.ended.min(now));
            if ended <= began {
                continue;
            }
            let inside_us = (ended - began).as_micros();
            busy_us += inside_us;
            // The part of a write inside the window, by time.
            let whole_us = write
                .ended
                .saturating_duration_since(write.began)
                .as_micros();
            bytes += write.bytes as u128 * inside_us / whole_us.max(1);
        }
        if busy_us * 100 < WINDOW.as_micros() * u128::from(BUSY_PERCENT) {
            return None;
        }
        // Bytes over one second: bytes * 8 bits / 1000 = kilobits per second.
        u32::try_from(bytes * 8 / 1000)
            .ok()
            .filter(|&rate| rate > 0)
    }
}

#[cfg(test)]
mod tests {
    //! A viewer that is busy writing measures the link; one that idles, or has too little history,
    //! does not.
    use super::*;

    /// A viewer that is behind on a link of `kbit_s` kilobits per second: each write of `bytes`
    /// starts when the last returned and takes as long as the link needs to carry that many
    /// bytes. Writes `count` of them from `start`; returns when the last returned.
    fn backed_up(
        link: &mut LinkRate,
        start: Instant,
        count: usize,
        bytes: usize,
        kbit_s: u64,
    ) -> Instant {
        let each = Duration::from_micros(bytes as u64 * 8 * 1000 / kbit_s);
        let mut now = start;
        for _ in 0..count {
            link.record(bytes, now, now + each);
            now += each;
        }
        now
    }

    /// A viewer that was busy for the whole last second reads the link it was fed through.
    #[test]
    fn a_busy_second_measures_the_link() {
        let mut link = LinkRate::default();
        let start = Instant::now();
        let end = backed_up(&mut link, start, 100, 4_000, 3_000);
        let estimate = link.estimate(end).unwrap();
        assert!((2_900..=3_100).contains(&estimate), "{estimate}");
    }

    /// A viewer that keeps up idles between frames, so its quick writes say nothing about the link.
    #[test]
    fn writes_spaced_by_the_frame_interval_give_no_estimate() {
        let mut link = LinkRate::default();
        let start = Instant::now();
        for step in 0..150 {
            let at = start + Duration::from_millis(8 * step);
            link.record(4_000, at, at + Duration::from_micros(50));
        }
        assert_eq!(link.estimate(start + Duration::from_millis(8 * 149)), None);
    }

    /// A keyframe's long write counts like any other, and a write that straddles the start of the
    /// second counts only its share.
    #[test]
    fn a_keyframe_write_counts_and_a_straddling_write_counts_its_share() {
        let mut link = LinkRate::default();
        let start = Instant::now();
        // A 200 000-byte keyframe over 533 ms at 3 Mbit/s, then deltas for 0.6 s.
        let after_keyframe = backed_up(&mut link, start, 1, 200_000, 3_000);
        let end = backed_up(&mut link, after_keyframe, 56, 4_000, 3_000);
        // The second ends at `end`: it starts 0.12 s into the keyframe's last stretch.
        let estimate = link.estimate(end).unwrap();
        assert!((2_900..=3_100).contains(&estimate), "{estimate}");
    }

    /// Time spent idle, or a link that was not full for the whole second, gives no reading.
    #[test]
    fn a_second_with_idle_time_gives_no_estimate() {
        let mut link = LinkRate::default();
        let start = Instant::now();
        // 0.5 s busy, then 0.5 s idle.
        let busy_until = backed_up(&mut link, start, 47, 4_000, 3_000);
        assert_eq!(link.estimate(busy_until + Duration::from_millis(500)), None);
        // Busy again for most of a second: the quiet half has left the window.
        let end = backed_up(
            &mut link,
            busy_until + Duration::from_millis(500),
            100,
            4_000,
            3_000,
        );
        assert!(link.estimate(end).is_some());
    }

    /// The reading follows the link when its rate changes.
    #[test]
    fn the_reading_follows_a_rate_change() {
        let mut link = LinkRate::default();
        let start = Instant::now();
        let switched = backed_up(&mut link, start, 60, 4_000, 10_000);
        // The link drops to 2 Mbit/s with no idle gap; a second later only that is in the window.
        let end = backed_up(&mut link, switched, 80, 4_000, 2_000);
        let estimate = link.estimate(end).unwrap();
        assert!((1_900..=2_100).contains(&estimate), "{estimate}");
    }
}
