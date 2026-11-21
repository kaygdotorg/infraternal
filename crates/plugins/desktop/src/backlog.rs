//! A short, age-bounded queue of encoded frames at one hand-off, so a brief stall costs a few delta frames, not a keyframe [D254, #146].
//!
//! App window video passes through several hand-offs on its way to a viewer
//! (the helper's frame slot, the source's sender, the server's per-viewer
//! delivery, the page and its decode worker). Each used to hold one frame.
//! When its consumer was busy for a moment, the next frame replaced the
//! waiting one, and because a delta frame cannot be decoded without the one
//! before it, the stream had to be repaired with a keyframe: 41–251 KB instead
//! of 0.4–5 KB, for every viewer of the session (J1078 on #146).
//!
//! A [`Backlog`] keeps the deltas instead, but only for a short time. While its
//! oldest waiting frame is younger than [`MAX_AGE`] (and the queue stays under
//! [`MAX_UNITS`] frames and [`MAX_BYTES`] bytes), every frame is queued and the
//! consumer catches up by sending a few small deltas. Past the bound the
//! consumer is too far behind for the deltas to be worth sending: the backlog
//! drops everything, refuses further deltas ("sealed") and the caller asks for
//! a keyframe. That is D254's drop-to-newest, applied only beyond the bound.
//! A keyframe always replaces whatever is waiting, because it is newer and
//! needs nothing before it.
//!
//! The time the consumer spends writing a keyframe does not count against the
//! deltas waiting behind it. On a slow link a keyframe can take longer than
//! the bound to write (a 250 KB keyframe takes ~0.7 s at 3 Mbit/s); counting
//! that time would drop every delta behind it, ask for another keyframe, and
//! so keep the link full of keyframes (measured on #146). Frames that waited
//! behind a keyframe age from the moment the consumer is free again.
//!
//! The type holds no lock, timer or task: callers keep it behind their own
//! mutex and wake their consumer the way they already do. Time is passed in,
//! so tests can drive it.
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// How long the oldest waiting frame may have waited before the hand-off gives
/// up on deltas. About 100 ms, as agreed by the owner (#146, 2026-11-21): long
/// enough for a 40–80 ms stall, short enough that a viewer never watches a
/// picture more than this far behind because of one hand-off.
pub const MAX_AGE: Duration = Duration::from_millis(100);
/// The most frames that may wait at one hand-off: one second at 120 Hz, the
/// longest a viewer write may take. 100 ms at 120 Hz is only 12 frames; the
/// rest covers the frames that queue behind a keyframe being written. Memory
/// is bounded by [`MAX_BYTES`].
pub const MAX_UNITS: usize = 128;
/// The most bytes that may wait at one hand-off. A keyframe is always taken
/// (it replaces everything); this bounds the deltas behind it, and so the
/// memory one hand-off can hold, to 1 MiB.
pub const MAX_BYTES: usize = 1 << 20;

/// What a backlog needs to know about the frames it holds.
pub trait Unit {
    /// True if a decoder can start from this frame alone.
    fn keyframe(&self) -> bool;
    /// The frame's encoded size in bytes, counted against [`MAX_BYTES`].
    fn size(&self) -> usize;
}

impl Unit for Vec<u8> {
    /// The helper's frame body: an 8-byte capture time, then the keyframe flag.
    fn keyframe(&self) -> bool {
        self.get(8) == Some(&1)
    }
    /// The whole body, header included.
    fn size(&self) -> usize {
        self.len()
    }
}

/// What [`Backlog::push`] did with a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The frame waits for the consumer.
    Queued,
    /// The consumer fell beyond the bound: every waiting frame and this one were
    /// dropped, and deltas are refused until a keyframe. Ask for a keyframe.
    Overflowed,
    /// A delta arrived while the backlog waits for a keyframe and was dropped.
    /// The keyframe request may need repeating.
    Sealed,
}

/// The frames waiting at one hand-off, oldest first, each with the time it was
/// queued. See the module docs for the rules.
#[derive(Debug)]
pub struct Backlog<T> {
    /// Waiting frames and when each was queued.
    units: VecDeque<(Instant, T)>,
    /// The total size of `units`.
    bytes: usize,
    /// Deltas are refused until the next keyframe.
    sealed: bool,
    /// The last frame taken was a keyframe, so the consumer is (or was) busy
    /// writing it: waiting frames do not age meanwhile.
    keyframe_taken: bool,
    /// Waiting frames count their age from this moment if it is later than
    /// when they were queued: when the consumer came back from a keyframe.
    aged_from: Option<Instant>,
}

impl<T> Default for Backlog<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Backlog<T> {
    /// An empty backlog that accepts deltas. It allocates nothing until the
    /// first frame waits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            units: VecDeque::new(),
            bytes: 0,
            sealed: false,
            keyframe_taken: false,
            aged_from: None,
        }
    }
    /// Takes the oldest waiting frame, if any, at `now`: the consumer is free.
    /// If the previous frame taken was a keyframe, the frames still waiting
    /// age from `now` (see the module docs).
    pub fn pop(&mut self, now: Instant) -> Option<T>
    where
        T: Unit,
    {
        if std::mem::take(&mut self.keyframe_taken) {
            self.aged_from = Some(now);
        }
        let (_, unit) = self.units.pop_front()?;
        self.bytes -= unit.size();
        self.keyframe_taken = unit.keyframe();
        Some(unit)
    }
    /// How many frames are waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.units.len()
    }
    /// True when no frame is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
    /// The total size of the waiting frames, for memory accounting.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
    /// Drops every waiting frame and refuses deltas until the next keyframe,
    /// for a consumer that lost a frame downstream and needs a fresh start.
    pub fn seal(&mut self) {
        self.units.clear();
        self.bytes = 0;
        self.sealed = true;
    }
    /// Offers `unit`, queued at `now`. A keyframe replaces everything waiting
    /// and lifts a seal. A delta is queued unless the backlog is sealed or its
    /// oldest frame has waited longer than [`MAX_AGE`] (not counting time
    /// spent behind a keyframe being written), or the delta would take it past
    /// [`MAX_UNITS`] or [`MAX_BYTES`]; then the backlog overflows (see
    /// [`Admission::Overflowed`]). An empty backlog always takes one delta,
    /// whatever its size, so a large frame cannot seal an idle hand-off.
    pub fn push(&mut self, unit: T, now: Instant) -> Admission
    where
        T: Unit,
    {
        if unit.keyframe() {
            self.units.clear();
            self.sealed = false;
            self.bytes = unit.size();
            self.units.push_back((now, unit));
            return Admission::Queued;
        }
        if self.sealed {
            return Admission::Sealed;
        }
        if let Some((oldest, _)) = self.units.front()
            && ((!self.keyframe_taken
                && now.saturating_duration_since(
                    self.aged_from.map_or(*oldest, |from| from.max(*oldest)),
                ) > MAX_AGE)
                || self.units.len() >= MAX_UNITS
                || self.bytes + unit.size() > MAX_BYTES)
        {
            self.seal();
            return Admission::Overflowed;
        }
        self.bytes += unit.size();
        self.units.push_back((now, unit));
        Admission::Queued
    }
}

#[cfg(test)]
mod tests {
    //! The bound rules, driven with explicit times.
    use super::*;

    /// A test frame: keyframe flag and size.
    struct Frame(bool, usize);
    impl Unit for Frame {
        fn keyframe(&self) -> bool {
            self.0
        }
        fn size(&self) -> usize {
            self.1
        }
    }

    /// A stall shorter than the bound queues every delta, in order.
    #[test]
    fn deltas_within_the_age_bound_wait_in_order() {
        let start = Instant::now();
        let mut backlog = Backlog::new();
        for index in 0..10_u64 {
            let at = start + Duration::from_millis(index * 8);
            assert_eq!(backlog.push(Frame(false, 500), at), Admission::Queued);
        }
        assert_eq!((backlog.len(), backlog.bytes()), (10, 5000));
        assert!(backlog.pop(start).is_some_and(|frame| !frame.0));
        assert_eq!(backlog.bytes(), 4500);
    }

    /// Past the age bound the backlog drops everything and waits for a keyframe.
    #[test]
    fn an_old_backlog_overflows_and_seals_until_a_keyframe() {
        let start = Instant::now();
        let mut backlog = Backlog::new();
        assert_eq!(backlog.push(Frame(false, 500), start), Admission::Queued);
        let late = start + MAX_AGE + Duration::from_millis(1);
        assert_eq!(backlog.push(Frame(false, 500), late), Admission::Overflowed);
        assert!(backlog.is_empty());
        assert_eq!(backlog.push(Frame(false, 500), late), Admission::Sealed);
        assert_eq!(backlog.push(Frame(true, 40_000), late), Admission::Queued);
        assert_eq!(backlog.push(Frame(false, 500), late), Admission::Queued);
        assert_eq!((backlog.len(), backlog.bytes()), (2, 40_500));
    }

    /// The unit and byte caps overflow too, even within the age bound.
    #[test]
    fn unit_and_byte_caps_bound_memory() {
        let now = Instant::now();
        let mut backlog = Backlog::new();
        for _ in 0..MAX_UNITS {
            assert_eq!(backlog.push(Frame(false, 1), now), Admission::Queued);
        }
        assert_eq!(backlog.push(Frame(false, 1), now), Admission::Overflowed);
        let mut backlog = Backlog::new();
        assert_eq!(
            backlog.push(Frame(false, MAX_BYTES), now),
            Admission::Queued
        );
        assert_eq!(backlog.push(Frame(false, 1), now), Admission::Overflowed);
    }

    /// Deltas that queue while a keyframe is being written wait as long as that
    /// write takes, then age from the moment the consumer is free again.
    #[test]
    fn time_spent_writing_a_keyframe_does_not_age_the_deltas_behind_it() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let mut backlog = Backlog::new();
        backlog.push(Frame(true, 100_000), start);
        assert!(backlog.pop(start).is_some_and(|frame| frame.0));
        // The keyframe takes 400 ms to write; 48 deltas queue behind it.
        for index in 1..=48 {
            assert_eq!(
                backlog.push(Frame(false, 500), at(index * 8)),
                Admission::Queued
            );
        }
        // Free again at 400 ms: the oldest delta now ages from 400 ms.
        assert!(backlog.pop(at(400)).is_some_and(|frame| !frame.0));
        assert_eq!(backlog.push(Frame(false, 500), at(480)), Admission::Queued);
        // A consumer stuck on a delta write still overflows past the bound.
        assert_eq!(
            backlog.push(Frame(false, 500), at(520)),
            Admission::Overflowed
        );
    }

    /// A keyframe replaces older waiting frames: they are obsolete.
    #[test]
    fn a_keyframe_replaces_waiting_deltas() {
        let now = Instant::now();
        let mut backlog = Backlog::new();
        backlog.push(Frame(false, 500), now);
        backlog.push(Frame(false, 500), now);
        assert_eq!(backlog.push(Frame(true, 9000), now), Admission::Queued);
        assert_eq!((backlog.len(), backlog.bytes()), (1, 9000));
        assert!(backlog.pop(now).is_some_and(|frame| frame.0));
    }
}
