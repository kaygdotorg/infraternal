//! Keeps bounded per-writer PTY acceptance in the surviving shim [13][50], shared across peer replacement.
use super::InputCursors;
use crate::frame::MAX_FRAME;
use std::{
    collections::{HashMap, VecDeque},
    io,
};

const MAX_WRITERS: usize = 512;

#[cfg(not(feature = "process-per-user"))]
type Cursors = HashMap<u32, InputCursors>;

/// Most shared sessions have only writer zero. Its inline state avoids one
/// allocation per idle session; selecting another writer promotes it exactly
/// once without resetting accepted/written offsets or staged geometry.
#[cfg(feature = "process-per-user")]
enum Cursors {
    Legacy(InputCursors),
    Multiple(HashMap<u32, InputCursors>),
}
#[cfg(feature = "process-per-user")]
impl From<[(u32, InputCursors); 1]> for Cursors {
    fn from([(writer, cursor)]: [(u32, InputCursors); 1]) -> Self {
        debug_assert_eq!(writer, 0);
        Self::Legacy(cursor)
    }
}
#[cfg(feature = "process-per-user")]
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "retain HashMap's borrowed-key API so production callers stay identical"
)]
impl Cursors {
    fn get(&self, writer: &u32) -> Option<&InputCursors> {
        match self {
            Self::Legacy(cursor) => (*writer == 0).then_some(cursor),
            Self::Multiple(cursors) => cursors.get(writer),
        }
    }
    fn get_mut(&mut self, writer: &u32) -> Option<&mut InputCursors> {
        match self {
            Self::Legacy(cursor) => (*writer == 0).then_some(cursor),
            Self::Multiple(cursors) => cursors.get_mut(writer),
        }
    }
    fn contains_key(&self, writer: &u32) -> bool {
        self.get(writer).is_some()
    }
    fn len(&self) -> usize {
        match self {
            Self::Legacy(_) => 1,
            Self::Multiple(cursors) => cursors.len(),
        }
    }
    fn capacity(&self) -> usize {
        match self {
            Self::Legacy(_) => 0,
            Self::Multiple(cursors) => cursors.capacity(),
        }
    }
    fn insert(&mut self, writer: u32, cursor: InputCursors) {
        if let Self::Legacy(legacy) = self {
            *self = Self::Multiple(HashMap::from([(0, std::mem::take(legacy))]));
        }
        if let Self::Multiple(cursors) = self {
            cursors.insert(writer, cursor);
        }
    }
}

/// Queue ownership follows byte segments so a partial PTY write credits only
/// the writers whose bytes were actually written. Identity zero preserves v1.
pub(super) struct Inputs {
    pub(super) active_writer: Option<u32>,
    cursors: Cursors,
    segments: VecDeque<(u32, usize)>,
    #[cfg(feature = "process-per-user")]
    segment_limit: usize,
}
impl Default for Inputs {
    fn default() -> Self {
        Self::with_geometry((80, 24, 0, 0))
    }
}
impl Inputs {
    pub(super) fn with_geometry(size: (u16, u16, u16, u16)) -> Self {
        Self {
            active_writer: None,
            cursors: Cursors::from([(
                0,
                InputCursors {
                    requested_size: size,
                    accepted_size: size,
                    ..InputCursors::default()
                },
            )]),
            segments: VecDeque::new(),
            #[cfg(feature = "process-per-user")]
            segment_limit: MAX_FRAME,
        }
    }
    #[cfg(feature = "process-per-user")]
    pub(super) fn for_host(size: (u16, u16, u16, u16)) -> Self {
        Self {
            segment_limit: 1024,
            ..Self::with_geometry(size)
        }
    }
    #[cfg(feature = "process-per-user")]
    pub(super) fn allocated_bytes(&self) -> usize {
        let buckets = if self.cursors.capacity() == 0 {
            0
        } else {
            (self.cursors.capacity() + 1).next_power_of_two()
        };
        buckets * (std::mem::size_of::<(u32, InputCursors)>() + 1)
            + if buckets == 0 { 0 } else { 32 }
            + self.segments.capacity() * std::mem::size_of::<(u32, usize)>()
    }
    #[cfg(feature = "process-per-user")]
    pub(super) fn available(&self, writer: u32, queued: usize) -> usize {
        if self.segments.len() >= self.segment_limit
            && self
                .segments
                .back()
                .is_some_and(|(last, _)| *last != writer)
        {
            return 0;
        }
        MAX_FRAME - queued
    }
    pub(super) fn select(&mut self, writer: u32, size: (u16, u16, u16, u16)) -> io::Result<()> {
        if self.cursors.contains_key(&writer) {
            return Ok(());
        }
        if self.cursors.len() > MAX_WRITERS {
            return Err(super::invalid_input());
        }
        self.cursors.insert(
            writer,
            InputCursors {
                requested_size: size,
                accepted_size: size,
                ..InputCursors::default()
            },
        );
        Ok(())
    }
    pub(super) fn request_resize(
        &mut self,
        writer: Option<u32>,
        size: (u16, u16, u16, u16),
    ) -> io::Result<()> {
        self.cursors
            .get_mut(&writer.ok_or_else(super::invalid_input)?)
            .ok_or_else(super::invalid_input)?
            .requested_size = size;
        Ok(())
    }
    pub(super) fn finish_resize(
        &mut self,
        writer: Option<u32>,
        applied: bool,
    ) -> io::Result<(u16, u16, u16, u16)> {
        let state = self
            .cursors
            .get_mut(&writer.ok_or_else(super::invalid_input)?)
            .ok_or_else(super::invalid_input)?;
        if applied {
            state.accepted_size = state.requested_size;
        } else {
            state.requested_size = state.accepted_size;
        }
        Ok(state.requested_size)
    }
    pub(super) fn get(&self, writer: Option<u32>) -> io::Result<&InputCursors> {
        self.cursors
            .get(&writer.ok_or_else(super::invalid_input)?)
            .ok_or_else(super::invalid_input)
    }
    pub(super) fn accept(
        &mut self,
        writer: u32,
        seq: u64,
        bytes: &[u8],
        queue: &mut VecDeque<u8>,
    ) -> io::Result<()> {
        let state = self
            .cursors
            .get_mut(&writer)
            .ok_or_else(super::invalid_input)?;
        #[cfg(feature = "process-per-user")]
        if seq.saturating_add(bytes.len() as u64) > state.accepted
            && self.segments.len() >= self.segment_limit
            && self
                .segments
                .back()
                .is_some_and(|(last, _)| *last != writer)
        {
            return Err(super::invalid_input());
        }
        let before = queue.len();
        state.accept(seq, bytes, queue)?;
        let added = queue.len() - before;
        if added > 0 {
            if let Some((last, count)) = self.segments.back_mut()
                && *last == writer
            {
                *count += added;
            } else {
                // At least one queued byte backs every segment; the existing
                // MAX_FRAME byte budget bounds even alternating one-byte writers.
                debug_assert!(self.segments.len() < MAX_FRAME);
                self.segments.push_back((writer, added));
            }
        }
        Ok(())
    }
    pub(super) fn advance(&mut self, mut bytes: usize) -> io::Result<()> {
        while bytes > 0 {
            let (writer, count) = self.segments.front_mut().ok_or_else(super::invalid_input)?;
            let used = bytes.min(*count);
            let state = self
                .cursors
                .get_mut(writer)
                .ok_or_else(super::invalid_input)?;
            state.written = state
                .written
                .checked_add(used as u64)
                .ok_or_else(super::invalid_input)?;
            #[cfg(feature = "host-diagnostics")]
            crate::host_trace::credit(*writer, state.written, used);
            *count -= used;
            bytes -= used;
            if *count == 0 {
                self.segments.pop_front();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Verify writer ownership at actual partial-write boundaries and retained identity limits.
    use super::*;
    #[cfg(feature = "host-diagnostics")]
    #[test]
    fn diagnostic_credits_follow_partial_writes_across_writers() {
        let mut inputs = Inputs::default();
        let mut pending = VecDeque::new();
        for writer in [1, 2] {
            inputs.select(writer, (80, 24, 0, 0)).unwrap();
        }
        inputs.accept(1, 0, b"one", &mut pending).unwrap();
        inputs.accept(2, 0, b"xy", &mut pending).unwrap();
        inputs.accept(1, 3, b"more", &mut pending).unwrap();
        crate::host_trace::enable(true).unwrap();
        crate::host_trace::dump(&mut io::sink()).unwrap();
        crate::host_trace::context([8; 16], 55);
        inputs.advance(4).unwrap();
        assert_eq!(crate::host_trace::credited_ranges(), [(1, 3, 3), (2, 1, 1)]);
        inputs.advance(5).unwrap();
        assert_eq!(
            crate::host_trace::credited_ranges(),
            [(1, 3, 3), (2, 1, 1), (2, 2, 1), (1, 7, 4)]
        );
        crate::host_trace::enable(false).unwrap();
    }

    #[cfg(feature = "process-per-user")]
    #[test]
    fn host_legacy_writer_needs_no_heap_table() {
        let (mut inputs, allocation) =
            crate::heap_accounting::measure(|| Inputs::for_host((81, 25, 0, 0)));
        assert_eq!(allocation.bytes, 0, "idle legacy cursor allocated a table");
        assert_eq!(inputs.get(Some(0)).unwrap().requested_size, (81, 25, 0, 0));
        let mut queue = VecDeque::new();
        inputs.accept(0, 0, b"ab", &mut queue).unwrap();
        inputs.advance(1).unwrap();
        inputs.select(7, (80, 24, 0, 0)).unwrap();
        assert_eq!(inputs.get(Some(0)).unwrap().written, 1);
        assert_eq!(inputs.get(Some(0)).unwrap().accepted, 2);
        assert_eq!(inputs.get(Some(7)).unwrap().accepted, 0);
        inputs.advance(1).unwrap();
        assert_eq!(inputs.get(Some(0)).unwrap().written, 2);
    }
    #[test]
    fn partial_writes_credit_only_the_owner_and_replay_trims_per_writer() {
        let mut inputs = Inputs::default();
        inputs.select(7, (80, 24, 0, 0)).unwrap();
        inputs.select(9, (80, 24, 0, 0)).unwrap();
        let mut queue = VecDeque::new();
        inputs.accept(7, 0, b"abc", &mut queue).unwrap();
        inputs.accept(9, 0, b"de", &mut queue).unwrap();
        inputs.advance(4).unwrap();
        assert_eq!(inputs.get(Some(7)).unwrap().written, 3);
        assert_eq!(inputs.get(Some(9)).unwrap().written, 1);
        assert_eq!(inputs.get(Some(9)).unwrap().accepted, 2);
        for _ in 0..4 {
            queue.pop_front();
        }
        inputs.accept(7, 0, b"abc", &mut queue).unwrap();
        inputs.accept(9, 1, b"ef", &mut queue).unwrap();
        assert_eq!(queue.iter().copied().collect::<Vec<_>>(), b"ef");
        inputs.advance(2).unwrap();
        assert_eq!(inputs.get(Some(9)).unwrap().written, 3);
        assert!(inputs.accept(7, 4, b"gap", &mut queue).is_err());
        assert!(inputs.accept(9, u64::MAX, b"overflow", &mut queue).is_err());
        assert_eq!(inputs.get(Some(7)).unwrap().accepted, 3);
    }
    #[test]
    fn identity_cap_preserves_all_existing_cursors() {
        let mut inputs = Inputs::default();
        for writer in 1..=512 {
            inputs.select(writer, (80, 24, 0, 0)).unwrap();
        }
        assert!(inputs.select(513, (80, 24, 0, 0)).is_err());
        inputs.select(512, (80, 24, 0, 0)).unwrap();
        assert!(inputs.get(Some(513)).is_err());
        assert_eq!(inputs.get(Some(512)).unwrap().written, 0);
    }
}

#[cfg(all(test, feature = "process-per-user"))]
mod host_budget_tests {
    //! Segment refusal preserves accepted offsets and resumes when a slot drains.
    use super::*;
    #[test]
    fn alternating_writers_cannot_expand_shared_host_bookkeeping_without_bound() {
        let mut inputs = Inputs::for_host((80, 24, 0, 0));
        inputs.select(7, (80, 24, 0, 0)).unwrap();
        inputs.select(9, (80, 24, 0, 0)).unwrap();
        let mut queue = VecDeque::new();
        for index in 0..1024 {
            let writer = if index % 2 == 0 { 7 } else { 9 };
            let accepted = inputs.get(Some(writer)).unwrap().accepted;
            inputs.accept(writer, accepted, b"x", &mut queue).unwrap();
        }
        assert_eq!(inputs.available(7, queue.len()), 0);
        let accepted = inputs.get(Some(7)).unwrap().accepted;
        assert!(inputs.accept(7, accepted, b"x", &mut queue).is_err());
        assert_eq!(inputs.get(Some(7)).unwrap().accepted, accepted);
        assert_eq!(queue.len(), 1024);
        assert!(inputs.segments.capacity() <= 1024);
        // A duplicate remains idempotent even at the cap.
        inputs.accept(7, accepted - 1, b"x", &mut queue).unwrap();
        inputs.advance(1).unwrap();
        queue.pop_front();
        inputs.accept(7, accepted, b"x", &mut queue).unwrap();
        assert_eq!(inputs.get(Some(7)).unwrap().accepted, accepted + 1);
    }
}
