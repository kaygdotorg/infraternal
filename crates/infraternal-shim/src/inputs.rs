//! Keeps bounded per-writer PTY acceptance in the surviving shim [13][50], shared across peer replacement.
use super::InputCursors;
use crate::frame::MAX_FRAME;
use std::{
    collections::{HashMap, VecDeque},
    io,
};

#[cfg(test)]
#[path = "../tests/unit/review_merge_inputs.rs"]
mod merge_review;

/// Most distinct writer identities one session keeps cursors for. Selecting a
/// new one beyond this is refused; existing writers are unaffected.
const MAX_WRITERS: usize = 512;

/// Per-writer cursors, keyed by writer id. Writer `u64::MAX` is reserved for
/// internal replies (see `Inputs::reply`) and is outside the `u32` range peers
/// can choose.
#[cfg(not(feature = "process-per-user"))]
type Cursors = HashMap<u64, InputCursors>;

/// Most shared sessions have only writer zero. Its inline state avoids one
/// allocation per idle session; selecting another writer promotes it exactly
/// once without resetting accepted/written offsets or staged geometry.
#[cfg(feature = "process-per-user")]
enum Cursors {
    /// Only writer zero exists. Stored inline, so an idle session allocates nothing.
    Legacy(InputCursors),
    /// Several writers, in a map. Once promoted to this form a session never goes
    /// back.
    Multiple(HashMap<u64, InputCursors>),
}
#[cfg(feature = "process-per-user")]
impl From<[(u64, InputCursors); 1]> for Cursors {
    fn from([(writer, cursor)]: [(u64, InputCursors); 1]) -> Self {
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
    /// The cursors for `writer`, or `None`. In the inline form only writer zero
    /// exists.
    fn get(&self, writer: &u64) -> Option<&InputCursors> {
        match self {
            Self::Legacy(cursor) => (*writer == 0).then_some(cursor),
            Self::Multiple(cursors) => cursors.get(writer),
        }
    }
    /// The same as `get`, but mutable.
    fn get_mut(&mut self, writer: &u64) -> Option<&mut InputCursors> {
        match self {
            Self::Legacy(cursor) => (*writer == 0).then_some(cursor),
            Self::Multiple(cursors) => cursors.get_mut(writer),
        }
    }
    /// True if `writer` has cursors.
    fn contains_key(&self, writer: &u64) -> bool {
        self.get(writer).is_some()
    }
    /// Number of writers with cursors.
    fn len(&self) -> usize {
        match self {
            Self::Legacy(_) => 1,
            Self::Multiple(cursors) => cursors.len(),
        }
    }
    /// Capacity of the backing map; zero in the inline form. Used only to size
    /// memory accounting.
    fn capacity(&self) -> usize {
        match self {
            Self::Legacy(_) => 0,
            Self::Multiple(cursors) => cursors.capacity(),
        }
    }
    /// Adds or replaces the cursors for `writer`. Promotes the inline form to a map
    /// first, moving writer zero's cursors over unchanged so its accepted and
    /// written offsets and staged size survive.
    fn insert(&mut self, writer: u64, cursor: InputCursors) {
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
    /// The writer whose input the terminal is currently taking, if any.
    pub(super) active_writer: Option<u32>,
    /// Per-writer progress: what was accepted and what was written.
    cursors: Cursors,
    /// The queued bytes grouped into runs by owner: `(writer, count)` in queue
    /// order. This lets a partial PTY write credit only the writers whose bytes
    /// actually went out.
    segments: VecDeque<(u64, usize)>,
    /// Most runs `segments` may hold. Bounds bookkeeping when writers alternate
    /// byte by byte.
    #[cfg(feature = "process-per-user")]
    segment_limit: usize,
}
impl Default for Inputs {
    fn default() -> Self {
        Self::with_geometry((80, 24, 0, 0))
    }
}
impl Inputs {
    /// Creates the input state with only writer zero, whose staged and accepted
    /// terminal size are `size` (columns, rows, pixel width, pixel height).
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
    /// Same as `with_geometry`, but for a shared host with a small cap (1024) on
    /// queued runs, so many sessions stay cheap.
    #[cfg(feature = "process-per-user")]
    pub(super) fn for_host(size: (u16, u16, u16, u16)) -> Self {
        Self {
            segment_limit: 1024,
            ..Self::with_geometry(size)
        }
    }
    /// Estimate of heap bytes held by the writer map and the run list, for the
    /// user's memory pool.
    #[cfg(feature = "process-per-user")]
    pub(super) fn allocated_bytes(&self) -> usize {
        let buckets = if self.cursors.capacity() == 0 {
            0
        } else {
            (self.cursors.capacity() + 1).next_power_of_two()
        };
        buckets * (std::mem::size_of::<(u64, InputCursors)>() + 1)
            + if buckets == 0 { 0 } else { 32 }
            + self.segments.capacity() * std::mem::size_of::<(u64, usize)>()
    }
    /// How many more bytes `writer` may add to a queue already holding `queued`
    /// bytes. This is zero when the run list is full and `writer` would start a new
    /// run. Otherwise it is whatever room is left under `MAX_FRAME`.
    #[cfg(feature = "process-per-user")]
    pub(super) fn available(&self, writer: u32, queued: usize) -> usize {
        if self.segments.len() >= self.segment_limit
            && self
                .segments
                .back()
                .is_some_and(|(last, _)| *last != u64::from(writer))
        {
            return 0;
        }
        MAX_FRAME - queued
    }
    /// Registers `writer` with `size` as its initial terminal size. A known writer
    /// is left untouched. Fails with an invalid-input error once `MAX_WRITERS`
    /// writers exist (the internal reply writer does not count).
    pub(super) fn select(&mut self, writer: u32, size: (u16, u16, u16, u16)) -> io::Result<()> {
        if self.cursors.contains_key(&u64::from(writer)) {
            return Ok(());
        }
        if self.cursors.len() > MAX_WRITERS + usize::from(self.cursors.contains_key(&u64::MAX)) {
            return Err(super::invalid_input());
        }
        self.cursors.insert(
            u64::from(writer),
            InputCursors {
                requested_size: size,
                accepted_size: size,
                ..InputCursors::default()
            },
        );
        Ok(())
    }
    /// Stages `size` as the requested size for `writer`; it is not applied yet.
    /// Fails if there is no writer or it is unknown.
    pub(super) fn request_resize(
        &mut self,
        writer: Option<u32>,
        size: (u16, u16, u16, u16),
    ) -> io::Result<()> {
        self.cursors
            .get_mut(&u64::from(writer.ok_or_else(super::invalid_input)?))
            .ok_or_else(super::invalid_input)?
            .requested_size = size;
        Ok(())
    }
    /// Settles a staged resize. If `applied`, the requested size becomes the
    /// accepted size; if not, the request is rolled back to the last accepted size.
    /// Returns the resulting size. Fails if the writer is missing or unknown.
    pub(super) fn finish_resize(
        &mut self,
        writer: Option<u32>,
        applied: bool,
    ) -> io::Result<(u16, u16, u16, u16)> {
        let state = self
            .cursors
            .get_mut(&u64::from(writer.ok_or_else(super::invalid_input)?))
            .ok_or_else(super::invalid_input)?;
        if applied {
            state.accepted_size = state.requested_size;
        } else {
            state.requested_size = state.accepted_size;
        }
        Ok(state.requested_size)
    }
    /// The cursors for `writer`. Fails with an invalid-input error if there is no
    /// writer or it is unknown.
    pub(super) fn get(&self, writer: Option<u32>) -> io::Result<&InputCursors> {
        self.cursors
            .get(&u64::from(writer.ok_or_else(super::invalid_input)?))
            .ok_or_else(super::invalid_input)
    }
    /// Queues a writer's input.
    ///
    /// `seq` is the offset of `bytes[0]` in that writer's stream. Bytes before the
    /// writer's accepted offset are skipped (so replays after reconnect are
    /// harmless). A `seq` beyond the accepted offset would leave a gap and is
    /// refused, as is input that would overflow the `MAX_FRAME` queue. A refusal
    /// changes nothing.
    pub(super) fn accept(
        &mut self,
        writer: u32,
        seq: u64,
        bytes: &[u8],
        queue: &mut VecDeque<u8>,
    ) -> io::Result<()> {
        self.accept_owned(u64::from(writer), seq, bytes, queue)
    }
    /// Implements `accept` for any key, including the internal reply writer, and
    /// records the new bytes in the run list. On the shared host it also refuses
    /// when a new run is needed but the run list is full.
    fn accept_owned(
        &mut self,
        writer: u64,
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
    /// Reply queue ownership is separate from every selected writer. It never
    /// updates active geometry or publishes an input acknowledgement [307].
    /// All reply admission checks precede mutation, including older typing's
    /// reservation. Refusal is expected expiry, so it needs no allocated error.
    pub(super) fn reply(&mut self, reserved: bool, bytes: &[u8], queue: &mut VecDeque<u8>) -> bool {
        if reserved
            || bytes.is_empty()
            || bytes.len() > 1024
            || queue.len().saturating_add(bytes.len()) > MAX_FRAME
        {
            return false;
        }
        // The internal key is outside the full u32 peer-writer namespace.
        // Widening keys leaves the aligned segment layout unchanged.
        #[cfg(not(feature = "process-per-user"))]
        let seq = self.cursors.entry(u64::MAX).or_default().accepted;
        #[cfg(feature = "process-per-user")]
        let seq = {
            if !self.cursors.contains_key(&u64::MAX) {
                self.cursors.insert(u64::MAX, InputCursors::default());
            }
            let Some(state) = self.cursors.get(&u64::MAX) else {
                return false;
            };
            state.accepted
        };
        self.accept_owned(u64::MAX, seq, bytes, queue).is_ok()
    }
    /// Records that `bytes` bytes were written from the front of the queue to the
    /// PTY, advancing each owner's written offset by what was theirs. Fails if more
    /// bytes are claimed than are queued.
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
            if let Ok(writer) = u32::try_from(*writer) {
                crate::host_trace::credit(writer, state.written, used);
            }
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

#[cfg(test)]
mod reply_tests {
    //! Replies share the bounded PTY queue while leaving keyboard offsets and geometry intact.
    use super::*;
    #[cfg(feature = "host-diagnostics")]
    #[test]
    fn reply_segments_never_publish_typing_credit() {
        let mut inputs = Inputs::default();
        let mut queue = VecDeque::new();
        inputs.select(u32::MAX, (80, 24, 0, 0)).unwrap();
        inputs.accept(u32::MAX, 0, b"ab", &mut queue).unwrap();
        assert!(inputs.reply(false, b"reply", &mut queue));
        crate::host_trace::enable(true).unwrap();
        crate::host_trace::dump(&mut io::sink()).unwrap();
        crate::host_trace::context([9; 16], 56);
        inputs.advance(3).unwrap();
        assert_eq!(
            crate::host_trace::credited_ranges(),
            [(u32::MAX as usize, 2, 2)]
        );
        inputs.advance(4).unwrap();
        assert_eq!(
            crate::host_trace::credited_ranges(),
            [(u32::MAX as usize, 2, 2)]
        );
        crate::host_trace::enable(false).unwrap();
    }

    #[test]
    fn reply_identity_is_outside_peer_namespace_and_writer_limit() {
        let mut inputs = Inputs::default();
        let mut queue = VecDeque::new();
        assert!(inputs.reply(false, b"r", &mut queue));
        for writer in 1..512 {
            inputs.select(writer, (80, 24, 0, 0)).unwrap();
        }
        inputs.select(u32::MAX, (120, 40, 0, 0)).unwrap();
        assert!(inputs.select(512, (80, 24, 0, 0)).is_err());
        inputs.accept(u32::MAX, 0, b"ab", &mut queue).unwrap();
        assert!(inputs.reply(false, b"s", &mut queue));
        assert_eq!(queue.iter().copied().collect::<Vec<_>>(), b"rabs");
        inputs.advance(2).unwrap();
        assert_eq!(inputs.get(Some(u32::MAX)).unwrap().written, 1);
        assert_eq!(inputs.cursors.get(&u64::MAX).unwrap().written, 1);
        inputs.advance(2).unwrap();
        assert_eq!(inputs.get(Some(u32::MAX)).unwrap().written, 2);
        assert_eq!(inputs.cursors.get(&u64::MAX).unwrap().written, 2);
    }

    #[cfg(feature = "process-per-user")]
    #[test]
    fn host_replies_preserve_segment_budget_and_account_for_promoted_storage() {
        let mut inputs = Inputs::for_host((81, 25, 0, 0));
        let mut queue = VecDeque::with_capacity(2048);
        let ((), allocation) = crate::heap_accounting::measure(|| {
            for seq in 0..512 {
                inputs.accept(0, seq, b"x", &mut queue).unwrap();
                assert!(inputs.reply(false, b"r", &mut queue));
            }
        });
        assert_eq!(inputs.segments.len(), 1024);
        assert!(inputs.segments.capacity() <= 1024);
        assert_eq!(inputs.available(0, queue.len()), 0);
        let accounted = i64::try_from(inputs.allocated_bytes()).unwrap();
        assert!(accounted >= allocation.bytes);
        assert!(accounted <= allocation.bytes + 32);
        println!(
            "reply queue bookkeeping: measured={} accounted={accounted} segments={} key_bytes={} segment_bytes={}",
            allocation.bytes,
            inputs.segments.len(),
            std::mem::size_of::<u64>(),
            std::mem::size_of::<(u64, usize)>()
        );
        // The final reply can coalesce; a new typing segment needs a free slot.
        assert!(inputs.reply(false, b"s", &mut queue));
        assert!(inputs.accept(0, 512, b"x", &mut queue).is_err());
        assert_eq!(inputs.get(Some(0)).unwrap().accepted, 512);
        inputs.advance(1).unwrap();
        queue.pop_front();
        inputs.accept(0, 512, b"x", &mut queue).unwrap();
        let before = queue.clone();
        let reply_accepted = inputs.cursors.get(&u64::MAX).unwrap().accepted;
        assert!(!inputs.reply(false, b"t", &mut queue));
        assert_eq!(queue, before);
        assert_eq!(
            inputs.cursors.get(&u64::MAX).unwrap().accepted,
            reply_accepted
        );
    }

    #[test]
    fn replies_preserve_selected_writer_cursor_and_geometry() {
        let mut cursors = Inputs::default();
        let mut queue = VecDeque::new();
        cursors.select(7, (120, 40, 0, 0)).unwrap();
        cursors.active_writer = Some(7);
        cursors.accept(7, 0, b"typed", &mut queue).unwrap();
        assert!(!cursors.reply(true, b"\x1b[1;1R", &mut queue));
        assert_eq!(queue.iter().copied().collect::<Vec<_>>(), b"typed");
        assert!(!cursors.cursors.contains_key(&u64::MAX));
        assert!(cursors.reply(false, b"\x1b[1;1R", &mut queue));
        assert_eq!(cursors.get(Some(7)).unwrap().accepted, 5);
        assert_eq!(cursors.active_writer, Some(7));
        cursors.advance(queue.len()).unwrap();
        assert_eq!(cursors.get(Some(7)).unwrap().written, 5);
        assert_eq!(
            cursors.get(Some(7)).unwrap().requested_size,
            (120, 40, 0, 0)
        );
        assert!(!cursors.reply(false, &vec![b'x'; 1025], &mut queue));
    }
}
