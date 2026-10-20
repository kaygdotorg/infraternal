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

const MAX_WRITERS: usize = 512;

/// Queue ownership follows byte segments so a partial PTY write credits only
/// the writers whose bytes were actually written. Identity zero preserves v1.
pub(super) struct Inputs {
    pub(super) active_writer: Option<u32>,
    cursors: HashMap<u64, InputCursors>,
    segments: VecDeque<(u64, usize)>,
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
            cursors: HashMap::from([(
                0,
                InputCursors {
                    requested_size: size,
                    accepted_size: size,
                    ..InputCursors::default()
                },
            )]),
            segments: VecDeque::new(),
        }
    }
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
    pub(super) fn get(&self, writer: Option<u32>) -> io::Result<&InputCursors> {
        self.cursors
            .get(&u64::from(writer.ok_or_else(super::invalid_input)?))
            .ok_or_else(super::invalid_input)
    }
    pub(super) fn accept(
        &mut self,
        writer: u32,
        seq: u64,
        bytes: &[u8],
        queue: &mut VecDeque<u8>,
    ) -> io::Result<()> {
        self.accept_owned(u64::from(writer), seq, bytes, queue)
    }
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
        let state = self.cursors.entry(u64::MAX).or_default();
        let seq = state.accepted;
        self.accept_owned(u64::MAX, seq, bytes, queue).is_ok()
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

#[cfg(test)]
mod reply_tests {
    //! Replies share the bounded PTY queue while leaving keyboard offsets and geometry intact.
    use super::*;
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
