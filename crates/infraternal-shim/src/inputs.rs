//! Keeps bounded per-writer PTY acceptance in the surviving shim [13][50], shared across peer replacement.
use super::InputCursors;
use crate::frame::MAX_FRAME;
use std::{
    collections::{HashMap, VecDeque},
    io,
};

const MAX_WRITERS: usize = 512;

/// Queue ownership follows byte segments so a partial PTY write credits only
/// the writers whose bytes were actually written. Identity zero preserves v1.
pub(super) struct Inputs {
    pub(super) active_writer: Option<u32>,
    cursors: HashMap<u32, InputCursors>,
    segments: VecDeque<(u32, usize)>,
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
