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
        Self {
            active_writer: None,
            cursors: HashMap::from([(0, InputCursors::default())]),
            segments: VecDeque::new(),
        }
    }
}
impl Inputs {
    pub(super) fn select(&mut self, writer: u32) -> io::Result<()> {
        if self.cursors.contains_key(&writer) {
            return Ok(());
        }
        if self.cursors.len() > MAX_WRITERS {
            return Err(super::invalid_input());
        }
        self.cursors.insert(writer, InputCursors::default());
        Ok(())
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
