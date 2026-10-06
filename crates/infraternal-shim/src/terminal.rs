//! Ghostty VT state with bounded snapshot and unfinished-parser carry [13][94].
#![forbid(unsafe_code)]
use crate::{frame::MAX_FRAME, ring::Ring, terminal_native::Engine};
use std::io;
/// A byte budget, not a row count: about 10,000 typical 200-column ASCII rows.
/// Ghostty's page storage includes cell capacity and sparse style/grapheme data.
const SCROLLBACK_BYTES: usize = 17 * 1024 * 1024;
#[derive(Default)]
struct Observer {
    complete: bool,
}
impl vte::Perform for Observer {
    fn print(&mut self, _: char) {
        self.complete = true;
    }
    fn execute(&mut self, byte: u8) {
        if matches!(byte, 0x18 | 0x1a) {
            self.complete = true;
        }
    }
    fn csi_dispatch(&mut self, _: &vte::Params, _: &[u8], _: bool, _: char) {
        self.complete = true;
    }
    fn esc_dispatch(&mut self, _: &[u8], _: bool, _: u8) {
        self.complete = true;
    }
    fn osc_dispatch(&mut self, _: &[&[u8]], _: bool) {
        self.complete = true;
    }
    fn unhook(&mut self) {
        self.complete = true;
    }
}
// Geometry changes and lost state are separate recovery certificates; neither
// permits raw reconstruction merely because the ring still has origin bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Recovery {
    Exact,
    GeometryChanged,
    Approximate,
}
pub struct Terminal {
    engine: Engine,
    observer: Observer,
    parser: vte::Parser,
    pending: Vec<u8>,
    carry_overflow: bool,
    dimensions: (u16, u16),
    // Replaying raw output at a different historical geometry is not exact.
    recovery: Recovery,
    recovery_pending: bool,
}
impl Terminal {
    pub fn new(cols: u16, rows: u16) -> io::Result<Self> {
        Ok(Self {
            engine: Engine::new(cols, rows, SCROLLBACK_BYTES)?,
            observer: Observer::default(),
            parser: vte::Parser::new(),
            pending: Vec::with_capacity(4096),
            carry_overflow: false,
            dimensions: (cols, rows),
            recovery: Recovery::Exact,
            recovery_pending: false,
        })
    }
    pub fn process(&mut self, bytes: &[u8]) {
        // A persistent allocation refusal must not stop PTY/ring progress.
        // Retry fresh ownership on later output; until then, touch no handle.
        if self.recovery_pending && self.recover(None).is_err() {
            return;
        }
        self.engine.process(bytes);
        for &byte in bytes {
            // Only ESC can start a sequence among ground-state ASCII/C0.
            // LF/CR/TAB and charset shifts are already handled by Ghostty;
            // feeding them to the carry parser adds work to output floods.
            // Inside a pending sequence, still parse C0 execution/cancellation.
            if byte != 0x1b && byte < 0x80 && self.pending.is_empty() {
                continue;
            }
            let string = self
                .pending
                .get(1)
                .is_some_and(|start| matches!(start, b']' | b'P' | b'_' | b'^' | b'X'));
            if byte == 0x1b && !string {
                self.pending.clear();
                self.carry_overflow = false;
            }
            if !self.pending.is_empty() || byte == 0x1b || byte >= 0xc0 {
                if self.pending.len() < MAX_FRAME - 9 {
                    self.pending.push(byte);
                } else {
                    self.carry_overflow = true;
                }
            }
            self.observer.complete = false;
            self.parser.advance(&mut self.observer, &[byte]);
            if self.observer.complete {
                self.pending.clear();
                self.carry_overflow = false;
                if byte == 0x1b {
                    self.pending.push(byte);
                }
            }
            // C0 actions execute within CSI. Carry only its unfinished syntax,
            // otherwise the snapshot continuation executes those actions twice.
            if !self.observer.complete
                && byte < 0x20
                && byte != 0x1b
                && self.pending.last() == Some(&byte)
            {
                self.pending.pop();
            }
        }
    }
    pub fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.resize_with_ring(cols, rows, None)
    }
    /// Recover at the last good size after any native resize error. Exact raw
    /// reconstruction requires origin coverage and unchanged geometry; byte
    /// coverage alone cannot reproduce earlier resize/reflow effects.
    pub fn resize_with_ring(
        &mut self,
        cols: u16,
        rows: u16,
        ring: Option<&Ring>,
    ) -> io::Result<()> {
        if let Err(error) = self.engine.resize(cols, rows) {
            self.recovery_pending = true;
            self.recover(ring)?;
            return Err(error);
        }
        if self.dimensions != (cols, rows) && self.recovery != Recovery::Approximate {
            self.recovery = Recovery::GeometryChanged;
        }
        self.dimensions = (cols, rows);
        Ok(())
    }
    fn recover(&mut self, ring: Option<&Ring>) -> io::Result<()> {
        let mut restored = Self::new(self.dimensions.0, self.dimensions.1)?;
        let complete = ring.filter(|ring| ring.start() == 0 && self.recovery == Recovery::Exact);
        if let Some(ring) = complete {
            // Borrow both deque fragments: recovery after allocation refusal
            // must not allocate an additional full-ring replay buffer.
            let (first, second) = ring
                .origin_slices()
                .ok_or_else(|| io::Error::other("recovery ring coverage changed"))?;
            restored.process(first);
            restored.process(second);
        } else {
            restored.process(b"\x1bc");
            restored.recovery = Recovery::Approximate;
        }
        *self = restored;
        Ok(())
    }
    /// A clean or still-pending rebuild cannot certify faithful state. Keep
    /// this provenance across peer replacement and further output/resizes.
    pub fn requires_approximation(&self) -> bool {
        self.recovery == Recovery::Approximate || self.recovery_pending
    }
    /// Bounded visible fallback; fidelity gaps and clipping are explicitly
    /// announced by the negotiated frame, never substituted for a faithful VT.
    #[must_use]
    pub fn approximate_snapshot(&self) -> Vec<u8> {
        let budget = MAX_FRAME - 10;
        // Preserve unfinished syntax only when the entire carry and a useful
        // repaint fit. Never trim a control string or UTF-8 scalar in half.
        let carry = if !self.carry_overflow && self.pending.len() <= budget - 256 {
            self.pending.as_slice()
        } else {
            &[]
        };
        let mut out = vec![0; budget - carry.len()];
        let len = self.engine.approximate_snapshot(&mut out);
        out.truncate(len);
        if out.is_empty() {
            // Allocation succeeded and the engine is live. This defensive
            // fallback still gives a valid, explicitly approximate reset.
            out.extend_from_slice(b"\x1bc");
        }
        out.extend_from_slice(carry);
        out
    }
    pub fn snapshot(&self) -> io::Result<Vec<u8>> {
        if self.requires_approximation() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "terminal state was recovered approximately after a resize error",
            ));
        }
        if self.carry_overflow {
            return Err(io::Error::other(
                "unfinished VT sequence exceeds frozen frame limit",
            ));
        }
        let mut out = vec![0; MAX_FRAME - 9 - self.pending.len()];
        // Retry only when the bounded frame cannot fit the tail. The visible
        // screens are mandatory; Error(1) remains the session's response if
        // even those exceed the frozen 1 MiB frame limit.
        let mut tail = 256;
        loop {
            if let Some(len) = self.engine.try_snapshot(&mut out, tail)? {
                out.truncate(len);
                out.extend_from_slice(&self.pending);
                return Ok(out);
            }
            if tail == 0 {
                break;
            }
            // Avoid repeatedly walking an oversized screen. A geometric tail
            // reduction bounds failed serialization to nine attempts.
            tail /= 2;
        }
        Err(io::Error::other(
            "screen repaint exceeds frozen frame limit",
        ))
    }
}
#[cfg(test)]
#[path = "../tests/unit/terminal.rs"]
mod checks;
#[cfg(test)]
#[path = "../tests/unit/terminal_budgets.rs"]
mod measurements;

#[cfg(test)]
#[path = "../tests/unit/snapshot_fidelity.rs"]
mod fidelity;
