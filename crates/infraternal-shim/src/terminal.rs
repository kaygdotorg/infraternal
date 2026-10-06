//! Ghostty VT state with bounded snapshot and unfinished-parser carry [13][94].
#![forbid(unsafe_code)]
use crate::{frame::MAX_FRAME, terminal_native::Engine};
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
pub struct Terminal {
    engine: Engine,
    observer: Observer,
    parser: vte::Parser,
    pending: Vec<u8>,
    carry_overflow: bool,
}
impl Terminal {
    pub fn new(cols: u16, rows: u16) -> io::Result<Self> {
        Ok(Self {
            engine: Engine::new(cols, rows, SCROLLBACK_BYTES)?,
            observer: Observer::default(),
            parser: vte::Parser::new(),
            pending: Vec::with_capacity(4096),
            carry_overflow: false,
        })
    }
    pub fn process(&mut self, bytes: &[u8]) {
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
        self.engine.resize(cols, rows)
    }
    pub fn snapshot(&self) -> io::Result<Vec<u8>> {
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
            if let Some(len) = self.engine.snapshot(&mut out, tail) {
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
