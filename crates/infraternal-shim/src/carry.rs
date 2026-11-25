//! A byte-exact shadow of the terminal engine's parser state, used to find the
//! unfinished escape sequence at the end of the output (the snapshot "carry",
//! D13, D94, #561).
//!
//! A snapshot repaints the screen and then appends the bytes of whatever
//! sequence the program had not finished, so a viewer's engine ends up in the
//! same parser state as ours and the live stream continues cleanly. That only
//! works when the shadow and the engine agree on *when a sequence ends*. They
//! used to disagree: the shadow was a general-purpose VT parser that treats
//! C1 bytes (0x80 to 0x9F) as inert inside a sequence, while the engine obeys
//! them there, and the two decode broken UTF-8 differently. A carry that the
//! engine had already finished was replayed, and its text printed twice.
//!
//! This module follows the engine's own rules instead, and nothing else:
//!
//! - **Ground** decodes UTF-8 with the same DFA as the engine (a Hoehrmann
//!   decoder that replaces an ill-formed sequence and then looks at the
//!   offending byte again). C1 bytes that reach ground, raw or decoded, do
//!   nothing. Only ESC leaves ground.
//! - **Everywhere else** the engine's transition table applies: CAN, SUB and
//!   the C1 range jump to ground, CSI, DCS, OSC or a string, with these
//!   exceptions. OSC takes every byte from 0x20 up as payload, and so do DCS
//!   passthrough and DCS ignore for 0x80 and up, because UTF-8 text can carry
//!   those bytes.
//!
//! The shadow never produces output. It only answers "is the engine at
//! ground now", and "is it inside a string" (strings keep their prefix when
//! another ESC arrives, so the terminator can still dispatch them).
//!
//! The UTF-8 tables are Bjoern Hoehrmann's DFA decoder (MIT licensed,
//! <http://bjoern.hoehrmann.de/utf-8/decoder/dfa>), the same tables the engine
//! uses, so the two cannot drift apart on ill-formed input.
//!
//! The mirror is kept by hand, so it names the engine release it was checked
//! against in `MIRRORED_ENGINE`. A unit check fails when `scripts/build-vt`
//! pins a different release: whoever moves the engine diffs its
//! `src/terminal/Parser.zig`, `parse_table.zig`, `UTF8Decoder.zig`,
//! `stream.zig` and `src/simd/vt.*` against the previous release, updates
//! this module to match, and only then moves the constant. For 1.0.1 to
//! 1.0.2 (#575, J1197) all of those files are byte-identical, so the tables
//! and rules below did not change.

/// The libghostty-vt release whose parser this module mirrors; see the module
/// docs for what to re-check before changing it. Only the unit checks read it.
#[cfg(test)]
pub(crate) const MIRRORED_ENGINE: &str = "1.0.2";

/// Parser states of the engine's VT500-style machine, one per table state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Ground,
    Escape,
    EscapeIntermediate,
    CsiEntry,
    CsiParam,
    CsiIntermediate,
    CsiIgnore,
    DcsEntry,
    DcsParam,
    DcsIntermediate,
    DcsIgnore,
    DcsPassthrough,
    Osc,
    /// SOS, PM and APC strings share one state in the engine.
    SosPmApc,
}

/// Character classes of the UTF-8 DFA, indexed by byte.
#[rustfmt::skip]
const CHAR_CLASSES: [u8; 256] = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8,
];

/// DFA transitions: `TRANSITIONS[state + class]` is the next state.
#[rustfmt::skip]
const TRANSITIONS: [u8; 108] = [
     0,12,24,36,60,96,84,12,12,12,48,72, 12,12,12,12,12,12,12,12,12,12,12,12,
    12, 0,12,12,12,12,12, 0,12, 0,12,12, 12,24,12,12,12,12,12,24,12,24,12,12,
    12,12,12,12,12,12,12,24,12,12,12,12, 12,24,12,12,12,12,12,12,12,24,12,12,
    12,12,12,12,12,12,12,36,12,36,12,12, 12,36,12,12,12,12,12,36,12,36,12,12,
    12,36,12,12,12,12,12,12,12,12,12,12,
];

/// DFA state meaning "between characters".
const ACCEPT: u8 = 0;
/// DFA state meaning "this byte is ill-formed here".
const REJECT: u8 = 12;

/// Shadow of the engine's parser; see the module docs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Carry {
    /// Where the engine's escape-sequence machine is.
    state: State,
    /// The UTF-8 DFA state; only ever non-zero while `state` is `Ground`.
    utf8: u8,
}

impl Default for Carry {
    fn default() -> Self {
        Self {
            state: State::Ground,
            utf8: ACCEPT,
        }
    }
}

impl Carry {
    /// True when the engine holds no unfinished sequence and no half-decoded
    /// UTF-8 character, so nothing needs carrying.
    pub(crate) fn at_ground(self) -> bool {
        self.state == State::Ground && self.utf8 == ACCEPT
    }

    /// True when the engine is inside an escape sequence (not merely half
    /// way through a UTF-8 character). A C1 introducer starts a new sequence
    /// only here.
    pub(crate) fn in_sequence(self) -> bool {
        self.state != State::Ground
    }

    /// True when the engine is inside a control string (OSC, DCS, SOS, PM or
    /// APC). A later ESC or C1 introducer does not discard the carry then: the
    /// string's payload is still needed when its terminator dispatches it.
    pub(crate) fn in_string(self) -> bool {
        matches!(
            self.state,
            State::Osc
                | State::SosPmApc
                | State::DcsEntry
                | State::DcsParam
                | State::DcsIntermediate
                | State::DcsIgnore
                | State::DcsPassthrough
        )
    }

    /// True when the engine treats a C0 byte inside the current sequence as
    /// payload to keep (DCS data, APC strings). Anywhere else a C0 byte is
    /// executed or ignored on the spot, so the carry must not repeat it.
    pub(crate) fn keeps_c0(self) -> bool {
        matches!(self.state, State::DcsPassthrough | State::SosPmApc)
    }

    /// Follows the engine through one more output byte.
    ///
    /// Returns true when the byte cut short a half-decoded UTF-8 character
    /// and was then read again as the start of something new. The engine has
    /// already printed a replacement character for the abandoned bytes, so a
    /// carry that still held them would print it a second time: the caller
    /// must drop everything before this byte.
    pub(crate) fn advance(&mut self, byte: u8) -> bool {
        if self.state == State::Ground {
            self.ground(byte)
        } else {
            self.state = Self::next(self.state, byte);
            false
        }
    }

    /// Ground state: UTF-8 decoding, where only a decoded ESC changes state.
    /// Returns true when an ill-formed character was replaced and `byte` read again.
    fn ground(&mut self, byte: u8) -> bool {
        // An ill-formed sequence is replaced and the byte is looked at again,
        // which can only repeat once: the DFA is back at its start state.
        let mut reread = false;
        loop {
            let class = CHAR_CLASSES[usize::from(byte)];
            let before = self.utf8;
            let next = TRANSITIONS[usize::from(before) + usize::from(class)];
            if next == REJECT {
                self.utf8 = ACCEPT;
                if before == ACCEPT {
                    // The first byte of a character was bad and is consumed.
                    return reread;
                }
                reread = true;
                continue;
            }
            self.utf8 = next;
            if next == ACCEPT && byte == 0x1b {
                self.state = State::Escape;
            }
            return reread;
        }
    }

    /// The engine's transition table outside ground: the next state for
    /// `byte` in `state`.
    fn next(state: State, byte: u8) -> State {
        use State::{
            CsiEntry, CsiIgnore, CsiIntermediate, CsiParam, DcsEntry, DcsIgnore, DcsIntermediate,
            DcsParam, DcsPassthrough, Escape, EscapeIntermediate, Ground, Osc, SosPmApc,
        };
        // Strings carry text, so the high bytes (and, for OSC, everything from
        // 0x20) are payload there and override the "anywhere" jumps below.
        match (state, byte) {
            (Osc, 0x07) => return Ground,
            (Osc, 0x20..=0xff) | (DcsIgnore | DcsPassthrough, 0x80..=0xff) => return state,
            _ => {}
        }
        // "Anywhere" transitions.
        match byte {
            0x18 | 0x1a | 0x80..=0x8f | 0x91..=0x97 | 0x99 | 0x9a | 0x9c => return Ground,
            0x1b => return Escape,
            0x98 | 0x9e | 0x9f => return SosPmApc,
            0x9b => return CsiEntry,
            0x90 => return DcsEntry,
            0x9d => return Osc,
            _ => {}
        }
        match (state, byte) {
            (Escape, 0x30..=0x4f | 0x51..=0x57 | 0x59 | 0x5a | 0x5c | 0x60..=0x7e)
            | (EscapeIntermediate, 0x30..=0x7e)
            | (CsiEntry | CsiParam | CsiIntermediate | CsiIgnore, 0x40..=0x7e) => Ground,
            (Escape, 0x20..=0x2f) => EscapeIntermediate,
            (Escape, 0x50) => DcsEntry,
            (Escape, 0x58 | 0x5e | 0x5f) => SosPmApc,
            (Escape, 0x5b) => CsiEntry,
            (Escape, 0x5d) => Osc,
            (CsiEntry, 0x3a) | (CsiParam, 0x3c..=0x3f) | (CsiIntermediate, 0x30..=0x3f) => {
                CsiIgnore
            }
            (CsiEntry | CsiParam, 0x20..=0x2f) => CsiIntermediate,
            (CsiEntry, 0x30..=0x39 | 0x3b | 0x3c..=0x3f) => CsiParam,
            (DcsEntry | DcsParam, 0x20..=0x2f) => DcsIntermediate,
            (DcsEntry, 0x3a) | (DcsIntermediate, 0x30..=0x3f) | (DcsParam, 0x3a | 0x3c..=0x3f) => {
                DcsIgnore
            }
            (DcsEntry, 0x30..=0x39 | 0x3b | 0x3c..=0x3f) => DcsParam,
            (DcsEntry | DcsIntermediate | DcsParam, 0x40..=0x7e) => DcsPassthrough,
            _ => state,
        }
    }
}

/// Unit checks for the carry shadow, one per engine rule it copies.
#[cfg(test)]
#[path = "../tests/unit/carry.rs"]
mod checks;
