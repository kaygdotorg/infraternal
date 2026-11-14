//! Reduce a terminal byte stream to the text it prints.
//!
//! Multiplexers redraw with escape sequences whose parameters and final bytes
//! are letters and digits; matching probe tokens against raw bytes would find
//! false hits. This strips CSI, OSC, DCS/SOS/PM/APC strings and two-byte
//! escapes, keeping printable bytes and newlines. It is a filter, not a
//! terminal emulator: it does not track the screen.
/// Parser states for printable text and terminal escape sequences.
#[derive(Clone, Copy, PartialEq)]
enum State {
    Ground,
    Esc,
    Csi,
    Str,
    StrEsc,
    Charset,
}

/// Incrementally remove terminal control sequences while retaining printable text.
pub struct Stripper {
    state: State,
}

impl Default for Stripper {
    fn default() -> Self {
        Self { state: State::Ground }
    }
}

impl Stripper {
    /// Consume a byte chunk and append its printable characters to `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) {
        for &b in input {
            self.state = match self.state {
                State::Ground => match b {
                    0x1b => State::Esc,
                    b'\n' => {
                        out.push(b'\n');
                        State::Ground
                    }
                    0x20..=0x7e | 0x80..=0xff => {
                        out.push(b);
                        State::Ground
                    }
                    _ => State::Ground,
                },
                State::Esc => match b {
                    b'[' => State::Csi,
                    b']' | b'P' | b'X' | b'^' | b'_' => State::Str,
                    b'(' | b')' | b'*' | b'+' | b'#' | b'%' => State::Charset,
                    _ => State::Ground,
                },
                State::Csi => {
                    if (0x40..=0x7e).contains(&b) {
                        State::Ground
                    } else {
                        State::Csi
                    }
                }
                State::Str => match b {
                    0x07 => State::Ground,
                    0x1b => State::StrEsc,
                    _ => State::Str,
                },
                State::StrEsc => {
                    if b == b'\\' {
                        State::Ground
                    } else {
                        State::Str
                    }
                }
                State::Charset => State::Ground,
            };
        }
    }
}
