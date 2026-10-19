//! Per-session streaming control-string limits for a shared PTY host [D270].
//!
//! A discarded string remains a string until its terminator; its bytes must
//! never become printable text or interpreted control commands in the VT.
#![forbid(unsafe_code)]

pub(super) const STRING_BYTES: usize = 4096;

#[derive(Clone, Copy, Default)]
enum State {
    #[default]
    Ground,
    Escape,
    EscapeIntermediate,
    Csi,
    String {
        osc: bool,
        bytes: usize,
    },
    StringEscape {
        osc: bool,
    },
    Discard {
        osc: bool,
    },
    DiscardEscape {
        osc: bool,
    },
}

pub(super) enum Action {
    Keep,
    Drop,
    Restart,
    Start(u8),
}

#[derive(Default)]
pub(super) struct Limits {
    state: State,
}
impl Limits {
    pub(super) fn carry_suffix(&self) -> &'static [u8] {
        if matches!(self.state, State::DiscardEscape { .. }) {
            b"\x1b"
        } else {
            b""
        }
    }
    // Stop forwarding excess payload without cancelling the native parser.
    // Its bounded prefix remains resumable through the existing snapshot carry.
    // Terminators and a new ESC command still reach both parser layers.
    // Keep the transition table together so overflow/restart cases are audited
    // against every state rather than split across independent helpers.
    #[allow(clippy::too_many_lines)]
    pub(super) fn byte(&mut self, byte: u8) -> Action {
        use Action::{Drop, Keep, Restart};
        use State::{
            Csi, Discard, DiscardEscape, Escape, EscapeIntermediate, Ground, String, StringEscape,
        };
        // C1 controls are interpreted outside UTF-8 ground state. OSC treats
        // high bytes as payload, so it remains excluded. Canonical seven-bit
        // syntax also preserves the same boundary in the carry observer.
        if !matches!(
            self.state,
            Ground | String { osc: true, .. } | Discard { osc: true }
        ) {
            let introducer = match byte {
                0x90 => Some(b'P'),
                0x98 => Some(b'X'),
                0x9d => Some(b']'),
                0x9e => Some(b'^'),
                0x9f => Some(b'_'),
                _ => None,
            };
            if let Some(introducer) = introducer {
                self.state = String {
                    osc: introducer == b']',
                    bytes: 2,
                };
                return Action::Start(introducer);
            }
            if byte == 0x9b {
                self.state = Csi;
                return Action::Start(b'[');
            }
            if matches!(byte, 0x80..=0x8f | 0x91..=0x97 | 0x99 | 0x9a | 0x9c) {
                self.state = Ground;
                return Action::Start(byte - 0x40);
            }
        }
        let (next, output) = match self.state {
            Ground => (if byte == 0x1b { Escape } else { Ground }, Keep),
            Escape => (
                match byte {
                    b']' | b'P' | b'_' | b'^' | b'X' => String {
                        osc: byte == b']',
                        bytes: 2,
                    },
                    b'[' | 0x9b => Csi,
                    0x1b | 0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f | 0xa0..=0xff => Escape,
                    0x20..=0x2f => EscapeIntermediate,
                    0x90 | 0x98 | 0x9d | 0x9e | 0x9f => String {
                        osc: byte == 0x9d,
                        bytes: 1,
                    },
                    _ => Ground,
                },
                Keep,
            ),
            EscapeIntermediate | Csi => {
                let next = match byte {
                    0x1b => Escape,
                    0x18 | 0x1a | 0x80..=0x8f | 0x91..=0x97 | 0x99 | 0x9a | 0x9c => Ground,
                    0x90 | 0x98 | 0x9d | 0x9e | 0x9f => String {
                        osc: byte == 0x9d,
                        bytes: 1,
                    },
                    0x9b => Csi,
                    0x30..=0x7e if matches!(self.state, EscapeIntermediate) => Ground,
                    0x40..=0x7e if matches!(self.state, Csi) => Ground,
                    _ => self.state,
                };
                (next, Keep)
            }
            String { osc, bytes } => {
                if matches!(byte, 0x18 | 0x1a) || (osc && byte == 7) {
                    (Ground, Keep)
                } else if bytes == STRING_BYTES {
                    (
                        if byte == 0x1b {
                            DiscardEscape { osc }
                        } else {
                            Discard { osc }
                        },
                        Drop,
                    )
                } else {
                    (
                        if byte == 0x1b {
                            StringEscape { osc }
                        } else {
                            String {
                                osc,
                                bytes: bytes + 1,
                            }
                        },
                        Keep,
                    )
                }
            }
            StringEscape { osc } => {
                if byte == b'\\' || matches!(byte, 0x18 | 0x1a) || (osc && byte == 7) {
                    (Ground, Keep)
                } else {
                    // ESC abandons a string and begins a new escape sequence.
                    // Reprocess this byte as the character following ESC.
                    self.state = Escape;
                    let result = self.byte(byte);
                    return result;
                }
            }
            Discard { osc } => (
                if byte == 0x1b {
                    DiscardEscape { osc }
                } else if matches!(byte, 0x18 | 0x1a) || (osc && byte == 7) {
                    Ground
                } else {
                    Discard { osc }
                },
                if matches!(byte, 0x18 | 0x1a) || (osc && byte == 7) {
                    Keep
                } else {
                    Drop
                },
            ),
            DiscardEscape { osc } => {
                if byte == b'\\' || matches!(byte, 0x18 | 0x1a) || (osc && byte == 7) {
                    (Ground, if byte == b'\\' { Restart } else { Keep })
                } else if byte == 0x1b {
                    (DiscardEscape { osc }, Drop)
                } else {
                    // The dropped ESC must be restored before its following
                    // byte, whether ending the string or starting a command.
                    self.state = Escape;
                    let action = self.byte(byte);
                    return if let Action::Start(_) = action {
                        action
                    } else {
                        Restart
                    };
                }
            }
        };
        self.state = next;
        output
    }
}

#[cfg(test)]
mod tests {
    //! Fragmentation, cancellation, restart and finite payloads keep parser boundaries.
    use super::*;
    fn filter(limits: &mut Limits, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for &byte in input {
            match limits.byte(byte) {
                Action::Keep => out.push(byte),
                Action::Drop => {}
                Action::Restart => out.extend_from_slice(&[0x1b, byte]),
                Action::Start(introducer) => out.extend_from_slice(&[0x1b, introducer]),
            }
        }
        out
    }
    #[test]
    fn fragmented_overflow_stays_discarded_until_a_real_terminator() {
        for introducer in *b"]P_^X" {
            let mut limits = Limits::default();
            let mut out = filter(&mut limits, &[0x1b, introducer]);
            for _ in 0..8192 {
                out.extend(filter(&mut limits, b"xx"));
            }
            assert_eq!(out.len(), STRING_BYTES);
            assert_eq!(filter(&mut limits, b"\x1b"), [] as [u8; 0]);
            assert_eq!(filter(&mut limits, b"\\AFTER"), b"\x1b\\AFTER");
        }
    }
    #[test]
    fn escape_after_discard_restarts_without_losing_the_next_command() {
        let mut limits = Limits::default();
        filter(&mut limits, b"\x1b]0;");
        filter(&mut limits, &[b'x'; STRING_BYTES]);
        assert_eq!(filter(&mut limits, b"\x1b[31mRED"), b"\x1b[31mRED");
    }
    #[test]
    fn finite_sequences_are_identical_for_every_fragment_boundary() {
        let bytes = b"plain\x1b]0;title\x07\x1bP1;2qdata\x1b\\\x1b_ignored\x1b\\\x1b[31mred";
        for boundary in 0..=bytes.len() {
            let mut limits = Limits::default();
            let mut out = filter(&mut limits, &bytes[..boundary]);
            out.extend(filter(&mut limits, &bytes[boundary..]));
            assert_eq!(out, bytes);
        }
    }
}

#[cfg(test)]
mod defensive_tests {
    //! C0 execution inside ESC must not let the introducer bypass string limits.
    use super::*;
    #[test]
    fn executed_c0_between_escape_and_introducer_keeps_the_bound() {
        let mut limits = Limits::default();
        for &byte in b"\x1b\n]0;" {
            limits.byte(byte);
        }
        let retained = (0..STRING_BYTES * 4)
            .filter(|_| matches!(limits.byte(b'x'), Action::Keep))
            .count();
        assert!(
            retained <= STRING_BYTES,
            "OSC payload bypassed cap through ESC/LF"
        );
    }
}

#[cfg(test)]
mod c1_tests {
    //! C1 introducers in non-ground states must also enter bounded canonical syntax.
    use super::*;
    #[test]
    fn c1_string_inside_csi_has_a_seven_bit_replay_boundary() {
        let mut limits = Limits::default();
        limits.byte(0x1b);
        limits.byte(b'[');
        // Canonical syntax lets the carry observer preserve the same pending
        // string as the native parser, whose CSI accepts this raw C1 control.
        let action = limits.byte(0x9d);
        assert!(
            !matches!(action, Action::Keep),
            "raw C1 bypasses the carry observer"
        );
    }
}
