//! Reduces local SSH authentication receipts to method metadata without retaining diagnostics or inferring a provider (#190).
//!
//! The local OpenSSH client prints a line such as
//! `Authenticated to <host> using "<method>".` in its debug output. This module
//! recognizes that one line byte by byte, in constant memory, and keeps a single
//! bit: whether the method was `none` (the network admitted us without a key or
//! password). Everything else on the line (host name, banner text, process id)
//! is matched and then forgotten. Any deviation from the exact line shape marks
//! the line invalid, so partial or spoofed text never counts as evidence.
//!
//! The result is only a hint. Whether the SSH socket was really admitted is
//! decided elsewhere; this bit never grants access.

/// Literal start of the receipt line.
const PREFIX: &[u8] = b"Authenticated to ";
/// Debug location tag of the one trusted source line (final result of the user-auth exchange).
/// A line from any other source location, such as the banner handler, is ignored.
const TAG: &[u8] = b"sshconnect2.c:ssh_userauth2():";
/// Literal between the host name and the method name, ending at the opening quote.
const USING: &[u8] = b" using \"";

/// Position of the recognizer inside one line. The `bool` carried by the late
/// states is "the method spelled exactly `none`".
#[derive(Clone, Copy)]
enum Phase {
    /// Matching `PREFIX`; the number is how many bytes matched so far.
    Prefix(usize),
    /// Matching the debug location tag.
    Tag(usize),
    /// Reading the decimal source line number (at most 10 digits).
    Location(usize),
    /// Expecting `(` of the `(pid=...)` context.
    Open,
    /// Reading the printable context text up to `)` (at most 128 bytes).
    Context(usize),
    /// Expecting `:` after the context.
    Colon,
    /// Expecting the single space before the receipt text.
    Space,
    /// Saw `\r` after a complete receipt, waiting for `\n`.
    CrEnd(bool),
    /// Scanning the host name for `USING`; the number is how many bytes of it matched.
    Using(usize),
    /// Reading the method name (lowercase letters and `-`, at most 64 bytes).
    Method { length: usize, none: bool },
    /// Expecting the closing `.` after the method's closing quote.
    Dot(bool),
    /// Complete receipt; only a line end may follow.
    End(bool),
    /// The line broke the expected shape; ignored until the next `\n`.
    Invalid,
}

/// A constant-size streaming recognizer. It stores only literal-match positions
/// and a public method bit, never a hostname, banner, credential or raw line.
pub struct MethodReceipt {
    /// Where the current line stands.
    phase: Phase,
    /// `Some(true)` when the last complete receipt used method `none`,
    /// `Some(false)` for any other method, `None` if no complete receipt was seen.
    network: Option<bool>,
}
/// Starts at the beginning of a line with no receipt seen.
impl Default for MethodReceipt {
    fn default() -> Self {
        Self {
            phase: Phase::Prefix(0),
            network: None,
        }
    }
}
impl MethodReceipt {
    /// Feed arbitrary diagnostic chunk boundaries, keeping the last full receipt.
    /// Earlier pre-authentication banners cannot supersede the later local result.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                if let Phase::End(none) | Phase::CrEnd(none) = self.phase {
                    self.network = Some(none);
                }
                self.phase = Phase::Prefix(0);
                continue;
            }
            self.phase = match self.phase {
                Phase::Prefix(0) if byte == TAG[0] => Phase::Tag(1),
                Phase::Tag(index) if TAG.get(index) == Some(&byte) => {
                    if index + 1 == TAG.len() {
                        Phase::Location(0)
                    } else {
                        Phase::Tag(index + 1)
                    }
                }
                Phase::Location(length) if length < 10 && byte.is_ascii_digit() => {
                    Phase::Location(length + 1)
                }
                Phase::Location(length) if length > 0 && byte == b' ' => Phase::Open,
                Phase::Open if byte == b'(' => Phase::Context(0),
                Phase::Context(_) if byte == b')' => Phase::Colon,
                Phase::Context(length)
                    if length < 128 && (byte.is_ascii_graphic() || byte == b' ') =>
                {
                    Phase::Context(length + 1)
                }
                Phase::Colon if byte == b':' => Phase::Space,
                Phase::Space if byte == b' ' => Phase::Prefix(0),
                Phase::End(none) if byte == b'\r' => Phase::CrEnd(none),
                Phase::Prefix(index) if PREFIX.get(index) == Some(&byte) => {
                    if index + 1 == PREFIX.len() {
                        Phase::Using(0)
                    } else {
                        Phase::Prefix(index + 1)
                    }
                }
                Phase::Using(index) => {
                    if USING.get(index) == Some(&byte) {
                        if index + 1 == USING.len() {
                            Phase::Method {
                                length: 0,
                                none: true,
                            }
                        } else {
                            Phase::Using(index + 1)
                        }
                    } else {
                        Phase::Using(usize::from(byte == USING[0]))
                    }
                }
                Phase::Method { length, none } if byte == b'"' && length > 0 => {
                    Phase::Dot(none && length == 4)
                }
                Phase::Method { length, none }
                    if length < 64 && (byte.is_ascii_lowercase() || byte == b'-') =>
                {
                    Phase::Method {
                        length: length + 1,
                        none: none && b"none".get(length) == Some(&byte),
                    }
                }
                Phase::Dot(none) if byte == b'.' => Phase::End(none),
                _ => Phase::Invalid,
            };
        }
    }

    /// What the last complete receipt said: `Some(true)` if the method was
    /// `none` (network-level admission), `Some(false)` for any other method,
    /// `None` when no valid receipt has been seen yet.
    ///
    /// Only a method hint; SSH socket admission remains the authentication proof.
    #[must_use]
    pub fn network(&self) -> Option<bool> {
        self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_is_identical_at_every_chunk_boundary() {
        let line = b"Authenticated to fixture ([127.0.0.1]:22) using \"none\".\n";
        for split in 0..=line.len() {
            let mut receipt = MethodReceipt::default();
            receipt.feed(&line[..split]);
            receipt.feed(&line[split..]);
            assert_eq!(receipt.network(), Some(true));
        }
        let mut receipt = MethodReceipt::default();
        for byte in line {
            receipt.feed(&[*byte]);
        }
        assert_eq!(receipt.network(), Some(true));
    }

    #[test]
    fn selected_local_authentication_diagnostics_keep_method_at_every_boundary() {
        let line = b"sshconnect2.c:ssh_userauth2():458 (pid=123): Authenticated to fixture using \"none\".\r\n";
        for split in 0..=line.len() {
            let mut receipt = MethodReceipt::default();
            receipt.feed(&line[..split]);
            receipt.feed(&line[split..]);
            assert_eq!(receipt.network(), Some(true));
        }
        let mut receipt = MethodReceipt::default();
        receipt.feed(b"sshconnect2.c:input_userauth_banner():1 (pid=123): Authenticated to fixture using \"none\".\r\n");
        assert_eq!(receipt.network(), None);
    }

    #[test]
    fn later_local_key_receipt_supersedes_an_earlier_banner() {
        let mut receipt = MethodReceipt::default();
        receipt.feed(b"Authenticated to banner using \"none\".\n");
        receipt.feed(b"Authenticated to fixture using \"publickey\".\n");
        assert_eq!(receipt.network(), Some(false));
        receipt.feed(b"unrelated diagnostic\n");
        assert_eq!(receipt.network(), Some(false));
    }

    #[test]
    fn partial_and_malformed_receipts_are_not_method_evidence() {
        for bytes in [
            b"Authenticated to fixture using \"none\".".as_slice(),
            b"prefix Authenticated to fixture using \"none\".\n",
            b"Authenticated to fixture using \"none\". extra\n",
            b"Authenticated to fixture using \"\".\n",
            b"Authenticated to fixture using \"none-extra\"\n",
        ] {
            let mut receipt = MethodReceipt::default();
            receipt.feed(bytes);
            assert_eq!(receipt.network(), None);
        }
    }
}
