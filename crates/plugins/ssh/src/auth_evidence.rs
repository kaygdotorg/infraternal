//! Reduces local SSH authentication receipts to method metadata without retaining diagnostics or inferring a provider (#190).

const PREFIX: &[u8] = b"Authenticated to ";
const USING: &[u8] = b" using \"";

#[derive(Clone, Copy)]
enum Phase {
    Prefix(usize),
    Using(usize),
    Method { length: usize, none: bool },
    Dot(bool),
    End(bool),
    Invalid,
}

/// A constant-size streaming recognizer. It stores only literal-match positions
/// and a public method bit, never a hostname, banner, credential or raw line.
pub struct MethodReceipt {
    phase: Phase,
    network: Option<bool>,
}
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
                if let Phase::End(none) = self.phase {
                    self.network = Some(none);
                }
                self.phase = Phase::Prefix(0);
                continue;
            }
            self.phase = match self.phase {
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
