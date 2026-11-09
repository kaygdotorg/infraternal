//! The frames between the server and the root relay of a root upgrade (D376, #399).
//!
//! During an upgrade the person's password starts one short-lived root process
//! on the host, the *relay*. The server then runs the same root install steps
//! an Add host over SSH runs, but through the relay instead of SSH. Each step
//! is a *channel*: the server opens it with a shell script, streams its stdin,
//! and reads its stdout, its stderr (the first [`MAX_STDERR`] bytes, which is
//! where install steps name a refusal) and its exit code back.
//!
//! The rootless infraternal agent carries these bytes between the server and
//! the relay and never reads them: it is a pipe. Only the server writes `Open`
//! frames, and the relay runs nothing else. The one frame the agent itself
//! writes is the first: [`Frame::Token`], the one-time token it typed to the
//! relay's terminal, which proves to the relay that this socket's listener is
//! the agent that started it (J415 B5).
//!
//! # Ending
//!
//! The server sends [`Frame::Rollback`] before any step: the script that
//! puts the host back as it was. The relay keeps it and runs it itself,
//! after stopping every step, whenever the upgrade ends without a
//! [`Frame::Commit`]: on [`Frame::Close`], end of input, a protocol error or
//! its lifetime (J415 R4). So a lost link never leaves a half-installed root
//! service behind, even though the server can no longer reach the host.
//!
//! # Wire format
//!
//! Every frame is `kind (1) ‖ channel (4, big endian) ‖ length (4, big endian) ‖ body`.
//! The [`Decoder`] refuses unknown kinds, oversized bodies and malformed fixed
//! bodies, so a broken peer ends the relay instead of confusing it.

/// Largest `Open` body: one install script. The biggest today, the check with
/// its recovery library, is well under this.
pub const MAX_SCRIPT: usize = 1 << 20;
/// Largest data body (`Stdin`, `Stdout`). Senders split larger writes.
pub const MAX_CHUNK: usize = 256 << 10;
/// Most stderr bytes the relay forwards per channel. The server keeps no more
/// than this of an SSH command's stderr either.
pub const MAX_STDERR: usize = 8192;
/// Most channels open at once. Install steps run one at a time; the margin
/// covers a check that overlaps a cleanup.
pub const MAX_CHANNELS: usize = 8;
/// Bytes of a frame before its body.
const HEAD: usize = 9;

/// One frame of the relay protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// Server → relay: run this script as root under `/bin/sh -c`.
    Open { channel: u32, script: String },
    /// Server → relay: bytes for the script's stdin.
    Stdin { channel: u32, bytes: Vec<u8> },
    /// Server → relay: the script's stdin is finished.
    StdinEnd { channel: u32 },
    /// Server → relay: stop this script's process group now.
    Kill { channel: u32 },
    /// Relay → server: bytes the script wrote to stdout.
    Stdout { channel: u32, bytes: Vec<u8> },
    /// Relay → server: bytes the script wrote to stderr (bounded per channel).
    Stderr { channel: u32, bytes: Vec<u8> },
    /// Relay → server: the script ended. `code` is its exit code, or `None`
    /// when a signal ended it.
    Exit { channel: u32, code: Option<u8> },
    /// Relay → server: the relay is ready and will run scripts. Sent once,
    /// first; the server starts nothing before it.
    Ready,
    /// Server → relay: the upgrade is over; stop every script and exit.
    /// Without an earlier [`Frame::Commit`], the relay rolls back first.
    Close,
    /// Agent → relay, first and once: the 32-byte one-time token typed to the
    /// relay's terminal. The relay refuses a socket whose first frame isn't it.
    Token { bytes: [u8; 32] },
    /// Server → relay, before any `Open`: the rollback script, kept by the
    /// relay and run if the upgrade ends without `Commit`.
    Rollback { script: String },
    /// Server → relay: the install committed; a later end needs no rollback.
    Commit,
}

impl Frame {
    /// The kind byte on the wire.
    const fn kind(&self) -> u8 {
        match self {
            Self::Open { .. } => 1,
            Self::Stdin { .. } => 2,
            Self::StdinEnd { .. } => 3,
            Self::Kill { .. } => 4,
            Self::Stdout { .. } => 5,
            Self::Exit { .. } => 6,
            Self::Ready => 7,
            Self::Close => 8,
            Self::Stderr { .. } => 9,
            Self::Token { .. } => 10,
            Self::Rollback { .. } => 11,
            Self::Commit => 12,
        }
    }

    /// Append this frame's bytes to `out`.
    ///
    /// # Panics
    /// When a body is larger than the protocol allows; callers split data
    /// with [`MAX_CHUNK`] and scripts are fixed text far below [`MAX_SCRIPT`].
    pub fn encode(&self, out: &mut Vec<u8>) {
        // An exit's two body bytes live here so the borrow below outlives the match.
        let exit = match self {
            Self::Exit {
                code: Some(code), ..
            } => [1, *code],
            _ => [0, 0],
        };
        let (channel, body): (u32, &[u8]) = match self {
            Self::Open { channel, script } => (*channel, script.as_bytes()),
            Self::Rollback { script } => (0, script.as_bytes()),
            Self::Token { bytes } => (0, &bytes[..]),
            Self::Stdin { channel, bytes }
            | Self::Stdout { channel, bytes }
            | Self::Stderr { channel, bytes } => (*channel, bytes),
            Self::StdinEnd { channel } | Self::Kill { channel } => (*channel, &[]),
            Self::Exit { channel, .. } => (*channel, &exit[..]),
            Self::Ready | Self::Close | Self::Commit => (0, &[]),
        };
        assert!(
            body.len() <= limit(self.kind()),
            "relay frame body too large"
        );
        out.push(self.kind());
        out.extend_from_slice(&channel.to_be_bytes());
        out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(body);
    }
}

/// The largest body a frame of `kind` may carry.
const fn limit(kind: u8) -> usize {
    match kind {
        1 | 11 => MAX_SCRIPT,
        2 | 5 => MAX_CHUNK,
        9 => MAX_STDERR,
        6 => 2,
        10 => 32,
        _ => 0,
    }
}

/// Why a byte stream is not valid relay protocol. Any of these ends the relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// An unknown kind byte.
    Kind,
    /// A body longer than its kind allows, or a fixed body of the wrong size.
    Length,
    /// A script that is not UTF-8, or an exit body that is not well formed.
    Body,
}

/// Turns a byte stream into frames, holding at most one partial frame.
#[derive(Default)]
pub struct Decoder {
    buffer: Vec<u8>,
}

impl Decoder {
    /// Add bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// The next whole frame, `Ok(None)` when more bytes are needed.
    ///
    /// # Errors
    /// The stream is not valid relay protocol ([`Malformed`]); stop reading it.
    pub fn frame(&mut self) -> Result<Option<Frame>, Malformed> {
        if self.buffer.len() < HEAD {
            return Ok(None);
        }
        let kind = self.buffer[0];
        if !(1..=12).contains(&kind) {
            return Err(Malformed::Kind);
        }
        let channel = u32::from_be_bytes([
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
            self.buffer[4],
        ]);
        let length = u32::from_be_bytes([
            self.buffer[5],
            self.buffer[6],
            self.buffer[7],
            self.buffer[8],
        ]) as usize;
        if length > limit(kind) || (kind == 6 && length != 2) || (kind == 10 && length != 32) {
            return Err(Malformed::Length);
        }
        if self.buffer.len() < HEAD + length {
            return Ok(None);
        }
        let body: Vec<u8> = self.buffer.drain(..HEAD + length).skip(HEAD).collect();
        let frame = match kind {
            1 => Frame::Open {
                channel,
                script: String::from_utf8(body).map_err(|_| Malformed::Body)?,
            },
            2 => Frame::Stdin {
                channel,
                bytes: body,
            },
            3 => Frame::StdinEnd { channel },
            4 => Frame::Kill { channel },
            5 => Frame::Stdout {
                channel,
                bytes: body,
            },
            6 => Frame::Exit {
                channel,
                code: match body[..] {
                    [1, code] => Some(code),
                    [0, 0] => None,
                    _ => return Err(Malformed::Body),
                },
            },
            7 => Frame::Ready,
            8 => Frame::Close,
            9 => Frame::Stderr {
                channel,
                bytes: body,
            },
            10 => Frame::Token {
                bytes: body.try_into().map_err(|_| Malformed::Length)?,
            },
            11 => Frame::Rollback {
                script: String::from_utf8(body).map_err(|_| Malformed::Body)?,
            },
            _ => Frame::Commit,
        };
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    //! Frames survive the wire byte by byte, and bad streams are refused.
    use super::*;

    /// Every kind of frame decodes back to itself, even fed one byte at a time.
    #[test]
    fn frames_round_trip_through_split_reads() {
        let frames = [
            Frame::Ready,
            Frame::Open {
                channel: 1,
                script: "printf ok".into(),
            },
            Frame::Stdin {
                channel: 1,
                bytes: vec![0, 255, 10],
            },
            Frame::StdinEnd { channel: 1 },
            Frame::Stdout {
                channel: 1,
                bytes: b"ok".to_vec(),
            },
            Frame::Stderr {
                channel: 1,
                bytes: b"INFRATERNAL_REFUSED cache\n".to_vec(),
            },
            Frame::Exit {
                channel: 1,
                code: Some(71),
            },
            Frame::Exit {
                channel: 2,
                code: None,
            },
            Frame::Kill { channel: 3 },
            Frame::Token { bytes: [7; 32] },
            Frame::Rollback {
                script: "rollback".into(),
            },
            Frame::Commit,
            Frame::Close,
        ];
        let mut wire = Vec::new();
        for frame in &frames {
            frame.encode(&mut wire);
        }
        let mut decoder = Decoder::default();
        let mut seen = Vec::new();
        for byte in wire {
            decoder.push(&[byte]);
            while let Some(frame) = decoder.frame().unwrap() {
                seen.push(frame);
            }
        }
        assert_eq!(seen, frames);
    }

    /// Unknown kinds, oversized bodies, bad exits and non-UTF-8 scripts are
    /// refused before the body is even buffered in full.
    #[test]
    fn malformed_streams_are_refused() {
        let mut decoder = Decoder::default();
        decoder.push(&[0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decoder.frame(), Err(Malformed::Kind));

        let mut decoder = Decoder::default();
        let mut head = vec![2, 0, 0, 0, 1];
        head.extend_from_slice(&u32::try_from(MAX_CHUNK + 1).unwrap().to_be_bytes());
        decoder.push(&head);
        assert_eq!(decoder.frame(), Err(Malformed::Length));

        let mut decoder = Decoder::default();
        decoder.push(&[6, 0, 0, 0, 1, 0, 0, 0, 2, 2, 0]);
        assert_eq!(decoder.frame(), Err(Malformed::Body));

        let mut decoder = Decoder::default();
        decoder.push(&[7, 0, 0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(decoder.frame(), Err(Malformed::Length));

        let mut decoder = Decoder::default();
        decoder.push(&[1, 0, 0, 0, 1, 0, 0, 0, 1, 0xff]);
        assert_eq!(decoder.frame(), Err(Malformed::Body));

        // A token is exactly 32 bytes; a short one is refused.
        let mut decoder = Decoder::default();
        decoder.push(&[10, 0, 0, 0, 0, 0, 0, 0, 31]);
        assert_eq!(decoder.frame(), Err(Malformed::Length));

        let mut decoder = Decoder::default();
        decoder.push(&[13, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decoder.frame(), Err(Malformed::Kind));
    }
}
