//! Encodes and decodes the borrowed wire frames and stream mux used by legs A and B [11][12].
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

#[cfg(any(test, feature = "desktop"))]
pub mod desktop;
#[cfg(test)]
mod desktop_tests;
#[cfg(test)]
mod stream_tests;
#[cfg(test)]
mod tests;

/// Maximum length of a frame's type byte and body, as specified by wire §2.
pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;

/// `Close` code on a terminal stream meaning the session no longer exists on
/// its host: its shim is gone, or the account never had it. The answer is
/// final. A viewer must not attach to that session again, unlike every other
/// stream close, which a viewer may retry (wire §4, #158).
pub const CLOSE_SESSION_GONE: u16 = 4404;
/// The reason sent with [`CLOSE_SESSION_GONE`]; logs read it, people never do.
pub const SESSION_GONE_REASON: &str = "session ended";

const MAX_VARINT_BYTES: usize = 5;

/// A decoded frame borrows its variable-sized fields from the input buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// Negotiated desktop extension, owned by the desktop plugin.
    #[cfg(any(test, feature = "desktop"))]
    Desktop(desktop::Message<'a>),
    /// Connection greeting, sent by both sides on stream zero.
    Hello {
        /// Protocol version.
        version: u16,
        /// Negotiated feature capability bits.
        caps: u64,
        /// UTF-8 client description.
        client_info: &'a str,
    },
    /// Server response containing a new connection identity and resume window.
    Welcome {
        /// Stable connection identifier.
        connection_id: &'a [u8; 16],
        /// Opaque token used to resume the connection.
        resume_token: &'a [u8; 32],
        /// Resume window in seconds.
        resume_window_seconds: u32,
        /// Public authenticated-session incarnation, negotiated with Hello bit 4.
        session_incarnation: Option<&'a str>,
    },
    /// Client request to resume an existing connection.
    Resume {
        /// Connection identifier received in `Welcome`.
        connection_id: &'a [u8; 16],
        /// Resume token received in `Welcome`.
        resume_token: &'a [u8; 32],
    },
    /// Latency probe.
    Ping {
        /// Caller-chosen nonce.
        nonce: u64,
        /// Send timestamp in microseconds.
        sent_us: u64,
    },
    /// Response to a latency probe.
    Pong {
        /// Nonce copied from `Ping`.
        nonce: u64,
        /// Send timestamp copied from `Ping`.
        sent_us: u64,
    },
    /// Graceful protocol close.
    Close {
        /// Application-defined close code.
        code: u16,
        /// UTF-8 close reason.
        reason: &'a str,
    },
    /// Bytes entered by the client, beginning at `in_seq`.
    Input {
        /// Byte offset of the first payload byte.
        in_seq: u64,
        /// Keystroke or paste bytes.
        bytes: &'a [u8],
    },
    /// Reply-marked Input extension [307], independent of the typing cursor.
    InputReply {
        /// Session output offset of the query opening escape byte.
        query_seq: u64,
        /// One complete renderer response, bounded to 1024 bytes.
        bytes: &'a [u8],
    },
    /// Bytes written by the PTY, beginning at `out_seq`.
    Output {
        /// Shim byte offset of the first payload byte.
        out_seq: u64,
        /// PTY output bytes.
        bytes: &'a [u8],
    },
    /// Terminal dimensions.
    Resize {
        /// Character columns.
        cols: u16,
        /// Character rows.
        rows: u16,
        /// Pixel width.
        px_w: u16,
        /// Pixel height.
        px_h: u16,
    },
    /// Highest client input sequence written to the PTY.
    Ack {
        /// Acknowledged byte offset.
        in_seq_acked: u64,
    },
    /// Client-granted number of output bytes.
    Credit {
        /// Available output bytes.
        bytes: u32,
    },
    /// Screen contents valid at a particular output sequence.
    Snapshot {
        /// Output byte offset represented by this snapshot.
        out_seq: u64,
        /// Opaque screen repaint bytes.
        bytes: &'a [u8],
    },
    /// Opens or resumes a terminal stream.
    AttachTerm {
        /// Terminal session identifier.
        session_id: &'a [u8; 16],
        /// Last output byte displayed by the client.
        last_out_seq: u64,
        /// Last input byte acknowledged by the server.
        last_in_seq: u64,
    },
    /// Requests a plugin action. JSON input remains borrowed and opaque here.
    Call {
        /// Request identifier copied into the matching `Result`.
        call_id: u32,
        /// UTF-8 action identifier.
        action_id: &'a str,
        /// JSON input bytes.
        input_json: &'a [u8],
    },
    /// Response to a plugin action. JSON output remains borrowed and opaque here.
    Result {
        /// Request identifier from the matching `Call`.
        call_id: u32,
        /// Whether the action succeeded.
        ok: bool,
        /// JSON output or error bytes.
        json: &'a [u8],
    },
    /// Starts an event subscription. The JSON filter remains borrowed and opaque here.
    Subscribe {
        /// Subscription identifier.
        sub_id: u32,
        /// JSON filter bytes.
        filter_json: &'a [u8],
    },
    /// Event delivered to a subscription. The JSON event remains borrowed and opaque here.
    Event {
        /// Subscription identifier.
        sub_id: u32,
        /// JSON event bytes.
        event_json: &'a [u8],
    },
}

/// A decoded frame and the number of bytes it occupied in the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFrame<'a> {
    /// Decoded frame fields, borrowing payloads from the source bytes.
    pub frame: Frame<'a>,
    /// Frame prefix, type byte, and body length in bytes.
    pub wire_len: usize,
}

/// A decoded mux envelope and the frame carried by it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedMuxedFrame<'a> {
    /// Mux stream identifier.
    pub stream_id: u32,
    /// Decoded frame fields, borrowing payloads from the source bytes.
    pub frame: Frame<'a>,
    /// Stream identifier prefix and frame length in bytes.
    pub wire_len: usize,
}

/// Typed failures from decoding an untrusted wire frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// More bytes are needed to finish the varint or frame.
    Incomplete,
    /// A frame length prefix encoded zero bytes for its type and body.
    EmptyFrame,
    /// The declared frame length exceeds [`MAX_FRAME_LEN`].
    FrameTooLarge {
        /// Declared length of the type byte and body.
        length: u32,
    },
    /// The varint does not fit in an unsigned 32-bit integer.
    VarintOverflow,
    /// The varint uses more bytes than the canonical shortest representation.
    NonCanonicalVarint,
    /// The varint continues beyond the maximum five-byte u32 representation.
    VarintTooLong,
    /// The bounded incremental buffer could not reserve storage for received bytes.
    AllocationFailed,
    /// The internal incremental buffer exceeded the already-validated frame boundary.
    BufferLimitExceeded,
    /// A frame type is not defined by wire §4.
    UnknownType(u8),
    /// A known frame has a malformed field layout.
    InvalidBody {
        /// Frame type byte.
        frame_type: u8,
        /// Field-layout problem.
        reason: &'static str,
    },
    /// A field specified as UTF-8 contains invalid bytes.
    InvalidUtf8 {
        /// Frame type byte.
        frame_type: u8,
    },
}

/// Typed failures from encoding a frame into a reusable buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A field length or body length cannot be represented by the protocol.
    LengthOverflow,
    /// The type byte and body exceed [`MAX_FRAME_LEN`].
    FrameTooLarge {
        /// Computed length of the type byte and body.
        length: usize,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => formatter.write_str("wire data is incomplete"),
            Self::EmptyFrame => formatter.write_str("frame length cannot be zero"),
            Self::FrameTooLarge { length } => {
                write!(formatter, "frame length {length} exceeds {MAX_FRAME_LEN}")
            }
            Self::VarintOverflow => formatter.write_str("varint exceeds u32"),
            Self::NonCanonicalVarint => formatter.write_str("varint is not in shortest form"),
            Self::VarintTooLong => formatter.write_str("varint exceeds five bytes"),
            Self::AllocationFailed => formatter.write_str("incremental buffer allocation failed"),
            Self::BufferLimitExceeded => {
                formatter.write_str("incremental buffer exceeded its validated frame length")
            }
            Self::UnknownType(frame_type) => {
                write!(formatter, "unknown frame type 0x{frame_type:02x}")
            }
            Self::InvalidBody { frame_type, reason } => {
                write!(
                    formatter,
                    "invalid body for frame type 0x{frame_type:02x}: {reason}"
                )
            }
            Self::InvalidUtf8 { frame_type } => {
                write!(formatter, "invalid UTF-8 in frame type 0x{frame_type:02x}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LengthOverflow => formatter.write_str("encoded field length exceeds u32"),
            Self::FrameTooLarge { length } => {
                write!(formatter, "frame length {length} exceeds {MAX_FRAME_LEN}")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Decodes one complete frame without allocating; payload fields borrow `input`.
///
/// Trailing bytes are left for the caller to decode as the next frame.
///
/// # Errors
///
/// Returns a typed error for partial data, invalid varints, oversized frames,
/// unknown frame types, invalid UTF-8, or malformed field layouts.
#[inline]
pub fn decode_frame(input: &[u8]) -> Result<DecodedFrame<'_>, DecodeError> {
    let (length, prefix_len) = read_frame_length(input, 0)?;
    if length == 0 {
        return Err(DecodeError::EmptyFrame);
    }

    let length = usize::try_from(length).map_err(|_| DecodeError::VarintOverflow)?;
    let wire_len = prefix_len
        .checked_add(length)
        .ok_or(DecodeError::VarintOverflow)?;
    let encoded = input.get(..wire_len).ok_or(DecodeError::Incomplete)?;
    let frame_type = *encoded.get(prefix_len).ok_or(DecodeError::EmptyFrame)?;
    let body = encoded
        .get(prefix_len + 1..)
        .ok_or(DecodeError::Incomplete)?;

    Ok(DecodedFrame {
        frame: decode_body(frame_type, body)?,
        wire_len,
    })
}

/// Decodes one mux envelope and frame without allocating; payloads borrow `input`.
///
/// # Errors
///
/// Returns the same errors as [`decode_frame`] and rejects invalid stream-id
/// varints.
pub fn decode_muxed_frame(input: &[u8]) -> Result<DecodedMuxedFrame<'_>, DecodeError> {
    let (stream_id, stream_prefix_len) = read_varint(input, 0)?;
    let frame_input = input
        .get(stream_prefix_len..)
        .ok_or(DecodeError::Incomplete)?;
    let decoded = decode_frame(frame_input)?;
    let wire_len = stream_prefix_len
        .checked_add(decoded.wire_len)
        .ok_or(DecodeError::VarintOverflow)?;
    Ok(DecodedMuxedFrame {
        stream_id,
        frame: decoded.frame,
        wire_len,
    })
}

/// Encodes one frame into `output`, clearing and reusing its existing allocation.
///
/// # Errors
///
/// Returns an error if the frame exceeds the protocol length limit or a nested
/// UTF-8 length cannot fit the unsigned 32-bit varint representation.
pub fn encode_frame_into(frame: &Frame<'_>, output: &mut Vec<u8>) -> Result<usize, EncodeError> {
    let body_len = body_len(frame)?;
    let frame_len = validate_frame_len(body_len)?;

    output.clear();
    output.reserve(varint_len_u32(frame_len) + body_len + 1);
    append_frame(frame, frame_len, output)?;
    Ok(output.len())
}

/// Encodes a mux stream identifier and frame into a reusable buffer.
///
/// Stream ownership (odd client ids, even server ids, and control id zero) is a
/// connection-state invariant and is intentionally not enforced by this codec.
///
/// # Errors
///
/// Returns an error if the frame exceeds the protocol length limit or a nested
/// UTF-8 length cannot fit the unsigned 32-bit varint representation.
pub fn encode_muxed_frame_into(
    stream_id: u32,
    frame: &Frame<'_>,
    output: &mut Vec<u8>,
) -> Result<usize, EncodeError> {
    let body_len = body_len(frame)?;
    let frame_len = validate_frame_len(body_len)?;
    let frame_wire_len = varint_len_u32(frame_len) + body_len + 1;
    let mux_wire_len = varint_len_u32(stream_id)
        .checked_add(frame_wire_len)
        .ok_or(EncodeError::LengthOverflow)?;

    output.clear();
    output.reserve(mux_wire_len);
    write_varint(stream_id, output);
    append_frame(frame, frame_len, output)?;
    Ok(output.len())
}

/// Incrementally decodes unwrapped frames from arbitrary stream chunks.
pub struct FrameStreamDecoder {
    inner: StreamDecoder,
}

impl Default for FrameStreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameStreamDecoder {
    /// Creates an empty incremental frame decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: StreamDecoder::new(false),
        }
    }

    /// Returns the number of bytes retained from an incomplete frame.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.inner.buffer.len()
    }

    /// Feeds a chunk and invokes `on_frame` for each complete decoded frame.
    ///
    /// The callback's payload references are valid only until it returns.
    ///
    /// # Errors
    ///
    /// Returns a typed decode error when the buffered stream contains malformed
    /// data or a frame over the protocol limit.
    pub fn feed<F>(&mut self, input: &[u8], mut on_frame: F) -> Result<(), DecodeError>
    where
        F: FnMut(Frame<'_>),
    {
        self.inner.feed(input, |_, frame| on_frame(frame))
    }
}

/// Incrementally decodes mux envelopes from leg-A or TCP leg-B stream chunks.
///
/// Fragmented bytes are copied into private storage. Callback borrows cannot be
/// sent to asynchronous tasks; transports needing retained zero-copy dispatch
/// should own their receive buffer and use `decode_muxed_frame` directly.
pub struct MuxStreamDecoder {
    inner: StreamDecoder,
}

impl Default for MuxStreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl MuxStreamDecoder {
    /// Creates an empty incremental mux decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: StreamDecoder::new(true),
        }
    }

    /// Returns the number of bytes retained from an incomplete mux envelope.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.inner.buffer.len()
    }

    /// Feeds a chunk and invokes `on_frame` for each complete muxed frame.
    ///
    /// The callback's payload references are valid only until it returns.
    ///
    /// # Errors
    ///
    /// Returns a typed decode error when the buffered stream contains malformed
    /// data or a frame over the protocol limit.
    pub fn feed<F>(&mut self, input: &[u8], mut on_frame: F) -> Result<(), DecodeError>
    where
        F: FnMut(u32, Frame<'_>),
    {
        self.inner.feed(input, |stream_id, frame| {
            if let Some(stream_id) = stream_id {
                on_frame(stream_id, frame);
            }
        })
    }
}

struct StreamDecoder {
    muxed: bool,
    buffer: Vec<u8>,
}

impl StreamDecoder {
    const fn new(muxed: bool) -> Self {
        Self {
            muxed,
            buffer: Vec::new(),
        }
    }

    fn feed<F>(&mut self, input: &[u8], mut on_frame: F) -> Result<(), DecodeError>
    where
        F: FnMut(Option<u32>, Frame<'_>),
    {
        // Header-only buffering stays capped until a valid length has passed the
        // 4 MiB check; body bytes are reserved only up to that checked length.
        let mut offset = 0;
        while offset < input.len() || self.has_complete_buffered_frame()? {
            if self.buffer.is_empty() {
                let remaining = input.get(offset..).ok_or(DecodeError::Incomplete)?;
                match self.decode_one(remaining) {
                    Ok((stream_id, decoded, wire_len)) => {
                        on_frame(stream_id, decoded);
                        offset = offset
                            .checked_add(wire_len)
                            .ok_or(DecodeError::VarintOverflow)?;
                    }
                    Err(DecodeError::Incomplete) => {
                        self.retain_incomplete(remaining)?;
                        offset = input.len();
                    }
                    Err(error) => return Err(error),
                }
            } else {
                let Some(expected_len) = wire_frame_len(&self.buffer, self.muxed)? else {
                    let remaining = input.get(offset..).ok_or(DecodeError::Incomplete)?;
                    let missing_header =
                        max_header_len(self.muxed).saturating_sub(self.buffer.len());
                    // Read only one header byte before checking the length again.
                    // A maximum-size refill can swallow the next short envelope.
                    let copy_len = remaining.len().min(missing_header).min(1);
                    if copy_len == 0 {
                        self.buffer.clear();
                        return Err(DecodeError::VarintTooLong);
                    }
                    let bytes = remaining.get(..copy_len).ok_or(DecodeError::Incomplete)?;
                    self.buffer_bytes(bytes, max_header_len(self.muxed))?;
                    offset = offset
                        .checked_add(copy_len)
                        .ok_or(DecodeError::VarintOverflow)?;
                    continue;
                };

                if self.buffer.len() < expected_len {
                    let remaining = input.get(offset..).ok_or(DecodeError::Incomplete)?;
                    let missing = expected_len - self.buffer.len();
                    let copy_len = remaining.len().min(missing);
                    let bytes = remaining.get(..copy_len).ok_or(DecodeError::Incomplete)?;
                    self.buffer_bytes(bytes, expected_len)?;
                    offset = offset
                        .checked_add(copy_len)
                        .ok_or(DecodeError::VarintOverflow)?;
                    if copy_len == 0 {
                        break;
                    }
                    continue;
                }

                match self.decode_one(&self.buffer) {
                    Ok((stream_id, decoded, _)) => {
                        on_frame(stream_id, decoded);
                        self.buffer.clear();
                    }
                    Err(error) => {
                        self.buffer.clear();
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    fn decode_one<'a>(
        &self,
        input: &'a [u8],
    ) -> Result<(Option<u32>, Frame<'a>, usize), DecodeError> {
        if self.muxed {
            let decoded = decode_muxed_frame(input)?;
            Ok((Some(decoded.stream_id), decoded.frame, decoded.wire_len))
        } else {
            let decoded = decode_frame(input)?;
            Ok((None, decoded.frame, decoded.wire_len))
        }
    }

    fn retain_incomplete(&mut self, input: &[u8]) -> Result<(), DecodeError> {
        if let Some(expected_len) = wire_frame_len(input, self.muxed)? {
            self.buffer_bytes(input, expected_len)?;
        } else {
            let header_len = max_header_len(self.muxed);
            let copy_len = input.len().min(header_len);
            let bytes = input.get(..copy_len).ok_or(DecodeError::Incomplete)?;
            self.buffer_bytes(bytes, header_len)?;
        }
        Ok(())
    }

    fn buffer_bytes(&mut self, bytes: &[u8], max_capacity: usize) -> Result<(), DecodeError> {
        let needed = self
            .buffer
            .len()
            .checked_add(bytes.len())
            .ok_or(DecodeError::VarintOverflow)?;
        if needed > max_capacity {
            return Err(DecodeError::BufferLimitExceeded);
        }
        if needed > self.buffer.capacity() {
            // Geometric growth avoids copying every partial network chunk while
            // the validated total keeps capacity within the frame's bound.
            let doubled_capacity = self.buffer.capacity().saturating_mul(2);
            let target_capacity = needed.max(doubled_capacity).min(max_capacity);
            let additional = target_capacity - self.buffer.len();
            self.buffer
                .try_reserve_exact(additional)
                .map_err(|_| DecodeError::AllocationFailed)?;
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    fn has_complete_buffered_frame(&self) -> Result<bool, DecodeError> {
        Ok(wire_frame_len(&self.buffer, self.muxed)?
            .is_some_and(|wire_len| self.buffer.len() >= wire_len))
    }
}

fn max_header_len(muxed: bool) -> usize {
    MAX_VARINT_BYTES * if muxed { 2 } else { 1 }
}

fn wire_frame_len(input: &[u8], muxed: bool) -> Result<Option<usize>, DecodeError> {
    let (frame_offset, mux_prefix) = if muxed {
        match read_varint(input, 0) {
            Ok((_, prefix_len)) => (prefix_len, prefix_len),
            Err(DecodeError::Incomplete) => return Ok(None),
            Err(error) => return Err(error),
        }
    } else {
        (0, 0)
    };
    let (frame_length, frame_prefix) = match read_frame_length(input, frame_offset) {
        Ok(decoded) => decoded,
        Err(DecodeError::Incomplete) => return Ok(None),
        Err(error) => return Err(error),
    };
    if frame_length == 0 {
        return Err(DecodeError::EmptyFrame);
    }
    let frame_length = usize::try_from(frame_length).map_err(|_| DecodeError::VarintOverflow)?;
    mux_prefix
        .checked_add(frame_prefix)
        .and_then(|prefix| prefix.checked_add(frame_length))
        .map(Some)
        .ok_or(DecodeError::VarintOverflow)
}

#[inline]
fn read_frame_length(input: &[u8], offset: usize) -> Result<(u32, usize), DecodeError> {
    let (length, prefix_len) = read_varint(input, offset)?;
    if usize::try_from(length).map_err(|_| DecodeError::VarintOverflow)? > MAX_FRAME_LEN {
        return Err(DecodeError::FrameTooLarge { length });
    }
    Ok((length, prefix_len))
}

#[inline]
fn read_varint(input: &[u8], offset: usize) -> Result<(u32, usize), DecodeError> {
    // Shortest-form u32 varints keep one representation per value and bound mux
    // and nested string headers independently of the enclosing frame length.
    let Some(&first) = input.get(offset) else {
        return Err(DecodeError::Incomplete);
    };
    if first & 0x80 == 0 {
        return Ok((u32::from(first), 1));
    }

    let mut value = u32::from(first & 0x7f);
    for byte_index in 1..MAX_VARINT_BYTES {
        let index = offset
            .checked_add(byte_index)
            .ok_or(DecodeError::VarintOverflow)?;
        let Some(&byte) = input.get(index) else {
            return Err(DecodeError::Incomplete);
        };
        let payload = u32::from(byte & 0x7f);
        if byte_index == MAX_VARINT_BYTES - 1 && payload > 0x0f {
            return Err(DecodeError::VarintOverflow);
        }
        let shift = u32::try_from(byte_index * 7).map_err(|_| DecodeError::VarintOverflow)?;
        value |= payload << shift;
        if byte & 0x80 == 0 {
            let encoded_len = byte_index + 1;
            if varint_len_u32(value) != encoded_len {
                return Err(DecodeError::NonCanonicalVarint);
            }
            return Ok((value, encoded_len));
        }
    }
    Err(DecodeError::VarintTooLong)
}

#[inline]
fn decode_body(frame_type: u8, body: &[u8]) -> Result<Frame<'_>, DecodeError> {
    match frame_type {
        0x00 | 0x01 | 0x02 | 0x08 | 0x09 | 0x0f => decode_connection_body(frame_type, body),
        0x10..=0x17 => decode_terminal_body(frame_type, body),
        0x30..=0x33 => decode_control_body(frame_type, body),
        #[cfg(any(test, feature = "desktop"))]
        0x40..=0x45 => desktop::decode(frame_type, body).map(Frame::Desktop),
        _ => Err(DecodeError::UnknownType(frame_type)),
    }
}

fn decode_connection_body(frame_type: u8, body: &[u8]) -> Result<Frame<'_>, DecodeError> {
    match frame_type {
        0x00 => {
            let version = body_u16(frame_type, body, 0)?;
            let caps = body_u64(frame_type, body, 2)?;
            let (client_info, end) = body_string(frame_type, body, 10)?;
            ensure_end(frame_type, body, end)?;
            Ok(Frame::Hello {
                version,
                caps,
                client_info,
            })
        }
        0x01 => {
            let connection_id = body_array::<16>(frame_type, body, 0)?;
            let resume_token = body_array::<32>(frame_type, body, 16)?;
            let resume_window_seconds = body_u32(frame_type, body, 48)?;
            let session_incarnation = if body.len() == 52 {
                None
            } else {
                let (value, end) = body_string(frame_type, body, 52)?;
                ensure_end(frame_type, body, end)?;
                if !valid_incarnation(value) {
                    return Err(invalid_body(frame_type, "invalid session incarnation"));
                }
                Some(value)
            };
            Ok(Frame::Welcome {
                connection_id,
                resume_token,
                resume_window_seconds,
                session_incarnation,
            })
        }
        0x02 => {
            let connection_id = body_array::<16>(frame_type, body, 0)?;
            let resume_token = body_array::<32>(frame_type, body, 16)?;
            ensure_end(frame_type, body, 48)?;
            Ok(Frame::Resume {
                connection_id,
                resume_token,
            })
        }
        0x08 | 0x09 => {
            let nonce = body_u64(frame_type, body, 0)?;
            let sent_us = body_u64(frame_type, body, 8)?;
            ensure_end(frame_type, body, 16)?;
            if frame_type == 0x08 {
                Ok(Frame::Ping { nonce, sent_us })
            } else {
                Ok(Frame::Pong { nonce, sent_us })
            }
        }
        0x0f => {
            let code = body_u16(frame_type, body, 0)?;
            let reason = body_utf8_rest(frame_type, body, 2)?;
            Ok(Frame::Close { code, reason })
        }
        _ => Err(DecodeError::UnknownType(frame_type)),
    }
}

#[inline]
fn decode_terminal_body(frame_type: u8, body: &[u8]) -> Result<Frame<'_>, DecodeError> {
    match frame_type {
        0x17 => {
            let query_seq = body_u64(frame_type, body, 0)?;
            let bytes = &body[8..];
            if bytes.is_empty() || bytes.len() > 1024 {
                return Err(invalid_body(frame_type, "reply size"));
            }
            Ok(Frame::InputReply { query_seq, bytes })
        }
        0x10 | 0x11 | 0x15 => {
            let sequence = body_u64(frame_type, body, 0)?;
            let bytes = body
                .get(8..)
                .ok_or_else(|| invalid_body(frame_type, "missing payload"))?;
            match frame_type {
                0x10 => Ok(Frame::Input {
                    in_seq: sequence,
                    bytes,
                }),
                0x11 => Ok(Frame::Output {
                    out_seq: sequence,
                    bytes,
                }),
                _ => Ok(Frame::Snapshot {
                    out_seq: sequence,
                    bytes,
                }),
            }
        }
        0x12 => {
            let cols = body_u16(frame_type, body, 0)?;
            let rows = body_u16(frame_type, body, 2)?;
            let px_w = body_u16(frame_type, body, 4)?;
            let px_h = body_u16(frame_type, body, 6)?;
            ensure_end(frame_type, body, 8)?;
            Ok(Frame::Resize {
                cols,
                rows,
                px_w,
                px_h,
            })
        }
        0x13 => {
            let in_seq_acked = body_u64(frame_type, body, 0)?;
            ensure_end(frame_type, body, 8)?;
            Ok(Frame::Ack { in_seq_acked })
        }
        0x14 => {
            let bytes = body_u32(frame_type, body, 0)?;
            ensure_end(frame_type, body, 4)?;
            Ok(Frame::Credit { bytes })
        }
        0x16 => {
            let session_id = body_array::<16>(frame_type, body, 0)?;
            let last_out_seq = body_u64(frame_type, body, 16)?;
            let last_in_seq = body_u64(frame_type, body, 24)?;
            ensure_end(frame_type, body, 32)?;
            Ok(Frame::AttachTerm {
                session_id,
                last_out_seq,
                last_in_seq,
            })
        }
        _ => Err(DecodeError::UnknownType(frame_type)),
    }
}

fn decode_control_body(frame_type: u8, body: &[u8]) -> Result<Frame<'_>, DecodeError> {
    match frame_type {
        0x30 => {
            let call_id = body_u32(frame_type, body, 0)?;
            let (action_id, json_offset) = body_string(frame_type, body, 4)?;
            let input_json = body
                .get(json_offset..)
                .ok_or_else(|| invalid_body(frame_type, "missing JSON input"))?;
            Ok(Frame::Call {
                call_id,
                action_id,
                input_json,
            })
        }
        0x31 => {
            let call_id = body_u32(frame_type, body, 0)?;
            let ok_byte = *body
                .get(4)
                .ok_or_else(|| invalid_body(frame_type, "missing success byte"))?;
            let ok = match ok_byte {
                0 => false,
                1 => true,
                _ => return Err(invalid_body(frame_type, "success byte must be zero or one")),
            };
            let json = body
                .get(5..)
                .ok_or_else(|| invalid_body(frame_type, "missing JSON result"))?;
            Ok(Frame::Result { call_id, ok, json })
        }
        0x32 | 0x33 => {
            let id = body_u32(frame_type, body, 0)?;
            let json = body
                .get(4..)
                .ok_or_else(|| invalid_body(frame_type, "missing JSON body"))?;
            if frame_type == 0x32 {
                Ok(Frame::Subscribe {
                    sub_id: id,
                    filter_json: json,
                })
            } else {
                Ok(Frame::Event {
                    sub_id: id,
                    event_json: json,
                })
            }
        }
        _ => Err(DecodeError::UnknownType(frame_type)),
    }
}

fn invalid_body(frame_type: u8, reason: &'static str) -> DecodeError {
    DecodeError::InvalidBody { frame_type, reason }
}

fn body_slice<const N: usize>(
    frame_type: u8,
    body: &[u8],
    offset: usize,
) -> Result<&[u8; N], DecodeError> {
    let end = offset.checked_add(N).ok_or(DecodeError::VarintOverflow)?;
    body.get(offset..end)
        .ok_or_else(|| invalid_body(frame_type, "field is truncated"))?
        .try_into()
        .map_err(|_| invalid_body(frame_type, "field has an invalid width"))
}

fn body_array<const N: usize>(
    frame_type: u8,
    body: &[u8],
    offset: usize,
) -> Result<&[u8; N], DecodeError> {
    body_slice(frame_type, body, offset)
}

fn body_u16(frame_type: u8, body: &[u8], offset: usize) -> Result<u16, DecodeError> {
    Ok(u16::from_le_bytes(*body_slice(frame_type, body, offset)?))
}

fn body_u32(frame_type: u8, body: &[u8], offset: usize) -> Result<u32, DecodeError> {
    Ok(u32::from_le_bytes(*body_slice(frame_type, body, offset)?))
}

fn body_u64(frame_type: u8, body: &[u8], offset: usize) -> Result<u64, DecodeError> {
    Ok(u64::from_le_bytes(*body_slice(frame_type, body, offset)?))
}

fn body_string(frame_type: u8, body: &[u8], offset: usize) -> Result<(&str, usize), DecodeError> {
    let (string_len, prefix_len) = read_varint(body, offset).map_err(|error| match error {
        DecodeError::Incomplete => invalid_body(frame_type, "string length prefix is truncated"),
        other => other,
    })?;
    let string_len = usize::try_from(string_len).map_err(|_| DecodeError::VarintOverflow)?;
    let string_start = offset
        .checked_add(prefix_len)
        .ok_or(DecodeError::VarintOverflow)?;
    let string_end = string_start
        .checked_add(string_len)
        .ok_or(DecodeError::VarintOverflow)?;
    let bytes = body
        .get(string_start..string_end)
        .ok_or_else(|| invalid_body(frame_type, "string length exceeds the frame body"))?;
    let string = std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8 { frame_type })?;
    Ok((string, string_end))
}

fn body_utf8_rest(frame_type: u8, body: &[u8], offset: usize) -> Result<&str, DecodeError> {
    let bytes = body
        .get(offset..)
        .ok_or_else(|| invalid_body(frame_type, "string field is truncated"))?;
    std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8 { frame_type })
}

fn ensure_end(frame_type: u8, body: &[u8], expected_len: usize) -> Result<(), DecodeError> {
    if body.len() == expected_len {
        Ok(())
    } else {
        Err(invalid_body(
            frame_type,
            "unexpected trailing or missing bytes",
        ))
    }
}

fn valid_incarnation(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn body_len(frame: &Frame<'_>) -> Result<usize, EncodeError> {
    match frame {
        #[cfg(any(test, feature = "desktop"))]
        Frame::Desktop(message) => message.len(),
        Frame::Hello { client_info, .. } => string_field_len(client_info)?
            .checked_add(10)
            .ok_or(EncodeError::LengthOverflow),
        Frame::Welcome {
            session_incarnation,
            ..
        } => {
            if session_incarnation.is_some_and(|value| !valid_incarnation(value)) {
                return Err(EncodeError::LengthOverflow);
            }
            Ok(if session_incarnation.is_some() {
                96
            } else {
                52
            })
        }
        Frame::Resume { .. } => Ok(48),
        Frame::Ping { .. } | Frame::Pong { .. } => Ok(16),
        Frame::Close { reason, .. } => reason
            .len()
            .checked_add(2)
            .ok_or(EncodeError::LengthOverflow),
        Frame::InputReply { bytes, .. } => {
            if bytes.is_empty() || bytes.len() > 1024 {
                return Err(EncodeError::LengthOverflow);
            }
            Ok(8 + bytes.len())
        }
        Frame::Input { bytes, .. }
        | Frame::Output { bytes, .. }
        | Frame::Snapshot { bytes, .. } => 8_usize
            .checked_add(bytes.len())
            .ok_or(EncodeError::LengthOverflow),
        Frame::Resize { .. } | Frame::Ack { .. } => Ok(8),
        Frame::Credit { .. } => Ok(4),
        Frame::AttachTerm { .. } => Ok(32),
        Frame::Call {
            action_id,
            input_json,
            ..
        } => string_field_len(action_id)?
            .checked_add(4)
            .and_then(|len| len.checked_add(input_json.len()))
            .ok_or(EncodeError::LengthOverflow),
        Frame::Result { json, .. } => 5_usize
            .checked_add(json.len())
            .ok_or(EncodeError::LengthOverflow),
        Frame::Subscribe { filter_json, .. } => 4_usize
            .checked_add(filter_json.len())
            .ok_or(EncodeError::LengthOverflow),
        Frame::Event { event_json, .. } => 4_usize
            .checked_add(event_json.len())
            .ok_or(EncodeError::LengthOverflow),
    }
}

fn string_field_len(value: &str) -> Result<usize, EncodeError> {
    let length = u32::try_from(value.len()).map_err(|_| EncodeError::LengthOverflow)?;
    varint_len_u32(length)
        .checked_add(value.len())
        .ok_or(EncodeError::LengthOverflow)
}

fn validate_frame_len(body_len: usize) -> Result<u32, EncodeError> {
    let frame_len = body_len.checked_add(1).ok_or(EncodeError::LengthOverflow)?;
    if frame_len > MAX_FRAME_LEN {
        return Err(EncodeError::FrameTooLarge { length: frame_len });
    }
    u32::try_from(frame_len).map_err(|_| EncodeError::LengthOverflow)
}

fn append_frame(
    frame: &Frame<'_>,
    frame_len: u32,
    output: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    write_varint(frame_len, output);
    output.push(frame_type(frame));
    append_frame_body(frame, output)
}

/// Returns the frozen type byte used by compiled plugin direction declarations.
#[must_use]
pub fn frame_type(frame: &Frame<'_>) -> u8 {
    match frame {
        #[cfg(any(test, feature = "desktop"))]
        Frame::Desktop(message) => message.tag(),
        Frame::Hello { .. } => 0x00,
        Frame::Welcome { .. } => 0x01,
        Frame::Resume { .. } => 0x02,
        Frame::Ping { .. } => 0x08,
        Frame::Pong { .. } => 0x09,
        Frame::Close { .. } => 0x0f,
        Frame::InputReply { .. } => 0x17,
        Frame::Input { .. } => 0x10,
        Frame::Output { .. } => 0x11,
        Frame::Resize { .. } => 0x12,
        Frame::Ack { .. } => 0x13,
        Frame::Credit { .. } => 0x14,
        Frame::Snapshot { .. } => 0x15,
        Frame::AttachTerm { .. } => 0x16,
        Frame::Call { .. } => 0x30,
        Frame::Result { .. } => 0x31,
        Frame::Subscribe { .. } => 0x32,
        Frame::Event { .. } => 0x33,
    }
}

fn append_frame_body(frame: &Frame<'_>, output: &mut Vec<u8>) -> Result<(), EncodeError> {
    match frame {
        #[cfg(any(test, feature = "desktop"))]
        Frame::Desktop(message) => {
            message.append(output);
            Ok(())
        }
        Frame::Hello { .. }
        | Frame::Welcome { .. }
        | Frame::Resume { .. }
        | Frame::Ping { .. }
        | Frame::Pong { .. }
        | Frame::Close { .. } => append_connection_body(frame, output),
        Frame::InputReply { .. }
        | Frame::Input { .. }
        | Frame::Output { .. }
        | Frame::Resize { .. }
        | Frame::Ack { .. }
        | Frame::Credit { .. }
        | Frame::Snapshot { .. }
        | Frame::AttachTerm { .. } => append_terminal_body(frame, output),
        Frame::Call { .. }
        | Frame::Result { .. }
        | Frame::Subscribe { .. }
        | Frame::Event { .. } => append_control_body(frame, output),
    }
}

fn append_connection_body(frame: &Frame<'_>, output: &mut Vec<u8>) -> Result<(), EncodeError> {
    match frame {
        Frame::Hello {
            version,
            caps,
            client_info,
        } => {
            output.extend_from_slice(&version.to_le_bytes());
            output.extend_from_slice(&caps.to_le_bytes());
            write_string(client_info, output)?;
        }
        Frame::Welcome {
            connection_id,
            resume_token,
            resume_window_seconds,
            session_incarnation,
        } => {
            output.extend_from_slice(*connection_id);
            output.extend_from_slice(*resume_token);
            output.extend_from_slice(&resume_window_seconds.to_le_bytes());
            if let Some(value) = session_incarnation {
                write_string(value, output)?;
            }
        }
        Frame::Resume {
            connection_id,
            resume_token,
        } => {
            output.extend_from_slice(*connection_id);
            output.extend_from_slice(*resume_token);
        }
        Frame::Ping { nonce, sent_us } | Frame::Pong { nonce, sent_us } => {
            output.extend_from_slice(&nonce.to_le_bytes());
            output.extend_from_slice(&sent_us.to_le_bytes());
        }
        Frame::Close { code, reason } => {
            output.extend_from_slice(&code.to_le_bytes());
            output.extend_from_slice(reason.as_bytes());
        }
        _ => return Err(EncodeError::LengthOverflow),
    }
    Ok(())
}

fn append_terminal_body(frame: &Frame<'_>, output: &mut Vec<u8>) -> Result<(), EncodeError> {
    match frame {
        Frame::InputReply { query_seq, bytes } => {
            output.extend_from_slice(&query_seq.to_le_bytes());
            output.extend_from_slice(bytes);
        }
        Frame::Input { in_seq, bytes } => {
            output.extend_from_slice(&in_seq.to_le_bytes());
            output.extend_from_slice(bytes);
        }
        Frame::Output { out_seq, bytes } | Frame::Snapshot { out_seq, bytes } => {
            output.extend_from_slice(&out_seq.to_le_bytes());
            output.extend_from_slice(bytes);
        }
        Frame::Resize {
            cols,
            rows,
            px_w,
            px_h,
        } => {
            output.extend_from_slice(&cols.to_le_bytes());
            output.extend_from_slice(&rows.to_le_bytes());
            output.extend_from_slice(&px_w.to_le_bytes());
            output.extend_from_slice(&px_h.to_le_bytes());
        }
        Frame::Ack { in_seq_acked } => {
            output.extend_from_slice(&in_seq_acked.to_le_bytes());
        }
        Frame::Credit { bytes } => {
            output.extend_from_slice(&bytes.to_le_bytes());
        }
        Frame::AttachTerm {
            session_id,
            last_out_seq,
            last_in_seq,
        } => {
            output.extend_from_slice(*session_id);
            output.extend_from_slice(&last_out_seq.to_le_bytes());
            output.extend_from_slice(&last_in_seq.to_le_bytes());
        }
        _ => return Err(EncodeError::LengthOverflow),
    }
    Ok(())
}

fn append_control_body(frame: &Frame<'_>, output: &mut Vec<u8>) -> Result<(), EncodeError> {
    match frame {
        Frame::Call {
            call_id,
            action_id,
            input_json,
        } => {
            output.extend_from_slice(&call_id.to_le_bytes());
            write_string(action_id, output)?;
            output.extend_from_slice(input_json);
        }
        Frame::Result { call_id, ok, json } => {
            output.extend_from_slice(&call_id.to_le_bytes());
            output.push(u8::from(*ok));
            output.extend_from_slice(json);
        }
        Frame::Subscribe {
            sub_id,
            filter_json,
        } => {
            output.extend_from_slice(&sub_id.to_le_bytes());
            output.extend_from_slice(filter_json);
        }
        Frame::Event { sub_id, event_json } => {
            output.extend_from_slice(&sub_id.to_le_bytes());
            output.extend_from_slice(event_json);
        }
        _ => return Err(EncodeError::LengthOverflow),
    }
    Ok(())
}

fn write_string(value: &str, output: &mut Vec<u8>) -> Result<(), EncodeError> {
    let length = u32::try_from(value.len()).map_err(|_| EncodeError::LengthOverflow)?;
    write_varint(length, output);
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn write_varint(mut value: u32, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value.to_le_bytes()[0] & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value.to_le_bytes()[0]);
}

fn varint_len_u32(mut value: u32) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        length += 1;
        value >>= 7;
    }
    length
}
