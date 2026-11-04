//! Wire messages of remote-desktop sessions: video from the host, input and requests from the viewer.
//!
//! Each [`Message`] travels as the body of a [`crate::Frame::Desktop`] frame, so it uses the normal
//! frame header (length, then a one-byte tag from `0x40` up). Bodies are little-endian. Decoding
//! borrows from the input buffer and allocates nothing, and [`Message::validate`] runs on both
//! encode and decode, so a malformed message never reaches the desktop plugin.
//!
//! | Tag | Message | Direction |
//! |-----|---------|-----------|
//! | `0x40` | [`Message::Attach`] | viewer to host, first message of a session |
//! | `0x41` | [`Message::Video`] | host to viewer, over a reliable stream |
//! | `0x42` | [`Message::Size`] | viewer to host |
//! | `0x43` | [`Message::Input`] | viewer to host (`Control` is added by the server) |
//! | `0x44` | [`Message::Repair`] | viewer to host |
//! | `0x45` | [`Message::Fragment`] | host to viewer, over QUIC datagrams |
//!
//! Relay streams and QUIC datagrams share this one encoding [D12, D104, D232].
use crate::{
    DecodeError, EncodeError, MAX_FRAME_LEN, body_array, body_u16, body_u32, body_u64, ensure_end,
    invalid_body,
};

/// Capability bit a browser connection (leg A) advertises when it can show remote desktops.
/// It is independent of [`NATIVE_CAPABILITY`] and of the core capabilities of native connections (leg B).
pub const CAPABILITY: u64 = 1 << 4;
/// Capability bit for remote desktops on native connections (leg B). Bits 0–7 of leg B are
/// reserved for transport control, so desktop takes the first lane bit, bit 8.
pub const NATIVE_CAPABILITY: u64 = 1 << 8;
/// Largest video payload (one encoded access unit) in bytes: the frame limit minus 42, the tag
/// plus the largest desktop header (the 41-byte `Fragment` header).
pub const MAX_VIDEO_BYTES: usize = MAX_FRAME_LEN - 42;

/// How video reaches the viewer. The viewer picks one in [`Message::Attach`]. Both candidates
/// stay available until the owner selects one from measurements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Delivery {
    /// Video travels as [`Message::Video`] on the ordered, reliable stream.
    Reliable = 0,
    /// Video travels as [`Message::Fragment`] in unreliable QUIC datagrams.
    Datagram = 1,
}
/// Reads the delivery byte of an `Attach` body: `0` is `Reliable`, `1` is `Datagram`.
/// Any other value is a decode error.
impl TryFrom<u8> for Delivery {
    type Error = DecodeError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Reliable),
            1 => Ok(Self::Datagram),
            _ => Err(invalid_body(0x40, "invalid delivery mode")),
        }
    }
}

/// One input event from the viewer, applied to the remote desktop.
///
/// Coordinates (`x`, `y`) are unsigned millionths of the current output frame, including
/// letterbox bands, so `0..=1_000_000` spans the frame. This avoids nonfinite floating point
/// values and keeps subpixel positioning at 4096 px. `modifiers` is a bit mask; only the low
/// four bits may be set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// Ordered cleanup relinquishes held keys and buttons without replay.
    Release,
    /// One committed Unicode scalar; the helper posts its UTF-16 without layout loss.
    Text { scalar: u32 },
    /// Server-generated control-session visibility; viewers cannot originate it.
    Control { active: bool },
    /// A pointer event at (`x`, `y`). `button` and `state` are each `0..=2`; they are checked
    /// here, and their meaning is defined by the desktop helper that applies them.
    Mouse {
        x: u32,
        y: u32,
        button: u8,
        state: u8,
        modifiers: u8,
    },
    /// A scroll at (`x`, `y`) by `dx`, `dy` (signed, in the helper's scroll units).
    Scroll {
        x: u32,
        y: u32,
        dx: i32,
        dy: i32,
        modifiers: u8,
    },
    /// A physical key press (`down`) or release. `keycode` must be at most 127.
    Key {
        keycode: u16,
        down: bool,
        modifiers: u8,
    },
}

/// One decoded (or to-be-encoded) desktop message. It borrows its byte slices, so it
/// allocates nothing. Which side may send which variant, and on which stream, is enforced by
/// the desktop plugin, not here. The tag of each variant is given by [`Message::tag`].
///
/// `Repair` (viewer to host, tag `0x44`, 8 bytes) asks the host for a new keyframe, for example
/// after video was lost. Its `last_sequence` is the last video sequence the viewer received; the
/// current host produces a keyframe whatever its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    /// Viewer to host, tag `0x40`, 17 bytes: the 16-byte `session_id` of the desktop session to
    /// watch, then the `delivery` byte. Sent first on the stream.
    Attach {
        session_id: &'a [u8; 16],
        delivery: Delivery,
    },
    /// Host to viewer, tag `0x41`: one encoded video access unit, sent whole over the reliable
    /// stream. Body: `sequence` (u64), `capture_ns` (u64, capture time in nanoseconds), a
    /// `keyframe` flag (0 or 1), then `bytes`. `sequence` starts at 1 and `bytes` is
    /// non-empty and at most [`MAX_VIDEO_BYTES`].
    Video {
        sequence: u64,
        capture_ns: u64,
        keyframe: bool,
        bytes: &'a [u8],
    },
    /// Viewer to host, tag `0x42`, 6 bytes: the size the viewer wants, in physical pixels
    /// (`width`, `height`, each even and `2..=4096`, at most 4 Mpixel in total) and the display
    /// density in thousandths (`density_milli`, `1000..=4000`, so 2000 means 2x).
    Size {
        width: u16,
        height: u16,
        density_milli: u16,
    },
    /// Viewer to host, tag `0x43`: an [`Input`] event. The body starts with a kind byte
    /// (mouse 0, scroll 1, key 2, release 3, text 4, control 5).
    Input(Input),
    Repair {
        last_sequence: u64,
    },
    /// Host to viewer, tag `0x45`: one piece of a video access unit sent as a datagram, with its
    /// own header, so each datagram stands alone. `session_id`, `sequence`, `capture_ns` and
    /// `keyframe` repeat the `Video` fields; `total` is the whole unit's length and `offset`
    /// where this piece starts. Pieces carry 1024 bytes each (the last may be shorter), and
    /// `offset` is a multiple of 1024 below `total`.
    Fragment {
        session_id: &'a [u8; 16],
        sequence: u64,
        capture_ns: u64,
        keyframe: bool,
        total: u32,
        offset: u32,
        bytes: &'a [u8],
    },
}
impl Message<'_> {
    /// Stable additive frame tag; none overlaps the frozen upgrade range.
    ///
    /// The tag is the byte after the frame length: `0x40` Attach, `0x41` Video, `0x42` Size,
    /// `0x43` Input, `0x44` Repair, `0x45` Fragment.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Attach { .. } => 0x40,
            Self::Video { .. } => 0x41,
            Self::Size { .. } => 0x42,
            Self::Input(_) => 0x43,
            Self::Repair { .. } => 0x44,
            Self::Fragment { .. } => 0x45,
        }
    }
    /// Length of the encoded body in bytes (without tag or frame length). Fails with
    /// `LengthOverflow` when the message does not pass [`Message::validate`].
    pub(crate) fn len(self) -> Result<usize, EncodeError> {
        self.validate().map_err(|_| EncodeError::LengthOverflow)?;
        Ok(match self {
            Self::Attach { .. } => 17,
            Self::Video { bytes, .. } => 17 + bytes.len(),
            Self::Size { .. } => 6,
            Self::Input(input) => match input {
                Input::Release => 1,
                Input::Control { .. } => 2,
                Input::Text { .. } | Input::Key { .. } => 5,
                Input::Mouse { .. } => 12,
                Input::Scroll { .. } => 18,
            },
            Self::Repair { .. } => 8,
            Self::Fragment { bytes, .. } => 41 + bytes.len(),
        })
    }
    /// Rejects invalid dimensions, coordinates, flags and fragment arithmetic before any
    /// allocation. The limits are the ones given on each variant above.
    ///
    /// # Errors
    /// Returns a fixed layout error; it contains no payload bytes.
    pub fn validate(self) -> Result<(), DecodeError> {
        let valid = match self {
            Self::Attach { .. } | Self::Repair { .. } => true,
            Self::Video {
                sequence, bytes, ..
            } => sequence > 0 && !bytes.is_empty() && bytes.len() <= MAX_VIDEO_BYTES,
            Self::Size {
                width,
                height,
                density_milli,
            } => {
                (2..=4096).contains(&width)
                    && (2..=4096).contains(&height)
                    && width.is_multiple_of(2)
                    && height.is_multiple_of(2)
                    && u32::from(width) * u32::from(height) <= 4 * 1024 * 1024
                    && (1000..=4000).contains(&density_milli)
            }
            Self::Input(input) => match input {
                Input::Release | Input::Control { .. } => true,
                Input::Text { scalar } => {
                    char::from_u32(scalar).is_some_and(|value| !value.is_control())
                }
                Input::Mouse {
                    x,
                    y,
                    button,
                    state,
                    modifiers,
                } => {
                    x <= 1_000_000
                        && y <= 1_000_000
                        && button <= 2
                        && state <= 2
                        && modifiers & !15 == 0
                }
                Input::Scroll {
                    x, y, modifiers, ..
                } => x <= 1_000_000 && y <= 1_000_000 && modifiers & !15 == 0,
                Input::Key {
                    keycode, modifiers, ..
                } => keycode <= 127 && modifiers & !15 == 0,
            },
            Self::Fragment {
                sequence,
                total,
                offset,
                bytes,
                ..
            } => {
                sequence > 0
                    && total > 0
                    && total as usize <= MAX_VIDEO_BYTES
                    && !bytes.is_empty()
                    && offset.is_multiple_of(1024)
                    && offset < total
                    && bytes.len() == (total - offset).min(1024) as usize
            }
        };
        if valid {
            Ok(())
        } else {
            Err(invalid_body(self.tag(), "invalid desktop fields"))
        }
    }
    /// Appends the body (not the tag or frame length) to `output`. The caller has already
    /// validated the message.
    pub(crate) fn append(self, output: &mut Vec<u8>) {
        match self {
            Self::Attach {
                session_id,
                delivery,
            } => {
                output.extend_from_slice(session_id);
                output.push(delivery as u8);
            }
            Self::Video {
                sequence,
                capture_ns,
                keyframe,
                bytes,
            } => {
                append_video_metadata(sequence, capture_ns, keyframe, output);
                output.extend_from_slice(bytes);
            }
            Self::Size {
                width,
                height,
                density_milli,
            } => {
                output.extend_from_slice(&width.to_le_bytes());
                output.extend_from_slice(&height.to_le_bytes());
                output.extend_from_slice(&density_milli.to_le_bytes());
            }
            Self::Input(input) => match input {
                Input::Release => output.push(3),
                Input::Control { active } => output.extend_from_slice(&[5, u8::from(active)]),
                Input::Text { scalar } => {
                    output.push(4);
                    output.extend_from_slice(&scalar.to_le_bytes());
                }
                Input::Mouse {
                    x,
                    y,
                    button,
                    state,
                    modifiers,
                } => {
                    output.push(0);
                    output.extend_from_slice(&x.to_le_bytes());
                    output.extend_from_slice(&y.to_le_bytes());
                    output.extend_from_slice(&[button, state, modifiers]);
                }
                Input::Scroll {
                    x,
                    y,
                    dx,
                    dy,
                    modifiers,
                } => {
                    output.push(1);
                    output.extend_from_slice(&x.to_le_bytes());
                    output.extend_from_slice(&y.to_le_bytes());
                    output.extend_from_slice(&dx.to_le_bytes());
                    output.extend_from_slice(&dy.to_le_bytes());
                    output.push(modifiers);
                }
                Input::Key {
                    keycode,
                    down,
                    modifiers,
                } => {
                    output.push(2);
                    output.extend_from_slice(&keycode.to_le_bytes());
                    output.extend_from_slice(&[u8::from(down), modifiers]);
                }
            },
            Self::Repair { last_sequence } => {
                output.extend_from_slice(&last_sequence.to_le_bytes());
            }
            Self::Fragment {
                session_id,
                sequence,
                capture_ns,
                keyframe,
                total,
                offset,
                bytes,
            } => {
                output.extend_from_slice(session_id);
                output.extend_from_slice(&sequence.to_le_bytes());
                output.extend_from_slice(&capture_ns.to_le_bytes());
                output.push(u8::from(keyframe));
                output.extend_from_slice(&total.to_le_bytes());
                output.extend_from_slice(&offset.to_le_bytes());
                output.extend_from_slice(bytes);
            }
        }
    }
}
/// Reads the byte at `offset` of a body, or a truncation error naming `tag`.
fn byte(tag: u8, body: &[u8], offset: usize) -> Result<u8, DecodeError> {
    body.get(offset)
        .copied()
        .ok_or_else(|| invalid_body(tag, "truncated desktop field"))
}
/// Reads a boolean byte: `0` is false, `1` is true, anything else is an error.
fn flag(tag: u8, body: &[u8], offset: usize) -> Result<bool, DecodeError> {
    match byte(tag, body, offset)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_body(tag, "invalid desktop flag")),
    }
}
/// Decodes the body of a desktop frame with the given `tag`.
///
/// Returns `UnknownType` for a tag outside `0x40..=0x45`, and an invalid-body error for a body
/// that is too short or too long, has a bad flag or input kind, or fails validation. The result
/// borrows its byte slices from `body`.
pub(crate) fn decode(tag: u8, body: &[u8]) -> Result<Message<'_>, DecodeError> {
    let message = match tag {
        0x40 => {
            ensure_end(tag, body, 17)?;
            Message::Attach {
                session_id: body_array(tag, body, 0)?,
                delivery: byte(tag, body, 16)?.try_into()?,
            }
        }
        0x41 => Message::Video {
            sequence: body_u64(tag, body, 0)?,
            capture_ns: body_u64(tag, body, 8)?,
            keyframe: flag(tag, body, 16)?,
            bytes: body
                .get(17..)
                .ok_or_else(|| invalid_body(tag, "missing video"))?,
        },
        0x42 => {
            ensure_end(tag, body, 6)?;
            Message::Size {
                width: body_u16(tag, body, 0)?,
                height: body_u16(tag, body, 2)?,
                density_milli: body_u16(tag, body, 4)?,
            }
        }
        0x43 => Message::Input(match byte(tag, body, 0)? {
            0 => {
                ensure_end(tag, body, 12)?;
                Input::Mouse {
                    x: body_u32(tag, body, 1)?,
                    y: body_u32(tag, body, 5)?,
                    button: byte(tag, body, 9)?,
                    state: byte(tag, body, 10)?,
                    modifiers: byte(tag, body, 11)?,
                }
            }
            1 => {
                ensure_end(tag, body, 18)?;
                Input::Scroll {
                    x: body_u32(tag, body, 1)?,
                    y: body_u32(tag, body, 5)?,
                    dx: i32::from_le_bytes(*body_array(tag, body, 9)?),
                    dy: i32::from_le_bytes(*body_array(tag, body, 13)?),
                    modifiers: byte(tag, body, 17)?,
                }
            }
            2 => {
                ensure_end(tag, body, 5)?;
                Input::Key {
                    keycode: body_u16(tag, body, 1)?,
                    down: flag(tag, body, 3)?,
                    modifiers: byte(tag, body, 4)?,
                }
            }
            5 => {
                ensure_end(tag, body, 2)?;
                Input::Control {
                    active: flag(tag, body, 1)?,
                }
            }
            4 => {
                ensure_end(tag, body, 5)?;
                Input::Text {
                    scalar: body_u32(tag, body, 1)?,
                }
            }
            3 => {
                ensure_end(tag, body, 1)?;
                Input::Release
            }
            _ => return Err(invalid_body(tag, "unknown desktop input")),
        }),
        0x44 => {
            ensure_end(tag, body, 8)?;
            Message::Repair {
                last_sequence: body_u64(tag, body, 0)?,
            }
        }
        0x45 => Message::Fragment {
            session_id: body_array(tag, body, 0)?,
            sequence: body_u64(tag, body, 16)?,
            capture_ns: body_u64(tag, body, 24)?,
            keyframe: flag(tag, body, 32)?,
            total: body_u32(tag, body, 33)?,
            offset: body_u32(tag, body, 37)?,
            bytes: body
                .get(41..)
                .ok_or_else(|| invalid_body(tag, "missing fragment"))?,
        },
        _ => return Err(DecodeError::UnknownType(tag)),
    };
    message.validate()?;
    Ok(message)
}

/// Encodes only the header of a `Video` frame, for scatter/gather transport.
///
/// `output` is cleared and filled with the frame length, the tag and the 17-byte video header,
/// and the number of bytes written is returned. The caller then sends `bytes` itself, unchanged
/// and before any later frame, so the payload is never copied. Bounds checks and metadata
/// are the same as the ordinary encoder's, without allocating a stand-in payload.
///
/// # Errors
/// Refuses an invalid sequence, empty or oversize `bytes`, or frame length overflow.
pub fn encode_video_prefix_into(
    sequence: u64,
    capture_ns: u64,
    keyframe: bool,
    bytes: &[u8],
    output: &mut Vec<u8>,
) -> Result<usize, EncodeError> {
    let message = Message::Video {
        sequence,
        capture_ns,
        keyframe,
        bytes,
    };
    let frame_len = crate::validate_frame_len(message.len()?)?;
    output.clear();
    output.reserve(crate::varint_len_u32(frame_len) + 18);
    crate::write_varint(frame_len, output);
    output.push(message.tag());
    append_video_metadata(sequence, capture_ns, keyframe, output);
    Ok(output.len())
}
/// Appends the 17-byte `Video` header: `sequence`, `capture_ns`, then the keyframe flag.
fn append_video_metadata(sequence: u64, capture_ns: u64, keyframe: bool, output: &mut Vec<u8>) {
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(&capture_ns.to_le_bytes());
    output.push(u8::from(keyframe));
}
