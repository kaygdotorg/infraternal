//! Borrowed binary desktop messages shared by relay streams and QUIC fragments [D12,D104,D232].
use crate::{
    DecodeError, EncodeError, MAX_FRAME_LEN, body_array, body_u16, body_u32, body_u64, ensure_end,
    invalid_body,
};

/// Browser leg-A capability, independent of native leg-B core capabilities.
pub const CAPABILITY: u64 = 1 << 4;
/// Leg B reserves bits 0–7 for transport control; desktop uses the first native lane bit.
pub const NATIVE_CAPABILITY: u64 = 1 << 8;
/// Access units leave room for the largest desktop header inside the frozen frame limit.
pub const MAX_VIDEO_BYTES: usize = MAX_FRAME_LEN - 42;

/// Both delivery candidates stay explicit until the owner selects one from measurements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Delivery {
    Reliable = 0,
    Datagram = 1,
}
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

/// Input coordinates are unsigned millionths of the current output frame, including letterbox bands.
/// This avoids nonfinite floating point values and preserves subpixel positioning at 4096px.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// Ordered cleanup relinquishes held keys and buttons without replay.
    Release,
    /// One committed Unicode scalar; the helper posts its UTF-16 without layout loss.
    Text { scalar: u32 },
    /// Server-generated control-session visibility; viewers cannot originate it.
    Control { active: bool },
    Mouse {
        x: u32,
        y: u32,
        button: u8,
        state: u8,
        modifiers: u8,
    },
    Scroll {
        x: u32,
        y: u32,
        dx: i32,
        dy: i32,
        modifiers: u8,
    },
    Key {
        keycode: u16,
        down: bool,
        modifiers: u8,
    },
}

/// Allocation-free desktop payload; mux/native stream ownership is enforced by the plugin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message<'a> {
    Attach {
        session_id: &'a [u8; 16],
        delivery: Delivery,
    },
    Video {
        sequence: u64,
        capture_ns: u64,
        keyframe: bool,
        bytes: &'a [u8],
    },
    Size {
        width: u16,
        height: u16,
        density_milli: u16,
    },
    Input(Input),
    Repair {
        last_sequence: u64,
    },
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
    /// Reject invalid dimensions, coordinates, flags and fragment arithmetic before allocation.
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
fn byte(tag: u8, body: &[u8], offset: usize) -> Result<u8, DecodeError> {
    body.get(offset)
        .copied()
        .ok_or_else(|| invalid_body(tag, "truncated desktop field"))
}
fn flag(tag: u8, body: &[u8], offset: usize) -> Result<bool, DecodeError> {
    match byte(tag, body, offset)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_body(tag, "invalid desktop flag")),
    }
}
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

/// Encode only the canonical video header for scatter/gather transport.
/// The caller appends the same immutable payload before any later frame. Bounds
/// and metadata share the ordinary encoder; no dummy payload allocation occurs.
/// # Errors
/// Refuses invalid sequence, empty/oversize data or frame arithmetic overflow.
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
fn append_video_metadata(sequence: u64, capture_ns: u64, keyframe: bool, output: &mut Vec<u8>) {
    output.extend_from_slice(&sequence.to_le_bytes());
    output.extend_from_slice(&capture_ns.to_le_bytes());
    output.push(u8::from(keyframe));
}
