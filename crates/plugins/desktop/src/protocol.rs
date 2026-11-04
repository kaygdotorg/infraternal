//! Bounded local helper framing; headers are validated before payload allocation [D12,D40,D203].
//!
//! The wire format between the desktop helper and its clients (and between the
//! helper and its native companion). Each message is:
//!
//! - 4 bytes: big-endian length of everything after these 4 bytes;
//! - 1 byte: protocol [`VERSION`];
//! - 1 byte: the message [`Kind`];
//! - the payload: a JSON object, except for [`Kind::Video`].
//!
//! A video payload starts with an 8-byte capture timestamp and a 1-byte keyframe
//! flag (0 or 1), followed by the encoded frame.
//!
//! Headers are checked before any payload is allocated: the version, the kind and
//! the size limits ([`MAX_FRAME`] for video, [`MAX_CONTROL`] for everything else).
//! [`validate_command`] checks the body of a request before anything acts on it.
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// The protocol version byte; any other value is rejected.
pub const VERSION: u8 = 1;
/// Largest allowed message (length field), in bytes: 4 MiB. Applies to video.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
/// Largest allowed non-video message, in bytes: 64 KiB.
pub const MAX_CONTROL: usize = 64 * 1024;

/// The message type byte. Values 1-10 are requests from a client; values from
/// 65 up are replies and video from the helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Request the list of windows and displays.
    List = 1,
    /// Start capturing a target (body: [`Start`]).
    Start = 2,
    /// Change output size (body: [`Size`]).
    Resize = 3,
    /// Send keyboard, mouse or scroll input (body: [`Input`]).
    Input = 4,
    /// Stop the current capture.
    Stop = 5,
    /// Ask for current state and geometry.
    Status = 6,
    /// Ask for a new keyframe.
    Keyframe = 7,
    /// Release any keys or buttons currently held down.
    ReleaseInput = 8,
    /// Tell the encoder the viewer's connection is backed up.
    Congested = 9,
    /// Take or give up input control (body: `{"active": bool}`).
    Control = 10,
    /// Reply: the window and display inventory.
    Windows = 65,
    /// Reply: the actual captured area.
    Geometry = 66,
    /// Reply: outcome of an input event.
    InputResult = 67,
    /// Reply: current state.
    State = 68,
    /// Reply: the request failed.
    Error = 69,
    /// An encoded video frame.
    Video = 70,
}
impl TryFrom<u8> for Kind {
    type Error = io::Error;
    fn try_from(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::List),
            2 => Ok(Self::Start),
            3 => Ok(Self::Resize),
            4 => Ok(Self::Input),
            5 => Ok(Self::Stop),
            6 => Ok(Self::Status),
            7 => Ok(Self::Keyframe),
            8 => Ok(Self::ReleaseInput),
            9 => Ok(Self::Congested),
            10 => Ok(Self::Control),
            65 => Ok(Self::Windows),
            66 => Ok(Self::Geometry),
            67 => Ok(Self::InputResult),
            68 => Ok(Self::State),
            69 => Ok(Self::Error),
            70 => Ok(Self::Video),
            _ => Err(invalid()),
        }
    }
}

/// The one generic error for any malformed message, so the text reveals nothing
/// about what was wrong.
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid desktop helper message.",
    )
}

/// One decoded message, borrowing its payload from the input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: Kind,
    /// The bytes after the six-byte header.
    pub payload: &'a [u8],
}

/// Decode without allocation; incomplete input consumes nothing.
///
/// Returns `Ok(None)` when more bytes are needed. On success returns the frame
/// and the total number of bytes it occupies (header included), so the caller
/// can drop that many from its buffer.
/// # Errors
/// Rejects invalid length, version, kind, or video prefix before exposing bytes.
pub fn decode(bytes: &[u8]) -> io::Result<Option<(Frame<'_>, usize)>> {
    let Some(prefix) = bytes.get(..4) else {
        return Ok(None);
    };
    let length = u32::from_be_bytes(prefix.try_into().map_err(|_| invalid())?) as usize;
    if !(2..=MAX_FRAME).contains(&length) {
        return Err(invalid());
    }
    if bytes.get(4).is_some_and(|version| *version != VERSION) {
        return Err(invalid());
    }
    let Some(&tag) = bytes.get(5) else {
        return Ok(None);
    };
    let kind = Kind::try_from(tag)?;
    if kind != Kind::Video && length > MAX_CONTROL || kind == Kind::Video && length < 12 {
        return Err(invalid());
    }
    let Some(payload) = bytes.get(6..length + 4) else {
        return Ok(None);
    };
    if kind == Kind::Video && payload[8] > 1 {
        return Err(invalid());
    }
    Ok(Some((Frame { kind, payload }, length + 4)))
}

/// Read exactly one frame, validating its six-byte header before allocation.
///
/// Blocks until the whole message arrives. Returns the kind and the payload
/// (without the header).
/// # Errors
/// Reports framing or I/O failure, including EOF in a partial message.
pub fn read(reader: &mut impl Read) -> io::Result<(Kind, Vec<u8>)> {
    let mut header = [0; 6];
    reader.read_exact(&mut header)?;
    let _ = decode(&header)?;
    let length = u32::from_be_bytes(header[..4].try_into().map_err(|_| invalid())?) as usize;
    let mut bytes = vec![0; length + 4];
    bytes[..6].copy_from_slice(&header);
    reader.read_exact(&mut bytes[6..])?;
    let (frame, _) = decode(&bytes)?.ok_or_else(invalid)?;
    let kind = frame.kind;
    bytes.drain(..6);
    Ok((kind, bytes))
}

/// Write one bounded message; never silently truncate a frame.
/// # Errors
/// Reports bounds, malformed video metadata or writer failure.
pub fn write(writer: &mut impl Write, kind: Kind, payload: &[u8]) -> io::Result<()> {
    let length = payload.len().checked_add(2).ok_or_else(invalid)?;
    if length > MAX_FRAME
        || kind != Kind::Video && length > MAX_CONTROL
        || kind == Kind::Video && (payload.len() < 10 || payload[8] > 1)
    {
        return Err(invalid());
    }
    let length = u32::try_from(length).map_err(|_| invalid())?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&[VERSION, kind as u8])?;
    writer.write_all(payload)
}

/// What to capture.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    /// One application window. The process id guards against a recycled window id.
    Window { window_id: u32, owner_pid: i32 },
    /// A whole display.
    Screen { display_id: u32 },
}

/// The output size of a capture.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Size {
    /// Output width in pixels (even, 2 to 4096).
    pub width: u32,
    /// Output height in pixels (even, 2 to 4096).
    pub height: u32,
    /// Viewer canvas width in points.
    pub canvas_width: f64,
    /// Viewer canvas height in points.
    pub canvas_height: f64,
    /// Pixels per point (1 to 4). `canvas * backing_scale` must match the pixel
    /// size to within one pixel.
    pub backing_scale: f64,
}
impl Size {
    /// Checks the size is usable: even dimensions within 4096 and 4 Mi pixels
    /// total, and consistent, finite point geometry.
    ///
    /// # Errors
    /// Bounds pixel memory and refuses nonfinite or inconsistent point geometry.
    pub fn validate(self) -> io::Result<()> {
        if self.width < 2
            || self.height < 2
            || self.width > 4096
            || self.height > 4096
            || u64::from(self.width) * u64::from(self.height) > 4 * 1024 * 1024
            || !self.width.is_multiple_of(2)
            || !self.height.is_multiple_of(2)
            || !self.backing_scale.is_finite()
            || !(1.0..=4.0).contains(&self.backing_scale)
            || !self.canvas_width.is_finite()
            || !self.canvas_height.is_finite()
            || self.canvas_width <= 0.0
            || self.canvas_height <= 0.0
            || (self.canvas_width * self.backing_scale - f64::from(self.width)).abs() > 1.0
            || (self.canvas_height * self.backing_scale - f64::from(self.height)).abs() > 1.0
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Body of a [`Kind::Start`] request: what to capture and at what size.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub target: Target,
    pub size: Size,
}
impl Start {
    /// Checks the size and that the target ids are non-zero (and the process id positive).
    ///
    /// # Errors
    /// Applies the existing helper target and geometry bounds without JSON work.
    pub fn validate(&self) -> io::Result<()> {
        self.size.validate()?;
        if matches!(
            self.target,
            Target::Window { window_id: 0, .. }
                | Target::Window {
                    owner_pid: ..=0,
                    ..
                }
                | Target::Screen { display_id: 0 }
        ) {
            return Err(invalid());
        }
        Ok(())
    }
}

/// One input event sent to the captured window or display. Positions are in the
/// viewer canvas's points, from 0 to 4096.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    /// Typed text: one Unicode scalar value (not a control character).
    Text { scalar: u32 },
    /// Mouse button or movement. `button` and `state` are each 0 to 2.
    Mouse {
        x: f64,
        y: f64,
        button: u8,
        state: u8,
        /// Modifier-key bit set, at most 15.
        modifiers: u8,
    },
    /// Scroll at a position by `dx`, `dy`.
    Scroll {
        x: f64,
        y: f64,
        dx: i32,
        dy: i32,
        modifiers: u8,
    },
    /// A physical key press (`down`) or release; `keycode` is 0 to 127.
    Key {
        keycode: u16,
        down: bool,
        modifiers: u8,
    },
}
impl Input {
    /// Checks the event is in range: finite positions inside the canvas bounds, a
    /// known key code, button and state values, and valid modifier bits.
    ///
    /// # Errors
    /// Rejects unsupported physical codes, modifier bits and nonfinite positions.
    pub fn validate(self) -> io::Result<()> {
        let (modifiers, valid) = match self {
            Self::Text { scalar } => (
                0,
                char::from_u32(scalar).is_some_and(|value| !value.is_control()),
            ),
            Self::Mouse {
                x,
                y,
                button,
                state,
                modifiers,
            } => (
                modifiers,
                x.is_finite()
                    && y.is_finite()
                    && x >= 0.0
                    && y >= 0.0
                    && x <= 4096.0
                    && y <= 4096.0
                    && button <= 2
                    && state <= 2,
            ),
            Self::Scroll {
                x, y, modifiers, ..
            } => (
                modifiers,
                x.is_finite()
                    && y.is_finite()
                    && x >= 0.0
                    && y >= 0.0
                    && x <= 4096.0
                    && y <= 4096.0,
            ),
            Self::Key {
                keycode, modifiers, ..
            } => (modifiers, keycode <= 127),
        };
        if valid && modifiers <= 15 {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

/// Validate commands before any native side effect.
///
/// `payload` must be a JSON object shaped for `kind`: [`Start`], [`Size`],
/// [`Input`], `{"active": bool}` for control, or `{}` for the argument-less
/// requests. Reply kinds and video are never valid commands.
/// # Errors
/// Refuses response kinds as requests and invalid/malformed control bodies.
pub fn validate_command(kind: Kind, payload: &[u8]) -> io::Result<()> {
    // Empty Serde structs accept sequences too; require a JSON object before dispatch.
    if payload.len() + 2 > MAX_CONTROL
        || payload.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(invalid());
    }
    match kind {
        Kind::Start => serde_json::from_slice::<Start>(payload)
            .map_err(|_| invalid())?
            .validate()?,
        Kind::Control => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Control {
                active: bool,
            }
            let control: Control = serde_json::from_slice(payload).map_err(|_| invalid())?;
            let _ = control.active;
        }
        Kind::Resize => serde_json::from_slice::<Size>(payload)
            .map_err(|_| invalid())?
            .validate()?,
        Kind::Input => serde_json::from_slice::<Input>(payload)
            .map_err(|_| invalid())?
            .validate()?,
        Kind::List
        | Kind::Stop
        | Kind::Status
        | Kind::Keyframe
        | Kind::ReleaseInput
        | Kind::Congested => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Empty {}
            let _: Empty = serde_json::from_slice(payload).map_err(|_| invalid())?;
        }
        _ => return Err(invalid()),
    }
    Ok(())
}
