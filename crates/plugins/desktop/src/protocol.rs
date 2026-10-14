//! Bounded local helper framing; headers are validated before payload allocation [D12,D40,D203].
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 4 * 1024 * 1024;
pub const MAX_CONTROL: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    List = 1,
    Start = 2,
    Resize = 3,
    Input = 4,
    Stop = 5,
    Status = 6,
    Keyframe = 7,
    ReleaseInput = 8,
    Congested = 9,
    Control = 10,
    Windows = 65,
    Geometry = 66,
    InputResult = 67,
    State = 68,
    Error = 69,
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

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Invalid desktop helper message.",
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub payload: &'a [u8],
}

/// Decode without allocation; incomplete input consumes nothing.
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Window { window_id: u32, owner_pid: i32 },
    Screen { display_id: u32 },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Size {
    pub width: u32,
    pub height: u32,
    pub canvas_width: f64,
    pub canvas_height: f64,
    pub backing_scale: f64,
}
impl Size {
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub target: Target,
    pub size: Size,
}
impl Start {
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Input {
    Text {
        scalar: u32,
    },
    Mouse {
        x: f64,
        y: f64,
        button: u8,
        state: u8,
        modifiers: u8,
    },
    Scroll {
        x: f64,
        y: f64,
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
impl Input {
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
