//! Capture abstraction keeps framework objects and replacement bindings private [D204].
use crate::protocol::{Size, Target};
use std::io;

/// Platform-neutral capture rectangle in desktop points.
#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct Rect {
    /// Left edge.
    pub x: f64,
    /// Top edge.
    pub y: f64,
    pub width: f64,
    pub height: f64,
}
impl Rect {
    /// True when every value is finite and the width and height are positive.
    #[must_use]
    pub fn valid(self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|v| v.is_finite())
            && self.width > 0.0
            && self.height > 0.0
    }
}

/// Display-change timestamp retained until an owned capture reaches the encoder.
pub trait CapturedFrame {
    /// When the display changed, in the platform's capture clock ticks.
    fn capture_ticks(&self) -> u64;
}

/// A running capture of one window or display, behind a platform-neutral API.
///
/// Latest-frame delivery replaces queued frames rather than increasing latency.
pub trait Capture {
    /// What [`Capture::take_latest`] hands out.
    type Frame: CapturedFrame;
    /// Starts capturing `target` into an output of `size` pixels showing `rect`
    /// (in desktop points).
    ///
    /// # Errors
    /// Refuses unavailable identities, invalid geometry and framework failure.
    fn start(target: &Target, size: Size, rect: Rect) -> io::Result<Self>
    where
        Self: Sized;
    /// # Errors
    /// Reports update failure without silently falling back to whole-screen capture.
    fn resize(&mut self, size: Size, rect: Rect) -> io::Result<()>;
    /// Copies the current picture out as BGRA bytes, 4 per pixel.
    ///
    /// # Errors
    /// Reports safe owned-pixel capture failure; never exposes an aliased framework buffer.
    fn copy_pixels(&self) -> io::Result<Vec<u8>>;
    /// Takes the newest frame captured since the last call, or `None` if there
    /// is none. Older frames are dropped, never queued.
    fn take_latest(&self) -> Option<Self::Frame>;
    /// Stops capturing.
    ///
    /// # Errors
    /// Reports failure to stop the underlying framework stream.
    fn stop(&mut self) -> io::Result<()>;
}
