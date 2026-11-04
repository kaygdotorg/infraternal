//! Native desktop capture and local helper lifecycle, removable at build time [D198,D203,D204,D208].
//!
//! The crate has three roles, each behind a Cargo feature so a build can leave
//! out what it does not need:
//!
//! - `desktop`: the per-user helper that runs inside a logged-in macOS session
//!   (`component`, `helper`, `macos`, `native`, `socket`).
//! - `source`: the part of the infraternal agent that serves a host's windows to
//!   the server (`source`, `source_request`, `source_manifest`).
//! - `server`: the part of the server that owns sessions and talks to browsers
//!   (`server`, `session`, `registry`, `relay`, `delivery`).
//!
//! `protocol` (helper wire format), `wire` and `media` are shared. The
//! crate forbids `unsafe` code.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
/// Platform-neutral capture trait and geometry.
pub mod capture;
/// Runs the helper as a switchable child process.
#[cfg(feature = "desktop")]
pub mod component;
#[cfg(all(feature = "desktop", test, not(target_os = "macos")))]
mod macos {
    //! Supplies inert owned capture bindings to Linux unit builds of the helper.
    use crate::{
        capture::{Capture, CapturedFrame, Rect},
        protocol::{Size, Target},
    };
    use std::io;

    pub struct MacCapture(Size);

    pub struct Frame;

    impl CapturedFrame for Frame {
        fn capture_ticks(&self) -> u64 {
            0
        }
    }

    impl Capture for MacCapture {
        type Frame = Frame;

        fn start(_: &Target, size: Size, _: Rect) -> io::Result<Self> {
            Ok(Self(size))
        }

        fn resize(&mut self, size: Size, _: Rect) -> io::Result<()> {
            self.0 = size;
            Ok(())
        }

        fn copy_pixels(&self) -> io::Result<Vec<u8>> {
            Ok(vec![0; self.0.width as usize * self.0.height as usize * 4])
        }

        fn take_latest(&self) -> Option<Self::Frame> {
            Some(Frame)
        }

        fn stop(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
#[cfg(all(feature = "desktop", any(target_os = "macos", test)))]
/// One helper client session: commands in, video and state out.
pub mod helper;
#[cfg(all(feature = "desktop", target_os = "macos"))]
/// `ScreenCaptureKit` implementation of the capture trait.
pub mod macos;
#[cfg(feature = "desktop")]
/// Descriptor and actions of the helper plugin.
pub mod manifest;
#[cfg(all(feature = "desktop", any(target_os = "macos", test)))]
/// Supervision of the native companion process.
pub mod native;
/// Framing and message types spoken between the helper and its clients.
pub mod protocol;
#[cfg(test)]
mod protocol_tests;
#[cfg(feature = "desktop")]
/// The helper's private Unix socket: creation, checks and peer admission.
pub mod socket;

#[cfg(any(feature = "source", feature = "server"))]
/// Splitting video access units into datagram fragments and putting them back together.
pub mod datagram;
#[cfg(any(
    feature = "source",
    feature = "server",
    all(feature = "desktop", any(target_os = "macos", test))
))]
mod measurement;
#[cfg(any(feature = "source", feature = "server"))]
/// Video access unit type, shared error and timing constants.
pub mod media;
#[cfg(feature = "source")]
/// The source plugin that the infraternal agent runs on a host.
pub mod source;
#[cfg(feature = "source")]
mod source_inventory;
#[cfg(feature = "source")]
mod source_ipc;
#[cfg(feature = "source")]
/// Descriptor and actions of the source plugin.
pub mod source_manifest;
#[cfg(feature = "source")]
/// Decoding of source actions into typed requests.
pub mod source_request;
#[cfg(feature = "source")]
mod source_worker;
#[cfg(any(feature = "source", feature = "server"))]
/// The desktop data-lane declaration shared by source and server.
pub mod wire;

#[cfg(feature = "server")]
/// Delivery of video frames to viewers over reliable or datagram lanes.
pub mod delivery;
#[cfg(feature = "server")]
/// Choosing which H.264 parameter sets a viewer's keyframes carry.
pub mod parameter_sets;
#[cfg(feature = "server")]
/// Lookup table of live sessions that viewers can attach to.
pub mod registry;
#[cfg(feature = "server")]
/// Moves video and commands between a session and its host data lane.
pub mod relay;
#[cfg(feature = "server")]
/// The server plugin: actions, sessions and viewers.
pub mod server;
#[cfg(feature = "server")]
/// Descriptor and actions of the server plugin.
pub mod server_manifest;
#[cfg(feature = "server")]
/// One capture session: latest-frame sharing, viewers and input control.
pub mod session;
