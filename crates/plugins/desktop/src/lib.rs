//! Native desktop capture and local helper lifecycle, removable at build time [D198,D203,D204,D208].
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod capture;
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
pub mod helper;
#[cfg(all(feature = "desktop", target_os = "macos"))]
pub mod macos;
#[cfg(feature = "desktop")]
pub mod manifest;
#[cfg(all(feature = "desktop", any(target_os = "macos", test)))]
pub mod native;
pub mod protocol;
#[cfg(test)]
mod protocol_tests;
#[cfg(feature = "desktop")]
pub mod socket;

#[cfg(any(feature = "source", feature = "server"))]
pub mod datagram;
#[cfg(any(
    feature = "source",
    feature = "server",
    all(feature = "desktop", any(target_os = "macos", test))
))]
mod measurement;
#[cfg(any(feature = "source", feature = "server"))]
pub mod media;
#[cfg(feature = "source")]
pub mod source;
#[cfg(feature = "source")]
mod source_inventory;
#[cfg(feature = "source")]
mod source_ipc;
#[cfg(feature = "source")]
pub mod source_manifest;
#[cfg(feature = "source")]
pub mod source_request;
#[cfg(feature = "source")]
mod source_worker;
#[cfg(any(feature = "source", feature = "server"))]
pub mod wire;

#[cfg(feature = "server")]
pub mod delivery;
#[cfg(feature = "server")]
pub mod parameter_sets;
#[cfg(feature = "server")]
pub mod registry;
#[cfg(feature = "server")]
pub mod relay;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod server_manifest;
#[cfg(feature = "server")]
pub mod session;
