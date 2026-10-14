//! Native desktop capture and local helper lifecycle, removable at build time [D198,D203,D204,D208].
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod capture;
#[cfg(feature = "desktop")]
pub mod component;
#[cfg(all(feature = "desktop", target_os = "macos"))]
pub mod helper;
#[cfg(all(feature = "desktop", target_os = "macos"))]
pub mod macos;
#[cfg(feature = "desktop")]
pub mod manifest;
#[cfg(all(feature = "desktop", target_os = "macos"))]
pub mod native;
pub mod protocol;
#[cfg(test)]
mod protocol_tests;
#[cfg(feature = "desktop")]
pub mod socket;

#[cfg(feature = "source")]
pub mod datagram;
#[cfg(feature = "source")]
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
#[cfg(feature = "source")]
pub mod wire;
