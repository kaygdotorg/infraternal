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
