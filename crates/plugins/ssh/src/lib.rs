//! Implements SSH as the first plugin for saved hosts and hosts without an infraternal agent [4][15][21][22].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod auth_evidence;
pub mod auth_once;
pub mod auth_order;
pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod credentials;
pub mod duplex;
pub mod install;
mod lifecycle;
pub mod stdio;

pub mod manifest;
pub mod master;
pub mod model;
pub mod openssh;
mod payload;
mod payload_encoding;
pub mod previous_attempt;
pub mod probe;
pub mod process;
mod prompt;
mod prompt_image;
pub mod socket_connector;
pub mod transport;
pub mod trust;

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod test_common;
