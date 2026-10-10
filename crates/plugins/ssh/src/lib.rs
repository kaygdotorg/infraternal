//! Implements SSH as the first plugin for saved hosts and hosts without an infraternal agent [4][15][21][22].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod auth_once;
pub mod auth_order;
pub mod bootstrap;
pub mod config;
pub mod credentials;
pub mod install;
mod lifecycle;

pub mod manifest;
pub mod master;
pub mod model;
pub mod openssh;
pub mod probe;
pub mod process;
mod prompt;
pub mod transport;
pub mod trust;
