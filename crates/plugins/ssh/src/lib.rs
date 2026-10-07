//! Implements SSH as the first plugin for saved hosts and hosts without an infraternal agent [4][15][21][22].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod model;
pub mod probe;
