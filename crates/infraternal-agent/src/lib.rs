//! Runs on each managed host and owns its local PTY and engine work [9][13][18].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
pub mod relay;
