//! Owns managed proxy acquisition, node-local configuration, custody and supervision [D316], #281.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod custody;

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;
