//! Owns managed proxy acquisition, node-local configuration, custody and supervision [D316], #281.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod custody;
pub mod installer;
pub mod manifest;
pub mod names;
pub mod cli;

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod manifest_tests;

#[cfg(test)]
#[path = "installer_tests.rs"]
mod installer_tests;

#[cfg(test)]
#[path = "names_tests.rs"]
mod names_tests;

#[cfg(test)]
#[path = "cli_tests.rs"]
mod cli_tests;
