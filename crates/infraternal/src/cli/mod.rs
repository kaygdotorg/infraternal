//! Provides shared command output, action registration, and help adapters.

pub mod actions;
pub mod command_tree;
pub mod output;
pub mod skills;
pub mod usage;

#[cfg(all(feature = "plugin-agent", target_os = "linux"))]
pub mod sessions;
