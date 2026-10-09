//! Owns trusted identity, roles, audit, state, API, and routing; it relays host work through infraternal agents [8][9][10][19].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod auth;
#[cfg(feature = "cli-plugin")]
pub mod cli;
mod embedded;
mod runtime;
mod web_assets;
mod websocket;

pub use runtime::{ProxyNetwork, ServerConfig, ServerError, TlsFiles, serve};
