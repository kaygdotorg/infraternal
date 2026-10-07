//! Owns trusted identity, roles, audit, state, API, and routing; it relays host work through infraternal agents [8][9][10][19].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod auth;
pub mod ca;
pub mod ca_memory;
pub mod csr;
mod embedded;
pub mod enrollment;
pub mod remote_enrollment;
mod runtime;
mod web_assets;
mod websocket;

pub use runtime::{ProxyNetwork, ServerConfig, ServerError, TlsFiles, serve};

pub mod bootstrap_api;
