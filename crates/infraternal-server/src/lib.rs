//! Owns trusted identity, roles, audit, state, API, and routing; it relays host work through infraternal agents [8][9][10][19].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod auth;
mod embedded;
/// Compatibility path for existing Rust adapters; implementation belongs to the plugin.
#[cfg(feature = "mesh")]
pub use infraternal_plugin_mesh::api as mesh_api;
#[cfg(all(test, feature = "mesh"))]
mod mesh_api_tests;
mod runtime;
mod web_assets;
mod websocket;

pub use runtime::{ProxyNetwork, ServerConfig, ServerError, TlsFiles, serve};
