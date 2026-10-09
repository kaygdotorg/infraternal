//! Owns trusted identity, roles, audit, state, API, and routing; it relays host work through infraternal agents [8][9][10][19].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod auth;
pub mod ca;
pub mod ca_copies;
pub mod ca_membership;
pub mod ca_memory;
pub mod csr;
mod embedded;
pub mod enrollment;
pub mod remote_enrollment;
mod remote_guard;
pub mod remote_http;
mod remote_link;
mod remote_renewal;
mod remote_runtime;
mod remote_startup;
mod runtime;
mod server_tls;
mod web_assets;
mod websocket;

pub use remote_runtime::RemoteService;
pub use remote_startup::RemoteStartup;
pub use runtime::{
    ProxyNetwork, ServerConfig, ServerError, TlsFiles, serve, serve_with_enrollment,
    serve_with_remote,
};
