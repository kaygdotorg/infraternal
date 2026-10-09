//! Owns trusted identity, roles, audit, state, API, and routing; it relays host work through infraternal agents [8][9][10][19].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod auth;
#[cfg(feature = "remote")]
pub mod ca;
#[cfg(feature = "remote")]
pub mod ca_administration;
#[cfg(feature = "remote")]
pub mod ca_copies;
#[cfg(feature = "remote")]
pub mod ca_http;
#[cfg(feature = "remote")]
pub mod ca_membership;
#[cfg(feature = "remote")]
pub mod ca_memory;
#[cfg(feature = "remote")]
pub mod csr;
mod embedded;
#[cfg(feature = "remote")]
pub mod enrollment;
#[cfg(feature = "remote")]
mod remote_accept;
#[cfg(feature = "remote")]
mod remote_admission;
#[cfg(feature = "remote")]
pub mod remote_enrollment;
#[cfg(feature = "remote")]
mod remote_guard;
#[cfg(feature = "remote")]
pub mod remote_http;
#[cfg(feature = "remote")]
mod remote_link;
#[cfg(feature = "remote")]
mod remote_renewal;
#[cfg(feature = "remote")]
mod remote_runtime;
#[cfg(feature = "remote")]
mod remote_startup;
mod runtime;
mod server_tls;
mod web_assets;
mod websocket;

#[cfg(feature = "remote")]
pub use remote_runtime::RemoteService;
#[cfg(feature = "remote")]
pub use remote_startup::RemoteStartup;
pub use runtime::{ProxyNetwork, ServerConfig, ServerError, TlsFiles, configure_logging, serve};
#[cfg(feature = "remote")]
pub use runtime::{serve_with_enrollment, serve_with_remote};
