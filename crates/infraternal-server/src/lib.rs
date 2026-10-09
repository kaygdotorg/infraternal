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
#[cfg(feature = "ssh")]
pub mod ssh_key;
mod web_assets;
mod websocket;

pub use runtime::{ProxyNetwork, ServerConfig, ServerError, TlsFiles, serve};

#[cfg(feature = "ssh")]
pub mod bootstrap_api;
#[cfg(feature = "ssh")]
pub mod bootstrap_runtime;

/// Feature-selected declarations have no runtime work or initialization side effects.
#[must_use]
pub fn compiled_plugins() -> &'static [&'static infraternal_plugin_api::PluginDescriptor] {
    COMPILED_PLUGINS
}

static COMPILED_PLUGINS: &[&infraternal_plugin_api::PluginDescriptor] = &[
    #[cfg(feature = "ssh")]
    &infraternal_plugin_ssh::manifest::DESCRIPTOR,
];
