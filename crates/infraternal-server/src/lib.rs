//! Owns trusted identity, roles, audit, state, API, and routing; it relays host work through infraternal agents [8][9][10][19].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

/// Shared compiled release identity; channel policy remains in the release plugin [225,226].
pub use infraternal_plugin_api::{VERSION, release_version};
pub mod auth;
#[cfg(feature = "remote")]
pub mod ca;
#[cfg(feature = "remote")]
pub mod ca_administration;
#[cfg(feature = "remote")]
pub mod ca_bootstrap;
#[cfg(feature = "remote")]
pub mod ca_copies;
#[cfg(feature = "remote")]
pub mod ca_handoff;
#[cfg(feature = "remote")]
pub mod ca_handoff_binary;
#[cfg(feature = "remote")]
pub mod ca_http;
#[cfg(feature = "remote")]
pub mod ca_membership;
#[cfg(feature = "remote")]
pub mod ca_memory;
#[cfg(feature = "cli-plugin")]
pub mod cli;
#[cfg(feature = "remote")]
pub mod csr;
mod embedded;
mod node_bridge;
#[cfg(any(feature = "ssh", feature = "release"))]
mod release_http;
#[cfg(feature = "release")]
mod release_latest;
#[cfg(feature = "release")]
pub use release_latest::release_service;
pub mod release_manifest;
pub mod release_verify;
/// Compatibility path for existing Rust adapters; implementation belongs to the plugin.
#[cfg(feature = "mesh")]
pub use infraternal_plugin_mesh::api as mesh_api;
#[cfg(feature = "remote")]
pub mod enrollment;
#[cfg(all(test, feature = "mesh"))]
mod mesh_api_tests;
pub mod plugins;
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
#[cfg(all(test, feature = "mesh", feature = "remote"))]
mod remote_mesh_revocation_tests;
#[cfg(feature = "remote")]
mod remote_renewal;
#[cfg(feature = "remote")]
mod remote_runtime;
#[cfg(feature = "remote")]
mod remote_standby;
#[cfg(feature = "remote")]
pub mod remote_standby_request;
#[cfg(feature = "remote")]
mod remote_startup;
mod runtime;
mod server_tls;
mod terminal_exit;
mod web_assets;
mod websocket;
mod websocket_input;

#[cfg(feature = "remote")]
pub use remote_runtime::RemoteService;
#[cfg(feature = "remote")]
pub use remote_startup::RemoteStartup;
pub use runtime::{
    ProxyNetwork, ServerConfig, ServerError, TlsFiles, configure_logging, serve,
    serve_with_plugin_descriptors,
};
#[cfg(feature = "remote")]
pub use runtime::{serve_with_enrollment, serve_with_remote};

#[cfg(feature = "ssh")]
pub mod bootstrap_api;
#[cfg(feature = "ssh")]
pub mod bootstrap_runtime;
#[cfg(feature = "ssh")]
pub mod ssh_key;

/// Inspect every compiled server component without starting it [198].
#[must_use]
pub fn compiled_plugins() -> &'static [&'static infraternal_plugin_api::PluginDescriptor] {
    COMPILED_PLUGINS
}
static COMPILED_PLUGINS: &[&infraternal_plugin_api::PluginDescriptor] = &[
    #[cfg(feature = "ssh")]
    &infraternal_plugin_ssh::manifest::DESCRIPTOR,
    #[cfg(feature = "remote")]
    &infraternal_plugin_remote::DESCRIPTOR,
    #[cfg(feature = "mesh")]
    &infraternal_plugin_mesh::descriptor::DESCRIPTOR,
    #[cfg(feature = "release")]
    &infraternal_plugin_release::descriptor::DESCRIPTOR,
];

#[cfg(feature = "remote")]
mod remote_removal;
#[cfg(feature = "remote")]
mod remote_removal_http;

#[cfg(test)]
mod release_build_tests;

#[cfg(feature = "ssh")]
mod release_payload;
