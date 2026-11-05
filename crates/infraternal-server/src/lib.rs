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
#[cfg(feature = "canvas")]
pub mod canvas_store;
#[cfg(feature = "cli-plugin")]
pub mod cli;
mod completion;
#[cfg(feature = "remote")]
pub mod csr;
mod embedded;
mod node_bridge;
#[cfg(any(feature = "ssh", feature = "release"))]
mod release_http;
#[cfg(feature = "release")]
mod release_latest;
mod terminal_queries;
pub(crate) mod terminal_startup;
#[cfg(feature = "release")]
pub use release_latest::release_service;
#[cfg(feature = "parser-checks")]
#[doc(hidden)]
pub use terminal_queries::verify_terminal_query_sample;
mod liveness;
pub mod login_access;
#[cfg(all(feature = "ssh", feature = "mesh", feature = "remote"))]
mod mesh_ssh;
#[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
mod node_host;
pub mod release_manifest;
pub mod release_verify;
/// Compatibility path for existing Rust adapters; implementation belongs to the plugin.
#[cfg(feature = "mesh")]
pub use infraternal_plugin_mesh::api as mesh_api;
#[cfg(feature = "remote")]
mod api_actions;
#[cfg(feature = "remote")]
pub mod enrollment;
#[cfg(all(test, feature = "mesh"))]
mod mesh_api_tests;
pub mod plugins;
#[cfg(feature = "ssh")]
pub mod preferred_accounts;
#[cfg(feature = "remote")]
mod remote_accept;
#[cfg(feature = "remote")]
mod remote_admission;
#[cfg(feature = "remote")]
mod remote_agent_http;
#[cfg(all(test, feature = "mesh-transport-proof"))]
mod remote_autoswitch_probe;
#[cfg(feature = "remote")]
pub mod remote_enrollment;
#[cfg(feature = "remote")]
mod remote_guard;
#[cfg(feature = "remote")]
pub mod remote_http;
#[cfg(feature = "remote")]
mod remote_inventory;
#[cfg(feature = "remote")]
pub use infraternal_plugin_remote::inventory::decode_list as decode_host_inventory;
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
#[cfg(any(test, feature = "native-streams"))]
mod socket_authority;
mod stream_close;
mod terminal_exit;
mod web_assets;
mod websocket;
mod websocket_input;
mod websocket_transport;
#[cfg(any(test, feature = "native-streams"))]
mod wire_identity;

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
    #[cfg(feature = "desktop")]
    &infraternal_plugin_desktop::server_manifest::DESCRIPTOR,
    #[cfg(feature = "ssh")]
    &infraternal_plugin_ssh::manifest::DESCRIPTOR,
    #[cfg(feature = "remote")]
    &infraternal_plugin_remote::DESCRIPTOR,
    #[cfg(feature = "remote")]
    &infraternal_plugin_remote::inventory::DESCRIPTOR,
    #[cfg(feature = "mesh")]
    &infraternal_plugin_mesh::descriptor::DESCRIPTOR,
    #[cfg(feature = "release")]
    &infraternal_plugin_release::descriptor::DESCRIPTOR,
    #[cfg(feature = "canvas")]
    &infraternal_plugin_canvas::socket::DESCRIPTOR,
];

#[cfg(feature = "remote")]
mod remote_removal;
#[cfg(feature = "remote")]
mod remote_removal_http;

#[cfg(test)]
mod release_build_tests;

#[cfg(feature = "ssh")]
mod release_payload;

#[cfg(all(test, feature = "remote"))]
mod ca_update_audit_tests;
