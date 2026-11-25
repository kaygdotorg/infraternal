//! Owns trusted identity, roles, audit, state, API, and routing; it relays host work through infraternal agents [8][9][10][19].
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

/// Shared compiled release identity; channel policy remains in the release plugin [225,226].
pub use infraternal_plugin_api::{VERSION, release_version};
/// Each account's live browser sockets, and taking over the longest-hidden one when the account is full (#523).
mod account_sockets;
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
/// Public CA lock and root expiry status (D168, #285).
#[cfg(feature = "remote")]
pub mod ca_status;
#[cfg(feature = "canvas")]
pub mod canvas_store;
#[cfg(feature = "cli-plugin")]
pub mod cli;
/// Whether the server's clock can be trusted for certificate decisions (#285).
#[cfg(feature = "remote")]
pub mod clock_health;
mod completion;
#[cfg(feature = "remote")]
pub mod csr;
mod embedded;
/// Moves embedded server mesh state between durable storage and rollback runtime paths [J501, #489].
pub mod embedded_mesh_state;
mod node_bridge;
/// The bounded run-and-wait queue of one socket's plugin calls (#556).
mod plugin_calls;
/// `release.update.*` actions over the private control socket, for `infraternal server update` (#211, D400).
#[cfg(feature = "release")]
pub mod release_control;
#[cfg(any(feature = "ssh", feature = "release"))]
mod release_http;
#[cfg(feature = "release")]
mod release_latest;
mod terminal_queries;
pub(crate) mod terminal_startup;
/// When someone last typed or attached, for the update quiet window (#211 S4).
mod update_activity;
/// The quiet-window apply, the new release's trial and the D295 undo (#211 S4).
#[cfg(feature = "release")]
pub mod update_apply;
/// Preserves the wire writer-ID clock across D295 database restores (#211).
#[cfg(feature = "release")]
mod update_writer_clock;
#[cfg(feature = "release")]
pub use release_latest::release_service;
#[cfg(feature = "parser-checks")]
#[doc(hidden)]
pub use terminal_queries::verify_terminal_query_sample;
#[cfg(feature = "parser-checks")]
#[doc(hidden)]
pub use websocket::receive_checks::verify_receive_wire_sample;
/// Fuzz entry point for the machine join and approval parsers (`parser-checks` only).
#[cfg(all(feature = "remote", any(test, feature = "parser-checks")))]
mod remote_join_checks;
#[cfg(all(feature = "remote", feature = "parser-checks"))]
#[doc(hidden)]
pub use remote_join_checks::verify_remote_join_sample;
mod liveness;
pub mod login_access;
#[cfg(all(feature = "ssh", feature = "mesh", feature = "remote"))]
mod mesh_ssh;
#[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
mod node_host;
pub mod release_verify;
/// Compatibility path for existing Rust adapters; implementation belongs to the plugin.
#[cfg(feature = "mesh")]
pub use infraternal_plugin_mesh::api as mesh_api;
/// D356: the access report a host returns when it revokes a login (#355).
#[cfg(feature = "remote")]
mod access_report;
/// D398: the words of an access report for the owner's Inbox (#355).
mod access_report_text;
#[cfg(feature = "remote")]
mod api_actions;
#[cfg(feature = "remote")]
pub mod enrollment;
/// The host activity log and the root upgrade's wait rule (D376, #399).
pub mod host_activity;
/// The server's side of a root upgrade over the rootless infraternal agent (D376, #399).
#[cfg(all(feature = "ssh", feature = "remote"))]
mod host_privilege;
/// The browser's endpoints for a root upgrade (D376, #399).
#[cfg(all(feature = "ssh", feature = "remote"))]
mod host_privilege_http;
/// Drives one root upgrade from begin to handover (D376, #399).
#[cfg(all(feature = "ssh", feature = "remote"))]
mod host_promotion;
#[cfg(feature = "remote")]
/// The identity key algorithms (Ed25519 for hosts, P-256 for devices) and their stored form (#580).
pub mod identity_key;
/// Server-scheduled host identity key rotation (#285).
#[cfg(feature = "remote")]
mod identity_rotation;
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
/// The server end of a device's held leg-B link, which serves nothing (#580).
#[cfg(feature = "remote")]
mod remote_device_link;
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
/// Process-bound readiness for the local server relocation transaction.
#[cfg(target_os = "linux")]
pub mod move_health;
#[cfg(feature = "remote")]
mod remote_link;
#[cfg(all(test, feature = "mesh", feature = "remote"))]
mod remote_mesh_revocation_tests;
/// Recovery of an expired host certificate through its registered key (#285).
#[cfg(feature = "remote")]
mod remote_recovery;
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
/// A root upgrade's successor lane and its outboxes (D376, #399).
#[cfg(feature = "remote")]
mod remote_successor;
mod runtime;
/// Bounds the unsent data in each browser socket's kernel buffer (`TCP_NOTSENT_LOWAT`, #146).
mod send_queue;
/// The server's short-lived, rotating leg-B TLS leaf (#559).
#[cfg(feature = "remote")]
mod server_leaf;
mod server_tls;
#[cfg(any(test, feature = "native-streams"))]
mod socket_authority;
mod stream_close;
/// Closes local terminal rows a fresh shim census no longer lists, on the D379 writer (#562).
mod terminal_census;
mod terminal_exit;
/// Records each terminal input Ack in one D379 writer transaction before the browser sees it (#562).
mod terminal_input_ack;
/// Closes a remote host's terminal row once the host reports its shell gone (#588).
mod terminal_remote_gone;
/// Periodically prunes closed `terminal_sessions` rows older than 30 days (#571, #579).
mod terminal_session_prune;
/// Persists a newly opened terminal's session row on the D379 writer (#562).
mod terminal_session_record;
/// Claims a device's durable input writer row for an attachment on the D379 writer (#562).
mod terminal_writer_claim;
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
/// Tests of the `device` host mode and the ring-signed P-256 test client (#580).
#[cfg(all(test, feature = "remote"))]
mod remote_device_tests;
