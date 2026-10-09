//! Declares remote host capabilities and owns their selected transport primitives [16][198][201][202], #78.
//! No module starts a task or listener merely by being present in a binary.
#![cfg_attr(
    any(test, feature = "test-support"),
    allow(clippy::expect_used, clippy::unwrap_used)
)]

#[cfg(feature = "transport")]
use infraternal_plugin_api::channel;
use infraternal_plugin_api::{ActionDef, PluginDescriptor, SettingDef};
#[cfg(feature = "transport")]
pub mod remote_native;
#[cfg(feature = "transport")]
pub mod remote_quic;
#[cfg(feature = "transport")]
pub mod remote_renewal;
#[cfg(feature = "transport")]
pub mod remote_tls;

/// Enroll one node; this action cannot create a server.
pub const JOIN: ActionDef = ActionDef {
    id: "remote.host.join",
    summary: "Enroll the infraternal agent through pinned HTTPS, then connect",
    instructions: &[
        "Obtain an invitation from an existing server.",
        "Pass invitation material through private stdin.",
        "Run infraternal agent join with the server enrollment URL.",
        "Retain the private enrolled identity for subsequent reconnects.",
    ],
};
/// Reconnect a node with its existing private identity.
pub const RUN: ActionDef = ActionDef {
    id: "remote.host.run",
    summary: "Reconnect the infraternal agent using its enrolled identity",
    instructions: &[
        "Select the private enrolled identity directory.",
        "Run infraternal agent run.",
        "Keep the foreground process running; stopping it removes the connection.",
    ],
};
/// Activate a capability only on an already configured server.
pub const SERVE: ActionDef = ActionDef {
    id: "remote.server.serve",
    summary: "Accept enrolled infraternal agents on a configured server",
    instructions: &[
        "Initialize and confirm the server separately.",
        "Configure private machine certificate storage; first setup requires a fresh administrator passkey.",
        "Configure the remote listener and public server trust.",
        "Start the server; call remote.ca.bootstrap from an administrator session before enrolling a host.",
    ],
};
/// Create machine trust only after a fresh administrator passkey verification.
pub const BOOTSTRAP_CA: ActionDef = ActionDef {
    id: "remote.ca.bootstrap",
    summary: "Set up machine certificates",
    instructions: &[
        "Use an administrator session on the existing server.",
        "POST /remote/ca/bootstrap/start with the exact Origin and session cookie.",
        "Verify the returned passkey challenge with user verification required.",
        "Derive the scoped CA key locally with HKDF-SHA256, the returned salt and info infraternal/ca-wrap/v1|member|generation.",
        "POST ceremony, proof and scoped_key to /remote/ca/bootstrap/finish, then create the host invitation.",
        "On a cold start the same bootstrap calls unlock the retained issuer using this administrator's wrapped copy.",
    ],
};
/// Explicit defaults leave remote runtime work disabled until configured.
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "remote",
    api: 1,
    actions: &[JOIN, RUN, SERVE, BOOTSTRAP_CA],
    settings: &[
        SettingDef {
            id: "enabled",
            summary: "Enable remote host transport on this node",
            default: "false",
        },
        SettingDef {
            id: "listen",
            summary: "Server transport socket address",
            default: "null",
        },
        SettingDef {
            id: "ca-directory",
            summary: "Retained public certificate-authority trust",
            default: "null",
        },
        SettingDef {
            id: "identity-directory",
            summary: "Private enrolled node identity",
            default: "null",
        },
    ],
    role_dependencies: &[
        "remote.host.join:existing-server",
        "remote.host.run:enrolled-node",
        "remote.server.serve:confirmed-server",
        "remote.ca.bootstrap:confirmed-server",
    ],
};
