//! Declares remote host capabilities and owns their selected transport primitives [16][198][201][202], #78.
//! No module starts a task or listener merely by being present in a binary.
#![cfg_attr(
    any(test, feature = "test-support"),
    allow(clippy::expect_used, clippy::unwrap_used)
)]

#[cfg(feature = "transport")]
use infraternal_plugin_api::channel;
use infraternal_plugin_api::{
    API_VERSION, ActionDef, DefaultValue, Dependency, DryRun, Effect, Permission, PluginDescriptor,
    RoleDef, SchemaRef, SettingDefault, Target,
};
#[cfg(feature = "transport")]
pub mod remote_native;
#[cfg(feature = "transport")]
pub mod remote_path_socket;
#[cfg(feature = "transport")]
pub mod remote_quic;
#[cfg(feature = "transport")]
pub mod remote_renewal;
#[cfg(feature = "transport")]
pub mod remote_tls;

/// Remove one enrolled host under a purpose-bound fresh owner passkey proof.
pub const REMOVE: ActionDef = ActionDef {
    id: "remote.host.remove",
    summary: "Remove host",
    instructions: &[
        "Select an enrolled host on the existing server.",
        "Preview removal; it revokes host access and forgets application SSH trust.",
        "Confirm the named host with a fresh owner passkey.",
        "By default uninstall the owned infraternal agent through its current channel.",
        "If the host is unreachable, remove server access and report what remains on the host.",
    ],
    input: SchemaRef("remote.host.remove"),
    output: SchemaRef("remote.host.removed"),
    target: Target::Node,
    effect: Effect::Destructive,
    permission: Permission::One("remote.manage"),
    dry_run: DryRun::Required,
    opens: None,
};
/// Internal node handoff; only an authenticated server can request its exact installation.
pub const UNINSTALL: ActionDef = ActionDef {
    id: "remote.host.uninstall",
    summary: "Uninstall the owned infraternal agent",
    instructions: &[
        "Validate this installation's host identity and owned artifacts.",
        "Transmit acceptance before handing cleanup to an independent service.",
    ],
    input: SchemaRef("remote.host.uninstall"),
    output: SchemaRef("remote.host.uninstall.result"),
    target: Target::Node,
    effect: Effect::Destructive,
    permission: Permission::One("remote.manage"),
    dry_run: DryRun::Required,
    opens: None,
};
#[cfg(feature = "agent")]
pub mod uninstall;

/// Enroll one node; this action cannot create a server.
pub const JOIN: ActionDef = ActionDef {
    id: "remote.host.join",
    summary: "Enroll the infraternal agent through pinned HTTPS, then connect",
    instructions: &[
        "Obtain an invitation from an existing server.",
        "Pass invitation material through private stdin.",
        "Run infraternal agent join with the server enrollment URL.",
        "For service installation use --enroll-only, then start the retained identity with infraternal agent run.",
        "Retain the private enrolled identity for subsequent reconnects.",
    ],
    input: SchemaRef("remote.host.join"),
    output: SchemaRef("remote.identity"),
    target: Target::Node,
    effect: Effect::Write,
    permission: Permission::One("remote.host.join"),
    dry_run: DryRun::Unsupported,
    opens: None,
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
    input: SchemaRef("remote.identity"),
    output: SchemaRef("remote.status"),
    target: Target::Node,
    effect: Effect::Write,
    permission: Permission::One("remote.host.run"),
    dry_run: DryRun::Unsupported,
    opens: None,
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
    input: SchemaRef("remote.server.serve"),
    output: SchemaRef("remote.status"),
    target: Target::Global,
    effect: Effect::Write,
    permission: Permission::One("server.configure"),
    dry_run: DryRun::Unsupported,
    opens: None,
};
pub mod cli;
#[cfg(feature = "server")]
pub mod inventory;
pub mod server_restart;
pub use server_restart::RESTART;

/// Create machine trust only after a fresh administrator passkey verification.
pub const BOOTSTRAP_CA: ActionDef = ActionDef {
    input: SchemaRef("remote.request"),
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    output: SchemaRef("remote.response"),
    permission: Permission::One("remote.manage"),
    effect: Effect::Write,
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
/// Manage current administrator generations without transporting any account key.
pub const CA_ADMINISTRATORS: ActionDef = ActionDef {
    input: SchemaRef("remote.request"),
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    output: SchemaRef("remote.response"),
    permission: Permission::One("remote.manage"),
    effect: Effect::Write,
    id: "remote.ca.administrators",
    summary: "Manage machine certificate administrators",
    instructions: &[
        "Sign in as the server owner.",
        "POST user_id and administrator to /remote/ca/administrators/start.",
        "Verify the exact returned passkey challenge with user verification required.",
        "POST ceremony and proof to /remote/ca/administrators/finish.",
        "An offline recipient has a pending copy grant; their device calls remote.ca.bootstrap with its own scoped key while the CA is unlocked.",
        "Revoking membership removes its previous wrapped copy and advances its generation.",
    ],
};
/// Explicit defaults leave remote runtime work disabled until configured.
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "remote",
    api: API_VERSION,
    actions: &[
        JOIN,
        RUN,
        SERVE,
        RESTART,
        BOOTSTRAP_CA,
        CA_ADMINISTRATORS,
        REMOVE,
    ],
    // Settings retain the source declarations; these adapters have no socket dispatcher.
    settings: Some(SchemaRef(
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","description":"Enable remote host transport on this node","default":false},"listen":{"type":["string","null"],"description":"Server transport socket address","default":null},"ca-directory":{"type":["string","null"],"description":"Retained public certificate-authority trust","default":null},"identity-directory":{"type":["string","null"],"description":"Private enrolled node identity","default":null}},"additionalProperties":false}"#,
    )),
    defaults: &[
        SettingDefault {
            id: "enabled",
            value: DefaultValue::Bool(false),
        },
        SettingDefault {
            id: "listen",
            value: DefaultValue::Null,
        },
        SettingDefault {
            id: "ca-directory",
            value: DefaultValue::Null,
        },
        SettingDefault {
            id: "identity-directory",
            value: DefaultValue::Null,
        },
    ],
    dependencies: &[Dependency::ExistingServer],
    can_enable_components: &[],
    roles: &[
        RoleDef {
            id: "remote.host.join",
            requires: &["existing-server"],
            default_enabled: false,
        },
        RoleDef {
            id: "remote.host.run",
            requires: &["enrolled-node"],
            default_enabled: false,
        },
        RoleDef {
            id: "remote.server.serve",
            requires: &["confirmed-server"],
            default_enabled: false,
        },
    ],
    events: &[],
    streams: &[],
    topics: &[],
    max_frame_len: 0,
    unavailable: &[],
    unavailable_event: &[],
};

/// Private authenticated server-to-node handoff; absent from the browser action catalogue.
/// A browser cannot bypass purpose-bound removal by invoking the uninstall transport action.
#[cfg(feature = "agent")]
pub const NODE_DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    actions: &[UNINSTALL],
    ..DESCRIPTOR
};
