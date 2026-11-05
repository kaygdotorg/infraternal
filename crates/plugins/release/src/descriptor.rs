//! Declares release settings and actions once for CLI, API, discovery and skills [16,198,202,226].
use infraternal_plugin_api::{
    ActionDef, DefaultValue, Dependency, DryRun, Effect, Permission, PluginDescriptor, RoleDef,
    SchemaRef, SettingDefault, Target,
};
/// Exact wording shared by every explicit edge confirmation.
pub const EDGE_WARNING: &str = "Edge builds are published as they are made, unreviewed.";
/// Stable has no fallback to edge; this instruction documents a deliberate opt-in.
pub const STABLE_EMPTY: &str = "no stable release yet";
pub const EDGE_OPT_IN: &str =
    "To opt in explicitly, run infraternal server channel edge (or use --yes without a TTY).";
pub const CHANNEL_GET: ActionDef = ActionDef {
    id: "release.channel.get",
    summary: "Read the server release channel",
    instructions: &["Read the existing server's release channel; the default is stable."],
    input: SchemaRef(r#"{"type":"object","additionalProperties":false}"#),
    output: SchemaRef("ReleaseChannel"),
    permission: Permission::One("server.configure"),
    effect: Effect::Read,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
pub const CHANNEL_SET: ActionDef = ActionDef {
    id: "release.channel.set",
    summary: "Switch the server between the stable and edge release channels.",
    instructions: &[
        "Choose stable or edge for the server.",
        EDGE_WARNING,
        "Edge needs your confirmation: you are asked in a terminal, and scripts must pass --yes.",
        "Switching back to stable needs no confirmation.",
    ],
    input: SchemaRef(
        r#"{"type":"object","properties":{"channel":{"enum":["stable","edge"]},"confirmed":{"type":"boolean","default":false}},"required":["channel"],"additionalProperties":false}"#,
    ),
    output: SchemaRef("ReleaseChannel"),
    permission: Permission::One("server.configure"),
    effect: Effect::Write,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
pub const LATEST: ActionDef = ActionDef {
    id: "release.latest",
    summary: "Show the newest verified release on the server's channel.",
    instructions: &[
        "Read the newest release the server has published for its channel.",
        "Check its signature before trusting it.",
        "If stable has no release yet the command says so; it never falls back to edge.",
    ],
    input: CHANNEL_GET.input,
    output: SchemaRef("VerifiedRelease"),
    permission: Permission::One("server.configure"),
    effect: Effect::Read,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "release",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[CHANNEL_GET, CHANNEL_SET, LATEST],
    topics: &[],
    settings: Some(SchemaRef(
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":true},"channel":{"enum":["stable","edge"],"default":"stable"}},"additionalProperties":false}"#,
    )),
    events: &[],
    streams: &[],
    defaults: &[SettingDefault {
        id: "channel",
        value: DefaultValue::Text("stable"),
    }],
    dependencies: &[Dependency::ExistingServer],
    can_enable_components: &[],
    roles: &[RoleDef {
        id: "server",
        requires: &["server"],
        default_enabled: true,
    }],
    max_frame_len: 2048,
    unavailable: br#"{"error":"release unavailable"}"#,
    unavailable_event: br#"{"type":"error","error":"release unavailable"}"#,
};

/// Bind existing-server operator commands to the same release wire contracts [16,202].
#[must_use]
pub fn server_cli_actions() -> Vec<infraternal_plugin_api::ActionDefinition> {
    use infraternal_plugin_api::{
        ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun, CliHandler,
        JsonSchema,
    };
    [
        (&CHANNEL_SET, vec!["server", "channel"]),
        (&LATEST, vec!["server", "release", "latest"]),
    ]
    .into_iter()
    .map(|(source, path)| {
        let mut fields = vec![(
            "data".to_owned(),
            JsonSchema::string("Data folder of the running server."),
        )];
        if source.id == CHANNEL_SET.id {
            fields.extend([
                (
                    "channel".to_owned(),
                    JsonSchema::string("Stable or edge. Leave it out to show the current channel."),
                ),
                (
                    "yes".to_owned(),
                    JsonSchema::boolean("Confirm switching to edge without being asked."),
                ),
            ]);
        }
        let mut action = ActionDefinition::new(
            path,
            source.summary,
            "Use this on the machine that runs the server, as the account that owns its data.",
            source.instructions.iter().copied(),
            JsonSchema::object(fields, std::iter::empty()),
            JsonSchema::command_result_with(JsonSchema::object(
                [(
                    "release".to_owned(),
                    JsonSchema {
                        additional_properties: Some(true),
                        ..JsonSchema::empty_object()
                    },
                )],
                std::iter::empty(),
            )),
            ActionContract::new(
                ActionTarget::Global,
                if source.id == CHANNEL_SET.id {
                    ActionEffect::Write
                } else {
                    ActionEffect::Read
                },
                "server.configure",
                CliDryRun::Unsupported,
            ),
        )
        .with_cli_handler(CliHandler::ServerPlugin);
        action.hosted = Some(*source);
        if source.id == CHANNEL_SET.id {
            action.cli_positionals.push("channel".to_owned());
        }
        action
    })
    .collect()
}
