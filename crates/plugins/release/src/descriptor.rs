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
/// The topic that streams [`UPDATE_STATUS`]'s state whenever it changes (#211 S3).
pub const UPDATE_TOPIC: &str = "release.update";
/// Read the server's update state (#211 S3): running version, channel, newest verified release, staged release, last and next check, last error.
pub const UPDATE_STATUS: ActionDef = ActionDef {
    id: "release.update.status",
    summary: "Show the server's update state.",
    instructions: &[
        "Read the running version, the channel, the quiet window, the newest verified release, the staged release, the last and next check, and the rollback plan (what going back would restore and lose).",
        "A staged release is verified and waiting; staging never applies it.",
        "mode is auto or off; when off, reason says why updates are off on this host.",
        "Subscribe to release.update to receive the same state whenever it changes.",
    ],
    input: CHANNEL_GET.input,
    output: SchemaRef("UpdateState"),
    permission: Permission::One("server.configure"),
    effect: Effect::Read,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
/// Ask for an update check now, or stage one exact release (#211 S5). Without `version` it is the
/// periodic check run on demand (owner). With `version` it is an explicit request: an older version
/// (a rollback target) or another channel's release may be staged, held until applied or cancelled,
/// and it needs the owner with a fresh passkey session.
pub const UPDATE_CHECK: ActionDef = ActionDef {
    id: "release.update.check",
    summary: "Check for an update now, or stage one exact release.",
    instructions: &[
        "Without a version, check the channel now and stage a newer release if there is one.",
        "With a version, stage exactly that release, even an older one or one from the other channel. This needs the owner with a recent passkey tap.",
        "A release staged by version is held: periodic checks leave it until it is applied or cancelled.",
        "The release is verified before it is staged; staging never applies it.",
    ],
    input: SchemaRef(
        r#"{"type":"object","properties":{"version":{"type":"string","maxLength":64}},"additionalProperties":false}"#,
    ),
    output: SchemaRef("UpdateCheck"),
    permission: Permission::One("server.configure"),
    effect: Effect::Write,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
/// Apply the staged release (#211 S5, switch by S4).
pub const UPDATE_APPLY: ActionDef = ActionDef {
    id: "release.update.apply",
    summary: "Update the server to the staged release now.",
    instructions: &[
        "Re-verify the staged release against the channel, then switch the server to it.",
        "The server restarts warm: sessions and the unlocked authority stay. If the new version fails its health check the server goes back by itself and the Inbox says so.",
        "Pass version to be sure the release you saw is the one applied; it is refused if another is staged.",
        "This needs the owner with a recent passkey tap.",
    ],
    input: SchemaRef(
        r#"{"type":"object","properties":{"version":{"type":"string","maxLength":64}},"additionalProperties":false}"#,
    ),
    output: SchemaRef("UpdateStarted"),
    permission: Permission::One("server.configure"),
    // Write, not Destructive: a destructive action must offer a required dry run, and an update has none.
    effect: Effect::Write,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
/// Go back to the previous version (#211 S5, D295 undo by S4).
pub const UPDATE_ROLLBACK: ActionDef = ActionDef {
    id: "release.update.rollback",
    summary: "Go back to the version the server ran before the last update.",
    instructions: &[
        "Restore the previous binary and the database copy taken right before the last update (D295).",
        "Everything written after that copy was taken is lost; the answer says since when.",
        "release.update.status shows the plan (rollback) before you ask.",
        "This needs the owner with a recent passkey tap, but no passkey is needed to unlock afterwards.",
    ],
    input: CHANNEL_GET.input,
    output: SchemaRef("UpdateStarted"),
    permission: Permission::One("server.configure"),
    // Write, not Destructive: a destructive action must offer a required dry run, and an update has none.
    effect: Effect::Write,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
/// Drop a release staged by version without applying it (#211 S5).
pub const UPDATE_CANCEL: ActionDef = ActionDef {
    id: "release.update.cancel",
    summary: "Cancel a release that was staged by version.",
    instructions: &[
        "Remove the held release and let periodic checks run again.",
        "This needs the owner with a recent passkey tap.",
    ],
    input: CHANNEL_GET.input,
    output: SchemaRef("UpdateState"),
    permission: Permission::One("server.configure"),
    effect: Effect::Write,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
/// Read what the updater did, newest first (#211 S5).
pub const UPDATE_HISTORY: ActionDef = ActionDef {
    id: "release.update.history",
    summary: "Show what the updater did, newest first.",
    instructions: &[
        "Each entry says when, what (staged, removed, applied, rolled_back, failed), which version and why.",
        "The list keeps the newest 30 entries.",
    ],
    input: CHANNEL_GET.input,
    output: SchemaRef("UpdateHistory"),
    permission: Permission::One("server.configure"),
    effect: Effect::Read,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
/// Set the quiet window the apply step waits for (#211 S5).
pub const UPDATE_SETTINGS: ActionDef = ActionDef {
    id: "release.update.settings",
    summary: "Set how long the server must be idle before it applies an update by itself, and whether it applies updates by itself at all.",
    instructions: &[
        "quiet_minutes is how long nobody may have typed or attached before an automatic update applies (default 5, 1 to 1440).",
        "automatic false turns automatic apply off: the server still checks and stages on schedule, so the state shows what is available, but it only switches when release.update.apply is called. The default is true. Send quiet_minutes, automatic or both.",
        "The channel is set with release.channel.set.",
        "This needs the owner with a recent passkey tap.",
    ],
    input: SchemaRef(
        r#"{"type":"object","properties":{"quiet_minutes":{"type":"integer","minimum":1,"maximum":1440},"automatic":{"type":"boolean"}},"minProperties":1,"additionalProperties":false}"#,
    ),
    output: SchemaRef("UpdateState"),
    permission: Permission::One("server.configure"),
    effect: Effect::Write,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
/// The release plugin's declaration: channel actions, `release.latest`, the update status action and the `release.update` topic.
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "release",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[
        CHANNEL_GET,
        CHANNEL_SET,
        LATEST,
        UPDATE_STATUS,
        UPDATE_CHECK,
        UPDATE_APPLY,
        UPDATE_ROLLBACK,
        UPDATE_CANCEL,
        UPDATE_HISTORY,
        UPDATE_SETTINGS,
    ],
    topics: &[UPDATE_TOPIC],
    settings: Some(SchemaRef(
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":true},"channel":{"enum":["stable","edge"],"default":"stable"},"quiet_minutes":{"type":"integer","minimum":1,"maximum":1440,"default":5}},"additionalProperties":false}"#,
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
    max_frame_len: 4096,
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
    .chain(server_update_cli_actions())
    .collect()
}

/// What every `infraternal server update` command says about who may run it (D400).
pub const LOCAL_UPDATE_RULE: &str = "Run it on the server machine as root (or the account the server runs as). It talks to the running server over its private control socket, so no passkey is needed there; from any other device, use the web app, which asks the owner for a recent passkey tap.";

/// How long `apply` and `rollback` wait for the outcome before they stop waiting.
pub const UPDATE_WAIT_MINUTES: u64 = 5;

/// The `infraternal server update …` commands (#211, D400): a thin client over the same
/// `release.update.*` actions as the web app, sent to the running server over its private control
/// socket. Each command carries its hosted action, so `infraternal skill server update <command>`
/// shows the same contract an AI agent sees for the API, with the local rule instead of the
/// passkey sentence.
fn server_update_cli_actions() -> impl Iterator<Item = infraternal_plugin_api::ActionDefinition> {
    use infraternal_plugin_api::{
        ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun, CliHandler,
        JsonSchema,
    };
    [
        (&UPDATE_STATUS, "status", ("server update status --json", "Read the update state as JSON.")),
        (&UPDATE_CHECK, "check", ("server update check", "Check the channel now and stage a newer release.")),
        (&UPDATE_APPLY, "apply", ("server update apply --json", "Switch to the staged release and wait for its health check.")),
        (&UPDATE_ROLLBACK, "rollback", ("server update rollback", "Go back to the version that ran before the last update.")),
        (&UPDATE_CANCEL, "cancel", ("server update cancel", "Drop a release that was staged by version.")),
        (&UPDATE_HISTORY, "history", ("server update history", "List what the updater did, newest first.")),
        (&UPDATE_SETTINGS, "settings", ("server update settings --automatic off", "Stage updates but apply them only when asked.")),
    ]
    .into_iter()
    .map(|(source, name, example)| {
        let mut fields = vec![(
            "data".to_owned(),
            JsonSchema::string("Data folder of the running server."),
        )];
        let required = Vec::new();
        let mut positionals = Vec::new();
        if matches!(name, "check" | "apply") {
            fields.push((
                "version".to_owned(),
                JsonSchema::string(if name == "check" {
                    "Stage exactly this release (even an older one or another channel's). Leave it out to check the channel."
                } else {
                    "Apply only if this is the staged release."
                }),
            ));
            positionals.push("version".to_owned());
        }
        if matches!(name, "apply" | "rollback") {
            fields.push((
                "no_wait".to_owned(),
                JsonSchema::boolean(
                    "Return once the switch has started instead of waiting for its outcome.",
                ),
            ));
        }
        if name == "settings" {
            fields.push((
                "quiet_minutes".to_owned(),
                JsonSchema::integer(
                    "Minutes nobody may type or attach before an update applies by itself (1 to 1440).",
                ),
            ));
            fields.push((
                "automatic".to_owned(),
                JsonSchema::string(
                    "Turn automatic apply off or on. Off stops the server applying staged updates by itself (it still checks and stages), so only `server update apply` switches.",
                ),
            ));
        }
        let mut instructions: Vec<&'static str> = source
            .instructions
            .iter()
            .copied()
            .filter(|line| !line.contains("passkey tap"))
            .collect();
        if matches!(name, "apply" | "rollback") {
            instructions.push("It waits until the server has switched and passed its health check, or went back by itself, for up to 5 minutes; the exit code is non-zero when the update was undone.");
        }
        instructions.push(LOCAL_UPDATE_RULE);
        let effect = if source.effect == Effect::Read {
            ActionEffect::Read
        } else {
            ActionEffect::Write
        };
        let mut action = ActionDefinition::new(
            ["server", "update", name],
            source.summary,
            "Use this on the machine that runs the server, as root, to update it from a shell or a script.",
            instructions,
            JsonSchema::object(fields, required),
            JsonSchema::command_result_with(JsonSchema::object(
                [(
                    "update".to_owned(),
                    JsonSchema {
                        additional_properties: Some(true),
                        ..JsonSchema::empty_object()
                    },
                )],
                std::iter::empty(),
            )),
            ActionContract::new(
                ActionTarget::Global,
                effect,
                "server.configure",
                CliDryRun::Unsupported,
            ),
        )
        .with_cli_handler(CliHandler::ServerPlugin)
        .with_example(example.0, example.1);
        action.hosted = Some(*source);
        action.cli_positionals = positionals;
        action
    })
}
