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
};
pub const CHANNEL_SET: ActionDef = ActionDef {
    id: "release.channel.set",
    summary: "Change the server release channel",
    instructions: &[
        "Choose stable or edge for this existing server.",
        EDGE_WARNING,
        "Confirm edge explicitly; the API requires confirmed=true, the CLI asks on a TTY and requires --yes otherwise.",
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
};
pub const LATEST: ActionDef = ActionDef {
    id: "release.latest",
    summary: "Read the newest verified release in the server channel",
    instructions: &[
        "Read releases/channels/<channel>.json for the selected server channel.",
        "Verify the signed manifest and VERSION before trusting the release identity.",
        "If stable is empty, report no stable release yet; never fall back to edge.",
    ],
    input: CHANNEL_GET.input,
    output: SchemaRef("VerifiedRelease"),
    permission: Permission::One("server.configure"),
    effect: Effect::Read,
    target: Target::Global,
    dry_run: DryRun::Unsupported,
    opens: None,
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
