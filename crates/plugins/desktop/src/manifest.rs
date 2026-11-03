//! Desktop lifecycle/action metadata shared with CLI, skills and future adapters [D16,D198,D202].
use infraternal_plugin_api::{
    ActionDef, DefaultValue, Dependency, DryRun, Effect, Permission, PluginDescriptor, RoleDef,
    SchemaRef, SettingDefault, Target,
};

pub const UP: ActionDef = ActionDef {
    id: "desktop.up",
    summary: "Enable window and whole-screen capture in the macOS session",
    instructions: &[
        "Run the desktop component as the logged-in user.",
        "Allow Screen Recording and Accessibility for the desktop helper.",
        "Connect the infraternal agent daemon to the private desktop socket.",
    ],
    input: SchemaRef("desktop.runtime"),
    output: SchemaRef("desktop.status"),
    permission: Permission::One("desktop.control"),
    effect: Effect::Write,
    target: Target::Node,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
pub const DOWN: ActionDef = ActionDef {
    id: "desktop.down",
    summary: "Stop desktop capture and restore window frames",
    instructions: &[
        "Stop the desktop component.",
        "Wait for capture, input and the control indicator to retire.",
    ],
    input: SchemaRef("desktop.empty"),
    output: SchemaRef("desktop.status"),
    permission: Permission::One("desktop.control"),
    effect: Effect::Write,
    target: Target::Node,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
pub const STATUS: ActionDef = ActionDef {
    id: "desktop.status",
    summary: "Read the desktop component state",
    instructions: &[
        "Read whether the desktop component is on or off.",
        "Use the local helper client to list available windows and displays.",
    ],
    input: SchemaRef("desktop.empty"),
    output: SchemaRef("desktop.status"),
    permission: Permission::One("desktop.read"),
    effect: Effect::Read,
    target: Target::Node,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
pub const LIST: ActionDef = ActionDef {
    id: "desktop.list",
    summary: "List app windows and whole screens",
    instructions: &[
        "Connect to the logged-in user's private desktop socket.",
        "Read the window ID, owner PID, point frame and display ID.",
        "Use a fresh identity when starting capture.",
    ],
    input: SchemaRef("desktop.empty"),
    output: SchemaRef("desktop.inventory"),
    permission: Permission::One("desktop.read"),
    effect: Effect::Read,
    target: Target::Node,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
pub const CAPTURE: ActionDef = ActionDef {
    id: "desktop.capture",
    summary: "Save an app window or whole screen as H.264",
    instructions: &[
        "List available windows and displays.",
        "Write a start request with the fresh target identity, canvas dimensions and backing scale.",
        "Run capture with the request file, a new output path and a duration in seconds.",
        "Wait for stop to restore the original window frame.",
    ],
    input: SchemaRef("desktop.start"),
    output: SchemaRef("desktop.geometry"),
    permission: Permission::One("desktop.control"),
    effect: Effect::Write,
    target: Target::Node,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
pub const SESSION_STATUS: ActionDef = ActionDef {
    id: "desktop.capture.status",
    summary: "Read the local capture geometry and state",
    instructions: &[
        "Connect to the private desktop helper socket.",
        "Read capture state, output dimensions and follow or letterbox geometry.",
    ],
    input: SchemaRef("desktop.empty"),
    output: SchemaRef("desktop.geometry"),
    permission: Permission::One("desktop.read"),
    effect: Effect::Read,
    target: Target::Node,
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "desktop",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[UP, DOWN, STATUS, LIST, CAPTURE, SESSION_STATUS],
    topics: &[],
    settings: Some(SchemaRef(
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":false}},"additionalProperties":false}"#,
    )),
    events: &[],
    streams: &[],
    defaults: &[SettingDefault {
        id: "enabled",
        value: DefaultValue::Bool(false),
    }],
    dependencies: &[Dependency::Component("agent")],
    can_enable_components: &[],
    roles: &[RoleDef {
        id: "node",
        requires: &["agent"],
        default_enabled: false,
    }],
    max_frame_len: crate::protocol::MAX_FRAME,
    unavailable: br#"{"error":"Desktop capture is unavailable."}"#,
    unavailable_event: br#"{"error":"Desktop capture is unavailable."}"#,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_declares_disabled_node_lifecycle_without_server_creation() {
        DESCRIPTOR.validate().unwrap();
        assert!(!DESCRIPTOR.roles[0].default_enabled);
        assert!(
            !DESCRIPTOR
                .dependencies
                .contains(&Dependency::ExistingServer)
        );
        assert!(UP.help().contains("Screen Recording"));
    }
}
