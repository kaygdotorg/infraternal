//! Declares server-held desktop capture actions and disabled feature metadata [D16,D104,D198,D201,D232].
use infraternal_plugin_api::{
    ActionDef, DefaultValue, Dependency, DryRun, Effect, Permission, PluginDescriptor, RoleDef,
    SchemaRef, SettingDefault, StreamDef, Target,
};

const READ: &[&str] = &[
    "Sign in to the existing server.",
    "Select an enrolled host you may view.",
    "Read its current app windows and displays.",
];
const STATUS: &[&str] = &[
    "Select an existing desktop capture session on a host you may view.",
    "Read its current output size, sequence and source state.",
];
const CLOCK: &[&str] = &[
    "Select an active desktop capture session on a host you may view.",
    "Sample its source clock between local send and receive timestamps.",
    "Repeat samples and retain the smallest round trip with its uncertainty.",
];
const START: &[&str] = &[
    "List the selected host's current app windows and displays.",
    "Select a fresh window or display identity and output dimensions.",
    "Choose reliable or datagram delivery explicitly.",
    "Start a server-held session and attach a viewer to its returned identity.",
];
const STOP: &[&str] = &[
    "Select a session you may control.",
    "Stop the server-held session.",
    "Wait for held input and capture to retire and the original geometry to restore.",
];
const CONTROL: &[&str] = &[
    "Attach a viewer to an existing server-held session.",
    "Take control using that viewer's stream identity.",
    "Send input; local input on the host always takes precedence.",
];
pub const ACTIONS: &[ActionDef] = &[
    ActionDef {
        id: "desktop.session.parameters",
        summary: "Select decoder parameter sets for an attached viewer",
        instructions: &[
            "Attach a viewer to an existing app-window session.",
            "Select encoder or low_delay parameters using that viewer stream identity.",
            "Wait for the repairing keyframe before comparing decoder behavior.",
        ],
        input: SchemaRef("desktop.session.parameters"),
        output: SchemaRef("desktop.session.parameters"),
        permission: Permission::One("desktop.read"),
        effect: Effect::Read,
        target: Target::Session,
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    },
    ActionDef {
        id: "desktop.windows",
        summary: "List app windows and displays on an enrolled host",
        instructions: READ,
        input: SchemaRef("desktop.host"),
        output: SchemaRef("desktop.inventory"),
        permission: Permission::One("desktop.read"),
        effect: Effect::Read,
        target: Target::Host,
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    },
    ActionDef {
        id: "desktop.session.start",
        summary: "Start a server-held window or whole-screen session",
        instructions: START,
        input: SchemaRef("desktop.session.start"),
        output: SchemaRef("desktop.session"),
        permission: Permission::One("desktop.control"),
        effect: Effect::Write,
        target: Target::Host,
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    },
    ActionDef {
        id: "desktop.session.stop",
        summary: "Stop desktop capture and restore window geometry",
        instructions: STOP,
        input: SchemaRef("desktop.session.id"),
        output: SchemaRef("desktop.session.stopped"),
        permission: Permission::One("desktop.control"),
        effect: Effect::Write,
        target: Target::Session,
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    },
    ActionDef {
        id: "desktop.session.control",
        summary: "Take control through an attached desktop viewer",
        instructions: CONTROL,
        input: SchemaRef("desktop.session.viewer"),
        output: SchemaRef("desktop.session.controller"),
        permission: Permission::One("desktop.control"),
        effect: Effect::Write,
        target: Target::Session,
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    },
    ActionDef {
        id: "desktop.session.status",
        summary: "Read the active desktop capture source state",
        instructions: STATUS,
        input: SchemaRef("desktop.session.id"),
        output: SchemaRef("desktop.session.status"),
        permission: Permission::One("desktop.read"),
        effect: Effect::Read,
        target: Target::Session,
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    },
    ActionDef {
        id: "desktop.session.clock",
        summary: "Sample the active source clock for latency calibration",
        instructions: CLOCK,
        input: SchemaRef("desktop.session.id"),
        output: SchemaRef("desktop.session.clock"),
        permission: Permission::One("desktop.read"),
        effect: Effect::Read,
        target: Target::Session,
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    },
];
/// Server metadata cannot enable a node component or create a server [D201].
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "desktop",
    api: infraternal_plugin_api::API_VERSION,
    actions: ACTIONS,
    topics: &[],
    settings: Some(SchemaRef(
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":false}},"additionalProperties":false}"#,
    )),
    events: &[],
    streams: &[StreamDef {
        id: "desktop.viewer",
        schema: SchemaRef("desktop.wire"),
        resumable: false,
        wire: Some(crate::server::WIRE),
    }],
    defaults: &[SettingDefault {
        id: "enabled",
        value: DefaultValue::Bool(false),
    }],
    dependencies: &[Dependency::ExistingServer],
    can_enable_components: &[],
    roles: &[RoleDef {
        id: "server",
        requires: &["server"],
        default_enabled: false,
    }],
    max_frame_len: crate::protocol::MAX_CONTROL,
    unavailable: br#"{"error":"Desktop sessions are unavailable."}"#,
    unavailable_event: br#"{"error":"Desktop sessions are unavailable."}"#,
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn server_metadata_requires_existing_server_and_explicit_delivery() {
        DESCRIPTOR.validate().unwrap();
        assert!(!DESCRIPTOR.roles[0].default_enabled);
        assert_eq!(DESCRIPTOR.dependencies, &[Dependency::ExistingServer]);
        assert_eq!(DESCRIPTOR.can_enable_components, &[] as &[&str]);
        assert!(
            ACTIONS
                .iter()
                .find(|action| action.id == "desktop.session.start")
                .unwrap()
                .help()
                .contains("explicitly")
        );
        assert!(ACTIONS.iter().all(|action| !action.instructions.is_empty()));
    }
}
