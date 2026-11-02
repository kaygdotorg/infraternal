//! Reuses desktop lifecycle metadata while declaring only node-owned preparation and native source actions [D16,D198,D232].
use crate::manifest::{DOWN, STATUS, UP};
use infraternal_plugin_api::{
    ActionDef, Dependency, DryRun, Effect, Permission, PluginDescriptor, RoleDef, SchemaRef,
    StreamDef, Target,
};
const fn action(id: &'static str, summary: &'static str, effect: Effect) -> ActionDef {
    ActionDef {
        id,
        summary,
        instructions: &[
            "Use the existing enrolled node and its explicitly enabled desktop component.",
        ],
        input: SchemaRef("desktop.source.request"),
        output: SchemaRef("desktop.source.reply"),
        permission: Permission::One("desktop.control"),
        effect,
        target: Target::Node,
        dry_run: DryRun::Unsupported,
        opens: None,
    }
}
pub static DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    actions: &[
        UP,
        DOWN,
        STATUS,
        action(
            "desktop.source.start",
            "Prepare a window or whole-screen source identity",
            Effect::Write,
        ),
        action(
            "desktop.source.stop",
            "Stop and join a desktop capture source",
            Effect::Write,
        ),
        action(
            "desktop.source.windows",
            "Read a bounded window and display inventory page",
            Effect::Read,
        ),
        action(
            "desktop.source.status",
            "Read retained desktop capture source state",
            Effect::Read,
        ),
        action(
            "desktop.source.clock",
            "Sample the desktop capture clock",
            Effect::Read,
        ),
    ],
    streams: &[StreamDef {
        id: "desktop.capture",
        schema: SchemaRef("desktop.wire"),
        resumable: false,
        wire: Some(crate::wire::WIRE),
    }],
    dependencies: &[Dependency::Component("agent")],
    roles: &[RoleDef {
        id: "node",
        requires: &["agent"],
        default_enabled: false,
    }],
    ..crate::manifest::DESCRIPTOR
};
