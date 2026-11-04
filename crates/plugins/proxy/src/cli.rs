//! Declares the owner-approved publication command for CLI, JSON, and skill adapters [D303, D314, #281].

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, CliHandler,
    Effect, JsonSchema, Permission, PluginDefinition, SafetyNotes, SchemaRef, Target,
};

/// Stable plugin owner used by the shared action registry.
pub const ID: &str = "proxy";

pub const PUBLISH_ACTION: infraternal_plugin_api::ActionDef = infraternal_plugin_api::ActionDef {
    id: "proxy.publish",
    summary: "Publish or list services on this node.",
    instructions: &[
        "With no port, list the services published on this node and their URLs.",
        "With a port, publish that local TCP port to mesh peers permitted by its grant.",
        "Use --public to expose it to the internet; the first public publication needs --confirm-public.",
        "The default name uses a wildcard kept on this node; --flat-name uses an exact service certificate whose name appears in public CT logs.",
    ],
    input: SchemaRef("ProxyPublish"),
    output: SchemaRef("ProxyPublishResult"),
    effect: Effect::Write,
    permission: Permission::One("proxy.publish"),
    target: Target::Node,
    dry_run: infraternal_plugin_api::DryRun::Unsupported,
    opens: None,
};

/// Remove one publication by local port or exact DNS name.
pub const UNPUBLISH_ACTION: infraternal_plugin_api::ActionDef = infraternal_plugin_api::ActionDef {
    id: "proxy.unpublish",
    summary: "Stop publishing a local service.",
    instructions: &[
        "Give the local TCP port or exact published name to remove.",
        "A missing publication returns D303 missing and exit code 4.",
    ],
    input: SchemaRef("ProxyUnpublish"),
    output: SchemaRef("ProxyPublishResult"),
    effect: Effect::Write,
    permission: Permission::One("proxy.publish"),
    target: Target::Node,
    dry_run: infraternal_plugin_api::DryRun::Unsupported,
    opens: None,
};

/// Build the proxy command table.
#[must_use]
pub fn plugin() -> PluginDefinition {
    let mut publish = ActionDefinition::new(
        ["publish"],
        "Publish a local service through the node proxy.",
        "Use this to list publications or expose a local TCP port through the mesh, with optional public access.",
        PUBLISH_ACTION.instructions.iter().copied(),
        JsonSchema::object(
            [
                (
                    "port".to_owned(),
                    JsonSchema::integer("Local TCP port to publish; omit it to list publications."),
                ),
                (
                    "public".to_owned(),
                    JsonSchema::boolean("Also allow requests from the public internet."),
                ),
                (
                    "confirm_public".to_owned(),
                    JsonSchema::boolean("Confirm the first public publication on this node."),
                ),
                (
                    "flat_name".to_owned(),
                    JsonSchema::boolean("Use a flat service name and an exact per-service certificate."),
                ),
            ],
            std::iter::empty::<String>(),
        ),
        JsonSchema::command_result(),
        ActionContract::new(
            ActionTarget::Host,
            ActionEffect::Write,
            "proxy.publish",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::NodeComponent)
    .with_cli_positionals(["port"])
    .with_example("publish", "List publications and the URLs attached to them.")
    .with_example("publish 3000", "Publish local TCP port 3000 on the mesh.")
    .with_example(
        "publish 3000 --public --confirm-public",
        "Publish local TCP port 3000 to the internet after first-use confirmation.",
    )
    .with_safety(SafetyNotes {
        destructive: false,
        dry_run_first: false,
        notes: vec![
            "Public access is opt-in and needs first-use confirmation on this node.".to_owned(),
            "Mesh access follows the same grants that govern reachability to the local service port.".to_owned(),
        ],
    });
    publish.hosted = Some(PUBLISH_ACTION);
    let mut unpublish = ActionDefinition::new(
        ["unpublish"],
        "Remove a published local service.",
        "Stop publishing a local TCP port or one exact published name.",
        UNPUBLISH_ACTION.instructions.iter().copied(),
        JsonSchema::object(
            [(
                "target".to_owned(),
                JsonSchema::string("Local port or exact published name."),
            )],
            ["target".to_owned()],
        ),
        JsonSchema::command_result(),
        ActionContract::new(
            ActionTarget::Host,
            ActionEffect::Write,
            "proxy.unpublish",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::NodeComponent)
    .with_cli_positionals(["target"])
    .with_example("unpublish 3000", "Stop publishing local TCP port 3000.")
    .with_example(
        "unpublish port-3000.web01.example.org",
        "Stop publishing the exact named service.",
    )
    .with_safety(SafetyNotes {
        destructive: true,
        dry_run_first: false,
        notes: vec!["A missing publication is reported with exit code 4.".to_owned()],
    });
    unpublish.hosted = Some(UNPUBLISH_ACTION);
    PluginDefinition::new(
        ID,
        "Publish and unpublish local services through the node proxy.",
        [publish, unpublish],
    )
}
