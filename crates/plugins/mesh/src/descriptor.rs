//! Declares Mesh coordinator actions and node CLI metadata, permissions, settings and defaults [16,187,198,201,202].
use infraternal_plugin_api::{
    ActionDef, Effect,
    Permission::{Any, One},
    PluginDescriptor, RoleDef,
};
const MANAGEMENT: [&str; 4] = [
    "mesh.manage_nodes",
    "mesh.manage_tags",
    "mesh.manage_grants",
    "mesh.manage_roles",
];
const READ: &[&str] = &[
    "Sign in to the server.",
    "Read the inventory allowed by your Mesh management roles.",
];
const WRITE: &[&str] = &[
    "Sign in to the server.",
    "Choose the hosts or tags covered by your Mesh management role.",
    "Submit the action and read the resulting revision.",
];
const DESTRUCTIVE: &[&str] = &[
    "Sign in to the server.",
    "Review the affected hosts, tags and grants.",
    "Confirm with your passkey.",
    "Submit the action and read the resulting revision.",
];
pub const ACTIONS: &[ActionDef] = &[
    ActionDef {
        target: infraternal_plugin_api::Target::Global,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.default.get",
        summary: "Read Mesh default",
        instructions: &[
            "Sign in as the server owner.",
            "Read the stored Mesh default, or the edition default before first use.",
        ],
        input: infraternal_plugin_api::SchemaRef("Empty"),
        output: infraternal_plugin_api::SchemaRef("MeshDefault"),
        permission: One("server.configure"),
        effect: Effect::Read,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Global,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.default.preview",
        summary: "Preview lost Mesh reach",
        instructions: &[
            "Sign in as the server owner.",
            "Preview member pairs that would lose reach under the proposed default.",
            "Follow next_cursor to review more affected member pairs at this revision.",
            "Use mesh.default.set with this revision to apply after a fresh passkey confirmation.",
        ],
        input: infraternal_plugin_api::SchemaRef("MeshDefaultPreview"),
        output: infraternal_plugin_api::SchemaRef("MeshReachPreview"),
        permission: One("server.configure"),
        effect: Effect::Read,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Global,
        dry_run: infraternal_plugin_api::DryRun::Required,
        opens: None,
        id: "mesh.default.set",
        summary: "Change Mesh default",
        instructions: &[
            "Sign in as the server owner.",
            "Preview member pairs that would lose reach under the proposed default.",
            "Confirm with your passkey and submit the preview revision to apply.",
        ],
        input: infraternal_plugin_api::SchemaRef("MeshDefaultSet"),
        output: infraternal_plugin_api::SchemaRef("MeshDefault"),
        permission: One("server.configure"),
        effect: Effect::Destructive,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Global,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.rotation.get",
        summary: "Read Mesh key rotation",
        instructions: &[
            "Sign in as the server owner.",
            "Read the Mesh key rotation interval and each host's current schedule.",
        ],
        input: infraternal_plugin_api::SchemaRef("Empty"),
        output: infraternal_plugin_api::SchemaRef("MeshRotationSettings"),
        permission: One("server.configure"),
        effect: Effect::Read,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Global,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.rotation.interval.set",
        summary: "Change Mesh key rotation interval",
        instructions: &[
            "Sign in as the server owner.",
            "Confirm the new interval with your passkey.",
            "Submit the revision returned by mesh.rotation.get.",
        ],
        input: infraternal_plugin_api::SchemaRef("MeshRotationIntervalSet"),
        output: infraternal_plugin_api::SchemaRef("MeshRotationInterval"),
        permission: One("server.configure"),
        effect: Effect::Destructive,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.list",
        summary: "List Mesh inventory",
        instructions: READ,
        input: infraternal_plugin_api::SchemaRef("MeshFilter"),
        output: infraternal_plugin_api::SchemaRef("MeshSnapshot"),
        permission: Any(&MANAGEMENT),
        effect: Effect::Read,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.node.enroll",
        summary: "Enroll a host",
        instructions: WRITE,
        input: infraternal_plugin_api::SchemaRef("NodeEnroll"),
        output: infraternal_plugin_api::SchemaRef("Enrollment"),
        permission: One("mesh.manage_nodes"),
        effect: Effect::Write,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.node.observe",
        summary: "Record host liveness",
        instructions: WRITE,
        input: infraternal_plugin_api::SchemaRef("NodeObservation"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_nodes"),
        effect: Effect::Write,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.node.rename",
        summary: "Rename a host",
        instructions: WRITE,
        input: infraternal_plugin_api::SchemaRef("NodeRename"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_nodes"),
        effect: Effect::Write,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Required,
        opens: None,
        id: "mesh.node.delete",
        summary: "Remove a host",
        instructions: DESTRUCTIVE,
        input: infraternal_plugin_api::SchemaRef("NodeIdInput"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_nodes"),
        effect: Effect::Destructive,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.tag.create",
        summary: "Create a tag",
        instructions: WRITE,
        input: infraternal_plugin_api::SchemaRef("NamedInput"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_tags"),
        effect: Effect::Write,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.tag.rename",
        summary: "Rename a tag",
        instructions: WRITE,
        input: infraternal_plugin_api::SchemaRef("RenameInput"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_tags"),
        effect: Effect::Write,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Required,
        opens: None,
        id: "mesh.tag.delete",
        summary: "Remove a tag",
        instructions: DESTRUCTIVE,
        input: infraternal_plugin_api::SchemaRef("NamedInput"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_tags"),
        effect: Effect::Destructive,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.tag.member.add",
        summary: "Add a host to a tag",
        instructions: WRITE,
        input: infraternal_plugin_api::SchemaRef("MembershipInput"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_tags"),
        effect: Effect::Write,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Required,
        opens: None,
        id: "mesh.tag.member.remove",
        summary: "Remove a host from a tag",
        instructions: DESTRUCTIVE,
        input: infraternal_plugin_api::SchemaRef("MembershipInput"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_tags"),
        effect: Effect::Destructive,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.grant.create",
        summary: "Create a named grant",
        instructions: WRITE,
        input: infraternal_plugin_api::SchemaRef("GrantCreate"),
        output: infraternal_plugin_api::SchemaRef("GrantCreated"),
        permission: One("mesh.manage_grants"),
        effect: Effect::Write,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Required,
        opens: None,
        id: "mesh.grant.move",
        summary: "Move a grant endpoint",
        instructions: DESTRUCTIVE,
        input: infraternal_plugin_api::SchemaRef("GrantMove"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_grants"),
        effect: Effect::Destructive,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Required,
        opens: None,
        id: "mesh.grant.delete",
        summary: "Remove a grant",
        instructions: DESTRUCTIVE,
        input: infraternal_plugin_api::SchemaRef("NamedInput"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_grants"),
        effect: Effect::Destructive,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        id: "mesh.grant.rename",
        summary: "Rename a grant",
        instructions: WRITE,
        input: infraternal_plugin_api::SchemaRef("RenameInput"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_grants"),
        effect: Effect::Write,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Required,
        opens: None,
        id: "mesh.role.define",
        summary: "Define a Mesh role",
        instructions: DESTRUCTIVE,
        input: infraternal_plugin_api::SchemaRef("RoleDefinition"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_roles"),
        effect: Effect::Destructive,
    },
    ActionDef {
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Required,
        opens: None,
        id: "mesh.role.assign",
        summary: "Assign a Mesh role",
        instructions: DESTRUCTIVE,
        input: infraternal_plugin_api::SchemaRef("RoleAssignment"),
        output: infraternal_plugin_api::SchemaRef("Revision"),
        permission: One("mesh.manage_roles"),
        effect: Effect::Destructive,
    },
];
/// The server part requires an existing server; a future node part joins this same plugin [201].
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    defaults: &[infraternal_plugin_api::SettingDefault {
        id: "default_policy",
        value: infraternal_plugin_api::DefaultValue::Text(if cfg!(feature = "ee") {
            "Deny"
        } else {
            "Allow"
        }),
    }],
    dependencies: &[],
    can_enable_components: &[],
    events: &[],
    streams: &[],
    id: "mesh",
    api: infraternal_plugin_api::API_VERSION,
    actions: ACTIONS,
    topics: &["mesh"],
    settings: Some(infraternal_plugin_api::SchemaRef(if cfg!(feature = "ee") {
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":true},"default_policy":{"type":"string","title":"Mesh default","enum":["Allow","Deny"],"default":"Deny"}},"additionalProperties":false}"#
    } else {
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":true},"default_policy":{"type":"string","title":"Mesh default","enum":["Allow","Deny"],"default":"Allow"}},"additionalProperties":false}"#
    })),
    roles: &[RoleDef {
        id: "server",
        requires: &["server"],
        default_enabled: true,
    }],
    max_frame_len: crate::api::MAX_MESH_FRAME_LEN,
    unavailable: br#"{"error":"mesh unavailable"}"#,
    unavailable_event: br#"{"type":"error","error":"mesh unavailable"}"#,
};

/// Bind public node commands and coordinator declarations inside their owning plugin.
#[must_use]
pub fn cli_plugin() -> infraternal_plugin_api::PluginDefinition {
    use infraternal_plugin_api::ActionTarget;
    #[cfg(any(
        all(feature = "agent", target_os = "linux"),
        all(feature = "agent", target_os = "macos")
    ))]
    use infraternal_plugin_api::JsonSchema;
    let mut plugin = if infraternal_plugin_api::PLACEHOLDERS {
        DESCRIPTOR.cli_plugin(ActionTarget::Global)
    } else {
        infraternal_plugin_api::PluginDefinition::new(DESCRIPTOR.id, "", [])
    };
    "Link your machines privately and see how they reach each other."
        .clone_into(&mut plugin.description);
    #[cfg(all(feature = "agent", target_os = "linux"))]
    for mut action in crate::node_actions::DESCRIPTOR
        .cli_plugin(ActionTarget::Host)
        .actions
    {
        action.availability = infraternal_plugin_api::ActionAvailability::Available;
        action.cli_handler = infraternal_plugin_api::CliHandler::NodeComponent;
        "Use this action on the running local infraternal agent."
            .clone_into(&mut action.when_to_use);
        action.safety.notes.clear();
        // Scripts and tests use these; people do not need them in help.
        action.cli_hidden_inputs = vec!["input_stdin".to_owned(), "state".to_owned()];
        action.input_schema = JsonSchema::object(
            [
                (
                    "state".to_owned(),
                    JsonSchema::string(
                        "Runtime folder of the infraternal agent, if not the default.",
                    ),
                ),
                (
                    "input_stdin".to_owned(),
                    JsonSchema::boolean("Read the request as JSON from standard input."),
                ),
            ],
            std::iter::empty(),
        );
        if action.command == ["mesh", "up"] {
            // Preserve the declared SSH request flag; unsupported node inputs
            // remain refused by the component rather than claiming SSH is live.
            action.input_schema.properties.insert(
                "ssh".to_owned(),
                JsonSchema::boolean("Also turn on SSH access over the mesh."),
            );
        }
        plugin.actions.push(action);
    }
    #[cfg(all(feature = "agent", target_os = "macos"))]
    for mut action in crate::policy::cli::actions() {
        action.availability = infraternal_plugin_api::ActionAvailability::Available;
        action.cli_handler = infraternal_plugin_api::CliHandler::MeshService;
        action.examples.clear();
        action.instructions = match action.command.last().map(String::as_str) {
            Some("up") => vec![
                "Run this command on the Mac that should join the configured Mesh.".to_owned(),
                "Approve the one-time administrator prompt to start the system service.".to_owned(),
            ],
            Some("down") => {
                vec!["Stop the system service and disconnect this Mac from the Mesh.".to_owned()]
            }
            _ => vec!["Read whether the system Mesh service is running.".to_owned()],
        };
        action.input_schema = if matches!(
            action.command.last().map(String::as_str),
            Some("up" | "down")
        ) {
            action.cli_hidden_inputs = vec!["system_service".to_owned()];
            JsonSchema::object(
                [(
                    "system_service".to_owned(),
                    JsonSchema::boolean("Internal service-control request."),
                )],
                std::iter::empty(),
            )
        } else {
            JsonSchema::empty_object()
        };
        plugin.actions.push(action);
    }
    #[cfg(not(any(
        all(feature = "agent", target_os = "linux"),
        all(feature = "agent", target_os = "macos")
    )))]
    plugin.actions.extend(crate::policy::cli::plugin().actions);
    plugin
}

#[cfg(all(test, feature = "agent", target_os = "macos"))]
mod macos_cli_tests {
    use super::cli_plugin;
    use infraternal_plugin_api::{ActionAvailability, CliHandler};

    #[test]
    fn macos_mesh_lifecycle_actions_use_the_system_service() {
        let plugin = cli_plugin();
        for command in [
            &["mesh", "up"][..],
            &["mesh", "down"][..],
            &["mesh", "status"][..],
        ] {
            let action = plugin
                .actions
                .iter()
                .find(|action| {
                    action
                        .command
                        .iter()
                        .map(String::as_str)
                        .eq(command.iter().copied())
                })
                .unwrap_or_else(|| panic!("missing mesh action {command:?}"));
            assert_eq!(action.availability, ActionAvailability::Available);
            assert_eq!(action.cli_handler, CliHandler::MeshService);
        }
    }
}

#[cfg(test)]
mod rotation_action_tests {
    //! The socket adapter grants fresh-passkey context only to destructive actions.
    use super::*;

    #[test]
    fn changing_rotation_interval_requires_fresh_confirmation() {
        assert!(ACTIONS.iter().any(|action| {
            action.id == "mesh.rotation.interval.set" && action.effect == Effect::Destructive
        }));
    }
}
