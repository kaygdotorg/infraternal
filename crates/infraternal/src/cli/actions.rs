//! Builds the validated action registry from built-in and enabled component plugins.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionRegistry, ActionTarget, CliHandler,
    DryRun, JsonSchema, PluginDefinition, RegistryError,
};

/// Create the action registry for the plugins enabled in this binary.
pub fn registry() -> Result<ActionRegistry, RegistryError> {
    let plugins = vec![
        cli_plugin(),
        #[cfg(feature = "plugin-server")]
        infraternal_server::cli::plugin(),
        #[cfg(feature = "plugin-agent")]
        infraternal_agent::cli::plugin(),
        #[cfg(feature = "plugin-mesh")]
        infraternal_mesh::cli::plugin(),
        #[cfg(feature = "plugin-relay")]
        infraternal_plugin_relay::cli::plugin(),
        #[cfg(feature = "plugin-backup")]
        infraternal_plugin_backup::cli::plugin(),
        #[cfg(feature = "plugin-ssh")]
        infraternal_plugin_ssh::cli::plugin(),
    ];
    ActionRegistry::new(plugins)
}

fn cli_plugin() -> PluginDefinition {
    PluginDefinition::new(
        "cli",
        "Inspect this node and manage its configured components.",
        [
            status_action(),
            up_action(),
            skill_action(),
            session_shim_action(),
        ],
    )
}

fn status_action() -> ActionDefinition {
    let component = JsonSchema::object(
        [
            ("name".to_owned(), JsonSchema::string("Component name.")),
            (
                "state".to_owned(),
                JsonSchema::string("Current component state."),
            ),
        ],
        ["name".to_owned(), "state".to_owned()],
    );
    let status_data = JsonSchema::object(
        [
            ("role".to_owned(), JsonSchema::string("Current node role.")),
            (
                "components".to_owned(),
                JsonSchema::array(component, "Components and their observed states."),
            ),
        ],
        ["role".to_owned(), "components".to_owned()],
    );
    ActionDefinition::new(
        ["status"],
        "Show this node's role and running components.",
        "Use this command to check which infraternal services are running on this node.",
        [
            "Inspect the local infraternal server service.",
            "Review the role and component states in the result.",
        ],
        JsonSchema::empty_object(),
        JsonSchema::command_result_with(status_data),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Read,
            "cli.status",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::Status)
    .with_example("status", "Show this node's current role and components.")
}

fn up_action() -> ActionDefinition {
    let up_data = JsonSchema::object(
        [(
            "started".to_owned(),
            JsonSchema::array(JsonSchema::string("Component name."), "Started components."),
        )],
        ["started".to_owned()],
    );
    ActionDefinition::new(
        ["up"],
        "Start the configured node components.",
        "Use this command when this node should bring its configured components online.",
        [
            "Review the configured components with status.",
            "Start the node components when lifecycle management is available.",
        ],
        JsonSchema::empty_object(),
        JsonSchema::command_result_with(up_data),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Write,
            "cli.up",
            DryRun::Unsupported,
        ),
    )
    .not_available_yet()
    .with_example(
        "up",
        "Request startup of this node's configured components.",
    )
}

fn skill_action() -> ActionDefinition {
    ActionDefinition::new(
        ["skill"],
        "List commands or print generated skills for AI agents.",
        "Use this command to discover enabled commands or share their contracts with an AI agent.",
        [
            "Run `infraternal skill` to list the commands enabled in this build.",
            "Add a command path to print its generated skill and stable JSON output shape.",
            "Pass --write DIR to save one Markdown skill file per visible command.",
        ],
        skill_input_schema(),
        JsonSchema::command_result_with(skill_output_data_schema()),
        ActionContract::new(
            ActionTarget::Global,
            ActionEffect::Read,
            "cli.skill",
            DryRun::Unsupported,
        ),
    )
    .with_cli_handler(CliHandler::Skill)
    .with_example("skill status", "Print the generated skill for status.")
}

fn session_shim_action() -> ActionDefinition {
    ActionDefinition::new(
        ["__shim"],
        "Run the internal session shim.",
        "Use this hidden command only when a host process starts a private session shim.",
        [
            "Connect the shim to the requested session identifier and user.",
            "Use the optional terminal dimensions, state directory and replay capacity when supplied.",
        ],
        JsonSchema::object(
            [
                (
                    "session".to_owned(),
                    JsonSchema::string("Validated session identifier."),
                ),
                (
                    "uid".to_owned(),
                    JsonSchema::integer("Effective user identifier."),
                ),
                (
                    "cols".to_owned(),
                    JsonSchema::integer("PTY column count; defaults to 80."),
                ),
                (
                    "rows".to_owned(),
                    JsonSchema::integer("PTY row count; defaults to 24."),
                ),
                (
                    "state".to_owned(),
                    JsonSchema::string("Private session state directory."),
                ),
                (
                    "detach".to_owned(),
                    JsonSchema::boolean("Detach from the parent process."),
                ),
                (
                    "ring_capacity".to_owned(),
                    JsonSchema::integer("Replay ring capacity; defaults to 8388608 bytes."),
                ),
            ],
            ["session".to_owned(), "uid".to_owned()],
        ),
        JsonSchema::command_result(),
        ActionContract::new(
            ActionTarget::Session,
            ActionEffect::Write,
            "cli.internal.session-shim",
            DryRun::Unsupported,
        ),
    )
    .hidden()
    .with_cli_handler(CliHandler::SessionShim)
}

fn skill_input_schema() -> JsonSchema {
    JsonSchema::object(
        [
            (
                "command".to_owned(),
                JsonSchema::array(
                    JsonSchema::string("Command path part."),
                    "Optional command path following `skill`.",
                ),
            ),
            (
                "write".to_owned(),
                JsonSchema::string("Directory receiving one skill file per visible command."),
            ),
        ],
        std::iter::empty(),
    )
}

fn skill_output_data_schema() -> JsonSchema {
    let skill_command_row = JsonSchema::object(
        [
            (
                "command".to_owned(),
                JsonSchema::string("Registered command path."),
            ),
            (
                "description".to_owned(),
                JsonSchema::string("Short command description."),
            ),
        ],
        ["command".to_owned(), "description".to_owned()],
    );
    JsonSchema::object(
        [
            (
                "commands".to_owned(),
                JsonSchema::array(skill_command_row, "Visible registered commands."),
            ),
            (
                "skill".to_owned(),
                JsonSchema::string("Generated Markdown skill, empty when not requested."),
            ),
            (
                "files".to_owned(),
                JsonSchema::array(
                    JsonSchema::string("Written skill filename."),
                    "Written skill files.",
                ),
            ),
        ],
        [
            "commands".to_owned(),
            "skill".to_owned(),
            "files".to_owned(),
        ],
    )
}

#[cfg(test)]
mod tests {
    //! Verifies every enabled public action has complete, collision-free metadata.

    use super::registry;
    use infraternal_plugin_api::CliHandler;

    #[test]
    fn every_registered_action_has_description_and_step_by_step_guidance() {
        let registry = registry().expect("built-in plugin metadata is valid");
        let actions = registry.actions().collect::<Vec<_>>();
        assert!(!actions.is_empty());
        for registered in actions {
            assert_ne!(registered.action.description.trim(), "");
            assert_ne!(registered.action.when_to_use.trim(), "");
            assert_ne!(registered.action.instructions, [] as [String; 0]);
            assert!(
                registered
                    .action
                    .instructions
                    .iter()
                    .all(|instruction| !instruction.trim().is_empty())
            );
        }
    }

    #[test]
    fn hidden_session_shim_is_registered_to_its_runtime_handler() {
        let registry = registry().expect("built-in plugin metadata is valid");
        let action = registry
            .find(&["__shim"])
            .expect("internal shim action is registered");
        assert!(!action.action.visible);
        assert_eq!(action.action.cli_handler, CliHandler::SessionShim);
    }

    #[cfg(feature = "plugin-mesh")]
    #[test]
    fn registered_actions_include_plugin_permission_contract_fields() {
        let registry = registry().expect("built-in plugin metadata is valid");
        let action = registry
            .find(&["mesh", "up"])
            .expect("mesh action is registered");
        let value = serde_json::to_value(action.action).expect("serialize action definition");

        for field in ["target", "effect", "permission", "dry_run"] {
            assert!(
                value.get(field).is_some(),
                "registered action is missing the `{field}` field required by the plugin contract: {value}"
            );
        }
    }

    #[cfg(not(feature = "plugin-mesh"))]
    #[test]
    fn compiled_out_mesh_has_no_registered_commands() {
        let registry = registry().expect("built-in plugin metadata is valid");
        assert!(registry.find(&["mesh", "up"]).is_none());
    }

    #[cfg(feature = "plugin-mesh")]
    #[test]
    fn enabled_mesh_plugin_registers_its_component_commands() {
        let registry = registry().expect("built-in plugin metadata is valid");
        assert!(registry.find(&["mesh", "up"]).is_some());
    }

    #[cfg(all(
        not(feature = "plugin-agent"),
        not(feature = "plugin-backup"),
        not(feature = "plugin-mesh"),
        not(feature = "plugin-relay"),
        not(feature = "plugin-server"),
        not(feature = "plugin-ssh")
    ))]
    #[test]
    fn no_default_plugins_register_no_component_commands() {
        let registry = registry().expect("core CLI metadata is valid");
        for command in [
            ["agent", "up"],
            ["backup", "up"],
            ["mesh", "up"],
            ["relay", "up"],
            ["server", "init"],
            ["ssh", "up"],
        ] {
            assert!(
                registry.find(&command).is_none(),
                "{command:?} is compiled out"
            );
        }
    }

    #[cfg(not(feature = "plugin-server"))]
    #[test]
    fn server_only_dependencies_are_removed_with_server_plugin() {
        let manifest = include_str!("../../Cargo.toml");
        let dependencies = manifest
            .split("[dependencies]")
            .nth(1)
            .expect("normal dependency section")
            .split("[features]")
            .next()
            .expect("feature section boundary");
        let server_feature = manifest
            .lines()
            .find(|line| line.starts_with("plugin-server ="))
            .expect("server feature declaration");

        for dependency in ["sqlx", "tokio"] {
            let declaration = dependencies
                .lines()
                .map(str::trim)
                .find(|line| line.starts_with(&format!("{dependency}.")));
            let Some(declaration) = declaration else {
                continue;
            };
            assert!(
                declaration.contains("optional = true")
                    && server_feature.contains(&format!("dep:{dependency}")),
                "{dependency} remains available without the server plugin: {declaration}"
            );
        }
    }

    #[cfg(not(feature = "plugin-agent"))]
    #[test]
    fn agent_session_integration_target_is_gated_by_agent_plugin() {
        let integration_test = include_str!("../../tests/agent_sessions.rs");
        assert!(
            integration_test
                .lines()
                .any(|line| line.trim() == "#![cfg(feature = \"plugin-agent\")]")
        );
    }
}
