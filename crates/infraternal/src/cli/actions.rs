//! Builds the validated action registry from built-in and enabled component plugins.

use infraternal_plugin_api::{
    ActionDefinition, ActionRegistry, JsonSchema, PluginDefinition, RegistryError,
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
        [status_action(), up_action()],
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
    )
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
    )
    .not_available_yet()
    .with_example(
        "up",
        "Request startup of this node's configured components.",
    )
}

#[cfg(test)]
mod tests {
    //! Verifies every enabled public action has complete, collision-free metadata.

    use super::registry;

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
}
