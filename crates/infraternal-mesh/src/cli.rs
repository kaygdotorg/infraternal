//! Declares mesh node actions shared by CLI help and generated skills.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, JsonSchema,
    PluginDefinition, SafetyNotes, placeholders,
};

/// Register the mesh component actions exposed by this plugin.
#[must_use]
pub fn plugin() -> PluginDefinition {
    PluginDefinition::new(
        "mesh",
        "Manage this node's mesh component.",
        placeholders(actions),
    )
}

/// Declare node actions for adapters that have implemented the component.
///
/// Keeping declarations separate from `plugin` lets a platform adapter expose
/// implemented commands without enabling placeholder text in unrelated builds.
#[must_use]
pub fn actions() -> [ActionDefinition; 3] {
    [
        ActionDefinition::new(
            ["mesh", "up"],
            "Start mesh connectivity on this node.",
            "Use this command when this node should join the configured mesh.",
            [
                "The mesh component command is not available yet.",
                "Use --ssh to request SSH connectivity when the mesh runtime is available.",
            ],
            JsonSchema::object(
                [(
                    "ssh".to_owned(),
                    JsonSchema::boolean("Also turn on SSH access over the mesh."),
                )],
                std::iter::empty(),
            ),
            JsonSchema::command_result(),
            ActionContract::new(
                ActionTarget::Global,
                ActionEffect::Write,
                "mesh.up",
                DryRun::Unsupported,
            ),
        )
        .not_available_yet()
        .with_example("mesh up --ssh", "Request mesh and SSH connectivity."),
        ActionDefinition::new(
            ["mesh", "down"],
            "Stop mesh connectivity on this node.",
            "Use this command when this node should leave the configured mesh.",
            ["The mesh component command is not available yet."],
            JsonSchema::empty_object(),
            JsonSchema::command_result(),
            ActionContract::new(
                ActionTarget::Global,
                ActionEffect::Write,
                "mesh.down",
                DryRun::Unsupported,
            ),
        )
        .not_available_yet()
        .with_safety(SafetyNotes {
            destructive: false,
            dry_run_first: false,
            notes: vec!["Leaving the mesh disconnects services reachable through it.".to_owned()],
        })
        .with_example("mesh down", "Stop mesh connectivity on this node."),
        ActionDefinition::new(
            ["mesh", "status"],
            "Show the mesh component state.",
            "Use this command to check whether this node is connected to the mesh.",
            ["The mesh component command is not available yet."],
            JsonSchema::empty_object(),
            JsonSchema::command_result(),
            ActionContract::new(
                ActionTarget::Global,
                ActionEffect::Read,
                "mesh.status",
                DryRun::Unsupported,
            ),
        )
        .not_available_yet()
        .with_example("mesh status", "Check mesh connectivity on this node."),
    ]
}

#[cfg(test)]
mod tests {
    //! Verifies mesh actions include schema guidance and honest availability.

    use super::plugin;
    use infraternal_plugin_api::{ActionAvailability, JsonSchemaType};

    #[test]
    fn mesh_actions_are_complete_with_optional_ssh_connectivity() {
        let plugin = plugin();
        assert_eq!(plugin.id, "mesh");
        if !infraternal_plugin_api::PLACEHOLDERS {
            // Default builds leave the declarations out; the feature build checks them.
            assert_eq!(plugin.actions.len(), 0);
            return;
        }
        assert_eq!(plugin.actions.len(), 3);
        let up = &plugin.actions[0];
        assert_eq!(up.input_schema.schema_type, JsonSchemaType::Object);
        assert_eq!(
            up.input_schema.properties["ssh"].schema_type,
            JsonSchemaType::Boolean
        );
        assert_eq!(up.input_schema.required, [] as [String; 0]);
        for action in plugin.actions {
            assert_eq!(action.command[0], "mesh");
            assert!(
                action
                    .description
                    .chars()
                    .any(|character| !character.is_whitespace())
            );
            assert!(
                action
                    .instructions
                    .iter()
                    .any(|step| !step.trim().is_empty())
            );
            assert_eq!(action.availability, ActionAvailability::NotAvailableYet);
        }
    }
}
