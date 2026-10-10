//! Declares the relay component actions shared by CLI help and generated skills.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, DryRun, JsonSchema,
    PluginDefinition, SafetyNotes,
};

/// Stable plugin owner used to materialize only the requested CLI definitions.
pub const ID: &str = "relay";

/// Register the relay component actions exposed by this plugin.
#[must_use]
pub fn plugin() -> PluginDefinition {
    PluginDefinition::new(
        ID,
        "Manage the relay component on this node.",
        [
            ActionDefinition::new(
                ["relay", "up"],
                "Start the relay component on this node.",
                "Use this command when this node should relay connections.",
                ["The relay component command is not available yet."],
                JsonSchema::empty_object(),
                JsonSchema::command_result(),
                ActionContract::new(
                    ActionTarget::Global,
                    ActionEffect::Write,
                    "relay.up",
                    DryRun::Unsupported,
                ),
            )
            .not_available_yet()
            .with_example("relay up", "Request relay service on this node."),
            ActionDefinition::new(
                ["relay", "down"],
                "Stop the relay component on this node.",
                "Use this command when this node should stop relaying connections.",
                ["The relay component command is not available yet."],
                JsonSchema::empty_object(),
                JsonSchema::command_result(),
                ActionContract::new(
                    ActionTarget::Global,
                    ActionEffect::Write,
                    "relay.down",
                    DryRun::Unsupported,
                ),
            )
            .not_available_yet()
            .with_safety(SafetyNotes {
                destructive: false,
                dry_run_first: false,
                notes: vec!["Stopping the relay may interrupt active connections.".to_owned()],
            })
            .with_example("relay down", "Stop relay service on this node."),
            ActionDefinition::new(
                ["relay", "status"],
                "Show the relay component state.",
                "Use this command to check whether relay service is running.",
                ["The relay component command is not available yet."],
                JsonSchema::empty_object(),
                JsonSchema::command_result(),
                ActionContract::new(
                    ActionTarget::Global,
                    ActionEffect::Read,
                    "relay.status",
                    DryRun::Unsupported,
                ),
            )
            .not_available_yet()
            .with_example("relay status", "Check relay service on this node."),
        ],
    )
}

#[cfg(test)]
mod tests {
    //! Verifies relay actions have complete metadata and honest availability.

    use super::plugin;
    use infraternal_plugin_api::ActionAvailability;

    #[test]
    fn relay_actions_are_complete_and_unavailable_until_runtime_exists() {
        let plugin = plugin();
        assert_eq!(plugin.id, "relay");
        assert_eq!(plugin.actions.len(), 3);
        for action in plugin.actions {
            assert_eq!(action.command[0], "relay");
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
