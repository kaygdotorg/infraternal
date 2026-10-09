//! Declares agent component actions shared by CLI help and generated skills.

use infraternal_plugin_api::{ActionDefinition, JsonSchema, PluginDefinition, SafetyNotes};

/// Register the agent component actions exposed by this plugin.
#[must_use]
pub fn plugin() -> PluginDefinition {
    PluginDefinition::new(
        "agent",
        "Manage the infraternal agent component on this node.",
        [
            ActionDefinition::new(
                ["agent", "up"],
                "Start and connect the agent component on this node.",
                "Use this command when this node should join a server as a managed node.",
                ["The agent component command is not available yet."],
                JsonSchema::empty_object(),
                JsonSchema::command_result(),
            )
            .not_available_yet()
            .with_example("agent up", "Request agent setup for this node."),
            ActionDefinition::new(
                ["agent", "down"],
                "Stop the agent component on this node.",
                "Use this command when this node should leave its managed-node role.",
                ["The agent component command is not available yet."],
                JsonSchema::empty_object(),
                JsonSchema::command_result(),
            )
            .not_available_yet()
            .with_safety(SafetyNotes {
                destructive: false,
                dry_run_first: false,
                notes: vec!["Stopping the agent disconnects this node from its server.".to_owned()],
            })
            .with_example("agent down", "Stop the agent component on this node."),
            ActionDefinition::new(
                ["agent", "status"],
                "Show the agent component state.",
                "Use this command to check whether this node is connected to a server.",
                ["The agent component command is not available yet."],
                JsonSchema::empty_object(),
                JsonSchema::command_result(),
            )
            .not_available_yet()
            .with_example("agent status", "Check the agent component state."),
        ],
    )
}

#[cfg(test)]
mod tests {
    //! Verifies agent actions have complete metadata and honest availability.

    use super::plugin;
    use infraternal_plugin_api::ActionAvailability;

    #[test]
    fn agent_actions_are_complete_and_unavailable_until_lifecycle_exists() {
        let plugin = plugin();
        assert_eq!(plugin.id, "agent");
        assert_eq!(plugin.actions.len(), 3);
        for action in plugin.actions {
            assert_eq!(action.command[0], "agent");
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
