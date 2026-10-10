//! Declares agent component actions shared by CLI help and generated skills.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliHandler, DryRun, JsonSchema,
    PluginDefinition, SafetyNotes,
};

/// Stable plugin owner used to materialize only the requested CLI definitions.
pub const ID: &str = "agent";

/// Register the agent component actions exposed by this plugin.
#[must_use]
pub fn plugin() -> PluginDefinition {
    PluginDefinition::new(
        ID,
        "Manage the infraternal agent component on this node.",
        [
            ActionDefinition::new(
                ["agent"],
                "Run an infraternal agent over its inherited server connection.",
                "Use this internal command only when a server launches an agent with a private socketpair.",
                [
                    "Receive the inherited socket file descriptor from the server.",
                    "Run the agent for the lifetime of that connection.",
                ],
                JsonSchema::object(
                    [
                        ("fd".to_owned(), JsonSchema::integer("Inherited socket file descriptor.")),
                        ("state".to_owned(), JsonSchema::string("Private agent state directory.")),
                    ],
                    std::iter::empty(),
                ),
                JsonSchema::command_result(),
                ActionContract::new(
                    ActionTarget::Global,
                    ActionEffect::Write,
                    "agent.run",
                    DryRun::Unsupported,
                ),
            )
            .with_cli_handler(CliHandler::EmbeddedAgent)
            .hidden(),
            ActionDefinition::new(
                ["agent", "up"],
                "Start and connect the infraternal agent component on this node.",
                "Use this command when this node should join a server as a managed node.",
                ["The infraternal agent component command is not available yet."],
                JsonSchema::empty_object(),
                JsonSchema::command_result(),
                ActionContract::new(
                    ActionTarget::Global,
                    ActionEffect::Write,
                    "agent.up",
                    DryRun::Unsupported,
                ),
            )
            .not_available_yet()
            .with_example("agent up", "Request agent setup for this node."),
            ActionDefinition::new(
                ["agent", "down"],
                "Stop the infraternal agent component on this node.",
                "Use this command when this node should leave its managed-node role.",
                ["The agent component command is not available yet."],
                JsonSchema::empty_object(),
                JsonSchema::command_result(),
                ActionContract::new(
                    ActionTarget::Global,
                    ActionEffect::Write,
                    "agent.down",
                    DryRun::Unsupported,
                ),
            )
            .not_available_yet()
            .with_safety(SafetyNotes {
                destructive: false,
                dry_run_first: false,
                notes: vec![
                    "Stopping the infraternal agent disconnects this node from its server."
                        .to_owned(),
                ],
            })
            .with_example("agent down", "Stop the agent component on this node."),
            ActionDefinition::new(
                ["agent", "status"],
                "Show the infraternal agent component state.",
                "Use this command to check whether this node is connected to a server.",
                ["The agent component command is not available yet."],
                JsonSchema::empty_object(),
                JsonSchema::command_result(),
                ActionContract::new(
                    ActionTarget::Global,
                    ActionEffect::Read,
                    "agent.status",
                    DryRun::Unsupported,
                ),
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
        assert_eq!(plugin.actions.len(), 4);
        assert_eq!(plugin.actions[0].command, ["agent"]);
        assert!(!plugin.actions[0].visible);
        for action in plugin.actions.iter().skip(1) {
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
