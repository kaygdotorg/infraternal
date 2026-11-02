//! Declares agent component actions shared by CLI help and generated skills.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, CliHandler,
    JsonSchema, PluginDefinition, SafetyNotes, placeholders,
};

/// Stable plugin owner used to materialize only the requested CLI definitions.
pub const ID: &str = "agent";

/// Register the agent component actions exposed by this plugin.
#[must_use]
pub fn plugin() -> PluginDefinition {
    let mut plugin = PluginDefinition::new(
        ID,
        "Connect this machine to a server.",
        [
            ActionDefinition::new(
                ["agent"],
                "Run an infraternal agent over its inherited server connection.",
                "Use this internal command only when a server launches an agent with a private socketpair.",
                [
                    "Receive the inherited socket file descriptor from the server.",
                    "Run the infraternal agent for the lifetime of that connection.",
                ],
                JsonSchema::object(
                    [
                        ("fd".to_owned(), JsonSchema::integer("Inherited socket file descriptor.")),
                        ("state".to_owned(), JsonSchema::string("Private infraternal agent state directory.")),
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
        ],
    );
    plugin.actions.extend(placeholders(unbuilt));
    #[cfg(feature = "remote")]
    {
        plugin.actions[0].input_schema.properties.insert(
            "data".to_owned(),
            JsonSchema::string("Private enrolled identity directory."),
        );
        plugin
            .actions
            .extend(infraternal_plugin_remote::cli::agent_actions());
    }
    plugin
}

/// Lifecycle commands for the agent component that is not built yet.
fn unbuilt() -> [ActionDefinition; 3] {
    [
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
        .with_example("agent up", "Request infraternal agent setup for this node."),
        ActionDefinition::new(
            ["agent", "down"],
            "Stop the infraternal agent component on this node.",
            "Use this command when this node should leave its managed-node role.",
            ["The infraternal agent component command is not available yet."],
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
                "Stopping the infraternal agent disconnects this node from its server.".to_owned(),
            ],
        })
        .with_example(
            "agent down",
            "Stop the infraternal agent component on this node.",
        ),
        ActionDefinition::new(
            ["agent", "status"],
            "Show the infraternal agent component state.",
            "Use this command to check whether this node is connected to a server.",
            ["The infraternal agent component command is not available yet."],
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
        .with_example(
            "agent status",
            "Check the infraternal agent component state.",
        ),
    ]
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
        let remote = if cfg!(feature = "remote") { 3 } else { 0 };
        let unbuilt = if infraternal_plugin_api::PLACEHOLDERS {
            3
        } else {
            0
        };
        assert_eq!(plugin.actions.len(), 1 + unbuilt + remote);
        assert_eq!(plugin.actions[0].command, ["agent"]);
        assert!(!plugin.actions[0].visible);
        for action in plugin
            .actions
            .iter()
            .skip(1)
            .take(if infraternal_plugin_api::PLACEHOLDERS {
                3
            } else {
                0
            })
        {
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
