//! The command-line actions of the relay component: `relay up`, `relay down`
//! and `relay status`.
//!
//! These declarations feed both the CLI help and the generated AI-agent
//! skills, so each action carries a description, usage steps, input and output
//! schemas, and an example. None of the commands work yet: each is marked "not
//! available yet" until the relay runtime can be controlled from the CLI. The
//! declarations are compiled in only for builds with placeholders enabled;
//! other builds register the plugin with no actions.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, JsonSchema,
    PluginDefinition, SafetyNotes, placeholders,
};

/// The plugin id, `relay`. The CLI uses it to build only the definitions of the
/// plugin that was asked for.
pub const ID: &str = "relay";

/// Describes the relay plugin and its three actions.
///
/// - `relay up`: start relaying connections on this node (a write).
/// - `relay down`: stop relaying; warns that active connections may be
///   interrupted (a write, not destructive).
/// - `relay status`: show whether the relay is running (a read).
///
/// Every action targets the node as a whole, takes no input and does not
/// support dry runs. All are marked not available yet.
#[must_use]
pub fn plugin() -> PluginDefinition {
    PluginDefinition::new(
        ID,
        "Manage the relay component on this node.",
        placeholders(|| {
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
            ]
        }),
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
        if !infraternal_plugin_api::PLACEHOLDERS {
            // Default builds leave the declarations out; the feature build checks them.
            assert_eq!(plugin.actions.len(), 0);
            return;
        }
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
