//! Declares SSH component actions for CLI, help, and generated skill adapters.
//!
//! The `ssh up`, `ssh down` and `ssh status` commands are declared here so
//! help and generated skills can list them, but each is marked "not available
//! yet": the declarations are placeholders and are only compiled in when the
//! plugin API's placeholder feature is on. None of them runs anything.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, JsonSchema,
    PluginDefinition, SafetyNotes, placeholders,
};

/// Stable plugin owner used to materialize only the requested CLI definitions.
pub const ID: &str = "ssh";

/// Register the SSH component actions exposed by this plugin.
///
/// Returns a plugin with id [`ID`]. Without the placeholder feature the action
/// list is empty.
#[must_use]
pub fn plugin() -> PluginDefinition {
    PluginDefinition::new(
        ID,
        "Manage SSH access on this node.",
        placeholders(|| {
            [
                ActionDefinition::new(
                    ["ssh", "up"],
                    "Start the SSH component on this node.",
                    "Use this command when this node should offer SSH access.",
                    ["The SSH component command is not available yet."],
                    JsonSchema::empty_object(),
                    JsonSchema::command_result(),
                    ActionContract::new(
                        ActionTarget::Global,
                        ActionEffect::Write,
                        "ssh.up",
                        DryRun::Unsupported,
                    ),
                )
                .not_available_yet()
                .with_example("ssh up", "Request SSH access on this node."),
                ActionDefinition::new(
                    ["ssh", "down"],
                    "Stop the SSH component on this node.",
                    "Use this command when this node should stop offering SSH access.",
                    ["The SSH component command is not available yet."],
                    JsonSchema::empty_object(),
                    JsonSchema::command_result(),
                    ActionContract::new(
                        ActionTarget::Global,
                        ActionEffect::Write,
                        "ssh.down",
                        DryRun::Unsupported,
                    ),
                )
                .not_available_yet()
                .with_safety(SafetyNotes {
                    destructive: false,
                    dry_run_first: false,
                    notes: vec!["Stopping SSH access may interrupt active sessions.".to_owned()],
                })
                .with_example("ssh down", "Stop SSH access on this node."),
                ActionDefinition::new(
                    ["ssh", "status"],
                    "Show the SSH component state.",
                    "Use this command to check whether SSH access is running.",
                    ["The SSH component command is not available yet."],
                    JsonSchema::empty_object(),
                    JsonSchema::command_result(),
                    ActionContract::new(
                        ActionTarget::Global,
                        ActionEffect::Read,
                        "ssh.status",
                        DryRun::Unsupported,
                    ),
                )
                .not_available_yet()
                .with_example("ssh status", "Check the SSH component state."),
            ]
        }),
    )
}

#[cfg(test)]
mod tests {
    //! Verifies the SSH plugin exposes complete component action metadata.

    use super::plugin;
    use infraternal_plugin_api::ActionAvailability;

    #[test]
    fn ssh_actions_are_complete_and_marked_unavailable() {
        let plugin = plugin();
        assert_eq!(plugin.id, "ssh");
        if !infraternal_plugin_api::PLACEHOLDERS {
            // Default builds leave the declarations out; the feature build checks them.
            assert_eq!(plugin.actions.len(), 0);
            return;
        }
        assert_eq!(plugin.actions.len(), 3);
        for action in plugin.actions {
            assert_eq!(action.command[0], "ssh");
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
