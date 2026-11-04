//! Declares the backup component actions shared by CLI help and generated skills.

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, JsonSchema,
    PluginDefinition, SafetyNotes, placeholders,
};

/// Stable plugin owner used to materialize only the requested CLI definitions.
pub const ID: &str = "backup";

/// Build the backup plugin definition: its `backup up`, `backup down` and
/// `backup status` commands.
///
/// Every action is marked "not available yet" because no backup runtime exists.
/// The action declarations are placeholders: they are only present when the
/// plugin API is built with its placeholders feature, otherwise the returned
/// definition has no actions. Pure and cheap; call it whenever the CLI help or
/// generated skills need the definition.
#[must_use]
pub fn plugin() -> PluginDefinition {
    PluginDefinition::new(
        ID,
        "Manage server backup jobs on this node.",
        placeholders(|| {
            [
                ActionDefinition::new(
                    ["backup", "up"],
                    "Start the backup component on this node.",
                    "Use this command when this node should run scheduled backups.",
                    ["The backup component command is not available yet."],
                    JsonSchema::empty_object(),
                    JsonSchema::command_result(),
                    ActionContract::new(
                        ActionTarget::Global,
                        ActionEffect::Write,
                        "backup.up",
                        DryRun::Unsupported,
                    ),
                )
                .not_available_yet()
                .with_example("backup up", "Request backup service on this node."),
                ActionDefinition::new(
                    ["backup", "down"],
                    "Stop the backup component on this node.",
                    "Use this command when this node should stop scheduled backups.",
                    ["The backup component command is not available yet."],
                    JsonSchema::empty_object(),
                    JsonSchema::command_result(),
                    ActionContract::new(
                        ActionTarget::Global,
                        ActionEffect::Write,
                        "backup.down",
                        DryRun::Unsupported,
                    ),
                )
                .not_available_yet()
                .with_safety(SafetyNotes {
                    destructive: false,
                    dry_run_first: false,
                    notes: vec!["Stopping backups pauses future scheduled snapshots.".to_owned()],
                })
                .with_example("backup down", "Pause scheduled backups on this node."),
                ActionDefinition::new(
                    ["backup", "status"],
                    "Show the backup component state.",
                    "Use this command to check whether scheduled backups are running.",
                    ["The backup component command is not available yet."],
                    JsonSchema::empty_object(),
                    JsonSchema::command_result(),
                    ActionContract::new(
                        ActionTarget::Global,
                        ActionEffect::Read,
                        "backup.status",
                        DryRun::Unsupported,
                    ),
                )
                .not_available_yet()
                .with_example("backup status", "Check scheduled backup state."),
            ]
        }),
    )
}

#[cfg(test)]
mod tests {
    //! Verifies backup actions have complete metadata and honest availability.

    use super::plugin;
    use infraternal_plugin_api::ActionAvailability;

    #[test]
    fn backup_actions_are_complete_and_unavailable_until_runtime_exists() {
        let plugin = plugin();
        assert_eq!(plugin.id, "backup");
        if !infraternal_plugin_api::PLACEHOLDERS {
            // Default builds leave the declarations out; the feature build checks them.
            assert_eq!(plugin.actions.len(), 0);
            return;
        }
        assert_eq!(plugin.actions.len(), 3);
        for action in plugin.actions {
            assert_eq!(action.command[0], "backup");
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
