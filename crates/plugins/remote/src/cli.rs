//! Adds deployed operator commands to the shared action registry [16][202][217].

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, CliHandler,
    JsonSchema,
};

/// Adapt the existing transport action rather than duplicating its help and skill instructions.
fn action(
    definition: infraternal_plugin_api::ActionDef,
    command: &[&str],
    inputs: JsonSchema,
    handler: CliHandler,
) -> ActionDefinition {
    let mut action = ActionDefinition::new(
        command.iter().copied(),
        definition.summary,
        definition.summary,
        definition.instructions.iter().copied(),
        inputs,
        operator_output(definition),
        ActionContract::new(
            match definition.target {
                infraternal_plugin_api::Target::Global | infraternal_plugin_api::Target::Node => {
                    ActionTarget::Global
                }
                infraternal_plugin_api::Target::Host => ActionTarget::Host,
                infraternal_plugin_api::Target::Session => ActionTarget::Session,
            },
            match definition.effect {
                infraternal_plugin_api::Effect::Read => ActionEffect::Read,
                infraternal_plugin_api::Effect::Write => ActionEffect::Write,
                infraternal_plugin_api::Effect::Destructive => ActionEffect::Destructive,
            },
            match definition.permission {
                infraternal_plugin_api::Permission::One(permission) => permission,
                infraternal_plugin_api::Permission::Any(permissions) => {
                    permissions.first().copied().unwrap_or("")
                }
            },
            match definition.dry_run {
                infraternal_plugin_api::DryRun::Unsupported => DryRun::Unsupported,
                infraternal_plugin_api::DryRun::Supported => DryRun::Supported,
                infraternal_plugin_api::DryRun::Required => DryRun::Required,
            },
        ),
    )
    .with_cli_handler(handler);
    if let infraternal_plugin_api::Permission::Any(permissions) = definition.permission {
        action.contract.permission = infraternal_plugin_api::ActionPermission::Any {
            any: permissions
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
        };
    }
    action.hosted = Some(definition);
    action
}

/// Operator records keep the deployed format, while removal can print a hosted challenge/result.
fn operator_output(definition: infraternal_plugin_api::ActionDef) -> JsonSchema {
    let required = if definition.id == super::REMOVE.id {
        Vec::new()
    } else {
        vec!["state".to_owned(), "message".to_owned()]
    };
    let mut schema = JsonSchema::object(
        [
            (
                "state".to_owned(),
                JsonSchema::string("Confirmed operator state."),
            ),
            (
                "message".to_owned(),
                JsonSchema::string("Operator result summary."),
            ),
            (
                "next".to_owned(),
                JsonSchema::string("Recommended follow-up."),
            ),
        ],
        required,
    )
    .with_description(format!(
        "Operator records for {}. Hosted response schema: {}.",
        definition.id, definition.output.0
    ));
    // Hosted schemas remain authoritative for challenge/result fields. Local CLI
    // errors may also use the versioned envelope; neither requires rewriting deployed output.
    schema.additional_properties = Some(true);
    schema
}

/// Enrollment and reconnect remain actions owned by the infraternal agent component.
#[must_use]
pub fn agent_actions() -> Vec<ActionDefinition> {
    vec![
        action(
            super::JOIN,
            &["agent", "join"],
            JsonSchema::object(
                [
                    (
                        "url".to_owned(),
                        JsonSchema::string("Pinned server enrollment URL."),
                    ),
                    (
                        "enroll_only".to_owned(),
                        JsonSchema::boolean("Save identity without starting the connection."),
                    ),
                ],
                ["url".to_owned()],
            ),
            CliHandler::RemoteAgent,
        )
        .with_cli_positionals(["url"]),
        action(
            super::RUN,
            &["agent", "run"],
            JsonSchema::empty_object(),
            CliHandler::RemoteAgent,
        ),
    ]
}

/// Replacement uses the running server's private data coordinate inherited by Clap.
#[must_use]
pub fn restart_action() -> ActionDefinition {
    action(
        super::RESTART,
        &["server", "restart"],
        JsonSchema::object(
            [(
                "binary".to_owned(),
                JsonSchema::string("Verified replacement executable."),
            )],
            std::iter::empty(),
        ),
        CliHandler::ServerRestart,
    )
}

/// Host removal retains fresh proof and the deployed positional host identifier.
#[must_use]
pub fn remove_action() -> ActionDefinition {
    let mut action = action(
        super::REMOVE,
        &["remove-host"],
        JsonSchema::object(
            [
                ("host".to_owned(), JsonSchema::string("Enrolled host UUID.")),
                (
                    "server".to_owned(),
                    JsonSchema::string("Existing server URL."),
                ),
                (
                    "finish".to_owned(),
                    JsonSchema::boolean("Complete fresh proof using private stdin."),
                ),
                (
                    "retain".to_owned(),
                    JsonSchema::boolean("Keep the installation after revoking access."),
                ),
            ],
            ["host".to_owned(), "server".to_owned()],
        ),
        CliHandler::RemoveHost,
    )
    .with_cli_positionals(["host"]);
    action.contract.effect = ActionEffect::Destructive;
    action.contract.dry_run = DryRun::Required;
    action
}
