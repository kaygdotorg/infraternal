//! Adds deployed operator commands to the shared action registry [16][202][217].

use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun as DryRun, CliHandler,
    JsonSchema,
};

/// Plain words on when each operator command is the right one.
fn when_to_use(id: &str) -> &'static str {
    match id {
        "remote.host.remove" => "Use this when a machine should no longer belong to your server.",
        "remote.host.join" => {
            "Use this on a machine that should become part of an existing server."
        }
        "remote.host.run" => "Use this on an enrolled machine to bring its connection back up.",
        _ => "Use this on the machine that runs the server, when it should restart.",
    }
}

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
        when_to_use(definition.id),
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

/// Operator records use the shared envelope; `data` carries the hosted response when there is one
/// (for example the passkey challenge of a host removal) and is empty for progress records.
fn operator_output(definition: infraternal_plugin_api::ActionDef) -> JsonSchema {
    let mut data = JsonSchema::empty_object().with_description(format!(
        "Hosted response for {}, shaped by schema {}; empty for progress records.",
        definition.id, definition.output.0
    ));
    data.additional_properties = Some(true);
    JsonSchema::command_result_with(data)
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
                        JsonSchema::string(
                            "The server's enrollment address, from your invitation.",
                        ),
                    ),
                    (
                        "enroll_only".to_owned(),
                        JsonSchema::boolean("Save the identity and stop; do not connect yet."),
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
        ActionDefinition::new(
            ["agent", "prepare-join-key"],
            "Prepare a private host key for authenticated setup.",
            "Internal command used by the server during verified SSH setup.",
            ["Check the HTTPS origin before creating or returning the host key digest."],
            JsonSchema::object(
                [("origin".to_owned(), JsonSchema::string("Public HTTPS origin."))],
                ["origin".to_owned()],
            ),
            JsonSchema::command_result(),
            ActionContract::new(
                ActionTarget::Global,
                ActionEffect::Write,
                "agent.prepare-join-key",
                DryRun::Unsupported,
            ),
        )
        .with_cli_handler(CliHandler::RemoteAgent)
        .with_cli_positionals(["origin"])
        .hidden(),
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
                JsonSchema::string("Program to restart into, instead of the current one."),
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
                (
                    "host".to_owned(),
                    JsonSchema::string("ID of the host to remove."),
                ),
                (
                    "server".to_owned(),
                    JsonSchema::string(
                        "Address of your server, such as https://infra.example.org.",
                    ),
                ),
                (
                    "finish".to_owned(),
                    JsonSchema::boolean(
                        "Finish the removal with your passkey proof, read from standard input.",
                    ),
                ),
                (
                    "retain".to_owned(),
                    JsonSchema::boolean(
                        "Cut the host's access but leave the infraternal agent installed on it.",
                    ),
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
