//! Defines session command inputs, help and skills once for the CLI and local handler (D16/D314).
use infraternal_plugin_api::{
    ActionContract, ActionDefinition, ActionEffect, ActionTarget, CliDryRun, CliHandler, JsonSchema,
};

pub(super) fn actions() -> Vec<ActionDefinition> {
    [
        ("", "List saved sessions on this machine.", vec!["machine"], vec![]),
        ("new", "Create a saved session on this machine.", vec!["machine", "command"], vec!["machine", "name"]),
        ("send", "Send text to a saved session.", vec!["target", "text"], vec!["target", "text"]),
        ("read", "Read retained output from a saved session.", vec!["target"], vec!["target", "last"]),
        ("close", "Request a saved session to stop.", vec!["target"], vec!["target"]),
    ].into_iter().map(|(verb, description, positionals, required)| {
        let mut fields = vec![("state".to_owned(), JsonSchema::string("Private state folder of the local infraternal agent."))];
        for field in positionals.iter().chain(required.iter()) {
            if fields.iter().any(|(name, _)| name == field) { continue; }
            let schema = match *field {
                "command" => JsonSchema::array(JsonSchema::string("Literal program argument."), "Program and literal arguments after --."),
                "last" => JsonSchema::integer("Maximum trailing lines to read, from 1 to 10000."),
                "machine" => JsonSchema::string("This machine's hostname, or local."),
                "name" => JsonSchema::string("Unique session name, up to 64 letters, digits, dots, dashes or underscores."),
                "target" => JsonSchema::string("Saved session as <machine>:<session>."),
                _ => JsonSchema::string("Exact text to send, with no added Enter."),
            };
            fields.push(((*field).to_owned(), schema));
        }
        if verb.is_empty() {
            fields.push(("after".to_owned(), JsonSchema::string("Private page cursor for the CLI adapter.")));
        }
        let path = if verb.is_empty() { vec!["sessions"] } else { vec!["sessions", verb] };
        ActionDefinition::new(path, description,
            "Automate your own sessions from a saved shell on this machine.",
            ["Run from a saved infraternal session on this account.",
             "Use local for this machine; cross-machine access requires an access rule and approval.",
             "Use --json for the stable result; use the app for interactive terminal access."],
            JsonSchema::object(fields, required.into_iter().map(str::to_owned)),
            JsonSchema::command_result_with(output_schema(verb)),
            ActionContract::new(ActionTarget::Session,
                if matches!(verb, "" | "read") { ActionEffect::Read } else { ActionEffect::Write },
                format!("sessions.{}", if verb.is_empty() { "list" } else { verb }), CliDryRun::Unsupported))
            .with_cli_handler(CliHandler::Sessions)
            .with_cli_positionals(positionals)
            .with_cli_hidden_inputs(if verb.is_empty() { vec!["after"] } else { vec![] })
    }).collect()
}

fn output_schema(verb: &str) -> JsonSchema {
    let row = || {
        JsonSchema::object(
            [
                ("id".to_owned(), JsonSchema::string("Stable session UUID.")),
                (
                    "name".to_owned(),
                    JsonSchema::string("Saved name, or UUID for unnamed sessions."),
                ),
                (
                    "machine".to_owned(),
                    JsonSchema::string("The local machine."),
                ),
            ],
            ["id".to_owned(), "name".to_owned(), "machine".to_owned()],
        )
    };
    let properties = match verb {
        "" => vec![(
            "sessions".to_owned(),
            JsonSchema::array(row(), "Available sessions on this account."),
        )],
        "new" => vec![("session".to_owned(), row())],
        "send" => vec![(
            "bytes_sent".to_owned(),
            JsonSchema::integer("Bytes acknowledged written to the PTY."),
        )],
        "read" => vec![
            (
                "text".to_owned(),
                JsonSchema::string("Trailing retained output, with lossy UTF-8 replacement."),
            ),
            (
                "truncated".to_owned(),
                JsonSchema::boolean(
                    "Earlier output was omitted to fit the requested lines or bounded reply.",
                ),
            ),
            (
                "snapshot".to_owned(),
                JsonSchema::boolean("Screen recovery replaced unavailable exact output."),
            ),
        ],
        _ => vec![
            ("session".to_owned(), row()),
            (
                "close_requested".to_owned(),
                JsonSchema::boolean("Closure was requested; process exit is not implied."),
            ),
        ],
    };
    JsonSchema::object(properties, std::iter::empty())
}
