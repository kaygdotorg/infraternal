//! Runs node component commands against the local infraternal agent and presents the reply in the shared envelope [16,198,202], #239.
//!
//! Commands come from plugin declarations; this module knows no plugin fields. The plugin
//! presents its own reply (`present`), and the answer, the aligned text and the JSON data
//! all come from that one presentation.
use clap::ArgMatches;
use infraternal_plugin_api::{
    ActionDefinition, JsonSchema, JsonSchemaType, PluginRegistry,
    present::{Presented, Tone},
};
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    path::PathBuf,
    process::ExitCode,
};

use crate::cli::output::{CommandResult, CommandState, Exit, RenderOptions, emit, print};

/// Causes that happen before any call to the infraternal agent, tagged inside the `io::Error` so
/// [`refuse`] can say what really went wrong instead of blaming a reply that never came.
#[derive(Debug)]
enum Cause {
    /// No usable runtime directory: `XDG_RUNTIME_DIR` is unset or not private to this account.
    NoRuntimeDirectory,
    /// The input given on standard input is not accepted.
    BadInput,
}

impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoRuntimeDirectory => "no usable runtime directory",
            Self::BadInput => "input not accepted",
        })
    }
}

impl std::error::Error for Cause {}

pub(crate) fn run_action(
    action: &infraternal_plugin_api::ActionDefinition,
    arguments: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    let definition = action;
    let command = definition.command.join(" ");
    let Some(action) = action.hosted else {
        return ExitCode::FAILURE;
    };
    let Ok(registry) =
        infraternal_agent::plugins::registry(infraternal_agent::plugins::ExecutionMode::Embedded)
    else {
        return ExitCode::FAILURE;
    };
    let result = (|| {
        let mut action_exit = Exit::Ok;
        let mut input = if arguments.get_flag("input_stdin") {
            let mut bytes = Vec::new();
            io::stdin()
                .take((infraternal_plugin_api::MAX_ACTION_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > infraternal_plugin_api::MAX_ACTION_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, Cause::BadInput));
            }
            serde_json::from_slice(&bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, Cause::BadInput))?
        } else {
            json!({})
        };
        add_cli_values(definition, arguments, &mut input)?;
        let state = infraternal_agent::sessions::state_path(
            arguments.get_one::<String>("state").map(PathBuf::from),
        )
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, Cause::NoRuntimeDirectory))?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // Share the startup reactor instead of generating another poll loop [243].
        infraternal_agent::block_on_io(
            &runtime,
            Box::pin(async {
                action_exit =
                    execute(&state, &registry, &command, action.id, input, json_output).await?;
                Ok(())
            }),
        )?;
        Ok(action_exit)
    })();
    match result {
        Ok(exit) => ExitCode::from(exit.code()),
        Err(error) => refuse(json_output, &command, &error),
    }
}

/// Map stable D303 component errors to their process exit behavior.
#[must_use]
pub(crate) fn component_error_exit(code: &str) -> Option<Exit> {
    match code {
        "failed" => Some(Exit::Failed),
        "usage" => Some(Exit::Usage),
        "not_allowed" => Some(Exit::NotAllowed),
        "missing" | "not_found" => Some(Exit::NotFound),
        "unreachable" | "component_down" => Some(Exit::Unreachable),
        "partial" => Some(Exit::Partial),
        _ => None,
    }
}

fn component_error_result(command: &str, value: &Value) -> Option<(CommandResult<Value>, Exit)> {
    let code = value.get("error")?.get("code")?.as_str()?;
    let exit = component_error_exit(code).unwrap_or(Exit::Failed);
    let message = value
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| !message.trim().is_empty())
        .unwrap_or("The component action could not be completed.");
    let data = value.get("data").cloned().unwrap_or_else(|| json!({}));
    Some((
        CommandResult::new(command, CommandState::Failed, message, data).with_error_code(code),
        exit,
    ))
}

#[cfg(test)]
#[path = "component_cli_tests.rs"]
mod tests;

/// Say which of the possible causes it was, and the one thing to do about it.
fn refuse(json_output: bool, command: &str, error: &io::Error) -> ExitCode {
    let cause = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Cause>());
    let (message, why, next, exit) = match (cause, error.kind()) {
        (Some(Cause::NoRuntimeDirectory), _) => (
            "The infraternal agent's runtime directory could not be found.",
            "XDG_RUNTIME_DIR is not set, or it is not a private directory of this account.",
            "Run this command in a login session of the account that runs the infraternal agent, or pass --state.",
            Exit::Unreachable,
        ),
        (Some(Cause::BadInput), _) => (
            "The input given on standard input was not accepted.",
            "It is too large or is not the JSON this command reads.",
            "infraternal skill",
            Exit::Usage,
        ),
        (None, io::ErrorKind::NotFound) => (
            "The infraternal agent on this machine is not running.",
            "No socket was found in the infraternal agent's runtime directory.",
            "infraternal status",
            Exit::Unreachable,
        ),
        (None, io::ErrorKind::ConnectionRefused) => (
            "The infraternal agent on this machine is not running.",
            "Its socket is there, but nothing answers on it.",
            "infraternal status",
            Exit::Unreachable,
        ),
        (None, io::ErrorKind::PermissionDenied) => (
            "This account is not allowed to use the infraternal agent here.",
            "The infraternal agent answers only the account that runs it.",
            "Run this command as the account that runs the infraternal agent.",
            Exit::NotAllowed,
        ),
        (None, io::ErrorKind::TimedOut) => (
            "The infraternal agent did not answer in time.",
            "There was no reply within 5 seconds.",
            "infraternal status",
            Exit::Unreachable,
        ),
        (None, _) => (
            "The infraternal agent could not complete this request.",
            "It sent a reply this command does not understand.",
            "infraternal status",
            Exit::Failed,
        ),
    };
    emit(
        CommandResult::new(command, CommandState::Failed, message, json!({}))
            .with_details(why)
            .with_next_step(next),
        json_output,
        exit,
    )
}
async fn call(state: &std::path::Path, action: &str, input: &Value) -> io::Result<Vec<u8>> {
    let input = serde_json::to_vec(input).map_err(io::Error::other)?;
    infraternal_agent::plugin_control::call(state, action, &input).await
}

fn state_of(presented: &Presented) -> CommandState {
    match presented.tone {
        Tone::Good => CommandState::Ready,
        Tone::Idle => CommandState::Stopped,
        Tone::Attention => CommandState::Pending,
    }
}

/// Convert generated CLI matches into the action's typed JSON input. The action schema remains
/// the single source for both argument parsing and serialization.
pub(crate) fn add_cli_values(
    action: &ActionDefinition,
    matches: &ArgMatches,
    input: &mut Value,
) -> io::Result<()> {
    let values = input.as_object_mut().ok_or(io::ErrorKind::InvalidData)?;
    for (name, schema) in &action.input_schema.properties {
        if name == "input_stdin" || name == "state" {
            continue;
        }
        let value = match schema.schema_type {
            JsonSchemaType::Boolean => matches.get_flag(name).then_some(Value::Bool(true)),
            JsonSchemaType::Integer => matches.get_one::<i64>(name).map(|value| json!(value)),
            JsonSchemaType::Number => matches
                .get_one::<f64>(name)
                .and_then(|value| serde_json::Number::from_f64(*value))
                .map(Value::Number),
            JsonSchemaType::String => matches.get_one::<String>(name).map(|value| json!(value)),
            JsonSchemaType::Object => matches
                .get_one::<String>(name)
                .map(|value| parse_cli_value(schema, value))
                .transpose()?,
            JsonSchemaType::Array => {
                let Some(arguments) = matches.get_many::<String>(name) else {
                    continue;
                };
                let item_schema = schema.items.as_deref().ok_or(io::ErrorKind::InvalidData)?;
                Some(Value::Array(
                    arguments
                        .map(|value| parse_cli_value(item_schema, value))
                        .collect::<io::Result<Vec<_>>>()?,
                ))
            }
        };
        if let Some(value) = value {
            values.insert(name.clone(), value);
        }
    }
    Ok(())
}

fn parse_cli_value(schema: &JsonSchema, value: &str) -> io::Result<Value> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, Cause::BadInput);
    match schema.schema_type {
        JsonSchemaType::String => Ok(json!(value)),
        JsonSchemaType::Integer => value.parse::<i64>().map(Value::from).map_err(|_| invalid()),
        JsonSchemaType::Number => value
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .ok_or_else(invalid),
        JsonSchemaType::Boolean => value
            .parse::<bool>()
            .map(Value::Bool)
            .map_err(|_| invalid()),
        JsonSchemaType::Object | JsonSchemaType::Array => {
            let parsed: Value = serde_json::from_str(value).map_err(|_| invalid())?;
            let has_expected_shape = match schema.schema_type {
                JsonSchemaType::Object => parsed.is_object(),
                JsonSchemaType::Array => parsed.is_array(),
                _ => true,
            };
            has_expected_shape.then_some(parsed).ok_or_else(invalid)
        }
    }
}

async fn execute(
    state: &std::path::Path,
    registry: &PluginRegistry,
    command: &str,
    action: &str,
    mut input: Value,
    json_output: bool,
) -> io::Result<Exit> {
    let mut pages = None;
    loop {
        let output = call(state, action, &input).await?;
        let value: Value = serde_json::from_slice(&output).map_err(io::Error::other)?;
        let next_cursor = value
            .get("next_cursor")
            .filter(|cursor| !cursor.is_null())
            .cloned();
        if let Some(all_pages) = &mut pages {
            merge_page(all_pages, value)?;
        } else {
            pages = Some(value);
        }
        let Some(cursor) = next_cursor else {
            break;
        };
        let object = input.as_object_mut().ok_or(io::ErrorKind::InvalidData)?;
        if object.get("cursor") == Some(&cursor) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        object.insert("cursor".into(), cursor.clone());
    }

    let value = pages.ok_or(io::ErrorKind::InvalidData)?;
    if let Some((result, exit)) = component_error_result(command, &value) {
        emit(result, json_output, exit);
        return Ok(exit);
    }
    // Present and write only after every page succeeds, so the envelope describes the whole list.
    let output = serde_json::to_vec(&value).map_err(io::Error::other)?;
    // A write may show the current status of what it changed.
    let presentation = registry
        .human_status_action(action)
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let shown = if let Some(presentation) = presentation {
        call(state, presentation, &json!({})).await?
    } else {
        output
    };
    let width = RenderOptions::detect(false).usable_width();
    let presented = registry
        .present(presentation.unwrap_or(action), &shown, width)
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let mut result = CommandResult::new(
        command,
        state_of(&presented),
        presented.message.clone(),
        presented.data.clone(),
    )
    .with_body(presented.body.clone());
    for next in &presented.next {
        result = result.with_next_step(next.clone());
    }
    print(&result, json_output, false);
    Ok(Exit::Ok)
}

/// Combine the array records from successive pages and retain the final page's metadata.
fn merge_page(all_pages: &mut Value, page: Value) -> io::Result<()> {
    let Value::Object(page) = page else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    let Some(all_pages) = all_pages.as_object_mut() else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    for (key, value) in page {
        match all_pages.entry(key) {
            serde_json::map::Entry::Vacant(entry) => {
                entry.insert(value);
            }
            serde_json::map::Entry::Occupied(mut entry) => match (entry.get_mut(), value) {
                (Value::Array(all), Value::Array(mut next)) => all.append(&mut next),
                (current, value) => *current = value,
            },
        }
    }
    Ok(())
}
