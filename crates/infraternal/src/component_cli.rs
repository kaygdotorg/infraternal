//! Runs node component commands against the local infraternal agent and presents the reply in the shared envelope [16,198,202], #239.
//!
//! Commands come from plugin declarations; this module knows no plugin fields. The plugin
//! presents its own reply (`present`), and the answer, the aligned text and the JSON data
//! all come from that one presentation.
use clap::ArgMatches;
use infraternal_plugin_api::{
    PluginRegistry,
    present::{Presented, Tone},
};
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    path::PathBuf,
    process::ExitCode,
};

use crate::cli::output::{CommandResult, CommandState, Exit, RenderOptions, emit, print};

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
        let mut input = if arguments.get_flag("input_stdin") {
            let mut bytes = Vec::new();
            io::stdin()
                .take((infraternal_plugin_api::MAX_ACTION_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > infraternal_plugin_api::MAX_ACTION_BYTES {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            serde_json::from_slice(&bytes).map_err(io::Error::other)?
        } else {
            json!({})
        };
        for (name, schema) in &definition.input_schema.properties {
            if name != "input_stdin"
                && schema.schema_type == infraternal_plugin_api::JsonSchemaType::Boolean
                && arguments.get_flag(name)
            {
                input
                    .as_object_mut()
                    .ok_or(io::ErrorKind::InvalidInput)?
                    .insert(name.clone(), Value::Bool(true));
            }
        }
        let state = infraternal_agent::sessions::state_path(
            arguments.get_one::<String>("state").map(PathBuf::from),
        )?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(execute(
                &state,
                &registry,
                &command,
                action.id,
                input,
                json_output,
            ))
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => refuse(json_output, &command, &error),
    }
}

/// Say which of the possible causes it was, and the one thing to do about it.
fn refuse(json_output: bool, command: &str, error: &io::Error) -> ExitCode {
    let (message, why, next) = match error.kind() {
        io::ErrorKind::NotFound => (
            "The infraternal agent on this machine is not running.",
            "No agent socket was found in its runtime directory.",
            "infraternal status",
        ),
        io::ErrorKind::ConnectionRefused => (
            "The infraternal agent on this machine is not running.",
            "Its socket is there, but nothing answers on it.",
            "infraternal status",
        ),
        io::ErrorKind::PermissionDenied => (
            "This account is not allowed to use the infraternal agent here.",
            "The agent answers only the account that runs it.",
            "Run this command as the account that runs the infraternal agent.",
        ),
        io::ErrorKind::TimedOut => (
            "The infraternal agent did not answer in time.",
            "There was no reply within 5 seconds.",
            "infraternal status",
        ),
        _ => (
            "The infraternal agent could not complete this request.",
            "It sent a reply this command does not understand.",
            "infraternal status",
        ),
    };
    emit(
        CommandResult::new(command, CommandState::Failed, message, json!({}))
            .with_details(why)
            .with_next_step(next),
        json_output,
        Exit::Failed,
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

async fn execute(
    state: &std::path::Path,
    registry: &PluginRegistry,
    command: &str,
    action: &str,
    mut input: Value,
    json_output: bool,
) -> io::Result<()> {
    loop {
        let output = call(state, action, &input).await?;
        let value: Value = serde_json::from_slice(&output).map_err(io::Error::other)?;
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
        let Some(cursor) = value.get("next_cursor").filter(|cursor| !cursor.is_null()) else {
            return Ok(());
        };
        let object = input.as_object_mut().ok_or(io::ErrorKind::InvalidData)?;
        if object.get("cursor") == Some(cursor) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        object.insert("cursor".into(), cursor.clone());
    }
}
