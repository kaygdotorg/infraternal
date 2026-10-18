//! Generates node component commands from plugin declarations; execution and human presentation stay in their plugins [16,198,202].
use clap::ArgMatches;
use infraternal_plugin_api::PluginRegistry;
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    path::PathBuf,
    process::ExitCode,
};

pub(crate) fn run_action(
    action: &infraternal_plugin_api::ActionDefinition,
    arguments: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    let definition = action;
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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // Share the startup reactor instead of generating another poll loop [243].
        infraternal_agent::block_on_io(
            &runtime,
            Box::pin(execute(&state, &registry, action.id, input, json_output)),
        )
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => refuse(
            json_output,
            action.id,
            "The component action was refused or the local infraternal agent is unavailable.",
        ),
    }
}
fn refuse(json_output: bool, action: &str, message: &str) -> ExitCode {
    crate::output::refuse(
        json_output,
        action,
        message,
        "Use the infraternal agent's uid and runtime directory; read the action help.",
        1,
    )
}
async fn call(state: &std::path::Path, action: &str, input: &Value) -> io::Result<Vec<u8>> {
    let input = serde_json::to_vec(input).map_err(io::Error::other)?;
    infraternal_agent::plugin_control::call(state, action, &input).await
}
async fn execute(
    state: &std::path::Path,
    registry: &PluginRegistry,
    action: &str,
    mut input: Value,
    json_output: bool,
) -> io::Result<()> {
    loop {
        let output = call(state, action, &input).await?;
        let value: Value = serde_json::from_slice(&output).map_err(io::Error::other)?;
        if json_output {
            println!("{value}");
        } else {
            let presentation = registry
                .human_status_action(action)
                .map_err(|_| io::ErrorKind::InvalidData)?;
            let shown = if let Some(presentation) = presentation {
                call(state, presentation, &json!({})).await?
            } else {
                output
            };
            println!(
                "{}",
                registry
                    .format_human(presentation.unwrap_or(action), &shown)
                    .map_err(|_| io::ErrorKind::InvalidData)?
            );
        }
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
