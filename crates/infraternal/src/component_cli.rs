//! Generates node component commands from plugin declarations; execution and human presentation stay in their plugins [16,198,202].
use clap::{Arg, ArgAction, ArgMatches, Command};
use infraternal_plugin_api::{PluginDescriptor, PluginRegistry};
use serde_json::{Value, json};
use std::{
    io::{self, Read},
    path::PathBuf,
    process::ExitCode,
};

pub(crate) fn command(descriptor: &'static PluginDescriptor) -> Command {
    let mut command = Command::new(descriptor.id)
        .about(format!("Manage the {} node component", descriptor.id))
        .subcommand_required(true)
        .arg(
            Arg::new("state")
                .long("state")
                .global(true)
                .value_parser(clap::value_parser!(PathBuf))
                .help("Private runtime directory of the running infraternal agent"),
        );
    for action in descriptor.actions {
        if let Some(name) = action.id.strip_prefix(&format!("{}.", descriptor.id)) {
            command = command.subcommand(
                Command::new(name)
                    .about(action.summary)
                    .long_about(action.help())
                    .arg(
                        Arg::new("input-stdin")
                            .long("input-stdin")
                            .action(ArgAction::SetTrue)
                            .help("Read the action's bounded JSON input from standard input"),
                    ),
            );
        }
    }
    command
}
pub(crate) fn run(
    descriptor: &'static PluginDescriptor,
    registry: &PluginRegistry,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    let Some((name, arguments)) = matches.subcommand() else {
        return refuse(json_output, descriptor.id, "Choose a component action.");
    };
    let Some(action) = descriptor
        .actions
        .iter()
        .find(|action| action.id.strip_prefix(&format!("{}.", descriptor.id)) == Some(name))
    else {
        return refuse(
            json_output,
            descriptor.id,
            "The component action is unavailable.",
        );
    };
    let result = (|| {
        let input = if arguments.get_flag("input-stdin") {
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
        let state =
            infraternal_agent::sessions::state_path(matches.get_one::<PathBuf>("state").cloned())?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(execute(&state, registry, action.id, input, json_output))
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
