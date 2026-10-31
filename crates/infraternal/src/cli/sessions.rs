//! Adapts shared session actions to the bounded local control socket and D303 envelope (#251).
use super::output::{CommandResult, CommandState, Exit, emit};
use clap::ArgMatches;
use infraternal_agent::automation::{Reply, validate};
use infraternal_plugin_api::ActionDefinition;
use serde_json::{Value, json};
use std::{io, path::PathBuf, process::ExitCode};

pub fn run(action: &ActionDefinition, matches: &ArgMatches, json_output: bool) -> ExitCode {
    let verb = action.command.get(1).map_or("list", String::as_str);
    let mut input = json!({});
    for (name, schema) in &action.input_schema.properties {
        if name == "state" {
            continue;
        }
        let value = match schema.schema_type {
            infraternal_plugin_api::JsonSchemaType::Integer => {
                matches.get_one::<i64>(name).map(|n| json!(n))
            }
            infraternal_plugin_api::JsonSchemaType::Array => matches
                .get_many::<String>(name)
                .map(|args| json!(args.collect::<Vec<_>>())),
            _ => matches.get_one::<String>(name).map(|s| json!(s)),
        };
        if let Some(value) = value {
            input[name] = value;
        }
    }
    let command = action.command.join(" ");
    if let Err(reply) = validate(verb, &input) {
        return output(&command, reply, json_output);
    }
    let result = (|| {
        let state = infraternal_agent::sessions::state_path(
            matches.get_one::<String>("state").map(PathBuf::from),
        )?;
        let bytes = serde_json::to_vec(&input)?;
        if bytes.len() > infraternal_plugin_api::MAX_ACTION_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut reply = None;
        infraternal_agent::block_on_io(
            &runtime,
            Box::pin(async {
                reply = Some(execute(&state, verb, &input, &bytes).await?);
                Ok(())
            }),
        )?;
        reply.ok_or_else(|| io::ErrorKind::InvalidData.into())
    })();
    let reply = result.unwrap_or_else(|error: io::Error| {
        let code = match error.kind() {
            io::ErrorKind::InvalidInput => 2,
            io::ErrorKind::PermissionDenied => 3,
            _ => 5,
        };
        Reply { code,
            message: if code == 2 { "The session request is too large." } else { "The local infraternal agent could not accept this request." }.into(),
            next: "Use a saved session on this account and machine; check that the infraternal agent is running, then list sessions before retrying.".into(),
            data: json!({}) }
    });
    output(&command, reply, json_output)
}
fn output(command: &str, reply: Reply, json_output: bool) -> ExitCode {
    let exit = match reply.code {
        0 => Exit::Ok,
        2 => Exit::Usage,
        3 => Exit::NotAllowed,
        4 => Exit::NotFound,
        5 => Exit::Unreachable,
        6 => Exit::Partial,
        _ => Exit::Failed,
    };
    let state = if reply.code == 0 {
        CommandState::Ready
    } else {
        CommandState::Failed
    };
    let body = pretty(&reply.data);
    let mut result = CommandResult::new(command, state, reply.message, reply.data).with_body(body);
    if !reply.next.is_empty() {
        result = result.with_next_step(reply.next);
    }
    emit(result, json_output, exit)
}
fn pretty(data: &Value) -> String {
    // Retained terminal output is data. Escape control bytes in human output so
    // merely reading it cannot send terminal control sequences to this caller.
    if let Some(text) = data["text"].as_str() {
        return text
            .chars()
            .flat_map(|c| {
                if c.is_control() && !matches!(c, '\n' | '\t') {
                    c.escape_default().collect::<Vec<_>>()
                } else {
                    vec![c]
                }
            })
            .collect();
    }
    if let Some(rows) = data["sessions"].as_array() {
        return rows
            .iter()
            .map(|row| {
                format!(
                    "local:{}  {}",
                    row["name"].as_str().unwrap_or(""),
                    row["id"].as_str().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    if let Some(row) = data.get("session") {
        return format!("local:{}", row["name"].as_str().unwrap_or(""));
    }
    String::new()
}

/// The transport stays bounded while a list can contain any number of sessions.
async fn execute(
    state: &std::path::Path,
    verb: &str,
    input: &Value,
    bytes: &[u8],
) -> io::Result<Reply> {
    let action = format!("sessions.{verb}");
    let bytes = infraternal_agent::plugin_control::call(state, &action, bytes).await?;
    let mut reply: Reply = serde_json::from_slice(&bytes)?;
    if verb != "list" || reply.code != 0 {
        return Ok(reply);
    }
    let mut rows = reply.data["sessions"]
        .as_array()
        .cloned()
        .ok_or(io::ErrorKind::InvalidData)?;
    let mut previous = String::new();
    while let Some(after) = reply.data["next_after"].as_str().map(str::to_owned) {
        if after <= previous {
            return Err(io::ErrorKind::InvalidData.into());
        }
        previous.clone_from(&after);
        let mut page = input.clone();
        page["after"] = json!(after);
        let result =
            infraternal_agent::plugin_control::call(state, &action, &serde_json::to_vec(&page)?)
                .await;
        let next = result
            .and_then(|bytes| serde_json::from_slice::<Reply>(&bytes).map_err(io::Error::other));
        match next {
            Ok(next) if next.code == 0 => {
                rows.extend(
                    next.data["sessions"]
                        .as_array()
                        .ok_or(io::ErrorKind::InvalidData)?
                        .iter()
                        .cloned(),
                );
                reply = next;
            }
            _ => {
                reply.code = 6;
                reply.message = "Only part of the session list could be read.".into();
                reply.next =
                    "Check the infraternal agent connection, then run infraternal sessions again."
                        .into();
                break;
            }
        }
    }
    rows.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    reply.data = json!({"sessions": rows});
    Ok(reply)
}
