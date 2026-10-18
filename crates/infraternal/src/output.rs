//! Progress and refusal records of the operator commands, in the one envelope every command uses (#239, D202, D299).
//!
//! Operator commands such as `agent join` print a record per step. Each record is a
//! complete result of the shared kind, so scripts read them line by line and people
//! read the same plain sentences. Internal action ids map to the command a person typed.

use std::process::ExitCode;

use crate::cli::output::{CommandResult, CommandState, Exit, emit, print_progress};
use serde_json::json;

/// The command path a person typed for an operator action id.
fn command_for(action: &str) -> &str {
    match action {
        "remote.host.join" => "agent join",
        "remote.host.run" => "agent run",
        "remote.host.remove" => "remove-host",
        "remote.server.restart" => "server restart",
        "internal.key-memory-check" => "__key-memory-check",
        "agent.embedded" => "agent",
        other => other,
    }
}

fn state_of(word: &str) -> CommandState {
    match word {
        "starting" => CommandState::Running,
        "stopped" => CommandState::Stopped,
        "confirmation required" => CommandState::Pending,
        "refused" => CommandState::Refused,
        _ => CommandState::Ready,
    }
}

/// A progress record of a command that is still working. In JSON mode it goes to standard
/// error, so standard output carries exactly one envelope: the command's final result.
/// People see it on standard output as they always did. Callers report only confirmed states.
pub(crate) fn report(json: bool, action: &str, state: &str, message: &str, next: &str) {
    let mut result = CommandResult::new(command_for(action), state_of(state), message, json!({}));
    if !next.is_empty() {
        result = result.with_next_step(next);
    }
    print_progress(&result, json, json);
}

/// The final, successful result of a command: the one envelope on standard output.
pub(crate) fn done(json: bool, action: &str, state: &str, message: &str, next: &str) -> ExitCode {
    let mut result = CommandResult::new(command_for(action), state_of(state), message, json!({}));
    if !next.is_empty() {
        result = result.with_next_step(next);
    }
    emit(result, json, Exit::Ok)
}

/// Static refusals do not reflect a path, invitation, proof or private identity.
pub(crate) fn refuse(json: bool, action: &str, message: &str, next: &str, exit: Exit) -> ExitCode {
    let mut result = CommandResult::new(
        command_for(action),
        CommandState::Refused,
        message,
        json!({}),
    );
    if !next.is_empty() {
        result = result.with_next_step(next);
    }
    emit(result, json, exit)
}
