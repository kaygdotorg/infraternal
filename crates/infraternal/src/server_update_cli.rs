//! `infraternal server update …`: update the running server from a shell on its own machine (#211, D400).
//!
//! The commands are a thin client over the server's `release.update.*` actions, the same ones the
//! web app's Updates page uses:
//!
//! | command | action |
//! |---|---|
//! | `status` | `release.update.status` |
//! | `check [VERSION]` | `release.update.check` (with a version: stage exactly that release) |
//! | `apply [VERSION] [--no-wait]` | `release.update.apply`, then wait for the outcome |
//! | `rollback [--no-wait]` | `release.update.rollback`, then wait for the outcome |
//! | `cancel` | `release.update.cancel` |
//! | `history` | `release.update.history` |
//! | `settings --quiet-minutes N` | `release.update.settings` |
//!
//! They reach the running server through its private control socket
//! ([`infraternal_server::release_control`]), so they work only on the server machine, as root or
//! the account the server runs as, and need no passkey there (D400). Every command prints the
//! stable result envelope with `--json`, and a short readable report otherwise.
//!
//! `apply` and `rollback` wait, by default, until the server has switched and the new version has
//! passed its health check (or the server went back by itself), reading the outcome from the
//! status the server records. The warm restart closes the connection that asked, so a missing
//! answer to those two requests is expected and is not an error.
use crate::cli::output::{CommandResult, CommandState, Exit, emit};
use infraternal_plugin_release::descriptor::UPDATE_WAIT_MINUTES;
use infraternal_server::release_control::{CallError, call};
use serde_json::{Value, json};
use std::{path::Path, process::ExitCode, time::Duration};

/// How often `apply` and `rollback` read the status while they wait.
const POLL: Duration = Duration::from_secs(1);

/// Run one `infraternal server update <name>` command selected by `definition`.
///
/// `matches` carries `--data` and the command's own inputs (`VERSION`, `--no-wait`,
/// `--quiet-minutes`). Prints the result and returns its exit code (D303).
pub(crate) fn run(
    definition: &infraternal_plugin_api::ActionDefinition,
    matches: &clap::ArgMatches,
    json_output: bool,
) -> ExitCode {
    let command = definition.command.join(" ");
    let (Some(source), Some(name)) = (definition.hosted, definition.command.last()) else {
        return failure(&command, json_output, &Failure::not_update());
    };
    let version = matches
        .try_get_one::<String>("version")
        .ok()
        .flatten()
        .cloned();
    let quiet = matches.try_get_one::<i64>("quiet_minutes").ok().flatten();
    let no_wait = matches.try_get_one::<bool>("no_wait").ok().flatten() == Some(&true);
    let input = match input(name, version.as_deref(), quiet.copied()) {
        Ok(input) => input,
        Err(refused) => return failure(&command, json_output, &refused),
    };
    let data = crate::server_data_directory(
        matches.get_one::<String>("data").map(String::as_str),
        infraternal_status::Roots::detect,
    );
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return failure(&command, json_output, &Failure::runtime());
    };
    let report = crate::block_on(&runtime, async {
        if matches!(name.as_str(), "apply" | "rollback") {
            switch(&data, name, source.id, &input, version.as_deref(), no_wait).await
        } else {
            call(&data, source.id, &input)
                .await
                .map(|value| present(name, value))
                .map_err(|error| Failure::from_call(&error))
        }
    });
    match report {
        Ok(report) => {
            let mut result = CommandResult::new(
                &command,
                report.state,
                report.message,
                json!({"update": report.data}),
            )
            .with_body(report.body);
            for next in report.next {
                result = result.with_next_step(next);
            }
            emit(result, json_output, report.exit)
        }
        Err(refused) => failure(&command, json_output, &refused),
    }
}

/// A finished command, ready to print.
#[derive(Debug, PartialEq)]
struct Report {
    /// The envelope's state.
    state: CommandState,
    /// One sentence saying what happened.
    message: String,
    /// The aligned lines people see under the message (empty for none).
    body: String,
    /// Follow-ups that are true now.
    next: Vec<String>,
    /// The server's answer, kept whole in the envelope's `data.update`.
    data: Value,
    /// The exit code.
    exit: Exit,
}

impl Report {
    /// A successful report with no body.
    fn done(message: impl Into<String>, data: Value) -> Self {
        Self {
            state: CommandState::Ready,
            message: message.into(),
            body: String::new(),
            next: Vec::new(),
            data,
            exit: Exit::Ok,
        }
    }
}

/// A command that did not get the server's answer, or was refused.
#[derive(Debug, PartialEq)]
struct Failure {
    /// What went wrong, in one sentence.
    message: String,
    /// What to do about it.
    next: &'static str,
    /// The exit code.
    exit: Exit,
}

impl Failure {
    /// The definition is not one of the update commands.
    fn not_update() -> Self {
        Self {
            message: "That is not an update command.".into(),
            next: "infraternal server update status",
            exit: Exit::Usage,
        }
    }
    /// The async runtime could not start.
    fn runtime() -> Self {
        Self {
            message: "The command could not start its async runtime.".into(),
            next: "Free some memory or threads on this machine, then run it again.",
            exit: Exit::Failed,
        }
    }
    /// Map a control-socket failure to its sentence, next step and exit code.
    fn from_call(error: &CallError) -> Self {
        match error {
            CallError::NotRunning => Self {
                message: "No running server answered in that data directory.".into(),
                next: "Start the server, or pass --data with the data directory of the running server.",
                exit: Exit::Unreachable,
            },
            CallError::NotAllowed => Self {
                message: "Only root or the account the server runs as may update the server."
                    .into(),
                next: "Run it as root on the server machine, for example with sudo.",
                exit: Exit::NotAllowed,
            },
            CallError::Closed => Self {
                message: "The running server closed the connection without answering.".into(),
                next: "Run it as root. A server older than this command has no update controls; check its version with infraternal --version.",
                exit: Exit::Unreachable,
            },
            CallError::Refused(reason) if reason == "invalid input" => Self {
                message: "The server did not accept those inputs.".into(),
                next: "See infraternal server update --help.",
                exit: Exit::Usage,
            },
            CallError::Refused(reason) => Self {
                message: format!("The server refused: {reason}."),
                next: "Read the update state with infraternal server update status.",
                exit: Exit::Failed,
            },
            CallError::Broken => Self {
                message: "The server's answer could not be read.".into(),
                next: "Run it again; if it keeps failing, check the server's log.",
                exit: Exit::Failed,
            },
        }
    }
}

/// Print a failure with its next step and return its exit code.
fn failure(command: &str, json_output: bool, failure: &Failure) -> ExitCode {
    let state = if failure.exit == Exit::NotAllowed || failure.exit == Exit::Usage {
        CommandState::Refused
    } else {
        CommandState::Failed
    };
    let result = CommandResult::new(command, state, failure.message.clone(), json!({}))
        .with_next_step(failure.next);
    emit(result, json_output, failure.exit)
}

/// The action's JSON input for command `name`, from its parsed arguments.
///
/// `check` and `apply` send their optional `version`; `settings` needs `--quiet-minutes`
/// between 1 and 1440 (checked here so a typo is a usage error, not a server refusal); the
/// other commands send `{}`.
fn input(name: &str, version: Option<&str>, quiet: Option<i64>) -> Result<Value, Failure> {
    match name {
        "check" | "apply" => Ok(version.map_or_else(|| json!({}), |v| json!({"version": v}))),
        "settings" => match quiet {
            Some(minutes) if (1..=1440).contains(&minutes) => Ok(json!({"quiet_minutes": minutes})),
            _ => Err(Failure {
                message: "--quiet-minutes must be a whole number of minutes from 1 to 1440.".into(),
                next: "infraternal server update settings --quiet-minutes 5",
                exit: Exit::Usage,
            }),
        },
        "status" | "rollback" | "cancel" | "history" => Ok(json!({})),
        _ => Err(Failure::not_update()),
    }
}

/// Turn the answer of a command other than `apply` and `rollback` into its report.
fn present(name: &str, value: Value) -> Report {
    match name {
        "status" => {
            let mut report = Report::done(status_message(&value), Value::Null);
            report.body = status_body(&value);
            if value["staged"].is_string() {
                report
                    .next
                    .push("Apply it now with infraternal server update apply.".into());
            }
            report.data = value;
            report
        }
        "check" => {
            let version = value["version"].as_str().unwrap_or("");
            let message = match value["outcome"].as_str() {
                Some("staged") => format!("Staged {version}; it applies in the next quiet window."),
                Some("held") => {
                    format!("{version} is staged and held until you apply or cancel it.")
                }
                Some("current") => {
                    format!("Up to date: the channel offers {version}, which is running.")
                }
                Some("refused") => format!(
                    "Nothing staged: {}.",
                    value["reason"]
                        .as_str()
                        .unwrap_or("the release was refused")
                ),
                _ => "The channel offers no release yet.".to_owned(),
            };
            let mut report = Report::done(message, value);
            if matches!(report.data["outcome"].as_str(), Some("staged" | "held")) {
                report
                    .next
                    .push("Apply it now with infraternal server update apply.".into());
            }
            report
        }
        "cancel" => Report::done(
            "Cancelled the held release; periodic checks run again.",
            value,
        ),
        "history" => {
            let entries = value["entries"].as_array().map_or(0, Vec::len);
            let mut report = Report::done(
                if entries == 0 {
                    "The updater has done nothing yet.".to_owned()
                } else {
                    format!("The last {entries} things the updater did, newest first.")
                },
                Value::Null,
            );
            report.body = history_body(&value);
            report.data = value;
            report
        }
        "settings" => Report::done(
            format!(
                "Updates now wait for {} quiet minutes before they apply by themselves.",
                value["quiet_minutes"]
            ),
            value,
        ),
        _ => Report::done("Done.", value),
    }
}

/// `apply` or `rollback`: start the switch, then (unless `no_wait`) wait for its outcome.
///
/// The status is read first, so the outcome can be told apart from the previous switch's, and so
/// the target is known even when the warm restart closes the connection before the answer.
async fn switch(
    data: &Path,
    name: &str,
    action: &str,
    input: &Value,
    version: Option<&str>,
    no_wait: bool,
) -> Result<Report, Failure> {
    let status = infraternal_plugin_release::descriptor::UPDATE_STATUS.id;
    let before = call(data, status, &json!({}))
        .await
        .map_err(|error| Failure::from_call(&error))?;
    let started = match call(data, action, input).await {
        Ok(started) => Some(started),
        // The warm restart closes this connection; the switch has started.
        Err(CallError::Closed) => None,
        Err(error) => return Err(Failure::from_call(&error)),
    };
    let target = started
        .as_ref()
        .and_then(|started| started["to"].as_str().map(str::to_owned))
        .or_else(|| version.map(str::to_owned))
        .or_else(|| {
            let planned = if name == "rollback" {
                &before["rollback"]["to"]
            } else {
                &before["staged"]
            };
            planned.as_str().map(str::to_owned)
        })
        .unwrap_or_default();
    let started = started.unwrap_or(Value::Null);
    if no_wait {
        let mut report = Report::done(
            format!("Switching to {target}; the server restarts warm."),
            json!({"started": started}),
        );
        report
            .next
            .push("Follow it with infraternal server update status.".into());
        return Ok(report);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(UPDATE_WAIT_MINUTES * 60);
    loop {
        // Polling, not a fixed wait: the server answers again as soon as its successor listens.
        tokio::time::sleep(POLL).await;
        if let Ok(now) = call(data, status, &json!({})).await
            && let Some(report) = finished(name, &before, &now, &target, &started)
        {
            return Ok(report);
        }
        if tokio::time::Instant::now() >= deadline {
            let mut report = Report::done(
                format!(
                    "The switch to {target} has not finished after {UPDATE_WAIT_MINUTES} minutes."
                ),
                json!({"started": started}),
            );
            report.state = CommandState::Unknown;
            report.exit = Exit::Partial;
            report
                .next
                .push("Follow it with infraternal server update status.".into());
            return Ok(report);
        }
    }
}

/// The report for a finished switch, or `None` while it is still running.
///
/// A switch has finished when the server records a new outcome (`applied` differs from the one
/// read `before`): for `apply`, the outcome of the switch to `target`; for `rollback`, an undo
/// with the server running `target` again.
fn finished(
    name: &str,
    before: &Value,
    now: &Value,
    target: &str,
    started: &Value,
) -> Option<Report> {
    let applied = &now["applied"];
    if applied.is_null() || *applied == before["applied"] {
        return None;
    }
    let outcome = applied["outcome"].as_str().unwrap_or("");
    let reason = applied["reason"]
        .as_str()
        .unwrap_or("no reason was recorded");
    let current = now["current"].as_str().unwrap_or("");
    let data = json!({"started": started, "state": now});
    let mut report = if name == "rollback" {
        if outcome != "undone" || current != target {
            return None;
        }
        let lost = started["lost_since"]
            .as_i64()
            .or_else(|| before["rollback"]["copy_taken_at"].as_i64())
            .map_or_else(String::new, |at| {
                format!(" Changes made after {} were lost.", when(at))
            });
        Report::done(format!("Back on {current}.{lost}"), data)
    } else {
        if applied["version"].as_str() != Some(target) {
            return None;
        }
        match outcome {
            "applied" => {
                let mut report = Report::done(
                    format!(
                        "Updated to {target}. It passed its health check; the server restarted warm."
                    ),
                    data,
                );
                report
                    .next
                    .push("Go back with infraternal server update rollback.".into());
                report
            }
            "undone" => Report {
                state: CommandState::Failed,
                message: format!(
                    "The update to {target} was undone: {reason}. The server runs {current}."
                ),
                body: String::new(),
                next: vec!["See what happened with infraternal server update history.".into()],
                data,
                exit: Exit::Failed,
            },
            _ => Report {
                state: CommandState::Failed,
                message: format!("{target} was not applied: {reason}."),
                body: String::new(),
                next: vec!["Read the update state with infraternal server update status.".into()],
                data,
                exit: Exit::Failed,
            },
        }
    };
    report.body = status_body(now);
    Some(report)
}

/// The status in one sentence: what runs, on which channel, and whether updates are on.
fn status_message(state: &Value) -> String {
    let current = state["current"].as_str().unwrap_or("an unknown version");
    let channel = state["channel"].as_str().unwrap_or("stable");
    match (state["mode"].as_str(), state["reason"].as_str()) {
        (Some("off"), Some(reason)) => {
            format!("Running {current} on {channel}. Updates are off: {reason}.")
        }
        _ => format!("Running {current} on {channel}. Updates are on."),
    }
}

/// The status as aligned `label  value` lines, leaving out what is not set.
fn status_body(state: &Value) -> String {
    let text = |key: &str| state[key].as_str().map(str::to_owned);
    let mut rows: Vec<(&str, String)> = Vec::new();
    if let Some(available) = text("available") {
        rows.push(("Newest", available));
    }
    match (text("staged"), text("hold")) {
        (Some(staged), Some(hold)) if staged == hold => {
            rows.push((
                "Staged",
                format!("{staged} (held until applied or cancelled)"),
            ));
        }
        (Some(staged), _) => rows.push(("Staged", staged)),
        (None, _) => rows.push(("Staged", "nothing".into())),
    }
    if let Some(at) = state["last_check"].as_i64() {
        let error =
            text("last_error").map_or_else(String::new, |error| format!(" (failed: {error})"));
        rows.push(("Last check", format!("{}{error}", when(at))));
    }
    if let Some(refused) = text("refused") {
        rows.push(("Refused", refused));
    }
    if let Some(at) = state["next_check"].as_i64() {
        rows.push(("Next check", when(at)));
    }
    if let Some(minutes) = state["quiet_minutes"].as_u64() {
        rows.push(("Quiet window", format!("{minutes} minutes")));
    }
    let applied = &state["applied"];
    if let (Some(version), Some(outcome)) =
        (applied["version"].as_str(), applied["outcome"].as_str())
    {
        let at = applied["at"]
            .as_i64()
            .map_or_else(String::new, |at| format!(", {}", when(at)));
        let reason = applied["reason"]
            .as_str()
            .map_or_else(String::new, |r| format!(": {r}"));
        rows.push(("Last switch", format!("{version} {outcome}{at}{reason}")));
    }
    if let Some(paused) = text("paused") {
        rows.push((
            "Paused",
            format!("{paused} (failed here; not staged again by itself)"),
        ));
    }
    match (
        state["rollback"]["to"].as_str(),
        state["rollback"]["copy_taken_at"].as_i64(),
    ) {
        (Some(to), Some(at)) => rows.push((
            "Roll back",
            format!("to {to}; changes made after {} would be lost", when(at)),
        )),
        _ => rows.push(("Roll back", "nothing to go back to".into())),
    }
    let width = rows.iter().map(|(label, _)| label.len()).max().unwrap_or(0);
    rows.iter()
        .map(|(label, value)| format!("{label:<width$}  {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The history as one line per entry: when, what, which version, and why.
fn history_body(history: &Value) -> String {
    history["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            let at = entry["at"].as_i64().map_or_else(|| "-".to_owned(), when);
            let kind = entry["kind"].as_str().unwrap_or("-").replace('_', " ");
            let version = entry["version"].as_str().unwrap_or("-");
            let detail = entry["detail"]
                .as_str()
                .map_or_else(String::new, |d| format!("  {d}"));
            format!("{at}  {kind:<11}  {version}{detail}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Unix seconds as a UTC date and time people can read, such as `2026-11-22 04:30 UTC`.
fn when(seconds: i64) -> String {
    let (year, month, day, hour, minute, _) =
        crate::install_move::utc_parts(u64::try_from(seconds).unwrap_or(0));
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

/// Argument parsing, inputs, refusals and readable output of the update commands.
#[cfg(test)]
#[path = "server_update_cli_tests.rs"]
mod tests;
