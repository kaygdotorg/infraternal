//! Presents declared release actions for an existing server, requiring deliberate edge confirmation [16,201,202,226].
use crate::cli::output::{Exit, emit};
use infraternal_plugin_release::descriptor::{CHANNEL_GET, CHANNEL_SET, EDGE_WARNING, LATEST};
use serde_json::json;
use std::{
    io::{BufRead, IsTerminal, Read, Write},
    process::ExitCode,
};

/// Decides whether the person has confirmed switching to the `edge` channel.
///
/// Only `edge` needs confirmation, so any other channel (or none) returns `false` and
/// asks nothing. For `edge` the unreviewed-builds warning always goes to standard error.
/// `--yes` confirms at once. Without it, both standard input and standard error must be a
/// terminal, the person must type exactly `yes` (at most 128 bytes are read), and anything
/// else, including a script with no terminal, counts as not confirmed.
fn confirmed(channel: Option<&str>, yes: bool) -> bool {
    if channel != Some("edge") {
        return false;
    }
    eprintln!("{EDGE_WARNING}");
    if yes {
        return true;
    }
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        return false;
    }
    eprint!("Follow edge releases? Type yes to confirm: ");
    if std::io::stderr().flush().is_err() {
        return false;
    }
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .take(128)
        .read_line(&mut answer)
        .is_ok()
        && answer.trim() == "yes"
}
/// Refuse implicit server creation and use the same service as the socket API.
///
/// Runs `infraternal server release latest`, `infraternal server channel` (read the
/// channel) or `infraternal server channel <stable|edge> [--yes]` (switch it), as selected
/// by `definition`. `matches` carries `--data` (the server's data folder) and, for a switch,
/// the channel and `--yes`.
///
/// It talks to the existing server's database directly and never creates one. Before opening
/// it, it checks that the data folder and `infraternal.sqlite` belong to the current user,
/// are private (no group or other access) and that the file is a regular file with one
/// link; otherwise it refuses. Prints the result (JSON when `json_output`) and returns the
/// exit code: success, or a refusal with the exit code and next step chosen by `classify`.
#[allow(clippy::verbose_bit_mask)]
pub(crate) fn run(
    definition: &infraternal_plugin_api::ActionDefinition,
    matches: &clap::ArgMatches,
    json_output: bool,
) -> ExitCode {
    let command = definition.command.join(" ");
    let latest = match definition.hosted.map(|source| source.id) {
        Some(id) if id == LATEST.id => true,
        Some(id) if id == CHANNEL_SET.id => false,
        _ => {
            return refusal(
                &command,
                json_output,
                "That is not a release command.",
                "infraternal server release latest",
                Exit::Usage,
            );
        }
    };
    let channel = if latest {
        None
    } else {
        matches.get_one::<String>("channel").map(String::as_str)
    };
    let yes = !latest && matches.get_flag("yes");
    let action = if latest {
        LATEST.id
    } else if channel.is_some() {
        CHANNEL_SET.id
    } else {
        CHANNEL_GET.id
    };
    let data = crate::server_data_directory(
        matches.get_one::<String>("data").map(String::as_str),
        infraternal_status::Roots::detect,
    );
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return refusal(
            &command,
            json_output,
            "The command could not start its async runtime.",
            "Free some memory or threads on this machine, then run it again.",
            Exit::Failed,
        );
    };
    let input = channel.map_or_else(
        || json!({}),
        |channel| json!({"channel":channel,"confirmed":confirmed(Some(channel),yes)}),
    );
    let result = crate::block_on(&runtime, async {
        use std::os::unix::fs::MetadataExt;
        let directory =
            std::fs::symlink_metadata(&data).map_err(|_| "existing server unavailable")?;
        let file = data.join("infraternal.sqlite");
        let metadata =
            std::fs::symlink_metadata(&file).map_err(|_| "existing server unavailable")?;
        if !directory.is_dir()
            || directory.uid() != nix::unistd::geteuid().as_raw()
            || directory.mode() & 0o077 != 0
            || !metadata.is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err("existing server storage is unsafe");
        }
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&file)
            .create_if_missing(false)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await
            .map_err(|_| "existing server unavailable")?;
        let bytes = serde_json::to_vec(&input).map_err(|_| "invalid input")?;
        let result = infraternal_server::release_service(pool.clone(), &data)
            .call(action, &bytes, None)
            .await;
        pool.close().await;
        result
    });
    match result {
        Ok(value) => present(value, &command, json_output),
        Err(error) => {
            let (message, next, exit) = classify(error);
            refusal(&command, json_output, message, next, exit)
        }
    }
}

/// Each cause of a failed release read gets its own sentence, next step and exit code (D303).
/// Maps a failure from the release service to a sentence for the person, a next step and
/// an exit code. Raw error text is never shown, so nothing from the machine leaks into output.
fn classify(error: &'static str) -> (&'static str, &'static str, Exit) {
    if error == EDGE_WARNING {
        (
            error,
            "Confirm explicitly on a TTY or pass --yes to acknowledge unreviewed edge builds.",
            Exit::NotAllowed,
        )
    } else if error == "existing server storage is unsafe" {
        (
            "The server's data directory is not private to this account.",
            "Run this as the account that owns the server's data directory.",
            Exit::NotAllowed,
        )
    } else {
        (
            "No server was found in that data directory.",
            "Pass --data with the data directory of the running server.",
            Exit::NotFound,
        )
    }
}

/// Prints a successful release read and returns success.
///
/// The message is the service's own `message` when it has one, otherwise
/// "Release channel: <channel>" (default `stable`), plus the verified version when known.
/// The whole service answer is kept in the result under `release`.
fn present(value: serde_json::Value, command: &str, json_output: bool) -> ExitCode {
    use crate::cli::output::{CommandResult, CommandState};
    let message = value.get("message").and_then(|v| v.as_str()).map_or_else(
        || {
            let channel = value["channel"].as_str().unwrap_or("stable");
            value.get("version").and_then(|v| v.as_str()).map_or_else(
                || format!("Release channel: {channel}"),
                |version| format!("Release channel: {channel}; verified version: {version}"),
            )
        },
        str::to_owned,
    );
    let next = value
        .get("next")
        .and_then(|v| v.as_str())
        .unwrap_or("Read the selected channel with infraternal server release latest.")
        .to_owned();
    let data =
        serde_json::Value::Object(serde_json::Map::from_iter([("release".to_owned(), value)]));
    let result =
        CommandResult::new(command, CommandState::Ready, message, data).with_next_step(next);
    crate::print_result(&result, json_output, false);
    ExitCode::SUCCESS
}

/// Prints a failed release command with its next step and returns `exit`.
fn refusal(command: &str, json_output: bool, message: &str, next: &str, exit: Exit) -> ExitCode {
    use crate::cli::output::{CommandResult, CommandState};
    let result =
        CommandResult::new(command, CommandState::Failed, message, json!({})).with_next_step(next);
    emit(result, json_output, exit)
}
