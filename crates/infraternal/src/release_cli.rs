//! Presents declared release actions for an existing server, requiring deliberate edge confirmation [16,201,202,226].
use infraternal_plugin_release::descriptor::{CHANNEL_GET, CHANNEL_SET, EDGE_WARNING, LATEST};
use serde_json::json;
use std::{
    io::{BufRead, IsTerminal, Read, Write},
    path::Path,
    process::ExitCode,
};

/// Human confirmation is accepted only from a TTY; automation must pass --yes.
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
#[allow(clippy::verbose_bit_mask)]
pub(crate) fn run(
    runtime: &tokio::runtime::Runtime,
    data: &Path,
    command: &super::ServerAction,
    json_output: bool,
) -> ExitCode {
    let (channel, yes, latest) = match command {
        super::ServerAction::Channel { channel, yes } => (channel.as_deref(), *yes, false),
        super::ServerAction::Release {
            action: super::ReleaseAction::Latest,
        } => (None, false, true),
        _ => {
            return crate::output::refuse(
                json_output,
                LATEST.id,
                "Invalid release command",
                "Choose server channel or server release latest.",
                2,
            );
        }
    };
    let action = if latest {
        LATEST.id
    } else if channel.is_some() {
        CHANNEL_SET.id
    } else {
        CHANNEL_GET.id
    };
    let input = channel.map_or_else(
        || json!({}),
        |channel| json!({"channel":channel,"confirmed":confirmed(Some(channel),yes)}),
    );
    let result = runtime.block_on(async {
        use std::os::unix::fs::MetadataExt;
        let directory =
            std::fs::symlink_metadata(data).map_err(|_| "existing server unavailable")?;
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
        let result = infraternal_server::release_service(pool.clone(), data)
            .call(action, &bytes, None)
            .await;
        pool.close().await;
        result
    });
    match result {
        Ok(value) => present(value, action, json_output),
        Err(error) => crate::output::refuse(
            json_output,
            action,
            error,
            if channel == Some("edge") && error == EDGE_WARNING {
                "Confirm explicitly on a TTY or pass --yes to acknowledge unreviewed edge builds."
            } else {
                "Check the existing server's --data directory, release settings and verification."
            },
            1,
        ),
    }
}

fn present(mut value: serde_json::Value, action: &str, json_output: bool) -> ExitCode {
    if json_output {
        value["action"] = json!(action);
        println!("{value}");
    } else {
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
        let state = value
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or("configured");
        let next = value
            .get("next")
            .and_then(|v| v.as_str())
            .unwrap_or("Read the selected channel with infraternal server release latest.");
        crate::output::report(false, action, state, &message, next);
    }
    ExitCode::SUCCESS
}
