//! `infraternal server mesh routes …`: approve the networks machines advertise, from the server machine
//! (D197 M3, #580, D400).
//!
//! | command | action |
//! |---|---|
//! | `routes` | `mesh.route.list` |
//! | `routes approve <NODE> <NETWORK> [--keep-source]` | `mesh.route.approve` |
//! | `routes revoke <ROUTE>` | `mesh.route.revoke` |
//!
//! Like `server update`, these are a thin client over the running server's own actions, reached
//! through its private control socket ([`infraternal_server::release_control`]): they work only on
//! the server machine, as root or the account the server runs as, with no passkey (D400). The web
//! app and other devices call the same actions as the owner with a fresh passkey.
//!
//! `NODE` is a mesh name or node number. A name is resolved from the route list itself, so only a
//! machine that advertises something can be named, and an unknown or ambiguous name is refused
//! before anything is sent. A refused approval (an overlap, an unroutable network) prints the
//! server's sentence and exits with a usage error.
use crate::cli::output::{CommandResult, CommandState, Exit, emit};
use infraternal_server::release_control::{CallError, call};
use serde_json::{Value, json};
use std::{path::Path, process::ExitCode};

/// Run one `infraternal server mesh routes` command selected by `definition`.
pub(crate) fn run(
    definition: &infraternal_plugin_api::ActionDefinition,
    matches: &clap::ArgMatches,
    json_output: bool,
) -> ExitCode {
    let command = definition.command.join(" ");
    let data = crate::server_data_directory(
        matches.get_one::<String>("data").map(String::as_str),
        infraternal_status::Roots::detect,
    );
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return refuse(
            &command,
            json_output,
            "The command could not start its async runtime.",
            "Free some memory or threads on this machine, then run it again.",
            Exit::Failed,
        );
    };
    let name = definition.command.last().map_or("", String::as_str);
    let result = crate::block_on(&runtime, async {
        match name {
            "approve" => {
                let node = matches
                    .get_one::<String>("node")
                    .map(String::as_str)
                    .unwrap_or_default();
                let network = matches
                    .get_one::<String>("network")
                    .map(String::as_str)
                    .unwrap_or_default();
                approve(
                    &data,
                    node,
                    network,
                    matches.try_get_one::<bool>("keep_source").ok().flatten() == Some(&true),
                )
                .await
            }
            "revoke" => {
                let route = matches.get_one::<i64>("route").copied().unwrap_or(0);
                revoke(&data, route).await
            }
            _ => list(&data).await,
        }
    });
    match result {
        Ok((message, body, data)) => emit(
            CommandResult::new(&command, CommandState::Ready, message, data).with_panel(body),
            json_output,
            Exit::Ok,
        ),
        Err((message, next, exit)) => refuse(&command, json_output, &message, next, exit),
    }
}

/// A command's printable answer: the sentence, the aligned lines, and the envelope's data.
type Answer = Result<(String, String, Value), (String, &'static str, Exit)>;

/// Print a refusal or failure with its next step and return its exit code.
fn refuse(command: &str, json_output: bool, message: &str, next: &str, exit: Exit) -> ExitCode {
    let state = if matches!(exit, Exit::NotAllowed | Exit::Usage) {
        CommandState::Refused
    } else {
        CommandState::Failed
    };
    emit(
        CommandResult::new(command, state, message, json!({})).with_next_step(next),
        json_output,
        exit,
    )
}

/// Map a control-socket failure to its sentence, next step and exit code.
fn from_call(error: CallError) -> (String, &'static str, Exit) {
    match error {
        CallError::NotRunning => (
            "No running server answered in that data directory.".into(),
            "Start the server, or pass --data with the data directory of the running server.",
            Exit::Unreachable,
        ),
        CallError::NotAllowed => (
            "Only root or the account the server runs as may manage subnet routes here.".into(),
            "Run it as root on the server machine, for example with sudo.",
            Exit::NotAllowed,
        ),
        CallError::Closed => (
            "The running server closed the connection without answering.".into(),
            "A server older than this command has no route controls; check its version with infraternal --version.",
            Exit::Unreachable,
        ),
        CallError::Refused(reason) if reason == "invalid input" => (
            "The server did not accept those inputs.".into(),
            "See infraternal server mesh routes --help.",
            Exit::Usage,
        ),
        CallError::Refused(reason) if reason == "not found" => (
            "No approved route has that number.".into(),
            "List the routes with infraternal server mesh routes.",
            Exit::NotFound,
        ),
        CallError::Refused(reason) => (
            format!("The server refused: {reason}."),
            "List the routes with infraternal server mesh routes.",
            Exit::Failed,
        ),
        CallError::Broken => (
            "The server's answer could not be read.".into(),
            "Run it again; if it keeps failing, check the server's log.",
            Exit::Failed,
        ),
    }
}

/// `routes`: every advertised network as a table.
async fn list(data: &Path) -> Answer {
    let value = call(data, "mesh.route.list", &json!({}))
        .await
        .map_err(from_call)?;
    let routes = value["routes"].as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = routes
        .iter()
        .map(|route| {
            let mut state = route["state"].as_str().unwrap_or("?").to_owned();
            if let Some(reason) = route["refused"].as_str() {
                state = format!("{state}; cannot be approved: {reason}");
            } else if route["state"] != "waiting for approval" && route["masquerade"] == false {
                state.push_str("; keeps source addresses");
            }
            vec![
                route["route_id"].to_string(),
                route["node"].as_str().unwrap_or("?").to_owned(),
                route["network"].as_str().unwrap_or("?").to_owned(),
                state,
            ]
        })
        .collect();
    let waiting = routes
        .iter()
        .filter(|route| route["state"] == "waiting for approval")
        .count();
    let message = if routes.is_empty() {
        "No machine advertises a network.".to_owned()
    } else {
        format!("{} networks, {waiting} waiting for approval.", routes.len())
    };
    let body = infraternal_plugin_api::present::table(
        &["Route", "Machine", "Network", "State"],
        &rows,
        2,
        crate::cli::output::RenderOptions::detect(false).usable_width(),
        None,
    );
    Ok((message, body, value))
}

/// `routes approve`: resolve the machine, then ask the server.
async fn approve(data: &Path, node: &str, network: &str, keep_source: bool) -> Answer {
    let network: infraternal_plugin_mesh::policy::networks::Network = network.parse().map_err(
        |error: infraternal_plugin_mesh::policy::networks::ParseNetworkError| {
            (
                format!("{error}."),
                "Write the network as address/prefix, such as 192.168.1.0/24.",
                Exit::Usage,
            )
        },
    )?;
    let node_id = if let Ok(id) = node.parse::<u64>() {
        id
    } else {
        let listed = call(data, "mesh.route.list", &json!({}))
            .await
            .map_err(from_call)?;
        let ids: std::collections::BTreeSet<u64> = listed["routes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|route| route["node"].as_str() == Some(node))
            .filter_map(|route| route["node_id"].as_u64())
            .collect();
        match ids.len() {
            1 => ids.into_iter().next().unwrap_or_default(),
            0 => {
                return Err((
                    format!("No machine named {node} advertises a network."),
                    "List the routes with infraternal server mesh routes.",
                    Exit::NotFound,
                ));
            }
            _ => {
                return Err((
                    format!("More than one machine is named {node}."),
                    "Name the machine by its node number from infraternal server mesh routes --json.",
                    Exit::Usage,
                ));
            }
        }
    };
    let value = call(
        data,
        "mesh.route.approve",
        &json!({"node_id": node_id, "network": network, "masquerade": !keep_source}),
    )
    .await
    .map_err(from_call)?;
    if value["state"] == "refused" {
        return Err((
            format!(
                "{network} cannot be approved: {}.",
                value["reason"].as_str().unwrap_or("refused")
            ),
            "List the routes with infraternal server mesh routes.",
            Exit::Usage,
        ));
    }
    let how = if keep_source {
        "peers keep their mesh addresses"
    } else {
        "traffic is masqueraded"
    };
    Ok((
        format!("Approved {network} (route {}); {how}.", value["route_id"]),
        String::new(),
        value,
    ))
}

/// `routes revoke`: ask the server to stop routing one approval.
async fn revoke(data: &Path, route: i64) -> Answer {
    if route < 1 {
        return Err((
            "Give the route number from infraternal server mesh routes.".into(),
            "infraternal server mesh routes",
            Exit::Usage,
        ));
    }
    let value = call(data, "mesh.route.revoke", &json!({"route_id": route}))
        .await
        .map_err(from_call)?;
    Ok((
        format!(
            "Revoked route {route}; {} arrows to it were removed.",
            value["arrows_removed"]
        ),
        String::new(),
        value,
    ))
}
