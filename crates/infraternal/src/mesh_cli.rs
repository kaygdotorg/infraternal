//! Generates Mesh operator commands from node action declarations and calls the private local control surface [16,198,202].
use clap::{Arg, ArgMatches, Command};
use serde_json::{Value, json};
use std::{io, path::PathBuf, process::ExitCode};

fn actions() -> &'static [infraternal_plugin_api::ActionDef] {
    infraternal_agent::plugins::descriptors()
        .iter()
        .find(|descriptor| descriptor.id == "mesh")
        .map_or(&[], |descriptor| descriptor.actions)
}
/// Every subcommand label and help text comes from the compiled public registry.
pub(crate) fn command() -> Command {
    let mut command = Command::new("mesh")
        .about("Manage Mesh on this node")
        .subcommand_required(true)
        .arg(
            Arg::new("state")
                .long("state")
                .value_parser(clap::value_parser!(PathBuf))
                .help("Private runtime directory used by the running infraternal agent"),
        );
    for action in actions() {
        if let Some(name) = action.id.strip_prefix("mesh.") {
            command = command.subcommand(
                Command::new(name)
                    .about(action.summary)
                    .long_about(action.help()),
            );
        }
    }
    command
}
pub(crate) fn run(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let Some((name, _)) = matches.subcommand() else {
        return crate::output::refuse(
            json_output,
            "mesh",
            "Choose a Mesh action.",
            "Read infraternal mesh --help.",
            2,
        );
    };
    let Some(action) = actions()
        .iter()
        .find(|action| action.id.strip_prefix("mesh.") == Some(name))
    else {
        return crate::output::refuse(
            json_output,
            "mesh",
            "Mesh is unavailable.",
            "Use a build with the Mesh component.",
            2,
        );
    };
    let result = (|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let state =
            infraternal_agent::sessions::state_path(matches.get_one::<PathBuf>("state").cloned())?;
        runtime.block_on(execute(&state, action.id, json_output))
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => crate::output::refuse(
            json_output,
            action.id,
            "Mesh action refused or the local infraternal agent is unavailable.",
            "Run as the infraternal agent's uid and check its runtime directory; read the action help.",
            1,
        ),
    }
}
async fn call(state: &std::path::Path, action: &str, input: &Value) -> io::Result<Value> {
    let input = serde_json::to_vec(input).map_err(io::Error::other)?;
    let reply = infraternal_agent::plugin_control::call(state, action, &input).await?;
    serde_json::from_slice(&reply).map_err(io::Error::other)
}
async fn execute(state: &std::path::Path, action: &str, json_output: bool) -> io::Result<()> {
    if action == "mesh.peers" {
        let mut cursor = Value::Null;
        if !json_output {
            println!(
                "Mesh peers\n  {:>8}  {:<39}  {:<47}  {:<10}  {:>12}  {:>12}",
                "Node", "Address", "Endpoint", "Path", "RX bytes", "TX bytes"
            );
        }
        loop {
            let reply = call(state, action, &json!({"cursor":cursor})).await?;
            if json_output {
                println!("{reply}");
            } else {
                for peer in reply["peers"]
                    .as_array()
                    .ok_or(io::ErrorKind::InvalidData)?
                {
                    println!(
                        "  {:>8}  {:<39}  {:<47}  {:<10}  {:>12}  {:>12}",
                        peer["node"].as_u64().ok_or(io::ErrorKind::InvalidData)?,
                        peer["peer"]["addresses"]["ipv4"]
                            .as_str()
                            .ok_or(io::ErrorKind::InvalidData)?,
                        peer["peer"]["endpoint"].as_str().unwrap_or("Unlearned"),
                        peer["path"].as_str().ok_or(io::ErrorKind::InvalidData)?,
                        peer["counters"]["received_bytes"].as_u64().unwrap_or(0),
                        peer["counters"]["sent_bytes"].as_u64().unwrap_or(0)
                    );
                }
            }
            cursor = reply["next_cursor"].clone();
            if cursor.is_null() {
                break;
            }
        }
        if !json_output {
            println!("\n  Next  Send traffic to establish an unproven direct path.");
        }
        return Ok(());
    }
    let reply = call(state, action, &json!({})).await?;
    if json_output {
        println!("{reply}");
        return Ok(());
    }
    let status = if action == "mesh.status" {
        reply
    } else {
        call(state, "mesh.status", &json!({})).await?
    };
    let state = status["state"].as_str().ok_or(io::ErrorKind::InvalidData)?;
    println!(
        "Mesh\n  State    {state}\n  Peers    {}",
        status["peer_count"].as_u64().unwrap_or(0)
    );
    if let Some(version) = status["version"].as_u64() {
        println!("  Version  {version}");
    }
    if let Some(address) = status["addresses"]["ipv4"].as_str() {
        println!("  IPv4     {address}");
    }
    if let Some(address) = status["addresses"]["ipv6"].as_str() {
        println!("  IPv6     {address}");
    }
    println!(
        "  Next     {}",
        match state {
            "Off" => "Run infraternal mesh up to start the component.",
            "Waiting" => "Connect this infraternal agent to its enrolled server.",
            "Stopping" => "Run infraternal mesh down again to finish cleanup.",
            _ => "Run infraternal mesh peers to inspect direct paths.",
        }
    );
    Ok(())
}
