//! Formats public Mesh node records for human operators; the generic CLI never knows Mesh fields [16,198,202].
use infraternal_plugin_api::PluginError;
use serde_json::Value;
use std::fmt::Write;

pub(crate) fn format(action: &str, output: &[u8]) -> Result<String, PluginError> {
    let value: Value = serde_json::from_slice(output).map_err(|_| PluginError::Rejected)?;
    match action {
        "mesh.status" => status(&value),
        "mesh.peers" => peers(&value),
        _ => Err(PluginError::UnknownAction),
    }
}
fn status(value: &Value) -> Result<String, PluginError> {
    let state = value["state"].as_str().ok_or(PluginError::Rejected)?;
    let next = match state {
        "Off" => "Run infraternal mesh up to start the component.",
        "Waiting" => "Connect this infraternal agent to its enrolled server.",
        "Stopping" => "Run infraternal mesh down again to finish cleanup.",
        "On" => "Run infraternal mesh peers to inspect direct paths.",
        _ => return Err(PluginError::Rejected),
    };
    let mut text = format!(
        "Mesh\n  State    {state}\n  Peers    {}",
        value["peer_count"].as_u64().ok_or(PluginError::Rejected)?
    );
    if let Some(version) = value["version"].as_u64() {
        write!(text, "\n  Version  {version}").map_err(|_| PluginError::Rejected)?;
    }
    if let Some(policy) = value["default_policy"].as_str() {
        if !matches!(policy, "Allow" | "Deny") {
            return Err(PluginError::Rejected);
        }
        write!(text, "\n  Default  {policy}").map_err(|_| PluginError::Rejected)?;
    }
    if let Some(address) = value["addresses"]["ipv4"].as_str() {
        let address: std::net::Ipv4Addr = address.parse().map_err(|_| PluginError::Rejected)?;
        write!(text, "\n  IPv4     {address}").map_err(|_| PluginError::Rejected)?;
    }
    if let Some(address) = value["addresses"]["ipv6"].as_str() {
        let address: std::net::Ipv6Addr = address.parse().map_err(|_| PluginError::Rejected)?;
        write!(text, "\n  IPv6     {address}").map_err(|_| PluginError::Rejected)?;
    }
    write!(text, "\n  Next     {next}").map_err(|_| PluginError::Rejected)?;
    Ok(text)
}
fn peers(value: &Value) -> Result<String, PluginError> {
    let mut text = format!(
        "Mesh peers\n  {:>8}  {:<15}  {:<47}  {:<10}  {:>12}  {:>12}",
        "Node", "Address", "Endpoint", "Path", "RX bytes", "TX bytes"
    );
    for row in value["peers"].as_array().ok_or(PluginError::Rejected)? {
        let node = row["node"].as_u64().ok_or(PluginError::Rejected)?;
        let address: std::net::Ipv4Addr = row["peer"]["addresses"]["ipv4"]
            .as_str()
            .ok_or(PluginError::Rejected)?
            .parse()
            .map_err(|_| PluginError::Rejected)?;
        let endpoint = row["peer"]["endpoint"]
            .as_str()
            .map(|endpoint| {
                endpoint
                    .parse::<std::net::SocketAddr>()
                    .map(|endpoint| endpoint.to_string())
            })
            .transpose()
            .map_err(|_| PluginError::Rejected)?
            .unwrap_or_else(|| "Unlearned".into());
        let path = row["path"].as_str().ok_or(PluginError::Rejected)?;
        if !matches!(path, "Direct" | "Unproven") {
            return Err(PluginError::Rejected);
        }
        let received = row["counters"]["received_bytes"]
            .as_u64()
            .ok_or(PluginError::Rejected)?;
        let sent = row["counters"]["sent_bytes"]
            .as_u64()
            .ok_or(PluginError::Rejected)?;
        write!(
            text,
            "\n  {node:>8}  {address:<15}  {endpoint:<47}  {path:<10}  {received:>12}  {sent:>12}"
        )
        .map_err(|_| PluginError::Rejected)?;
    }
    if value["next_cursor"].is_null() {
        text.push_str("\n\n  Next  Send traffic to establish an unproven direct path.");
    }
    Ok(text)
}
