//! Presents public Mesh node records for people and for the JSON envelope; the generic CLI never knows Mesh fields [16,198,202], #239.
use infraternal_plugin_api::{
    PluginError,
    present::{Presented, Tone, pairs, table},
};
use serde_json::Value;

pub(crate) fn present(action: &str, output: &[u8], width: usize) -> Result<Presented, PluginError> {
    let value: Value = serde_json::from_slice(output).map_err(|_| PluginError::Rejected)?;
    match action {
        "mesh.status" => status(value, width),
        "mesh.peers" => peers(value, width),
        _ => Err(PluginError::UnknownAction),
    }
}

fn plural(count: u64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

fn status(value: Value, width: usize) -> Result<Presented, PluginError> {
    let state = value["state"].as_str().ok_or(PluginError::Rejected)?;
    let count = value["peer_count"].as_u64().ok_or(PluginError::Rejected)?;
    let (tone, message, next) = match state {
        "Off" => (
            Tone::Idle,
            "Mesh is off on this machine.".to_owned(),
            vec!["infraternal mesh up"],
        ),
        "Waiting" => (
            Tone::Attention,
            "Mesh is on, waiting for this machine to reach its server.".to_owned(),
            vec!["infraternal status"],
        ),
        "Stopping" => (
            Tone::Attention,
            "Mesh is shutting down.".to_owned(),
            vec!["infraternal mesh down"],
        ),
        "On" => (
            Tone::Good,
            format!("Mesh is on. {}.", plural(count, "peer", "peers")),
            // Only offer the list when it has something in it.
            if count > 0 {
                vec!["infraternal mesh peers"]
            } else {
                Vec::new()
            },
        ),
        _ => return Err(PluginError::Rejected),
    };
    let mut rows: Vec<(&str, String)> = Vec::new();
    if let Some(address) = value["addresses"]["ipv4"].as_str() {
        let address: std::net::Ipv4Addr = address.parse().map_err(|_| PluginError::Rejected)?;
        rows.push(("Address", address.to_string()));
    }
    if let Some(address) = value["addresses"]["ipv6"].as_str() {
        let address: std::net::Ipv6Addr = address.parse().map_err(|_| PluginError::Rejected)?;
        rows.push(("Address", address.to_string()));
    }
    if let Some(policy) = value["default_policy"].as_str() {
        rows.push((
            "Access",
            match policy {
                "Allow" => "everyone may reach everyone, unless a rule says otherwise",
                "Deny" => "nothing is reachable unless a rule allows it",
                _ => return Err(PluginError::Rejected),
            }
            .to_owned(),
        ));
    }
    if let Some(link) = value.get("server_link") {
        use infraternal_plugin_api::server_path::{ServerLink, ServerLinkKind, ServerLinkReason};
        let link: ServerLink =
            serde_json::from_value(link.clone()).map_err(|_| PluginError::Rejected)?;
        let kind = match link.kind {
            ServerLinkKind::Disconnected => "not connected",
            ServerLinkKind::Local => "this machine is the server",
            ServerLinkKind::Fallback => "over the enrolled port",
            ServerLinkKind::Mesh => "over the mesh",
        };
        let reason = match link.reason {
            ServerLinkReason::Connecting => "connecting to the enrolled server",
            ServerLinkReason::Local => "the server runs on this machine",
            ServerLinkReason::MeshUnavailable => "the mesh path is not available",
            ServerLinkReason::MeshProven => "the mesh path is proven",
            ServerLinkReason::MeshRefused => "the mesh path was refused, retrying",
            ServerLinkReason::MeshInterrupted => "the mesh path was interrupted",
            ServerLinkReason::MeshDisabled => "the mesh path was withdrawn",
        };
        rows.push(("Server", format!("{kind}; {reason}")));
        if let Some(endpoint) = link.endpoint {
            rows.push(("Link", endpoint.to_string()));
        }
    }
    if let Some(version) = value["version"].as_u64() {
        rows.push(("Rules", format!("version {version}")));
    }
    Ok(Presented {
        tone,
        message,
        body: pairs(&rows, 0, width),
        next: next.into_iter().map(str::to_owned).collect(),
        data: value,
    })
}

fn peers(value: Value, width: usize) -> Result<Presented, PluginError> {
    let mut rows = Vec::new();
    let mut unproven = 0_u64;
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
        unproven += u64::from(path == "Unproven");
        let received = row["counters"]["received_bytes"]
            .as_u64()
            .ok_or(PluginError::Rejected)?;
        let sent = row["counters"]["sent_bytes"]
            .as_u64()
            .ok_or(PluginError::Rejected)?;
        rows.push(vec![
            node.to_string(),
            address.to_string(),
            endpoint,
            path.to_owned(),
            received.to_string(),
            sent.to_string(),
        ]);
    }
    let more = !value["next_cursor"].is_null();
    let message = if rows.is_empty() {
        "No other machines are on the mesh.".to_owned()
    } else {
        plural(rows.len() as u64, "peer", "peers") + " on the mesh."
    };
    let next = if unproven > 0 && !more {
        vec!["Send traffic to a peer marked Unproven to establish its direct path.".to_owned()]
    } else {
        Vec::new()
    };
    Ok(Presented {
        tone: Tone::Good,
        message,
        body: table(
            &[
                "Node", "Address", "Endpoint", "Path", "RX bytes", "TX bytes",
            ],
            &rows,
            0,
            width,
            None,
        ),
        next,
        data: value,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use infraternal_plugin_api::server_path::{ServerLink, ServerLinkKind, ServerLinkReason};
    #[test]
    fn status_explains_the_observed_server_transport() {
        for (kind, reason, label, explanation) in [
            (
                ServerLinkKind::Mesh,
                ServerLinkReason::MeshProven,
                "over the mesh",
                "the mesh path is proven",
            ),
            (
                ServerLinkKind::Fallback,
                ServerLinkReason::MeshInterrupted,
                "over the enrolled port",
                "the mesh path was interrupted",
            ),
            (
                ServerLinkKind::Fallback,
                ServerLinkReason::MeshRefused,
                "over the enrolled port",
                "the mesh path was refused, retrying",
            ),
        ] {
            let link = ServerLink {
                kind,
                reason,
                endpoint: Some("10.254.0.1:7443".parse().expect("fixture address")),
                source_port: None,
            };
            let value = serde_json::json!({"state":"On","peer_count":2,"server_link":link});
            let text = status(value, 100).expect("human status").body;
            assert!(text.contains(label), "{text}");
            assert!(text.contains(explanation), "{text}");
            assert!(text.contains("Link    10.254.0.1:7443"), "{text}");
        }
    }
    #[test]
    fn legacy_status_remains_readable_and_invalid_link_is_refused() {
        assert!(status(serde_json::json!({"state":"On","peer_count":0}), 80).is_ok());
        assert!(status(serde_json::json!({"state":"On","peer_count":0,"server_link":{"kind":"Mesh","reason":"MeshProven","endpoint":"invalid input"}}), 80).is_err());
    }
}
