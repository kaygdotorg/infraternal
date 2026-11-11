//! Presents public Mesh node records for people and for the JSON envelope; the generic CLI never knows Mesh fields [16,198,202], #239.
use infraternal_plugin_api::{
    PluginError,
    present::{Presented, Tone, age, bytes, pairs, table},
};
use serde_json::Value;

pub(crate) fn present(action: &str, output: &[u8], width: usize) -> Result<Presented, PluginError> {
    let value: Value = serde_json::from_slice(output).map_err(|_| PluginError::Rejected)?;
    match action {
        "mesh.status" => status(value, width),
        "mesh.peers" => peers(&value, width),
        _ => Err(PluginError::UnknownAction),
    }
}

fn plural(count: u64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Turn public mesh status JSON into a short message and suggested next command.
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
            "Waiting for server.".to_owned(),
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
    if let Some(selection) = value.get("engine_selection").filter(|v| !v.is_null()) {
        let engine = match selection["engine"].as_str() {
            Some("gotatun") => "GotaTun (userspace)",
            Some("kernel") => "kernel WireGuard",
            _ => return Err(PluginError::Rejected),
        };
        let reason = match selection["reason"].as_str() {
            Some("default") => "the default",
            Some("chosen") => "chosen for this machine",
            _ => return Err(PluginError::Rejected),
        };
        rows.push(("Data plane", format!("{engine}, {reason}")));
    }
    if let Some(detail) = value["proxy_containment"]["detail"].as_str() {
        rows.push(("Proxy", detail.to_owned()));
    }
    let (tone, message) = engine_health(&value, &mut rows)?.unwrap_or((tone, message));
    Ok(Presented {
        tone,
        message,
        body: pairs(&rows, 0, width),
        next: next.into_iter().map(str::to_owned).collect(),
        data: value,
    })
}

/// The Mac node reports no engine health yet, so its status has no health rows.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps)]
fn engine_health(
    _value: &Value,
    _rows: &mut Vec<(&str, String)>,
) -> Result<Option<(Tone, String)>, PluginError> {
    Ok(None)
}

/// The `GotaTun` engine's health rows, and a replacement headline while it is stopped. Absent
/// for kernel `WireGuard`, and quiet while the engine has nothing to report.
#[cfg(target_os = "linux")]
fn engine_health(
    value: &Value,
    rows: &mut Vec<(&str, String)>,
) -> Result<Option<(Tone, String)>, PluginError> {
    let Some(engine) = value.get("engine").filter(|engine| !engine.is_null()) else {
        return Ok(None);
    };
    let health: crate::gotatun_node::EngineHealth =
        serde_json::from_value(engine.clone()).map_err(|_| PluginError::Rejected)?;
    if health.restarts > 0 {
        rows.push((
            "Engine",
            format!(
                "restarted {} after an error",
                plural(health.restarts, "time", "times")
            ),
        ));
    }
    if health.refused_frames > 0 {
        rows.push((
            "Dropped",
            format!(
                "{} this machine sent that the mesh could not read",
                plural(health.refused_frames, "packet", "packets")
            ),
        ));
    }
    let short_queue = health
        .tx_queue_len
        .filter(|&len| len < crate::gotatun_node::TUN_TX_QUEUE_LEN);
    if let Some(len) = short_queue {
        rows.push((
            "Queue",
            if len == 0 {
                "the TUN transmit queue could not be read; the engine needs 1024 packets".to_owned()
            } else {
                format!(
                    "the TUN transmit queue holds {len} packets, below the 1024 the engine needs; raising it needs network-admin rights"
                )
            },
        ));
    }
    Ok(if health.stopped {
        Some((
            Tone::Attention,
            "Mesh engine stopped on an error and restarts in a moment.".to_owned(),
        ))
    } else {
        short_queue.map(|_| {
            (
                Tone::Attention,
                "Mesh is on, but its TUN transmit queue is short and can drop packets under load."
                    .to_owned(),
            )
        })
    })
}

/// Standard base64 of a 32-byte public key; the JSON form of a key is text, never a byte array.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |n, (i, byte)| n | (u32::from(*byte) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn peers(value: &Value, width: usize) -> Result<Presented, PluginError> {
    peers_at(value, width, now_secs())
}

/// One peer as a table row, a JSON record, and, when it has no direct path yet, its label and address.
struct PeerView {
    cells: Vec<String>,
    record: Value,
    waiting: Option<(String, String)>,
}

fn peer_view(row: &Value, now: u64) -> Result<PeerView, PluginError> {
    let node = row["node"].as_u64().ok_or(PluginError::Rejected)?;
    let address: std::net::Ipv4Addr = row["peer"]["addresses"]["ipv4"]
        .as_str()
        .ok_or(PluginError::Rejected)?
        .parse()
        .map_err(|_| PluginError::Rejected)?;
    let endpoint = row["peer"]["endpoint"]
        .as_str()
        .map(str::parse::<std::net::SocketAddr>)
        .transpose()
        .map_err(|_| PluginError::Rejected)?;
    let direct = match row["path"].as_str() {
        Some("Direct") => true,
        Some("Unproven") => false,
        _ => return Err(PluginError::Rejected),
    };
    let received = row["counters"]["received_bytes"]
        .as_u64()
        .ok_or(PluginError::Rejected)?;
    let sent = row["counters"]["sent_bytes"]
        .as_u64()
        .ok_or(PluginError::Rejected)?;
    // The kernel reports the time of the last handshake; people want its age.
    let ago = row["counters"]["handshake_secs"]
        .as_u64()
        .filter(|secs| *secs > 0)
        .map(|secs| now.saturating_sub(secs));
    let key: Vec<u8> = row["peer"]["key"]
        .as_array()
        .ok_or(PluginError::Rejected)?
        .iter()
        .map(|byte| byte.as_u64().and_then(|byte| u8::try_from(byte).ok()))
        .collect::<Option<_>>()
        .ok_or(PluginError::Rejected)?;
    // The server will send machine names once the mesh configuration carries them; until
    // then a peer is known by its mesh address.
    let name = row["peer"]["name"].as_str().map(str::to_owned);
    let label = name.clone().unwrap_or_else(|| address.to_string());
    let mut record = serde_json::json!({
        "node": node,
        "address": address.to_string(),
        "path": if direct { "direct" } else { "unproven" },
        "key": base64(&key),
        "received_bytes": received,
        "sent_bytes": sent,
    });
    if let Some(name) = name {
        record["name"] = name.into();
    }
    if let Some(endpoint) = endpoint {
        record["endpoint"] = endpoint.to_string().into();
    }
    if let Some(ago) = ago {
        record["last_handshake_secs_ago"] = ago.into();
    }
    Ok(PeerView {
        cells: vec![
            label.clone(),
            if direct { "direct" } else { "none yet" }.to_owned(),
            bytes(received),
            bytes(sent),
            ago.map_or_else(|| "never".to_owned(), age),
            endpoint.map_or_else(String::new, |endpoint| endpoint.to_string()),
        ],
        record,
        waiting: (!direct).then(|| (label, address.to_string())),
    })
}

/// The peers page as people and scripts read it. `now` is the wall clock in seconds, so tests can fix it.
fn peers_at(value: &Value, width: usize, now: u64) -> Result<Presented, PluginError> {
    let mut rows = Vec::new();
    let mut records = Vec::new();
    let mut waiting = Vec::new();
    for row in value["peers"].as_array().ok_or(PluginError::Rejected)? {
        let view = peer_view(row, now)?;
        rows.push(view.cells);
        records.push(view.record);
        waiting.extend(view.waiting);
    }
    let more = !value["next_cursor"].is_null();
    let count = records.len() as u64;
    let message = if count == 0 {
        "No other machines are on the mesh.".to_owned()
    } else if waiting.is_empty() {
        format!(
            "{}, all direct.",
            plural(count, "peer on the mesh", "peers on the mesh")
        )
    } else {
        format!(
            "{}, {} without a direct path yet.",
            plural(count, "peer on the mesh", "peers on the mesh"),
            waiting.len()
        )
    };
    // Only offer to set up a path when one is missing, and name the machine.
    let next = match waiting.first() {
        Some((label, address)) if !more => vec![format!(
            "Send traffic to {label} to set up its direct path, for example: ping {address}"
        )],
        _ => Vec::new(),
    };
    let mut data = serde_json::json!({"peers": records});
    for key in ["version", "next_cursor"] {
        if !value[key].is_null() {
            data[key] = value[key].clone();
        }
    }
    Ok(Presented {
        tone: Tone::Good,
        message,
        body: table(
            &["Peer", "Path", "Received", "Sent", "Handshake", "Endpoint"],
            &rows,
            0,
            width,
            None,
        ),
        next,
        data,
    })
}

#[cfg(test)]
/// Tests the user-facing CLI presentation of Mesh status and peer rows.
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use infraternal_plugin_api::server_path::{ServerLink, ServerLinkKind, ServerLinkReason};

    /// A refused node tells the person to wait for a usable server snapshot.
    #[test]
    fn refused_node_says_waiting_for_server() {
        let shown = status(serde_json::json!({"state":"Waiting","peer_count":0}), 100)
            .expect("waiting status");
        assert_eq!(shown.message, "Waiting for server.");
    }

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
    #[cfg(target_os = "linux")]
    fn status_shows_a_stopped_or_restarted_engine_and_stays_quiet_when_healthy() {
        let healthy = serde_json::json!({"state":"On","peer_count":1,
            "engine":{"stopped":false,"restarts":0,"refused_frames":0}});
        let shown = status(healthy, 100).expect("healthy");
        assert_eq!(shown.message, "Mesh is on. 1 peer.");
        assert!(!shown.body.contains("Engine"), "{}", shown.body);
        let stopped = serde_json::json!({"state":"On","peer_count":1,
            "engine":{"stopped":true,"restarts":2,"refused_frames":1}});
        let shown = status(stopped, 100).expect("stopped");
        assert!(matches!(shown.tone, Tone::Attention));
        assert_eq!(
            shown.message,
            "Mesh engine stopped on an error and restarts in a moment."
        );
        assert!(
            shown.body.contains("restarted 2 times after an error"),
            "{}",
            shown.body
        );
        assert!(
            shown.body.contains("1 packet this machine sent"),
            "{}",
            shown.body
        );
        let short = serde_json::json!({"state":"On","peer_count":1,
            "engine":{"stopped":false,"restarts":0,"refused_frames":0,"tx_queue_len":500}});
        let shown = status(short, 120).expect("short queue");
        assert!(matches!(shown.tone, Tone::Attention));
        assert!(
            shown.message.contains("transmit queue is short"),
            "{}",
            shown.message
        );
        assert!(shown.body.contains("holds 500 packets"), "{}", shown.body);
        let raised = serde_json::json!({"state":"On","peer_count":1,
            "engine":{"stopped":false,"restarts":0,"refused_frames":0,"tx_queue_len":1024}});
        assert_eq!(
            status(raised, 100).expect("raised").message,
            "Mesh is on. 1 peer."
        );
        let kernel = serde_json::json!({"state":"On","peer_count":1,"engine":null});
        assert_eq!(
            status(kernel, 100).expect("kernel").message,
            "Mesh is on. 1 peer."
        );
    }
    #[test]
    fn status_names_the_running_engine_and_why() {
        let default = serde_json::json!({"state":"On","peer_count":1,
            "engine_selection":{"engine":"gotatun","reason":"default"}});
        let shown = status(default, 100).expect("default engine").body;
        assert!(
            shown.contains("Data plane  GotaTun (userspace), the default"),
            "{shown}"
        );
        let chosen = serde_json::json!({"state":"On","peer_count":1,
            "engine_selection":{"engine":"kernel","reason":"chosen"}});
        let shown = status(chosen, 100).expect("chosen engine").body;
        assert!(
            shown.contains("Data plane  kernel WireGuard, chosen for this machine"),
            "{shown}"
        );
    }
    #[test]
    fn legacy_status_remains_readable_and_invalid_link_is_refused() {
        assert!(status(serde_json::json!({"state":"On","peer_count":0}), 80).is_ok());
        assert!(status(serde_json::json!({"state":"On","peer_count":0,"server_link":{"kind":"Mesh","reason":"MeshProven","endpoint":"invalid input"}}), 80).is_err());
    }

    #[test]
    fn status_says_when_proxy_containment_is_limited() {
        let value = serde_json::json!({"state":"On","peer_count":0,"proxy_containment":{"kind":"fallback","detail":"limited: the infraternal agent's unit lacks Delegate=yes"}});
        let text = status(value, 120).expect("human status").body;
        assert!(text.contains("Proxy"), "{text}");
        assert!(text.contains("lacks Delegate=yes"), "{text}");
    }

    fn peer(node: u64, address: &str, handshake: u64) -> serde_json::Value {
        serde_json::json!({
            "node": node,
            "peer": {"key": vec![1_u8; 32], "addresses": {"ipv4": address}, "endpoint": "10.69.69.217:47823"},
            "inbound": {"state": "All"}, "outbound": {"state": "All"},
            "counters": {"handshake_secs": handshake, "received_bytes": 18_056_740_u64, "sent_bytes": 19_041_052_u64},
            "path": if handshake > 0 { "Direct" } else { "Unproven" },
        })
    }

    #[test]
    fn peers_show_units_ages_and_no_hint_when_every_path_is_direct() {
        let page = serde_json::json!({"peers": [peer(3, "10.254.0.3", 988)], "version": 4, "next_cursor": null});
        let shown = peers_at(&page, 100, 1000).expect("present peers");
        assert_eq!(shown.message, "1 peer on the mesh, all direct.");
        assert_eq!(
            shown.body,
            "10.254.0.3  direct  18 MB  19 MB  12 s ago  10.69.69.217:47823\n"
        );
        assert!(shown.next.is_empty(), "{:?}", shown.next);
        // JSON: text key, an age instead of an epoch time, raw byte counts.
        let record = &shown.data["peers"][0];
        assert_eq!(
            record["key"],
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        );
        assert_eq!(record["last_handshake_secs_ago"], 12);
        assert_eq!(record["received_bytes"], 18_056_740_u64);
        assert!(record.get("counters").is_none());
    }

    #[test]
    fn an_unproven_peer_gets_a_hint_that_names_it() {
        let page = serde_json::json!({"peers": [peer(3, "10.254.0.3", 990), peer(4, "10.254.0.4", 0)], "next_cursor": null});
        let shown = peers_at(&page, 100, 1000).expect("present peers");
        assert_eq!(
            shown.message,
            "2 peers on the mesh, 1 without a direct path yet."
        );
        assert!(shown.next[0].contains("10.254.0.4"), "{:?}", shown.next);
        assert!(shown.body.starts_with("PEER"), "{}", shown.body);
        assert!(shown.body.lines().all(|line| line.chars().count() <= 100));
    }

    #[test]
    fn a_wide_table_stays_within_the_width() {
        let mut row = peer(3, "10.254.0.3", 990);
        row["peer"]["endpoint"] = "[2001:db8:1234:5678:9abc:def0:1234:5678]:47823".into();
        let page =
            serde_json::json!({"peers": [row, peer(4, "10.254.0.4", 990)], "next_cursor": null});
        let shown = peers_at(&page, 80, 1000).expect("present peers");
        assert!(
            shown.body.lines().all(|line| line.chars().count() <= 80),
            "{}",
            shown.body
        );
    }
}
