//! Presents public Mesh node records for people and for the JSON envelope; the generic CLI never knows Mesh fields [16,198,202], #239.
use infraternal_plugin_api::{
    PluginError,
    present::{Presented, Tone, age, bytes, pairs, table},
};
use serde_json::Value;

/// Present an action on a node that has no host-specific engine health.
///
/// # Errors
/// Rejects unknown actions and invalid action output.
pub fn present(action: &str, output: &[u8], width: usize) -> Result<Presented, PluginError> {
    present_with(action, output, width, |_, _| Ok(None))
}

/// Adds optional host-specific rows and a replacement status headline.
pub type EngineHealth =
    fn(&Value, &mut Vec<(&str, String)>) -> Result<Option<(Tone, String)>, PluginError>;

/// Present one mesh node action's JSON for people: status, peers and the subnet route view.
///
/// # Errors
/// Rejects unknown actions and invalid action output.
pub fn present_with(
    action: &str,
    output: &[u8],
    width: usize,
    engine_health: EngineHealth,
) -> Result<Presented, PluginError> {
    let value: Value = serde_json::from_slice(output).map_err(|_| PluginError::Rejected)?;
    match action {
        "mesh.status" => status_with(value, width, engine_health),
        "mesh.peers" => peers(&value, width),
        "mesh.routes" | "mesh.routes.advertise" | "mesh.routes.withdraw" => routes(&value, width),
        _ => Err(PluginError::UnknownAction),
    }
}

/// Present `mesh routes` (and the answer to `advertise` and `withdraw`, which is the same view):
/// what this machine offers, what it serves, and the networks it reaches through other machines.
fn routes(value: &Value, width: usize) -> Result<Presented, PluginError> {
    let advertised: Vec<&str> = value["advertised"]
        .as_array()
        .ok_or(PluginError::Rejected)?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let serving = value["serving"].as_array().ok_or(PluginError::Rejected)?;
    let reachable = value["reachable"].as_array().ok_or(PluginError::Rejected)?;
    let mut body = String::new();
    let mut rows: Vec<(&str, String)> = Vec::new();
    rows.push((
        "Advertised",
        if advertised.is_empty() {
            "none".to_owned()
        } else {
            advertised.join(", ")
        },
    ));
    if !serving.is_empty() {
        let served: Vec<String> = serving
            .iter()
            .map(|network| {
                format!(
                    "{} ({}, {})",
                    network["network"].as_str().unwrap_or("?"),
                    plural(network["peers"].as_u64().unwrap_or(0), "peer", "peers"),
                    if network["masquerade"] == true {
                        "masqueraded"
                    } else {
                        "keeps source addresses"
                    }
                )
            })
            .collect();
        rows.push(("Serving", served.join(", ")));
    }
    let forwarding = &value["forwarding"];
    match forwarding["state"].as_str() {
        Some("on") => rows.push((
            "Forwarding",
            format!(
                "on; IPv4 forwarding {}",
                forwarding["ip_forward"].as_str().unwrap_or("on")
            ),
        )),
        Some("unavailable") => rows.push((
            "Forwarding",
            format!(
                "unavailable: {}",
                forwarding["reason"].as_str().unwrap_or("unknown")
            ),
        )),
        _ => {}
    }
    body.push_str(&pairs(&rows, 2, width));
    if !reachable.is_empty() {
        let table_rows: Vec<Vec<String>> = reachable
            .iter()
            .map(|network| {
                let installed = &network["installed"];
                let state = match installed["reason"].as_str() {
                    Some(reason) => {
                        format!("{}: {reason}", installed["state"].as_str().unwrap_or("?"))
                    }
                    None => installed["state"].as_str().unwrap_or("?").to_owned(),
                };
                vec![
                    network["network"].as_str().unwrap_or("?").to_owned(),
                    network["via"]
                        .as_str()
                        .map_or_else(|| format!("node {}", network["via_node"]), str::to_owned),
                    state,
                ]
            })
            .collect();
        body.push('\n');
        body.push_str(&table(
            &["Network", "Through", "Route"],
            &table_rows,
            2,
            width,
            None,
        ));
    }
    let tone = if forwarding["state"] == "unavailable"
        || reachable
            .iter()
            .any(|network| network["installed"]["state"] != "installed")
    {
        Tone::Attention
    } else {
        Tone::Good
    };
    let message = format!(
        "{} advertised, {} served, {} reachable.",
        plural(advertised.len() as u64, "network", "networks"),
        serving.len(),
        reachable.len()
    );
    let next = if advertised.len() > serving.len() {
        vec!["infraternal server mesh routes".to_owned()]
    } else {
        Vec::new()
    };
    Ok(Presented {
        tone,
        message,
        body,
        next,
        data: value.clone(),
    })
}

/// Format a count using the matching singular or plural label.
#[must_use]
pub fn plural(count: u64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Turn public mesh status JSON into a short message and suggested next command.
///
/// # Errors
/// Refuses status fields that do not match the node action's output schema.
pub fn status_with(
    value: Value,
    width: usize,
    engine_health: EngineHealth,
) -> Result<Presented, PluginError> {
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
    if value["ipv6"] == false {
        // The mesh link has IPv6 off (#578): no IPv6 address was installed, so do not list one.
        rows.push((
            "IPv6",
            "off on this machine (net.ipv6.conf disable_ipv6); the mesh runs IPv4-only".to_owned(),
        ));
    } else if let Some(address) = value["addresses"]["ipv6"].as_str() {
        let address: std::net::Ipv6Addr = address.parse().map_err(|_| PluginError::Rejected)?;
        rows.push(("Address", address.to_string()));
    }
    if let Some(port) = value.get("udp_port").filter(|port| !port.is_null()) {
        let port = port
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or(PluginError::Rejected)?;
        rows.push(("UDP listen port", port.to_string()));
    }
    if let Some(dns) = value.get("dns").filter(|dns| !dns.is_null()) {
        let detail = dns["detail"].as_str().ok_or(PluginError::Rejected)?;
        let label = match dns["mode"].as_str() {
            Some("resolved" | "networkmanager" | "resolver-files") => "on",
            Some("hosts") => "limited",
            Some("unprivileged") => "not installed",
            Some("unavailable") => "failed",
            Some("off") => "off",
            _ => return Err(PluginError::Rejected),
        };
        rows.push(("Host DNS", format!("{label}: {detail}")));
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
    if let Some(enforcement) = value.get("enforcement").and_then(Value::as_str) {
        rows.push((
            "Enforcement",
            match enforcement {
                "userspace" => "D164 access rules checked at both userspace TUN edges",
                "kernel" => "D164 access rules checked by kernel WireGuard",
                _ => return Err(PluginError::Rejected),
            }
            .to_owned(),
        ));
    }
    if let Some(detail) = value["proxy_containment"]["detail"].as_str() {
        rows.push(("Proxy", detail.to_owned()));
    }
    render_relays(&value["relay"], &mut rows);
    let guard_missing = render_kernel_guard(&value, &mut rows)?;
    let (mut tone, mut message) = engine_health(&value, &mut rows)?.unwrap_or((tone, message));
    if state == "On" && guard_missing {
        tone = Tone::Attention;
        "Mesh is on, but kernel-only protections are missing.".clone_into(&mut message);
    }
    Ok(Presented {
        tone,
        message,
        body: pairs(&rows, 0, width),
        next: next.into_iter().map(str::to_owned).collect(),
        data: value,
    })
}

/// Add the relay rows (D402): the relay this machine serves, the relays it knows, and each
/// relayed pair as "via <relay>, because <reason>" (D285). Absent on builds without relays.
fn render_relays(relay: &Value, rows: &mut Vec<(&str, String)>) {
    if let Some(serving) = relay.get("serving").filter(|serving| !serving.is_null()) {
        let port = serving["port"]
            .as_u64()
            .map_or_else(|| "a UDP port".to_owned(), |port| format!("UDP {port}"));
        rows.push((
            "Relay",
            format!(
                "serving as {} on {port}; {}, {}",
                serving["name"].as_str().unwrap_or("this machine"),
                plural(
                    serving["hosts"].as_u64().unwrap_or(0),
                    "machine connected",
                    "machines connected"
                ),
                plural(
                    serving["links"].as_u64().unwrap_or(0),
                    "pair carried",
                    "pairs carried"
                ),
            ),
        ));
    }
    let names: Vec<&str> = relay["relays"]
        .as_array()
        .map(|relays| {
            relays
                .iter()
                .filter_map(|relay| relay["name"].as_str())
                .collect()
        })
        .unwrap_or_default();
    if !names.is_empty() {
        rows.push(("Relays", names.join(", ")));
    }
    for pair in relay["relayed"].as_array().into_iter().flatten() {
        let peer = pair["peer"].as_str().unwrap_or("a peer");
        let via = pair["via"].as_str().unwrap_or("a relay (connecting)");
        let because = pair["because"].as_str().unwrap_or("its direct path failed");
        rows.push(("Relayed", format!("{peer}: via {via}, because {because}")));
    }
}

/// Add the kernel guard's exact gaps and tool result to the status rows.
fn render_kernel_guard(value: &Value, rows: &mut Vec<(&str, String)>) -> Result<bool, PluginError> {
    let Some(guard) = value.get("kernel_guard").filter(|guard| !guard.is_null()) else {
        return Ok(false);
    };
    let state = guard["state"].as_str().ok_or(PluginError::Rejected)?;
    let missing = guard["missing"].as_array().ok_or(PluginError::Rejected)?;
    let missing = missing
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or(PluginError::Rejected)?;
    let detail = guard["detail"].as_str().ok_or(PluginError::Rejected)?;
    match state {
        "installed" => {
            if !missing.is_empty() {
                return Err(PluginError::Rejected);
            }
            rows.push(("Kernel guard", detail.to_owned()));
            Ok(false)
        }
        "pending" | "missing" | "failed" => {
            rows.push((
                "Kernel guard",
                format!("missing: {}; {detail}", missing.join(", ")),
            ));
            Ok(true)
        }
        _ => Err(PluginError::Rejected),
    }
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

/// Read the current Unix time used to display handshake ages.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Present installed peers with packet counters and path status.
fn peers(value: &Value, width: usize) -> Result<Presented, PluginError> {
    peers_at(value, width, now_secs())
}

/// One peer as a table row, a JSON record, and, when it has no direct path yet, what to tell the person.
struct PeerView {
    cells: Vec<String>,
    record: Value,
    waiting: Option<Waiting>,
}

/// A peer without a direct path: its label, its mesh address, and whether traffic already went unanswered.
struct Waiting {
    label: String,
    address: String,
    /// This machine sent the peer packets and got nothing back. Sending more will not help, so the
    /// hint must not suggest it (#483: on blocked or untraversable networks people were told to ping).
    unanswered: bool,
}

/// Turn one `mesh.peers` row into its table cells, its JSON record and, for a peer without a
/// direct path, the hint data. `now` is the wall clock in seconds, so ages are testable.
/// # Errors
/// Refuses a row missing a node id, mesh address, key, counters or a known path value.
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
    // A peer that runs IPv4-only has no IPv6 route here and no AAAA name (#578, J1142).
    let ipv4_only = row["peer"]["ipv4_only"] == true;
    let mut record = serde_json::json!({
        "node": node,
        "address": address.to_string(),
        "path": if direct { "direct" } else { "unproven" },
        "key": base64(&key),
        "received_bytes": received,
        "sent_bytes": sent,
    });
    if ipv4_only {
        record["ipv6"] = "off".into();
    }
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
            if ipv4_only {
                format!("{label} (IPv4 only)")
            } else {
                label.clone()
            },
            if direct { "direct" } else { "none yet" }.to_owned(),
            bytes(received),
            bytes(sent),
            ago.map_or_else(|| "never".to_owned(), age),
            endpoint.map_or_else(String::new, |endpoint| endpoint.to_string()),
        ],
        record,
        waiting: (!direct).then(|| Waiting {
            label,
            address: address.to_string(),
            unanswered: sent > 0 && received == 0,
        }),
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
    // Only offer to set up a path when one is missing, and name the machine. If traffic already
    // went unanswered, say so instead of asking for more.
    let next = match waiting.first() {
        Some(peer) if !more && peer.unanswered => vec![format!(
            "{} has not answered anything sent to it. A firewall or NAT between the two machines may block direct UDP; the pair moves to a relay when the server lists one.",
            peer.label
        )],
        Some(peer) if !more => vec![format!(
            "Send traffic to {} to set up its direct path, for example: ping {}",
            peer.label, peer.address
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

/// Checks that mesh actions produce readable status and peer summaries.
#[cfg(test)]
/// Tests the user-facing CLI presentation of Mesh status and peer rows.
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use infraternal_plugin_api::server_path::{ServerLink, ServerLinkKind, ServerLinkReason};

    /// Presents a fixture without host-specific rows.
    fn status(value: Value, width: usize) -> Result<Presented, PluginError> {
        status_with(value, width, |_, _| Ok(None))
    }

    /// A refused node tells the person to wait for a usable server snapshot.
    #[test]
    fn refused_node_says_waiting_for_server() {
        let shown = status(serde_json::json!({"state":"Waiting","peer_count":0}), 100)
            .expect("waiting status");
        assert_eq!(shown.message, "Waiting for server.");
    }

    /// Describe the active server transport and its address.
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
    /// Show the selected engine and how the host chose it.
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

    /// An IPv6-off node says so instead of listing an IPv6 address it never installed (#578, J1142).
    #[test]
    fn status_says_when_the_mesh_runs_ipv4_only() {
        let off = status(
            serde_json::json!({"state":"On","peer_count":0,"ipv6":false,
                "addresses":{"ipv4":"10.254.0.1","ipv6":"fd01::1"}}),
            100,
        )
        .expect("ipv4-only status");
        assert!(off.body.contains("IPv4-only"), "{}", off.body);
        assert!(!off.body.contains("fd01::1"), "{}", off.body);
        let on = status(
            serde_json::json!({"state":"On","peer_count":0,"ipv6":true,
                "addresses":{"ipv4":"10.254.0.1","ipv6":"fd01::1"}}),
            100,
        )
        .expect("dual-stack status");
        assert!(on.body.contains("fd01::1"), "{}", on.body);
        assert!(!on.body.contains("IPv4-only"), "{}", on.body);
    }

    /// Status says how mesh names reach the host resolver, and why when they do not.
    #[test]
    fn status_reports_the_host_dns_state() {
        let shown = status(
            serde_json::json!({"state":"On","peer_count":0,
                "dns":{"mode":"unavailable","detail":"no resolver tool","suffixes":[],"search":false}}),
            100,
        )
        .expect("dns status");
        assert!(shown.body.contains("Host DNS"), "{}", shown.body);
        assert!(
            shown.body.contains("failed: no resolver tool"),
            "{}",
            shown.body
        );
    }

    /// Human status includes the listener selected after a default-port collision.
    #[test]
    fn status_reports_the_udp_listener_port() {
        let shown = status(
            serde_json::json!({"state":"On","peer_count":0,"udp_port":49123}),
            100,
        )
        .expect("listener status");
        assert!(shown.body.contains("49123"), "{}", shown.body);
        assert!(shown.body.contains("UDP listen port"), "{}", shown.body);
        assert!(
            status(
                serde_json::json!({"state":"On","peer_count":0,"udp_port":0}),
                100,
            )
            .is_err()
        );
    }

    /// Status calls out every kernel-only protection when a `GotaTun` guard is unavailable.
    #[test]
    fn status_names_missing_kernel_only_protections() {
        let value = serde_json::json!({
            "state":"On",
            "peer_count":1,
            "enforcement":"userspace",
            "kernel_guard":{
                "state":"missing",
                "missing":[
                    "mesh-address anti-spoofing on non-mesh interfaces",
                    "forwarding drops",
                    "public TCP/80 and TCP/443 gate"
                ],
                "detail":"nft at /usr/sbin/nft and iptables-nft at /usr/sbin/iptables-nft were not found"
            }
        });
        let shown = status(value, 160).expect("status");
        assert!(matches!(shown.tone, Tone::Attention));
        assert!(
            shown
                .message
                .contains("kernel-only protections are missing")
        );
        assert!(shown.body.contains("Enforcement"));
        assert!(shown.body.contains("userspace TUN edges"));
        for protection in [
            "mesh-address anti-spoofing on non-mesh interfaces",
            "forwarding drops",
            "public TCP/80 and TCP/443 gate",
            "/usr/sbin/nft",
            "/usr/sbin/iptables-nft",
        ] {
            assert!(
                shown.body.contains(protection),
                "missing {protection}: {}",
                shown.body
            );
        }
    }

    /// Read older status output and refuse an invalid transport record.
    #[test]
    fn legacy_status_remains_readable_and_invalid_link_is_refused() {
        assert!(status(serde_json::json!({"state":"On","peer_count":0}), 80).is_ok());
        assert!(status(serde_json::json!({"state":"On","peer_count":0,"server_link":{"kind":"Mesh","reason":"MeshProven","endpoint":"invalid input"}}), 80).is_err());
    }

    /// Present the proxy containment detail.
    #[test]
    fn status_says_when_proxy_containment_is_limited() {
        let value = serde_json::json!({"state":"On","peer_count":0,"proxy_containment":{"kind":"fallback","detail":"limited: the infraternal agent's unit lacks Delegate=yes"}});
        let text = status(value, 120).expect("human status").body;
        assert!(text.contains("Proxy"), "{text}");
        assert!(text.contains("lacks Delegate=yes"), "{text}");
    }

    /// Build one peer record for presentation tests.
    fn peer(node: u64, address: &str, handshake: u64) -> serde_json::Value {
        serde_json::json!({
            "node": node,
            "peer": {"key": vec![1_u8; 32], "addresses": {"ipv4": address}, "endpoint": "10.69.69.217:47823"},
            "inbound": {"state": "All"}, "outbound": {"state": "All"},
            "counters": {"handshake_secs": handshake, "received_bytes": 18_056_740_u64, "sent_bytes": 19_041_052_u64},
            "path": if handshake > 0 { "Direct" } else { "Unproven" },
        })
    }

    /// Render counters and ages for peers whose paths are all proven.
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

    /// A peer that runs IPv4-only is marked in the table and in the JSON record (#578, J1142).
    #[test]
    fn an_ipv4_only_peer_is_marked() {
        let mut row = peer(3, "10.254.0.3", 988);
        row["peer"]["ipv4_only"] = true.into();
        let page =
            serde_json::json!({"peers": [row, peer(4, "10.254.0.4", 988)], "next_cursor": null});
        let shown = peers_at(&page, 120, 1000).expect("present peers");
        assert!(
            shown.body.contains("10.254.0.3 (IPv4 only)"),
            "{}",
            shown.body
        );
        assert!(
            !shown.body.contains("10.254.0.4 (IPv4 only)"),
            "{}",
            shown.body
        );
        assert_eq!(shown.data["peers"][0]["ipv6"], "off");
        assert!(shown.data["peers"][1].get("ipv6").is_none());
    }

    /// Name the peer whose direct path remains unproven.
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

    /// Sent data and nothing back: the hint explains instead of asking for another ping (#483).
    #[test]
    fn an_unanswered_peer_is_not_told_to_send_more() {
        let mut silent = peer(4, "10.254.0.4", 0);
        silent["counters"]["received_bytes"] = 0.into();
        silent["counters"]["sent_bytes"] = 2_220.into();
        let page = serde_json::json!({"peers": [silent], "next_cursor": null});
        let shown = peers_at(&page, 100, 1000).expect("present peers");
        assert_eq!(
            shown.message,
            "1 peer on the mesh, 1 without a direct path yet."
        );
        assert!(
            shown.next[0].starts_with("10.254.0.4 has not answered"),
            "{:?}",
            shown.next
        );
        assert!(!shown.next[0].contains("ping"), "{:?}", shown.next);
    }

    /// Nothing sent yet: a ping is still the step that starts the handshake.
    #[test]
    fn a_peer_never_sent_to_still_gets_the_ping_hint() {
        let mut idle = peer(4, "10.254.0.4", 0);
        idle["counters"]["received_bytes"] = 0.into();
        idle["counters"]["sent_bytes"] = 0.into();
        let page = serde_json::json!({"peers": [idle], "next_cursor": null});
        let shown = peers_at(&page, 100, 1000).expect("present peers");
        assert!(
            shown.next[0].contains("ping 10.254.0.4"),
            "{:?}",
            shown.next
        );
    }

    /// Keep the wide peer table within its requested width.
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
