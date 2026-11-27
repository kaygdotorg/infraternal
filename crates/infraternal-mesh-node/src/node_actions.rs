//! The portable mesh node action contract and request parser.

use crate::{dataplane::Chunk, peer_stats::CounterMap};
use infraternal_plugin_api::{
    ActionDef, DefaultValue, Dependency, DryRun, Effect, Permission, PluginDescriptor, PluginError,
    RoleDef, SchemaRef, SettingDefault, Target,
};
use serde::Deserialize;
use serde_json::json;

/// Fill the common mesh node permission, target and framing fields.
const fn action(
    id: &'static str,
    summary: &'static str,
    input: &'static str,
    output: &'static str,
    effect: Effect,
    steps: &'static [&'static str],
) -> ActionDef {
    ActionDef {
        id,
        summary,
        input: SchemaRef(input),
        output: SchemaRef(output),
        effect,
        instructions: steps,
        permission: Permission::One("mesh.node"),
        target: Target::Node,
        dry_run: DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    }
}
/// Mesh node actions shared by the API and command-line adapters.
pub const ACTIONS: &[ActionDef] = &[
    action(
        "mesh.status",
        "Show whether the mesh is on for this machine.",
        "Empty",
        "MeshNodeStatus",
        Effect::Read,
        &[
            "Read whether the mesh is on, its addresses, and which access rules apply.",
            "Read the UDP port this machine is actually listening on.",
            "Read how this machine reaches its server: over the mesh, or over the enrolled port.",
            "With --json, data.public_key is the active public key only; the field is absent without a Mesh identity.",
        ],
    ),
    action(
        "mesh.peers",
        "List the other machines on the mesh and how they connect.",
        "MeshPeerPage",
        "MeshPeers",
        Effect::Read,
        &[
            "Read each peer with its address, traffic and the age of its last handshake.",
            "A peer with no handshake yet has no direct path; send traffic to it to set one up.",
            "With --json, follow next_cursor for more peers.",
        ],
    ),
    action(
        "mesh.up",
        "Turn the mesh on for this machine.",
        "Empty",
        "MeshIdentity",
        Effect::Write,
        &[
            "Join this machine to a server first (infraternal agent join).",
            "Run as root: turning the mesh on creates a network interface.",
            "The server then sends the other machines and the access rules.",
        ],
    ),
    action(
        "mesh.routes",
        "Show the networks this machine routes for the mesh and the ones it reaches through it.",
        "Empty",
        "MeshRoutes",
        Effect::Read,
        &[
            "Read the networks this machine advertises, and which ones the server approved and routes.",
            "Read the networks behind other machines that this machine may reach, and whether each route is installed.",
            "A network is routed only after an administrator approves it on the server.",
        ],
    ),
    action(
        "mesh.routes.advertise",
        "Offer networks this machine can reach to the mesh, such as its LAN.",
        r#"{"type":"object","properties":{"networks":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":64}},"required":["networks"],"additionalProperties":false}"#,
        "MeshRoutes",
        Effect::Write,
        &[
            "Run as root on the machine that can reach the network, for example infraternal mesh routes advertise 192.168.1.0/24.",
            "Nothing is routed yet: an administrator approves each network on the server first.",
            "Approved networks are masqueraded by default, so hosts there need no route back to the mesh.",
            "The list is kept across restarts; run the command again to add more networks.",
        ],
    ),
    action(
        "mesh.routes.withdraw",
        "Stop offering networks to the mesh.",
        r#"{"type":"object","properties":{"networks":{"type":"array","items":{"type":"string"},"maxItems":64}},"additionalProperties":false}"#,
        "MeshRoutes",
        Effect::Write,
        &[
            "Name the networks to withdraw, or none to withdraw every network.",
            "The server keeps the approval, but the network is not routed until it is advertised again.",
        ],
    ),
    action(
        "mesh.down",
        "Turn the mesh off for this machine.",
        "Empty",
        "MeshNodeStatus",
        Effect::Write,
        &[
            "Remove the mesh network interface and its packet filter from this machine.",
            "The command checks that the mesh is off, and reports a failure if cleanup was incomplete.",
        ],
    ),
];
/// The control actions an infraternal agent registers for its Mesh node.
pub const CONTROL_ACTIONS: &[ActionDef] = &[
    action(
        "mesh.identity",
        "Read enabled Mesh identity",
        "MeshIdentityProbe",
        "OptionalMeshIdentity",
        Effect::Write,
        &[
            "The authenticated coordinator queries the enabled node identity.",
            "An explicitly stopped component stays off.",
        ],
    ),
    action(
        "mesh.rotation.prepare",
        "Prepare a local Mesh key rotation",
        r#"{"type":"object","properties":{"operation_id":{"type":"string","minLength":36,"maxLength":36},"sequence":{"type":"integer","minimum":1}},"required":["operation_id","sequence"],"additionalProperties":false}"#,
        r#"{"type":"object","properties":{"public_key":{"type":"array","items":{"type":"integer","minimum":0,"maximum":255},"minItems":32,"maxItems":32}},"required":["public_key"],"additionalProperties":false}"#,
        Effect::Write,
        &["Persist a candidate private key locally before returning its public key."],
    ),
    action(
        "mesh.rotation.commit",
        "Commit a prepared local Mesh key rotation",
        r#"{"type":"object","properties":{"operation_id":{"type":"string","minLength":36,"maxLength":36},"sequence":{"type":"integer","minimum":1}},"required":["operation_id","sequence"],"additionalProperties":false}"#,
        r#"{"type":"object","properties":{"public_key":{"type":"array","items":{"type":"integer","minimum":0,"maximum":255},"minItems":32,"maxItems":32}},"required":["public_key"],"additionalProperties":false}"#,
        Effect::Write,
        &["Switch the local WireGuard identity to the acknowledged candidate key."],
    ),
    action(
        "mesh.rotation.finish",
        "Finish a completed local Mesh key rotation",
        r#"{"type":"object","properties":{"operation_id":{"type":"string","minLength":36,"maxLength":36},"sequence":{"type":"integer","minimum":1}},"required":["operation_id","sequence"],"additionalProperties":false}"#,
        "Empty",
        Effect::Write,
        &["Erase the retained predecessor after the coordinator retires the overlap."],
    ),
    action(
        "mesh.configure",
        "Apply a Mesh configuration chunk",
        "MeshConfigChunk",
        "MeshApplied",
        Effect::Write,
        &[
            "The authenticated coordinator sends ordered bounded chunks.",
            "Only a complete final chunk changes the applied version.",
            "Request a snapshot after a stale or rejected version.",
        ],
    ),
];
/// Plugin descriptor shared by every mesh node host.
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "mesh",
    api: infraternal_plugin_api::API_VERSION,
    actions: ACTIONS,
    topics: &[],
    settings: Some(SchemaRef(
        r#"{"type":"object","properties":{"enabled":{"type":"boolean","default":true}},"additionalProperties":false}"#,
    )),
    events: &[infraternal_plugin_api::EventDef {
        id: "mesh.changed",
        schema: SchemaRef("Empty"),
    }],
    streams: &[],
    defaults: &[SettingDefault {
        id: "enabled",
        value: DefaultValue::Bool(true),
    }],
    dependencies: &[Dependency::ExistingServer],
    can_enable_components: &[],
    roles: &[RoleDef {
        id: "node",
        requires: &[],
        default_enabled: true,
    }],
    max_frame_len: infraternal_plugin_api::MAX_ACTION_BYTES,
    unavailable: br#"{"error":"Mesh is unavailable."}"#,
    unavailable_event: br#"{"type":"error","error":"Mesh is unavailable."}"#,
};

/// Strict empty JSON object used by actions without parameters.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
/// Optional explicit negotiation keeps ordinary replies compatible with strict older decoders.
#[derive(Clone, Copy, Deserialize, Default)]
#[serde(deny_unknown_fields)]
// Each flag is an independently negotiated field; using a state enum would change the wire shape.
#[allow(clippy::struct_excessive_bools)]
pub struct IdentityProbe {
    /// Whether the coordinator can send compact access updates.
    #[serde(default)]
    pub compact_access: bool,
    /// Whether the coordinator can send names with the node configuration.
    #[cfg(feature = "mesh-dns")]
    #[serde(default)]
    pub dns_names: bool,
    /// Whether the coordinator supports mesh key rotation.
    #[serde(default)]
    pub key_rotation: bool,
    /// Whether the coordinator sends its authority epoch.
    #[serde(default)]
    pub authority_epoch: bool,
    /// Opt in to operation-bound rotation continuity metadata.
    #[serde(default)]
    pub rotation_continuity: bool,
    /// The coordinator can send ordered direct-path candidates and wants this node's LAN
    /// addresses (#515). Asked on its own, so a strict older node refuses only this probe.
    #[serde(default)]
    pub candidates: bool,
    /// The coordinator understands `Peer::ipv4_only` and wants to know whether this node runs
    /// IPv4-only (#578, J1142). Asked on its own so a strict older node refuses only this probe.
    #[serde(default)]
    pub ipv6_state: bool,
    /// The coordinator understands subnet routes (D197 M3) and wants the networks this node
    /// advertises. Asked on its own so a strict older node refuses only this probe.
    #[serde(default)]
    pub routes: bool,
    /// The coordinator understands `Peer::side_port` and wants to know whether this node runs the
    /// side-mark receive rule with a second socket (#260, J1211). Asked on its own so a strict
    /// older node refuses only this probe.
    #[serde(default)]
    pub side_socket: bool,
}
/// The networks named on a `mesh routes advertise` or `withdraw` command line.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteList {
    /// Each network as text, such as `192.168.1.0/24`; parsed and checked by [`parse_networks`].
    #[serde(default)]
    networks: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// Durable server operation key and epoch for one local `WireGuard` key change.
pub struct RotationOperation {
    /// Coordinator UUID for this rotation.
    pub operation_id: String,
    /// Coordinator sequence for the rotation.
    pub sequence: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// A bounded revision-pinned peer page request.
pub struct Page {
    /// Where the previous page ended, if it had another page.
    #[serde(default)]
    pub cursor: Option<Cursor>,
    /// Rows of counters only, `[node, handshake_secs, received_bytes, persistent_keepalive_secs, endpoint?]`, for the
    /// server's presence poll (presence.rs). The server asks only its own node, which is always the same build,
    /// so an older node never sees the field. A quarter of the bytes of a full row: fewer pages per poll.
    #[serde(default)]
    pub presence: bool,
}
/// Last peer included in the page and the snapshot revision it came from.
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    /// Snapshot revision that the page belongs to.
    pub version: u64,
    /// Node ID at the end of the page.
    pub node: crate::policy::model::NodeId,
}
/// Summarize a direction of access policy in node status output.
#[must_use]
pub fn policy_summary(policy: &crate::policy::rules::TrafficPolicy) -> serde_json::Value {
    use crate::policy::rules::TrafficPolicy;
    match policy {
        TrafficPolicy::All => json!({"state":"All"}),
        TrafficPolicy::None => json!({"state":"None"}),
        TrafficPolicy::Ports(ports) => json!({"state":"Ports","count":ports.len()}),
    }
}
/// Decode a strict, size-bounded node action object.
///
/// # Errors
/// Refuses a body outside the action bound or invalid for the requested schema.
pub fn parse<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<T, PluginError> {
    if input.len() > infraternal_plugin_api::MAX_ACTION_BYTES
        || input.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(PluginError::Rejected);
    }
    serde_json::from_slice(input).map_err(|_| PluginError::Rejected)
}
/// Pure node action request. No kernel or filesystem operation occurs during parsing.
pub enum Request {
    /// Read the node identity with the requested capability flags.
    Identity {
        /// Whether the coordinator accepts compact access updates.
        compact_access: bool,
        /// Whether the coordinator sends DNS names in configurations.
        #[cfg(feature = "mesh-dns")]
        dns_names: bool,
        /// Whether the coordinator supports rotation of the mesh identity.
        key_rotation: bool,
        /// Whether the coordinator includes its authority epoch.
        authority_epoch: bool,
        /// Whether the caller accepts rotation continuity metadata.
        rotation_continuity: bool,
        /// Whether the caller accepts direct-path candidates and requests LAN addresses.
        candidates: bool,
        /// Whether the caller wants this node's IPv6 state and sends `Peer::ipv4_only`.
        ipv6_state: bool,
        /// Whether the caller wants the advertised networks and sends `PeerPolicy::networks`.
        routes: bool,
        /// Whether the caller wants this node's side-socket capability and sends `Peer::side_port`.
        side_socket: bool,
    },
    /// Show advertised, served and reachable networks (D197 M3).
    Routes,
    /// Add networks to the advertised list (still unparsed text; see [`parse_networks`]).
    RoutesAdvertise(Vec<String>),
    /// Remove networks from the advertised list; empty removes them all.
    RoutesWithdraw(Vec<String>),
    /// Prepare and persist a new candidate key.
    RotationPrepare(RotationOperation),
    /// Switch to the prepared candidate key.
    RotationCommit(RotationOperation),
    /// Retire the old key after coordinator acknowledgement.
    RotationFinish(RotationOperation),
    /// Enable mesh on this device.
    Up,
    /// Disable mesh on this device.
    Down,
    /// Read the current node status.
    Status,
    /// Stage one bounded chunk of a configuration update.
    Configure(Box<Chunk>),
    /// Read a bounded page of peers.
    Peers(Page),
}
/// Parse the same bounded strict object accepted by the authenticated dispatcher.
/// # Errors
/// Refuses unknown actions, alternate JSON forms, duplicate fields or oversized bodies.
pub fn parse_action(action: &str, input: &[u8]) -> Result<Request, PluginError> {
    match action {
        "mesh.identity" => {
            let probe: IdentityProbe = parse(input)?;
            Ok(Request::Identity {
                compact_access: probe.compact_access,
                #[cfg(feature = "mesh-dns")]
                dns_names: probe.dns_names,
                key_rotation: probe.key_rotation,
                authority_epoch: probe.authority_epoch,
                rotation_continuity: probe.rotation_continuity,
                candidates: probe.candidates,
                ipv6_state: probe.ipv6_state,
                routes: probe.routes,
                side_socket: probe.side_socket,
            })
        }
        "mesh.routes" => {
            let _: Empty = parse(input)?;
            Ok(Request::Routes)
        }
        "mesh.routes.advertise" => {
            let list: RouteList = parse(input)?;
            if list.networks.is_empty() {
                return Err(PluginError::Rejected);
            }
            Ok(Request::RoutesAdvertise(list.networks))
        }
        "mesh.routes.withdraw" => {
            let list: RouteList = parse(input)?;
            Ok(Request::RoutesWithdraw(list.networks))
        }
        "mesh.rotation.prepare" => Ok(Request::RotationPrepare(parse(input)?)),
        "mesh.rotation.commit" => Ok(Request::RotationCommit(parse(input)?)),
        "mesh.rotation.finish" => Ok(Request::RotationFinish(parse(input)?)),
        "mesh.up" | "mesh.down" | "mesh.status" => {
            let _: Empty = parse(input)?;
            Ok(match action {
                "mesh.up" => Request::Up,
                "mesh.down" => Request::Down,
                _ => Request::Status,
            })
        }
        "mesh.configure" => Ok(Request::Configure(Box::new(parse(input)?))),
        "mesh.peers" => Ok(Request::Peers(parse(input)?)),
        _ => Err(PluginError::UnknownAction),
    }
}
/// Parse the networks of a `mesh routes` command, refusing anything this machine must never
/// offer: malformed or non-canonical text, the default route, loopback and the other blocks in
/// [`crate::policy::networks::check_routable`], IPv6 for now, more than
/// [`MAX_ADVERTISED_NETWORKS`] networks, and two networks that
/// overlap each other. The server checks the mesh range and other routers again on approval.
///
/// # Errors
/// The plain sentence for the person at the command line, naming the first network that is
/// refused and why.
pub fn parse_networks(texts: &[String]) -> Result<Vec<crate::policy::networks::Network>, String> {
    use crate::policy::networks::{Network, NetworkRefusal};
    if texts.len() > MAX_ADVERTISED_NETWORKS {
        return Err(format!(
            "A machine advertises at most {MAX_ADVERTISED_NETWORKS} networks."
        ));
    }
    // Only the address-block rules apply here; the mesh range is the server's to check, so a
    // range that can never overlap a routable IPv4 network stands in for it.
    let mut settings = crate::policy::model::MeshSettings::new([0; 5]);
    settings.ipv4 = crate::policy::model::Ipv4Range {
        network: std::net::Ipv4Addr::new(127, 0, 0, 0),
        prefix: 8,
    };
    let mut networks: Vec<Network> = Vec::new();
    for text in texts {
        let network: Network = text
            .trim()
            .parse()
            .map_err(|error: crate::policy::networks::ParseNetworkError| format!("{error}."))?;
        match crate::policy::networks::check_routable(network, &settings) {
            Ok(()) | Err(NetworkRefusal::MeshRange(..)) => {}
            Err(refusal) => return Err(format!("{refusal}.")),
        }
        if let Some(other) = networks
            .iter()
            .find(|other| other.overlaps(network) && **other != network)
        {
            return Err(format!(
                "{network} overlaps {other}; advertise one network for each address block."
            ));
        }
        if !networks.contains(&network) {
            networks.push(network);
        }
    }
    Ok(networks)
}
/// The most networks one machine advertises; the coordinator refuses longer lists the same way.
pub const MAX_ADVERTISED_NETWORKS: usize = 64;

/// One `mesh.peers` page: the peers after `cursor`, as many as fit one action frame.
///
/// Linear in the page: the cursor seeks the ordered peer map and each row's encoded size is added up once, rather
/// than re-encoding the whole page after every row (#236, review: 54 pages at 1000 peers were ~30 ms per listing).
///
/// # Errors
/// Reports a row that could not be encoded for sizing.
pub fn peer_page(
    config: Option<&crate::dataplane::Config>,
    counters: &CounterMap,
    cursor: Option<&Cursor>,
    presence: bool,
) -> Result<serde_json::Value, PluginError> {
    use std::ops::Bound::{Excluded, Unbounded};
    let mut peers = Vec::new();
    let mut last = None;
    let mut more = false;
    if let Some(config) = config {
        let from = cursor.map_or(Unbounded, |cursor| Excluded(cursor.node));
        // `[` and `]`, plus a comma between rows.
        let mut size = 1;
        for (id, peer) in config.peers.range((from, Unbounded)) {
            let stats = counters.get(&peer.peer.key).cloned().unwrap_or_default();
            let value = if presence {
                // The engine's current address for the peer comes last, so the server can read
                // its nodes' server-reflexive addresses from the same poll (#515, presence.rs).
                match stats.endpoint {
                    Some(endpoint) => json!([
                        id,
                        stats.handshake_secs,
                        stats.received_bytes,
                        stats.persistent_keepalive_secs,
                        endpoint.to_string()
                    ]),
                    None => json!([
                        id,
                        stats.handshake_secs,
                        stats.received_bytes,
                        stats.persistent_keepalive_secs
                    ]),
                }
            } else {
                json!({"node":id,"peer":peer.peer,"inbound":policy_summary(&peer.inbound),"outbound":policy_summary(&peer.outbound),"counters":stats,"path":if stats.handshake_secs > 0 {"Direct"} else {"Unproven"}})
            };
            // Fit resource-bound pages by encoded bytes, not an arbitrary peer-count cap [214].
            size += serde_json::to_vec(&value)
                .map_err(|_| PluginError::Rejected)?
                .len()
                + 1;
            if size > infraternal_plugin_api::MAX_ACTION_BYTES - 128 {
                more = true;
                break;
            }
            peers.push(value);
            last = Some(*id);
        }
    }
    Ok(
        json!({"peers":peers,"version":config.map(|config|config.version),"next_cursor":if more {last.zip(config).map(|(node,config)|Cursor {version:config.version,node})} else {None}}),
    )
}
