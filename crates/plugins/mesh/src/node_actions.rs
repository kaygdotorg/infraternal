//! Declares and dispatches the Mesh node's authenticated actions; all adapters share these instructions [16,198,202].
use crate::{
    dataplane::{Chunk, Config},
    node::Node,
};
use infraternal_plugin_api::{
    ActionDef, AgentPlugin, DefaultValue, Dependency, DryRun, Effect, Permission, PluginDescriptor,
    PluginError, RoleDef, SchemaRef, SettingDefault, Target,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
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
    }
}
pub const ACTIONS: &[ActionDef] = &[
    action(
        "mesh.status",
        "Show whether the mesh is on for this machine.",
        "Empty",
        "MeshNodeStatus",
        Effect::Read,
        &[
            "Read whether the mesh is on, its addresses, and which access rules apply.",
            "Read how this machine reaches its server: over the mesh, or over the enrolled port.",
            "Add --json for the same facts as data.",
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
const CONTROL_ACTIONS: &[ActionDef] = &[
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
/// The process retains kernel state across a remote-channel reconnect. A socket loss
/// never drops this owner; only explicit down retires the component [166].
struct Owner {
    node: Option<Node>,
    path: Option<std::path::PathBuf>,
}
impl Owner {
    fn node(&mut self) -> Result<&mut Node, PluginError> {
        if self.node.is_none() {
            let path = self.path.as_deref().ok_or(PluginError::Rejected)?;
            #[cfg(target_os = "linux")]
            let node = Node::restore(path);
            // The Mac registry restores eagerly with its enrolment (`from_node`);
            // only Linux reaches this lazy path, through `new`.
            #[cfg(target_os = "macos")]
            let node = Node::restore(path, None);
            self.node = Some(node.map_err(|_| PluginError::Rejected)?);
        }
        self.node.as_mut().ok_or(PluginError::Rejected)
    }
}
pub struct MeshNodePlugin {
    owner: Arc<Mutex<Owner>>,
    changed: AtomicBool,
    server_link: infraternal_plugin_api::server_path::ServerLink,
    configuration_observer: Option<ConfigurationObserver>,
    // The kernel dump behind the first `mesh.peers` page, reused by the pages that follow it (see `peer_page`).
    dump: Option<(std::time::Instant, Counters)>,
}
#[cfg(target_os = "linux")]
type Counters =
    std::collections::BTreeMap<crate::policy::model::PublicKey, crate::wireguard::Counters>;
#[cfg(target_os = "macos")]
type Counters =
    std::collections::BTreeMap<crate::policy::model::PublicKey, crate::macos_node::Counters>;
type ConfigurationObserver = Arc<dyn Fn(Option<Config>) -> std::io::Result<()> + Send + Sync>;
/// Synchronous return path used by the proxy controller after Traefik applies a route snapshot.
///
/// The flag says whether Traefik confirmed this state (see [`Node::set_proxy_ingress`]).
/// Linux only: proxy ingress opens ports in the nftables firewall, which Darwin nodes do not have yet.
#[cfg(target_os = "linux")]
pub type ProxyIngressObserver = Arc<
    dyn Fn(infraternal_mesh::proxy_ports::MeshProxyIngress, bool) -> std::io::Result<()>
        + Send
        + Sync,
>;
/// How long the following pages of one listing reuse the first page's kernel dump. A listing pages through in
/// milliseconds; anything older is a new listing and reads the kernel again.
const DUMP_REUSE: std::time::Duration = std::time::Duration::from_secs(2);
/// One `mesh.peers` page: the peers after `cursor`, as many as fit one action frame.
///
/// Linear in the page: the cursor seeks the ordered peer map and each row's encoded size is added up once, rather
/// than re-encoding the whole page after every row (#236, review: 54 pages at 1000 peers were ~30 ms per listing).
fn peer_page(
    config: Option<&crate::dataplane::Config>,
    counters: &Counters,
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
                json!([
                    id,
                    stats.handshake_secs,
                    stats.received_bytes,
                    stats.persistent_keepalive_secs
                ])
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
impl MeshNodePlugin {
    /// Bind one process-owned component to its validated public-state directory.
    #[must_use]
    pub fn new(path: &std::path::Path) -> Self {
        Self {
            owner: Arc::new(Mutex::new(Owner {
                node: None,
                path: Some(path.to_owned()),
            })),
            changed: AtomicBool::new(false),
            server_link: infraternal_plugin_api::server_path::ServerLink::default(),
            configuration_observer: None,
            dump: None,
        }
    }

    /// Bind an already restored node so Darwin resumes its utun before dialing the coordinator.
    #[must_use]
    pub fn from_node(node: Node) -> Self {
        Self {
            owner: Arc::new(Mutex::new(Owner {
                node: Some(node),
                path: None,
            })),
            changed: AtomicBool::new(false),
            server_link: infraternal_plugin_api::server_path::ServerLink::default(),
            configuration_observer: None,
            dump: None,
        }
    }

    /// Notify a sibling component only after Mesh has accepted a complete configuration.
    ///
    /// The observer receives the retained configuration, never an incoming partial chunk.
    #[must_use]
    pub fn with_configuration_observer(mut self, observer: ConfigurationObserver) -> Self {
        self.configuration_observer = Some(observer);
        self
    }

    /// Give the proxy controller a way to update this node's firewall after route application.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn proxy_ingress_observer(&self) -> ProxyIngressObserver {
        let owner = Arc::clone(&self.owner);
        Arc::new(move |proxy_ingress, confirmed| {
            let mut owner = owner
                .lock()
                .map_err(|_| std::io::Error::other("Mesh owner is unavailable"))?;
            owner
                .node()
                .map_err(|_| std::io::Error::other("Mesh state is unavailable"))?
                .set_proxy_ingress(proxy_ingress, confirmed)
        })
    }
}
impl Default for MeshNodePlugin {
    fn default() -> Self {
        Self {
            owner: Arc::new(Mutex::new(Owner {
                node: Some(Node::default()),
                path: None,
            })),
            changed: AtomicBool::new(false),
            server_link: infraternal_plugin_api::server_path::ServerLink::default(),
            configuration_observer: None,
            dump: None,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
/// Optional explicit negotiation keeps ordinary replies compatible with strict older decoders.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityProbe {
    #[serde(default)]
    compact_access: bool,
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(default)]
    dns_names: bool,
    #[serde(default)]
    key_rotation: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// Durable server operation key and epoch for one local `WireGuard` key change.
pub struct RotationOperation {
    operation_id: String,
    sequence: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// A bounded revision-pinned peer page request.
pub struct Page {
    #[serde(default)]
    cursor: Option<Cursor>,
    /// Rows of counters only, `[node, handshake_secs, received_bytes, persistent_keepalive_secs]`, for the
    /// server's presence poll (presence.rs). The server asks only its own node, which is always the same build,
    /// so an older node never sees the field. A quarter of the bytes of a full row: fewer pages per poll.
    #[serde(default)]
    presence: bool,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    version: u64,
    node: crate::policy::model::NodeId,
}
fn policy_summary(policy: &crate::policy::rules::TrafficPolicy) -> serde_json::Value {
    use crate::policy::rules::TrafficPolicy;
    match policy {
        TrafficPolicy::All => json!({"state":"All"}),
        TrafficPolicy::None => json!({"state":"None"}),
        TrafficPolicy::Ports(ports) => json!({"state":"Ports","count":ports.len()}),
    }
}
fn parse<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<T, PluginError> {
    if input.len() > infraternal_plugin_api::MAX_ACTION_BYTES
        || input.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(PluginError::Rejected);
    }
    serde_json::from_slice(input).map_err(|_| PluginError::Rejected)
}
/// Pure node action request. No kernel or filesystem operation occurs during parsing.
pub enum Request {
    Identity {
        compact_access: bool,
        #[cfg(feature = "mesh-dns-spike")]
        dns_names: bool,
        key_rotation: bool,
    },
    RotationPrepare(RotationOperation),
    RotationCommit(RotationOperation),
    RotationFinish(RotationOperation),
    Up,
    Down,
    Status,
    Configure(Box<Chunk>),
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
                #[cfg(feature = "mesh-dns-spike")]
                dns_names: probe.dns_names,
                key_rotation: probe.key_rotation,
            })
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
// Advertise extensions only after an explicit probe; ordinary callers receive the legacy shape.
/// One key rotation step on this node's own interface key (#285, D166).
fn rotation_response(node: &mut Node, request: Request) -> Result<serde_json::Value, PluginError> {
    Ok(match request {
        Request::RotationPrepare(operation) => json!({
            "public_key": node
                .prepare_rotation(&operation.operation_id, operation.sequence)
                .map_err(|_| PluginError::Rejected)?
        }),
        Request::RotationCommit(operation) => json!({
            "public_key": node
                .commit_rotation(&operation.operation_id, operation.sequence)
                .map_err(|_| PluginError::Rejected)?
                .public_key
        }),
        Request::RotationFinish(operation) => {
            node.finish_rotation(&operation.operation_id, operation.sequence)
                .map_err(|_| PluginError::Rejected)?;
            json!({})
        }
        _ => return Err(PluginError::Rejected),
    })
}
fn identity_response(
    identity: Option<crate::dataplane::Identity>,
    requested_compact_access: bool,
    requested_dns_names: bool,
    requested_key_rotation: bool,
) -> Option<IdentityResponse> {
    #[cfg(not(feature = "mesh-dns-spike"))]
    let _ = requested_dns_names;
    identity.map(|identity| IdentityResponse {
        public_key: identity.public_key,
        port: identity.port,
        compact_access: identity.compact_access && requested_compact_access,
        key_rotation: identity.key_rotation && requested_key_rotation,
        #[cfg(feature = "mesh-dns-spike")]
        dns_names: identity.dns_names && requested_dns_names,
    })
}
/// What `mesh.identity` and `mesh.up` answer: the node's key and port and the optional features both sides support.
#[derive(serde::Serialize)]
struct IdentityResponse {
    public_key: crate::policy::model::PublicKey,
    port: u16,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    compact_access: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    key_rotation: bool,
    #[cfg(feature = "mesh-dns-spike")]
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    dns_names: bool,
}

impl AgentPlugin for MeshNodePlugin {
    fn preferred_server(&self) -> Option<std::net::IpAddr> {
        let mut owner = self.owner.lock().ok()?;
        let node = owner.node().ok()?;
        if !node.enabled() || !node.active() {
            return None;
        }
        let config = node.config()?;
        let server = config.server?;
        if server == config.node {
            return None;
        }
        config
            .peers
            .get(&server)
            .map(|peer| peer.peer.addresses.ipv4.into())
    }
    fn set_server_link(&mut self, link: &infraternal_plugin_api::server_path::ServerLink) {
        self.server_link = link.clone();
    }

    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn has_cli(&self) -> bool {
        true
    }
    fn human_status_action(&self, action: &str) -> Option<&'static str> {
        matches!(action, "mesh.up" | "mesh.down").then_some("mesh.status")
    }
    fn present(
        &self,
        action: &str,
        output: &[u8],
        width: usize,
    ) -> Result<infraternal_plugin_api::present::Presented, PluginError> {
        crate::node_presentation::present(action, output, width)
    }
    fn control_actions(&self) -> &'static [ActionDef] {
        CONTROL_ACTIONS
    }
    fn take_events(&mut self) -> Vec<(&'static str, Vec<u8>)> {
        if self.changed.swap(false, Ordering::AcqRel) {
            vec![("mesh.changed", b"{}".to_vec())]
        } else {
            Vec::new()
        }
    }
    fn call(&mut self, action: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        let request = parse_action(action, input)?;
        // Proxy callbacks update this node's firewall, so release the Mesh owner lock before
        // notifying the sibling component to preserve one-way lock ordering.
        let (result, observed_config) = {
            let mut owner = self.owner.lock().map_err(|_| PluginError::Rejected)?;
            let node = owner.node()?;
            let result = match request {
                Request::Identity {
                    compact_access,
                    #[cfg(feature = "mesh-dns-spike")]
                    dns_names,
                    key_rotation,
                } => {
                    #[cfg(feature = "mesh-dns-spike")]
                    let requested_dns_names = dns_names;
                    #[cfg(not(feature = "mesh-dns-spike"))]
                    let requested_dns_names = false;
                    json!(identity_response(
                        node.ensure().map_err(|_| PluginError::Rejected)?,
                        compact_access,
                        requested_dns_names,
                        key_rotation,
                    ))
                }
                Request::Up => {
                    json!(identity_response(
                        Some(node.up().map_err(|_| PluginError::Rejected)?),
                        false,
                        false,
                        false,
                    ))
                }
                request @ (Request::RotationPrepare(_)
                | Request::RotationCommit(_)
                | Request::RotationFinish(_)) => rotation_response(node, request)?,
                Request::Down => {
                    node.down().map_err(|_| PluginError::Rejected)?;
                    json!({"state":"Off","version":null})
                }
                Request::Status => {
                    json!({"state":if node.stopping() {"Stopping"} else if !node.enabled() {"Off"} else if node.active() && node.config().is_some() {"On"} else {"Waiting"},"version":node.config().map(|c|c.version),"addresses":node.config().map(|c|c.addresses),"peer_count":node.config().map_or(0,|c|c.peers.len()),"default_policy":node.config().map(|c|c.default_policy),"server_link":self.server_link})
                }
                Request::Configure(chunk) => {
                    let applied = node.chunk(*chunk).map_err(|_| PluginError::Rejected)?;
                    json!({"applied":applied,"version":node.config().map(|c|c.version)})
                }
                Request::Peers(page) => {
                    if page.cursor.as_ref().is_some_and(|cursor| {
                        node.config()
                            .is_none_or(|config| config.version != cursor.version)
                    }) {
                        return Err(PluginError::Rejected);
                    }
                    // One kernel dump per listing: the first page reads the device, the pages after it reuse that
                    // reading, so a listing of N pages costs one dump, not N.
                    let reuse = page.cursor.is_some()
                        && self
                            .dump
                            .as_ref()
                            .is_some_and(|(at, _)| at.elapsed() < DUMP_REUSE);
                    if !reuse {
                        let counters = if node.active() {
                            read_counters(node)?
                        } else {
                            Counters::default()
                        };
                        self.dump = Some((std::time::Instant::now(), counters));
                    }
                    let (_, counters) = self.dump.as_ref().ok_or(PluginError::Rejected)?;
                    peer_page(node.config(), counters, page.cursor.as_ref(), page.presence)?
                }
            };
            let observed_config = matches!(
                action,
                "mesh.identity" | "mesh.up" | "mesh.down" | "mesh.status" | "mesh.configure"
            )
            .then(|| node.config().cloned());
            (result, observed_config)
        };
        if matches!(
            action,
            "mesh.up" | "mesh.down" | "mesh.rotation.commit" | "mesh.rotation.finish"
        ) {
            self.changed.store(true, Ordering::Release);
        }
        if let Some(config) = observed_config
            && let Some(observer) = &self.configuration_observer
        {
            observer(config).map_err(|_| PluginError::Rejected)?;
        }
        serde_json::to_vec(&result).map_err(|_| PluginError::Rejected)
    }
}

#[cfg(target_os = "linux")]
fn read_counters(_node: &mut Node) -> Result<Counters, PluginError> {
    crate::wireguard::Device::counters().map_err(|_| PluginError::Rejected)
}

#[cfg(target_os = "macos")]
fn read_counters(node: &mut Node) -> Result<Counters, PluginError> {
    node.counters().map_err(|_| PluginError::Rejected)
}

impl infraternal_plugin_api::ComponentPlugin for MeshNodePlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn status(&self) -> infraternal_plugin_api::PluginStatus {
        use infraternal_plugin_api::{PluginState, PluginStatus};
        self.owner.lock().map_or(
            PluginStatus {
                state: PluginState::Stopping,
                active_work: 1,
            },
            |owner| {
                let active = owner.node.as_ref().is_some_and(Node::active);
                let stopping = owner.node.as_ref().is_some_and(Node::stopping);
                PluginStatus {
                    state: if stopping {
                        PluginState::Stopping
                    } else if active {
                        PluginState::On
                    } else {
                        PluginState::Off
                    },
                    active_work: usize::from(active || stopping),
                }
            },
        )
    }
    fn set_enabled(&self, enabled: bool) -> infraternal_plugin_api::PluginOperation<'_, ()> {
        Box::pin(async move {
            // Component adapters invoke this boundary off their dispatch reactor,
            // just as the synchronous action registry does. Down returns only
            // after kernel state and the owned idle socket have retired.
            let config = {
                let mut owner = self.owner.lock().map_err(|_| "Mesh owner unavailable.")?;
                let node = owner.node().map_err(|_| "Mesh state unavailable.")?;
                if enabled {
                    node.up().map_err(|_| "Mesh start failed.")?;
                } else {
                    node.down().map_err(|_| "Mesh stop failed.")?;
                }
                node.config().cloned()
            };
            if let Some(observer) = &self.configuration_observer {
                observer(config).map_err(|_| "Mesh publication routes could not be updated.")?;
            }
            self.changed.store(true, Ordering::Release);
            Ok(())
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    #[test]
    #[ignore = "Run inside a dedicated kernel namespace with CAP_NET_ADMIN."]
    // Keep kernel setup, staged intent and explicit cleanup in one namespace owner.
    #[allow(clippy::too_many_lines)]
    fn applied_server_route_and_observed_link_survive_only_explicit_component_up() {
        use crate::{
            dataplane::{DefaultPolicy, Peer, PeerPolicy},
            policy::{
                model::{Addresses, NodeId},
                rules::TrafficPolicy,
            },
        };
        assert_eq!(nix::unistd::geteuid().as_raw(), 0, "namespace owner");
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").expect("own namespace"),
            std::fs::read_link("/proc/1/ns/net").expect("host namespace"),
            "kernel fixture requires a private network namespace"
        );
        let mut plugin = MeshNodePlugin::default();
        assert!(plugin.preferred_server().is_none());
        plugin.call("mesh.up", b"{}").expect("up");
        let (_, key) = crate::wireguard::Key::generate().expect("public peer fixture");
        let mut chunk = Chunk {
            access_updates: Vec::new(),
            server: Some(NodeId(2)),
            local_key: None,
            node: NodeId(1),
            #[cfg(feature = "mesh-dns-spike")]
            name: None,
            #[cfg(feature = "mesh-dns-spike")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            from_version: None,
            version: 1,
            index: 0,
            last: false,
            addresses: Addresses {
                ipv4: "10.254.0.1".parse().expect("IPv4"),
                ipv6: "fd01::1".parse().expect("IPv6"),
            },
            default_policy: DefaultPolicy::Allow,
            exposure: None,
            upserted: std::collections::BTreeMap::from([(
                NodeId(2),
                PeerPolicy {
                    peer: Peer {
                        key,
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: "10.254.0.2".parse().expect("IPv4"),
                            ipv6: "fd01::2".parse().expect("IPv6"),
                        },
                        endpoint: None,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                },
            )]),
            merged: std::collections::BTreeMap::new(),
            removed: Vec::new(),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: std::collections::BTreeMap::new(),
            #[cfg(feature = "mesh-dns-spike")]
            removed_peer_names: Vec::new(),
        };
        plugin
            .call(
                "mesh.configure",
                &serde_json::to_vec(&chunk).expect("chunk"),
            )
            .expect("stage");
        assert!(
            plugin.preferred_server().is_none(),
            "staged routes cannot move a live transport"
        );
        chunk.index = 1;
        chunk.last = true;
        chunk.upserted.clear();
        plugin
            .call(
                "mesh.configure",
                &serde_json::to_vec(&chunk).expect("chunk"),
            )
            .expect("apply");
        assert_eq!(
            plugin.preferred_server(),
            Some("10.254.0.2".parse().expect("IPv4"))
        );
        let observed = infraternal_plugin_api::server_path::ServerLink {
            kind: infraternal_plugin_api::server_path::ServerLinkKind::Fallback,
            endpoint: Some("127.0.0.1:7443".parse().expect("endpoint")),
            source_port: None,
            reason: infraternal_plugin_api::server_path::ServerLinkReason::MeshRefused,
        };
        plugin.set_server_link(&observed);
        let status: serde_json::Value =
            serde_json::from_slice(&plugin.call("mesh.status", b"{}").expect("status"))
                .expect("public status");
        assert_eq!(
            status["server_link"],
            serde_json::to_value(&observed).expect("observed link")
        );
        plugin.call("mesh.down", b"{}").expect("down");
        assert!(plugin.preferred_server().is_none());
        plugin.call("mesh.up", b"{}").expect("up");
        chunk.server = Some(chunk.node);
        chunk.version = 2;
        chunk.index = 0;
        plugin
            .call(
                "mesh.configure",
                &serde_json::to_vec(&chunk).expect("chunk"),
            )
            .expect("local server");
        assert!(
            plugin.preferred_server().is_none(),
            "a local server does not dial itself"
        );
        plugin.call("mesh.down", b"{}").expect("cleanup");
    }

    #[test]
    fn node_actions_register_without_kernel_work_and_hide_machine_calls() {
        let mut registry = infraternal_plugin_api::PluginRegistry::default();
        registry
            .register(Box::new(MeshNodePlugin::default()))
            .expect("valid node metadata");
        let metadata = serde_json::to_string(&DESCRIPTOR).expect("public descriptor");
        for action in ACTIONS {
            assert!(metadata.contains(action.id));
        }
        for action in CONTROL_ACTIONS {
            assert!(!metadata.contains(action.id));
        }
    }
    #[test]
    fn node_actions_refuse_alternate_forms_duplicates_and_unbounded_input() {
        for action in ACTIONS.iter().chain(CONTROL_ACTIONS) {
            assert!(parse_action(action.id, b"[]").is_err());
            assert!(parse_action(action.id, b"null").is_err());
            assert!(
                parse_action(
                    action.id,
                    &vec![b' '; infraternal_plugin_api::MAX_ACTION_BYTES + 1]
                )
                .is_err()
            );
        }
        assert!(parse_action("mesh.peers", br#"{"cursor":null,"cursor":null}"#).is_err());
        assert!(parse_action("mesh.peers", br#"{"cursor":{"version":-1,"node":1}}"#).is_err());
        assert!(parse_action("mesh.up", br#"{"enabled":false}"#).is_err());
        assert!(matches!(parse_action("mesh.up", b"{}"), Ok(Request::Up)));
    }
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn failed_cleanup_reports_stopping_and_reconnect_keeps_explicit_off() {
        use crate::{
            dataplane::DefaultPolicy,
            policy::model::{Addresses, NodeId},
        };
        use std::{
            io::Write as _,
            process::{Command, Stdio},
        };
        let mut plugin = MeshNodePlugin::default();
        plugin.call("mesh.up", b"{}").expect("start");
        let chunk = Chunk {
            access_updates: Vec::new(),
            local_key: None,
            server: None,
            node: NodeId(1),
            #[cfg(feature = "mesh-dns-spike")]
            name: None,
            #[cfg(feature = "mesh-dns-spike")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            from_version: None,
            version: 1,
            index: 0,
            last: true,
            addresses: Addresses {
                ipv4: "10.254.0.1".parse().expect("IPv4"),
                ipv6: "fd01::1".parse().expect("IPv6"),
            },
            default_policy: DefaultPolicy::Allow,
            exposure: None,
            upserted: std::collections::BTreeMap::new(),
            merged: std::collections::BTreeMap::new(),
            removed: Vec::new(),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: std::collections::BTreeMap::new(),
            #[cfg(feature = "mesh-dns-spike")]
            removed_peer_names: Vec::new(),
        };
        plugin
            .call(
                "mesh.configure",
                &serde_json::to_vec(&chunk).expect("chunk"),
            )
            .expect("configure");
        let mut child = Command::new("/usr/sbin/nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("fixture");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"delete table inet infraternal_mesh\nadd table inet infraternal_mesh\n")
            .expect("fixture batch");
        assert!(child.wait().expect("fixture status").success());
        assert!(plugin.call("mesh.down", b"{}").is_err());
        let status: serde_json::Value =
            serde_json::from_slice(&plugin.call("mesh.status", b"{}").expect("status"))
                .expect("JSON");
        assert_eq!(status["state"], "Stopping");
        assert!(
            Command::new("/usr/sbin/nft")
                .args(["delete", "table", "inet", "infraternal_mesh"])
                .status()
                .expect("fixture cleanup")
                .success()
        );
        plugin.call("mesh.down", b"{}").expect("finish cleanup");
        assert_eq!(
            plugin.call("mesh.identity", b"{}").expect("reconnect"),
            b"null"
        );
        assert_eq!(
            infraternal_plugin_api::ComponentPlugin::status(&plugin).active_work,
            0
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod identity_upgrade_tests {
    #[test]
    fn ordinary_identity_reply_retains_the_legacy_shape() {
        let identity = crate::dataplane::Identity {
            public_key: crate::policy::model::PublicKey([1; 32]),
            port: 44000,
            compact_access: true,
            #[cfg(feature = "mesh-dns-spike")]
            dns_names: true,
            key_rotation: true,
        };
        let legacy = serde_json::json!(super::identity_response(
            Some(identity.clone()),
            false,
            false,
            false
        ));
        assert_eq!(legacy.as_object().map(serde_json::Map::len), Some(2));
        assert_eq!(legacy["port"], 44000);
        assert!(legacy.get("compact_access").is_none());
        let negotiated = serde_json::json!(super::identity_response(
            Some(identity.clone()),
            true,
            true,
            true
        ));
        assert_eq!(negotiated["compact_access"], true);
        assert_eq!(negotiated["key_rotation"], true);
        #[cfg(feature = "mesh-dns-spike")]
        assert_eq!(negotiated["dns_names"], true);
        let compact_only =
            serde_json::json!(super::identity_response(Some(identity), true, false, false));
        assert_eq!(compact_only["compact_access"], true);
        assert!(compact_only.get("key_rotation").is_none());
        #[cfg(feature = "mesh-dns-spike")]
        assert!(compact_only.get("dns_names").is_none());
    }
}

/// `mesh.peers` paging and its cost (#236).
#[cfg(all(test, target_os = "linux"))]
mod peer_page_tests {
    #![allow(clippy::expect_used)]
    use super::{Counters, Cursor, peer_page};
    fn peer_config(peers: u64) -> crate::dataplane::Config {
        use crate::{
            dataplane::{Config, DefaultPolicy, Peer, PeerPolicy},
            policy::{
                model::{Addresses, NodeId, PublicKey},
                rules::TrafficPolicy,
            },
        };
        let address = |id: u64| {
            let id = u32::try_from(id).expect("fixture id");
            Addresses {
                ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
                ipv6: std::net::Ipv6Addr::from((0xfd01_u128 << 112) + u128::from(id)),
            }
        };
        Config {
            local_key: None,
            server: Some(NodeId(1)),
            node: NodeId(1),
            #[cfg(feature = "mesh-dns-spike")]
            name: None,
            #[cfg(feature = "mesh-dns-spike")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 4,
            addresses: address(1),
            default_policy: DefaultPolicy::Allow,
            exposure: None,
            peers: (2..=peers + 1)
                .map(|id| {
                    let byte = u8::try_from(id % 251).expect("fixture key");
                    (
                        NodeId(id),
                        PeerPolicy {
                            peer: Peer {
                                key: PublicKey([byte; 32]),
                                previous_key: None,
                                previous_active: false,
                                addresses: address(id),
                                endpoint: Some(std::net::SocketAddr::from((
                                    [203, 0, 113, 7],
                                    40_000,
                                ))),
                            },
                            inbound: TrafficPolicy::All,
                            outbound: TrafficPolicy::All,
                        },
                    )
                })
                .collect(),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: std::collections::BTreeMap::new(),
        }
    }
    fn page_through(
        config: &crate::dataplane::Config,
        counters: &Counters,
        presence: bool,
    ) -> Vec<serde_json::Value> {
        let mut pages = Vec::new();
        let mut cursor: Option<Cursor> = None;
        loop {
            let page = peer_page(Some(config), counters, cursor.as_ref(), presence).expect("page");
            assert!(
                serde_json::to_vec(&page).expect("encode").len()
                    <= infraternal_plugin_api::MAX_ACTION_BYTES
            );
            cursor = serde_json::from_value(page["next_cursor"].clone()).expect("cursor");
            pages.push(page);
            if cursor.is_none() {
                return pages;
            }
        }
    }
    /// Every peer is listed once, in order, and every page fits one action frame (#236).
    #[test]
    fn peer_pages_cover_every_peer_once_within_the_frame() {
        let config = peer_config(500);
        let pages = page_through(&config, &Counters::default(), false);
        let listed: Vec<u64> = pages
            .iter()
            .flat_map(|page| page["peers"].as_array().expect("rows").clone())
            .map(|row| row["node"].as_u64().expect("node"))
            .collect();
        assert_eq!(listed, (2..=501).collect::<Vec<_>>());
        // The presence form lists the same peers as counter rows, in a fraction of the pages.
        let compact = page_through(&config, &Counters::default(), true);
        let listed: Vec<u64> = compact
            .iter()
            .flat_map(|page| page["peers"].as_array().expect("rows").clone())
            .map(|row| row[0].as_u64().expect("node"))
            .collect();
        assert_eq!(listed, (2..=501).collect::<Vec<_>>());
        assert!(
            compact.len() * 3 < pages.len(),
            "{} vs {}",
            compact.len(),
            pages.len()
        );
        assert!(pages.len() > 1);
        // A full page stops when the next encoded row would exceed its byte budget.
        let first = serde_json::to_vec(&pages[0]["peers"])
            .expect("encode")
            .len();
        let next = serde_json::to_vec(&pages[1]["peers"][0])
            .expect("encode")
            .len();
        let budget = infraternal_plugin_api::MAX_ACTION_BYTES - 128;
        assert!(
            first <= budget && first + next + 1 > budget,
            "page has {first} bytes and next row has {next} bytes for {budget}-byte budget"
        );
    }
    /// Poll cost at scale, userspace only: every `mesh.peers` page the server's node builds for one poll, its
    /// encoding and decoding across the action frame, and the server's `presence::read_peers` (#236). The kernel
    /// dump is one per poll and measured separately. Run with
    /// `cargo test -p infraternal-plugin-mesh --features agent --release --lib -- --ignored --nocapture poll_cost`.
    #[cfg(feature = "server")]
    #[test]
    #[ignore = "measurement"]
    fn poll_cost() {
        for peers in [50_u64, 500, 1000] {
            let config = peer_config(peers);
            let counters: Counters = config
                .peers
                .values()
                .map(|peer| {
                    (
                        peer.peer.key,
                        crate::wireguard::Counters {
                            persistent_keepalive_secs: 25,
                            handshake_secs: 1_800_000_000,
                            received_bytes: 925_000,
                            sent_bytes: 925_000,
                            #[cfg(feature = "relay")]
                            handshake_nanos: 0,
                            endpoint: None,
                        },
                    )
                })
                .collect();
            let rounds = 50;
            let started = std::time::Instant::now();
            let mut pages = 0;
            for _ in 0..rounds {
                let mut rows = Vec::new();
                let mut cursor: Option<Cursor> = None;
                pages = 0;
                loop {
                    pages += 1;
                    let page =
                        peer_page(Some(&config), &counters, cursor.as_ref(), true).expect("page");
                    let wire = serde_json::to_vec(&page).expect("encode");
                    match crate::presence::read_peers(&wire, &mut rows).expect("decode") {
                        Some(next) => cursor = Some(serde_json::from_value(next).expect("cursor")),
                        None => break,
                    }
                }
                assert_eq!(rows.len(), config.peers.len());
            }
            let per_poll = started.elapsed() / rounds;
            println!(
                "peers={peers} pages={pages} per_poll={per_poll:?} cpu_share_at_5s={:.3}%",
                per_poll.as_secs_f64() / 5.0 * 100.0
            );
        }
    }
}
