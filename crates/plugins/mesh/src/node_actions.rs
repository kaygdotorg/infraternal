//! Declares and dispatches the Mesh node's authenticated actions; all adapters share these instructions [16,198,202].
use crate::{dataplane::Chunk, node::Node};
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
        "Read Mesh status",
        "Empty",
        "MeshNodeStatus",
        Effect::Read,
        &[
            "Read the node component's state and applied policy version.",
            "Inspect the active server link and its reason: mesh or the enrolled fallback port.",
            "Use --json for the machine record.",
        ],
    ),
    action(
        "mesh.peers",
        "List Mesh peers",
        "MeshPeerPage",
        "MeshPeers",
        Effect::Read,
        &[
            "Read public peers and kernel handshake counters.",
            "Follow next_cursor for more peers.",
            "A missing handshake means the direct path is unproven.",
        ],
    ),
    action(
        "mesh.up",
        "Start Mesh on this node",
        "Empty",
        "MeshIdentity",
        Effect::Write,
        &[
            "Join this node to an existing server first.",
            "Run as root to create the kernel interface.",
            "The server supplies public peers and Access policy over the authenticated channel.",
        ],
    ),
    action(
        "mesh.down",
        "Stop Mesh on this node",
        "Empty",
        "MeshNodeStatus",
        Effect::Write,
        &[
            "Remove this node's Mesh interface and packet filter.",
            "Verify the component is off; incomplete cleanup reports a failure.",
        ],
    ),
];
const CONTROL_ACTIONS: &[ActionDef] = &[
    action(
        "mesh.identity",
        "Read enabled Mesh identity",
        "Empty",
        "OptionalMeshIdentity",
        Effect::Write,
        &[
            "The authenticated coordinator queries the enabled node identity.",
            "An explicitly stopped component stays off.",
        ],
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
            self.node = Some(
                Node::restore(self.path.as_deref().ok_or(PluginError::Rejected)?)
                    .map_err(|_| PluginError::Rejected)?,
            );
        }
        self.node.as_mut().ok_or(PluginError::Rejected)
    }
}
pub struct MeshNodePlugin {
    owner: Arc<Mutex<Owner>>,
    changed: AtomicBool,
    server_link: infraternal_plugin_api::server_path::ServerLink,
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
        }
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
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// A bounded revision-pinned peer page request.
pub struct Page {
    #[serde(default)]
    cursor: Option<Cursor>,
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
    Identity,
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
        "mesh.identity" | "mesh.up" | "mesh.down" | "mesh.status" => {
            let _: Empty = parse(input)?;
            Ok(match action {
                "mesh.identity" => Request::Identity,
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
    fn format_human(&self, action: &str, output: &[u8]) -> Result<String, PluginError> {
        crate::node_presentation::format(action, output)
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
        let mut owner = self.owner.lock().map_err(|_| PluginError::Rejected)?;
        let node = owner.node()?;
        let result = match request {
            Request::Identity => {
                json!(node.ensure().map_err(|_| PluginError::Rejected)?)
            }
            Request::Up => {
                json!(node.up().map_err(|_| PluginError::Rejected)?)
            }
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
                let counters = if node.active() {
                    crate::wireguard::Device::counters().map_err(|_| PluginError::Rejected)?
                } else {
                    std::collections::BTreeMap::default()
                };
                let mut peers = Vec::new();
                let mut last = None;
                let mut more = false;
                if let Some(config) = node.config() {
                    for (id, peer) in &config.peers {
                        if page
                            .cursor
                            .as_ref()
                            .is_some_and(|cursor| *id <= cursor.node)
                        {
                            continue;
                        }
                        let stats = counters.get(&peer.peer.key).cloned().unwrap_or_default();
                        let value = json!({"node":id,"peer":peer.peer,"inbound":policy_summary(&peer.inbound),"outbound":policy_summary(&peer.outbound),"counters":stats,"path":if stats.handshake_secs > 0 {"Direct"} else {"Unproven"}});
                        // Fit resource-bound pages by encoded bytes, not an arbitrary peer-count cap [214].
                        peers.push(value);
                        if serde_json::to_vec(&peers)
                            .map_err(|_| PluginError::Rejected)?
                            .len()
                            > infraternal_plugin_api::MAX_ACTION_BYTES - 128
                        {
                            peers.pop();
                            more = true;
                            break;
                        }
                        last = Some(*id);
                    }
                }
                json!({"peers":peers,"version":node.config().map(|config|config.version),"next_cursor":if more {last.zip(node.config()).map(|(node,config)|Cursor {version:config.version,node})} else {None}})
            }
        };
        if matches!(action, "mesh.up" | "mesh.down") {
            self.changed.store(true, Ordering::Release);
        }
        serde_json::to_vec(&result).map_err(|_| PluginError::Rejected)
    }
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
            let mut owner = self.owner.lock().map_err(|_| "Mesh owner unavailable.")?;
            let node = owner.node().map_err(|_| "Mesh state unavailable.")?;
            if enabled {
                node.up().map_err(|_| "Mesh start failed.")?;
            } else {
                node.down().map_err(|_| "Mesh stop failed.")?;
            }
            self.changed.store(true, Ordering::Release);
            Ok(())
        })
    }
}

#[cfg(test)]
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
            server: Some(NodeId(2)),
            node: NodeId(1),
            from_version: None,
            version: 1,
            index: 0,
            last: false,
            addresses: Addresses {
                ipv4: "10.254.0.1".parse().expect("IPv4"),
                ipv6: "fd01::1".parse().expect("IPv6"),
            },
            default_policy: DefaultPolicy::Allow,
            upserted: std::collections::BTreeMap::from([(
                NodeId(2),
                PeerPolicy {
                    peer: Peer {
                        key,
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
            server: None,
            node: NodeId(1),
            from_version: None,
            version: 1,
            index: 0,
            last: true,
            addresses: Addresses {
                ipv4: "10.254.0.1".parse().expect("IPv4"),
                ipv6: "fd01::1".parse().expect("IPv6"),
            },
            default_policy: DefaultPolicy::Allow,
            upserted: std::collections::BTreeMap::new(),
            merged: std::collections::BTreeMap::new(),
            removed: Vec::new(),
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
