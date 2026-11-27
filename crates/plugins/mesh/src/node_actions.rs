//! Declares and dispatches the Mesh node's authenticated actions; all adapters share these instructions [16,198,202].
#[cfg(all(test, target_os = "linux"))]
use crate::dataplane::Chunk;
use crate::{dataplane::Config, node::Node};
/// Shared action descriptors and request types used by the host dispatch.
pub use infraternal_mesh_node::node_actions::{
    ACTIONS, DESCRIPTOR, MAX_ADVERTISED_NETWORKS, Page, Request, RotationOperation, RouteList,
    parse_action, parse_networks,
};
use infraternal_mesh_node::node_actions::{
    CONTROL_ACTIONS, IdentityProbe, peer_page, policy_summary,
};
#[cfg(all(test, target_os = "linux"))]
use infraternal_mesh_node::node_actions::{Cursor, parse};
use infraternal_plugin_api::{ActionDef, AgentPlugin, PluginDescriptor, PluginError};
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
/// The process retains kernel state across a remote-channel reconnect. A socket loss
/// never drops this owner; only explicit down retires the component [166].
struct Owner {
    node: Option<Node>,
    path: Option<std::path::PathBuf>,
    /// Suppress repeated restore failures until the next successful restore.
    restore_failed: bool,
}
impl Owner {
    /// Return the process-owned node, restoring it lazily when this action first needs it.
    fn node(&mut self) -> Result<&mut Node, PluginError> {
        if self.node.is_none() {
            let path = self.path.as_deref().ok_or(PluginError::Rejected)?;
            #[cfg(target_os = "linux")]
            let node = Node::restore(path);
            // The Mac registry restores eagerly with its enrolment (`from_node`);
            // only Linux reaches this lazy path, through `new`.
            #[cfg(target_os = "macos")]
            let node = Node::restore(path, None);
            self.node = Some(startup_result(node, &mut self.restore_failed, "restore")?);
        }
        self.node.as_mut().ok_or(PluginError::Rejected)
    }
}
/// Report a startup error once per streak, even before a tracing subscriber exists.
fn startup_result<T>(
    result: std::io::Result<T>,
    failed: &mut bool,
    phase: &str,
) -> Result<T, PluginError> {
    match result {
        Ok(value) => {
            *failed = false;
            Ok(value)
        }
        Err(error) => {
            if !*failed {
                eprintln!(
                    "Mesh node failed phase={phase} kind={:?}; check local mesh permissions and tunnel availability.",
                    error.kind()
                );
            }
            *failed = true;
            Err(node_action_error(&error))
        }
    }
}

/// Turn a configuration result into the action reply, and say on stderr why one was refused.
///
/// The reply carries only a short fixed reason, and an infraternal agent has no tracing
/// subscriber, so without this line the kernel or state error behind a refusal was lost: an
/// IPv6-off host failed to join with nothing logged at all (#578). It is printed once per streak
/// of refusals, because the coordinator can resend the same snapshot. Errors here are kernel
/// error numbers or fixed texts, never key material.
fn configure_result(result: std::io::Result<bool>, failed: &mut bool) -> Result<bool, PluginError> {
    match result {
        Ok(applied) => {
            *failed = false;
            Ok(applied)
        }
        Err(error) => {
            if !*failed {
                eprintln!(
                    "Mesh configuration was refused: {error} (kind={:?}).",
                    error.kind()
                );
            }
            *failed = true;
            Err(node_action_error(&error))
        }
    }
}

/// Owns the process's mesh actions and their startup diagnostics.
pub struct MeshNodePlugin {
    owner: Arc<Mutex<Owner>>,
    changed: AtomicBool,
    /// Reports activation failures once per streak.
    ensure_failed: bool,
    /// Reports refused configurations once per streak (#578).
    configure_failed: bool,
    server_link: infraternal_plugin_api::server_path::ServerLink,
    configuration_observer: Option<ConfigurationObserver>,
    proxy_containment: Option<ProxyContainmentProbe>,
    // The kernel dump behind the first `mesh.peers` page, reused by the pages that follow it (see `peer_page`).
    dump: Option<(std::time::Instant, Counters)>,
}
/// Counters from the host engine, indexed by active device key.
use infraternal_mesh_node::peer_stats::CounterMap as Counters;
/// Publishes each accepted mesh configuration and the engine enforcing its access rules.
type ConfigurationObserver = Arc<dyn Fn(Option<Config>, bool) -> std::io::Result<()> + Send + Sync>;
/// How this node contains its proxy processes, as `(kind, detail)` for `mesh.status` [#281, D336].
pub type ProxyContainmentProbe = Arc<dyn Fn() -> (&'static str, String) + Send + Sync>;
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
/// Map D346 nft refusals to their own reason while keeping unrelated local errors generic.
///
/// Every nft failure from the firewall starts with `nft ` (a missing tool, or `nft at <path>`
/// for a found one that failed), so the prefix identifies them wherever nft was found.
fn node_action_error(error: &std::io::Error) -> PluginError {
    let message = error.to_string();
    #[cfg(target_os = "linux")]
    {
        if message.starts_with("nft ") {
            return PluginError::KernelFirewallUnavailable;
        }
    }
    let _ = message;
    PluginError::Rejected
}

/// Keep the D346 path in component-operation failures while using the caller's fallback otherwise.
fn node_action_message(error: &std::io::Error, fallback: &'static str) -> &'static str {
    let error = node_action_error(error);
    if error == PluginError::KernelFirewallUnavailable {
        error.control_error_message()
    } else {
        fallback
    }
}

/// Keep a path-specific plugin refusal when adapting it to the component-operation result.
fn plugin_action_message(error: PluginError, fallback: &'static str) -> &'static str {
    if error == PluginError::KernelFirewallUnavailable {
        error.control_error_message()
    } else {
        fallback
    }
}

impl MeshNodePlugin {
    /// Bind one process-owned component to its validated public-state directory.
    #[must_use]
    pub fn new(path: &std::path::Path) -> Self {
        Self {
            owner: Arc::new(Mutex::new(Owner {
                node: None,
                path: Some(path.to_owned()),
                restore_failed: false,
            })),
            changed: AtomicBool::new(false),
            ensure_failed: false,
            configure_failed: false,
            server_link: infraternal_plugin_api::server_path::ServerLink::default(),
            configuration_observer: None,
            proxy_containment: None,
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
                restore_failed: false,
            })),
            changed: AtomicBool::new(false),
            ensure_failed: false,
            configure_failed: false,
            server_link: infraternal_plugin_api::server_path::ServerLink::default(),
            configuration_observer: None,
            proxy_containment: None,
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

    /// Report the proxy's process containment in `mesh.status`, because the proxy's Mesh
    /// listener is part of what this node exposes to its peers.
    #[must_use]
    pub fn with_proxy_containment(mut self, probe: ProxyContainmentProbe) -> Self {
        self.proxy_containment = Some(probe);
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
                restore_failed: false,
            })),
            changed: AtomicBool::new(false),
            ensure_failed: false,
            configure_failed: false,
            server_link: infraternal_plugin_api::server_path::ServerLink::default(),
            configuration_observer: None,
            proxy_containment: None,
            dump: None,
        }
    }
}
/// A refusal reply the local CLI shows as a failed command with `message` (D303 error codes).
fn refusal(code: &str, message: &str) -> serde_json::Value {
    json!({"error": {"code": code}, "message": message})
}
// Advertise extensions only after an explicit probe; ordinary callers receive the legacy shape.
/// One key rotation step on this node's own interface key (#285, D166), and whether the step changed the key this
/// node presents. Prepare changes it only when it settles an ended operation whose candidate the link already
/// holds (J273 P3-3); commit and finish always raise the change notice.
fn rotation_response(
    node: &mut Node,
    request: Request,
) -> Result<(serde_json::Value, bool), PluginError> {
    let before = node.interface_key();
    let value = match request {
        Request::RotationPrepare(operation) => json!({
            "public_key": node
                .prepare_rotation(&operation.operation_id, operation.sequence)
                .map_err(|error| node_action_error(&error))?
        }),
        Request::RotationCommit(operation) => json!({
            "public_key": node
                .commit_rotation(&operation.operation_id, operation.sequence)
                .map_err(|error| node_action_error(&error))?
                .public_key
        }),
        Request::RotationFinish(operation) => {
            node.finish_rotation(&operation.operation_id, operation.sequence)
                .map_err(|error| node_action_error(&error))?;
            json!({})
        }
        _ => return Err(PluginError::Rejected),
    };
    Ok((value, node.interface_key() != before))
}
/// The identity reply, offering each optional capability only when both the node and the requester support it.
///
/// `lan` is this node's LAN candidates ([`crate::candidates::lan_addresses`]); it is sent only to a
/// coordinator that asked for candidates. `ipv4_only` is whether IPv6 is off on the mesh link (#578); it is
/// reported only to a coordinator that asked, because a strict older one would not know the field.
/// `side_port` is whether this node runs the side-mark receive rule with its second socket on
/// (#260, J1211); it too is reported only to a coordinator that asked.
fn identity_response(
    identity: Option<crate::dataplane::Identity>,
    requested: IdentityProbe,
    lan: Vec<std::net::SocketAddr>,
    ipv4_only: bool,
    side_port: bool,
) -> Option<IdentityResponse> {
    identity.map(|identity| IdentityResponse {
        public_key: identity.public_key,
        port: identity.port,
        compact_access: identity.compact_access && requested.compact_access,
        key_rotation: identity.key_rotation && requested.key_rotation,
        authority_epoch: identity.authority_epoch && requested.authority_epoch,
        rotation_continuity: identity.rotation_continuity && requested.rotation_continuity,
        #[cfg(feature = "mesh-dns")]
        dns_names: identity.dns_names && requested.dns_names,
        candidates: requested.candidates,
        ipv6_state: requested.ipv6_state,
        ipv4_only: requested.ipv6_state && ipv4_only,
        lan: if requested.candidates {
            lan
        } else {
            Vec::new()
        },
        routes: false,
        advertised: Vec::new(),
        side_socket: requested.side_socket,
        side_port: requested.side_socket && side_port,
    })
}
/// What `mesh.identity` and `mesh.up` answer: the node's key and port and the optional features both sides support.
#[derive(serde::Serialize)]
// These flags are independent optional wire fields so older strict decoders keep their current shape.
#[allow(clippy::struct_excessive_bools)]
struct IdentityResponse {
    public_key: crate::policy::model::PublicKey,
    port: u16,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    compact_access: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    key_rotation: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    authority_epoch: bool,
    /// True only when both sides negotiated operation continuity.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    rotation_continuity: bool,
    #[cfg(feature = "mesh-dns")]
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    dns_names: bool,
    /// This node accepts `Peer::candidates` and walks them in order (#515).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    candidates: bool,
    /// This node understands subnet routes in its snapshots and reports what it advertises
    /// (D197 M3). Present only when the coordinator asked with `{"routes":true}`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    routes: bool,
    /// The networks this node advertises; present only with `routes`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    advertised: Vec<crate::policy::networks::Network>,
    /// This node's LAN candidates, for peers behind the same public address (#515).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lan: Vec<std::net::SocketAddr>,
    /// This node understands `Peer::ipv4_only` and reports its own IPv6 state (#578, J1142).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    ipv6_state: bool,
    /// IPv6 is off on the mesh link, so the node runs IPv4-only. Present only with `ipv6_state`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    ipv4_only: bool,
    /// This node understands `Peer::side_port` and reports whether it takes marked datagrams
    /// (#260, J1211). Present only when the coordinator asked with `{"side_socket":true}`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    side_socket: bool,
    /// This node runs `GotaTun`'s side-mark receive rule with its second socket on, so a peer may
    /// send it marked datagrams from its own second socket. Present only with `side_socket`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    side_port: bool,
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
                    #[cfg(feature = "mesh-dns")]
                    dns_names,
                    key_rotation,
                    authority_epoch,
                    rotation_continuity,
                    candidates,
                    ipv6_state,
                    routes,
                    side_socket,
                } => {
                    let requested = IdentityProbe {
                        compact_access,
                        #[cfg(feature = "mesh-dns")]
                        dns_names,
                        key_rotation,
                        authority_epoch,
                        rotation_continuity,
                        // Offered only by an engine that walks the list it would receive.
                        candidates: candidates && walks_candidates(node),
                        ipv6_state,
                        // Answered only by an engine that installs the networks it would receive.
                        routes: routes && understands_routes(node),
                        side_socket,
                    };
                    let candidates = requested.candidates;
                    let identity =
                        startup_result(node.ensure(), &mut self.ensure_failed, "activate")?;
                    let lan = match (&identity, candidates) {
                        (Some(identity), true) => {
                            // The node's own mesh addresses are never LAN candidates.
                            let own: Vec<std::net::IpAddr> = node
                                .config()
                                .map(|config| {
                                    vec![config.addresses.ipv4.into(), config.addresses.ipv6.into()]
                                })
                                .unwrap_or_default();
                            crate::candidates::lan_addresses(identity.port, &own)
                        }
                        _ => Vec::new(),
                    };
                    let answer_routes = requested.routes;
                    let mut response = identity_response(
                        identity,
                        requested,
                        lan,
                        ipv4_only(node),
                        side_port(node),
                    );
                    if answer_routes && let Some(response) = response.as_mut() {
                        response.routes = true;
                        response.advertised = advertised_routes(node);
                    }
                    json!(response)
                }
                Request::Routes => routes_view(node),
                Request::RoutesAdvertise(texts) => match parse_networks(&texts) {
                    Err(message) => refusal("usage", &message),
                    Ok(networks) => match change_advertised(node, networks, true) {
                        Ok(changed) => {
                            if changed {
                                self.changed.store(true, Ordering::Release);
                            }
                            routes_view(node)
                        }
                        Err(message) => refusal("failed", message),
                    },
                },
                Request::RoutesWithdraw(texts) => match parse_networks(&texts) {
                    Err(message) => refusal("usage", &message),
                    Ok(networks) => match change_advertised(node, networks, false) {
                        Ok(changed) => {
                            if changed {
                                self.changed.store(true, Ordering::Release);
                            }
                            routes_view(node)
                        }
                        Err(message) => refusal("failed", message),
                    },
                },
                Request::Up => {
                    json!(identity_response(
                        Some(node.up().map_err(|error| node_action_error(&error))?),
                        IdentityProbe::default(),
                        Vec::new(),
                        false,
                        false,
                    ))
                }
                request @ (Request::RotationPrepare(_)
                | Request::RotationCommit(_)
                | Request::RotationFinish(_)) => {
                    let (value, key_changed) = rotation_response(node, request)?;
                    if key_changed {
                        self.changed.store(true, Ordering::Release);
                    }
                    value
                }
                Request::Down => {
                    node.down().map_err(|error| node_action_error(&error))?;
                    json!({"state":"Off","version":null})
                }
                Request::Status => {
                    let state = if node.stopping() {
                        "Stopping"
                    } else if !node.enabled() {
                        "Off"
                    } else if node.awaiting_server_snapshot() {
                        "Waiting"
                    } else if node.active() && node.config().is_some() {
                        "On"
                    } else {
                        "Waiting"
                    };
                    let mut status = json!({
                        "state": state,
                        "version": node.config().map(|config| config.version),
                        "addresses": node.config().map(|config| config.addresses),
                        "peer_count": node.config().map_or(0, |config| config.peers.len()),
                        "default_policy": node.config().map(|config| config.default_policy),
                        "udp_port": node.listen_port(),
                        "dns": node.dns_state(),
                        "ipv6": !ipv4_only(node),
                        "side_socket": side_port(node),
                        "server_link": self.server_link,
                        "engine": engine_health(node),
                        "engine_selection": engine_selection(node),
                        "enforcement": access_enforcement(node),
                        "kernel_guard": kernel_guard_status(node),
                    });
                    // Public identity is useful for continuity checks; private key material never leaves the node.
                    if let Some(public_key) = node.interface_key() {
                        status["public_key"] = json!(public_key.0);
                    }
                    if let Some(probe) = &self.proxy_containment {
                        let (kind, detail) = probe();
                        status["proxy_containment"] = json!({"kind": kind, "detail": detail});
                    }
                    status
                }
                Request::Configure(chunk) => {
                    let applied = configure_result(node.chunk(*chunk), &mut self.configure_failed)?;
                    let mut reply =
                        json!({"applied":applied,"version":node.config().map(|c|c.version)});
                    // Told after every snapshot, because applying one is when the node reads its link:
                    // the coordinator learns IPv6 went away or came back from this reply (#578, J1142).
                    // Absent means dual-stack, so a reply without IPv4-only nodes keeps its old shape.
                    if ipv4_only(node) {
                        reply["ipv4_only"] = json!(true);
                    }
                    reply
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
            .then(|| {
                (
                    node.config().cloned(),
                    access_enforcement(node) == "userspace",
                )
            });
            (result, observed_config)
        };
        if matches!(
            action,
            "mesh.up" | "mesh.down" | "mesh.rotation.commit" | "mesh.rotation.finish"
        ) {
            self.changed.store(true, Ordering::Release);
        }
        if let Some((config, userspace_filter)) = observed_config
            && let Some(observer) = &self.configuration_observer
        {
            observer(config, userspace_filter).map_err(|error| node_action_error(&error))?;
        }
        serde_json::to_vec(&result).map_err(|_| PluginError::Rejected)
    }
}

/// Whether this node installs and enforces the subnet routes it receives (D197 M3), so the coordinator may
/// send them: a Linux node on the default `GotaTun` engine, whose packet filter polices routed and forwarded
/// flows at the TUN edge (D164, D384), and every Mac. The kernel `WireGuard` fallback (D346) answers like an
/// older node: it gets no networks, and its kernel table keeps refusing all forwarding.
#[cfg(target_os = "linux")]
fn understands_routes(node: &Node) -> bool {
    node.engine_selection().engine == crate::node::EngineKind::GotaTun
}

/// A Mac is a client of subnet routes (#580): its `GotaTun` device routes the networks it may reach into its
/// utun (root mode itself, user mode through the helper), and the shared packet filter polices the routed
/// flows. It never serves networks, so its forwarding switch stays off.
#[cfg(target_os = "macos")]
const fn understands_routes(_node: &Node) -> bool {
    true
}

/// The networks this node advertises, as the coordinator's probe reads them. A node that cannot read its
/// list answers with none rather than an old one: nothing is routed without the node's current word.
#[cfg(target_os = "linux")]
fn advertised_routes(node: &Node) -> Vec<crate::policy::networks::Network> {
    node.advertised_routes()
        .map(|networks| networks.into_iter().collect())
        .unwrap_or_default()
}

/// A Mac is a client of subnet routes only; it advertises none.
#[cfg(target_os = "macos")]
fn advertised_routes(_node: &Node) -> Vec<crate::policy::networks::Network> {
    Vec::new()
}

/// Add (`add`) or remove networks from the advertised list; removing none removes all. Returns whether the
/// list changed, so the coordinator is told (`mesh.changed`) only when there is news.
#[cfg(target_os = "linux")]
fn change_advertised(
    node: &mut Node,
    networks: Vec<crate::policy::networks::Network>,
    add: bool,
) -> Result<bool, &'static str> {
    if add && !understands_routes(node) {
        return Err(
            "Subnet routes need the GotaTun mesh engine, the default; this machine runs kernel WireGuard.",
        );
    }
    let before = node
        .advertised_routes()
        .map_err(|_| "The advertised networks could not be read from this machine's mesh state.")?;
    let mut after = before.clone();
    if add {
        after.extend(networks);
    } else if networks.is_empty() {
        after.clear();
    } else {
        for network in &networks {
            after.remove(network);
        }
    }
    if after.len() > MAX_ADVERTISED_NETWORKS {
        return Err("A machine advertises at most 64 networks.");
    }
    if add
        && after
            .iter()
            .any(|a| after.iter().any(|b| b != a && b.overlaps(*a)))
    {
        return Err(
            "A new network overlaps one this machine already advertises; withdraw the old one first.",
        );
    }
    if after == before {
        return Ok(false);
    }
    node.set_advertised_routes(&after)
        .map_err(|_| "The advertised networks could not be saved; run the command as root.")?;
    Ok(true)
}

/// Subnet routers run on Linux only in this slice (D197 M3).
#[cfg(target_os = "macos")]
fn change_advertised(
    _node: &mut Node,
    _networks: Vec<crate::policy::networks::Network>,
    _add: bool,
) -> Result<bool, &'static str> {
    Err("This Mac can use subnet routes but cannot offer networks to the mesh.")
}

/// Whether the route to a network behind a router peer is installed on this node, and why not.
fn network_route_state(
    node: &Node,
    network: crate::policy::networks::Network,
) -> serde_json::Value {
    node.network_route_state(network)
}

/// Whether this Linux node forwards for the networks it serves.
#[cfg(target_os = "linux")]
fn forwarding_state(node: &Node) -> serde_json::Value {
    node.forwarding_state()
}

/// A Mac never routes for the mesh in this slice.
#[cfg(target_os = "macos")]
fn forwarding_state(_node: &Node) -> serde_json::Value {
    json!({"state": "idle"})
}

/// What `mesh routes` shows: the advertised list, the approved networks this node serves (and to how many
/// peers), and the networks it reaches through other machines, with whether each route is installed.
fn routes_view(node: &Node) -> serde_json::Value {
    use std::collections::BTreeMap;
    let mut serving: BTreeMap<String, (usize, bool)> = BTreeMap::new();
    let mut reachable = Vec::new();
    if let Some(config) = node.config() {
        for (peer_id, policy) in &config.peers {
            for served in &policy.networks.served {
                let entry = serving
                    .entry(served.network.to_string())
                    .or_insert((0, !served.keep_source));
                entry.0 += 1;
            }
            for through in &policy.networks.through {
                #[cfg(feature = "mesh-dns")]
                let name = config.peer_names.get(peer_id).cloned();
                #[cfg(not(feature = "mesh-dns"))]
                let name: Option<String> = None;
                reachable.push(json!({
                    "network": through.network,
                    "via": name,
                    "via_node": peer_id,
                    "access": policy_summary(&through.outbound),
                    "installed": network_route_state(node, through.network),
                }));
            }
        }
    }
    let serving: Vec<_> = serving
        .into_iter()
        .map(|(network, (peers, masquerade))| {
            json!({"network": network, "peers": peers, "masquerade": masquerade})
        })
        .collect();
    json!({
        "advertised": advertised_routes(node),
        "serving": serving,
        "forwarding": forwarding_state(node),
        "reachable": reachable,
    })
}

/// Whether this node runs IPv4-only because IPv6 is off on its mesh link (#578, J1142).
#[cfg(target_os = "linux")]
fn ipv4_only(node: &Node) -> bool {
    node.ipv4_only()
}

/// The Mac node installs the mesh's IPv6 address on its own interface, which has no IPv6-off switch.
#[cfg(target_os = "macos")]
fn ipv4_only(_node: &Node) -> bool {
    false
}

/// Whether this node runs `GotaTun` with the second socket on, so peers may send it marks (#260, J1211).
fn side_port(node: &Node) -> bool {
    node.side_socket()
}

/// The Linux `GotaTun` engine's health for the status; null under kernel `WireGuard`.
#[cfg(target_os = "linux")]
fn engine_health(node: &Node) -> serde_json::Value {
    json!(node.engine_health())
}

/// The Mac node does not report engine health yet.
#[cfg(target_os = "macos")]
fn engine_health(_node: &Node) -> serde_json::Value {
    serde_json::Value::Null
}

/// The engine this node runs and why (D346).
#[cfg(target_os = "linux")]
fn engine_selection(node: &Node) -> serde_json::Value {
    json!(node.engine_selection())
}

/// The Mac node has one engine, `GotaTun`, and no choice to make.
#[cfg(target_os = "macos")]
fn engine_selection(_node: &Node) -> serde_json::Value {
    json!({"engine":"gotatun","reason":"default"})
}

/// Whether this node's engine walks an ordered candidate list (#515), and so may tell the
/// coordinator it accepts one: only `GotaTun`. Kernel `WireGuard` installs just the first
/// candidate, so it answers like an older node and keeps getting one public address. That node
/// also reports no LAN addresses; its peers still reach it through the reflexive address.
#[cfg(target_os = "linux")]
fn walks_candidates(node: &Node) -> bool {
    node.engine_selection().engine == crate::node::EngineKind::GotaTun
}

/// The Mac node runs `GotaTun` and walks its candidate lists with the same bookkeeping as Linux
/// (#515, J704), so it always accepts a list and reports its LAN addresses.
#[cfg(target_os = "macos")]
const fn walks_candidates(_node: &Node) -> bool {
    true
}

/// Name the packet path that actually enforces this node's access rules.
#[cfg(target_os = "linux")]
fn access_enforcement(node: &Node) -> &'static str {
    match node.engine_selection().engine {
        crate::gotatun_node::EngineKind::GotaTun => "userspace",
        crate::gotatun_node::EngineKind::Kernel => "kernel",
    }
}

/// macOS always enforces access rules at the userspace `GotaTun` TUN boundary.
#[cfg(target_os = "macos")]
fn access_enforcement(_node: &Node) -> &'static str {
    crate::macos_node::ENFORCEMENT
}

/// Serialize the optional Linux-only kernel guard, or report no separate guard on macOS.
#[cfg(target_os = "linux")]
fn kernel_guard_status(node: &Node) -> serde_json::Value {
    json!(node.kernel_guard_status())
}

/// macOS applies the filter in userspace and has no separate kernel guard state.
#[cfg(target_os = "macos")]
fn kernel_guard_status(_node: &Node) -> serde_json::Value {
    serde_json::Value::Null
}

/// Both node types read the counters of the engine they run.
fn read_counters(node: &mut Node) -> Result<Counters, PluginError> {
    node.counters().map_err(|error| node_action_error(&error))
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
            let (config, userspace_filter) = {
                let mut owner = self.owner.lock().map_err(|_| "Mesh owner unavailable.")?;
                let node = owner
                    .node()
                    .map_err(|error| plugin_action_message(error, "Mesh state unavailable."))?;
                if enabled {
                    node.up()
                        .map_err(|error| node_action_message(&error, "Mesh start failed."))?;
                } else {
                    node.down()
                        .map_err(|error| node_action_message(&error, "Mesh stop failed."))?;
                }
                (
                    node.config().cloned(),
                    access_enforcement(node) == "userspace",
                )
            };
            if let Some(observer) = &self.configuration_observer {
                observer(config, userspace_filter).map_err(|error| {
                    node_action_message(&error, "Mesh publication routes could not be updated.")
                })?;
            }
            self.changed.store(true, Ordering::Release);
            Ok(())
        })
    }
}

/// Node action checks that need a Linux kernel or network namespace.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::expect_used)]
    /// Embedded infraternal agents have no tracing subscriber; repeated restore failures still reach stderr once.
    #[test]
    #[cfg(target_os = "linux")]
    fn restore_failure_reaches_stderr_without_a_tracing_subscriber() {
        const CHILD: &str = "INFRATERNAL_MESH_RESTORE_DIAGNOSTIC_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let directory =
                std::env::temp_dir().join(format!("missing-mesh-{}", std::process::id()));
            let mut plugin = MeshNodePlugin::new(&directory);
            for _ in 0..3 {
                assert!(plugin.call("mesh.identity", b"{}").is_err());
            }
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "node_actions::tests::restore_failure_reaches_stderr_without_a_tracing_subscriber",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("run diagnostic child");
        assert!(output.status.success());
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 diagnostic");
        assert_eq!(
            stderr
                .matches("Mesh node failed phase=restore kind=NotFound")
                .count(),
            1,
            "{stderr}"
        );
        assert!(
            !stderr.contains("missing-mesh-"),
            "paths do not enter diagnostics"
        );
    }
    use super::*;

    /// A refused configuration reaches stderr once per streak, with the error behind it (#578),
    /// and an applied one ends the streak so the next refusal is reported again.
    #[test]
    fn a_refused_configuration_is_reported_once_per_streak() {
        const CHILD: &str = "INFRATERNAL_MESH_CONFIGURE_DIAGNOSTIC_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let mut failed = false;
            let refusal = || Err(std::io::Error::from_raw_os_error(13));
            for _ in 0..3 {
                assert_eq!(
                    configure_result(refusal(), &mut failed),
                    Err(PluginError::Rejected)
                );
            }
            assert_eq!(configure_result(Ok(true), &mut failed), Ok(true));
            assert!(configure_result(refusal(), &mut failed).is_err());
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "node_actions::tests::a_refused_configuration_is_reported_once_per_streak",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("run diagnostic child");
        assert!(output.status.success());
        let stderr = String::from_utf8(output.stderr).expect("UTF-8 diagnostic");
        assert_eq!(
            stderr
                .matches("Mesh configuration was refused: Permission denied (os error 13) (kind=PermissionDenied).")
                .count(),
            2,
            "{stderr}"
        );
    }

    /// `mesh.status` exposes only the live public identity needed to verify persistence.
    #[test]
    fn status_reports_its_public_mesh_key_without_private_material() {
        use crate::{dataplane::Identity, policy::model::PublicKey};

        let mut plugin = MeshNodePlugin::from_node(Node::with_identity_for_action_test(Identity {
            public_key: PublicKey([7; 32]),
            port: 44000,
            compact_access: false,
            #[cfg(feature = "mesh-dns")]
            dns_names: false,
            key_rotation: false,
            authority_epoch: false,
            rotation_continuity: false,
        }));
        let status: serde_json::Value =
            serde_json::from_slice(&plugin.call("mesh.status", b"{}").expect("mesh status"))
                .expect("status JSON");

        assert_eq!(status["public_key"], json!(vec![7; 32]));
        assert!(status.get("private_key").is_none());
    }

    /// An inactive rootless mesh can be read without kernel setup or persisted Mesh state.
    ///
    /// Opening the store creates only its private writer lock, which lets cleanup serialize with
    /// migration; no key, public snapshot, or engine record is written.
    #[test]
    fn rootless_owner_can_read_an_inactive_mesh_without_kernel_setup() {
        assert!(
            !nix::unistd::Uid::effective().is_root(),
            "run as an ordinary account"
        );
        let directory = crate::node_state::tests::Directory::new();
        let mut plugin = MeshNodePlugin::new(&directory.0);
        let peers: serde_json::Value =
            serde_json::from_slice(&plugin.call("mesh.peers", b"{}").expect("rootless peers"))
                .expect("peer JSON");
        assert_eq!(peers["peers"], json!([]));
        assert_eq!(peers["version"], serde_json::Value::Null);
        let status: serde_json::Value =
            serde_json::from_slice(&plugin.call("mesh.status", b"{}").expect("rootless status"))
                .expect("status JSON");
        assert_eq!(status["state"], "Off");
        let entries = std::fs::read_dir(&directory.0)
            .expect("state")
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()
            .expect("state entries");
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from(".mesh-store-write.lock")]
        );
    }

    /// Inactive rootless inspection must not conceal an unsafe retained ownership record.
    #[test]
    fn rootless_mesh_reads_refuse_an_unsafe_retained_owner() {
        use std::os::unix::fs::symlink;
        let directory = crate::node_state::tests::Directory::new();
        let unrelated = directory.0.join("unrelated");
        std::fs::write(&unrelated, b"keep").expect("unrelated file");
        symlink(&unrelated, directory.0.join("mesh-interface.json")).expect("unsafe owner");
        let mut plugin = MeshNodePlugin::new(&directory.0);
        assert!(plugin.call("mesh.peers", b"{}").is_err());
        assert_eq!(std::fs::read(&unrelated).expect("preserved file"), b"keep");
    }

    /// Required nft failures keep their own reason through mesh action mapping, whether nft is
    /// missing everywhere or was found (here in the Nix store) and then failed.
    #[test]
    fn required_nft_failure_is_not_reduced_to_generic_rejection() {
        for message in [
            "nft was not found as a root-owned executable in /usr/sbin, /usr/bin",
            "nft at /nix/store/aaaa-nftables-1.1.7/bin/nft could not run: denied",
        ] {
            let error = std::io::Error::new(std::io::ErrorKind::NotFound, message);
            assert_eq!(
                node_action_error(&error),
                PluginError::KernelFirewallUnavailable,
                "{message}"
            );
        }
        let other = std::io::Error::other("iptables-nft at /usr/sbin/iptables-nft could not run");
        assert_eq!(node_action_error(&other), PluginError::Rejected);
    }

    /// #382 P2 (J418): after a server rollback (D295) to a release without authority epochs, a
    /// node that saw an epoch adopts the epoch-less full snapshot instead of waiting forever.
    #[test]
    #[ignore = "Run inside a dedicated kernel namespace with CAP_NET_ADMIN."]
    fn epochless_snapshot_after_an_epoch_is_adopted() {
        use crate::{
            dataplane::{DefaultPolicy, Identity},
            policy::model::{Addresses, NodeId},
        };

        let mut plugin = MeshNodePlugin::default();
        let identity: Identity =
            serde_json::from_slice(&plugin.call("mesh.up", b"{}").expect("mesh up"))
                .expect("public identity");
        let accepted = Chunk {
            access_updates: Vec::new(),
            authority_epoch: Some("00000000-0000-4000-8000-000000000001".to_owned()),
            rotation_operation: None,
            server: Some(NodeId(2)),
            local_key: Some(identity.public_key),
            node: NodeId(1),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            from_version: None,
            version: 1,
            index: 0,
            last: true,
            addresses: Addresses {
                ipv4: "10.254.0.1".parse().expect("IPv4"),
                ipv6: "fd01::1".parse().expect("IPv6"),
            },
            default_policy: DefaultPolicy::Deny,
            exposure: None,
            upserted: std::collections::BTreeMap::new(),
            merged: std::collections::BTreeMap::new(),
            removed: Vec::new(),
            #[cfg(feature = "mesh-dns")]
            peer_names: std::collections::BTreeMap::new(),
            #[cfg(feature = "mesh-dns")]
            removed_peer_names: Vec::new(),
        };
        plugin
            .call(
                "mesh.configure",
                &serde_json::to_vec(&accepted).expect("accepted snapshot"),
            )
            .expect("accept epoch snapshot");
        let mut rolled_back = accepted;
        rolled_back.authority_epoch = None;
        rolled_back.version = 2;
        plugin
            .call(
                "mesh.configure",
                &serde_json::to_vec(&rolled_back).expect("rolled-back snapshot"),
            )
            .expect("a rolled-back server's full snapshot is adopted");

        let status: serde_json::Value =
            serde_json::from_slice(&plugin.call("mesh.status", b"{}").expect("mesh status"))
                .expect("status JSON");
        assert_ne!(
            status["state"], "Waiting",
            "the node is not left waiting: {status}"
        );
        plugin.call("mesh.down", b"{}").expect("mesh down");
    }

    /// Keeps kernel setup, staged intent and explicit cleanup in one namespace owner.
    #[test]
    #[ignore = "Run inside a dedicated kernel namespace with CAP_NET_ADMIN."]
    fn applied_server_route_and_observed_link_survive_only_explicit_component_up() {
        use crate::{
            dataplane::{DefaultPolicy, Peer, PeerPolicy},
            policy::{
                model::{Addresses, NodeId},
                rules::TrafficPolicy,
            },
        };
        assert_eq!(nix::unistd::geteuid().as_raw(), 0, "namespace owner");
        // The privileged runner starts a new PID namespace, where /proc/1 is
        // this sandbox's init process. Compare against its saved outer netns.
        let outer_network_namespace = std::env::var_os("INFRATERNAL_VERIFY_OUTER_NETNS")
            .map_or_else(
                || std::fs::read_link("/proc/1/ns/net").expect("host namespace"),
                std::path::PathBuf::from,
            );
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").expect("own namespace"),
            outer_network_namespace,
            "kernel fixture requires a private network namespace"
        );
        let mut plugin = MeshNodePlugin::default();
        assert!(plugin.preferred_server().is_none());
        plugin.call("mesh.up", b"{}").expect("up");
        let (_, key) = crate::wireguard::Key::generate().expect("public peer fixture");
        let mut chunk = Chunk {
            access_updates: Vec::new(),
            authority_epoch: None,
            rotation_operation: None,
            server: Some(NodeId(2)),
            local_key: None,
            node: NodeId(1),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
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
                        candidates: Vec::new(),
                        ipv4_only: false,
                        side_port: false,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                    networks: crate::dataplane::PeerNetworks::default(),
                },
            )]),
            merged: std::collections::BTreeMap::new(),
            removed: Vec::new(),
            #[cfg(feature = "mesh-dns")]
            peer_names: std::collections::BTreeMap::new(),
            #[cfg(feature = "mesh-dns")]
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
        assert_eq!(
            status["udp_port"], 10_254,
            "mesh status reports the actual listener port"
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

    /// `mesh.peers` reads its counters from the `GotaTun` engine when that is the selected engine.
    #[test]
    #[ignore = "Run inside a disposable network namespace with CAP_NET_ADMIN."]
    fn mesh_peers_action_reads_counters_from_the_selected_gotatun_engine() {
        use crate::{
            dataplane::{DefaultPolicy, Peer, PeerPolicy},
            node::EngineKind,
            policy::{
                model::{Addresses, NodeId},
                rules::TrafficPolicy,
            },
            wireguard::{Device, Key},
        };
        use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

        let directory = std::env::temp_dir().join(format!("gotatun-peers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).expect("private state directory");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("restrict state directory");
        let mut plugin = MeshNodePlugin::new(&directory);
        // GotaTun is selectable but not the default, so select it here, before the first action
        // would restore the node with the default engine.
        plugin.owner.lock().expect("node owner").node = Some(
            Node::restore_with_engine(&directory, EngineKind::GotaTun)
                .expect("restore with GotaTun"),
        );
        let (_, peer_key) = Key::generate().expect("peer key");
        let chunk = Chunk {
            authority_epoch: None,
            rotation_operation: None,
            local_key: None,
            server: Some(NodeId(1)),
            node: NodeId(2),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            from_version: None,
            version: 1,
            index: 0,
            last: true,
            addresses: Addresses {
                ipv4: "10.254.0.2".parse().expect("local IPv4"),
                ipv6: "fd01::2".parse().expect("local IPv6"),
            },
            default_policy: DefaultPolicy::Deny,
            exposure: None,
            upserted: BTreeMap::from([(
                NodeId(1),
                PeerPolicy {
                    peer: Peer {
                        key: peer_key,
                        previous_key: None,
                        previous_active: false,
                        addresses: Addresses {
                            ipv4: "10.254.0.1".parse().expect("peer IPv4"),
                            ipv6: "fd01::1".parse().expect("peer IPv6"),
                        },
                        endpoint: None,
                        candidates: Vec::new(),
                        ipv4_only: false,
                        side_port: false,
                    },
                    inbound: TrafficPolicy::All,
                    outbound: TrafficPolicy::All,
                    access_ssh: None,
                    networks: crate::dataplane::PeerNetworks::default(),
                },
            )]),
            merged: BTreeMap::new(),
            removed: Vec::new(),
            #[cfg(feature = "mesh-dns")]
            peer_names: BTreeMap::new(),
            #[cfg(feature = "mesh-dns")]
            removed_peer_names: Vec::new(),
            access_updates: Vec::new(),
        };

        let result = (|| {
            plugin.call("mesh.up", b"{}")?;
            assert!(Device::owned_tun().expect("selected GotaTun TUN"));
            plugin.call(
                "mesh.configure",
                &serde_json::to_vec(&chunk).expect("chunk"),
            )?;
            let page = plugin.call("mesh.peers", br#"{"cursor":null,"presence":false}"#)?;
            let page: serde_json::Value = serde_json::from_slice(&page).expect("peer page");
            assert_eq!(page["peers"].as_array().expect("rows").len(), 1);
            assert_eq!(page["peers"][0]["counters"]["sent_bytes"], 0);
            Ok::<_, PluginError>(())
        })();
        let stopped = plugin.call("mesh.down", b"{}");
        let _ = std::fs::remove_dir_all(&directory);
        assert!(
            result.is_ok(),
            "mesh.peers could not read GotaTun counters: {result:?}"
        );
        assert!(stopped.is_ok(), "mesh cleanup failed: {stopped:?}");
    }

    /// D346: the status names the engine and why: `GotaTun` by default, and an engine chosen in
    /// code as chosen. Built from fresh nodes, so the host's links and packet filter play no part.
    #[test]
    fn status_reports_the_default_engine_when_nothing_was_chosen() {
        assert_eq!(
            engine_selection(&Node::default()),
            serde_json::json!({"engine":"gotatun","reason":"default"})
        );
        assert_eq!(
            engine_selection(&Node::default().with_engine(crate::node::EngineKind::Kernel)),
            serde_json::json!({"engine":"kernel","reason":"chosen"})
        );
    }

    /// J585 F5 (#515): only an engine that walks candidates may say it accepts them. A node that
    /// installs just the first candidate would aim at a LAN address on another network when two
    /// sites share a public address, and never try the reflexive address an older node gets.
    #[test]
    fn only_the_walking_engine_offers_candidates() {
        assert!(walks_candidates(&Node::default()), "GotaTun walks");
        assert!(
            !walks_candidates(&Node::default().with_engine(crate::node::EngineKind::Kernel)),
            "kernel WireGuard installs only the first candidate"
        );
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

    /// `mesh.status` exposes the protections the optional Linux guard has not installed.
    #[cfg(target_os = "linux")]
    #[test]
    fn mesh_status_reports_optional_kernel_guard_state() {
        let mut plugin = MeshNodePlugin::default();
        let status: serde_json::Value =
            serde_json::from_slice(&plugin.call("mesh.status", b"{}").expect("mesh status"))
                .expect("status JSON");

        assert_eq!(status["enforcement"], "userspace");
        assert_eq!(status["kernel_guard"]["state"], "pending");
        assert_eq!(
            status["kernel_guard"]["missing"],
            serde_json::json!([
                "mesh-address anti-spoofing on non-mesh interfaces",
                "underlay delivery to mesh addresses",
                "forwarding drops",
                "public TCP/80 and TCP/443 gate"
            ])
        );
    }
    /// D386 lets mesh cleanup remove a recreated table in the product-owned namespace.
    ///
    /// It runs on the kernel `WireGuard` engine, where nft holds the full peer policy (D346), so
    /// the recreated table is the one the grants live in.
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn mesh_down_removes_a_recreated_product_table_and_keeps_explicit_off() {
        use crate::{
            dataplane::DefaultPolicy,
            policy::model::{Addresses, NodeId},
        };
        use std::{
            io::Write as _,
            process::{Command, Stdio},
        };
        let _nft_override = crate::host_firewall::NftTestPathOverride::with_fixed_nft_fixture();
        let nft = crate::host_firewall::discover_nft(None).expect("fixed-path nft fixture");
        let mut plugin = MeshNodePlugin::from_node(
            Node::default().with_engine(crate::gotatun_node::EngineKind::Kernel),
        );
        plugin.call("mesh.up", b"{}").expect("start");
        let chunk = Chunk {
            access_updates: Vec::new(),
            authority_epoch: None,
            rotation_operation: None,
            local_key: None,
            server: None,
            node: NodeId(1),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
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
            #[cfg(feature = "mesh-dns")]
            peer_names: std::collections::BTreeMap::new(),
            #[cfg(feature = "mesh-dns")]
            removed_peer_names: Vec::new(),
        };
        plugin
            .call(
                "mesh.configure",
                &serde_json::to_vec(&chunk).expect("chunk"),
            )
            .expect("configure");
        let mut child = Command::new(&nft)
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
        let down: serde_json::Value =
            serde_json::from_slice(&plugin.call("mesh.down", b"{}").expect("mesh down"))
                .expect("JSON");
        assert_eq!(down["state"], "Off");
        let status: serde_json::Value =
            serde_json::from_slice(&plugin.call("mesh.status", b"{}").expect("status"))
                .expect("JSON");
        assert_eq!(status["state"], "Off");
        assert!(
            !Command::new(&nft)
                .args(["-j", "list", "table", "inet", "infraternal_mesh"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("inspect product table")
                .success(),
            "D386 cleanup removes the product-owned table even without its old marker"
        );
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

/// The identity reply keeps its legacy shape unless a capability is requested.
#[cfg(all(test, target_os = "linux"))]
mod identity_upgrade_tests {
    #![allow(clippy::expect_used)]
    /// An ordinary identity request gets the reply older coordinators read.
    #[test]
    fn ordinary_identity_reply_retains_the_legacy_shape() {
        let identity = crate::dataplane::Identity {
            public_key: crate::policy::model::PublicKey([1; 32]),
            port: 44000,
            compact_access: true,
            #[cfg(feature = "mesh-dns")]
            dns_names: true,
            key_rotation: true,
            authority_epoch: true,
            rotation_continuity: true,
        };
        let legacy = serde_json::json!(super::identity_response(
            Some(identity.clone()),
            super::IdentityProbe::default(),
            vec!["10.1.0.2:44000".parse().expect("LAN fixture")],
            false,
            false,
        ));
        assert_eq!(legacy.as_object().map(serde_json::Map::len), Some(2));
        assert_eq!(legacy["port"], 44000);
        assert!(legacy.get("compact_access").is_none());
        let negotiated = serde_json::json!(super::identity_response(
            Some(identity.clone()),
            super::IdentityProbe {
                compact_access: true,
                #[cfg(feature = "mesh-dns")]
                dns_names: true,
                key_rotation: true,
                authority_epoch: true,
                rotation_continuity: true,
                candidates: false,
                ipv6_state: false,
                routes: false,
                side_socket: false,
            },
            Vec::new(),
            false,
            false,
        ));
        assert_eq!(negotiated["compact_access"], true);
        assert_eq!(negotiated["key_rotation"], true);
        assert_eq!(negotiated["authority_epoch"], true);
        assert_eq!(negotiated["rotation_continuity"], true);
        #[cfg(feature = "mesh-dns")]
        assert_eq!(negotiated["dns_names"], true);
        let compact_only = serde_json::json!(super::identity_response(
            Some(identity),
            super::IdentityProbe {
                compact_access: true,
                ..super::IdentityProbe::default()
            },
            Vec::new(),
            false,
            false,
        ));
        assert_eq!(compact_only["compact_access"], true);
        assert!(compact_only.get("key_rotation").is_none());
        assert!(compact_only.get("authority_epoch").is_none());
        assert!(compact_only.get("rotation_continuity").is_none());
        #[cfg(feature = "mesh-dns")]
        assert!(compact_only.get("dns_names").is_none());
    }

    /// A coordinator that asks for candidates learns that this node takes them, and its LAN
    /// addresses; nobody else sees either field (#515).
    #[test]
    fn candidates_and_lan_addresses_are_sent_only_when_asked() {
        let identity = crate::dataplane::Identity {
            public_key: crate::policy::model::PublicKey([1; 32]),
            port: 10254,
            compact_access: false,
            #[cfg(feature = "mesh-dns")]
            dns_names: false,
            key_rotation: false,
            authority_epoch: false,
            rotation_continuity: false,
        };
        let lan: Vec<std::net::SocketAddr> = vec!["10.9.0.3:10254".parse().expect("LAN fixture")];
        let asked = serde_json::json!(super::identity_response(
            Some(identity.clone()),
            super::IdentityProbe {
                candidates: true,
                ..super::IdentityProbe::default()
            },
            lan.clone(),
            false,
            false,
        ));
        assert_eq!(asked["candidates"], true);
        assert_eq!(asked["lan"], serde_json::json!(["10.9.0.3:10254"]));
        let parsed: super::IdentityProbe =
            super::parse(br#"{"candidates":true}"#).expect("candidate probe");
        assert!(parsed.candidates);
        let plain = serde_json::json!(super::identity_response(
            Some(identity),
            super::IdentityProbe::default(),
            lan,
            true,
            false,
        ));
        assert!(plain.get("candidates").is_none());
        assert!(plain.get("lan").is_none());
        assert!(
            plain.get("ipv4_only").is_none() && plain.get("ipv6_state").is_none(),
            "a caller that did not ask never sees the IPv6 fields: {plain}"
        );
    }

    /// A coordinator that asks learns that this node understands the side mark and whether it takes
    /// marked datagrams (#260, J1211); nobody else sees either field, and a node that does not run the
    /// side-mark receive rule (kernel engine, switch off) says so.
    #[test]
    fn the_side_socket_capability_is_sent_only_when_asked() {
        let identity = crate::dataplane::Identity {
            public_key: crate::policy::model::PublicKey([1; 32]),
            port: 10254,
            compact_access: false,
            #[cfg(feature = "mesh-dns")]
            dns_names: false,
            key_rotation: false,
            authority_epoch: false,
            rotation_continuity: false,
        };
        let probe: super::IdentityProbe =
            super::parse(br#"{"side_socket":true}"#).expect("side socket probe");
        assert!(probe.side_socket);
        let reply = |asked, takes_marks| {
            serde_json::json!(super::identity_response(
                Some(identity.clone()),
                super::IdentityProbe {
                    side_socket: asked,
                    ..super::IdentityProbe::default()
                },
                Vec::new(),
                false,
                takes_marks,
            ))
        };
        let capable = reply(true, true);
        assert_eq!(capable["side_socket"], true);
        assert_eq!(capable["side_port"], true);
        assert_eq!(
            crate::node_coordination::parse_side_socket(capable.to_string().as_bytes()),
            Some(true)
        );
        let incapable = reply(true, false);
        assert_eq!(incapable["side_socket"], true);
        assert!(incapable.get("side_port").is_none());
        assert_eq!(
            crate::node_coordination::parse_side_socket(incapable.to_string().as_bytes()),
            Some(false)
        );
        let unasked = reply(false, true);
        assert!(
            unasked.get("side_socket").is_none() && unasked.get("side_port").is_none(),
            "a caller that did not ask never sees the side-socket fields: {unasked}"
        );
        // An older node's reply has neither field: it does not report.
        assert_eq!(
            crate::node_coordination::parse_side_socket(br#"{"public_key":[1],"port":1}"#),
            None
        );
    }

    /// A coordinator that asks learns that this node reports its IPv6 state, and whether IPv6 is off
    /// (#578, J1142); a dual-stack node says only that it reports.
    #[test]
    fn the_ipv6_state_is_sent_only_when_asked() {
        let identity = crate::dataplane::Identity {
            public_key: crate::policy::model::PublicKey([1; 32]),
            port: 10254,
            compact_access: false,
            #[cfg(feature = "mesh-dns")]
            dns_names: false,
            key_rotation: false,
            authority_epoch: false,
            rotation_continuity: false,
        };
        let probe: super::IdentityProbe =
            super::parse(br#"{"ipv6_state":true}"#).expect("IPv6 state probe");
        assert!(probe.ipv6_state);
        let reply = |ipv4_only| {
            serde_json::json!(super::identity_response(
                Some(identity.clone()),
                super::IdentityProbe {
                    ipv6_state: true,
                    ..super::IdentityProbe::default()
                },
                Vec::new(),
                ipv4_only,
                false,
            ))
        };
        let off = reply(true);
        assert_eq!(off["ipv6_state"], true);
        assert_eq!(off["ipv4_only"], true);
        assert_eq!(
            crate::node_coordination::parse_ipv6_state(off.to_string().as_bytes()),
            Some(true)
        );
        let on = reply(false);
        assert_eq!(on["ipv6_state"], true);
        assert!(on.get("ipv4_only").is_none());
        assert_eq!(
            crate::node_coordination::parse_ipv6_state(on.to_string().as_bytes()),
            Some(false)
        );
        // An older node's reply has neither field: it does not report.
        assert_eq!(
            crate::node_coordination::parse_ipv6_state(br#"{"public_key":[1],"port":1}"#),
            None
        );
    }
}

/// `mesh.peers` paging and its cost (#236).
#[cfg(all(test, target_os = "linux"))]
mod peer_page_tests {
    #![allow(clippy::expect_used)]
    use super::{Counters, Cursor, peer_page};
    /// A configuration with `peers` peers, for paging tests.
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
            authority_epoch: None,
            rotation_operation: None,
            local_key: None,
            server: Some(NodeId(1)),
            node: NodeId(1),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
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
                                candidates: Vec::new(),
                                ipv4_only: false,
                                side_port: false,
                            },
                            inbound: TrafficPolicy::All,
                            outbound: TrafficPolicy::All,
                            access_ssh: None,
                            networks: crate::dataplane::PeerNetworks::default(),
                        },
                    )
                })
                .collect(),
            #[cfg(feature = "mesh-dns")]
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

/// The Mac node's answer to the coordinator's candidate offer.
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::{Node, walks_candidates};

    /// J699 P2-3 (#515): the Mac node walks candidate lists like Linux, so it accepts them and
    /// reports its LAN addresses. Before J704 it answered like an older node and got one address.
    #[test]
    fn the_mac_node_offers_candidates() {
        assert!(walks_candidates(&Node::default()));
    }
}
