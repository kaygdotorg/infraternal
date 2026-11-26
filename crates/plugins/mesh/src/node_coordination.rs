//! Issues public configurations over authenticated node channels and committed Access changes [163,166,169,198].
use crate::{
    api::{MeshApiError, MeshService},
    configuration,
    dataplane::Identity,
    store::{Snapshot, Store},
};
use infraternal_plugin_api::node_channel::NodeChannel;
use std::sync::Arc;
type ServerListener = Option<(
    std::net::IpAddr,
    Box<dyn infraternal_plugin_api::server_path::ListenerLease>,
)>;

/// Keep a working listener until its replacement is actually bound.
async fn update_listener(
    channel: &dyn NodeChannel,
    address: std::net::IpAddr,
    listener: &mut ServerListener,
) {
    if listener
        .as_ref()
        .is_none_or(|(current, _)| *current != address)
        && let Ok(Some(lease)) = channel.listen_server(address).await
    {
        *listener = Some((address, lease));
    }
}
/// How long a worker waits before it probes again after its attach was refused for unknown rotation support while
/// a rotation is open (J273 P3-2). Each probe is a few small calls on an authenticated channel.
const UNKNOWN_SUPPORT_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

/// The largest peer control reply any mesh coordinator parser accepts.
const MAX_COORDINATION_REPLY_BYTES: usize = infraternal_plugin_api::channel::MAX_CONTROL_JSON;

/// Decode one bounded reply from a node, before JSON can allocate from it.
fn parse_coordination_reply<T: serde::de::DeserializeOwned>(reply: &[u8]) -> Option<T> {
    if reply.len() > MAX_COORDINATION_REPLY_BYTES {
        return None;
    }
    serde_json::from_slice(reply).ok()
}

/// Deserialize at most `maximum` sequence items, without reserving from an untrusted size hint.
fn deserialize_bounded_sequence<'de, D, T>(
    deserializer: D,
    maximum: usize,
) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    /// The private visitor that stops a peer list at its protocol count limit.
    struct BoundedSequence<T> {
        maximum: usize,
        marker: std::marker::PhantomData<T>,
    }

    impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for BoundedSequence<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "a sequence with at most {} items", self.maximum)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(self.maximum);
            let mut items = Vec::with_capacity(capacity);
            while items.len() < self.maximum {
                let Some(item) = sequence.next_element()? else {
                    return Ok(items);
                };
                items.push(item);
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::invalid_length(
                    self.maximum.saturating_add(1),
                    &self,
                ));
            }
            Ok(items)
        }
    }

    deserializer.deserialize_seq(BoundedSequence {
        maximum,
        marker: std::marker::PhantomData,
    })
}

/// Bound the coordinator's private LAN candidate list to one address per family.
fn deserialize_lan<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<std::net::SocketAddr>, D::Error> {
    deserialize_bounded_sequence(deserializer, crate::candidates::MAX_LAN)
}

/// Bound one node's advertised routes before building the deserialized vector.
fn deserialize_advertised<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<crate::policy::networks::Network>, D::Error> {
    deserialize_bounded_sequence(deserializer, MAX_ADVERTISED_NETWORKS)
}

/// The authenticated identity and the additive capabilities proved for its reply.
struct IdentityProbe {
    /// The node identity and values returned by the successful request.
    identity: Identity,
    /// Whether the reply proves the node accepts key rotation fields.
    key_rotation_supported: Option<bool>,
    /// Whether the reply proves the node accepts authority epochs; `None` means probe ambiguity.
    authority_epoch_supported: Option<bool>,
}

/// Probe before advertising an extension. Strict older nodes reject the epoch field, then
/// answer the previous rotation probe or legacy request without receiving a new chunk shape.
/// Fallback replies keep epoch support unknown unless the full request was explicitly refused.
async fn read_identity(channel: &dyn NodeChannel) -> Option<IdentityProbe> {
    let (probe, without_epoch, before_rotation) = (
        br#"{"compact_access":true,"key_rotation":true,"authority_epoch":true}"#.as_slice(),
        br#"{"compact_access":true,"key_rotation":true}"#.as_slice(),
        br#"{"compact_access":true}"#.as_slice(),
    );
    let mut identity = probe_identity(
        |input| channel.call("mesh.identity", input),
        probe,
        without_epoch,
        before_rotation,
    )
    .await?;
    #[cfg(feature = "mesh-dns")]
    {
        identity.identity.dns_names = read_dns_names(channel).await;
    }
    // A timeout is not proof of an older receiver: withholding the view keeps an epoch
    // change from discarding a current receiver's journal during transient probe failure.
    identity.identity.rotation_continuity = match channel
        .call("mesh.identity", br#"{"rotation_continuity":true}"#.to_vec())
        .await
    {
        Ok(reply) => parse_identity(&reply)?.rotation_continuity,
        Err(infraternal_plugin_api::node_channel::CALL_REFUSED) => false,
        Err(_) => return None,
    };
    Some(identity)
}

/// Asks a node about direct-path candidates (#515, D391) on its own, the way DNS support is asked: a strict
/// older node refuses this probe alone and keeps its identity. `Some(lan)` when the node walks ordered candidate
/// lists, with the LAN addresses it reported; `None` for an older node or no answer.
async fn read_candidates(channel: &dyn NodeChannel) -> Option<Vec<std::net::SocketAddr>> {
    let reply = channel
        .call("mesh.identity", br#"{"candidates":true}"#.to_vec())
        .await
        .ok()?;
    parse_candidates(&reply)
}

/// Asks a node whether it reports its IPv6 state (#578, J1142), on its own like the other probes so a strict
/// older node refuses only this one and keeps its identity. `Some(ipv4_only)` when the node understands
/// `Peer::ipv4_only` and says whether IPv6 is off on its mesh link; `None` for an older node or no answer.
async fn read_ipv6_state(channel: &dyn NodeChannel) -> Option<bool> {
    let reply = channel
        .call("mesh.identity", br#"{"ipv6_state":true}"#.to_vec())
        .await
        .ok()?;
    parse_ipv6_state(&reply)
}

/// Asks a node whether it takes marked datagrams on its second UDP socket (#260, J1211), on its own like the
/// other probes so a strict older node refuses only this one and keeps its identity. `Some(takes_marks)` when
/// the node understands `Peer::side_port` and says whether it runs the side-mark receive rule with its second
/// socket on; `None` for an older node or no answer.
async fn read_side_socket(channel: &dyn NodeChannel) -> Option<bool> {
    let reply = channel
        .call("mesh.identity", br#"{"side_socket":true}"#.to_vec())
        .await
        .ok()?;
    parse_side_socket(&reply)
}

/// Asks a node which networks it advertises (D197 M3), on its own like the other probes so a strict older
/// node refuses only this one. `Some(networks)` when the node understands subnet routes, `None` otherwise.
async fn read_routes(channel: &dyn NodeChannel) -> Option<Vec<crate::policy::networks::Network>> {
    let reply = channel
        .call("mesh.identity", br#"{"routes":true}"#.to_vec())
        .await
        .ok()?;
    parse_routes(&reply)
}

/// The most networks one node may advertise. A LAN router has a handful; the bound keeps one node's
/// reply from growing every snapshot and the route table without limit.
pub const MAX_ADVERTISED_NETWORKS: usize = 64;

/// Reads the route fields of a `mesh.identity` reply to a `{"routes":true}` probe: `routes` says the node
/// understands subnet routes, `advertised` lists the networks it offers. A reply with a malformed network or
/// more than [`MAX_ADVERTISED_NETWORKS`] is treated as no answer, so nothing it says is recorded.
#[must_use]
pub fn parse_routes(reply: &[u8]) -> Option<Vec<crate::policy::networks::Network>> {
    /// The two fields this probe adds to the identity reply.
    #[derive(serde::Deserialize)]
    struct Reply {
        #[serde(default)]
        routes: bool,
        #[serde(default, deserialize_with = "deserialize_advertised")]
        advertised: Vec<crate::policy::networks::Network>,
    }
    let reply: Reply = parse_coordination_reply(reply)?;
    (reply.routes && reply.advertised.len() <= MAX_ADVERTISED_NETWORKS).then_some(reply.advertised)
}

/// Reads the side-socket fields of a `mesh.identity` reply to a `{"side_socket":true}` probe. The node's reply
/// carries `side_socket` when it understands the probe and `side_port` only while it takes marked datagrams.
#[must_use]
pub fn parse_side_socket(reply: &[u8]) -> Option<bool> {
    /// The two fields this probe adds to the identity reply.
    #[derive(serde::Deserialize)]
    struct Reply {
        #[serde(default)]
        side_socket: bool,
        #[serde(default)]
        side_port: bool,
    }
    let reply: Reply = parse_coordination_reply(reply)?;
    reply.side_socket.then_some(reply.side_port)
}

/// Reads the IPv6 fields of a `mesh.identity` reply to an `{"ipv6_state":true}` probe. The node's reply
/// carries `ipv6_state` when it understands the probe and `ipv4_only` only while IPv6 is off.
#[must_use]
pub fn parse_ipv6_state(reply: &[u8]) -> Option<bool> {
    /// The two fields this probe adds to the identity reply.
    #[derive(serde::Deserialize)]
    struct Reply {
        #[serde(default)]
        ipv6_state: bool,
        #[serde(default)]
        ipv4_only: bool,
    }
    let reply: Reply = parse_coordination_reply(reply)?;
    reply.ipv6_state.then_some(reply.ipv4_only)
}

/// Reads the candidate fields of a `mesh.identity` reply to a `{"candidates":true}` probe; the identity fields
/// it also carries are read elsewhere. The store keeps at most two private, sendable LAN addresses of what this
/// returns ([`crate::candidates::valid_lan`]).
#[must_use]
pub fn parse_candidates(reply: &[u8]) -> Option<Vec<std::net::SocketAddr>> {
    /// The two fields this probe adds to the identity reply.
    #[derive(serde::Deserialize)]
    struct Reply {
        #[serde(default)]
        candidates: bool,
        #[serde(default, deserialize_with = "deserialize_lan")]
        lan: Vec<std::net::SocketAddr>,
    }
    let reply: Reply = parse_coordination_reply(reply)?;
    reply.candidates.then_some(reply.lan)
}

/// Requests DNS support on its own so a strict pre-DNS node can reject it without losing identity.
#[cfg(feature = "mesh-dns")]
async fn read_dns_names(channel: &dyn NodeChannel) -> bool {
    channel
        .call("mesh.identity", br#"{"dns_names":true}"#.to_vec())
        .await
        .ok()
        .and_then(|reply| parse_identity(&reply))
        .is_some_and(|identity| identity.dns_names)
}

/// Classify the identity and capabilities proved by each compatible request shape (J262, D166, D352).
///
/// A strict receiver is first asked about authority epochs and rotation together. A full-probe
/// timeout may still allow a weaker request to recover identity, but it leaves epoch support unknown;
/// the worker withholds snapshots until a later full probe proves support or refusal.
async fn probe_identity<F, R>(
    call: F,
    probe: &[u8],
    without_epoch: &[u8],
    before_rotation: &[u8],
) -> Option<IdentityProbe>
where
    F: Fn(Vec<u8>) -> R,
    R: std::future::Future<Output = Result<Vec<u8>, &'static str>>,
{
    let mut epoch_refused = true;
    for _ in 0..2 {
        match call(probe.to_vec()).await {
            Ok(reply) => {
                return parse_identity(&reply).map(|identity| IdentityProbe {
                    key_rotation_supported: Some(identity.key_rotation),
                    authority_epoch_supported: Some(identity.authority_epoch),
                    identity,
                });
            }
            Err(error) if error == infraternal_plugin_api::node_channel::CALL_REFUSED => {}
            Err(_) => epoch_refused = false,
        }
    }
    let mut rotation_refused = true;
    for _ in 0..2 {
        match call(without_epoch.to_vec()).await {
            Ok(reply) => {
                return parse_identity(&reply).map(|identity| {
                    let key_rotation_supported = if epoch_refused {
                        Some(identity.key_rotation)
                    } else {
                        identity.key_rotation.then_some(true)
                    };
                    IdentityProbe {
                        identity,
                        key_rotation_supported,
                        authority_epoch_supported: epoch_refused.then_some(false),
                    }
                });
            }
            Err(error) if error == infraternal_plugin_api::node_channel::CALL_REFUSED => {}
            Err(_) => rotation_refused = false,
        }
    }
    match call(before_rotation.to_vec()).await {
        Ok(reply) => {
            return parse_identity(&reply).map(|identity| {
                let key_rotation_supported = if epoch_refused && rotation_refused {
                    Some(identity.key_rotation)
                } else {
                    identity.key_rotation.then_some(true)
                };
                IdentityProbe {
                    identity,
                    key_rotation_supported,
                    authority_epoch_supported: epoch_refused.then_some(false),
                }
            });
        }
        Err(error) if error == infraternal_plugin_api::node_channel::CALL_REFUSED => {}
        Err(_) => return None,
    }
    let reply = call(b"{}".to_vec()).await.ok()?;
    parse_identity(&reply).map(|identity| {
        let key_rotation_supported = identity.key_rotation.then_some(true);
        IdentityProbe {
            identity,
            key_rotation_supported,
            authority_epoch_supported: epoch_refused.then_some(false),
        }
    })
}

/// Decode an identity reply, refusing an unset key or port.
fn parse_identity(reply: &[u8]) -> Option<Identity> {
    parse_coordination_reply::<Option<Identity>>(reply)?
        .filter(|identity| identity.public_key.0 != [0; 32] && identity.port != 0)
}

/// The hostname the machine's infraternal agent reports in its host facts, when it reports one.
/// Only names a node the host record cannot name (store.rs `attach_named`, #236); any failure reads as none.
async fn read_hostname(channel: &dyn NodeChannel) -> Option<String> {
    let reply = channel
        .call("host.facts.read", br#"{"includeLive":false}"#.to_vec())
        .await
        .ok()?;
    let facts: serde_json::Value = parse_coordination_reply(&reply)?;
    facts["hostname"].as_str().map(str::to_owned)
}

/// One event-driven worker belongs to the generic plugin lifecycle; disabling
/// aborts and joins it. A disconnect never deletes durable mesh membership.
// Keep acknowledged-version recovery and source invalidation in one event loop.
pub async fn run(
    store: Store,
    service: MeshService,
    channel: Arc<dyn NodeChannel>,
    work: Arc<tokio::sync::Semaphore>,
) {
    let mut revisions = service.subscribe();
    let mut notices = channel.changes();
    let mut binding = None;
    let mut installed: Option<Snapshot> = None;
    let mut refresh_identity = true;
    let mut current_identity: Option<Identity> = None;
    let mut compact_access = false;
    let mut authority_epoch_supported = None;
    #[cfg(feature = "mesh-dns")]
    let mut dns_names = false;
    let mut ack_retry: Option<(infraternal_mesh::model::NodeId, u64)> = None;
    // Whether this node reports its IPv6 state (#578, J1142), and what it last said. A node's state
    // changes when it applies a snapshot, so each configure reply is read for it below.
    let mut ipv6_reporting = false;
    let mut known_ipv4_only = false;
    let mut presence_updates = service.subscribe_presence();
    let mut rotation_updates = service.subscribe_rotation_progress();
    // The relay list this node last accepted, and what wakes the worker to send a new one:
    // the server node's relay coming or going, or (on the server's own worker) a new leaf.
    let mut relays = crate::relay_list::Pushed::default();
    let mut relay_updates = service.subscribe_server_relay();
    let mut serve_updates = crate::relay_list::serve_source()
        .filter(|_| channel.is_server())
        .map(|source| source.changes.clone());
    // A restarted infraternal agent has lost its relay role (its key lives in memory only):
    // send the list again.
    let mut agent_restarts = channel.agent_restarts();
    let mut listener: ServerListener = None;
    let mut attach_retry: Option<std::time::Duration> = None;
    // Retry an ambiguous probe without weakening the identity request.
    let mut identity_retry: Option<tokio::time::Instant> = None;
    let mut transport_port = None;
    let mut config_retry = None;
    let mut peer_route: Option<(
        std::net::SocketAddr,
        Box<dyn infraternal_plugin_api::server_path::ListenerLease>,
    )> = None;
    loop {
        if refresh_identity {
            refresh_identity = false;
            relays.reset();
            let identity = read_identity(channel.as_ref()).await;
            if let Some(probe) = identity {
                let identity = probe.identity;
                let key_rotation = probe.key_rotation_supported;
                authority_epoch_supported = probe.authority_epoch_supported;
                identity_retry = authority_epoch_supported
                    .is_none()
                    .then(|| tokio::time::Instant::now() + UNKNOWN_SUPPORT_RETRY);
                compact_access = identity.compact_access;
                #[cfg(feature = "mesh-dns")]
                {
                    dns_names = identity.dns_names;
                }
                current_identity = Some(identity.clone());
                transport_port = if !channel.is_server() && channel.supports_server_paths() {
                    // Status is extensible; keep the strict identity response
                    // unchanged for older coordinators. The control channel
                    // authenticates these public local socket coordinates.
                    channel
                        .call("mesh.status", b"{}".to_vec())
                        .await
                        .ok()
                        .and_then(|reply| parse_coordination_reply::<serde_json::Value>(&reply))
                        .and_then(|reply| reply["server_link"]["source_port"].as_u64())
                        .and_then(|port| u16::try_from(port).ok())
                        .filter(|port| *port != 0)
                } else {
                    None
                };
                let reported = read_hostname(channel.as_ref()).await;
                let ip = channel.observed_ip();
                let endpoint =
                    (!ip.is_unspecified()).then(|| std::net::SocketAddr::new(ip, identity.port));
                let attached = {
                    let Ok(_permit) = work.acquire().await else {
                        return;
                    };
                    store
                        .attach_named_with_probed_capabilities(
                            channel.id(),
                            identity.public_key,
                            endpoint,
                            channel.is_server(),
                            reported.as_deref(),
                            key_rotation,
                            authority_epoch_supported,
                        )
                        .await
                };
                // Unknown support is refused while a rotation is open (J262). Nothing else may wake this worker
                // soon, so retry that refusal, and only that one, on a timer (J273 P3-2). Any other refusal, such
                // as a removed membership, is final until an owner acts (J284 P3-a).
                attach_retry = matches!(attached, Err(crate::store::ROTATION_IN_PROGRESS))
                    .then_some(UNKNOWN_SUPPORT_RETRY);
                if let Ok((node, updated)) = attached {
                    binding = Some(node);
                    // Ask before the first snapshot, so a new node's first peers already carry candidates.
                    let reported = read_candidates(channel.as_ref()).await;
                    let ipv6 = read_ipv6_state(channel.as_ref()).await;
                    // Whether this node, and so the peers that send to it, may use the second socket.
                    // Marked peers go into every other node's snapshot, so ask before the first one.
                    let side_port = read_side_socket(channel.as_ref()).await;
                    // Asked on every identity refresh: the node raises `mesh.changed` when its
                    // advertised networks change, which brings the worker back here (D197 M3).
                    let routes = read_routes(channel.as_ref()).await;
                    ipv6_reporting = ipv6.is_some();
                    known_ipv4_only = ipv6 == Some(true);
                    let Ok(_permit) = work.acquire().await else {
                        return;
                    };
                    let recorded = matches!(
                        store.record_candidates(node, reported.as_deref()).await,
                        Ok(true)
                    );
                    // A node that is IPv4-only must be marked before its peers' first snapshots too.
                    let recorded_ipv6 =
                        matches!(store.record_ipv6_state(node, ipv6).await, Ok(true));
                    let recorded_routes =
                        matches!(store.record_routes(node, routes.as_deref()).await, Ok(true));
                    let recorded_side_port =
                        matches!(store.record_side_port(node, side_port).await, Ok(true));
                    if updated || recorded || recorded_ipv6 || recorded_routes || recorded_side_port
                    {
                        service.invalidate_dataplane().await;
                    }
                } else {
                    binding = None;
                    installed = None;
                    current_identity = None;
                    authority_epoch_supported = None;
                    ipv6_reporting = false;
                }
            } else {
                binding = None;
                installed = None;
                current_identity = None;
                authority_epoch_supported = None;
                attach_retry = None;
                identity_retry = Some(tokio::time::Instant::now() + UNKNOWN_SUPPORT_RETRY);
            }
        }
        let local_identity = current_identity
            .as_ref()
            .map(|identity| identity.public_key);
        let config = if authority_epoch_supported.is_some()
            && let Some(node) = binding
        {
            match work.acquire().await {
                Ok(_permit) => match store.snapshot().await.and_then(|snapshot| {
                    local_identity.map_or(Err(MeshApiError::NotFound), |identity| {
                        snapshot
                            .config_for_identity(node, identity)
                            .map(|config| (config, snapshot))
                    })
                }) {
                    Ok(config) => Some(config),
                    Err(MeshApiError::NotFound) => {
                        // A deleted binding can be re-enrolled before this worker
                        // sees the notification. Re-query once; the tombstone
                        // still rejects attachment unless the owner enrolled it.
                        binding = None;
                        installed = None;
                        refresh_identity = true;
                        continue;
                    }
                    Err(_) => None,
                },
                Err(_) => return,
            }
        } else {
            None
        };
        if let Some((config, snapshot)) = config {
            let old = installed
                .as_ref()
                .and_then(|snapshot| snapshot.config(config.node).ok());
            // A new authority epoch retires the prior server even when policy is identical.
            let authority_changed = old.as_ref().is_some_and(|old| {
                old.authority_epoch.as_deref() != config.authority_epoch.as_deref()
            });
            // Liveness and management-role edits advance inventory revision but
            // do not change packet policy. Keep the node's acknowledged version
            // as the delta base, avoiding an unchanged snapshot/fsync per node.
            let changed = old.as_ref().is_none_or(|old| {
                #[cfg(feature = "mesh-dns")]
                let names_changed = old.name != config.name || old.peer_names != config.peer_names;
                #[cfg(not(feature = "mesh-dns"))]
                let names_changed = false;
                #[cfg(feature = "mesh-dns")]
                let dns_suffix_changed = old.dns_suffix != config.dns_suffix;
                #[cfg(not(feature = "mesh-dns"))]
                let dns_suffix_changed = false;
                old.server != config.server
                    || old.node != config.node
                    || names_changed
                    || dns_suffix_changed
                    || old.local_key != config.local_key
                    || old.addresses != config.addresses
                    || old.exposure != config.exposure
                    || old.default_policy != config.default_policy
                    || old.peers != config.peers
                    || authority_changed
            });
            if changed {
                if !channel.is_server()
                    && let Some(port) = transport_port.filter(|port| *port != 0)
                {
                    let address = std::net::SocketAddr::new(config.addresses.ipv4.into(), port);
                    if peer_route
                        .as_ref()
                        .is_none_or(|(current, _)| *current != address)
                    {
                        // Retire the old mapping before registering the new one;
                        // the live enrolled connection remains authoritative.
                        peer_route = None;
                        if let Ok(Some(lease)) = channel.route_peer(address).await {
                            peer_route = Some((address, lease));
                        }
                    }
                }
                // A reset needs a full snapshot so the receiver irreversibly fences old peers.
                let delta_base = if authority_changed {
                    None
                } else {
                    old.as_ref()
                };
                let was_delta = delta_base.is_some();
                // Never send additive fields to an older strict receiver. A
                // refused compact delta still retries the original full snapshot.
                let encoded = if compact_access {
                    crate::access_updates::chunks(delta_base, &config)
                } else {
                    configuration::chunks(delta_base, &config)
                };
                let Ok(chunks) = encoded else {
                    return;
                };
                let authority_epoch = match authority_epoch_supported {
                    Some(true) => {
                        let Some(epoch) = config.authority_epoch.clone() else {
                            tracing::error!(
                                node = ?config.node,
                                "mesh authority-capable node has no durable server epoch"
                            );
                            installed = None;
                            continue;
                        };
                        Some(epoch)
                    }
                    Some(false) => None,
                    None => {
                        // An ambiguous probe cannot authorize an epoch-less configuration chunk.
                        installed = None;
                        continue;
                    }
                };
                let mut failed = false;
                // The node's IPv6 state as of the snapshot it just applied, from the final reply.
                let mut reported_ipv4_only = None;
                for mut chunk in chunks {
                    if !current_identity
                        .as_ref()
                        .is_some_and(|identity| identity.rotation_continuity)
                    {
                        chunk.rotation_operation = None;
                    }
                    chunk.authority_epoch.clone_from(&authority_epoch);
                    if !channel.supports_server_paths() {
                        chunk.server = None;
                    }
                    #[cfg(feature = "mesh-dns")]
                    if !dns_names {
                        // Only negotiated resolvers receive host labels or a custom DNS zone.
                        chunk.name = None;
                        crate::dataplane::DEFAULT_DNS_SUFFIX.clone_into(&mut chunk.dns_suffix);
                        chunk.peer_names.clear();
                        chunk.removed_peer_names.clear();
                    }
                    let Ok(input) = serde_json::to_vec(&chunk) else {
                        return;
                    };
                    #[cfg(feature = "cutoff-measure")]
                    let ack = crate::cutoff_measure::Stage::new(config.node, config.version, "ack");
                    let reply = channel
                        .call("mesh.configure", input)
                        .await
                        .ok()
                        .and_then(|reply| parse_coordination_reply::<serde_json::Value>(&reply));
                    #[cfg(feature = "cutoff-measure")]
                    drop(ack);
                    if !reply.as_ref().is_some_and(|reply| {
                        !chunk.last
                            || reply["applied"] == true && reply["version"] == config.version
                    }) {
                        failed = true;
                        break;
                    }
                    if chunk.last && ipv6_reporting {
                        reported_ipv4_only = reply.map(|reply| reply["ipv4_only"] == true);
                    }
                }
                // Applying a snapshot is when a node reads its link, so this is where IPv6 going away
                // or coming back shows. Record it: peers' snapshots then gain or lose the IPv4-only mark
                // (no AAAA name, no IPv6 route) on the next revision (#578, J1142).
                if !failed
                    && let Some(ipv4_only) = reported_ipv4_only
                    && ipv4_only != known_ipv4_only
                {
                    known_ipv4_only = ipv4_only;
                    let Ok(_permit) = work.acquire().await else {
                        return;
                    };
                    if matches!(
                        store.record_ipv6_state(config.node, Some(ipv4_only)).await,
                        Ok(true)
                    ) {
                        service.invalidate_dataplane().await;
                    }
                }
                if !failed && snapshot.acknowledgments_required() {
                    match service.finalize_applied(config.node, config.version).await {
                        Ok(()) => ack_retry = None,
                        Err(_) => ack_retry = Some((config.node, config.version)),
                    }
                }
                installed = if failed { None } else { Some(snapshot) };
                // Retry failed full snapshots on a fixed deadline even without source events.
                // Delta refusal falls back immediately; success cancels the pending retry.
                config_retry = failed.then(|| tokio::time::Instant::now() + UNKNOWN_SUPPORT_RETRY);
                if failed && was_delta {
                    continue;
                }
            } else if snapshot.acknowledgments_required() && installed.is_some() {
                // A metadata-only revision can acknowledge an identical installed kernel view.
                match service.finalize_applied(config.node, config.version).await {
                    Ok(()) => ack_retry = None,
                    Err(_) => ack_retry = Some((config.node, config.version)),
                }
            }
        }
        if binding.is_none() {
            // Local off and membership removal own listener teardown too.
            listener = None;
            peer_route = None;
        } else if channel.is_server()
            && let Some(snapshot) = &installed
            && let Some(node) = binding
            && let Ok(config) = snapshot.config(node)
        {
            let address = std::net::IpAddr::V4(config.addresses.ipv4);
            update_listener(channel.as_ref(), address, &mut listener).await;
        }
        // Presence polls the server's own node only while it holds a delivered configuration (#562).
        // Other nodes' workers never speak for the server.
        if channel.is_server() {
            service.set_server_configured(installed.is_some());
        }
        // The relay list follows a delivered configuration, so a node learns its relays from
        // the same link and only once it is a member (D401 Q2). It is sent only on a change.
        if binding.is_some() && installed.is_some() {
            relay_updates.borrow_and_update();
            if let Some(updates) = serve_updates.as_mut() {
                updates.borrow_and_update();
            }
            crate::relay_list::push(&store, &service, channel.as_ref(), &mut relays).await;
        } else if channel.is_server() && binding.is_none() {
            // The server's node left the mesh: its relay is gone for everyone.
            service.set_server_relay(None);
        }
        // Consume our completed finalizer's publication before reading durable receipts.
        // Coalesced peer progress is covered by that read; later progress stays unseen.
        rotation_updates.borrow_and_update();
        let rotation_wait =
            if let (Some(node), Some(identity)) = (binding, current_identity.as_ref()) {
                let live = presence_updates.borrow().keys().copied().collect();
                match work.acquire().await {
                    Ok(_permit) => {
                        crate::rotation::drive(
                            &store,
                            &service,
                            channel.as_ref(),
                            node,
                            identity,
                            &live,
                        )
                        .await
                    }
                    Err(_) => return,
                }
            } else {
                None
            };
        // No heartbeat. Source changes, rotation deadlines and pending delivery or capability
        // retries wake the worker. Successful delivery leaves no view-retry timer. Closed sources retire it.
        tokio::select! {
            result=notices.changed()=> {if result.is_err() {return;}refresh_identity=true;installed=None;},
            result=revisions.recv()=>{
                if matches!(result,Err(tokio::sync::broadcast::error::RecvError::Closed)) {return;}
                // A committed revision can be the owner re-enrolling a node whose attach was refused (J284 P3-a),
                // so an unbound worker probes again. An ambiguous probe keeps its own fixed deadline instead, so
                // unrelated revisions cannot turn its retry into a probe storm (#382 P2-b).
                if binding.is_none() && identity_retry.is_none() {
                    refresh_identity = true;
                }
            },
            result=presence_updates.changed()=>if result.is_err() {return;},
            result=rotation_updates.changed()=>if result.is_err() {return;},
            result=relay_updates.changed()=>if result.is_err() {return;},
            () = watch_optional(serve_updates.as_mut()) => {},
            () = watch_optional(agent_restarts.as_mut()) => relays.reset(),
            () = tokio::time::sleep(std::time::Duration::from_secs(5)), if ack_retry.is_some() => {
                if let Some((node, revision)) = ack_retry
                    && service.finalize_applied(node, revision).await.is_ok()
                {
                    ack_retry = None;
                }
            },
            () = sleep_until_optional(config_retry) => { config_retry = None; }
            () = sleep_optional(rotation_wait) => {}
            () = sleep_optional(attach_retry) => {
                attach_retry = None;
                refresh_identity = true;
            }
            () = sleep_until_optional(identity_retry) => {
                identity_retry = None;
                refresh_identity = true;
            }
        }
    }
}

/// Wait for the next change of an optional watch; forever when there is none or its sender is
/// gone, so the caller's other select arms wake the worker.
async fn watch_optional<T>(updates: Option<&mut tokio::sync::watch::Receiver<T>>) {
    if let Some(updates) = updates
        && updates.changed().await.is_ok()
    {
        return;
    }
    std::future::pending::<()>().await;
}

/// Sleep for `delay`, or forever when there is no deadline; the caller's other select arms then wake the worker.
async fn sleep_optional(delay: Option<std::time::Duration>) {
    if let Some(delay) = delay {
        tokio::time::sleep(delay).await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// Wait for the original retry deadline, even when unrelated events wake the coordinator first.
async fn sleep_until_optional(deadline: Option<tokio::time::Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// Coordinator-side node worker checks against an in-memory node channel.
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use crate::policy::model::PublicKey;
    use infraternal_mesh::model::NodeId;
    use infraternal_plugin_api::PluginOperation;
    use sqlx::Row;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    /// Ensure every server migration has a unique version.
    #[test]
    fn server_migrations_have_unique_versions() {
        let migrations = sqlx::migrate!("../../infraternal-server/migrations");
        let mut versions = std::collections::HashSet::new();
        for migration in migrations.iter() {
            assert!(
                versions.insert(migration.version),
                "duplicate server migration version {}",
                migration.version
            );
        }
    }

    /// Refuse peer candidate arrays that exceed their advertised shape.
    #[test]
    fn peer_candidate_replies_refuse_more_addresses_than_the_protocol_allows() {
        let reply = serde_json::json!({
            "candidates": true,
            "lan": ["10.0.0.1:51820", "[fd00::1]:51820", "10.0.0.2:51820"]
        });
        assert_eq!(parse_candidates(reply.to_string().as_bytes()), None);
    }

    /// Refuse peer route arrays that exceed the accepted route count.
    #[test]
    fn peer_route_replies_refuse_more_than_the_advertised_network_limit() {
        let advertised: Vec<String> = (0..=MAX_ADVERTISED_NETWORKS)
            .map(|index| format!("10.0.{index}.0/24"))
            .collect();
        let reply = serde_json::json!({"routes": true, "advertised": advertised});
        assert_eq!(parse_routes(reply.to_string().as_bytes()), None);
    }

    /// Refuse peer replies before serde reads beyond the `NodeChannel` byte ceiling.
    #[test]
    fn peer_reply_parsers_refuse_bytes_over_the_node_channel_limit() {
        let oversized = vec![b' '; MAX_COORDINATION_REPLY_BYTES + 1];
        assert_eq!(parse_candidates(&oversized), None);
        assert_eq!(parse_routes(&oversized), None);
        assert_eq!(parse_ipv6_state(&oversized), None);
        assert_eq!(parse_side_socket(&oversized), None);
    }

    struct Lease(Arc<AtomicUsize>);
    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }
    /// An in-memory node channel whose identity, refusals and replies a test controls.
    struct Channel {
        server: bool,
        legacy_host_facts: bool,
        identity_key: PublicKey,
        key_rotation: bool,
        path_capable: AtomicBool,
        leases: Arc<AtomicUsize>,
        refuse_listener: AtomicBool,
        listened: tokio::sync::Notify,
        notices: Mutex<Option<tokio::sync::watch::Sender<()>>>,
        enabled: AtomicBool,
        refuse_delta: AtomicBool,
        /// Refuse one full snapshot to model a transient control-channel failure.
        refuse_full_once: AtomicBool,
        /// Fail one continuity probe without claiming the receiver is an older binary.
        fail_continuity_once: AtomicBool,
        /// Hold full deliveries refused until the bounded-retry proof releases them.
        refuse_full_always: AtomicBool,
        /// Record each delivery attempt before injecting a failure.
        configure_attempts: Mutex<Vec<tokio::time::Instant>>,
        /// Wake the retry proof on an attempted delivery, including failures.
        configured: tokio::sync::Semaphore,
        queried: tokio::sync::Notify,
        applied: tokio::sync::Semaphore,
        frames: Mutex<Vec<(Option<u64>, u64, bool)>>,
        /// Authority epochs carried by each mesh chunk received by this test node.
        authority_epochs: Mutex<Vec<Option<String>>>,
        hostname: Option<&'static str>,
        /// The full identity probe answers instead of failing (J273 P3-2).
        probe_answers: AtomicBool,
        /// Number of initial identity calls that time out in a probe regression.
        identity_timeouts: AtomicUsize,
        /// Number of identity calls observed by a retry regression.
        identity_calls: AtomicUsize,
        /// Identity probe bodies recorded so a regression can verify the retry shape.
        identity_requests: Mutex<Vec<Vec<u8>>>,
        /// Wakes a regression when another identity probe is issued.
        identity_probed: tokio::sync::Notify,
        /// The legacy `{}` reply hides rotation support, as a real node does when the request does not ask.
        legacy_hides_rotation: AtomicBool,
        /// The node's IPv6 report (#578, J1142): `None` is an older node that does not report, `Some(true)`
        /// a node whose mesh link has IPv6 off. Shared by the identity probe and the configure reply.
        ipv4_only: Mutex<Option<bool>>,
        /// The node's side-socket report (#260, J1211): `None` is an older node that does not report,
        /// `Some(true)` a node that takes marked datagrams on its second socket.
        side_port: Mutex<Option<bool>>,
    }
    impl Channel {
        fn new() -> Arc<Self> {
            Self::with_server(false)
        }
        fn with_server(server: bool) -> Arc<Self> {
            Self::named(server, None)
        }
        /// A channel for a server or ordinary node, optionally reporting a hostname.
        fn named(server: bool, hostname: Option<&'static str>) -> Arc<Self> {
            let (notices, _) = tokio::sync::watch::channel(());
            Arc::new(Self {
                server,
                legacy_host_facts: false,
                identity_key: PublicKey([2; 32]),
                key_rotation: false,
                path_capable: AtomicBool::new(server),
                leases: Arc::default(),
                refuse_listener: AtomicBool::new(false),
                listened: tokio::sync::Notify::new(),
                notices: Mutex::new(Some(notices)),
                enabled: AtomicBool::new(true),
                refuse_delta: AtomicBool::new(false),
                refuse_full_once: AtomicBool::new(false),
                fail_continuity_once: AtomicBool::new(false),
                refuse_full_always: AtomicBool::new(false),
                configure_attempts: Mutex::new(Vec::new()),
                configured: tokio::sync::Semaphore::new(0),
                queried: tokio::sync::Notify::new(),
                applied: tokio::sync::Semaphore::new(0),
                frames: Mutex::new(Vec::new()),
                authority_epochs: Mutex::new(Vec::new()),
                hostname,
                probe_answers: AtomicBool::new(false),
                identity_timeouts: AtomicUsize::new(0),
                identity_calls: AtomicUsize::new(0),
                identity_requests: Mutex::new(Vec::new()),
                identity_probed: tokio::sync::Notify::new(),
                legacy_hides_rotation: AtomicBool::new(false),
                ipv4_only: Mutex::new(None),
                side_port: Mutex::new(None),
            })
        }
        /// A test channel that presents the candidate key and advertises rotation support.
        fn candidate() -> Arc<Self> {
            let mut channel = Self::named(false, None);
            let candidate = Arc::get_mut(&mut channel).expect("new test channel is uniquely owned");
            candidate.identity_key = PublicKey([3; 32]);
            candidate.key_rotation = true;
            candidate.probe_answers.store(true, Ordering::Release);
            channel
        }
        fn legacy() -> Arc<Self> {
            let mut channel = Self::named(false, None);
            Arc::get_mut(&mut channel)
                .expect("new test channel is uniquely owned")
                .legacy_host_facts = true;
            channel
        }
        fn changed(&self) {
            self.notices
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .send_replace(());
        }
        /// Wait until the fake worker acknowledges the next observed channel update.
        async fn wait(&self) {
            tokio::time::timeout(std::time::Duration::from_secs(5), self.applied.acquire())
                .await
                .unwrap()
                .unwrap()
                .forget();
        }
        /// Wait until the last chunk of a config version arrives, optionally requiring a full snapshot.
        async fn wait_for_config_version(&self, version: u64, full_snapshot: bool) {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    if self
                        .frames
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|(base, current, last)| {
                            *current == version && *last && (!full_snapshot || base.is_none())
                        })
                    {
                        return;
                    }
                    self.applied.acquire().await.unwrap().forget();
                }
            })
            .await
            .expect("the requested config version was not received");
        }
        /// Count requests that explicitly probe the authenticated authority-epoch capability.
        fn authority_epoch_probe_count(&self) -> usize {
            self.identity_requests
                .lock()
                .unwrap()
                .iter()
                .filter(|request| {
                    serde_json::from_slice::<serde_json::Value>(request)
                        .is_ok_and(|probe| probe["authority_epoch"] == true)
                })
                .count()
        }
    }
    impl NodeChannel for Channel {
        fn id(&self) -> &'static str {
            if self.server {
                "server"
            } else {
                "00000000-0000-4000-8000-000000000001"
            }
        }
        fn observed_ip(&self) -> std::net::IpAddr {
            std::net::Ipv4Addr::new(192, 0, 2, 1).into()
        }
        fn is_server(&self) -> bool {
            self.server
        }
        fn supports_server_paths(&self) -> bool {
            self.path_capable.load(Ordering::Acquire)
        }
        fn route_peer(
            &self,
            address: std::net::SocketAddr,
        ) -> PluginOperation<'_, Option<Box<dyn infraternal_plugin_api::server_path::ListenerLease>>>
        {
            Box::pin(async move {
                assert!(!self.server);
                assert_eq!(address.port(), 43210);
                assert_ne!(address.ip(), self.observed_ip());
                self.leases.fetch_add(1, Ordering::AcqRel);
                Ok(Some(Box::new(Lease(self.leases.clone()))
                    as Box<
                        dyn infraternal_plugin_api::server_path::ListenerLease,
                    >))
            })
        }
        fn listen_server(
            &self,
            _address: std::net::IpAddr,
        ) -> PluginOperation<'_, Option<Box<dyn infraternal_plugin_api::server_path::ListenerLease>>>
        {
            Box::pin(async move {
                if self.refuse_listener.load(Ordering::Acquire) {
                    return Err("Listener refused.");
                }
                self.leases.fetch_add(1, Ordering::AcqRel);
                self.listened.notify_one();
                Ok(Some(Box::new(Lease(self.leases.clone()))
                    as Box<
                        dyn infraternal_plugin_api::server_path::ListenerLease,
                    >))
            })
        }
        fn changes(&self) -> tokio::sync::watch::Receiver<()> {
            self.notices.lock().unwrap().as_ref().unwrap().subscribe()
        }
        fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>> {
            let action = action.to_owned();
            Box::pin(async move {
                if action == "mesh.identity" {
                    let call = self.identity_calls.fetch_add(1, Ordering::AcqRel);
                    self.identity_requests.lock().unwrap().push(input.clone());
                    self.identity_probed.notify_one();
                    if call < self.identity_timeouts.load(Ordering::Acquire) {
                        self.queried.notify_one();
                        return Err("Node control timed out.");
                    }
                    if input == br#"{"rotation_continuity":true}"#
                        && self.fail_continuity_once.swap(false, Ordering::AcqRel)
                    {
                        return Err("Node control timed out.");
                    }
                    let legacy = input == b"{}";
                    let probe: serde_json::Value =
                        serde_json::from_slice(&input).map_err(|_| "invalid identity request")?;
                    // Model an older strict decoder: it refuses fields added after its build.
                    if !self.probe_answers.load(Ordering::Acquire)
                        && (probe["compact_access"] == true
                            || probe["dns_names"] == true
                            || probe["key_rotation"] == true
                            || probe["authority_epoch"] == true
                            || probe["rotation_continuity"] == true)
                    {
                        return Err(infraternal_plugin_api::node_channel::CALL_REFUSED);
                    }
                    let key_rotation = self.key_rotation
                        && probe["key_rotation"] == true
                        && !(legacy && self.legacy_hides_rotation.load(Ordering::Acquire));
                    let authority_epoch = self.probe_answers.load(Ordering::Acquire)
                        && probe["authority_epoch"] == true;
                    self.queried.notify_one();
                    let reported = *self.ipv4_only.lock().unwrap();
                    let report = (probe["ipv6_state"] == true).then_some(reported).flatten();
                    let identity = serde_json::to_value(
                        self.enabled.load(Ordering::Acquire).then_some(Identity {
                            compact_access: false,
                            #[cfg(feature = "mesh-dns")]
                            dns_names: false,
                            key_rotation,
                            authority_epoch,
                            rotation_continuity: probe["rotation_continuity"] == true,
                            public_key: if self.server {
                                PublicKey([1; 32])
                            } else {
                                self.identity_key
                            },
                            port: 44000,
                        }),
                    )
                    .map_err(|_| "encoding failed")?;
                    let mut identity = identity;
                    let side_report = (probe["side_socket"] == true)
                        .then(|| *self.side_port.lock().unwrap())
                        .flatten();
                    if let (Some(takes_marks), Some(fields)) =
                        (side_report, identity.as_object_mut())
                    {
                        fields.insert("side_socket".to_owned(), true.into());
                        if takes_marks {
                            fields.insert("side_port".to_owned(), true.into());
                        }
                    }
                    if let (Some(ipv4_only), Some(fields)) = (report, identity.as_object_mut()) {
                        fields.insert("ipv6_state".to_owned(), true.into());
                        if ipv4_only {
                            fields.insert("ipv4_only".to_owned(), true.into());
                        }
                    }
                    return serde_json::to_vec(&identity).map_err(|_| "encoding failed");
                }
                if action == "mesh.status" {
                    return Ok(br#"{"server_link":{"source_port":43210}}"#.to_vec());
                }
                if action == "host.facts.read" {
                    if self.legacy_host_facts {
                        // A release-4-era infraternal agent returns the old shape without `hostname`.
                        return Ok(br#"{"os":"Linux"}"#.to_vec());
                    }
                    return self
                        .hostname
                        .map(|name| format!(r#"{{"hostname":"{name}"}}"#).into_bytes())
                        .ok_or("host facts disabled");
                }
                if action == crate::relay_list::ACTION {
                    // This modelled node predates relay lists (D401): it refuses the action,
                    // and the worker stops asking until it reads the identity again.
                    return Err(infraternal_plugin_api::node_channel::CALL_REFUSED);
                }
                assert_eq!(action, "mesh.configure");
                if !self.server && self.supports_server_paths() {
                    assert_eq!(
                        self.leases.load(Ordering::Acquire),
                        1,
                        "routing must be ready before configuration publishes the path"
                    );
                }
                assert!(input.len() <= infraternal_plugin_api::MAX_ACTION_BYTES);
                if !self.server && !self.supports_server_paths() {
                    assert!(
                        serde_json::from_slice::<serde_json::Value>(&input)
                            .unwrap()
                            .get("server")
                            .is_none()
                    );
                }
                let chunk: crate::dataplane::Chunk = serde_json::from_slice(&input).unwrap();
                self.configure_attempts
                    .lock()
                    .unwrap()
                    .push(tokio::time::Instant::now());
                self.configured.add_permits(1);
                if chunk.from_version.is_none()
                    && (self.refuse_full_always.load(Ordering::Acquire)
                        || self.refuse_full_once.swap(false, Ordering::AcqRel))
                {
                    return Err("transient full configuration failure");
                }
                self.authority_epochs
                    .lock()
                    .unwrap()
                    .push(chunk.authority_epoch.clone());
                #[cfg(feature = "mesh-dns")]
                {
                    assert!(chunk.name.is_none());
                    assert!(chunk.peer_names.is_empty());
                }
                self.frames
                    .lock()
                    .unwrap()
                    .push((chunk.from_version, chunk.version, chunk.last));
                if chunk.from_version.is_some() && self.refuse_delta.swap(false, Ordering::AcqRel) {
                    return Err("stale version");
                }
                if chunk.last {
                    self.applied.add_permits(1);
                }
                let mut reply = serde_json::json!({"applied":chunk.last,"version":chunk.version});
                if *self.ipv4_only.lock().unwrap() == Some(true) {
                    reply["ipv4_only"] = true.into();
                }
                Ok(serde_json::to_vec(&reply).unwrap())
            })
        }
    }
    /// Seed the standard in-memory coordinator used by worker unit tests.
    async fn service() -> MeshService {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(2)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        service_on_pool(pool).await
    }
    /// Seed a coordinator fixture on either shared-memory or file-backed SQLite.
    async fn service_on_pool(pool: sqlx::SqlitePool) -> MeshService {
        sqlx::migrate!("../../infraternal-server/migrations")
            .run(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)")
            .bind(uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap().as_bytes().as_slice())
            .execute(&pool).await.unwrap();
        let service = MeshService::new(pool);
        service
            .dataplane()
            .attach("server", PublicKey([1; 32]), None, true)
            .await
            .unwrap();
        service
    }
    async fn names(service: &MeshService) -> Vec<String> {
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let snapshot = service
            .list("owner", crate::api::MeshFilter::default(), now)
            .await
            .unwrap();
        snapshot
            .nodes
            .into_iter()
            .map(|node| node.node.host)
            .collect()
    }
    async fn attach_once(service: &MeshService, channel: Arc<Channel>) {
        let worker = tokio::spawn(run(
            service.dataplane(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        worker.abort();
        let _ = worker.await;
    }
    /// Owner report 2026-10-17 (#236): minipc01 appeared as "mesh-<host id>" and the server as "server".
    #[tokio::test]
    async fn placeholder_names_become_the_machines_names() {
        let service = service().await;
        let host = "00000000-0000-4000-8000-000000000001";
        // Enrolled before names were known: the node carries a placeholder.
        service
            .dataplane()
            .attach(host, PublicKey([2; 32]), None, false)
            .await
            .unwrap();
        assert_eq!(names(&service).await, ["server", "host-000000"]);
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@minipc01')")
            .bind(uuid::Uuid::parse_str(host).unwrap().as_bytes().as_slice())
            .execute(&service.pool_for_tests())
            .await
            .unwrap();
        // The host record wins over what the machine reports.
        attach_once(&service, Channel::named(false, Some("other-name"))).await;
        attach_once(&service, Channel::named(true, Some("monitor01"))).await;
        assert_eq!(names(&service).await, ["monitor01", "minipc01"]);
    }
    /// A release-4-era host added by IP provides no usable name; a migrated UUID placeholder must become the D339 fallback name.
    #[tokio::test]
    async fn legacy_host_daemon_and_ip_record_do_not_leave_a_uuid_mesh_name() {
        let service = service().await;
        let host = "00000000-0000-4000-8000-000000000001";
        service
            .dataplane()
            .attach(host, PublicKey([2; 32]), None, false)
            .await
            .unwrap();
        let pool = service.pool_for_tests();
        sqlx::query(
            "UPDATE mesh_nodes SET name=?,name_source='placeholder',name_claim=NULL WHERE dataplane_host=?",
        )
        .bind(format!("mesh-{host}"))
        .bind(host)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.217')",
        )
        .bind(uuid::Uuid::parse_str(host).unwrap().as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();

        attach_once(&service, Channel::legacy()).await;

        assert_eq!(names(&service).await, ["server", "host-000000"]);
    }
    #[tokio::test]
    async fn a_reported_hostname_names_a_host_added_by_address() {
        let service = service().await;
        let host = "00000000-0000-4000-8000-000000000001";
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.217')",
        )
        .bind(uuid::Uuid::parse_str(host).unwrap().as_bytes().as_slice())
        .execute(&service.pool_for_tests())
        .await
        .unwrap();
        attach_once(&service, Channel::named(false, Some("minipc01"))).await;
        assert_eq!(names(&service).await, ["server", "minipc01"]);
    }
    #[tokio::test]
    async fn two_hosts_reporting_the_same_hostname_receive_distinct_names() {
        let service = service().await;
        let first = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let second = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
        let pool = service.pool_for_tests();
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.217')",
        )
        .bind(first.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)")
            .bind(second.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,'root@10.69.69.218')",
        )
        .bind(second.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();

        service
            .dataplane()
            .attach_named(
                &first.to_string(),
                PublicKey([2; 32]),
                None,
                false,
                Some("minipc01"),
            )
            .await
            .unwrap();
        service
            .dataplane()
            .attach_named(
                &second.to_string(),
                PublicKey([3; 32]),
                None,
                false,
                Some("minipc01"),
            )
            .await
            .unwrap();

        assert_eq!(names(&service).await, ["server", "minipc01", "minipc01-2"]);
    }
    #[tokio::test]
    async fn a_name_a_person_chose_is_kept() {
        let service = service().await;
        let host = "00000000-0000-4000-8000-000000000001";
        let (node, _) = service
            .dataplane()
            .attach(host, PublicKey([2; 32]), None, false)
            .await
            .unwrap();
        service
            .execute(
                "owner",
                "mesh.node.rename",
                &serde_json::to_vec(&serde_json::json!({"node_id":node.0,"name":"lab"})).unwrap(),
                1,
            )
            .await
            .unwrap();
        attach_once(&service, Channel::named(false, Some("minipc01"))).await;
        assert_eq!(names(&service).await, ["server", "lab"]);
    }
    /// What the store says about `node`'s IPv4-only mark in the snapshot the server's node receives.
    async fn marked_for_server(service: &MeshService, node: NodeId) -> bool {
        let store = service.dataplane();
        let server = store.config(NodeId(1)).await.unwrap();
        server.peers[&node].peer.ipv4_only
    }

    /// Wait until `marked_for_server` says `want`, failing the test after five seconds.
    async fn wait_for_mark(service: &MeshService, node: NodeId, want: bool) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while marked_for_server(service, node).await != want {
                // sleep: polls the store the worker writes after each applied snapshot; no event to await.
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the IPv4-only mark never became {want}"));
    }

    /// The coordinator learns a node's IPv6 state when it attaches and again from each configure reply, so
    /// peers' snapshots gain the IPv4-only mark when IPv6 goes away and lose it when IPv6 is back (#578,
    /// J1142). A node that does not report is never marked.
    #[tokio::test]
    async fn a_nodes_ipv6_report_marks_and_unmarks_it_for_its_peers() {
        let service = service().await;
        let store = service.dataplane();
        // The server's own node understands the mark, so its snapshots can carry it.
        assert!(
            store
                .record_ipv6_state(NodeId(1), Some(false))
                .await
                .unwrap()
        );
        let channel = Channel::new();
        *channel.ipv4_only.lock().unwrap() = Some(true);
        let worker = tokio::spawn(run(
            service.dataplane(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        let node = NodeId(2);
        // Attach probe: IPv6 off is known before the node's first snapshot reaches anyone.
        wait_for_mark(&service, node, true).await;

        // IPv6 comes back. The node says so in its reply to the next snapshot it applies; a rename of
        // another node is such a snapshot.
        *channel.ipv4_only.lock().unwrap() = Some(false);
        let rename = |name: &'static str| {
            let service = service.clone();
            async move {
                service
                    .execute(
                        "owner",
                        "mesh.node.rename",
                        &serde_json::to_vec(&serde_json::json!({"node_id":1,"name":name})).unwrap(),
                        1,
                    )
                    .await
                    .unwrap();
            }
        };
        rename("lab-one").await;
        wait_for_mark(&service, node, false).await;

        // And IPv6 goes away again.
        *channel.ipv4_only.lock().unwrap() = Some(true);
        rename("lab-two").await;
        wait_for_mark(&service, node, true).await;
        worker.abort();
        let _ = worker.await;
    }

    /// A node that never reports its IPv6 state keeps today's behaviour: no mark, whatever it says.
    #[tokio::test]
    async fn a_node_that_does_not_report_ipv6_is_never_marked() {
        let service = service().await;
        let store = service.dataplane();
        assert!(
            store
                .record_ipv6_state(NodeId(1), Some(false))
                .await
                .unwrap()
        );
        attach_once(&service, Channel::new()).await;
        assert!(!marked_for_server(&service, NodeId(2)).await);
    }

    /// What the store says about `node`'s side-port mark in the snapshot the server's node receives.
    async fn side_port_marked_for_server(service: &MeshService, node: NodeId) -> bool {
        let store = service.dataplane();
        let server = store.config(NodeId(1)).await.unwrap();
        server.peers[&node].peer.side_port
    }

    /// A node that says it takes marked datagrams is marked for peers that understand the field, from
    /// its attach probe on (#260, J1211): the mark is in place before its first peers' snapshots.
    #[tokio::test]
    async fn a_node_that_takes_marks_is_marked_for_its_peers_after_it_attaches() {
        let service = service().await;
        let store = service.dataplane();
        // The server's own node understands the field, so its snapshots can carry it.
        assert!(store.record_side_port(NodeId(1), Some(true)).await.unwrap());
        let channel = Channel::new();
        *channel.side_port.lock().unwrap() = Some(true);
        attach_once(&service, channel).await;
        assert!(side_port_marked_for_server(&service, NodeId(2)).await);
    }

    /// A node that answers the probe with "no", or never answers it, is never marked: nobody sends it a
    /// marked datagram, which kernel `WireGuard` and plain `GotaTun` would drop.
    #[tokio::test]
    async fn a_node_that_does_not_take_marks_is_never_marked() {
        for report in [None, Some(false)] {
            let service = service().await;
            assert!(
                service
                    .dataplane()
                    .record_side_port(NodeId(1), Some(true))
                    .await
                    .unwrap()
            );
            let channel = Channel::new();
            *channel.side_port.lock().unwrap() = report;
            attach_once(&service, channel).await;
            assert!(
                !side_port_marked_for_server(&service, NodeId(2)).await,
                "report {report:?} must not mark the node"
            );
        }
    }

    #[tokio::test]
    async fn peer_route_precedes_configuration_and_retires_with_the_node() {
        let service = service().await;
        let channel = Channel::new();
        channel.path_capable.store(true, Ordering::Release);
        let worker = tokio::spawn(run(
            service.dataplane(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        channel.enabled.store(false, Ordering::Release);
        channel.changed();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while channel.leases.load(Ordering::Acquire) != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        worker.abort();
        let _ = worker.await;
        assert_eq!(channel.leases.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn refused_listener_replacement_preserves_the_current_lease() {
        let channel = Channel::with_server(true);
        let old = "127.0.0.1".parse().unwrap();
        let new = "127.0.0.2".parse().unwrap();
        let mut listener = None;
        update_listener(channel.as_ref(), old, &mut listener).await;
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        channel.refuse_listener.store(true, Ordering::Release);
        update_listener(channel.as_ref(), new, &mut listener).await;
        assert_eq!(listener.as_ref().unwrap().0, old);
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        channel.refuse_listener.store(false, Ordering::Release);
        update_listener(channel.as_ref(), new, &mut listener).await;
        assert_eq!(listener.as_ref().unwrap().0, new);
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        drop(listener);
        assert_eq!(channel.leases.load(Ordering::Acquire), 0);
    }

    /// The server's listener lives only while its worker has applied an enabled configuration.
    #[tokio::test]
    async fn server_listener_belongs_to_applied_enabled_worker() {
        let service = service().await;
        let channel = Channel::with_server(true);
        channel.enabled.store(false, Ordering::Release);
        let task = tokio::spawn(run(
            service.dataplane(),
            service,
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.queried.notified(),
        )
        .await
        .unwrap();
        assert_eq!(channel.leases.load(Ordering::Acquire), 0);
        channel.enabled.store(true, Ordering::Release);
        channel.changed();
        channel.wait().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.listened.notified(),
        )
        .await
        .unwrap();
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        channel.enabled.store(false, Ordering::Release);
        channel.changed();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while channel.leases.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        channel.enabled.store(true, Ordering::Release);
        channel.changed();
        channel.wait().await;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.listened.notified(),
        )
        .await
        .unwrap();
        assert_eq!(channel.leases.load(Ordering::Acquire), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(channel.leases.load(Ordering::Acquire), 0);
    }

    /// The server's node worker tells presence when its node holds a delivered configuration (#562); an
    /// ordinary node's worker never speaks for the server.
    #[tokio::test]
    async fn the_servers_worker_publishes_that_its_node_has_a_mesh_configuration() {
        let service = service().await;
        let mut configured = service.subscribe_server_configured();
        assert!(!*configured.borrow(), "nothing is delivered yet");
        let ordinary = tokio::spawn(run(
            service.dataplane(),
            service.clone(),
            Channel::new(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        // sleep: an ordinary worker publishes nothing, so there is no event to wait for.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!*configured.borrow(), "an ordinary node does not set it");
        ordinary.abort();
        let channel = Channel::with_server(true);
        let task = tokio::spawn(run(
            service.dataplane(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            configured.wait_for(|on| *on),
        )
        .await
        .expect("a delivered configuration is announced")
        .unwrap();
        task.abort();
    }

    /// A restarted server sends its fresh authority epoch when policy is otherwise identical.
    #[tokio::test]
    async fn authority_epoch_change_reapplies_identical_mesh_snapshot() {
        let service = service().await;
        let store = service.dataplane();
        let host = "00000000-0000-4000-8000-000000000001";
        let (node, _) = store
            .attach(
                host,
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        let channel = Channel::new();
        channel.probe_answers.store(true, Ordering::Release);
        let task = tokio::spawn(run(
            store.clone(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        let before = store.snapshot().await.unwrap();
        let old_epoch = before
            .config(node)
            .unwrap()
            .authority_epoch
            .as_deref()
            .unwrap()
            .to_owned();

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        let restarted = MeshService::with_authority_epoch_for_test(
            service.pool_for_tests(),
            uuid::Uuid::new_v4().to_string().into(),
        );
        let restarted_store = restarted.dataplane();
        let restored = restarted_store.snapshot().await.unwrap();
        let new_config = restored.config(node).unwrap();
        let new_epoch = new_config.authority_epoch.as_deref().unwrap();
        assert_ne!(old_epoch, new_epoch);
        assert_eq!(new_config.version, before.config(node).unwrap().version);
        let restored_version = new_config.version;

        let task = tokio::spawn(run(
            restarted_store,
            restarted,
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));

        let permit =
            tokio::time::timeout(std::time::Duration::from_secs(5), channel.applied.acquire())
                .await
                .expect("authority-only restore did not send config")
                .unwrap();
        permit.forget();
        let frames = channel.frames.lock().unwrap().clone();
        let epochs = channel.authority_epochs.lock().unwrap().clone();
        assert_eq!(frames.len(), 2, "the authority change sent no replacement");
        assert_eq!(frames[1].0, None, "the new authority needs a full snapshot");
        assert_eq!(frames[1].1, restored_version);
        assert_eq!(epochs, [Some(old_epoch), Some(new_epoch.to_owned())]);

        channel.notices.lock().unwrap().take();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    /// A refused delta retries as a full snapshot and channel closure retires its worker.
    #[tokio::test]
    async fn refused_delta_recovers_immediately_and_closed_channel_retires_worker() {
        let service = service().await;
        let store = service.dataplane();
        let channel = Channel::new();
        let task = tokio::spawn(run(
            store.clone(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        let node = store
            .node_for_host(channel.id())
            .await
            .expect("the worker attached the authenticated host");
        let before = store.config(node).await.unwrap();
        // Wait for the worker's current snapshot without re-attaching through the legacy API.
        channel.wait_for_config_version(before.version, false).await;
        let baseline_frames = channel.frames.lock().unwrap().len();
        channel.refuse_delta.store(true, Ordering::Release);
        let next = if before.default_policy == crate::dataplane::DefaultPolicy::Allow {
            crate::dataplane::DefaultPolicy::Deny
        } else {
            crate::dataplane::DefaultPolicy::Allow
        };
        service
            .execute(
                "owner",
                "mesh.default.set",
                &serde_json::to_vec(
                    &serde_json::json!({"default_policy":next,"expected_revision":before.version}),
                )
                .unwrap(),
                1_800_000_000,
            )
            .await
            .unwrap();
        let after = store.config(node).await.unwrap();
        channel.wait_for_config_version(after.version, true).await;
        let frames = channel.frames.lock().unwrap().clone();
        assert_eq!(frames.len(), baseline_frames + 2);
        assert_eq!(frames[baseline_frames].0, Some(before.version));
        assert_eq!(frames[baseline_frames].1, after.version);
        assert_eq!(frames[baseline_frames + 1].0, None);
        assert_eq!(frames[baseline_frames + 1].1, after.version);
        channel.notices.lock().unwrap().take();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn explicit_off_waits_for_up_and_reconnect_requests_a_snapshot() {
        let service = service().await;
        let channel = Channel::new();
        channel.enabled.store(false, Ordering::Release);
        let task = tokio::spawn(run(
            service.dataplane(),
            service,
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        // The query notification fences scheduling without a polling loop.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.queried.notified(),
        )
        .await
        .unwrap();
        assert!(channel.frames.lock().unwrap().is_empty());
        channel.enabled.store(true, Ordering::Release);
        channel.changed();
        channel.wait().await;
        channel.changed();
        channel.wait().await;
        assert!(
            channel
                .frames
                .lock()
                .unwrap()
                .iter()
                .all(|frame| frame.0.is_none())
        );
        channel.notices.lock().unwrap().take();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn removed_binding_can_attach_only_after_authorized_reenrollment() {
        let service = service().await;
        let store = service.dataplane();
        let channel = Channel::new();
        let task = tokio::spawn(run(
            store.clone(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        let (old, _) = store
            .attach(
                "00000000-0000-4000-8000-000000000001",
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        service
            .execute(
                "owner",
                "mesh.node.delete",
                &serde_json::to_vec(&serde_json::json!({"node_id":old.0})).unwrap(),
                1_800_000_000,
            )
            .await
            .unwrap();
        assert!(
            store
                .attach(
                    "00000000-0000-4000-8000-000000000001",
                    PublicKey([2; 32]),
                    None,
                    false
                )
                .await
                .is_err()
        );
        service
            .execute(
                "owner",
                "mesh.node.enroll",
                &serde_json::to_vec(
                    &serde_json::json!({"name":"reenrolled","public_key":PublicKey([2;32]),"host_id":"00000000-0000-4000-8000-000000000001"}),
                )
                .unwrap(),
                1_800_000_000,
            )
            .await
            .unwrap();
        channel.wait().await;
        let (new, _) = store
            .attach(
                "00000000-0000-4000-8000-000000000001",
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        assert_ne!(old, new);
        channel.notices.lock().unwrap().take();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    /// Enroll a new node for `host` the way an owner would. It has not negotiated rotation support.
    async fn enroll_without_rotation_support(
        service: &MeshService,
        pool: &sqlx::SqlitePool,
        host: &str,
    ) {
        sqlx::query(
            "INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)",
        )
        .bind(uuid::Uuid::parse_str(host).unwrap().as_bytes().as_slice())
        .execute(pool)
        .await
        .unwrap();
        service
            .execute(
                "owner",
                "mesh.node.enroll",
                &serde_json::to_vec(&serde_json::json!({
                    "name":"unsupported-during-rotation",
                    "public_key":PublicKey([4; 32]),
                    "host_id":host
                }))
                .unwrap(),
                1_800_000_000,
            )
            .await
            .unwrap();
    }

    /// An unsupported node enrolled during preparation must keep the candidate unpublished.
    #[tokio::test]
    async fn overlap_is_refused_if_an_unsupported_node_joins_during_preparation() {
        let service = service().await;
        let store = service.dataplane();
        let (rotating, _) = store
            .attach_named_with_capability(
                "00000000-0000-4000-8000-000000000001",
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
                None,
                true,
            )
            .await
            .unwrap();
        let pool = service.pool_for_tests();
        sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1")
            .execute(&pool)
            .await
            .unwrap();
        let rotating_id = i64::try_from(rotating.0).unwrap();
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET last_rotation=0,schedule_boot_id='test-boot',schedule_monotonic=0,schedule_period_secs=604800 WHERE node_id=?",
        )
        .bind(rotating_id)
        .execute(&pool)
        .await
        .unwrap();
        let operation = store
            .begin_rotation(rotating, "test-boot", 1)
            .await
            .unwrap()
            .unwrap();

        let unsupported_host = "00000000-0000-4000-8000-000000000002";
        enroll_without_rotation_support(&service, &pool, unsupported_host).await;

        let supported: bool = sqlx::query_scalar(
            "SELECT key_rotation_supported FROM mesh_nodes WHERE dataplane_host=?",
        )
        .bind(unsupported_host)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !supported,
            "a newly enrolled node has no negotiated capability"
        );
        let overlap = store
            .start_rotation_overlap(
                rotating,
                &operation.operation_id,
                PublicKey([3; 32]),
                100,
                "test-boot",
                1_000,
            )
            .await;
        assert!(
            overlap.is_err(),
            "D166 requires deferring overlap when an unsupported node joins"
        );
        // Deferred, not abandoned: the node keeps its prepared candidate for this same operation.
        let (phase, operation_id, candidate): (Option<String>, Option<String>, Option<Vec<u8>>) =
            sqlx::query_as(
                "SELECT rotation_phase,operation_id,candidate_public_key FROM mesh_node_key_rotation WHERE node_id=?",
            )
            .bind(rotating_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(phase.as_deref(), Some("preparing"));
        assert_eq!(
            operation_id.as_deref(),
            Some(operation.operation_id.as_str())
        );
        assert_eq!(candidate, None, "no candidate key is published");
        let schedule = store
            .rotation_schedule(rotating, 100, "test-boot", 1, 1_000_000_000)
            .await
            .unwrap();
        assert!(
            !schedule.all_nodes_supported,
            "the rotation driver sees the gate closed and waits instead of retrying"
        );
    }

    /// Start a rotation for one supported node and return its id, row id and operation (J252 P2 fixtures).
    async fn rotating_node(
        service: &crate::api::MeshService,
        host: &str,
        key: PublicKey,
    ) -> (NodeId, i64, crate::store::RotationRecord) {
        let store = service.dataplane();
        let (node, _) = store
            .attach_named_with_capability(
                host,
                key,
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
                None,
                true,
            )
            .await
            .unwrap();
        let pool = service.pool_for_tests();
        // Every node supports rotation, so the D166 all-node gate opens.
        sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1")
            .execute(&pool)
            .await
            .unwrap();
        let node_id = i64::try_from(node.0).unwrap();
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET last_rotation=0,schedule_boot_id='test-boot',schedule_monotonic=0,schedule_period_secs=604800 WHERE node_id=?",
        )
        .bind(node_id)
        .execute(&pool)
        .await
        .unwrap();
        let operation = store
            .begin_rotation(node, "test-boot", 1)
            .await
            .unwrap()
            .unwrap();
        (node, node_id, operation)
    }

    /// A node's stored key, rotation support, phase, candidate, predecessor and operation id.
    type RotationRow = (
        Vec<u8>,
        bool,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<String>,
    );

    /// Read a node's stored key, rotation support and rotation columns.
    async fn rotation_row(service: &crate::api::MeshService, node_id: i64) -> RotationRow {
        sqlx::query_as(
            "SELECT n.public_key,n.key_rotation_supported,r.rotation_phase,r.candidate_public_key,r.previous_public_key,r.operation_id \
             FROM mesh_nodes AS n JOIN mesh_node_key_rotation AS r ON r.node_id=n.id WHERE n.id=?",
        )
        .bind(node_id)
        .fetch_one(&service.pool_for_tests())
        .await
        .unwrap()
    }

    /// J252 P2: a node whose rotation is being prepared restarts on an engine without rotation support (kernel to
    /// `GotaTun`, D346). The attach must succeed, record the lost support and abandon the rotation in one
    /// transaction, so the candidate is never published and later restarts are not refused.
    #[tokio::test]
    async fn a_node_that_loses_rotation_support_while_preparing_abandons_the_rotation() {
        let service = service().await;
        let store = service.dataplane();
        let host = "00000000-0000-4000-8000-000000000001";
        let key = PublicKey([2; 32]);
        let endpoint = Some("192.0.2.1:44000".parse().unwrap());
        let (node, node_id, operation) = rotating_node(&service, host, key).await;

        store
            .attach_named_with_capability(host, key, endpoint, false, None, false)
            .await
            .expect("an attach without rotation support is accepted while a rotation is open");
        let (current, supported, phase, candidate, previous, operation_id) =
            rotation_row(&service, node_id).await;
        assert_eq!(
            current,
            key.0.to_vec(),
            "the node keeps the key it presented"
        );
        assert!(!supported, "the lost support is recorded");
        assert_eq!(
            (phase, candidate, previous, operation_id),
            (None, None, None, None),
            "the rotation is abandoned"
        );
        assert!(
            store
                .start_rotation_overlap(
                    node,
                    &operation.operation_id,
                    PublicKey([3; 32]),
                    100,
                    "test-boot",
                    1_000
                )
                .await
                .is_err(),
            "the abandoned operation cannot publish its candidate"
        );
        assert!(
            store
                .begin_rotation(node, "test-boot", 2)
                .await
                .unwrap()
                .is_none(),
            "no new rotation starts while the node reports no support"
        );
        store
            .attach_named_with_capability(host, key, endpoint, false, None, false)
            .await
            .expect("a later restart attaches too");
    }

    /// J252 P2 in the overlap phase: peers already hold both keys and the node restarts without rotation support,
    /// presenting the predecessor it carried. The coordinator returns to that key alone and refuses the stale
    /// commit, so no peer is left routing to a key the node may not hold.
    #[tokio::test]
    async fn a_node_that_loses_rotation_support_during_overlap_keeps_the_key_it_presents() {
        let service = service().await;
        let store = service.dataplane();
        let host = "00000000-0000-4000-8000-000000000001";
        let previous = PublicKey([2; 32]);
        let endpoint = Some("192.0.2.1:44000".parse().unwrap());
        let (node, node_id, operation) = rotating_node(&service, host, previous).await;
        store
            .start_rotation_overlap(
                node,
                &operation.operation_id,
                PublicKey([3; 32]),
                100,
                "test-boot",
                1_000,
            )
            .await
            .unwrap();

        store
            .attach_named_with_capability(host, previous, endpoint, false, None, false)
            .await
            .expect("an attach without rotation support is accepted during the overlap");
        let (current, supported, phase, candidate, stored_previous, operation_id) =
            rotation_row(&service, node_id).await;
        assert_eq!(
            current,
            previous.0.to_vec(),
            "peers route to the key the node holds"
        );
        assert!(!supported);
        assert_eq!(
            (phase, candidate, stored_previous, operation_id),
            (None, None, None, None)
        );
        assert!(
            store
                .commit_rotation(node, &operation.operation_id)
                .await
                .is_err(),
            "the abandoned operation cannot commit"
        );
    }

    /// J262: a probe that could not show the capability (only the legacy request answered) must not abandon an
    /// open rotation. The attach keeps the old refusal, the rotation and its operation stay as they were, and
    /// the next attach that proves support continues the same operation.
    #[tokio::test]
    async fn an_unknown_capability_never_abandons_an_open_rotation() {
        let service = service().await;
        let store = service.dataplane();
        let host = "00000000-0000-4000-8000-000000000001";
        let predecessor = PublicKey([2; 32]);
        let endpoint = Some("192.0.2.1:44000".parse().unwrap());
        let (node, node_id, first) = rotating_node(&service, host, predecessor).await;
        store
            .start_rotation_overlap(
                node,
                &first.operation_id,
                PublicKey([3; 32]),
                100,
                "test-boot",
                1_000,
            )
            .await
            .unwrap();
        let before = rotation_row(&service, node_id).await;

        assert_eq!(
            store
                .attach_named_with_probed_capability(host, predecessor, endpoint, false, None, None)
                .await,
            Err("Mesh key rotation is in progress."),
            "an unknown capability is refused while the rotation is open"
        );
        assert_eq!(
            rotation_row(&service, node_id).await,
            before,
            "nothing was abandoned"
        );
        store
            .attach_named_with_probed_capability(
                host,
                predecessor,
                endpoint,
                false,
                None,
                Some(true),
            )
            .await
            .expect("the next probe that proves support attaches");
        let (_, supported, phase, _, _, operation) = rotation_row(&service, node_id).await;
        assert!(supported);
        assert_eq!(phase.as_deref(), Some("overlap"));
        assert_eq!(
            operation.as_deref(),
            Some(first.operation_id.as_str()),
            "the same operation continues"
        );
    }

    /// With no rotation open, an unknown capability attaches as unsupported, as a legacy attach always did.
    #[tokio::test]
    async fn an_unknown_capability_without_a_rotation_attaches_as_unsupported() {
        let service = service().await;
        let store = service.dataplane();
        let host = "00000000-0000-4000-8000-000000000001";
        let (node, _) = store
            .attach_named_with_probed_capability(host, PublicKey([2; 32]), None, false, None, None)
            .await
            .unwrap();
        let (_, supported, phase, ..) =
            rotation_row(&service, i64::try_from(node.0).unwrap()).await;
        assert!(!supported);
        assert_eq!(phase, None);
    }

    /// An identity reply from a receiver without authority-epoch support.
    fn identity_reply(key_rotation: bool) -> Vec<u8> {
        serde_json::to_vec(&Some(Identity {
            compact_access: false,
            #[cfg(feature = "mesh-dns")]
            dns_names: false,
            key_rotation,
            authority_epoch: false,
            rotation_continuity: false,
            public_key: PublicKey([2; 32]),
            port: 44000,
        }))
        .unwrap()
    }

    /// An identity reply from a receiver that explicitly accepts authority epochs.
    fn epoch_identity_reply() -> Vec<u8> {
        serde_json::to_vec(&Some(Identity {
            compact_access: false,
            #[cfg(feature = "mesh-dns")]
            dns_names: false,
            key_rotation: true,
            authority_epoch: true,
            rotation_continuity: false,
            public_key: PublicKey([2; 32]),
            port: 44000,
        }))
        .unwrap()
    }

    /// Run `probe_identity` against scripted replies (in call order) and return the classified support and the
    /// requests made.
    async fn classify(
        replies: Vec<Result<Vec<u8>, &'static str>>,
    ) -> (Option<(Option<bool>, Option<bool>)>, Vec<Vec<u8>>) {
        let replies = Mutex::new(replies.into_iter());
        let requests = Mutex::new(Vec::new());
        let result = probe_identity(
            |input| {
                requests.lock().unwrap().push(input);
                let reply = replies.lock().unwrap().next().unwrap_or(Err("no reply"));
                async move { reply }
            },
            b"FULL",
            b"WITHOUT_EPOCH",
            b"BEFORE",
        )
        .await
        .map(|probe| {
            (
                probe.key_rotation_supported,
                probe.authority_epoch_supported,
            )
        });
        (result, requests.into_inner().unwrap())
    }

    /// A transient continuity probe failure withholds configuration; explicit refusal remains compatible.
    #[tokio::test]
    async fn continuity_probe_failure_never_downgrades_a_current_receiver() {
        let channel = Channel::candidate();
        channel.fail_continuity_once.store(true, Ordering::Release);
        assert!(read_identity(channel.as_ref()).await.is_none());
        let retried = read_identity(channel.as_ref())
            .await
            .expect("successful retry");
        assert!(retried.identity.rotation_continuity);
        let legacy = read_identity(Channel::new().as_ref())
            .await
            .expect("explicit refusal permits fallback");
        assert!(!legacy.identity.rotation_continuity);
    }

    /// An ambiguous full probe leaves epoch support unknown even when a weaker request returns identity.
    #[tokio::test]
    async fn probe_timeouts_never_read_as_an_older_binary() {
        for failure in [
            "Node control timed out.",
            "Node control unavailable.",
            "Node authority ended.",
        ] {
            let (supported, requests) =
                classify(vec![Err(failure), Err(failure), Ok(identity_reply(false))]).await;
            assert_eq!(supported, Some((None, None)), "{failure}");
            assert_eq!(requests.len(), 3, "{failure}");
        }
        // One refusal and one timeout is still not a deterministic rejection.
        let (supported, requests) = classify(vec![
            Err(infraternal_plugin_api::node_channel::CALL_REFUSED),
            Err("Node control timed out."),
            Ok(identity_reply(false)),
        ])
        .await;
        assert_eq!(supported, Some((None, None)));
        assert_eq!(requests.len(), 3);
    }

    /// J262 (b): one transient probe failure is retried and the retry proves support.
    #[tokio::test]
    async fn a_transient_probe_failure_is_retried_before_any_fallback() {
        let (supported, requests) = classify(vec![
            Err("Node control timed out."),
            Ok(identity_reply(true)),
        ])
        .await;
        assert_eq!(supported, Some((Some(true), Some(false))));
        assert_eq!(requests, vec![b"FULL".to_vec(), b"FULL".to_vec()]);
    }

    /// A node that rejects the epoch field still reports its rotation support on the previous probe.
    #[tokio::test]
    async fn an_epoch_unsupported_node_keeps_rotation_negotiation() {
        let (supported, requests) = classify(vec![
            Err(infraternal_plugin_api::node_channel::CALL_REFUSED),
            Err(infraternal_plugin_api::node_channel::CALL_REFUSED),
            Ok(identity_reply(true)),
        ])
        .await;
        assert_eq!(supported, Some((Some(true), Some(false))));
        assert_eq!(requests.last().unwrap(), b"WITHOUT_EPOCH");
    }

    /// When only the legacy request answers, the failures prove nothing about rotation: support is unknown.
    #[tokio::test]
    async fn only_a_legacy_answer_leaves_rotation_support_unknown() {
        let (supported, requests) = classify(vec![
            Err("Node control timed out."),
            Err("Node control timed out."),
            Err("Node control timed out."),
            Err("Node control timed out."),
            Err(infraternal_plugin_api::node_channel::CALL_REFUSED),
            Ok(identity_reply(false)),
        ])
        .await;
        assert_eq!(supported, Some((None, None)));
        assert_eq!(requests.last().unwrap(), b"{}");
    }

    /// A pre-rotation strict decoder is still marked unsupported, which keeps the D166 rotation gate closed.
    #[tokio::test]
    async fn a_pre_rotation_node_refuses_rotation_and_epoch_extensions() {
        let refusal = infraternal_plugin_api::node_channel::CALL_REFUSED;
        let (supported, requests) = classify(vec![
            Err(refusal),
            Err(refusal),
            Err(refusal),
            Err(refusal),
            Ok(identity_reply(false)),
        ])
        .await;
        assert_eq!(supported, Some((Some(false), Some(false))));
        assert_eq!(requests.last().unwrap(), b"BEFORE");
    }

    /// A positive epoch bit from the full identity probe permits epoch-bearing configuration chunks.
    #[tokio::test]
    async fn epoch_support_requires_the_explicit_full_probe() {
        let (supported, requests) = classify(vec![Ok(epoch_identity_reply())]).await;
        assert_eq!(supported, Some((Some(true), Some(true))));
        assert_eq!(requests, vec![b"FULL".to_vec()]);
    }

    /// A timeout followed by an epoch-less answer must retry the full probe without sending a downgrade.
    #[tokio::test]
    async fn timed_out_epoch_probe_never_sends_epochless_config_and_reprobes() {
        let service = service().await;
        let presence_events = service.clone();
        let channel = Channel::new();
        channel.probe_answers.store(true, Ordering::Release);
        channel.identity_timeouts.store(2, Ordering::Release);
        let task = tokio::spawn(run(
            service.dataplane(),
            service,
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));

        // sleep: bound the ambiguous probe response before checking that no config was sent.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while channel.identity_requests.lock().unwrap().len() < 3 {
                channel.identity_probed.notified().await;
            }
        })
        .await
        .expect("the ambiguous probes did not finish");
        let early_config =
            tokio::time::timeout(std::time::Duration::from_secs(1), channel.applied.acquire())
                .await;
        assert!(
            early_config.is_err(),
            "the coordinator sent an epoch-less snapshot after an ambiguous probe"
        );
        assert!(channel.authority_epochs.lock().unwrap().is_empty());
        let initial_requests = channel.identity_requests.lock().unwrap().clone();
        assert!(initial_requests[..2].iter().all(|request| {
            serde_json::from_slice::<serde_json::Value>(request)
                .is_ok_and(|probe| probe["authority_epoch"] == true)
        }));
        let fallback: serde_json::Value = serde_json::from_slice(&initial_requests[2]).unwrap();
        assert!(fallback.get("authority_epoch").is_none());

        let presence_noise = tokio::spawn(async move {
            let mut live = crate::presence::Live::new();
            loop {
                if live.is_empty() {
                    live.insert(NodeId(2), None);
                } else {
                    live.clear();
                }
                presence_events.set_presence(live.clone());
                // sleep: repeatedly wake an unrelated select arm while the unknown-support retry is pending.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        });
        // sleep: bound the wait to the scheduled five-second identity reprobe.
        let reprobe = tokio::time::timeout(
            UNKNOWN_SUPPORT_RETRY + std::time::Duration::from_secs(2),
            async {
                while channel.authority_epoch_probe_count() < 3 {
                    channel.identity_probed.notified().await;
                }
            },
        )
        .await;
        presence_noise.abort();
        reprobe.expect("the full identity probe was not retried");
        let requests = channel.identity_requests.lock().unwrap().clone();
        let retry_request = requests
            .iter()
            .filter(|request| {
                serde_json::from_slice::<serde_json::Value>(request)
                    .is_ok_and(|probe| probe["authority_epoch"] == true)
            })
            .nth(2)
            .expect("the retry did not include a full authority probe");
        let retry: serde_json::Value = serde_json::from_slice(retry_request).unwrap();
        assert_eq!(
            retry["authority_epoch"], true,
            "retry omitted the epoch probe"
        );
        channel.wait().await;
        let epochs = channel.authority_epochs.lock().unwrap().clone();
        assert_eq!(epochs.len(), 1);
        assert!(
            epochs[0].is_some(),
            "the retry still sent an epoch-less snapshot"
        );

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    /// A coordinator restart in the overlap phase still publishes the previous key to peers.
    #[tokio::test]
    async fn coordinator_restart_restores_the_previous_key_during_overlap() {
        let service = service().await;
        let store = service.dataplane();
        let (node, _) = store
            .attach(
                "00000000-0000-4000-8000-000000000001",
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        let server = store.node_for_host("server").await.unwrap();
        let pool = service.pool_for_tests();
        let operation_id = "00000000-0000-4000-8000-000000000001";
        // Rotation starts only once every node supports it (D166), the server included.
        sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id=?,sequence=1 WHERE node_id=?",
        )
            .bind(operation_id)
            .bind(i64::try_from(node.0).unwrap())
            .execute(&pool)
            .await
            .unwrap();
        store
            .start_rotation_overlap(
                node,
                operation_id,
                PublicKey([3; 32]),
                100,
                "test-boot",
                1_000,
            )
            .await
            .unwrap();

        let restarted = crate::store::Store::new(pool);
        let config = restarted.config(server).await.unwrap();
        let peer = &config.peers[&node].peer;
        assert_eq!(peer.key, PublicKey([2; 32]));
        assert_eq!(
            peer.previous_key,
            Some(PublicKey([3; 32])),
            "a server restart must not forget the old public key before overlap retirement"
        );
        assert!(
            !peer.previous_active,
            "the previous key remains the route owner until the local candidate switch"
        );
    }

    /// A node that reconnects with its predecessor key during the overlap keeps the recorded candidate.
    #[tokio::test]
    async fn reconnect_with_predecessor_preserves_candidate_during_overlap() {
        let service = service().await;
        let store = service.dataplane();
        let host = "00000000-0000-4000-8000-000000000001";
        let predecessor = PublicKey([2; 32]);
        let candidate = PublicKey([3; 32]);
        let endpoint = Some("192.0.2.1:44000".parse().unwrap());
        let (node, _) = store
            .attach(host, predecessor, endpoint, false)
            .await
            .unwrap();
        let pool = service.pool_for_tests();
        let operation_id = "00000000-0000-4000-8000-000000000004";
        // Rotation starts only once every node supports it (D166), the server included.
        sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id=?,sequence=1 WHERE node_id=?",
        )
        .bind(operation_id)
        .bind(i64::try_from(node.0).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        store
            .start_rotation_overlap(node, operation_id, candidate, 100, "test-boot", 1_000)
            .await
            .unwrap();

        let (reattached, _) = store
            .attach_named_with_capability(host, predecessor, endpoint, false, None, true)
            .await
            .unwrap();

        assert_eq!(reattached, node);
        let schedule = store
            .rotation_schedule(node, 100, "test-boot", 0, 1_000)
            .await;
        assert!(
            schedule.is_ok(),
            "a predecessor reconnect must preserve the persisted candidate rotation"
        );
        let current: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM mesh_nodes WHERE id=?")
            .bind(i64::try_from(node.0).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(current, candidate.0);
    }

    /// A node may already present the candidate key before the server records the retiring phase.
    #[tokio::test]
    async fn candidate_identity_reconnects_before_server_marks_rotation_retiring() {
        let service = service().await;
        let store = service.dataplane();
        let (node, _) = store
            .attach(
                "00000000-0000-4000-8000-000000000001",
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        let operation_id = "00000000-0000-4000-8000-000000000003";
        // Rotation starts only once every node supports it (D166), the server included.
        sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1")
            .execute(&service.pool_for_tests())
            .await
            .unwrap();
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id=?,sequence=1 WHERE node_id=?",
        )
        .bind(operation_id)
        .bind(i64::try_from(node.0).unwrap())
        .execute(&service.pool_for_tests())
        .await
        .unwrap();
        store
            .start_rotation_overlap(
                node,
                operation_id,
                PublicKey([3; 32]),
                1_800_000_000,
                "test-boot",
                1_000,
            )
            .await
            .unwrap();

        let snapshot = store.snapshot().await.unwrap();
        let predecessor = snapshot
            .config_for_identity(node, PublicKey([2; 32]))
            .unwrap();
        assert_eq!(predecessor.local_key, Some(PublicKey([2; 32])));
        let candidate = snapshot
            .config_for_identity(node, PublicKey([3; 32]))
            .unwrap();
        assert_eq!(
            candidate.local_key,
            Some(PublicKey([3; 32])),
            "a host restored after local key commit must bind its full config to the candidate"
        );
        assert!(
            snapshot
                .config_for_identity(node, PublicKey([4; 32]))
                .is_err()
        );

        let server = store.node_for_host("server").await.unwrap();
        let peer = snapshot.config(server).unwrap().peers[&node].peer.clone();
        assert_eq!(peer.key, PublicKey([2; 32]));
        assert_eq!(peer.previous_key, Some(PublicKey([3; 32])));
        assert!(!peer.previous_active);
    }

    /// J284 P3-a: only the rotation-in-progress refusal is retried on the timer. A removed membership is final
    /// until an owner enrolls the host again, so the worker probes once and then waits for an event.
    #[tokio::test]
    async fn a_removed_membership_is_not_retried_on_the_timer() {
        let service = service().await;
        let pool = service.pool_for_tests();
        let host = "00000000-0000-4000-8000-000000000001";
        sqlx::query("INSERT INTO mesh_dataplane_removed(host) VALUES(?)")
            .bind(host)
            .execute(&pool)
            .await
            .unwrap();
        // Support reads as unknown: only the legacy request answers, and it hides rotation.
        let channel = Channel::candidate();
        channel.legacy_hides_rotation.store(true, Ordering::Release);
        channel.probe_answers.store(false, Ordering::Release);
        let worker = tokio::spawn(run(
            service.dataplane(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.queried.notified(),
        )
        .await
        .expect("the worker probes the node once");
        assert!(
            tokio::time::timeout(
                UNKNOWN_SUPPORT_RETRY + std::time::Duration::from_secs(2),
                channel.queried.notified(),
            )
            .await
            .is_err(),
            "a removed membership is not probed again on the timer"
        );
        worker.abort();
        let _ = worker.await;
    }

    /// J273 P3-2: a node whose support is unknown is refused while its rotation is open. The worker retries on a
    /// timer, so once the probe answers again the node attaches without waiting for an unrelated event.
    #[tokio::test]
    async fn a_refused_attach_with_unknown_support_retries_on_a_timer() {
        let service = service().await;
        let store = service.dataplane();
        let host = "00000000-0000-4000-8000-000000000001";
        let (node, _, operation) = rotating_node(&service, host, PublicKey([2; 32])).await;
        store
            .start_rotation_overlap(
                node,
                &operation.operation_id,
                PublicKey([3; 32]),
                1_800_000_000,
                "test-boot",
                1_000,
            )
            .await
            .unwrap();
        // The retiring phase makes no node calls, so the worker only attaches and configures.
        store
            .commit_rotation(node, &operation.operation_id)
            .await
            .unwrap();
        let channel = Channel::candidate();
        channel.legacy_hides_rotation.store(true, Ordering::Release);
        channel.probe_answers.store(false, Ordering::Release);
        let worker = tokio::spawn(run(
            store.clone(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            channel.queried.notified(),
        )
        .await
        .expect("the worker probes the node");
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), channel.applied.acquire())
                .await
                .is_err(),
            "unknown support is refused while the rotation is open"
        );
        // The probe answers again; no mesh, presence or channel event follows.
        channel.probe_answers.store(true, Ordering::Release);
        tokio::time::timeout(
            UNKNOWN_SUPPORT_RETRY + std::time::Duration::from_secs(5),
            channel.applied.acquire(),
        )
        .await
        .expect("the refused attach is retried on its own timer")
        .unwrap()
        .forget();
        worker.abort();
        let _ = worker.await;
    }

    /// Applied views are durably acknowledged while a rotation needs them, and a new server instance asks again.
    #[tokio::test]
    async fn successful_peer_configuration_is_durably_acknowledged_until_restart() {
        let service = service().await;
        let store = service.dataplane();
        let host_id = "00000000-0000-4000-8000-000000000001";
        let (node, _) = store
            .attach(
                host_id,
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        let pool = service.pool_for_tests();
        let operation_id = "00000000-0000-4000-8000-000000000002";
        // Rotation starts only once every node supports it (D166), the server included.
        sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id=?,sequence=1 WHERE node_id=?",
        )
        .bind(operation_id)
        .bind(i64::try_from(node.0).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        store
            .start_rotation_overlap(
                node,
                operation_id,
                PublicKey([3; 32]),
                1_800_000_000,
                "test-boot",
                1_000,
            )
            .await
            .unwrap();
        let rotation_revision = store.commit_rotation(node, operation_id).await.unwrap();
        let channel = Channel::candidate();
        let mut progress = service.subscribe_rotation_progress();
        let worker = tokio::spawn(run(
            store.clone(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        channel.wait().await;
        progress.changed().await.unwrap();
        let applied =
            sqlx::query("SELECT revision,server_instance FROM mesh_node_applied WHERE node_id=?")
                .bind(i64::try_from(node.0).unwrap())
                .fetch_optional(&pool)
                .await
                .unwrap()
                .expect("successful configuration must survive worker and coordinator restart");
        assert!(applied.get::<i64, _>("revision") >= i64::try_from(rotation_revision).unwrap());
        assert_eq!(
            applied.get::<String, _>("server_instance"),
            store.server_instance()
        );
        assert!(
            store
                .rotation_acks_ready(rotation_revision, &[node].into_iter().collect())
                .await
                .unwrap()
        );
        let restarted = crate::store::Store::new(pool);
        assert!(
            !restarted
                .rotation_acks_ready(rotation_revision, &[node].into_iter().collect())
                .await
                .unwrap(),
            "a new coordinator instance must reapply views before trusting old receipts"
        );
        worker.abort();
        let _ = worker.await;
    }

    /// A transient full-view failure must retry without an external event so retirement can obtain its own ack.
    #[tokio::test]
    async fn retiring_rotation_retries_its_failed_full_view_without_an_external_event() {
        let service = service().await;
        let store = service.dataplane();
        let (node, _) = store
            .attach(
                "00000000-0000-4000-8000-000000000001",
                PublicKey([2; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
            )
            .await
            .unwrap();
        let pool = service.pool_for_tests();
        let operation = "00000000-0000-4000-8000-000000000533";
        sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id=?,sequence=1 WHERE node_id=?",
        )
        .bind(operation)
        .bind(i64::try_from(node.0).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        store
            .start_rotation_overlap(node, operation, PublicKey([3; 32]), 100, "test-boot", 1_000)
            .await
            .unwrap();
        let retiring_revision = store.commit_rotation(node, operation).await.unwrap();
        // Establish the same capabilities beforehand so attachment itself cannot wake a retry.
        store
            .attach_named_with_probed_capabilities(
                "00000000-0000-4000-8000-000000000001",
                PublicKey([3; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
                None,
                Some(true),
                Some(true),
            )
            .await
            .unwrap();
        let channel = Channel::candidate();
        channel.refuse_full_once.store(true, Ordering::Release);
        let worker = tokio::spawn(run(
            store.clone(),
            service.clone(),
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        // Await an actual successful delivery. The timeout is a hang guard; no source event is sent.
        let retried = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            channel.applied.acquire(),
        )
        .await;
        worker.abort();
        let _ = worker.await;
        let phase: Option<String> =
            sqlx::query_scalar("SELECT rotation_phase FROM mesh_node_key_rotation WHERE node_id=?")
                .bind(i64::try_from(node.0).unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            retried.is_ok(),
            "rotation stayed {phase:?} at revision {retiring_revision}: one failed full delivery stranded its own acknowledgment"
        );
    }

    /// Failed full views wait five seconds between attempts and stop retrying after success.
    #[tokio::test]
    async fn failed_full_views_are_bounded_and_success_stops_delivery_retries() {
        let service = service().await;
        let store = service.dataplane();
        let channel = Channel::candidate();
        store
            .attach_named_with_probed_capabilities(
                "00000000-0000-4000-8000-000000000001",
                PublicKey([3; 32]),
                Some("192.0.2.1:44000".parse().unwrap()),
                false,
                None,
                Some(true),
                Some(true),
            )
            .await
            .unwrap();
        channel.refuse_full_always.store(true, Ordering::Release);
        let worker = tokio::spawn(run(
            store,
            service,
            channel.clone(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        ));
        let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            channel.configured.acquire_many(2).await.unwrap().forget();
            let attempts = channel.configure_attempts.lock().unwrap().clone();
            assert!(attempts[1].duration_since(attempts[0]) >= UNKNOWN_SUPPORT_RETRY,
                "failed full delivery retried before its monotonic deadline");
            channel.refuse_full_always.store(false, Ordering::Release);
            channel.configured.acquire().await.unwrap().forget();
            channel.applied.acquire().await.unwrap().forget();
            // The timeout observes absence across an entire retry period, not execution speed.
            assert!(tokio::time::timeout(UNKNOWN_SUPPORT_RETRY + std::time::Duration::from_secs(1),
                channel.configured.acquire()).await.is_err(), "settled view was delivered again");
            let attempts = channel.configure_attempts.lock().unwrap();
            assert_eq!(attempts.len(), 3);
            assert!(attempts[2].duration_since(attempts[1]) >= UNKNOWN_SUPPORT_RETRY);
            println!("J862_RETRY attempts=3 failure_intervals_at_least_5s=true settled_6s_no_delivery=true");
        }).await;
        worker.abort();
        let _ = worker.await;
        result.expect("bounded retry proof must complete");
    }

    /// Receipt idempotence, worker wakeups and stuck-cleanup regressions for #537.
    mod ack_loop_tests;

    /// Presence where one peer is reachable only through the relay and another is offline.
    fn live_with_relay_activity(
        rotating: NodeId,
        relay_peer: NodeId,
        offline_peer: NodeId,
        server: NodeId,
    ) -> crate::presence::Live {
        let now = 1_800_000_000;
        let mut tracker = crate::presence::Tracker::default();
        let rows = vec![
            crate::presence::PeerRow {
                node: rotating,
                handshake: now - 10,
                received: 100,
                keepalive: 0,
                endpoint: None,
            },
            crate::presence::PeerRow {
                node: relay_peer,
                handshake: 0,
                received: 200,
                keepalive: 0,
                endpoint: None,
            },
            crate::presence::PeerRow {
                node: offline_peer,
                handshake: 0,
                received: 0,
                keepalive: 0,
                endpoint: None,
            },
        ];
        tracker.record(Some((true, rows.clone())), now);
        let active_rows = rows
            .into_iter()
            .map(|mut row| {
                if row.node == relay_peer {
                    row.received += 1;
                }
                row
            })
            .collect();
        tracker.record(Some((true, active_rows)), now + 5);
        let live = tracker.live(Some(server), now + 5);
        assert_eq!(
            live.get(&relay_peer),
            Some(&Some(crate::presence::NodePath::Relay)),
            "relayed packet activity counts without a direct handshake"
        );
        live
    }

    /// A peer reachable only through the relay counts as reachable, so its missing acknowledgment blocks retirement.
    #[tokio::test]
    async fn relay_only_peer_without_candidate_ack_blocks_rotation_retirement() {
        let service = service().await;
        let store = service.dataplane();
        let (rotating, _) = store
            .attach(
                "00000000-0000-4000-8000-000000000001",
                PublicKey([2; 32]),
                None,
                false,
            )
            .await
            .unwrap();
        let (relay_peer, _) = store
            .attach(
                "00000000-0000-4000-8000-000000000002",
                PublicKey([4; 32]),
                None,
                false,
            )
            .await
            .unwrap();
        let (offline_peer, _) = store
            .attach(
                "00000000-0000-4000-8000-000000000003",
                PublicKey([5; 32]),
                None,
                false,
            )
            .await
            .unwrap();
        let server = store.node_for_host("server").await.unwrap();
        let pool = service.pool_for_tests();
        let operation_id = uuid::Uuid::new_v4().to_string();
        // Rotation starts only once every node supports it (D166), the server included.
        sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id=?,sequence=1 WHERE node_id=?",
        )
        .bind(&operation_id)
        .bind(i64::try_from(rotating.0).unwrap())
        .execute(&pool)
        .await
        .unwrap();
        let revision = store
            .start_rotation_overlap(
                rotating,
                &operation_id,
                PublicKey([3; 32]),
                1_800_000_000,
                "test-boot",
                1_000,
            )
            .await
            .unwrap();

        let live = live_with_relay_activity(rotating, relay_peer, offline_peer, server);
        let reachable = store
            .rotation_reachable_peers(rotating, &live.keys().copied().collect())
            .await
            .unwrap();
        assert!(reachable.contains(&relay_peer));
        assert!(
            !reachable.contains(&offline_peer),
            "D166 keeps offline peers exempt"
        );
        store.acknowledge_applied(server, revision).await.unwrap();
        store.acknowledge_applied(rotating, revision).await.unwrap();
        assert!(
            !store
                .rotation_acks_ready(revision, &reachable)
                .await
                .unwrap(),
            "the active relay-only peer has not applied the candidate view"
        );
    }

    /// Reload mesh state from the database the way a server restart does, and say whether it loads.
    async fn state_loads(service: &MeshService) -> Result<(), crate::api::MeshApiError> {
        let server = service.dataplane().node_for_host("server").await.unwrap();
        crate::store::Store::new(service.pool_for_tests())
            .config(server)
            .await
            .map(|_| ())
    }

    /// Attach `host` as a node that supports rotation, presenting `key`.
    async fn attach_rotating_capable(
        service: &MeshService,
        host: &str,
        key: PublicKey,
    ) -> Result<(NodeId, bool), &'static str> {
        service
            .dataplane()
            .attach_named_with_capability(
                host,
                key,
                Some("192.0.2.2:44000".parse().unwrap()),
                false,
                None,
                true,
            )
            .await
    }

    /// #572 finding 1 (J1082): while node V rotates, V's old key lives only in its rotation row. Another node
    /// that presents that key used to pass the UNIQUE index on `mesh_nodes.public_key`, and every later load
    /// then failed with "Mesh allocation invalid." because the checkpoint held the key twice. Attach (an
    /// existing node or a new one) and enrollment must refuse it, and the state must keep loading.
    #[tokio::test]
    async fn no_node_can_take_a_key_another_node_is_rotating_away_from() {
        let service = service().await;
        let mallory = "00000000-0000-4000-8000-000000000002";
        attach_rotating_capable(&service, mallory, PublicKey([5; 32]))
            .await
            .unwrap();
        let (victim, victim_id, operation) = rotating_node(
            &service,
            "00000000-0000-4000-8000-000000000001",
            PublicKey([2; 32]),
        )
        .await;
        service
            .dataplane()
            .start_rotation_overlap(
                victim,
                &operation.operation_id,
                PublicKey([3; 32]),
                100,
                "test-boot",
                1_000,
            )
            .await
            .unwrap();
        let (current, _, phase, candidate, previous, _) = rotation_row(&service, victim_id).await;
        assert_eq!(phase.as_deref(), Some("overlap"));
        assert_eq!(current, vec![3; 32]);
        assert_eq!(candidate, Some(vec![3; 32]));
        assert_eq!(previous, Some(vec![2; 32]));
        state_loads(&service).await.unwrap();

        for key in [PublicKey([2; 32]), PublicKey([3; 32])] {
            assert!(
                attach_rotating_capable(&service, mallory, key)
                    .await
                    .is_err(),
                "an enrolled node must not re-attach with the rotating node's previous or candidate key"
            );
            assert!(
                attach_rotating_capable(&service, "00000000-0000-4000-8000-000000000003", key)
                    .await
                    .is_err(),
                "a new node must not attach with the rotating node's previous or candidate key"
            );
        }
        let enrolled = "00000000-0000-4000-8000-000000000004";
        sqlx::query(
            "INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)",
        )
        .bind(uuid::Uuid::parse_str(enrolled).unwrap().as_bytes().as_slice())
        .execute(&service.pool_for_tests())
        .await
        .unwrap();
        let enroll = service
            .execute(
                "owner",
                "mesh.node.enroll",
                &serde_json::to_vec(&serde_json::json!({
                    "name":"previous-key-squatter",
                    "public_key":PublicKey([2; 32]),
                    "host_id":enrolled
                }))
                .unwrap(),
                1_800_000_000,
            )
            .await;
        assert!(
            matches!(enroll, Err(crate::api::MeshApiError::Conflict)),
            "enrollment must refuse a key a rotating node still owns: {enroll:?}"
        );
        state_loads(&service)
            .await
            .expect("mesh state must still load after the refused attaches");

        // Once the rotation is committed (retiring), the previous key is still reserved.
        service
            .dataplane()
            .commit_rotation(victim, &operation.operation_id)
            .await
            .unwrap();
        let (_, _, phase, _, previous, _) = rotation_row(&service, victim_id).await;
        assert_eq!(phase.as_deref(), Some("retiring"));
        assert_eq!(previous, Some(vec![2; 32]));
        assert!(
            attach_rotating_capable(&service, mallory, PublicKey([2; 32]))
                .await
                .is_err()
        );
        state_loads(&service).await.unwrap();
    }

    /// #572 finding 1, the other direction: a node publishing its rotation candidate must not pick a key
    /// another rotating node still holds as its previous key, or the next load sees that key twice.
    #[tokio::test]
    async fn a_rotation_candidate_cannot_be_another_nodes_previous_key() {
        let service = service().await;
        let second = "00000000-0000-4000-8000-000000000002";
        let (mallory, _) = attach_rotating_capable(&service, second, PublicKey([5; 32]))
            .await
            .unwrap();
        let (victim, _, operation) = rotating_node(
            &service,
            "00000000-0000-4000-8000-000000000001",
            PublicKey([2; 32]),
        )
        .await;
        let store = service.dataplane();
        store
            .start_rotation_overlap(
                victim,
                &operation.operation_id,
                PublicKey([3; 32]),
                100,
                "test-boot",
                1_000,
            )
            .await
            .unwrap();
        let mallory_operation = "00000000-0000-4000-8000-0000000000aa";
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id=?,sequence=sequence+1 WHERE node_id=?",
        )
        .bind(mallory_operation)
        .bind(i64::try_from(mallory.0).unwrap())
        .execute(&service.pool_for_tests())
        .await
        .unwrap();
        let overlap = store
            .start_rotation_overlap(
                mallory,
                mallory_operation,
                PublicKey([2; 32]),
                100,
                "test-boot",
                1_000,
            )
            .await;
        assert!(
            matches!(overlap, Err(crate::api::MeshApiError::Conflict)),
            "a candidate equal to another node's previous key must be refused: {overlap:?}"
        );
        state_loads(&service)
            .await
            .expect("mesh state must still load after the refused overlap");
    }
}

/// Checks that DNS capability negotiation leaves legacy identity probes intact.
#[cfg(all(test, feature = "mesh-dns"))]
#[path = "review_j354_identity.rs"]
mod review_j354_identity;
