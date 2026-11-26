//! Persists public Mesh allocations and compiles the existing Access table under one writer transaction [165,166,216].
use crate::{
    configuration,
    dataplane::{Config, DefaultPolicy},
    diagnostics::{StorageDiagnostics, storage_error, storage_sql_error},
    policy::{
        address::AddressAllocator,
        coordinator::Coordinator,
        model::{MeshSettings, Node, NodeId, PublicKey},
        rules::{Arrow, Endpoint, RuleId, TrafficPolicy},
    },
};
pub use infraternal_plugin_api::host_name::machine_name;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};
#[derive(Serialize, Deserialize)]
struct State {
    settings: MeshSettings,
    allocation: AddressAllocator,
    server: NodeId,
    members: BTreeSet<NodeId>,
    /// Last derived origin zone lets a changed public hostname advance the existing config revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin_dns_suffix: Option<String>,
}
/// One DB stores inventory, stable non-recycled addresses and policy defaults; no private keys.
#[derive(Clone)]
struct Loaded {
    coordinator: std::sync::Arc<Coordinator>,
    /// The one address an older node gets for each peer: reflexive when known, else the guess.
    endpoints: std::sync::Arc<BTreeMap<NodeId, SocketAddr>>,
    /// Every known direct-path candidate per node (#515); [`crate::candidates::order`] picks per pair.
    candidates: std::sync::Arc<BTreeMap<NodeId, crate::candidates::NodeCandidates>>,
    /// Nodes that walk an ordered candidate list; the rest get `endpoints` alone.
    accepts_candidates: std::sync::Arc<BTreeSet<NodeId>>,
    /// Nodes that understand `Peer::ipv4_only` and report their IPv6 state (#578, J1142).
    reports_ipv6: std::sync::Arc<BTreeSet<NodeId>>,
    /// Nodes that understand subnet routes in snapshots (`PeerPolicy::networks`, D197 M3).
    reports_routes: std::sync::Arc<BTreeSet<NodeId>>,
    /// Nodes whose last report said IPv6 is off on their mesh link; only nodes in `reports_ipv6` appear.
    ipv4_only: std::sync::Arc<BTreeSet<NodeId>>,
    /// Nodes that understand `Peer::side_port` and report whether they take marked datagrams
    /// (#260, J1211).
    reports_side_port: std::sync::Arc<BTreeSet<NodeId>>,
    /// Nodes whose last report said they run the side-mark receive rule with their second socket
    /// on; only nodes in `reports_side_port` appear.
    side_port: std::sync::Arc<BTreeSet<NodeId>>,
    /// The reflexive addresses published for each node before its current one, oldest first (J585 F3).
    reflexive_history: std::sync::Arc<BTreeMap<NodeId, Vec<SocketAddr>>>,
    default: DefaultPolicy,
    revision: u64,
    /// The durable authenticated deployment authority for every compiled node snapshot.
    authority_epoch: String,
    /// Durable key rotation phase per node; compiling a view rewrites peer keys from it.
    rotations: std::sync::Arc<BTreeMap<NodeId, RotationRecord>>,
    /// Synthetic unnamed labels remain reachable without creating DNS records.
    #[cfg(feature = "mesh-dns")]
    dns_placeholders: std::sync::Arc<BTreeSet<NodeId>>,
}

/// Where one node's key rotation stands: preparing the candidate, overlapping both keys, routing on the candidate
/// (retiring), then dropping the old key (cleanup).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RotationPhase {
    Preparing,
    Overlap,
    Retiring,
    Cleanup,
}
impl RotationPhase {
    /// The phase's name in `mesh_node_key_rotation.rotation_phase`.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Overlap => "overlap",
            Self::Retiring => "retiring",
            Self::Cleanup => "cleanup",
        }
    }
}

/// Durable public rotation metadata needed to compile each node's current phase.
#[derive(Clone, Debug)]
pub(crate) struct RotationRecord {
    pub(crate) phase: RotationPhase,
    pub(crate) candidate_key: Option<PublicKey>,
    pub(crate) previous_key: Option<PublicKey>,
    pub(crate) operation_id: String,
    pub(crate) sequence: u64,
    pub(crate) revision: Option<u64>,
    pub(crate) started_at: Option<i64>,
    pub(crate) monotonic: Option<i64>,
}

/// Durable scheduler view for one node. The monotonic deadline is tied to the recorded boot ID.
#[derive(Clone, Debug)]
pub(crate) struct RotationSchedule {
    pub(crate) due_in_secs: u64,
    pub(crate) supported: bool,
    pub(crate) all_nodes_supported: bool,
    pub(crate) record: Option<RotationRecord>,
}
/// Workers retain the shared source of their acknowledged version. Recompiling
/// its node view preserves exact deltas while idle memory stays proportional to
/// shared inventory and policy, rather than the number of delivered peer maps.
#[derive(Clone)]
pub(crate) struct Snapshot {
    loaded: Loaded,
    default_dns_suffix: String,
    /// The server's infraternal control-plane ports when this snapshot was taken.
    control_plane: TrafficPolicy,
}
impl Snapshot {
    /// Give a node that walks candidates each peer's full ordered list (#515, D391): `endpoint` is the first to
    /// try and `candidates` the rest. LAN addresses appear only for peers behind this node's own public address
    /// ([`crate::candidates::order`]). An older node keeps the single address the compiler already set.
    ///
    /// The server's own node gets no list either: it only answers its nodes, which always reach it first, and it
    /// observes their server-reflexive addresses from where its device sends. A walk there would move that address
    /// away from what the nodes' packets proved.
    ///
    /// A peer without network access in either direction gets no list (J585 F1): the compiler keeps denied peers in
    /// every snapshot so a later grant changes only policy, and a LAN address must not reach a neighbour the Access
    /// policy keeps apart. A grant changes the policy, which recompiles the snapshot with the list.
    fn order_candidates(&self, node: NodeId, config: &mut Config) {
        if !self.loaded.accepts_candidates.contains(&node) || Some(node) == config.server {
            return;
        }
        let empty = crate::candidates::NodeCandidates::default();
        let viewer = self.loaded.candidates.get(&node).unwrap_or(&empty);
        for (peer, policy) in &mut config.peers {
            if !policy.has_network_access() {
                continue;
            }
            let Some(known) = self.loaded.candidates.get(peer) else {
                continue;
            };
            let mut list = crate::candidates::order(viewer, known).into_iter();
            if let Some(first) = list.next() {
                policy.peer.endpoint = Some(first);
                policy.peer.candidates = list.collect();
            }
        }
    }
    /// Mark each peer that runs IPv4-only, for a node that understands the mark (#578, J1142).
    ///
    /// The receiver then installs no IPv6 route or allowed IP for that peer and its mesh DNS
    /// answers no `AAAA` for the name. An older receiver gets no mark, because its decoder refuses
    /// unknown fields; it keeps today's behaviour. Marks follow the peers' latest reports, so a
    /// peer whose IPv6 comes back is unmarked by the next snapshot.
    /// Drop subnet routes from the snapshot of a node that does not understand them (D197 M3).
    ///
    /// Its decoder refuses unknown fields, so the field would make it refuse the whole snapshot.
    /// Without the field it simply reaches no network, which is the safe side.
    fn gate_networks(&self, node: NodeId, config: &mut Config) {
        if self.loaded.reports_routes.contains(&node) {
            return;
        }
        for policy in config.peers.values_mut() {
            policy.networks = crate::dataplane::PeerNetworks::default();
        }
    }
    fn mark_ipv4_only(&self, node: NodeId, config: &mut Config) {
        if !self.loaded.reports_ipv6.contains(&node) {
            return;
        }
        for (peer, policy) in &mut config.peers {
            policy.peer.ipv4_only = self.loaded.ipv4_only.contains(peer);
        }
    }
    /// Mark each peer that takes marked datagrams on its second socket (#260, J1211), but only in the
    /// snapshot of a node that understands the field: `Peer` refuses unknown fields, so an older node
    /// would refuse the whole snapshot. A peer that never said so is never marked, so nobody sends it a
    /// marked datagram (kernel `WireGuard` and plain `GotaTun` drop those).
    fn mark_side_port(&self, node: NodeId, config: &mut Config) {
        if !self.loaded.reports_side_port.contains(&node) {
            return;
        }
        for (peer, policy) in &mut config.peers {
            policy.peer.side_port = self.loaded.side_port.contains(peer);
        }
    }
    /// Whether any node is past preparation, so applied views need durable acknowledgments before the rotation moves on.
    pub(crate) fn acknowledgments_required(&self) -> bool {
        self.loaded
            .rotations
            .values()
            .any(|rotation| rotation.phase != RotationPhase::Preparing)
    }
    /// Compile `node`'s configuration from this snapshot, applying any key rotation phase to its own and its peers' keys.
    pub(crate) fn config(&self, node: NodeId) -> Result<Config, crate::api::MeshApiError> {
        use crate::{api::MeshApiError, policy::model::MeshError};
        let coordinator = &self.loaded.coordinator;
        let endpoints = &self.loaded.endpoints;
        let default = self.loaded.default;
        let revision = self.loaded.revision;
        let rotations = &self.loaded.rotations;
        #[cfg(feature = "cutoff-measure")]
        let _compile = crate::cutoff_measure::Stage::new(node, revision, "compile");
        let compiled = configuration::compile_with_dns_suffix(
            coordinator,
            node,
            default,
            endpoints,
            &self.default_dns_suffix,
            &self.control_plane,
        );
        let mut config = compiled.map_err(|error| match error {
            MeshError::UnknownNode => MeshApiError::NotFound,
            _ => storage_error("configuration compilation failed"),
        })?;
        config.authority_epoch = Some(self.loaded.authority_epoch.clone());
        config.rotation_operation =
            rotations
                .get(&node)
                .map(|rotation| crate::dataplane::RotationContinuation {
                    operation_id: rotation.operation_id.clone(),
                    sequence: rotation.sequence,
                });
        self.order_candidates(node, &mut config);
        self.mark_ipv4_only(node, &mut config);
        self.mark_side_port(node, &mut config);
        self.gate_networks(node, &mut config);
        #[cfg(feature = "mesh-dns")]
        {
            if self.loaded.dns_placeholders.contains(&node) {
                config.name = None;
            }
            config
                .peer_names
                .retain(|peer, _| !self.loaded.dns_placeholders.contains(peer));
        }
        if let Some(rotation) = rotations.get(&node)
            && rotation.phase == RotationPhase::Overlap
        {
            config.local_key = rotation.previous_key;
        }
        for (peer_id, peer) in &mut config.peers {
            let Some(rotation) = rotations.get(peer_id) else {
                continue;
            };
            match rotation.phase {
                RotationPhase::Preparing => {}
                RotationPhase::Overlap => {
                    let previous = rotation
                        .previous_key
                        .ok_or_else(|| storage_error("Mesh rotation state invalid."))?;
                    let candidate = rotation
                        .candidate_key
                        .ok_or_else(|| storage_error("Mesh rotation state invalid."))?;
                    if peer.peer.key != candidate || previous == candidate {
                        return Err(storage_error("Mesh rotation state invalid."));
                    }
                    peer.peer.key = previous;
                    peer.peer.previous_key = Some(candidate);
                    // The candidate is installed before the node changes its
                    // interface key. Keep routes on the old key until the node
                    // confirms the local switch.
                    peer.peer.previous_active = false;
                }
                RotationPhase::Retiring => {
                    peer.peer.previous_active = false;
                }
                RotationPhase::Cleanup => {
                    peer.peer.previous_key = None;
                    peer.peer.previous_active = false;
                }
            }
        }
        config.version = revision;
        Ok(config)
    }

    /// Compile a node view for the identity it presented on the authenticated channel.
    pub(crate) fn config_for_identity(
        &self,
        node: NodeId,
        identity: crate::policy::model::PublicKey,
    ) -> Result<Config, crate::api::MeshApiError> {
        let mut config = self.config(node)?;
        if let Some(rotation) = self.loaded.rotations.get(&node)
            && rotation.phase == RotationPhase::Overlap
        {
            let previous = rotation
                .previous_key
                .ok_or_else(|| storage_error("Mesh rotation state invalid."))?;
            let candidate = rotation
                .candidate_key
                .ok_or_else(|| storage_error("Mesh rotation state invalid."))?;
            if previous == candidate || (identity != previous && identity != candidate) {
                return Err(storage_error(
                    "Mesh node identity does not match rotation state.",
                ));
            }
            config.local_key = Some(identity);
        } else if config.local_key.is_some_and(|local| local != identity) {
            return Err(storage_error(
                "Mesh node identity does not match rotation state.",
            ));
        }
        Ok(config)
    }
}
/// Who named a node; a higher rank may move a lower one's automatic name aside (migration 0026, #236).
fn rank(source: &str) -> u8 {
    match source {
        "hand" => 4,
        "server" => 3,
        "record" => 2,
        "reported" => 1,
        _ => 0,
    }
}
/// The label no remote machine may be called automatically: viewers read it as the server.
const SERVER_LABEL: &str = "server";
/// A node's current name, as naming sees it.
struct Named {
    id: i64,
    name: String,
    source: String,
    host: Option<String>,
    /// The name its source asked for before any suffix (migration 0027); `None` when that is `name` itself.
    claim: Option<String>,
}
/// One automatic name change, applied in order and written to the audit log with the attach's revision.
struct Renamed {
    id: i64,
    from: String,
    to: String,
    source: String,
    /// The claim to store with the new name; `None` keeps the stored one (a node moved aside keeps its claim).
    claim: Option<String>,
}
/// What one attach names: the attaching node's name and who gave it, and the other nodes it moves aside.
struct Naming {
    name: String,
    source: &'static str,
    moved: Vec<Renamed>,
    /// The name asked for before any suffix; `None` for a placeholder.
    claim: Option<String>,
}
/// The name for node `except` among `base` (unless `skip`) and `base-2` … `base-9`: one no other node holds and
/// that is not `taken` (the name being handed to someone else in the same change). The node's current name wins
/// when it is one of the suffixes and still free, so a node at `web-3` stays there when `web-2` frees up; `base`
/// itself, when free, still wins over any suffix.
fn free_name(nodes: &[Named], base: &str, except: i64, skip: bool, taken: &str) -> Option<String> {
    let stem = base[..base.len().min(61)].trim_end_matches('-');
    let available = |name: &str| {
        name != taken
            && !nodes
                .iter()
                .any(|node| node.id != except && node.name == name)
    };
    if !skip && available(base) {
        return Some(base.to_owned());
    }
    let suffixed = (2..=9).map(|n| format!("{stem}-{n}"));
    let current = nodes
        .iter()
        .find(|node| node.id == except)
        .map(|node| node.name.as_str());
    if let Some(current) = current
        && available(current)
        && suffixed.clone().any(|name| name == current)
    {
        return Some(current.to_owned());
    }
    suffixed.into_iter().find(|name| available(name))
}
/// Finds a free name from `base` (a fallback such as `linux-0a1b2c`, D339), extending beyond the short common
/// suffix range when inventory is large. The same rule as [`free_name`], so a node keeps its suffix across attaches.
fn fallback_name(nodes: &[Named], base: &str, except: i64, taken: &str) -> String {
    if let Some(name) = free_name(nodes, base, except, false, taken) {
        return name;
    }
    let mut suffix = 10_u64;
    loop {
        let name = format!("{base}-{suffix}");
        if name != taken
            && !nodes
                .iter()
                .any(|node| node.id != except && node.name == name)
        {
            return name;
        }
        suffix += 1;
    }
}
/// Moves `holder` off `name`, which a stronger claim takes: to the first free suffix of the holder's own claim
/// (`web-2` claimed `web` goes to `web-3`, not `web-2-2`), else past `-9` (`web-10` …).
/// Its claim and source stay. Exhaustion must keep searching rather than turn into a different rename result (#236).
fn move_aside(nodes: &[Named], holder: &Named, name: &str) -> Renamed {
    let base = holder.claim.as_deref().unwrap_or(&holder.name);
    let to = fallback_name(nodes, base, holder.id, name);
    Renamed {
        id: holder.id,
        from: holder.name.clone(),
        to,
        source: holder.source.clone(),
        claim: None,
    }
}
/// Names a node of `host` (`id`, currently `current`) that `wanted` names, given every other node's name and the
/// names the owner gave other hosts (`records`). Pure, so the whole decision is one place and testable.
///
/// Free: it takes the name. Held by a node of lower rank (an automatic name, never a person's): that node moves
/// aside to the next free suffix of its *own* claim and this one takes it. Held by an equal or higher rank: this
/// node, the newcomer, gets the suffix (`minipc01-2` … `-9`). A node that already holds a free suffix of its claim
/// keeps it rather than shuffling to a lower one, so restarts in any order rename nothing. A reported hostname
/// also yields to every other host's record name, enrolled or not, so a machine cannot pose as one the owner
/// named. With no name, a node gets `fallback` (D339: `<os>-<first 6 characters of the id>`), suffixed on a
/// collision; it keeps that name, suffix included, until a real one is known.
/// `None` keeps the current name.
fn naming(
    nodes: &[Named],
    id: i64,
    host: &str,
    current: Option<&str>,
    wanted: Option<(String, &'static str)>,
    records: &[String],
    fallback: &str,
) -> Option<Naming> {
    let free = |base: &str, except: i64, skip: bool, taken: &str| {
        free_name(nodes, base, except, skip, taken)
    };
    let Some((wanted, source)) = wanted else {
        // Two older placeholder schemes are replaced: `mesh-<host>` (before names were known) and the
        // `unnamed` / `unnamed-<n>` labels this rule supersedes.
        let stale_placeholder = current
            .is_some_and(|name| name == format!("mesh-{host}") || is_legacy_unnamed_label(name));
        if current.is_some() && !stale_placeholder {
            return None;
        }
        let name = if host == SERVER_LABEL {
            SERVER_LABEL.to_owned()
        } else {
            // A node already at a free suffix of the fallback keeps it (see `free_name`), so restarts rename nothing.
            fallback_name(nodes, fallback, id, "")
        };
        if current == Some(name.as_str()) {
            return None;
        }
        return Some(Naming {
            name,
            source: "placeholder",
            moved: Vec::new(),
            claim: None,
        });
    };
    let claim = wanted.clone();
    let holder = nodes
        .iter()
        .find(|node| node.id != id && node.name == wanted);
    let mut moved = Vec::new();
    let name = if source == "reported" && records.contains(&wanted) {
        free(&wanted, id, true, "")
    } else if let Some(holder) = holder.filter(|holder| rank(&holder.source) < rank(source)) {
        moved.push(move_aside(nodes, holder, &wanted));
        Some(wanted)
    } else {
        free(&wanted, id, holder.is_some(), "")
    };
    match (name, current) {
        (Some(name), current) if current != Some(name.as_str()) => Some(Naming {
            name,
            source,
            moved,
            claim: Some(claim),
        }),
        (None, Some(current)) if current == format!("mesh-{host}") => {
            naming(nodes, id, host, Some(current), None, records, fallback)
        }
        (Some(_), _) | (None, Some(_)) => None,
        (None, None) => naming(nodes, id, host, None, None, records, fallback),
    }
}

/// Whether `key` is already one of another node's keys: its current key, or
/// the candidate or previous key of a rotation it has open (D166).
///
/// `mesh_nodes.public_key` is UNIQUE, but during a rotation a node's old key
/// lives only in its rotation row, and the next load gives every node its
/// previous key too. A second node holding that key made every load fail
/// ("Mesh allocation invalid.") until someone edited the database (#572
/// finding 1). Every write that gives a node a key (attach, enrollment, a
/// rotation's candidate) checks here first, in the same transaction.
/// `node` is the node that would hold the key, `None` for a new one.
pub(crate) async fn key_held_by_another_node(
    connection: &mut sqlx::SqliteConnection,
    key: &[u8],
    node: Option<i64>,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mesh_nodes WHERE public_key=?1 AND id IS NOT ?2) \
             OR EXISTS(SELECT 1 FROM mesh_node_key_rotation WHERE node_id IS NOT ?2 \
                       AND (candidate_public_key=?1 OR previous_public_key=?1))",
    )
    .bind(key)
    .bind(node)
    .fetch_one(connection)
    .await
}

/// The `unnamed` / `unnamed-<n>` labels older versions stored for nodes without a name (migration 0029). Only used
/// to recognise them for replacement: a person may now pick such a name, which then has source `hand` and is never
/// touched, and a machine may report it as its hostname.
fn is_legacy_unnamed_label(name: &str) -> bool {
    name == "unnamed"
        || name.strip_prefix("unnamed-").is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        })
}
/// Abandon a node's open rotation because it reattached without rotation support (J252 P2, D166, D352).
///
/// A node that restarts on an engine that cannot rotate (kernel to `GotaTun`, D346), loses its journal or runs an
/// older binary keeps only one key. Keeping the rotation open would refuse that node forever, since only its own
/// commit can close it, and the overlap could later publish a candidate it no longer holds. The caller runs
/// this inside the attach transaction that records the lost support and the key the node presents, and bumps
/// the revision, so peers drop the abandoned candidate or predecessor in the same view. The sequence moves on,
/// so a step still in flight for the abandoned operation matches nothing.
async fn abandon_rotation(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    node_id: i64,
) -> Result<(), &'static str> {
    sqlx::query(
        "UPDATE mesh_node_key_rotation SET candidate_public_key=NULL,previous_public_key=NULL,rotation_phase=NULL,\
         rotation_started_at=NULL,rotation_boot_id=NULL,rotation_monotonic=NULL,operation_id=NULL,rotation_revision=NULL,\
         local_committed=0,sequence=sequence+1 WHERE node_id=? AND rotation_phase IS NOT NULL",
    )
    .bind(node_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| "Mesh storage unavailable.")?;
    Ok(())
}

/// What names a node of `host`, and who gives it, with the names the owner gave every other host.
///
/// The server is named after its own hostname; a remote machine after the name the owner typed when adding it,
/// else its reported hostname. `server` is never a remote machine's automatic name.
/// Coordinates kept for pending cleanup do not reserve a removed machine's name.
async fn wanted_name(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    host: &str,
    server: bool,
    reported: Option<&str>,
) -> Result<WantedName, &'static str> {
    let own = host.replace('-', "").to_ascii_lowercase();
    let mut recorded = None;
    let mut os = None;
    let mut records = Vec::new();
    for row in
        sqlx::query("SELECT lower(hex(b.host_id)) AS host,b.address,b.os FROM remote_host_bootstrap b WHERE NOT EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=b.host_id)")
            .fetch_all(&mut **tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?
    {
        let name = machine_name(&row.get::<String, _>("address"));
        if row.get::<String, _>("host") == own {
            recorded = name;
            os = row.get::<Option<String>, _>("os");
        } else {
            records.extend(name);
        }
    }
    let (cached, reported_os) = if let Ok(id) = uuid::Uuid::parse_str(host) {
        sqlx::query_as::<_, (Option<String>, Option<String>)>(
            "SELECT hostname,reported_os FROM remote_hosts WHERE id=?",
        )
        .bind(id.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?
        .unwrap_or((None, None))
    } else {
        (None, None)
    };
    // The SSH probe's OS name wins, as in the host list; a host that joined by invitation has no probe row, so
    // the OS its agent reported in the Hello names its fallback (D339, #337).
    let os = os.or(reported_os);
    let usable = |name: &String| name != SERVER_LABEL;
    let wanted = if server {
        reported.and_then(machine_name).map(|name| (name, "server"))
    } else {
        recorded
            .filter(usable)
            .map(|name| (name, "record"))
            .or_else(|| {
                reported
                    .and_then(machine_name)
                    .filter(usable)
                    .or_else(|| cached.as_deref().and_then(machine_name).filter(usable))
                    .map(|name| (name, "reported"))
            })
    };
    let fallback = infraternal_plugin_api::host_name::fallback_machine_name(os.as_deref(), &own);
    Ok((wanted, records, fallback))
}
/// What `wanted_name` decides: the name to ask for and who gives it, the names the owner gave other hosts, and the
/// fallback name for a node that gets none (D339).
type WantedName = (Option<(String, &'static str)>, Vec<String>, String);
/// Frees `name` for `actor`'s choice on node `id` (`None` while enrolling a new one). A person outranks every
/// automatic name (migration 0026), so a node holding `name` by record, report, placeholder or the server's own
/// hostname moves aside to a suffix of its own claim, audited under `actor` as an automatic rename with the
/// change's revision. Returns the nodes moved so their scopes receive the change notice. The caller must
/// authorize global node management before looking up names: target-only authority would expose hidden names
/// through a conflict or require moving a holder the caller cannot manage.
///
/// Only the label `server` and another person's name refuse here. Global node managers can already rename
/// automatic holders directly, so reported and server hostnames answer exactly as free names do.
pub(crate) async fn make_room(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    actor: &str,
    id: Option<i64>,
    name: &str,
) -> Result<Vec<i64>, crate::api::MeshApiError> {
    let unavailable = |_| storage_error("Mesh storage unavailable.");
    let nodes = named_nodes(tx).await.map_err(unavailable)?;
    // `server` is reserved for the server's node, so no other node may carry it: nobody sees two machines a
    // viewer could take for the server and `server.<suffix>` never points at a remote. The server's hostname is
    // an automatic name like any other, and only global node managers (who see every name) reach this code.
    // Before the server's node exists, `server` is still kept for it.
    if name == SERVER_LABEL
        && !nodes
            .iter()
            .any(|node| node.host.as_deref() == Some(SERVER_LABEL) && Some(node.id) == id)
    {
        return Err(crate::api::MeshApiError::Reserved);
    }
    let Some(holder) = nodes
        .iter()
        .find(|node| Some(node.id) != id && node.name == name)
    else {
        return Ok(Vec::new());
    };
    if rank(&holder.source) >= rank("hand") {
        return Err(crate::api::MeshApiError::Conflict);
    }
    let moved = [move_aside(&nodes, holder, name)];
    rename(tx, &moved)
        .await
        .map_err(|_| crate::api::MeshApiError::Conflict)?;
    // The person's change takes the next revision (`finish_change`); its audit row and this one share it.
    let revision: i64 = sqlx::query_scalar("SELECT revision+1 FROM mesh_state WHERE singleton=1")
        .fetch_one(&mut **tx)
        .await
        .map_err(unavailable)?;
    audit_renames(tx, &moved, revision, actor)
        .await
        .map_err(|_| storage_error("Mesh storage unavailable."))?;
    Ok(vec![holder.id])
}
/// Every node's name as naming sees it, read once per change.
async fn named_nodes(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<Vec<Named>, sqlx::Error> {
    Ok(
        sqlx::query("SELECT id,name,name_source,dataplane_host,name_claim FROM mesh_nodes")
            .fetch_all(&mut **tx)
            .await?
            .iter()
            .map(|row| Named {
                id: row.get("id"),
                name: row.get("name"),
                source: row.get("name_source"),
                host: row.get("dataplane_host"),
                claim: row.get("name_claim"),
            })
            .collect(),
    )
}
/// Applies automatic renames in order: a node moved aside first frees the name the next one takes.
async fn rename(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    renamed: &[Renamed],
) -> Result<(), &'static str> {
    for rename in renamed {
        sqlx::query(
            "UPDATE mesh_nodes SET name=?,name_source=?,name_claim=COALESCE(?,name_claim) WHERE id=?",
        )
        .bind(&rename.to)
        .bind(&rename.source)
        .bind(&rename.claim)
        .bind(rename.id)
            .execute(&mut **tx)
            .await
            .map_err(|_| "Mesh identity conflicts.")?;
    }
    Ok(())
}
/// Audits automatic renames with the change's revision, under the person who caused them (`actor`), else under
/// the instance owner: an attach has no person, and only the owner adds hosts. Each row says it was automatic.
async fn audit_renames(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    renamed: &[Renamed],
    revision: i64,
    actor: &str,
) -> Result<(), &'static str> {
    for rename in renamed {
        let detail = serde_json::json!({"node_id":rename.id,"name":rename.to,"previous":rename.from,"source":rename.source,"automatic":true});
        sqlx::query("INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json) SELECT id,'mesh.node.name',?1,?2,unixepoch(),?3 FROM users WHERE id=?4 OR owner=1 ORDER BY id=?4 DESC,rowid LIMIT 1")
            .bind(rename.id.to_string())
            .bind(revision)
            .bind(detail.to_string())
            .bind(actor)
            .execute(&mut **tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
    }
    Ok(())
}
/// The coordinator's durable store: inventory, addresses, policy and rotation state, with a cached snapshot.
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    cache: std::sync::Arc<tokio::sync::Mutex<Option<Loaded>>>,
    /// Server-process authority shared by every Store handle and persisted before a snapshot is published.
    authority_epoch: std::sync::Arc<str>,
    // Applied-view receipts are valid only for this server process lifetime.
    server_instance: std::sync::Arc<str>,
    load_diagnostics: StorageDiagnostics,
    config_diagnostics: StorageDiagnostics,
    preview_diagnostics: StorageDiagnostics,
    default_dns_suffix: String,
    /// Where the server's infraternal control plane listens; shared by every
    /// clone, set once by the server ([`Self::set_control_plane`]).
    control_plane: std::sync::Arc<std::sync::OnceLock<ControlPlane>>,
}

/// The ports every member may reach on the server's own node: the server's
/// infraternal control-plane listeners (D215). Read again for each snapshot,
/// because a fresh server starts its listener only after its CA is set up.
pub type ControlPlane = std::sync::Arc<dyn Fn() -> TrafficPolicy + Send + Sync>;

/// The attach refusal for a node whose rotation support is unknown while its rotation is open (J262). It is the
/// only refusal that clears up by itself once the node's probe answers again, so the coordinator retries it on a
/// timer (J273 P3-2, J284 P3-a).
pub(crate) const ROTATION_IN_PROGRESS: &str = "Mesh key rotation is in progress.";

/// Share one authority across all stores in this server process; a new process gets a fresh UUID.
static PROCESS_AUTHORITY_EPOCH: std::sync::LazyLock<std::sync::Arc<str>> =
    std::sync::LazyLock::new(|| uuid::Uuid::new_v4().to_string().into());

/// Return this process's stable Mesh authority epoch to every Store handle.
fn process_authority_epoch() -> std::sync::Arc<str> {
    std::sync::Arc::clone(&PROCESS_AUTHORITY_EPOCH)
}

impl Store {
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self::with_public_origin(pool, "")
    }

    /// Use the configured server origin to derive the default proxy exposure suffix.
    ///
    /// The optional Mesh DNS resolver remains controlled by `mesh-dns`; carrying the public
    /// suffix here lets publication use the accepted coordinator identity in ordinary builds.
    /// An explicit Mesh suffix still takes precedence when that resolver feature is enabled.
    #[must_use]
    pub fn with_public_origin(pool: SqlitePool, public_origin: &str) -> Self {
        Self::with_authority_epoch(pool, public_origin, process_authority_epoch())
    }

    /// Create a store that shares its process authority with every other handle from this server.
    fn with_authority_epoch(
        pool: SqlitePool,
        public_origin: &str,
        authority_epoch: std::sync::Arc<str>,
    ) -> Self {
        let default_dns_suffix = configuration::default_dns_suffix_from_origin(public_origin);
        Self {
            pool,
            cache: std::sync::Arc::default(),
            authority_epoch,
            server_instance: uuid::Uuid::new_v4().to_string().into(),
            load_diagnostics: StorageDiagnostics::new("mesh.coordinator.load"),
            config_diagnostics: StorageDiagnostics::new("mesh.coordinator.config"),
            preview_diagnostics: StorageDiagnostics::new("mesh.default.preview"),
            default_dns_suffix,
            control_plane: std::sync::Arc::default(),
        }
    }

    /// Give unit tests a distinct process authority without changing the production singleton.
    #[cfg(test)]
    pub(crate) fn with_authority_epoch_for_test(
        pool: SqlitePool,
        authority_epoch: std::sync::Arc<str>,
    ) -> Self {
        Self::with_authority_epoch(pool, "", authority_epoch)
    }
    /// The server instance ID that tags acknowledgment receipts.
    #[cfg(test)]
    pub(crate) fn server_instance(&self) -> &str {
        &self.server_instance
    }
    /// Record a kernel-applied view only while a rotation needs durable receipts.
    /// Return whether the receipt advanced; identical or stale receipts do not write.
    /// A new server instance overwrites old receipts so restart always reapplies views.
    pub(crate) async fn acknowledge_applied(
        &self,
        node: NodeId,
        revision: u64,
    ) -> Result<bool, crate::api::MeshApiError> {
        let node =
            i64::try_from(node.0).map_err(|_| storage_error("Mesh applied node invalid."))?;
        let revision =
            i64::try_from(revision).map_err(|_| storage_error("Mesh applied revision invalid."))?;
        // Read first so a quiet worker does not even acquire SQLite's writer lock. The
        // UPSERT guard repeats the comparison atomically for concurrent/stale deliveries.
        let needed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mesh_node_key_rotation WHERE rotation_phase IS NOT NULL) \
             AND NOT EXISTS(SELECT 1 FROM mesh_node_applied WHERE node_id=? AND server_instance=? AND revision>=?)",
        )
        .bind(node)
        .bind(self.server_instance.as_ref())
        .bind(revision)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| storage_sql_error(error))?;
        if !needed {
            return Ok(false);
        }
        let result = sqlx::query(
            "INSERT INTO mesh_node_applied(node_id,revision,server_instance) VALUES(?,?,?) \
             ON CONFLICT(node_id) DO UPDATE SET revision=excluded.revision,server_instance=excluded.server_instance \
             WHERE mesh_node_applied.server_instance<>excluded.server_instance OR mesh_node_applied.revision<excluded.revision",
        )
        .bind(node)
        .bind(revision)
        .bind(self.server_instance.as_ref())
        .execute(&self.pool)
        .await
        .map_err(|error| storage_sql_error(error))?;
        Ok(result.rows_affected() != 0)
    }
    /// Check whether every currently reachable peer has applied a rotation revision.
    pub(crate) async fn rotation_acks_ready(
        &self,
        revision: u64,
        reachable: &BTreeSet<NodeId>,
    ) -> Result<bool, crate::api::MeshApiError> {
        if reachable.is_empty() {
            return Ok(true);
        }
        let revision = i64::try_from(revision)
            .map_err(|_| storage_error("Mesh rotation revision invalid."))?;
        let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "SELECT COUNT(*) FROM mesh_node_applied WHERE server_instance=",
        );
        query
            .push_bind(self.server_instance.as_ref())
            .push(" AND revision >= ")
            .push_bind(revision)
            .push(" AND node_id IN (");
        let mut separated = query.separated(",");
        for node in reachable {
            separated.push_bind(
                i64::try_from(node.0).map_err(|_| storage_error("Mesh rotation peer invalid."))?,
            );
        }
        separated.push_unseparated(")");
        let applied: i64 = query
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await
            .map_err(|error| storage_sql_error(error))?;
        Ok(usize::try_from(applied).ok() == Some(reachable.len()))
    }
    /// Read and reconcile one node's persisted schedule and overlap clock.
    /// A reboot restarts the minimum overlap instead of allowing wall time to retire a key early.
    // Keep schedule repair, phase validation, and commit in one writer transaction.
    pub(crate) async fn rotation_schedule(
        &self,
        node: NodeId,
        wall_secs: i64,
        boot_id: &str,
        monotonic_secs: i64,
        monotonic_nanos: i64,
    ) -> Result<RotationSchedule, crate::api::MeshApiError> {
        use crate::api::MeshApiError;
        let node_id = i64::try_from(node.0).map_err(|_| MeshApiError::InvalidInput)?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(storage_sql_error)?;
        let row = sqlx::query(
            "SELECT n.public_key,r.last_rotation,r.schedule_boot_id,r.schedule_monotonic,r.schedule_period_secs,\
                    r.candidate_public_key,r.previous_public_key,r.rotation_phase,r.operation_id,r.sequence,r.rotation_revision,\
                    r.rotation_started_at,r.rotation_boot_id,r.rotation_monotonic,n.key_rotation_supported,\
                    d.rotation_period_secs \
             FROM mesh_node_key_rotation AS r \
             JOIN mesh_nodes AS n ON n.id=r.node_id \
             JOIN mesh_dataplane AS d ON d.singleton=1 WHERE r.node_id=?",
        )
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_sql_error)?
        .ok_or(MeshApiError::NotFound)?;
        let period: i64 = row
            .try_get("rotation_period_secs")
            .map_err(storage_sql_error)?;
        if period <= 0 {
            return Err(storage_error("Mesh rotation period invalid."));
        }
        let last_rotation: i64 = row.try_get("last_rotation").map_err(storage_sql_error)?;
        let mut schedule_boot: String =
            row.try_get("schedule_boot_id").map_err(storage_sql_error)?;
        let mut schedule_deadline: i64 = row
            .try_get("schedule_monotonic")
            .map_err(storage_sql_error)?;
        let mut scheduled_period: i64 = row
            .try_get("schedule_period_secs")
            .map_err(storage_sql_error)?;
        let phase: Option<String> = row.try_get("rotation_phase").map_err(storage_sql_error)?;
        let mut rotation_boot: Option<String> =
            row.try_get("rotation_boot_id").map_err(storage_sql_error)?;
        let mut rotation_monotonic: Option<i64> = row
            .try_get("rotation_monotonic")
            .map_err(storage_sql_error)?;

        if phase.is_none()
            && (schedule_boot != boot_id || scheduled_period != period || schedule_deadline == 0)
        {
            let due_wall = last_rotation.saturating_add(period);
            let remaining = due_wall.saturating_sub(wall_secs).max(0);
            schedule_deadline = monotonic_secs.saturating_add(remaining);
            schedule_boot = boot_id.to_owned();
            scheduled_period = period;
            sqlx::query(
                "UPDATE mesh_node_key_rotation SET schedule_boot_id=?,schedule_monotonic=?,schedule_period_secs=? WHERE node_id=? AND rotation_phase IS NULL",
            )
            .bind(&schedule_boot)
            .bind(schedule_deadline)
            .bind(scheduled_period)
            .bind(node_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_sql_error)?;
        }
        if phase.as_deref().is_some_and(|phase| phase != "preparing")
            && rotation_boot.as_deref() != Some(boot_id)
        {
            rotation_boot = Some(boot_id.to_owned());
            rotation_monotonic = Some(monotonic_nanos);
            sqlx::query(
                "UPDATE mesh_node_key_rotation SET rotation_boot_id=?,rotation_monotonic=? WHERE node_id=? AND rotation_phase IS NOT NULL",
            )
            .bind(boot_id)
            .bind(monotonic_nanos)
            .bind(node_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_sql_error)?;
        }

        let unsupported: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mesh_nodes WHERE key_rotation_supported=0)",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_sql_error)?;
        let supported: bool = row
            .try_get("key_rotation_supported")
            .map_err(storage_sql_error)?;
        let record = if let Some(phase) = phase {
            let candidate: Option<Vec<u8>> = row
                .try_get("candidate_public_key")
                .map_err(storage_sql_error)?;
            let candidate_key = candidate
                .map(|key| {
                    key.try_into()
                        .map(PublicKey)
                        .map_err(|_| storage_error("Mesh rotation candidate invalid."))
                })
                .transpose()?;
            let previous: Option<Vec<u8>> = row
                .try_get("previous_public_key")
                .map_err(storage_sql_error)?;
            let previous_key = previous
                .map(|key| {
                    key.try_into()
                        .map(PublicKey)
                        .map_err(|_| storage_error("Mesh rotation key invalid."))
                })
                .transpose()?;
            let phase = match phase.as_str() {
                "preparing" if previous_key.is_none() && candidate_key.is_none() => {
                    RotationPhase::Preparing
                }
                "overlap" if previous_key.is_some() && candidate_key.is_some() => {
                    RotationPhase::Overlap
                }
                "retiring" if previous_key.is_some() && candidate_key.is_none() => {
                    RotationPhase::Retiring
                }
                "cleanup" if previous_key.is_none() && candidate_key.is_none() => {
                    RotationPhase::Cleanup
                }
                _ => return Err(storage_error("Mesh rotation state invalid.")),
            };
            let current_key: Vec<u8> = row.try_get("public_key").map_err(storage_sql_error)?;
            if phase == RotationPhase::Overlap
                && candidate_key.is_none_or(|candidate| current_key.as_slice() != candidate.0)
            {
                return Err(storage_error("Mesh rotation state invalid."));
            }
            let operation_id: String = row.try_get("operation_id").map_err(storage_sql_error)?;
            uuid::Uuid::parse_str(&operation_id)
                .map_err(|_| storage_error("Mesh rotation operation invalid."))?;
            let sequence = u64::try_from(
                row.try_get::<i64, _>("sequence")
                    .map_err(storage_sql_error)?,
            )
            .ok()
            .filter(|sequence| *sequence > 0)
            .ok_or_else(|| storage_error("Mesh rotation sequence invalid."))?;
            let revision = row
                .try_get::<Option<i64>, _>("rotation_revision")
                .map_err(storage_sql_error)?
                .map(|revision| {
                    u64::try_from(revision)
                        .map_err(|_| storage_error("Mesh rotation revision invalid."))
                })
                .transpose()?;
            let started_at: Option<i64> = row
                .try_get("rotation_started_at")
                .map_err(storage_sql_error)?;
            let boot_id = rotation_boot;
            let monotonic = rotation_monotonic;
            if phase == RotationPhase::Preparing {
                if revision.is_some()
                    || started_at.is_some()
                    || boot_id.is_some()
                    || monotonic.is_some()
                {
                    return Err(storage_error("Mesh preparing state invalid."));
                }
            } else if revision.is_none()
                || started_at.is_none()
                || boot_id.is_none()
                || monotonic.is_none()
            {
                return Err(storage_error("Mesh rotation timing invalid."));
            }
            Some(RotationRecord {
                phase,
                candidate_key,
                previous_key,
                operation_id,
                sequence,
                revision,
                started_at,
                monotonic,
            })
        } else {
            None
        };
        tx.commit().await.map_err(storage_sql_error)?;
        Ok(RotationSchedule {
            due_in_secs: u64::try_from(schedule_deadline.saturating_sub(monotonic_secs).max(0))
                .unwrap_or(u64::MAX),
            supported,
            all_nodes_supported: !unsupported,
            record,
        })
    }
    /// Claim a due rotation by writing its id and sequence before the node generates a candidate key.
    pub(crate) async fn begin_rotation(
        &self,
        node: NodeId,
        boot_id: &str,
        monotonic_secs: i64,
    ) -> Result<Option<RotationRecord>, crate::api::MeshApiError> {
        use crate::api::MeshApiError;
        let node_id = i64::try_from(node.0).map_err(|_| MeshApiError::InvalidInput)?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(storage_sql_error)?;
        let row = sqlx::query(
            "SELECT r.rotation_phase,r.operation_id,r.sequence,r.schedule_boot_id,r.schedule_monotonic,\
                    r.schedule_period_secs,n.key_rotation_supported,d.rotation_period_secs \
             FROM mesh_node_key_rotation AS r JOIN mesh_nodes AS n ON n.id=r.node_id \
             JOIN mesh_dataplane AS d ON d.singleton=1 WHERE r.node_id=?",
        )
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_sql_error)?
        .ok_or(MeshApiError::NotFound)?;
        let phase: Option<String> = row.try_get("rotation_phase").map_err(storage_sql_error)?;
        if phase.as_deref() == Some("preparing") {
            let operation_id: String = row.try_get("operation_id").map_err(storage_sql_error)?;
            uuid::Uuid::parse_str(&operation_id)
                .map_err(|_| storage_error("Mesh rotation operation invalid."))?;
            let sequence = u64::try_from(
                row.try_get::<i64, _>("sequence")
                    .map_err(storage_sql_error)?,
            )
            .ok()
            .filter(|sequence| *sequence > 0)
            .ok_or_else(|| storage_error("Mesh rotation sequence invalid."))?;
            tx.commit().await.map_err(storage_sql_error)?;
            return Ok(Some(RotationRecord {
                phase: RotationPhase::Preparing,
                candidate_key: None,
                previous_key: None,
                operation_id,
                sequence,
                revision: None,
                started_at: None,
                monotonic: None,
            }));
        }
        let period: i64 = row
            .try_get("rotation_period_secs")
            .map_err(storage_sql_error)?;
        let schedule_period: i64 = row
            .try_get("schedule_period_secs")
            .map_err(storage_sql_error)?;
        let schedule_boot: String = row.try_get("schedule_boot_id").map_err(storage_sql_error)?;
        let deadline: i64 = row
            .try_get("schedule_monotonic")
            .map_err(storage_sql_error)?;
        let supported: bool = row
            .try_get("key_rotation_supported")
            .map_err(storage_sql_error)?;
        let unsupported: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mesh_nodes WHERE key_rotation_supported=0)",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_sql_error)?;
        if phase.is_some()
            || !supported
            || unsupported
            || period <= 0
            || schedule_period != period
            || schedule_boot != boot_id
            || deadline > monotonic_secs
        {
            tx.commit().await.map_err(storage_sql_error)?;
            return Ok(None);
        }
        let sequence = row
            .try_get::<i64, _>("sequence")
            .map_err(storage_sql_error)?
            .checked_add(1)
            .filter(|sequence| *sequence > 0)
            .ok_or_else(|| storage_error("Mesh rotation sequence exhausted."))?;
        let operation_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id=?,sequence=? WHERE node_id=? AND rotation_phase IS NULL",
        )
        .bind(&operation_id)
        .bind(sequence)
        .bind(node_id)
        .execute(&mut *tx)
        .await
        .map_err(storage_sql_error)?;
        tx.commit().await.map_err(storage_sql_error)?;
        Ok(Some(RotationRecord {
            phase: RotationPhase::Preparing,
            candidate_key: None,
            previous_key: None,
            operation_id,
            sequence: u64::try_from(sequence)
                .map_err(|_| storage_error("Mesh rotation sequence invalid."))?,
            revision: None,
            started_at: None,
            monotonic: None,
        }))
    }
    /// Publish a locally persisted candidate as a dual-key overlap in one database transaction.
    pub(crate) async fn start_rotation_overlap(
        &self,
        node: NodeId,
        operation_id: &str,
        candidate: PublicKey,
        wall_secs: i64,
        boot_id: &str,
        monotonic_nanos: i64,
    ) -> Result<u64, crate::api::MeshApiError> {
        use crate::api::MeshApiError;
        if candidate.0 == [0; 32] || uuid::Uuid::parse_str(operation_id).is_err() {
            return Err(MeshApiError::InvalidInput);
        }
        let node_id = i64::try_from(node.0).map_err(|_| MeshApiError::InvalidInput)?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(storage_sql_error)?;
        let row = sqlx::query(
            "SELECT n.public_key,r.candidate_public_key,r.rotation_phase,r.operation_id,r.sequence,r.rotation_revision \
             FROM mesh_nodes AS n JOIN mesh_node_key_rotation AS r ON r.node_id=n.id WHERE n.id=?",
        )
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_sql_error)?
        .ok_or(MeshApiError::NotFound)?;
        let current: Vec<u8> = row.try_get("public_key").map_err(storage_sql_error)?;
        let stored_candidate: Option<Vec<u8>> = row
            .try_get("candidate_public_key")
            .map_err(storage_sql_error)?;
        let phase: Option<String> = row.try_get("rotation_phase").map_err(storage_sql_error)?;
        let existing_operation: Option<String> =
            row.try_get("operation_id").map_err(storage_sql_error)?;
        if phase.as_deref() == Some("overlap")
            && existing_operation.as_deref() == Some(operation_id)
            && stored_candidate.as_deref() == Some(candidate.0.as_slice())
        {
            let revision = u64::try_from(
                row.try_get::<Option<i64>, _>("rotation_revision")
                    .map_err(storage_sql_error)?
                    .ok_or_else(|| storage_error("Mesh rotation revision missing."))?,
            )
            .map_err(|_| storage_error("Mesh rotation revision invalid."))?;
            tx.commit().await.map_err(storage_sql_error)?;
            return Ok(revision);
        }
        let sequence: i64 = row.try_get("sequence").map_err(storage_sql_error)?;
        if phase.as_deref() != Some("preparing")
            || existing_operation.as_deref() != Some(operation_id)
            || current.as_slice() == candidate.0
        {
            return Err(MeshApiError::Conflict);
        }
        // D166/D352: recheck the all-node gate inside this immediate transaction, which serializes against
        // enrollment. A node that cannot rotate may have joined since preparation began; publish nothing then.
        // The operation stays in preparation and resumes once every node supports rotation again.
        let unsupported: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mesh_nodes WHERE key_rotation_supported=0)",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_sql_error)?;
        if unsupported {
            return Err(MeshApiError::Conflict);
        }
        // The candidate must not be a key another node holds, including one it is rotating away from (#572).
        if key_held_by_another_node(&mut tx, candidate.0.as_slice(), Some(node_id))
            .await
            .map_err(storage_sql_error)?
        {
            return Err(MeshApiError::Conflict);
        }
        let revision: i64 = sqlx::query_scalar(
            "UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807 RETURNING revision",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_sql_error)?
        .ok_or(MeshApiError::Conflict)?;
        let changed = sqlx::query("UPDATE mesh_nodes SET public_key=? WHERE id=? AND public_key=?")
            .bind(candidate.0.as_slice())
            .bind(node_id)
            .bind(&current)
            .execute(&mut *tx)
            .await
            .map_err(storage_sql_error)?;
        if changed.rows_affected() != 1 {
            return Err(MeshApiError::Conflict);
        }
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET candidate_public_key=?,previous_public_key=?,rotation_phase='overlap',rotation_started_at=?,rotation_boot_id=?,rotation_monotonic=?,rotation_revision=?,local_committed=0 WHERE node_id=? AND rotation_phase='preparing' AND operation_id=? AND sequence=?",
        )
        .bind(candidate.0.as_slice())
        .bind(&current)
        .bind(wall_secs)
        .bind(boot_id)
        .bind(monotonic_nanos)
        .bind(revision)
        .bind(node_id)
        .bind(operation_id)
        .bind(sequence)
        .execute(&mut *tx)
        .await
        .map_err(storage_sql_error)?;
        tx.commit().await.map_err(storage_sql_error)?;
        u64::try_from(revision).map_err(|_| storage_error("Mesh revision invalid."))
    }
    /// Mark the node's local candidate active and advance every peer to candidate-first routing.
    pub(crate) async fn commit_rotation(
        &self,
        node: NodeId,
        operation_id: &str,
    ) -> Result<u64, crate::api::MeshApiError> {
        self.advance_rotation(
            node,
            operation_id,
            RotationPhase::Overlap,
            RotationPhase::Retiring,
        )
        .await
    }
    /// Drop the previous public key only after the new-route view is applied by reachable peers.
    pub(crate) async fn begin_rotation_cleanup(
        &self,
        node: NodeId,
        operation_id: &str,
    ) -> Result<u64, crate::api::MeshApiError> {
        self.advance_rotation(
            node,
            operation_id,
            RotationPhase::Retiring,
            RotationPhase::Cleanup,
        )
        .await
    }
    /// Move one node's rotation from `from` to `to` for the named operation in one immediate transaction that also
    /// advances the configuration revision. Repeating a step already taken returns its revision unchanged.
    async fn advance_rotation(
        &self,
        node: NodeId,
        operation_id: &str,
        from: RotationPhase,
        to: RotationPhase,
    ) -> Result<u64, crate::api::MeshApiError> {
        use crate::api::MeshApiError;
        let from_name = from.as_str();
        let to_name = to.as_str();
        let node_id = i64::try_from(node.0).map_err(|_| MeshApiError::InvalidInput)?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(storage_sql_error)?;
        let row = sqlx::query(
            "SELECT rotation_phase,operation_id,rotation_revision,candidate_public_key FROM mesh_node_key_rotation WHERE node_id=?",
        )
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_sql_error)?
        .ok_or(MeshApiError::NotFound)?;
        let phase: Option<String> = row.try_get("rotation_phase").map_err(storage_sql_error)?;
        let current_operation: Option<String> =
            row.try_get("operation_id").map_err(storage_sql_error)?;
        if phase.as_deref() == Some(to_name) && current_operation.as_deref() == Some(operation_id) {
            let revision = u64::try_from(
                row.try_get::<Option<i64>, _>("rotation_revision")
                    .map_err(storage_sql_error)?
                    .ok_or_else(|| storage_error("Mesh rotation revision missing."))?,
            )
            .map_err(|_| storage_error("Mesh rotation revision invalid."))?;
            tx.commit().await.map_err(storage_sql_error)?;
            return Ok(revision);
        }
        if phase.as_deref() != Some(from_name) || current_operation.as_deref() != Some(operation_id)
        {
            return Err(MeshApiError::Conflict);
        }
        let revision: i64 = sqlx::query_scalar(
            "UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807 RETURNING revision",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_sql_error)?
        .ok_or(MeshApiError::Conflict)?;
        if to == RotationPhase::Cleanup {
            sqlx::query(
                "UPDATE mesh_node_key_rotation SET previous_public_key=NULL,rotation_phase='cleanup',rotation_revision=? WHERE node_id=? AND rotation_phase='retiring' AND operation_id=?",
            )
            .bind(revision)
            .bind(node_id)
            .bind(operation_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_sql_error)?;
        } else {
            let candidate: Vec<u8> = row
                .try_get::<Option<Vec<u8>>, _>("candidate_public_key")
                .map_err(storage_sql_error)?
                .ok_or_else(|| storage_error("Mesh rotation candidate missing."))?;
            sqlx::query("UPDATE mesh_nodes SET public_key=? WHERE id=?")
                .bind(&candidate)
                .bind(node_id)
                .execute(&mut *tx)
                .await
                .map_err(storage_sql_error)?;
            sqlx::query(
                "UPDATE mesh_node_key_rotation SET candidate_public_key=NULL,rotation_phase='retiring',rotation_revision=?,local_committed=1 WHERE node_id=? AND rotation_phase='overlap' AND operation_id=?",
            )
            .bind(revision)
            .bind(node_id)
            .bind(operation_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_sql_error)?;
        }
        tx.commit().await.map_err(storage_sql_error)?;
        u64::try_from(revision).map_err(|_| storage_error("Mesh revision invalid."))
    }
    /// Finish the local private-key journal only after the no-previous-key view was acknowledged.
    pub(crate) async fn finish_rotation(
        &self,
        node: NodeId,
        operation_id: &str,
        wall_secs: i64,
        boot_id: &str,
        monotonic_secs: i64,
    ) -> Result<(), crate::api::MeshApiError> {
        use crate::api::MeshApiError;
        let node_id = i64::try_from(node.0).map_err(|_| MeshApiError::InvalidInput)?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(storage_sql_error)?;
        let row = sqlx::query(
            "SELECT r.rotation_phase,r.operation_id,r.last_rotation,r.sequence,d.rotation_period_secs \
             FROM mesh_node_key_rotation AS r JOIN mesh_dataplane AS d ON d.singleton=1 WHERE r.node_id=?",
        )
        .bind(node_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_sql_error)?
        .ok_or(MeshApiError::NotFound)?;
        let phase: Option<String> = row.try_get("rotation_phase").map_err(storage_sql_error)?;
        let current_operation: Option<String> =
            row.try_get("operation_id").map_err(storage_sql_error)?;
        if phase.is_none() && current_operation.is_none() {
            tx.commit().await.map_err(storage_sql_error)?;
            return Ok(());
        }
        if phase.as_deref() != Some("cleanup") || current_operation.as_deref() != Some(operation_id)
        {
            return Err(MeshApiError::Conflict);
        }
        let period: i64 = row
            .try_get("rotation_period_secs")
            .map_err(storage_sql_error)?;
        if period <= 0 {
            return Err(storage_error("Mesh rotation period invalid."));
        }
        let deadline = monotonic_secs.saturating_add(period);
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET last_rotation=?,schedule_boot_id=?,schedule_monotonic=?,schedule_period_secs=?,previous_public_key=NULL,rotation_phase=NULL,rotation_started_at=NULL,rotation_boot_id=NULL,rotation_monotonic=NULL,operation_id=NULL,rotation_revision=NULL,local_committed=0 WHERE node_id=? AND rotation_phase='cleanup' AND operation_id=?",
        )
        .bind(wall_secs)
        .bind(boot_id)
        .bind(deadline)
        .bind(period)
        .bind(node_id)
        .bind(operation_id)
        .execute(&mut *tx)
        .await
        .map_err(storage_sql_error)?;
        tx.commit().await.map_err(storage_sql_error)?;
        *self.cache.lock().await = None;
        Ok(())
    }
    /// Restrict retirement checks to configured peers that the server currently observes online.
    pub(crate) async fn rotation_reachable_peers(
        &self,
        node: NodeId,
        live: &BTreeSet<NodeId>,
    ) -> Result<BTreeSet<NodeId>, crate::api::MeshApiError> {
        let node = i64::try_from(node.0).map_err(|_| crate::api::MeshApiError::InvalidInput)?;
        let peers: Vec<i64> =
            sqlx::query_scalar("SELECT id FROM mesh_nodes WHERE id<>? ORDER BY id")
                .bind(node)
                .fetch_all(&self.pool)
                .await
                .map_err(storage_sql_error)?;
        peers.into_iter().try_fold(
            BTreeSet::from([NodeId(
                u64::try_from(node).map_err(|_| storage_error("Mesh rotation node invalid."))?,
            )]),
            |mut result, peer| {
                let peer = u64::try_from(peer)
                    .map(NodeId)
                    .map_err(|_| storage_error("Mesh rotation peer invalid."))?;
                if live.contains(&peer) {
                    result.insert(peer);
                }
                Ok(result)
            },
        )
    }
    /// Read the candidate public key already committed to the coordinator inventory.
    pub(crate) async fn rotation_candidate_key(
        &self,
        node: NodeId,
    ) -> Result<PublicKey, crate::api::MeshApiError> {
        let node = i64::try_from(node.0).map_err(|_| crate::api::MeshApiError::InvalidInput)?;
        let key: Vec<u8> = sqlx::query_scalar(
            "SELECT candidate_public_key FROM mesh_node_key_rotation WHERE node_id=? AND rotation_phase='overlap'",
        )
            .bind(node)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_sql_error)?
            .ok_or(crate::api::MeshApiError::NotFound)?;
        Ok(PublicKey(key.try_into().map_err(|_| {
            storage_error("Mesh rotation key invalid.")
        })?))
    }
    /// Tell every clone of this store where the server's control plane
    /// listens. Only the first call takes effect. Until it is set, the
    /// server's node admits peers only as Access allows (D352, #221).
    pub fn set_control_plane(&self, control_plane: ControlPlane) {
        let _ = self.control_plane.set(control_plane);
    }
    /// Attach an authenticated host using its approved inventory binding, never a public key as authority.
    /// # Errors
    /// Returns fixed public errors, not database input or authentication data.
    pub async fn attach(
        &self,
        host: &str,
        key: PublicKey,
        endpoint: Option<SocketAddr>,
        server: bool,
    ) -> Result<(NodeId, bool), &'static str> {
        self.attach_named(host, key, endpoint, server, None).await
    }
    /// [`Self::attach`], naming the node after the machine (TASTE "Machines are called by their names", #236).
    ///
    /// Who may name a node, strongest first: a person (`mesh.node.rename`, enrolment), never replaced; the server's
    /// own hostname, on the server's node; the host record (the host part of the address the owner added it with,
    /// the name its pill shows); `reported`, the hostname the machine's infraternal agent reports, only for a host
    /// the record cannot name. A collision suffixes the weaker claim (`minipc01-2`), so a machine can never take
    /// the server's name, `server`, or a name the owner gave another host. Each automatic rename is audited.
    /// Without any name a node gets `<os>-<first 6 characters of its id>` (D339) until one is known.
    /// # Errors
    /// Returns fixed public errors, not database input or authentication data.
    pub async fn attach_named(
        &self,
        host: &str,
        key: PublicKey,
        endpoint: Option<SocketAddr>,
        server: bool,
        reported: Option<&str>,
    ) -> Result<(NodeId, bool), &'static str> {
        self.attach_named_with_capability(host, key, endpoint, server, reported, false)
            .await
    }
    /// Preserve the coordinator's candidate key if a host reconnects before local activation.
    /// A pending operation accepts only the predecessor or current key for its durable phase.
    fn attached_public_key(
        row: &sqlx::sqlite::SqliteRow,
        presented: PublicKey,
        rotation_supported: bool,
    ) -> Result<Vec<u8>, &'static str> {
        let current: Vec<u8> = row
            .try_get("public_key")
            .map_err(|_| "Mesh storage unavailable.")?;
        let phase: Option<String> = row
            .try_get("rotation_phase")
            .map_err(|_| "Mesh storage unavailable.")?;
        // Without support the caller abandons any open rotation in this same transaction (J252 P2), so the
        // node attaches as one that is not rotating: with the key it presents.
        let Some(phase) = phase.filter(|_| rotation_supported) else {
            return Ok(presented.0.to_vec());
        };
        let candidate: Option<Vec<u8>> = row
            .try_get("candidate_public_key")
            .map_err(|_| "Mesh storage unavailable.")?;
        let previous: Option<Vec<u8>> = row
            .try_get("previous_public_key")
            .map_err(|_| "Mesh storage unavailable.")?;
        let presented = presented.0.as_slice();
        let valid = match phase.as_str() {
            "preparing" | "cleanup" => {
                candidate.is_none() && previous.is_none() && current.as_slice() == presented
            }
            "overlap" => {
                candidate.as_deref() == Some(current.as_slice())
                    && (current.as_slice() == presented || previous.as_deref() == Some(presented))
            }
            "retiring" => candidate.is_none() && current.as_slice() == presented,
            _ => false,
        };
        if valid {
            Ok(current)
        } else {
            Err("Mesh key rotation identity is invalid.")
        }
    }
    /// Bind identity and the negotiated dual-key rotation capability in one writer transaction.
    /// A legacy peer remains ineligible until a live channel explicitly advertises support.
    /// # Errors
    /// Returns fixed public errors, not database input or authentication data.
    pub async fn attach_named_with_capability(
        &self,
        host: &str,
        key: PublicKey,
        endpoint: Option<SocketAddr>,
        server: bool,
        reported: Option<&str>,
        key_rotation_supported: bool,
    ) -> Result<(NodeId, bool), &'static str> {
        self.attach_named_with_probed_capabilities(
            host,
            key,
            endpoint,
            server,
            reported,
            Some(key_rotation_supported),
            None,
        )
        .await
    }
    /// Attach with the rotation capability as the identity probe established it: `Some` when the node answered
    /// whether it rotates, `None` when only the legacy request answered and the probe could not tell (J262).
    ///
    /// Only a definite `Some(false)` abandons an open rotation (J252 P2). An unknown capability keeps the old
    /// refusal while a rotation is open, so a transient probe failure costs one retried attach instead of an
    /// abandoned rotation; with no rotation open it attaches as unsupported, which keeps the D166 gate closed.
    /// # Errors
    /// Returns fixed public errors, not database input or authentication data.
    pub async fn attach_named_with_probed_capability(
        &self,
        host: &str,
        key: PublicKey,
        endpoint: Option<SocketAddr>,
        server: bool,
        reported: Option<&str>,
        key_rotation: Option<bool>,
    ) -> Result<(NodeId, bool), &'static str> {
        self.attach_named_with_probed_capabilities(
            host,
            key,
            endpoint,
            server,
            reported,
            key_rotation,
            None,
        )
        .await
    }

    /// Up to `limit` recently removed hosts, newest first, as canonical UUID text. Old
    /// tombstones leave the relay list after the seven-day host-leaf lifetime (D401 Q3).
    /// # Errors
    /// Returns a fixed public error, not database input.
    pub async fn removed_hosts(&self, limit: usize) -> Result<Vec<String>, &'static str> {
        let limit = i64::try_from(limit).map_err(|_| "Mesh storage unavailable.")?;
        sqlx::query_scalar(
            "SELECT host FROM mesh_dataplane_removed \
             WHERE removed_at > CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) - 604800000 \
             ORDER BY removed_at DESC, host DESC LIMIT ?",
        )
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| "Mesh storage unavailable.")
    }

    /// Attach with the independently probed rotation and authority-epoch capabilities.
    ///
    /// A `None` epoch result stays unknown in storage. The inventory maps both unknown and
    /// unsupported to restore-unsafe, while a later successful identity probe can prove support.
    /// # Errors
    /// Returns fixed public errors, not database input or authentication data.
    pub async fn attach_named_with_probed_capabilities(
        &self,
        host: &str,
        key: PublicKey,
        endpoint: Option<SocketAddr>,
        server: bool,
        reported: Option<&str>,
        key_rotation: Option<bool>,
        authority_epoch: Option<bool>,
    ) -> Result<(NodeId, bool), &'static str> {
        let key_rotation_supported = key_rotation.unwrap_or(false);
        if server != (host == "server") {
            return Err("Mesh host identity invalid.");
        }
        let endpoint = endpoint.map(|endpoint| endpoint.to_string());
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        // Public enrollment keys identify inventory, never authorize host binding.
        // The authenticated host is the sole selector; uniqueness refuses any
        // conflicting key without changing another node's grants [164,166,235].
        let existing = sqlx::query(
            "SELECT n.id,n.name,n.name_source,n.public_key,n.endpoint,n.dataplane_host,n.key_rotation_supported,n.authority_epoch_supported,\
                    r.rotation_phase,r.candidate_public_key,r.previous_public_key \
             FROM mesh_nodes AS n LEFT JOIN mesh_node_key_rotation AS r ON r.node_id=n.id \
             WHERE n.dataplane_host=?",
        )
        .bind(host)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?;
        let removed: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mesh_dataplane_removed WHERE host=?)")
                .bind(host)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| "Mesh storage unavailable.")?;
        if removed {
            return Err("Mesh membership was removed; authorized enrollment is required.");
        }
        let (wanted, records, fallback) = wanted_name(&mut tx, host, server, reported).await?;
        let nodes = named_nodes(&mut tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let mut renamed = Vec::new();
        let id = if let Some(row) = existing {
            let rotating = row
                .try_get::<Option<String>, _>("rotation_phase")
                .map_err(|_| "Mesh storage unavailable.")?
                .is_some();
            if rotating && key_rotation.is_none() {
                return Err(ROTATION_IN_PROGRESS);
            }
            let public_key = Self::attached_public_key(&row, key, key_rotation_supported)?;
            let abandoned = rotating && key_rotation == Some(false);
            if abandoned {
                abandon_rotation(&mut tx, row.get("id")).await?;
            }
            // Temporary discovery absence is not an endpoint removal [166].
            // Keep the last known direct coordinate until an observed replacement arrives.
            let endpoint = endpoint.or_else(|| row.get::<Option<String>, _>("endpoint"));
            let id: i64 = row.get("id");
            let name: String = row.get("name");
            // A person's name is final. Any automatic name is re-claimed on each attach, so a squatter yields
            // once the owner's machine (or the server) comes along, and a placeholder heals.
            if row.get::<String, _>("name_source") != "hand"
                && let Some(naming) =
                    naming(&nodes, id, host, Some(&name), wanted, &records, &fallback)
            {
                renamed = naming.moved;
                renamed.push(Renamed {
                    id,
                    from: name,
                    to: naming.name,
                    source: naming.source.to_owned(),
                    claim: naming.claim,
                });
            }
            rename(&mut tx, &renamed).await?;
            if renamed.is_empty()
                && !abandoned
                && row.get::<Option<String>, _>("dataplane_host").as_deref() == Some(host)
                && row.get::<Vec<u8>, _>("public_key") == public_key
                && row.get::<Option<String>, _>("endpoint").as_deref() == endpoint.as_deref()
                && row.get::<bool, _>("key_rotation_supported") == key_rotation_supported
                && row.get::<Option<bool>, _>("authority_epoch_supported") == authority_epoch
            {
                return Ok((
                    NodeId(u64::try_from(id).map_err(|_| "Mesh identity invalid.")?),
                    false,
                ));
            }
            if key_held_by_another_node(&mut tx, &public_key, Some(id))
                .await
                .map_err(|_| "Mesh storage unavailable.")?
            {
                return Err("Mesh identity conflicts.");
            }
            sqlx::query(
                "UPDATE mesh_nodes SET public_key=?,endpoint=?,dataplane_host=?,key_rotation_supported=?,authority_epoch_supported=? WHERE id=?",
            )
            .bind(public_key)
            .bind(&endpoint)
            .bind(host)
            .bind(key_rotation_supported)
            .bind(authority_epoch)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|_| "Mesh identity conflicts.")?;
            id
        } else {
            let high:i64 = sqlx::query_scalar("UPDATE mesh_state SET node_id_high_water=node_id_high_water+1 WHERE singleton=1 AND node_id_high_water<9223372036854775807 RETURNING node_id_high_water").fetch_one(&mut *tx).await.map_err(|_|"Mesh storage unavailable.")?;
            // A new node always gets a name; only the nodes it moves aside are renames.
            let naming = naming(&nodes, high, host, None, wanted, &records, &fallback)
                .ok_or("Mesh identity invalid.")?;
            if key_held_by_another_node(&mut tx, key.0.as_slice(), None)
                .await
                .map_err(|_| "Mesh storage unavailable.")?
            {
                return Err("Mesh identity conflicts.");
            }
            renamed = naming.moved;
            rename(&mut tx, &renamed).await?;
            sqlx::query("INSERT INTO mesh_nodes(id,name,name_source,name_claim,public_key,dataplane_host,endpoint,key_rotation_supported,authority_epoch_supported) VALUES(?,?,?,?,?,?,?,?,?)").bind(high).bind(naming.name).bind(naming.source).bind(naming.claim).bind(key.0.as_slice()).bind(host).bind(&endpoint).bind(key_rotation_supported).bind(authority_epoch).execute(&mut *tx).await.map_err(|_|"Mesh identity conflicts.")?;
            high
        };
        let revision = sqlx::query_scalar::<_,i64>("UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807 RETURNING revision").fetch_one(&mut *tx).await.map_err(|_|"Mesh storage unavailable.")?;
        audit_renames(&mut tx, &renamed, revision, "").await?;
        tx.commit().await.map_err(|_| "Mesh storage unavailable.")?;
        Ok((
            NodeId(u64::try_from(id).map_err(|_| "Mesh identity invalid.")?),
            true,
        ))
    }
    /// Record what a node said about direct-path candidates when it attached (#515): whether it walks an ordered
    /// list, and its LAN addresses, filtered to at most two private, sendable ones. `None` means the node refused
    /// the probe (an older build), which stores "unsupported" and no LAN addresses.
    ///
    /// Writes, and advances the revision, only when something changed. Returns whether it did.
    /// # Errors
    /// Returns fixed public errors, not database input.
    pub async fn record_candidates(
        &self,
        node: NodeId,
        reported: Option<&[SocketAddr]>,
    ) -> Result<bool, &'static str> {
        let supported = reported.is_some();
        let lan = crate::candidates::valid_lan(reported.unwrap_or_default());
        let stored = (!lan.is_empty())
            .then(|| serde_json::to_string(&lan))
            .transpose()
            .map_err(|_| "Mesh identity invalid.")?;
        let id = i64::try_from(node.0).map_err(|_| "Mesh identity invalid.")?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let updated = sqlx::query(
            "UPDATE mesh_nodes SET lan_endpoints=?,candidates_supported=? \
             WHERE id=? AND (lan_endpoints IS NOT ? OR candidates_supported IS NOT ?)",
        )
        .bind(&stored)
        .bind(supported)
        .bind(id)
        .bind(&stored)
        .bind(supported)
        .execute(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?;
        self.commit_candidate_change(tx, updated.rows_affected() > 0)
            .await
    }
    /// Record what a node said about its IPv6 state (#578, J1142): `Some(ipv4_only)` from a node that
    /// reports it, `None` from an older node, which is never treated as IPv4-only and gets no mark.
    ///
    /// Writes, and advances the revision, only when something changed, so peers' snapshots are
    /// recompiled (adding or dropping the mark) exactly when a node's IPv6 state flips. Returns
    /// whether it did.
    /// # Errors
    /// Returns fixed public errors, not database input.
    pub async fn record_ipv6_state(
        &self,
        node: NodeId,
        reported: Option<bool>,
    ) -> Result<bool, &'static str> {
        let supported = reported.is_some();
        let ipv4_only = reported.unwrap_or(false);
        let id = i64::try_from(node.0).map_err(|_| "Mesh identity invalid.")?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let updated = sqlx::query(
            "UPDATE mesh_nodes SET ipv6_supported=?,ipv4_only=? \
             WHERE id=? AND (ipv6_supported IS NOT ? OR ipv4_only IS NOT ?)",
        )
        .bind(supported)
        .bind(ipv4_only)
        .bind(id)
        .bind(supported)
        .bind(ipv4_only)
        .execute(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?;
        self.commit_candidate_change(tx, updated.rows_affected() > 0)
            .await
    }
    /// Record what a node said about its second UDP socket (#260, J1211): `Some(takes_marks)` from a node
    /// that reports it, `None` from an older node, which is never marked as capable and gets no mark.
    ///
    /// Writes, and advances the revision, only when something changed, so peers' snapshots are
    /// recompiled (adding or dropping the mark) exactly when a node's capability flips, for example
    /// when its engine or its switch changes across a restart. Returns whether it did.
    /// # Errors
    /// Returns fixed public errors, not database input.
    pub async fn record_side_port(
        &self,
        node: NodeId,
        reported: Option<bool>,
    ) -> Result<bool, &'static str> {
        let supported = reported.is_some();
        let takes_marks = reported.unwrap_or(false);
        let id = i64::try_from(node.0).map_err(|_| "Mesh identity invalid.")?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let updated = sqlx::query(
            "UPDATE mesh_nodes SET side_port_supported=?,side_port=? \
             WHERE id=? AND (side_port_supported IS NOT ? OR side_port IS NOT ?)",
        )
        .bind(supported)
        .bind(takes_marks)
        .bind(id)
        .bind(supported)
        .bind(takes_marks)
        .execute(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?;
        self.commit_candidate_change(tx, updated.rows_affected() > 0)
            .await
    }
    /// Record what a node said it advertises (D197 M3): `Some(networks)` from a node that understands
    /// subnet routes, `None` from an older node, which advertises nothing and gets no routes.
    ///
    /// The list is the node's whole, current word. A network it names is marked advertised (and
    /// added, waiting for approval, when new). A network it no longer names keeps its approval but
    /// stops being routed, a declined one stays declined (so re-advertising it does not ask again),
    /// and one that is neither is forgotten. Malformed entries were refused by
    /// the parser; entries the model would never route are kept so `mesh.route.list` can say why.
    /// Commits, and advances the revision, only when something changed; returns whether it did.
    /// # Errors
    /// Returns fixed public errors, not database input.
    pub async fn record_routes(
        &self,
        node: NodeId,
        advertised: Option<&[crate::policy::networks::Network]>,
    ) -> Result<bool, &'static str> {
        let id = i64::try_from(node.0).map_err(|_| "Mesh identity invalid.")?;
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let supported = advertised.is_some();
        let mut changed = sqlx::query(
            "UPDATE mesh_nodes SET routes_supported=? WHERE id=? AND routes_supported IS NOT ?",
        )
        .bind(supported)
        .bind(id)
        .bind(supported)
        .execute(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?
        .rows_affected()
            > 0;
        let wanted: BTreeSet<String> = advertised
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .collect();
        let rows = sqlx::query(
            "SELECT network,advertised,approved_at,declined_at FROM mesh_routes WHERE node_id=?",
        )
        .bind(id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?;
        let mut known = BTreeSet::new();
        for row in rows {
            let network: String = row
                .try_get("network")
                .map_err(|_| "Mesh storage unavailable.")?;
            let was: bool = row
                .try_get("advertised")
                .map_err(|_| "Mesh storage unavailable.")?;
            let approved: Option<i64> = row
                .try_get("approved_at")
                .map_err(|_| "Mesh storage unavailable.")?;
            let declined: Option<i64> = row
                .try_get("declined_at")
                .map_err(|_| "Mesh storage unavailable.")?;
            let now = wanted.contains(&network);
            if !now && approved.is_none() && declined.is_none() {
                sqlx::query("DELETE FROM mesh_routes WHERE node_id=? AND network=?")
                    .bind(id)
                    .bind(&network)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| "Mesh storage unavailable.")?;
                changed = true;
            } else if now != was {
                sqlx::query("UPDATE mesh_routes SET advertised=? WHERE node_id=? AND network=?")
                    .bind(now)
                    .bind(id)
                    .bind(&network)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| "Mesh storage unavailable.")?;
                changed = true;
            }
            known.insert(network);
        }
        for network in wanted.difference(&known) {
            sqlx::query("INSERT INTO mesh_routes(node_id,network) VALUES (?,?)")
                .bind(id)
                .bind(network)
                .execute(&mut *tx)
                .await
                .map_err(|_| "Mesh storage unavailable.")?;
            changed = true;
        }
        self.commit_candidate_change(tx, changed).await
    }
    /// Record the server-reflexive addresses the server's own device just observed (#515, presence.rs). Private
    /// addresses ([`crate::candidates::is_private_scope`]) are never recorded.
    ///
    /// A proven observation replaces a different stored address. An unproven one is accepted only when the
    /// coordinator never published that address for the node: not its guess, reflexive or LAN address, and not one
    /// of the reflexive addresses it published before (J585 F3). The server's device sets those itself, from the
    /// current snapshot or one compiled earlier, so only an authenticated packet can have put any other address
    /// there. A replaced reflexive address joins the node's history, which keeps the last [`REFLEXIVE_HISTORY`].
    /// Each address is compared with the cached snapshot first, so a steady mesh costs no database write; only a
    /// changed address is written, all in one transaction with one revision. Returns whether anything changed.
    /// # Errors
    /// Returns fixed public errors, not database input.
    pub async fn record_reflexive(
        &self,
        observed: &[crate::presence::Reflexive],
    ) -> Result<bool, &'static str> {
        let loaded = self.load().await.map_err(|_| "Mesh storage unavailable.")?;
        let no_history = Vec::new();
        let changed: Vec<_> = observed
            .iter()
            // A private address is what a server on the node's own LAN sees: no reflexive address, and it must not
            // reach peers on other sites (J585 F9a). The node's LAN candidates already cover its own site.
            .filter(|seen| !crate::candidates::is_private_scope(seen.address.ip()))
            .filter_map(|seen| {
                let known = loaded.candidates.get(&seen.node)?;
                let history = loaded
                    .reflexive_history
                    .get(&seen.node)
                    .unwrap_or(&no_history);
                let new = if seen.proven {
                    known.reflexive != Some(seen.address)
                } else {
                    known.guess != Some(seen.address)
                        && known.reflexive != Some(seen.address)
                        && !known.lan.contains(&seen.address)
                        && !history.contains(&seen.address)
                };
                new.then(|| {
                    let mut history = history.clone();
                    if let Some(old) = known.reflexive {
                        history.retain(|earlier| *earlier != old && *earlier != seen.address);
                        history.push(old);
                    }
                    let excess = history.len().saturating_sub(REFLEXIVE_HISTORY);
                    history.drain(..excess);
                    (seen.node, seen.address, history)
                })
            })
            .collect();
        if changed.is_empty() {
            return Ok(false);
        }
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let mut any = false;
        for (node, address, history) in changed {
            let id = i64::try_from(node.0).map_err(|_| "Mesh identity invalid.")?;
            let address = address.to_string();
            let history = (!history.is_empty())
                .then(|| serde_json::to_string(&history))
                .transpose()
                .map_err(|_| "Mesh identity invalid.")?;
            let updated = sqlx::query(
                "UPDATE mesh_nodes SET reflexive_endpoint=?,reflexive_history=? \
                 WHERE id=? AND reflexive_endpoint IS NOT ?",
            )
            .bind(&address)
            .bind(&history)
            .bind(id)
            .bind(&address)
            .execute(&mut *tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
            any |= updated.rows_affected() > 0;
        }
        self.commit_candidate_change(tx, any).await
    }
    /// Advance the revision with a candidate change and commit, or roll back when nothing changed.
    async fn commit_candidate_change(
        &self,
        mut tx: sqlx::Transaction<'_, sqlx::Sqlite>,
        changed: bool,
    ) -> Result<bool, &'static str> {
        if !changed {
            tx.rollback()
                .await
                .map_err(|_| "Mesh storage unavailable.")?;
            return Ok(false);
        }
        sqlx::query("UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807")
            .execute(&mut *tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        tx.commit().await.map_err(|_| "Mesh storage unavailable.")?;
        Ok(true)
    }
    /// Reconcile an attached node after admitted-host inventory learns a name outside the attach path.
    ///
    /// Returns whether a name change committed. Its audit row and revision are committed together; callers publish
    /// the revision only after this method returns.
    pub(crate) async fn refresh_host_name(&self, host: &str) -> Result<bool, &'static str> {
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let row = sqlx::query("SELECT id,name,name_source FROM mesh_nodes WHERE dataplane_host=?")
            .bind(host)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let Some(row) = row else {
            tx.rollback()
                .await
                .map_err(|_| "Mesh storage unavailable.")?;
            return Ok(false);
        };
        if row.get::<String, _>("name_source") == "hand" {
            tx.rollback()
                .await
                .map_err(|_| "Mesh storage unavailable.")?;
            return Ok(false);
        }
        let id: i64 = row.get("id");
        let current: String = row.get("name");
        let (wanted, records, fallback) = wanted_name(&mut tx, host, false, None).await?;
        let nodes = named_nodes(&mut tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let Some(naming) = naming(
            &nodes,
            id,
            host,
            Some(&current),
            wanted,
            &records,
            &fallback,
        ) else {
            tx.rollback()
                .await
                .map_err(|_| "Mesh storage unavailable.")?;
            return Ok(false);
        };
        let mut renamed = naming.moved;
        renamed.push(Renamed {
            id,
            from: current,
            to: naming.name,
            source: naming.source.to_owned(),
            claim: naming.claim,
        });
        rename(&mut tx, &renamed).await?;
        let revision = sqlx::query_scalar::<_, i64>(
            "UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807 RETURNING revision",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?;
        audit_renames(&mut tx, &renamed, revision, "").await?;
        tx.commit().await.map_err(|_| "Mesh storage unavailable.")?;
        Ok(true)
    }
    /// The node bound to an authenticated host (`server` for the server itself), if it is enrolled.
    pub async fn node_for_host(&self, host: &str) -> Option<NodeId> {
        let id: i64 = sqlx::query_scalar("SELECT id FROM mesh_nodes WHERE dataplane_host=?")
            .bind(host)
            .fetch_optional(&self.pool)
            .await
            .ok()??;
        u64::try_from(id).ok().map(NodeId)
    }
    /// The deployment's IPv4 range, for services that match mesh addresses
    /// (the mesh SSH client configuration, #221). `None` before the first allocation.
    pub async fn ipv4_range(&self) -> Option<crate::policy::model::Ipv4Range> {
        let serialized: Option<String> =
            sqlx::query_scalar("SELECT allocation_json FROM mesh_dataplane WHERE singleton=1")
                .fetch_optional(&self.pool)
                .await
                .ok()??;
        let state: State = serde_json::from_str(&serialized?).ok()?;
        state.settings.ipv4.validate().ok()?;
        Some(state.settings.ipv4)
    }
    /// Compile a consistent current configuration and persist every new allocation before delivery.
    /// # Errors
    /// Refuses absent server identity, invalid inventory, allocation exhaustion or storage errors.
    pub async fn config(&self, node: NodeId) -> Result<Config, crate::api::MeshApiError> {
        self.config_diagnostics
            .run(async { self.snapshot().await?.config(node) })
            .await
    }
    /// Retain one shared immutable inventory/policy snapshot, rather than a peer map per node.
    /// The deployment's mesh settings (address range, suffix), from the loaded inventory. Subnet
    /// route approval checks networks against the range (D197 M3); loading also saves the
    /// allocation on a fresh deployment, so this works before the first snapshot was compiled.
    /// # Errors
    /// Sanitized storage errors.
    pub(crate) async fn mesh_settings(
        &self,
    ) -> Result<crate::policy::model::MeshSettings, crate::api::MeshApiError> {
        Ok(self.load().await?.coordinator.settings().clone())
    }
    pub(crate) async fn snapshot(&self) -> Result<Snapshot, crate::api::MeshApiError> {
        self.load().await.map(|loaded| Snapshot {
            loaded,
            default_dns_suffix: self.default_dns_suffix.clone(),
            control_plane: self
                .control_plane
                .get()
                .map_or(TrafficPolicy::None, |control_plane| control_plane()),
        })
    }
    /// Page directed reach losses at one revision without allocating the pair matrix.
    /// # Errors
    /// Refuses stale cursors, invalid offsets, arithmetic exhaustion or storage errors.
    pub async fn preview_page(
        &self,
        next: DefaultPolicy,
        cursor: Option<crate::api::MeshCursor>,
    ) -> Result<serde_json::Value, crate::api::MeshApiError> {
        self.preview_diagnostics.run(async {
            use crate::api::{MAX_MESH_FRAME_LEN, MeshApiError, MeshCursor};
            let loaded = self.load().await?;
            let coordinator = &loaded.coordinator;
            let default = loaded.default;
            let revision = loaded.revision;
            if cursor.is_some_and(|cursor| cursor.revision != revision) {
                return Err(MeshApiError::Conflict);
            }
            let views = coordinator.views();
            let losses = |view: &crate::policy::view::PeerView| {
                views.len().saturating_sub(1).saturating_sub(
                    view.peers
                        .values()
                        .filter(|peer| peer.outbound != TrafficPolicy::None)
                        .count(),
                )
            };
            let reducing = default == DefaultPolicy::Allow && next == DefaultPolicy::Deny;
            let mut total = 0usize;
            if reducing {
                for view in views.values() {
                    total = total
                        .checked_add(losses(view))
                        .ok_or_else(|| storage_error("reach count exhausted"))?;
                }
            }
            let offset = cursor.map_or(0, |cursor| cursor.offset);
            if offset > total {
                return Err(MeshApiError::InvalidInput);
            }
            // SSH and every other service on the server's own host follow
            // Access (owner, #221, D352): closing the default closes them for
            // every node without its own arrow there. Control-plane reach to the server is never lost, so
            // these are listed apart from `loses_reach`: on the first page
            // only, at most one entry per node, within the same frame budget.
            let server = coordinator.server();
            let mut ssh_to_server = Vec::new();
            let mut bytes = 2usize;
            if reducing && offset == 0 {
                for node in views.keys().filter(|node| **node != server) {
                    if coordinator.granted(*node, server) == TrafficPolicy::None {
                        let length = serde_json::to_vec(node)
                            .map_err(|_| storage_error("node serialization failed"))?
                            .len()
                            + 1;
                        if bytes + length > (MAX_MESH_FRAME_LEN - 1024) / 2 {
                            break;
                        }
                        bytes += length;
                        ssh_to_server.push(*node);
                    }
                }
            }
            let mut skip = offset;
            let mut pairs = Vec::new();
            'sources: for (node, view) in views.iter().filter(|_| reducing) {
                let count = losses(view);
                if skip >= count {
                    skip -= count;
                    continue;
                }
                for other in views.keys() {
                    if other == node
                        || view
                            .peers
                            .get(other)
                            .is_some_and(|peer| peer.outbound != TrafficPolicy::None)
                    {
                        continue;
                    }
                    if skip > 0 {
                        skip -= 1;
                        continue;
                    }
                    let pair = (*node, *other);
                    let length = serde_json::to_vec(&pair)
                        .map_err(|_| storage_error("reach pair serialization failed"))?
                        .len()
                        + 1;
                    if bytes + length > MAX_MESH_FRAME_LEN - 1024 {
                        break 'sources;
                    }
                    bytes += length;
                    pairs.push(pair);
                }
            }
            let delivered = offset
                .checked_add(pairs.len())
                .ok_or_else(|| storage_error("reach count exhausted"))?;
            let cursor = (delivered < total).then_some(MeshCursor {
                revision,
                offset: delivered,
            });
            Ok(
                serde_json::json!({"default_policy":next,"revision":revision,"loses_reach":pairs,"total_pairs":total,"loses_ssh_to_server":ssh_to_server,"next_cursor":cursor}),
            )
        }).await
    }
    /// Load mesh policy and refresh the cache when its revision or authority epoch changes.
    async fn load(&self) -> Result<Loaded, crate::api::MeshApiError> {
        self.load_diagnostics
            .run(async {
                let mut cached = self.cache.lock().await;
                let (revision, authority_epoch): (i64, Option<String>) = sqlx::query_as(
                    "SELECT revision,authority_epoch FROM mesh_state WHERE singleton=1",
                )
                .fetch_one(&self.pool)
                .await
                .map_err(|error| storage_sql_error(error))?;
                let revision =
                    u64::try_from(revision).map_err(|_| storage_error("Mesh revision invalid."))?;
                if let Some(loaded) = cached.as_ref()
                    && loaded.revision == revision
                    && authority_epoch.as_deref() == Some(loaded.authority_epoch.as_str())
                {
                    return Ok(loaded.clone());
                }
                let loaded = self.load_uncached().await?;
                *cached = Some(loaded.clone());
                Ok(loaded)
            })
            .await
    }
    /// Loads coordinator and node records in one write transaction.
    /// The shared snapshot keeps allocation repair and public configuration reads consistent.
    async fn load_uncached(&self) -> Result<Loaded, crate::api::MeshApiError> {
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(|error| storage_sql_error(error))?;
        let stored_authority_epoch: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT authority_epoch FROM mesh_state WHERE singleton=1",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
        let authority_epoch = match stored_authority_epoch {
            Some(epoch) if !crate::dataplane::valid_authority_epoch(&epoch) => {
                return Err(storage_error("Mesh authority epoch invalid."));
            }
            Some(epoch) if epoch.as_str() == self.authority_epoch.as_ref() => epoch,
            _ => {
                // Each server process gets a fresh authority. Commit it inside this writer
                // transaction before compiling a snapshot, so a failed write publishes nothing.
                let epoch = self.authority_epoch.to_string();
                let updated =
                    sqlx::query("UPDATE mesh_state SET authority_epoch=? WHERE singleton=1")
                        .bind(&epoch)
                        .execute(&mut *tx)
                        .await
                        .map_err(|error| storage_sql_error(error))?;
                if updated.rows_affected() != 1 {
                    return Err(storage_error("Mesh authority epoch reset was not stored."));
                }
                epoch
            }
        };
        let serialized: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT allocation_json FROM mesh_dataplane WHERE singleton=1",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?
        .flatten();
        #[cfg(feature = "mesh-dns")]
        let nodes_query = sqlx::query(
            "SELECT id,name,name_source,public_key,dataplane_host,endpoint,reflexive_endpoint,lan_endpoints,candidates_supported,ipv6_supported,ipv4_only,side_port_supported,side_port,routes_supported,reflexive_history FROM mesh_nodes ORDER BY id",
        );
        #[cfg(not(feature = "mesh-dns"))]
        let nodes_query = sqlx::query(
            "SELECT id,name,public_key,dataplane_host,endpoint,reflexive_endpoint,lan_endpoints,candidates_supported,ipv6_supported,ipv4_only,side_port_supported,side_port,routes_supported,reflexive_history FROM mesh_nodes ORDER BY id",
        );
        let rows = nodes_query
            .fetch_all(&mut *tx)
            .await
            .map_err(|error| storage_sql_error(error))?;
        let mut nodes = Vec::new();
        let mut endpoints = BTreeMap::new();
        let mut candidates = BTreeMap::new();
        let mut accepts_candidates = BTreeSet::new();
        let mut reports_ipv6 = BTreeSet::new();
        let mut reports_routes = BTreeSet::new();
        let mut ipv4_only = BTreeSet::new();
        let mut reports_side_port = BTreeSet::new();
        let mut side_port = BTreeSet::new();
        let mut reflexive_history = BTreeMap::new();
        #[cfg(feature = "mesh-dns")]
        let mut dns_placeholders = BTreeSet::new();
        let mut server = None;
        let mut tags_by_node = std::collections::BTreeMap::<i64, BTreeSet<String>>::new();
        for row in
            sqlx::query("SELECT node_id,tag_name FROM mesh_tag_members ORDER BY node_id,tag_name")
                .fetch_all(&mut *tx)
                .await
                .map_err(|error| storage_sql_error(error))?
        {
            tags_by_node
                .entry(
                    row.try_get("node_id")
                        .map_err(|error| storage_sql_error(error))?,
                )
                .or_default()
                .insert(
                    row.try_get("tag_name")
                        .map_err(|error| storage_sql_error(error))?,
                );
        }
        for row in rows {
            let raw_id: i64 = row
                .try_get("id")
                .map_err(|error| storage_sql_error(error))?;
            let id =
                NodeId(u64::try_from(raw_id).map_err(|_| storage_error("Mesh identity invalid."))?);
            #[cfg(feature = "mesh-dns")]
            if row
                .try_get::<String, _>("name_source")
                .map_err(|error| storage_sql_error(error))?
                == "placeholder"
            {
                dns_placeholders.insert(id);
            }
            let tags = tags_by_node.remove(&raw_id).unwrap_or_default();
            let key: Vec<u8> = row
                .try_get("public_key")
                .map_err(|error| storage_sql_error(error))?;
            let host: Option<String> = row
                .try_get("dataplane_host")
                .map_err(|error| storage_sql_error(error))?;
            if host.as_deref() == Some("server") {
                server = Some(id);
            }
            let known = stored_candidates(&row)?;
            if let Some(endpoint) = known.primary() {
                endpoints.insert(id, endpoint);
            }
            if row
                .try_get::<bool, _>("candidates_supported")
                .map_err(|error| storage_sql_error(error))?
            {
                accepts_candidates.insert(id);
            }
            candidates.insert(id, known);
            if row
                .try_get::<bool, _>("ipv6_supported")
                .map_err(|error| storage_sql_error(error))?
            {
                reports_ipv6.insert(id);
                if row
                    .try_get::<bool, _>("ipv4_only")
                    .map_err(|error| storage_sql_error(error))?
                {
                    ipv4_only.insert(id);
                }
            }
            if row
                .try_get::<bool, _>("side_port_supported")
                .map_err(|error| storage_sql_error(error))?
            {
                reports_side_port.insert(id);
                if row
                    .try_get::<bool, _>("side_port")
                    .map_err(|error| storage_sql_error(error))?
                {
                    side_port.insert(id);
                }
            }
            if row
                .try_get::<bool, _>("routes_supported")
                .map_err(|error| storage_sql_error(error))?
            {
                reports_routes.insert(id);
            }
            let history = stored_addresses(&row, "reflexive_history")?;
            if !history.is_empty() {
                reflexive_history.insert(id, history);
            }
            nodes.push(Node {
                id,
                public_key: PublicKey(
                    key.try_into()
                        .map_err(|_| storage_error("Mesh identity invalid."))?,
                ),
                host: row
                    .try_get("name")
                    .map_err(|error| storage_sql_error(error))?,
                tags: tags.into_iter().collect(),
            });
        }
        let server = server.ok_or_else(|| storage_error("Mesh server node is not connected."))?;
        let mut state = if let Some(serialized) = serialized {
            serde_json::from_str::<State>(&serialized)
                .map_err(|_| storage_error("Mesh allocation invalid."))?
        } else {
            // Public random ULA deployment identifier, generated once and persisted before use.
            let random = uuid::Uuid::new_v4();
            let mut global = [0; 5];
            global.copy_from_slice(&random.as_bytes()[..5]);
            let settings = MeshSettings::new(global);
            let allocation = AddressAllocator::new(settings.clone(), &[])
                .map_err(|_| storage_error("Mesh range invalid."))?;
            State {
                settings,
                allocation,
                server,
                members: BTreeSet::new(),
                origin_dns_suffix: Some(self.default_dns_suffix.clone()),
            }
        };
        let origin_dns_suffix_changed = {
            let previous = state
                .origin_dns_suffix
                .as_deref()
                .unwrap_or(crate::dataplane::DEFAULT_DNS_SUFFIX);
            #[cfg(feature = "mesh-dns")]
            let changed = state.settings.dns_suffix == crate::dataplane::DEFAULT_DNS_SUFFIX
                && previous != self.default_dns_suffix;
            #[cfg(not(feature = "mesh-dns"))]
            let changed = previous != self.default_dns_suffix;
            state.origin_dns_suffix = Some(self.default_dns_suffix.clone());
            changed
        };
        let rotation_period: i64 =
            sqlx::query_scalar("SELECT rotation_period_secs FROM mesh_dataplane WHERE singleton=1")
                .fetch_one(&mut *tx)
                .await
                .map_err(|error| storage_sql_error(error))?;
        state.settings.rotation_period_secs = u64::try_from(rotation_period)
            .ok()
            .filter(|period| *period > 0)
            .ok_or_else(|| storage_error("Mesh rotation period invalid."))?;
        if state.server != server {
            return Err(storage_error("Mesh server identity changed."));
        }
        let membership: BTreeSet<_> = nodes.iter().map(|node| node.id).collect();
        for id in &state.members {
            if !membership.contains(id) {
                state.allocation.remove(*id);
            }
        }
        state.members = membership.clone();
        for node in &nodes {
            state
                .allocation
                .allocate(node.id)
                .map_err(|_| storage_error("Mesh range exhausted."))?;
        }
        let mut coordinator = Coordinator::new(
            state.settings.clone(),
            &[],
            nodes
                .iter()
                .find(|node| node.id == server)
                .ok_or_else(|| storage_error("Mesh server is absent."))?
                .clone(),
        )
        .map_err(|_| storage_error("Mesh inventory invalid."))?;
        for node in nodes.iter().filter(|node| node.id != server) {
            coordinator
                .join(node.clone())
                .map_err(|_| storage_error("Mesh inventory invalid."))?;
        }
        // Approved networks the router still advertises (D197 M3). Loaded before the rules, so
        // arrows can name them. A row the model refuses now (for example after the mesh range
        // moved onto it) stays out instead of taking the whole mesh down; the route list shows it.
        for row in sqlx::query(
            "SELECT id,node_id,network,masquerade FROM mesh_routes \
             WHERE approved_at IS NOT NULL AND advertised=1 ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?
        {
            let id: i64 = row
                .try_get("id")
                .map_err(|error| storage_sql_error(error))?;
            let router: i64 = row
                .try_get("node_id")
                .map_err(|error| storage_sql_error(error))?;
            let network: String = row
                .try_get("network")
                .map_err(|error| storage_sql_error(error))?;
            let (Ok(id), Ok(router), Ok(network)) = (
                u64::try_from(id),
                u64::try_from(router),
                network.parse::<crate::policy::networks::Network>(),
            ) else {
                return Err(storage_error("Mesh route invalid."));
            };
            let approved = crate::policy::networks::ApprovedNetwork {
                id: crate::policy::networks::NetworkId(id),
                router: NodeId(router),
                network,
                masquerade: row
                    .try_get("masquerade")
                    .map_err(|error| storage_sql_error(error))?,
            };
            if membership.contains(&approved.router)
                && coordinator.approve_network(approved).is_err()
            {
                tracing::warn!(
                    route = id,
                    "approved mesh route is not routable now; skipped"
                );
            }
        }
        for row in sqlx::query(
            "SELECT id,from_kind,from_value,to_kind,to_value,both_ways,ports_json FROM mesh_grants",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?
        {
            let arrow = Arrow {
                id: RuleId(
                    u64::try_from(
                        row.try_get::<i64, _>("id")
                            .map_err(|error| storage_sql_error(error))?,
                    )
                    .map_err(|_| storage_error("Mesh rule invalid."))?,
                ),
                from: endpoint(
                    &row.try_get::<String, _>("from_kind")
                        .map_err(|error| storage_sql_error(error))?,
                    &row.try_get::<String, _>("from_value")
                        .map_err(|error| storage_sql_error(error))?,
                )?,
                to: endpoint(
                    &row.try_get::<String, _>("to_kind")
                        .map_err(|error| storage_sql_error(error))?,
                    &row.try_get::<String, _>("to_value")
                        .map_err(|error| storage_sql_error(error))?,
                )?,
                both_ways: row
                    .try_get("both_ways")
                    .map_err(|error| storage_sql_error(error))?,
                ports: serde_json::from_str::<TrafficPolicy>(
                    &row.try_get::<String, _>("ports_json")
                        .map_err(|error| storage_sql_error(error))?,
                )
                .map_err(|_| storage_error("Mesh rule invalid."))?,
            };
            // Deleted node endpoints remain dormant in the Access table; no other identity inherits them.
            // So do arrows to a network that is not approved and advertised right now.
            if [&arrow.from, &arrow.to].iter().any(|ep| match ep {
                Endpoint::Node(id) => !membership.contains(id),
                Endpoint::Network(id) => !coordinator.networks().contains_key(id),
                Endpoint::Tag(_) | Endpoint::User(_) => false,
            }) {
                continue;
            }
            coordinator
                .add_arrow(arrow)
                .map_err(|_| storage_error("Mesh rule invalid."))?;
        }
        let mut rotations = BTreeMap::new();
        for row in sqlx::query(
            "SELECT r.node_id,n.public_key,r.candidate_public_key,r.previous_public_key,r.rotation_phase,r.operation_id,r.sequence,r.rotation_revision,r.rotation_started_at,r.rotation_boot_id,r.rotation_monotonic \
             FROM mesh_node_key_rotation AS r JOIN mesh_nodes AS n ON n.id=r.node_id ORDER BY r.node_id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?
        {
            let Some(phase) = row
                .try_get::<Option<String>, _>("rotation_phase")
                .map_err(|error| storage_sql_error(error))?
            else {
                continue;
            };
            let node = NodeId(
                u64::try_from(
                    row.try_get::<i64, _>("node_id")
                        .map_err(|error| storage_sql_error(error))?,
                )
                .map_err(|_| storage_error("Mesh rotation node invalid."))?,
            );
            let current: Vec<u8> = row
                .try_get("public_key")
                .map_err(|error| storage_sql_error(error))?;
            let candidate: Option<Vec<u8>> = row
                .try_get("candidate_public_key")
                .map_err(|error| storage_sql_error(error))?;
            let candidate_key = candidate
                .map(|key| {
                    key.try_into()
                        .map(PublicKey)
                        .map_err(|_| storage_error("Mesh rotation candidate invalid."))
                })
                .transpose()?;
            let previous: Option<Vec<u8>> = row
                .try_get("previous_public_key")
                .map_err(|error| storage_sql_error(error))?;
            let previous_key = previous
                .map(|key| {
                    key.try_into()
                        .map(PublicKey)
                        .map_err(|_| storage_error("Mesh rotation key invalid."))
                })
                .transpose()?;
            let phase = match phase.as_str() {
                "preparing" if previous_key.is_none() && candidate_key.is_none() => RotationPhase::Preparing,
                "overlap" if previous_key.is_some() && candidate_key.is_some() => RotationPhase::Overlap,
                "retiring" if previous_key.is_some() && candidate_key.is_none() => RotationPhase::Retiring,
                "cleanup" if previous_key.is_none() && candidate_key.is_none() => RotationPhase::Cleanup,
                _ => return Err(storage_error("Mesh rotation state invalid.")),
            };
            if phase == RotationPhase::Overlap
                && candidate_key.is_none_or(|candidate| current.as_slice() != candidate.0)
            {
                return Err(storage_error("Mesh rotation state invalid."));
            }
            let operation_id: String = row
                .try_get("operation_id")
                .map_err(|error| storage_sql_error(error))?;
            uuid::Uuid::parse_str(&operation_id)
                .map_err(|_| storage_error("Mesh rotation operation invalid."))?;
            let sequence = u64::try_from(
                row.try_get::<i64, _>("sequence")
                    .map_err(|error| storage_sql_error(error))?,
            )
            .ok()
            .filter(|sequence| *sequence > 0)
            .ok_or_else(|| storage_error("Mesh rotation sequence invalid."))?;
            let revision = row
                .try_get::<Option<i64>, _>("rotation_revision")
                .map_err(|error| storage_sql_error(error))?
                .map(|revision| {
                    u64::try_from(revision)
                        .map_err(|_| storage_error("Mesh rotation revision invalid."))
                })
                .transpose()?;
            let started_at: Option<i64> = row
                .try_get("rotation_started_at")
                .map_err(|error| storage_sql_error(error))?;
            let boot_id: Option<String> = row
                .try_get("rotation_boot_id")
                .map_err(|error| storage_sql_error(error))?;
            let monotonic: Option<i64> = row
                .try_get("rotation_monotonic")
                .map_err(|error| storage_sql_error(error))?;
            if phase != RotationPhase::Preparing
                && (revision.is_none() || started_at.is_none() || boot_id.is_none() || monotonic.is_none())
            {
                return Err(storage_error("Mesh rotation timing invalid."));
            }
            rotations.insert(
                node,
                RotationRecord {
                    phase,
                    candidate_key,
                    previous_key,
                    operation_id,
                    sequence,
                    revision,
                    started_at,
                    monotonic,
                },
            );
        }
        let mut checkpoint = coordinator.checkpoint();
        checkpoint.allocation = state.allocation.clone();
        for member in &mut checkpoint.members {
            if let Some(rotation) = rotations.get(&member.node.id)
                && matches!(
                    rotation.phase,
                    RotationPhase::Overlap | RotationPhase::Retiring
                )
            {
                member.keys.previous = rotation.previous_key;
                let started_at = rotation
                    .started_at
                    .ok_or_else(|| storage_error("Mesh rotation timing invalid."))?;
                let deadline = started_at
                    .checked_add(120)
                    .and_then(|deadline| u64::try_from(deadline).ok())
                    .ok_or_else(|| storage_error("Mesh rotation deadline invalid."))?;
                member.retire_after = Some(deadline);
            }
        }
        coordinator = Coordinator::restore(checkpoint, &[])
            .map_err(|_| storage_error("Mesh allocation invalid."))?;
        let policy: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT default_policy FROM mesh_dataplane WHERE singleton=1",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?
        .flatten();
        let default = match policy.as_deref() {
            Some("allow") => DefaultPolicy::Allow,
            Some("deny") => DefaultPolicy::Deny,
            None => DefaultPolicy::default(),
            _ => return Err(storage_error("Mesh default invalid.")),
        };
        // Freeze the edition fallback on first use. A later edition build must
        // not silently change an already-running mesh without the Access preview.
        sqlx::query("INSERT INTO mesh_dataplane(singleton,allocation_json,default_policy) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET allocation_json=excluded.allocation_json,default_policy=COALESCE(mesh_dataplane.default_policy,excluded.default_policy)").bind(serde_json::to_string(&state).map_err(|_| storage_error("Mesh allocation invalid."))?).bind(if default==DefaultPolicy::Allow {"allow"} else {"deny"}).execute(&mut *tx).await.map_err(|error| storage_sql_error(error))?;
        let revision: i64 = if origin_dns_suffix_changed {
            sqlx::query_scalar("UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807 RETURNING revision")
                .fetch_one(&mut *tx)
                .await
                .map_err(|error| storage_sql_error(error))?
        } else {
            sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
                .fetch_one(&mut *tx)
                .await
                .map_err(|error| storage_sql_error(error))?
        };
        tx.commit()
            .await
            .map_err(|error| storage_sql_error(error))?;
        Ok(Loaded {
            coordinator: std::sync::Arc::new(coordinator),
            endpoints: std::sync::Arc::new(endpoints),
            candidates: std::sync::Arc::new(candidates),
            accepts_candidates: std::sync::Arc::new(accepts_candidates),
            reports_ipv6: std::sync::Arc::new(reports_ipv6),
            reports_routes: std::sync::Arc::new(reports_routes),
            ipv4_only: std::sync::Arc::new(ipv4_only),
            reports_side_port: std::sync::Arc::new(reports_side_port),
            side_port: std::sync::Arc::new(side_port),
            reflexive_history: std::sync::Arc::new(reflexive_history),
            default,
            revision: u64::try_from(revision)
                .map_err(|_| storage_error("Mesh revision invalid."))?,
            authority_epoch,
            rotations: std::sync::Arc::new(rotations),
            #[cfg(feature = "mesh-dns")]
            dns_placeholders: std::sync::Arc::new(dns_placeholders),
        })
    }
}
/// One `mesh_nodes` row's direct-path candidates (#515). A stored address that no longer parses is a storage
/// error, like the guess has always been.
fn stored_candidates(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<crate::candidates::NodeCandidates, crate::api::MeshApiError> {
    let address = |column: &str| -> Result<Option<SocketAddr>, crate::api::MeshApiError> {
        row.try_get::<Option<String>, _>(column)
            .map_err(|error| storage_sql_error(error))?
            .map(|text| text.parse())
            .transpose()
            .map_err(|_| storage_error("Mesh endpoint invalid."))
    };
    Ok(crate::candidates::NodeCandidates {
        guess: address("endpoint")?,
        reflexive: address("reflexive_endpoint")?,
        lan: stored_addresses(row, "lan_endpoints")?,
    })
}
/// A JSON array of addresses in `column` of a `mesh_nodes` row; empty when the column is NULL.
fn stored_addresses(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Vec<SocketAddr>, crate::api::MeshApiError> {
    Ok(row
        .try_get::<Option<String>, _>(column)
        .map_err(|error| storage_sql_error(error))?
        .map(|text| serde_json::from_str::<Vec<SocketAddr>>(&text))
        .transpose()
        .map_err(|_| storage_error("Mesh endpoint invalid."))?
        .unwrap_or_default())
}
/// How many earlier reflexive addresses a node's history keeps (J585 F3). A device holds an older one only until
/// the next snapshot lands, so a few cover every snapshot that can still be in flight.
const REFLEXIVE_HISTORY: usize = 8;
/// Decode a stored grant endpoint for the coordinator; a `network` endpoint names an approved route's identity.
fn endpoint(kind: &str, value: &str) -> Result<Endpoint, crate::api::MeshApiError> {
    match kind {
        "node" => Ok(Endpoint::Node(NodeId(
            value
                .parse()
                .map_err(|_| storage_error("Mesh rule invalid."))?,
        ))),
        "tag" => Ok(Endpoint::Tag(value.to_owned())),
        "network" => Ok(Endpoint::Network(crate::policy::networks::NetworkId(
            value
                .parse()
                .map_err(|_| storage_error("Mesh rule invalid."))?,
        ))),
        _ => Err(storage_error("Mesh rule invalid.")),
    }
}
#[cfg(test)]
mod naming_tests {
    use super::machine_name;
    #[test]
    fn an_address_or_hostname_gives_the_machines_name() {
        assert_eq!(machine_name("root@minipc01").as_deref(), Some("minipc01"));
        assert_eq!(
            machine_name("kayg@MiniPC01.lan").as_deref(),
            Some("minipc01")
        );
        assert_eq!(machine_name("minipc01:2222").as_deref(), Some("minipc01"));
        assert_eq!(machine_name("monitor01").as_deref(), Some("monitor01"));
        // Not an address: `x` is not followed by hex digits only.
        assert_eq!(machine_name("root@0xygen.lan").as_deref(), Some("0xygen"));
    }
    #[test]
    fn a_numeric_or_invalid_address_gives_no_name() {
        for source in [
            "root@10.69.69.217",
            "10.69.69.217:22",
            "root@[fd00::1]:22",
            "fd00::1",
            "",
            "root@",
            "a_b",
            "-x",
            "root@0x0a.0x45.0x45.0x05",
            "0X0A454505",
            "root@010.1",
            "10.69.69.5.",
            "root@localhost",
        ] {
            assert_eq!(machine_name(source), None, "{source}");
        }
    }
}

/// Direct-path candidates in compiled snapshots (#515, D391).
#[cfg(test)]
mod candidate_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Parse a fixture address.
    fn at(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    /// A store with the server and three nodes: `a` and `b` behind one public address, `c` elsewhere.
    async fn mesh() -> (Store, [NodeId; 4]) {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("../../infraternal-server/migrations")
            .run(&pool)
            .await
            .unwrap();
        let store = crate::api::MeshService::new(pool).dataplane();
        let mut ids = Vec::new();
        for (host, key, guess) in [
            ("server", 1, "198.51.100.10:10254"),
            ("a", 2, "198.51.100.21:10254"),
            ("b", 3, "198.51.100.21:10254"),
            ("c", 4, "203.0.113.9:10254"),
        ] {
            let (id, _) = store
                .attach(
                    host,
                    PublicKey([key; 32]),
                    Some(at(guess)),
                    host == "server",
                )
                .await
                .unwrap();
            ids.push(id);
        }
        (store, ids.try_into().unwrap())
    }

    /// One reflexive observation of `node` at `address`.
    fn seen(node: NodeId, address: &str, proven: bool) -> crate::presence::Reflexive {
        crate::presence::Reflexive {
            node,
            address: at(address),
            proven,
        }
    }

    /// The addresses `config`'s node tries for `peer`, in order.
    fn tries(config: &Config, peer: NodeId) -> Vec<SocketAddr> {
        let peer = &config.peers[&peer].peer;
        peer.endpoint
            .into_iter()
            .chain(peer.candidates.iter().copied())
            .collect()
    }

    /// A node that takes candidates gets its neighbour's LAN address first, then the reflexive address, then the
    /// guess; a node elsewhere never sees the LAN address; an older node gets the reflexive address alone.
    #[tokio::test]
    async fn snapshots_carry_ordered_candidates_only_to_nodes_that_take_them() {
        let (store, [server, a, b, c]) = mesh().await;
        assert!(store.record_candidates(server, Some(&[])).await.unwrap());
        assert!(
            store
                .record_candidates(a, Some(&[at("10.9.0.2:10254")]))
                .await
                .unwrap()
        );
        assert!(
            store
                .record_candidates(b, Some(&[at("10.9.0.3:10254")]))
                .await
                .unwrap()
        );
        assert!(
            !store.record_candidates(c, None).await.unwrap(),
            "an older node changes nothing"
        );
        assert!(
            !store
                .record_candidates(a, Some(&[at("10.9.0.2:10254")]))
                .await
                .unwrap(),
            "the same report writes nothing"
        );
        let before = store.load().await.unwrap().revision;
        assert!(
            store
                .record_reflexive(&[seen(a, "198.51.100.21:30254", true)])
                .await
                .unwrap()
        );
        assert!(
            !store
                .record_reflexive(&[seen(a, "198.51.100.21:30254", true)])
                .await
                .unwrap(),
            "an unchanged observation costs no write"
        );
        assert_eq!(store.load().await.unwrap().revision, before + 1);

        let neighbour = store.config(b).await.unwrap();
        assert_eq!(
            tries(&neighbour, a),
            [
                at("10.9.0.2:10254"),
                at("198.51.100.21:30254"),
                at("198.51.100.21:10254")
            ]
        );
        let server_view = store.config(server).await.unwrap();
        assert_eq!(
            tries(&server_view, a),
            [at("198.51.100.21:30254")],
            "the server's own node only answers, so it gets the observed address alone"
        );
        let older = store.config(c).await.unwrap();
        assert_eq!(tries(&older, a), [at("198.51.100.21:30254")]);
        assert_eq!(older.peers[&a].peer.candidates, Vec::<SocketAddr>::new());
        // Unobserved `b` keeps the pre-#515 address for the older node.
        assert_eq!(tries(&older, b), [at("198.51.100.21:10254")]);
        // Once `c` takes lists, it gets them, still without the LAN address of another site.
        assert!(store.record_candidates(c, Some(&[])).await.unwrap());
        assert_eq!(
            tries(&store.config(c).await.unwrap(), a),
            [at("198.51.100.21:30254"), at("198.51.100.21:10254")],
            "a node elsewhere never learns the LAN address"
        );
    }

    /// An unproven observation of an address the coordinator published itself (the server's device may hold it
    /// from the coordinator's list or a walk) changes nothing; a new one is a NAT's new mapping and is taken.
    #[tokio::test]
    async fn an_unproven_observation_counts_only_for_an_address_never_published() {
        let (store, [_, a, _, _]) = mesh().await;
        store
            .record_candidates(a, Some(&[at("10.9.0.2:10254")]))
            .await
            .unwrap();
        for published in ["198.51.100.21:10254", "10.9.0.2:10254"] {
            assert!(
                !store
                    .record_reflexive(&[seen(a, published, false)])
                    .await
                    .unwrap(),
                "{published} came from the coordinator itself"
            );
        }
        assert!(
            store
                .record_reflexive(&[seen(a, "198.51.100.21:41000", false)])
                .await
                .unwrap()
        );
        assert!(
            !store
                .record_reflexive(&[seen(a, "198.51.100.21:10254", false)])
                .await
                .unwrap(),
            "the guess cannot displace an observed mapping without proof"
        );
        assert!(
            store
                .record_reflexive(&[seen(a, "198.51.100.21:10254", true)])
                .await
                .unwrap()
        );
    }

    /// J585 F1 (#515): an ungranted peer behind the same public address must not learn a node's
    /// LAN address. The compiler keeps denied peers in every snapshot (so a later grant needs only
    /// policy), and `order_candidates` adds LAN candidates to them without looking at policy.
    #[tokio::test]
    async fn an_ungranted_peer_behind_the_same_public_address_gets_no_lan_candidate() {
        let (store, [_, a, b, _]) = mesh().await;
        store
            .record_candidates(a, Some(&[at("10.9.0.2:10254")]))
            .await
            .unwrap();
        store.record_candidates(b, Some(&[])).await.unwrap();
        // Deny by default (the enterprise edition's default); nobody grants a and b to each other.
        sqlx::query("UPDATE mesh_dataplane SET default_policy='deny' WHERE singleton=1")
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE mesh_state SET revision=revision+1 WHERE singleton=1")
            .execute(&store.pool)
            .await
            .unwrap();
        let view = store.config(b).await.unwrap();
        let policy = &view.peers[&a];
        assert_eq!(
            policy.outbound,
            TrafficPolicy::None,
            "fixture: the pair is denied"
        );
        assert_eq!(
            policy.inbound,
            TrafficPolicy::None,
            "fixture: the pair is denied"
        );
        assert!(
            !tries(&view, a).contains(&at("10.9.0.2:10254")),
            "an ungranted neighbour learned a's LAN address: {:?}",
            tries(&view, a)
        );
    }

    /// J699 (#515): a node that reaches the server over its LAN or a private overlay (a server on
    /// the same network, or a VPN in 100.64.0.0/10) has a private control-connection source, so
    /// its guess is a private address. The store drops a private *reflexive* address, but the
    /// guess is published as every peer's endpoint, granted or not (`configuration.rs` puts
    /// `endpoints` on every member). The user guide says local network addresses never leave
    /// their network, so an ungranted peer elsewhere must not learn this one.
    #[tokio::test]
    async fn an_ungranted_peer_never_learns_a_private_guess() {
        let (store, [_, _, _, c]) = mesh().await;
        let (d, _) = store
            .attach(
                "d",
                PublicKey([5; 32]),
                Some(at("100.100.7.9:10254")),
                false,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE mesh_dataplane SET default_policy='deny' WHERE singleton=1")
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE mesh_state SET revision=revision+1 WHERE singleton=1")
            .execute(&store.pool)
            .await
            .unwrap();
        let view = store.config(c).await.unwrap();
        let policy = &view.peers[&d];
        assert_eq!(
            policy.outbound,
            TrafficPolicy::None,
            "fixture: the pair is denied"
        );
        assert_eq!(
            policy.inbound,
            TrafficPolicy::None,
            "fixture: the pair is denied"
        );
        let private: Vec<SocketAddr> = tries(&view, d)
            .into_iter()
            .filter(|address| crate::candidates::is_lan(address.ip()))
            .collect();
        assert!(
            private.is_empty(),
            "an ungranted peer on another network learned d's private address: {private:?}"
        );
    }

    /// J699 P2-1's other half (#515): a homelab where the server and every node share one LAN
    /// has private guesses only, and the guess is the one address that works. A peer with
    /// network access (the default Allow here) still gets it; only ungranted peers lose it.
    #[tokio::test]
    async fn a_granted_peer_still_learns_a_private_guess() {
        let (store, [_, _, _, c]) = mesh().await;
        let (d, _) = store
            .attach(
                "d",
                PublicKey([5; 32]),
                Some(at("192.168.1.9:10254")),
                false,
            )
            .await
            .unwrap();
        let view = store.config(c).await.unwrap();
        assert!(
            view.peers[&d].has_network_access(),
            "fixture: allow by default"
        );
        assert_eq!(tries(&view, d), [at("192.168.1.9:10254")]);
    }

    /// J585 F2 (#515): "same public address" is decided by the UDP-observed reflexive address,
    /// which a member can steer (one authenticated packet with a spoofed source moves the server
    /// device's endpoint, and f37c5497b even accepts it unproven). A node whose control connection
    /// comes from another site must not learn that site's LAN addresses that way.
    #[tokio::test]
    async fn a_reflexive_address_alone_does_not_put_a_node_on_another_site() {
        let (store, [_, a, _, c]) = mesh().await;
        store
            .record_candidates(a, Some(&[at("10.9.0.2:10254")]))
            .await
            .unwrap();
        store.record_candidates(c, Some(&[])).await.unwrap();
        // `c` connects to the coordinator from 203.0.113.9, but one packet "from" a's public
        // address moved the server device's endpoint for `c` there.
        for proven in [false, true] {
            store
                .record_reflexive(&[seen(c, "198.51.100.21:40000", proven)])
                .await
                .unwrap();
            assert!(
                !tries(&store.config(c).await.unwrap(), a).contains(&at("10.9.0.2:10254")),
                "c learned a's LAN address from a UDP source it controls (proven={proven})"
            );
        }
    }

    /// J585 F3 (#515): an unproven observation counts only for an address the coordinator never
    /// published, but the check looks at the current addresses alone. The server device can hold
    /// an address the coordinator published *earlier* (a stale snapshot applied, or a restored
    /// device config read before the fresh snapshot), and that must not roll the mapping back.
    #[tokio::test]
    async fn an_address_published_earlier_is_not_new_evidence() {
        let (store, [_, a, _, _]) = mesh().await;
        assert!(
            store
                .record_reflexive(&[seen(a, "198.51.100.21:30254", true)])
                .await
                .unwrap()
        );
        assert!(
            store
                .record_reflexive(&[seen(a, "198.51.100.21:41000", false)])
                .await
                .unwrap(),
            "fixture: a NAT rebind is taken"
        );
        assert!(
            !store
                .record_reflexive(&[seen(a, "198.51.100.21:30254", false)])
                .await
                .unwrap(),
            "the coordinator published 198.51.100.21:30254 itself; seeing it again proves nothing"
        );
    }

    /// J585 F9a (#515): a server on the same LAN as a node sees that node's private address. It
    /// is no server-reflexive address, and publishing it would send a private address to every
    /// peer on every other site.
    #[tokio::test]
    async fn a_private_observed_address_is_not_a_reflexive_address() {
        let (store, [_, a, _, c]) = mesh().await;
        store.record_candidates(c, Some(&[])).await.unwrap();
        for proven in [false, true] {
            assert!(
                !store
                    .record_reflexive(&[seen(a, "10.9.0.2:40000", proven)])
                    .await
                    .unwrap(),
                "a private address was stored as reflexive (proven={proven})"
            );
        }
        assert!(!tries(&store.config(c).await.unwrap(), a).contains(&at("10.9.0.2:40000")));
    }

    /// A node cannot plant a public, loopback or excess LAN address.
    #[tokio::test]
    async fn reported_lan_addresses_are_filtered_and_capped() {
        let (store, [_, a, b, _]) = mesh().await;
        store
            .record_candidates(
                a,
                Some(&[
                    at("8.8.8.8:10254"),
                    at("127.0.0.1:10254"),
                    at("10.9.0.2:10254"),
                    at("192.168.1.2:10254"),
                    at("172.16.0.2:10254"),
                ]),
            )
            .await
            .unwrap();
        store.record_candidates(b, Some(&[])).await.unwrap();
        assert_eq!(
            tries(&store.config(b).await.unwrap(), a),
            [at("10.9.0.2:10254"), at("198.51.100.21:10254")],
            "one LAN address per family"
        );
    }

    /// The IPv4-only mark follows what each node reported (#578, J1142): only nodes that report their IPv6
    /// state get marks, only for peers that said IPv6 is off, and the mark leaves when IPv6 is back. A node
    /// that does not report is never marked, and never receives a mark, because it could not decode one.
    #[tokio::test]
    async fn peers_that_report_ipv6_off_are_marked_only_for_nodes_that_understand_it() {
        let (store, [server, a, b, c]) = mesh().await;
        // `a` and the server report; `b` reports IPv6 off; `c` is an older node that never reports.
        assert!(store.record_ipv6_state(server, Some(false)).await.unwrap());
        assert!(store.record_ipv6_state(a, Some(false)).await.unwrap());
        assert!(store.record_ipv6_state(b, Some(true)).await.unwrap());
        assert!(
            !store.record_ipv6_state(c, None).await.unwrap(),
            "an older node changes nothing"
        );
        assert!(
            !store.record_ipv6_state(b, Some(true)).await.unwrap(),
            "the same report writes nothing and publishes no revision"
        );

        let marked = |config: &Config| -> Vec<NodeId> {
            config
                .peers
                .iter()
                .filter(|(_, policy)| policy.peer.ipv4_only)
                .map(|(id, _)| *id)
                .collect()
        };
        assert_eq!(marked(&store.config(a).await.unwrap()), [b]);
        assert_eq!(marked(&store.config(server).await.unwrap()), [b]);
        assert_eq!(
            marked(&store.config(c).await.unwrap()),
            Vec::<NodeId>::new(),
            "an older node's snapshot never carries the field"
        );
        let listed = store.config(b).await.unwrap();
        assert_eq!(
            marked(&listed),
            Vec::<NodeId>::new(),
            "no dual-stack peer is marked"
        );

        // IPv6 comes back on `b`: the next snapshot of every node drops the mark.
        let before = store.load().await.unwrap().revision;
        assert!(store.record_ipv6_state(b, Some(false)).await.unwrap());
        assert_eq!(store.load().await.unwrap().revision, before + 1);
        assert_eq!(
            marked(&store.config(a).await.unwrap()),
            Vec::<NodeId>::new()
        );

        // A node that downgrades to not reporting (an older build reinstalled) is never marked.
        assert!(store.record_ipv6_state(b, Some(true)).await.unwrap());
        assert!(store.record_ipv6_state(b, None).await.unwrap());
        assert_eq!(
            marked(&store.config(a).await.unwrap()),
            Vec::<NodeId>::new()
        );
    }

    /// The side-port mark follows what each node reported (#260, J1211): only peers that said they take
    /// marked datagrams are marked, only in snapshots of nodes that understand the field, and the mark
    /// goes when a node stops saying it. A peer that never reported (an older build, kernel `WireGuard`)
    /// is never marked, so nobody sends it a marked datagram.
    #[tokio::test]
    async fn only_peers_that_take_marks_are_marked_and_only_for_nodes_that_understand_it() {
        let (store, [server, a, b, c]) = mesh().await;
        // `server` and `a` report that they take marks, `b` reports that it does not (its switch is
        // off or it runs the kernel engine), `c` is an older node that never reports.
        assert!(store.record_side_port(server, Some(true)).await.unwrap());
        assert!(store.record_side_port(a, Some(true)).await.unwrap());
        assert!(store.record_side_port(b, Some(false)).await.unwrap());
        assert!(
            !store.record_side_port(c, None).await.unwrap(),
            "an older node changes nothing"
        );
        assert!(
            !store.record_side_port(a, Some(true)).await.unwrap(),
            "the same report writes nothing and publishes no revision"
        );

        let marked = |config: &Config| -> Vec<NodeId> {
            config
                .peers
                .iter()
                .filter(|(_, policy)| policy.peer.side_port)
                .map(|(id, _)| *id)
                .collect()
        };
        assert_eq!(marked(&store.config(server).await.unwrap()), [a]);
        assert_eq!(marked(&store.config(a).await.unwrap()), [server]);
        assert_eq!(
            marked(&store.config(b).await.unwrap()),
            [server, a],
            "`b` understands the field, so it learns which peers take marks (it sends none while its own \
             switch is off, but the snapshot still says who could)"
        );
        assert_eq!(
            marked(&store.config(c).await.unwrap()),
            Vec::<NodeId>::new(),
            "an older node's snapshot never carries the field"
        );

        // `a` stops saying it (its switch went off across a restart): every snapshot drops the mark.
        let before = store.load().await.unwrap().revision;
        assert!(store.record_side_port(a, Some(false)).await.unwrap());
        assert_eq!(store.load().await.unwrap().revision, before + 1);
        assert_eq!(
            marked(&store.config(server).await.unwrap()),
            Vec::<NodeId>::new()
        );

        // A node that downgrades to not reporting is never marked.
        assert!(store.record_side_port(a, Some(true)).await.unwrap());
        assert!(store.record_side_port(a, None).await.unwrap());
        assert_eq!(
            marked(&store.config(server).await.unwrap()),
            Vec::<NodeId>::new()
        );
    }

    /// The newest removal reaches relay role data despite older host-sorted tombstones.
    #[tokio::test]
    async fn newly_removed_host_is_not_starved_by_old_tombstones() {
        const TOMBSTONES: usize = crate::relay_list::MAX_REVOKED;
        let (store, _) = mesh().await;
        for host in 0..TOMBSTONES {
            let host = format!("00000000-0000-0000-0000-{host:012x}");
            sqlx::query("INSERT INTO mesh_dataplane_removed(host) VALUES(?)")
                .bind(host)
                .execute(&store.pool)
                .await
                .unwrap();
        }
        let newest = "ffffffff-ffff-ffff-ffff-ffffffffffff";
        sqlx::query("INSERT INTO mesh_dataplane_removed(host) VALUES(?)")
            .bind(newest)
            .execute(&store.pool)
            .await
            .unwrap();

        let removed = store.removed_hosts(TOMBSTONES).await.unwrap();
        assert_eq!(removed.len(), TOMBSTONES);
        assert!(
            removed.iter().any(|host| host == newest),
            "the newest tombstone was starved by older host-sorted rows"
        );

        let has_recency_column: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('mesh_dataplane_removed') WHERE name='removed_at')",
        )
        .fetch_one(&store.pool)
        .await
        .unwrap();
        if has_recency_column {
            sqlx::query(
                "UPDATE mesh_dataplane_removed \
                 SET removed_at = CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) - 691200000 \
                 WHERE host != ?",
            )
            .bind(newest)
            .execute(&store.pool)
            .await
            .unwrap();
            assert_eq!(
                store.removed_hosts(TOMBSTONES).await.unwrap(),
                vec![newest.to_owned()]
            );
        }
    }
}
