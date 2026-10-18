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
}
/// One DB stores inventory, stable non-recycled addresses and policy defaults; no private keys.
type Loaded = (
    std::sync::Arc<Coordinator>,
    std::sync::Arc<BTreeMap<NodeId, SocketAddr>>,
    DefaultPolicy,
    u64,
);
/// Workers retain the shared source of their acknowledged version. Recompiling
/// its node view preserves exact deltas while idle memory stays proportional to
/// shared inventory and policy, rather than the number of delivered peer maps.
#[derive(Clone)]
pub(crate) struct Snapshot(Loaded);
impl Snapshot {
    pub(crate) fn config(&self, node: NodeId) -> Result<Config, crate::api::MeshApiError> {
        use crate::{api::MeshApiError, policy::model::MeshError};
        let (coordinator, endpoints, default, revision) = &self.0;
        #[cfg(feature = "cutoff-measure")]
        let _compile = crate::cutoff_measure::Stage::new(node, *revision, "compile");
        let mut config =
            configuration::compile(coordinator, node, *default, endpoints).map_err(|error| {
                match error {
                    MeshError::UnknownNode => MeshApiError::NotFound,
                    _ => storage_error("configuration compilation failed"),
                }
            })?;
        config.version = *revision;
        Ok(config)
    }
}
/// The name a machine is called by, from an address (`user@minipc01`, `minipc01.lan:22`) or a reported hostname.
///
/// Takes the first DNS label, lowercased. Anything address-like gives nothing, so a numeric address never becomes
/// a name and the caller falls back to the next source: IPv4 in any spelling (shortened `10.69.69`, hex
/// `0x0a.0x45`, octal), IPv6 in any spelling (bracketed, with a zone `%eth0` or `%25eth0`), and labels made only
/// of digits. So does anything that is not a valid Mesh host name.
#[must_use]
pub fn machine_name(source: &str) -> Option<String> {
    let host = source
        .rsplit_once('@')
        .map_or(source, |(_, host)| host)
        .trim();
    // Two colons, a bracket or a zone mark only occur in IPv6 spellings; one colon separates a port.
    if host.matches(':').count() > 1 || host.contains(['[', '%']) {
        return None;
    }
    let host = host.split_once(':').map_or(host, |(host, _)| host);
    if is_ipv4_spelling(host) {
        return None;
    }
    let label = host.split('.').next()?.to_ascii_lowercase();
    if label.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    crate::api::validate_host(&label).ok()?;
    // A machine called `unnamed-3` would read as a placeholder, and clash with what hidden viewers see.
    if crate::api::is_unnamed_label(&label) {
        return None;
    }
    Some(label)
}
/// Whether `host` is an IPv4 address in any spelling the C resolver (`inet_aton`, and so ssh) accepts: one to
/// four dot-separated numbers, each decimal, octal (leading `0`) or hex (`0x`), so `10.69.69`, `0x0a454505` and
/// `0x7f.1` are addresses too. A trailing dot (the absolute form) changes nothing.
fn is_ipv4_spelling(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    let number = |part: &str| match part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        Some(hex) => hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()),
    };
    !host.is_empty() && host.split('.').count() <= 4 && host.split('.').all(number)
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
/// What a node is called while no name is known.
const UNNAMED: &str = "unnamed";
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
/// Moves `holder` off `name`, which a stronger claim takes: to the first free suffix of the holder's own claim
/// (`web-2` claimed `web` goes to `web-3`, not `web-2-2`), else `mesh-<host>`. Its claim and source stay.
fn move_aside(nodes: &[Named], holder: &Named, name: &str) -> Renamed {
    let base = holder.claim.as_deref().unwrap_or(&holder.name);
    let to = free_name(nodes, base, holder.id, false, name)
        .unwrap_or_else(|| format!("mesh-{}", holder.host.as_deref().unwrap_or_default()));
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
/// named. With no name, a new node is `unnamed`.
/// `None` keeps the current name.
fn naming(
    nodes: &[Named],
    id: i64,
    host: &str,
    current: Option<&str>,
    wanted: Option<(String, &'static str)>,
    records: &[String],
) -> Option<Naming> {
    let free = |base: &str, except: i64, skip: bool, taken: &str| {
        free_name(nodes, base, except, skip, taken)
    };
    let Some((wanted, source)) = wanted else {
        if current.is_some() {
            return None;
        }
        let name = if host == SERVER_LABEL {
            SERVER_LABEL.to_owned()
        } else {
            free(UNNAMED, id, false, "").unwrap_or_else(|| format!("mesh-{host}"))
        };
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
        (Some(_), _) | (None, Some(_)) => None,
        (None, None) => naming(nodes, id, host, None, None, records),
    }
}
/// What names a node of `host`, and who gives it, with the names the owner gave every other host.
///
/// The server is named after its own hostname; a remote machine after the name the owner typed when adding it,
/// else its reported hostname. `server` is never a remote machine's automatic name.
async fn wanted_name(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    host: &str,
    server: bool,
    reported: Option<&str>,
) -> Result<(Option<(String, &'static str)>, Vec<String>), &'static str> {
    let own = host.replace('-', "").to_ascii_lowercase();
    let mut recorded = None;
    let mut records = Vec::new();
    for row in sqlx::query("SELECT lower(hex(host_id)) AS host,address FROM remote_host_bootstrap")
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?
    {
        let name = machine_name(&row.get::<String, _>("address"));
        if row.get::<String, _>("host") == own {
            recorded = name;
        } else {
            records.extend(name);
        }
    }
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
                    .map(|name| (name, "reported"))
            })
    };
    Ok((wanted, records))
}
/// Refuses a person's name for node `id` (`None` while enrolling a new one) that belongs to the server's node:
/// `server`, which every viewer without host facts reads as the server, and the name the server's node carries
/// now (its hostname). Automatic naming never gives either to a remote machine (`wanted_name`); this closes the
/// hand path, so no viewer ever sees two nodes called `server` and `server.<suffix>` never points at a remote.
/// The server's node itself may take either.
pub(crate) async fn refuse_server_names(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Option<i64>,
    name: &str,
) -> Result<(), crate::api::MeshApiError> {
    let server: Option<(i64, String)> =
        sqlx::query_as("SELECT id,name FROM mesh_nodes WHERE dataplane_host='server'")
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| storage_error("Mesh storage unavailable."))?;
    let is_server = server
        .as_ref()
        .is_some_and(|(server, _)| Some(*server) == id);
    let servers = name == SERVER_LABEL || server.is_some_and(|(_, held)| held == name);
    if servers && !is_server {
        return Err(crate::api::MeshApiError::Reserved);
    }
    Ok(())
}
/// Frees `name` for a person's choice on node `id` (`None` while enrolling a new one). A person outranks every
/// automatic name (migration 0026), so a node holding `name` by record, report or placeholder moves aside to a
/// suffix of its own claim, audited as an automatic rename with the change's revision. Returns the nodes moved.
///
/// Only another person's name refuses, as a bare conflict. That is no oracle: the refusal says only that the
/// name is in use, which every Mesh member can learn from the name's DNS record, while a name a machine
/// reported (a host fact, hidden from viewers who are not the owner) never refuses anything. The server's names
/// are refused before this, by [`refuse_server_names`].
pub(crate) async fn make_room(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: Option<i64>,
    name: &str,
) -> Result<Vec<i64>, crate::api::MeshApiError> {
    let unavailable = |_| storage_error("Mesh storage unavailable.");
    let nodes: Vec<Named> =
        sqlx::query("SELECT id,name,name_source,dataplane_host,name_claim FROM mesh_nodes")
            .fetch_all(&mut **tx)
            .await
            .map_err(unavailable)?
            .iter()
            .map(|row| Named {
                id: row.get("id"),
                name: row.get("name"),
                source: row.get("name_source"),
                host: row.get("dataplane_host"),
                claim: row.get("name_claim"),
            })
            .collect();
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
    audit_renames(tx, &moved, revision)
        .await
        .map_err(|_| storage_error("Mesh storage unavailable."))?;
    Ok(vec![holder.id])
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
/// Audits automatic renames with the attach's revision. An automatic rename is attributed to the instance owner,
/// the only person who adds hosts, and says it was automatic.
async fn audit_renames(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    renamed: &[Renamed],
    revision: i64,
) -> Result<(), &'static str> {
    for rename in renamed {
        let detail = serde_json::json!({"node_id":rename.id,"name":rename.to,"previous":rename.from,"source":rename.source,"automatic":true});
        sqlx::query("INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json) SELECT id,'mesh.node.name',?,?,unixepoch(),? FROM users WHERE owner=1 ORDER BY rowid LIMIT 1")
            .bind(rename.id.to_string())
            .bind(revision)
            .bind(detail.to_string())
            .execute(&mut **tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
    }
    Ok(())
}
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    cache: std::sync::Arc<tokio::sync::Mutex<Option<Loaded>>>,
    load_diagnostics: StorageDiagnostics,
    config_diagnostics: StorageDiagnostics,
    preview_diagnostics: StorageDiagnostics,
}
impl Store {
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            cache: std::sync::Arc::default(),
            load_diagnostics: StorageDiagnostics::new("mesh.coordinator.load"),
            config_diagnostics: StorageDiagnostics::new("mesh.coordinator.config"),
            preview_diagnostics: StorageDiagnostics::new("mesh.default.preview"),
        }
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
    /// Without any name a node is `unnamed` until one is known.
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
            "SELECT id,name,name_source,public_key,endpoint,dataplane_host FROM mesh_nodes WHERE dataplane_host=?",
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
        let (wanted, records) = wanted_name(&mut tx, host, server, reported).await?;
        let nodes: Vec<Named> =
            sqlx::query("SELECT id,name,name_source,dataplane_host,name_claim FROM mesh_nodes")
                .fetch_all(&mut *tx)
                .await
                .map_err(|_| "Mesh storage unavailable.")?
                .iter()
                .map(|row| Named {
                    id: row.get("id"),
                    name: row.get("name"),
                    source: row.get("name_source"),
                    host: row.get("dataplane_host"),
                    claim: row.get("name_claim"),
                })
                .collect();
        let mut renamed = Vec::new();
        let id = if let Some(row) = existing {
            // Temporary discovery absence is not an endpoint removal [166].
            // Keep the last known direct coordinate until an observed replacement arrives.
            let endpoint = endpoint.or_else(|| row.get::<Option<String>, _>("endpoint"));
            let id: i64 = row.get("id");
            let name: String = row.get("name");
            // A person's name is final. Any automatic name is re-claimed on each attach, so a squatter yields
            // once the owner's machine (or the server) comes along, and a placeholder heals.
            if row.get::<String, _>("name_source") != "hand"
                && let Some(naming) = naming(&nodes, id, host, Some(&name), wanted, &records)
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
                && row.get::<Option<String>, _>("dataplane_host").as_deref() == Some(host)
                && row.get::<Vec<u8>, _>("public_key") == key.0
                && row.get::<Option<String>, _>("endpoint").as_deref() == endpoint.as_deref()
            {
                return Ok((
                    NodeId(u64::try_from(id).map_err(|_| "Mesh identity invalid.")?),
                    false,
                ));
            }
            sqlx::query(
                "UPDATE mesh_nodes SET public_key=?,endpoint=?,dataplane_host=? WHERE id=?",
            )
            .bind(key.0.as_slice())
            .bind(&endpoint)
            .bind(host)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|_| "Mesh identity conflicts.")?;
            id
        } else {
            let high:i64 = sqlx::query_scalar("UPDATE mesh_state SET node_id_high_water=node_id_high_water+1 WHERE singleton=1 AND node_id_high_water<9223372036854775807 RETURNING node_id_high_water").fetch_one(&mut *tx).await.map_err(|_|"Mesh storage unavailable.")?;
            // A new node always gets a name; only the nodes it moves aside are renames.
            let naming = naming(&nodes, high, host, None, wanted, &records)
                .ok_or("Mesh identity invalid.")?;
            renamed = naming.moved;
            rename(&mut tx, &renamed).await?;
            sqlx::query("INSERT INTO mesh_nodes(id,name,name_source,name_claim,public_key,dataplane_host,endpoint) VALUES(?,?,?,?,?,?,?)").bind(high).bind(naming.name).bind(naming.source).bind(naming.claim).bind(key.0.as_slice()).bind(host).bind(&endpoint).execute(&mut *tx).await.map_err(|_|"Mesh identity conflicts.")?;
            high
        };
        let revision = sqlx::query_scalar::<_,i64>("UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807 RETURNING revision").fetch_one(&mut *tx).await.map_err(|_|"Mesh storage unavailable.")?;
        audit_renames(&mut tx, &renamed, revision).await?;
        tx.commit().await.map_err(|_| "Mesh storage unavailable.")?;
        Ok((
            NodeId(u64::try_from(id).map_err(|_| "Mesh identity invalid.")?),
            true,
        ))
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
    /// Compile a consistent current configuration and persist every new allocation before delivery.
    /// # Errors
    /// Refuses absent server identity, invalid inventory, allocation exhaustion or storage errors.
    pub async fn config(&self, node: NodeId) -> Result<Config, crate::api::MeshApiError> {
        self.config_diagnostics
            .run(async { self.snapshot().await?.config(node) })
            .await
    }
    /// Retain one shared immutable inventory/policy snapshot, rather than a peer map per node.
    pub(crate) async fn snapshot(&self) -> Result<Snapshot, crate::api::MeshApiError> {
        self.load().await.map(Snapshot)
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
            let (coordinator, _, default, revision) = self.load().await?;
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
            let mut skip = offset;
            let mut pairs = Vec::new();
            let mut bytes = 2usize;
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
                serde_json::json!({"default_policy":next,"revision":revision,"loses_reach":pairs,"total_pairs":total,"next_cursor":cursor}),
            )
        }).await
    }
    async fn load(&self) -> Result<Loaded, crate::api::MeshApiError> {
        self.load_diagnostics
            .run(async {
                let mut cached = self.cache.lock().await;
                let revision: i64 =
                    sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
                        .fetch_one(&self.pool)
                        .await
                        .map_err(|error| storage_sql_error(error))?;
                let revision =
                    u64::try_from(revision).map_err(|_| storage_error("Mesh revision invalid."))?;
                if let Some(loaded) = cached.as_ref()
                    && loaded.3 == revision
                {
                    return Ok(loaded.clone());
                }
                let loaded = self.load_uncached().await?;
                *cached = Some(loaded.clone());
                Ok(loaded)
            })
            .await
    }
    // Keep one writer snapshot, allocation rebuild and public persistence boundary together.
    #[allow(clippy::too_many_lines)]
    async fn load_uncached(&self) -> Result<Loaded, crate::api::MeshApiError> {
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool)
            .await
            .map_err(|error| storage_sql_error(error))?;
        let serialized: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT allocation_json FROM mesh_dataplane WHERE singleton=1",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?
        .flatten();
        let rows = sqlx::query(
            "SELECT id,name,public_key,dataplane_host,endpoint FROM mesh_nodes ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
        let mut nodes = Vec::new();
        let mut endpoints = BTreeMap::new();
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
            let id = NodeId(
                u64::try_from(
                    row.try_get::<i64, _>("id")
                        .map_err(|error| storage_sql_error(error))?,
                )
                .map_err(|_| storage_error("Mesh identity invalid."))?,
            );
            let tags = tags_by_node
                .remove(
                    &row.try_get::<i64, _>("id")
                        .map_err(|error| storage_sql_error(error))?,
                )
                .unwrap_or_default();
            let key: Vec<u8> = row
                .try_get("public_key")
                .map_err(|error| storage_sql_error(error))?;
            let host: Option<String> = row
                .try_get("dataplane_host")
                .map_err(|error| storage_sql_error(error))?;
            if host.as_deref() == Some("server") {
                server = Some(id);
            }
            if let Some(endpoint) = row
                .try_get::<Option<String>, _>("endpoint")
                .map_err(|error| storage_sql_error(error))?
            {
                endpoints.insert(
                    id,
                    endpoint
                        .parse()
                        .map_err(|_| storage_error("Mesh endpoint invalid."))?,
                );
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
            }
        };
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
            if [&arrow.from, &arrow.to]
                .iter()
                .any(|ep| matches!(ep,Endpoint::Node(id) if !membership.contains(id)))
            {
                continue;
            }
            coordinator
                .add_arrow(arrow)
                .map_err(|_| storage_error("Mesh rule invalid."))?;
        }
        let mut checkpoint = coordinator.checkpoint();
        checkpoint.allocation = state.allocation.clone();
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
        let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| storage_sql_error(error))?;
        tx.commit()
            .await
            .map_err(|error| storage_sql_error(error))?;
        Ok((
            std::sync::Arc::new(coordinator),
            std::sync::Arc::new(endpoints),
            default,
            u64::try_from(revision).map_err(|_| storage_error("Mesh revision invalid."))?,
        ))
    }
}
fn endpoint(kind: &str, value: &str) -> Result<Endpoint, crate::api::MeshApiError> {
    match kind {
        "node" => Ok(Endpoint::Node(NodeId(
            value
                .parse()
                .map_err(|_| storage_error("Mesh rule invalid."))?,
        ))),
        "tag" => Ok(Endpoint::Tag(value.to_owned())),
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
            "root@unnamed-3",
        ] {
            assert_eq!(machine_name(source), None, "{source}");
        }
    }
}
