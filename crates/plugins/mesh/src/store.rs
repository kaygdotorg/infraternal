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
    endpoints: std::sync::Arc<BTreeMap<NodeId, SocketAddr>>,
    default: DefaultPolicy,
    revision: u64,
    /// Synthetic unnamed labels remain reachable without creating DNS records.
    #[cfg(feature = "mesh-dns-spike")]
    dns_placeholders: std::sync::Arc<BTreeSet<NodeId>>,
}
/// Workers retain the shared source of their acknowledged version. Recompiling
/// its node view preserves exact deltas while idle memory stays proportional to
/// shared inventory and policy, rather than the number of delivered peer maps.
#[derive(Clone)]
pub(crate) struct Snapshot {
    loaded: Loaded,
    default_dns_suffix: String,
}
impl Snapshot {
    pub(crate) fn config(&self, node: NodeId) -> Result<Config, crate::api::MeshApiError> {
        use crate::{api::MeshApiError, policy::model::MeshError};
        let coordinator = &self.loaded.coordinator;
        let endpoints = &self.loaded.endpoints;
        let default = self.loaded.default;
        let revision = self.loaded.revision;
        #[cfg(feature = "cutoff-measure")]
        let _compile = crate::cutoff_measure::Stage::new(node, revision, "compile");
        let compiled = configuration::compile_with_dns_suffix(
            coordinator,
            node,
            default,
            endpoints,
            &self.default_dns_suffix,
        );
        let mut config = compiled.map_err(|error| match error {
            MeshError::UnknownNode => MeshApiError::NotFound,
            _ => storage_error("configuration compilation failed"),
        })?;
        #[cfg(feature = "mesh-dns-spike")]
        {
            if self.loaded.dns_placeholders.contains(&node) {
                config.name = None;
            }
            config
                .peer_names
                .retain(|peer, _| !self.loaded.dns_placeholders.contains(peer));
        }
        config.version = revision;
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
/// Finds a free reserved label, extending beyond the short common suffix range when inventory is large.
fn unnamed_name(nodes: &[Named], except: i64, taken: &str) -> String {
    if let Some(name) = free_name(nodes, UNNAMED, except, false, taken) {
        return name;
    }
    let mut suffix = 10_u64;
    loop {
        let name = format!("{UNNAMED}-{suffix}");
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
/// (`web-2` claimed `web` goes to `web-3`, not `web-2-2`), else to an available unnamed label.
/// Its claim and source stay. A fixed fallback alone can conflict and expose a hidden hostname to a global
/// manager, so exhaustion must keep searching rather than turn into a different rename result (#236).
fn move_aside(nodes: &[Named], holder: &Named, name: &str) -> Renamed {
    let base = holder.claim.as_deref().unwrap_or(&holder.name);
    let to = free_name(nodes, base, holder.id, false, name)
        .unwrap_or_else(|| unnamed_name(nodes, holder.id, name));
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
        let stale_placeholder = current.is_some_and(|name| name == format!("mesh-{host}"));
        if current.is_some() && !stale_placeholder {
            return None;
        }
        let name = if host == SERVER_LABEL {
            SERVER_LABEL.to_owned()
        } else {
            unnamed_name(nodes, id, "")
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
            naming(nodes, id, host, Some(current), None, records)
        }
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
    let cached = if let Ok(id) = uuid::Uuid::parse_str(host) {
        sqlx::query_scalar::<_, Option<String>>("SELECT hostname FROM remote_hosts WHERE id=?")
            .bind(id.as_bytes().as_slice())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?
            .flatten()
    } else {
        None
    };
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
    Ok((wanted, records))
}
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
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    cache: std::sync::Arc<tokio::sync::Mutex<Option<Loaded>>>,
    load_diagnostics: StorageDiagnostics,
    config_diagnostics: StorageDiagnostics,
    preview_diagnostics: StorageDiagnostics,
    default_dns_suffix: String,
}
impl Store {
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self::with_public_origin(pool, "")
    }

    /// Use the configured server origin to derive the default proxy exposure suffix.
    ///
    /// The optional Mesh DNS resolver remains controlled by `mesh-dns-spike`; carrying the public
    /// suffix here lets publication use the accepted coordinator identity in ordinary builds.
    /// An explicit Mesh suffix still takes precedence when that resolver feature is enabled.
    #[must_use]
    pub fn with_public_origin(pool: SqlitePool, public_origin: &str) -> Self {
        let default_dns_suffix = configuration::default_dns_suffix_from_origin(public_origin);
        Self {
            pool,
            cache: std::sync::Arc::default(),
            load_diagnostics: StorageDiagnostics::new("mesh.coordinator.load"),
            config_diagnostics: StorageDiagnostics::new("mesh.coordinator.config"),
            preview_diagnostics: StorageDiagnostics::new("mesh.default.preview"),
            default_dns_suffix,
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
        let nodes = named_nodes(&mut tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
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
        audit_renames(&mut tx, &renamed, revision, "").await?;
        tx.commit().await.map_err(|_| "Mesh storage unavailable.")?;
        Ok((
            NodeId(u64::try_from(id).map_err(|_| "Mesh identity invalid.")?),
            true,
        ))
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
        let (wanted, records) = wanted_name(&mut tx, host, false, None).await?;
        let nodes = named_nodes(&mut tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let Some(naming) = naming(&nodes, id, host, Some(&current), wanted, &records) else {
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
        self.load().await.map(|loaded| Snapshot {
            loaded,
            default_dns_suffix: self.default_dns_suffix.clone(),
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
                    && loaded.revision == revision
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
        #[cfg(feature = "mesh-dns-spike")]
        let nodes_query = sqlx::query(
            "SELECT id,name,name_source,public_key,dataplane_host,endpoint FROM mesh_nodes ORDER BY id",
        );
        #[cfg(not(feature = "mesh-dns-spike"))]
        let nodes_query = sqlx::query(
            "SELECT id,name,public_key,dataplane_host,endpoint FROM mesh_nodes ORDER BY id",
        );
        let rows = nodes_query
            .fetch_all(&mut *tx)
            .await
            .map_err(|error| storage_sql_error(error))?;
        let mut nodes = Vec::new();
        let mut endpoints = BTreeMap::new();
        #[cfg(feature = "mesh-dns-spike")]
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
            #[cfg(feature = "mesh-dns-spike")]
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
                origin_dns_suffix: Some(self.default_dns_suffix.clone()),
            }
        };
        let origin_dns_suffix_changed = {
            let previous = state
                .origin_dns_suffix
                .as_deref()
                .unwrap_or(crate::dataplane::DEFAULT_DNS_SUFFIX);
            #[cfg(feature = "mesh-dns-spike")]
            let changed = state.settings.dns_suffix == crate::dataplane::DEFAULT_DNS_SUFFIX
                && previous != self.default_dns_suffix;
            #[cfg(not(feature = "mesh-dns-spike"))]
            let changed = previous != self.default_dns_suffix;
            state.origin_dns_suffix = Some(self.default_dns_suffix.clone());
            changed
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
            default,
            revision: u64::try_from(revision)
                .map_err(|_| storage_error("Mesh revision invalid."))?,
            #[cfg(feature = "mesh-dns-spike")]
            dns_placeholders: std::sync::Arc::new(dns_placeholders),
        })
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
