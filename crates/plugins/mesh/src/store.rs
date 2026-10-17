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
/// a name and the caller falls back to the next source: IPv4 (also shortened, `10.69.69`), IPv6 in any spelling
/// (bracketed, with a zone `%eth0` or `%25eth0`), and labels made only of digits. So does anything that is not a
/// valid Mesh host name.
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
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return None;
    }
    let label = host.split('.').next()?.to_ascii_lowercase();
    if label.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    crate::api::validate_host(&label).ok()?;
    Some(label)
}
/// `wanted`, or `wanted-2` … `wanted-9` when another node holds it (names are unique, ignoring case).
async fn free_name(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    wanted: Option<&str>,
    except: i64,
) -> Result<Option<String>, &'static str> {
    let Some(wanted) = wanted else {
        return Ok(None);
    };
    for suffix in 1..10 {
        let name = if suffix == 1 {
            wanted.to_owned()
        } else {
            // Keep room for the suffix inside the 63-byte label limit.
            format!(
                "{}-{suffix}",
                wanted[..wanted.len().min(61)].trim_end_matches('-')
            )
        };
        let taken: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mesh_nodes WHERE name=? AND id!=?)")
                .bind(&name)
                .bind(except)
                .fetch_one(&mut **tx)
                .await
                .map_err(|_| "Mesh storage unavailable.")?;
        if !taken {
            return Ok(Some(name));
        }
    }
    Ok(None)
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
    /// The name is the host record's (the host part of the address it was added with, the name its pill shows),
    /// else `reported`, the hostname the machine's infraternal agent reports. A node still under its placeholder
    /// (`server`, or `mesh-<host id>` from before names were known) takes the name on its next attach; a name a
    /// person chose is never replaced. Without either name the placeholder stays until one is known.
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
            "SELECT id,name,public_key,endpoint,dataplane_host FROM mesh_nodes WHERE dataplane_host=?",
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
        let placeholder = if server {
            "server".to_owned()
        } else {
            format!("mesh-{host}")
        };
        let recorded: Option<String> = if server {
            None
        } else {
            // The host record's address is the name the person gave the machine when adding it.
            sqlx::query_scalar(
                "SELECT address FROM remote_host_bootstrap WHERE lower(hex(host_id))=replace(lower(?),'-','')",
            )
            .bind(host)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?
        };
        let wanted = recorded
            .as_deref()
            .and_then(machine_name)
            .or_else(|| reported.and_then(machine_name));
        let id = if let Some(row) = existing {
            // Temporary discovery absence is not an endpoint removal [166].
            // Keep the last known direct coordinate until an observed replacement arrives.
            let endpoint = endpoint.or_else(|| row.get::<Option<String>, _>("endpoint"));
            let id: i64 = row.get("id");
            let rename = if row.get::<String, _>("name") == placeholder {
                free_name(&mut tx, wanted.as_deref(), id).await?
            } else {
                None
            };
            if let Some(name) = &rename {
                sqlx::query("UPDATE mesh_nodes SET name=? WHERE id=?")
                    .bind(name)
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| "Mesh identity conflicts.")?;
            }
            if rename.is_none()
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
            let name = free_name(&mut tx, wanted.as_deref(), 0)
                .await?
                .unwrap_or(placeholder);
            sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,dataplane_host,endpoint) VALUES(?,?,?,?,?)").bind(high).bind(name).bind(key.0.as_slice()).bind(host).bind(&endpoint).execute(&mut *tx).await.map_err(|_|"Mesh identity conflicts.")?;
            high
        };
        sqlx::query_scalar::<_,i64>("UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 AND revision<9223372036854775807 RETURNING revision").fetch_one(&mut *tx).await.map_err(|_|"Mesh storage unavailable.")?;
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
        ] {
            assert_eq!(machine_name(source), None, "{source}");
        }
    }
}
