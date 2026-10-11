//! Persists public Mesh allocations and compiles the existing Access table under one writer transaction [165,166,216].
use crate::{
    configuration,
    dataplane::{Config, DefaultPolicy},
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
        let mut config =
            configuration::compile(coordinator, node, *default, endpoints).map_err(|error| {
                match error {
                    MeshError::UnknownNode => MeshApiError::NotFound,
                    _ => MeshApiError::Storage,
                }
            })?;
        config.version = *revision;
        Ok(config)
    }
}
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
    cache: std::sync::Arc<tokio::sync::Mutex<Option<Loaded>>>,
}
impl Store {
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            cache: std::sync::Arc::default(),
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
        if server != (host == "server") {
            return Err("Mesh host identity invalid.");
        }
        let endpoint = endpoint.map(|endpoint| endpoint.to_string());
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        // Public enrollment keys identify inventory, never authorize host binding.
        // The authenticated host is the sole selector; uniqueness refuses any
        // conflicting key without changing another node's grants [164,166,235].
        let existing = sqlx::query(
            "SELECT id,public_key,endpoint,dataplane_host FROM mesh_nodes WHERE dataplane_host=?",
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
        let id = if let Some(row) = existing {
            // Temporary discovery absence is not an endpoint removal [166].
            // Keep the last known direct coordinate until an observed replacement arrives.
            let endpoint = endpoint.or_else(|| row.get::<Option<String>, _>("endpoint"));
            let id: i64 = row.get("id");
            if row.get::<Option<String>, _>("dataplane_host").as_deref() == Some(host)
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
            let name = if server {
                "server".to_owned()
            } else {
                format!("mesh-{host}")
            };
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
    /// Compile a consistent current configuration and persist every new allocation before delivery.
    /// # Errors
    /// Refuses absent server identity, invalid inventory, allocation exhaustion or storage errors.
    pub async fn config(&self, node: NodeId) -> Result<Config, crate::api::MeshApiError> {
        self.snapshot().await?.config(node)
    }
    /// Retain one shared immutable inventory/policy snapshot, rather than a peer map per node.
    pub(crate) async fn snapshot(&self) -> Result<Snapshot, crate::api::MeshApiError> {
        self.load()
            .await
            .map(Snapshot)
            .map_err(|_| crate::api::MeshApiError::Storage)
    }
    /// Page directed reach losses at one revision without allocating the pair matrix.
    /// # Errors
    /// Refuses stale cursors, invalid offsets, arithmetic exhaustion or storage errors.
    pub async fn preview_page(
        &self,
        next: DefaultPolicy,
        cursor: Option<crate::api::MeshCursor>,
    ) -> Result<serde_json::Value, crate::api::MeshApiError> {
        use crate::api::{MAX_MESH_FRAME_LEN, MeshApiError, MeshCursor};
        let (coordinator, _, default, revision) =
            self.load().await.map_err(|_| MeshApiError::Storage)?;
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
                    .ok_or(MeshApiError::Storage)?;
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
                    .map_err(|_| MeshApiError::Storage)?
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
            .ok_or(MeshApiError::Storage)?;
        let cursor = (delivered < total).then_some(MeshCursor {
            revision,
            offset: delivered,
        });
        Ok(
            serde_json::json!({"default_policy":next,"revision":revision,"loses_reach":pairs,"total_pairs":total,"next_cursor":cursor}),
        )
    }
    async fn load(&self) -> Result<Loaded, &'static str> {
        let mut cached = self.cache.lock().await;
        let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let revision = u64::try_from(revision).map_err(|_| "Mesh revision invalid.")?;
        if let Some(loaded) = cached.as_ref()
            && loaded.3 == revision
        {
            return Ok(loaded.clone());
        }
        let loaded = self.load_uncached().await?;
        *cached = Some(loaded.clone());
        Ok(loaded)
    }
    // Keep one writer snapshot, allocation rebuild and public persistence boundary together.
    #[allow(clippy::too_many_lines)]
    async fn load_uncached(&self) -> Result<Loaded, &'static str> {
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        let serialized: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT allocation_json FROM mesh_dataplane WHERE singleton=1",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?
        .flatten();
        let rows = sqlx::query(
            "SELECT id,name,public_key,dataplane_host,endpoint FROM mesh_nodes ORDER BY id",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?;
        let mut nodes = Vec::new();
        let mut endpoints = BTreeMap::new();
        let mut server = None;
        let mut tags_by_node = std::collections::BTreeMap::<i64, BTreeSet<String>>::new();
        for row in
            sqlx::query("SELECT node_id,tag_name FROM mesh_tag_members ORDER BY node_id,tag_name")
                .fetch_all(&mut *tx)
                .await
                .map_err(|_| "Mesh storage unavailable.")?
        {
            tags_by_node
                .entry(row.get("node_id"))
                .or_default()
                .insert(row.get("tag_name"));
        }
        for row in rows {
            let id = NodeId(
                u64::try_from(row.get::<i64, _>("id")).map_err(|_| "Mesh identity invalid.")?,
            );
            let tags = tags_by_node
                .remove(&row.get::<i64, _>("id"))
                .unwrap_or_default();
            let key: Vec<u8> = row.get("public_key");
            let host: Option<String> = row.get("dataplane_host");
            if host.as_deref() == Some("server") {
                server = Some(id);
            }
            if let Some(endpoint) = row.get::<Option<String>, _>("endpoint") {
                endpoints.insert(id, endpoint.parse().map_err(|_| "Mesh endpoint invalid.")?);
            }
            nodes.push(Node {
                id,
                public_key: PublicKey(key.try_into().map_err(|_| "Mesh identity invalid.")?),
                host: row.get("name"),
                tags: tags.into_iter().collect(),
            });
        }
        let server = server.ok_or("Mesh server node is not connected.")?;
        let mut state = if let Some(serialized) = serialized {
            serde_json::from_str::<State>(&serialized).map_err(|_| "Mesh allocation invalid.")?
        } else {
            // Public random ULA deployment identifier, generated once and persisted before use.
            let random = uuid::Uuid::new_v4();
            let mut global = [0; 5];
            global.copy_from_slice(&random.as_bytes()[..5]);
            let settings = MeshSettings::new(global);
            let allocation =
                AddressAllocator::new(settings.clone(), &[]).map_err(|_| "Mesh range invalid.")?;
            State {
                settings,
                allocation,
                server,
                members: BTreeSet::new(),
            }
        };
        if state.server != server {
            return Err("Mesh server identity changed.");
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
                .map_err(|_| "Mesh range exhausted.")?;
        }
        let mut coordinator = Coordinator::new(
            state.settings.clone(),
            &[],
            nodes
                .iter()
                .find(|node| node.id == server)
                .ok_or("Mesh server is absent.")?
                .clone(),
        )
        .map_err(|_| "Mesh inventory invalid.")?;
        for node in nodes.iter().filter(|node| node.id != server) {
            coordinator
                .join(node.clone())
                .map_err(|_| "Mesh inventory invalid.")?;
        }
        for row in sqlx::query(
            "SELECT id,from_kind,from_value,to_kind,to_value,both_ways,ports_json FROM mesh_grants",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?
        {
            let arrow = Arrow {
                id: RuleId(
                    u64::try_from(row.get::<i64, _>("id")).map_err(|_| "Mesh rule invalid.")?,
                ),
                from: endpoint(
                    &row.get::<String, _>("from_kind"),
                    &row.get::<String, _>("from_value"),
                )?,
                to: endpoint(
                    &row.get::<String, _>("to_kind"),
                    &row.get::<String, _>("to_value"),
                )?,
                both_ways: row.get("both_ways"),
                ports: serde_json::from_str::<TrafficPolicy>(&row.get::<String, _>("ports_json"))
                    .map_err(|_| "Mesh rule invalid.")?,
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
                .map_err(|_| "Mesh rule invalid.")?;
        }
        let mut checkpoint = coordinator.checkpoint();
        checkpoint.allocation = state.allocation.clone();
        coordinator =
            Coordinator::restore(checkpoint, &[]).map_err(|_| "Mesh allocation invalid.")?;
        let policy: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT default_policy FROM mesh_dataplane WHERE singleton=1",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| "Mesh storage unavailable.")?
        .flatten();
        let default = match policy.as_deref() {
            Some("allow") => DefaultPolicy::Allow,
            Some("deny") => DefaultPolicy::Deny,
            None => DefaultPolicy::default(),
            _ => return Err("Mesh default invalid."),
        };
        // Freeze the edition fallback on first use. A later edition build must
        // not silently change an already-running mesh without the Access preview.
        sqlx::query("INSERT INTO mesh_dataplane(singleton,allocation_json,default_policy) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET allocation_json=excluded.allocation_json,default_policy=COALESCE(mesh_dataplane.default_policy,excluded.default_policy)").bind(serde_json::to_string(&state).map_err(|_|"Mesh allocation invalid.")?).bind(if default==DefaultPolicy::Allow {"allow"} else {"deny"}).execute(&mut *tx).await.map_err(|_|"Mesh storage unavailable.")?;
        let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| "Mesh storage unavailable.")?;
        tx.commit().await.map_err(|_| "Mesh storage unavailable.")?;
        Ok((
            std::sync::Arc::new(coordinator),
            std::sync::Arc::new(endpoints),
            default,
            u64::try_from(revision).map_err(|_| "Mesh revision invalid.")?,
        ))
    }
}
fn endpoint(kind: &str, value: &str) -> Result<Endpoint, &'static str> {
    match kind {
        "node" => Ok(Endpoint::Node(NodeId(
            value.parse().map_err(|_| "Mesh rule invalid.")?,
        ))),
        "tag" => Ok(Endpoint::Tag(value.to_owned())),
        _ => Err("Mesh rule invalid."),
    }
}
