//! SQLite-backed Mesh inventory, named grants, action authorization, and change revisions [154,163,164,166,187].

use crate::diagnostics::{ActionDiagnostics, StorageDiagnostics, storage_error, storage_sql_error};
use infraternal_mesh::{
    model::{Node, NodeId, PublicKey},
    rules::{Arrow, Endpoint, RuleId, TrafficPolicy},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::broadcast;

const MANAGE_NODES: &str = "mesh.manage_nodes";
const MANAGE_TAGS: &str = "mesh.manage_tags";
const MANAGE_GRANTS: &str = "mesh.manage_grants";
const MANAGE_ROLES: &str = "mesh.manage_roles";
const ROLE_ACTIONS: [&str; 4] = [MANAGE_NODES, MANAGE_TAGS, MANAGE_GRANTS, MANAGE_ROLES];
const NODE_LIVE_SECONDS: i64 = 30;
const CHANGE_BUFFER: usize = 256;
// Reserve room for snapshot keys, cursor, event envelope and mux/frame headers.
// Mesh frames share a socket with latency-sensitive terminal traffic [D11].
// Exact per-item JSON counting leaves 1 KiB for fixed snapshot/event/cursor and
// mux/frame envelopes, including maximum-width numeric identifiers.
/// Mesh work never occupies more than one 64 KiB shared-socket frame [11].
pub const MAX_MESH_FRAME_LEN: usize = 64 * 1024;
const PAGE_ITEM_BYTES: usize = MAX_MESH_FRAME_LEN - 1024;

/// A committed inventory change with the tag scopes needed to filter live invalidations.
#[derive(Clone, Debug)]
pub struct MeshChange {
    /// Monotonic database revision.
    pub revision: i64,
    /// `None` means instance-wide; an empty set is visible only to unscoped roles.
    pub scopes: Option<BTreeSet<String>>,
    /// Observation deadline hint; it re-arms a watch with no previously live nodes.
    pub liveness_deadline: Option<i64>,
}

/// A node combines mesh-core identity with control-plane liveness observations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeshNode {
    /// Policy and key identity shared with mesh-core.
    pub node: Node,
    /// Whether the last attached infraternal agent can safely rotate its mesh key.
    pub key_rotation_supported: bool,
    /// True when the last heartbeat is within the fixed live window.
    pub live: bool,
    /// Unix seconds of the last successful observation.
    pub last_seen: Option<i64>,
    /// Last measured round-trip time in microseconds.
    pub last_rtt_us: Option<u64>,
    /// How packets reach the node from the server while it is online, when the server's device shows it (#236).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<crate::presence::NodePath>,
}

/// A tag and its stable node membership.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeshTag {
    /// Canonical tag name used by mesh-core endpoints.
    pub name: String,
    /// Members sorted by stable mesh node ID.
    pub members: Vec<NodeId>,
}

/// A readable grant name attached to mesh-core's validated directional policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeshGrant {
    /// Stable human-readable grant name, referenced by layout edges [180].
    pub name: String,
    /// Shared mesh-core arrow and traffic policy.
    pub arrow: Arrow,
}

/// Permission-filtered inventory returned by `mesh.list` and the first Mesh event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MeshSnapshot {
    /// Monotonic revision incremented atomically with each audited edit.
    pub revision: u64,
    /// Visible enrolled nodes.
    pub nodes: Vec<MeshNode>,
    /// Visible tags and members.
    pub tags: Vec<MeshTag>,
    /// Visible grants, keyed by stable readable name.
    pub grants: Vec<MeshGrant>,
    /// Continue a bounded wire snapshot; absent for a complete snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<MeshCursor>,
}

/// Position in a revision's permission-filtered nodes, tags, then grants.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshCursor {
    /// Revision whose ordered inventory is being paged.
    pub revision: u64,
    /// Number of previously delivered objects across the three arrays.
    pub offset: usize,
}

/// Optional filter accepted by `mesh.list` and Mesh subscriptions.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MeshFilter {
    /// Restrict the view to one authorized tag and its directly visible endpoints.
    pub tag: Option<String>,
    /// Continue a `mesh.list` page; subscriptions always begin without a cursor.
    pub cursor: Option<MeshCursor>,
}

/// Validated action request. Parsing is pure so fuzz targets exercise the same boundary as WebSocket calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MeshRequest {
    /// Owner-only edition fallback and reach-loss preview.
    Default(crate::settings::Request),
    /// List the caller's permitted Mesh inventory.
    List(MeshFilter),
    /// Enroll a host using its public key.
    EnrollNode(NodeEnroll),
    /// Update a node's last heartbeat and optional measured RTT.
    ObserveNode(NodeObservation),
    /// Change a stable node's readable hostname.
    RenameNode(NodeRename),
    /// Remove a node and grants that reference it.
    DeleteNode(NodeIdInput),
    /// Create an empty tag.
    CreateTag(NamedInput),
    /// Rename a tag and its endpoint and role-scope references atomically.
    RenameTag(RenameInput),
    /// Delete an unreferenced tag.
    DeleteTag(NamedInput),
    /// Add a node to a tag.
    AddMember(MembershipInput),
    /// Remove a node from a tag.
    RemoveMember(MembershipInput),
    /// Create a named, directional grant.
    CreateGrant(GrantCreate),
    /// Move one endpoint of an existing grant.
    MoveGrant(GrantMove),
    /// Delete a named grant.
    DeleteGrant(NamedInput),
    /// Rename a grant without changing its stable numeric identity.
    RenameGrant(RenameInput),
    /// Define or replace a custom action role.
    DefineRole(RoleDefinition),
    /// Assign an existing action role to an instance user.
    AssignRole(RoleAssignment),
}

/// Public node enrollment input. Private key material has no field or serialization path.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeEnroll {
    /// Canonical single-label host name.
    pub name: String,
    /// Public `WireGuard` key only.
    pub public_key: [u8; 32],
    /// Optional authenticated remote host explicitly authorized by node management.
    pub host_id: Option<String>,
}

/// Node liveness observation supplied by the control-plane integration.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeObservation {
    /// Stable mesh node identity.
    pub node_id: u64,
    /// Last measured round-trip time, when available.
    pub last_rtt_us: Option<u64>,
}

/// Stable node rename input.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeRename {
    /// Stable mesh node identity.
    pub node_id: u64,
    /// New canonical single-label hostname.
    pub name: String,
}

/// A canonical name input used by tag creation and grant deletion.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamedInput {
    /// Canonical object name.
    pub name: String,
}

/// Rename an existing tag or grant.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenameInput {
    /// Existing canonical name.
    pub name: String,
    /// New canonical name.
    pub new_name: String,
}

/// Stable node ID used by deletion requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeIdInput {
    /// Stable mesh node identity.
    pub node_id: u64,
}

/// Tag membership edit input.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MembershipInput {
    /// Tag name.
    pub tag: String,
    /// Stable mesh node identity.
    pub node_id: u64,
}

/// New grant input. Missing `ports` means unrestricted traffic as specified by D164.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantCreate {
    /// Stable readable name referenced by the canvas document.
    pub name: String,
    /// Initiating endpoint.
    pub from: Endpoint,
    /// Destination endpoint.
    pub to: Endpoint,
    /// Permit initiation in both directions when true.
    pub both_ways: bool,
    /// Optional narrowed TCP/UDP policy; omission grants all ports, explicit null is refused.
    #[serde(default, deserialize_with = "deserialize_provided")]
    pub ports: Option<TrafficPolicy>,
}

/// A provided policy or scope must be typed. Only field absence uses Serde's
/// default; explicit null cannot acquire omission's unrestricted authority.
fn deserialize_provided<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Which end of a named grant should move.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EndpointSide {
    /// Change the initiating endpoint.
    From,
    /// Change the destination endpoint.
    To,
}

/// Move one endpoint while keeping the grant's identity and traffic policy.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantMove {
    /// Existing grant name.
    pub name: String,
    /// Endpoint side to change.
    pub side: EndpointSide,
    /// New node or tag endpoint.
    pub endpoint: Endpoint,
}

/// Replace a role's allowed actions and optional tag scope.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleDefinition {
    /// Canonical role name.
    pub name: String,
    /// Granular actions granted by this role.
    pub actions: BTreeSet<String>,
    /// Omitted means instance-wide; provided names restrict every action. Null is refused.
    #[serde(default, deserialize_with = "deserialize_provided")]
    pub scopes: Option<BTreeSet<String>>,
}

/// Assign an existing custom role to a user account.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoleAssignment {
    /// Existing instance user ID.
    pub user_id: String,
    /// Existing role name.
    pub role: String,
}

/// Sanitized failures shared by the WebSocket and direct service API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeshApiError {
    /// Unknown action, malformed JSON, or invalid field values.
    InvalidInput,
    /// The caller lacks the required role action or scope.
    Denied,
    /// Destructive browser authority expired before commit [28].
    FreshRequired,
    /// A referenced object is absent or hidden from this caller.
    NotFound,
    /// A unique name, key, or nonempty-tag invariant would be violated.
    Conflict,
    /// The name belongs to the server's node: `server`, or the server's own name (#236).
    Reserved,
    /// SQLite or serialization failed; details are intentionally not exposed.
    Storage,
}

impl MeshApiError {
    /// Return a stable generic wire error without including inputs, SQL, or secret state.
    #[must_use]
    pub const fn wire_error(self) -> &'static [u8] {
        match self {
            Self::InvalidInput => br#"{"error":"invalid input"}"#,
            Self::FreshRequired => br#"{"error":"confirm with your passkey again"}"#,
            Self::Denied => br#"{"error":"forbidden"}"#,
            Self::NotFound => br#"{"error":"not found"}"#,
            Self::Conflict => br#"{"error":"conflict"}"#,
            Self::Reserved => br#"{"error":"reserved for the server"}"#,
            Self::Storage => br#"{"error":"mesh unavailable"}"#,
        }
    }
}

/// Parse a public mesh action and reject unknown fields before any database work.
///
/// # Errors
/// Returns `InvalidInput` for unknown actions, malformed JSON, or an invalid mesh policy.
pub fn parse_action(action: &str, input: &[u8]) -> Result<MeshRequest, MeshApiError> {
    let request = match action {
        "mesh.default.get"
        | "mesh.default.preview"
        | "mesh.default.set"
        | "mesh.rotation.get"
        | "mesh.rotation.interval.set" => {
            MeshRequest::Default(crate::settings::parse_action(action, input)?)
        }
        "mesh.list" => MeshRequest::List(parse(input)?),
        "mesh.node.enroll" => MeshRequest::EnrollNode(parse(input)?),
        "mesh.node.observe" => MeshRequest::ObserveNode(parse(input)?),
        "mesh.node.rename" => MeshRequest::RenameNode(parse(input)?),
        "mesh.node.delete" => MeshRequest::DeleteNode(parse(input)?),
        "mesh.tag.create" => MeshRequest::CreateTag(parse(input)?),
        "mesh.tag.rename" => MeshRequest::RenameTag(parse(input)?),
        "mesh.tag.delete" => MeshRequest::DeleteTag(parse(input)?),
        "mesh.tag.member.add" => MeshRequest::AddMember(parse(input)?),
        "mesh.tag.member.remove" => MeshRequest::RemoveMember(parse(input)?),
        "mesh.grant.create" => MeshRequest::CreateGrant(parse(input)?),
        "mesh.grant.move" => MeshRequest::MoveGrant(parse(input)?),
        "mesh.grant.delete" => MeshRequest::DeleteGrant(parse(input)?),
        "mesh.grant.rename" => MeshRequest::RenameGrant(parse(input)?),
        "mesh.role.define" => MeshRequest::DefineRole(parse(input)?),
        "mesh.role.assign" => MeshRequest::AssignRole(parse(input)?),
        _ => return Err(MeshApiError::InvalidInput),
    };
    match &request {
        MeshRequest::Default(_) => {}
        MeshRequest::List(filter) => {
            if filter
                .cursor
                .is_some_and(|cursor| cursor.offset == 0 || i64::try_from(cursor.revision).is_err())
            {
                return Err(MeshApiError::InvalidInput);
            }
            if let Some(tag) = &filter.tag {
                validate_name(tag)?;
            }
        }
        MeshRequest::EnrollNode(input) => {
            validate_host(&input.name)?;
            if input.public_key == [0; 32] {
                return Err(MeshApiError::InvalidInput);
            }
            if let Some(host) = &input.host_id {
                let id = uuid::Uuid::parse_str(host).map_err(|_| MeshApiError::InvalidInput)?;
                if id.to_string() != *host {
                    return Err(MeshApiError::InvalidInput);
                }
            }
        }
        MeshRequest::ObserveNode(input) => {
            node_id(input.node_id)?;
            if input
                .last_rtt_us
                .is_some_and(|rtt| i64::try_from(rtt).is_err())
            {
                return Err(MeshApiError::InvalidInput);
            }
        }
        MeshRequest::RenameNode(input) => {
            node_id(input.node_id)?;
            validate_host(&input.name)?;
        }
        MeshRequest::DeleteNode(input) => {
            node_id(input.node_id)?;
        }
        MeshRequest::CreateTag(input)
        | MeshRequest::DeleteTag(input)
        | MeshRequest::DeleteGrant(input) => {
            validate_name(&input.name)?;
        }
        MeshRequest::RenameTag(input) | MeshRequest::RenameGrant(input) => {
            validate_name(&input.name)?;
            validate_name(&input.new_name)?;
        }
        MeshRequest::AddMember(input) | MeshRequest::RemoveMember(input) => {
            validate_name(&input.tag)?;
            node_id(input.node_id)?;
        }
        MeshRequest::CreateGrant(input) => {
            validate_name(&input.name)?;
            let arrow = Arrow {
                id: RuleId(1),
                from: input.from.clone(),
                to: input.to.clone(),
                both_ways: input.both_ways,
                ports: input.ports.clone().unwrap_or(TrafficPolicy::All),
            };
            arrow.validate().map_err(|_| MeshApiError::InvalidInput)?;
            validate_endpoint_shape(&arrow.from)?;
            validate_endpoint_shape(&arrow.to)?;
        }
        MeshRequest::MoveGrant(input) => {
            validate_name(&input.name)?;
            validate_endpoint_shape(&input.endpoint)?;
        }
        MeshRequest::DefineRole(input) => {
            validate_name(&input.name)?;
            if input.actions.is_empty()
                || input
                    .actions
                    .iter()
                    .any(|action| !ROLE_ACTIONS.contains(&action.as_str()))
                || input.scopes.as_ref().is_some_and(BTreeSet::is_empty)
                || (input.actions.contains(MANAGE_ROLES) && input.scopes.is_some())
            {
                return Err(MeshApiError::InvalidInput);
            }
            if let Some(scopes) = &input.scopes {
                for scope in scopes {
                    validate_name(scope)?;
                }
            }
        }
        MeshRequest::AssignRole(input) => {
            validate_name(&input.role)?;
            if input.user_id.is_empty()
                || input.user_id.len() > 128
                || input.user_id.chars().any(char::is_control)
            {
                return Err(MeshApiError::InvalidInput);
            }
        }
    }
    Ok(request)
}

fn parse<T: for<'de> Deserialize<'de>>(input: &[u8]) -> Result<T, MeshApiError> {
    serde_json::from_slice(input).map_err(|_| MeshApiError::InvalidInput)
}

fn validate_endpoint_shape(endpoint: &Endpoint) -> Result<(), MeshApiError> {
    match endpoint {
        Endpoint::Node(id) => i64::try_from(id.0)
            .ok()
            .filter(|id| *id > 0)
            .map(|_| ())
            .ok_or(MeshApiError::InvalidInput),
        Endpoint::Tag(name) => validate_name(name),
        Endpoint::User(_) => Err(MeshApiError::InvalidInput),
    }
}

fn validate_name(name: &str) -> Result<(), MeshApiError> {
    if name.is_empty()
        || name.len() > 63
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || name.starts_with('-')
        || name.ends_with('-')
    {
        return Err(MeshApiError::InvalidInput);
    }
    Ok(())
}

pub(crate) fn validate_host(name: &str) -> Result<(), MeshApiError> {
    validate_name(name)
}

fn node_id(id: u64) -> Result<i64, MeshApiError> {
    i64::try_from(id)
        .ok()
        .filter(|id| *id > 0)
        .ok_or(MeshApiError::InvalidInput)
}

/// Shared server service. Change notifications carry only a revision, so authorization is reapplied per viewer.
#[derive(Clone)]
pub struct MeshService {
    pool: SqlitePool,
    updates: broadcast::Sender<MeshChange>,
    // Runtime liveness from the server's own device; never persisted (presence.rs, #236).
    presence: std::sync::Arc<crate::presence::Presence>,
    // Rotation drivers sleep until a deadline and wake only when a peer applies a view.
    rotation_updates: tokio::sync::watch::Sender<u64>,
    // Request-local authority is never installed in the shared service.
    fresh_authority: Option<String>,
    store: crate::store::Store,
    invalid_hosts: crate::diagnostics::InvalidHosts,
    list_diagnostics: StorageDiagnostics,
    action_diagnostics: ActionDiagnostics,
    change_diagnostics: StorageDiagnostics,
    deadline_diagnostics: StorageDiagnostics,
}

impl MeshService {
    /// Bind the API to the server's migrated SQLite pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self::with_store(pool.clone(), crate::store::Store::new(pool))
    }

    /// Bind the API and coordinator snapshots to the server's configured public origin.
    #[must_use]
    pub fn with_public_origin(pool: SqlitePool, public_origin: &str) -> Self {
        Self::with_store(
            pool.clone(),
            crate::store::Store::with_public_origin(pool, public_origin),
        )
    }

    /// Build a service with a different authority epoch to model another server process in tests.
    #[cfg(test)]
    pub(crate) fn with_authority_epoch_for_test(
        pool: SqlitePool,
        authority_epoch: std::sync::Arc<str>,
    ) -> Self {
        let store =
            crate::store::Store::with_authority_epoch_for_test(pool.clone(), authority_epoch);
        Self::with_store(pool, store)
    }

    /// Build the service around an already opened store, with a fresh change broadcast.
    fn with_store(pool: SqlitePool, store: crate::store::Store) -> Self {
        let (updates, _) = broadcast::channel(CHANGE_BUFFER);
        Self {
            store,
            pool,
            updates,
            presence: std::sync::Arc::default(),
            rotation_updates: tokio::sync::watch::Sender::new(0),
            fresh_authority: None,
            invalid_hosts: crate::diagnostics::InvalidHosts::default(),
            list_diagnostics: StorageDiagnostics::new("mesh.list"),
            action_diagnostics: ActionDiagnostics::default(),
            change_diagnostics: StorageDiagnostics::new("mesh.watch.access"),
            deadline_diagnostics: StorageDiagnostics::new("mesh.watch.deadline"),
        }
    }

    /// Reuse one revision cache for previews and all node workers.
    #[must_use]
    pub fn dataplane(&self) -> crate::store::Store {
        self.store.clone()
    }

    /// Publish an authenticated binding change after its writer transaction commits.
    pub async fn invalidate_dataplane(&self) {
        if let Ok(revision) =
            sqlx::query_scalar::<_, i64>("SELECT revision FROM mesh_state WHERE singleton=1")
                .fetch_one(&self.pool)
                .await
        {
            let _ = self.updates.send(MeshChange {
                revision,
                scopes: None,
                liveness_deadline: None,
            });
        }
    }

    /// Rename an attached node from newly retained host inventory and notify live Mesh viewers after commit.
    pub async fn refresh_host_name(&self, host: &str) -> bool {
        if self.store.refresh_host_name(host).await != Ok(true) {
            return false;
        }
        self.invalidate_dataplane().await;
        true
    }

    /// Bind destructive browser authority to the transaction that commits the edit.
    /// Direct service callers remain responsible for authenticating their adapter.
    #[must_use]
    pub fn with_fresh_authority(&self, token_hash: String) -> Self {
        let mut request = self.clone();
        request.fresh_authority = Some(token_hash);
        request
    }

    #[cfg(test)]
    pub(crate) fn pool_for_tests(&self) -> SqlitePool {
        self.pool.clone()
    }

    /// Install the server's current reading of who is online; watchers wake only when it changed (#236).
    pub fn set_presence(&self, live: crate::presence::Live) {
        self.presence.replace(live);
    }

    /// Watch presence transitions. They advance no revision; socket.rs resyncs only viewers who see a change.
    #[must_use]
    pub fn subscribe_presence(
        &self,
    ) -> tokio::sync::watch::Receiver<std::sync::Arc<crate::presence::Live>> {
        self.presence.subscribe()
    }

    /// Wake rotation drivers after an applied-view receipt is committed.
    pub(crate) fn rotation_applied(&self) {
        self.rotation_updates
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    /// Subscribe to coalesced applied-view progress without a polling timer.
    #[must_use]
    pub(crate) fn subscribe_rotation_progress(&self) -> tokio::sync::watch::Receiver<u64> {
        self.rotation_updates.subscribe()
    }

    /// Subscribe to post-commit revision invalidations; a lagging reader should reload its filtered list.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<MeshChange> {
        self.updates.subscribe()
    }

    /// Check whether a committed change intersects the caller's current Mesh view permissions.
    ///
    /// # Errors
    /// Returns an authorization or storage error if the caller can no longer hold this view.
    pub async fn can_view_change(
        &self,
        actor: &str,
        filter: &MeshFilter,
        change: &MeshChange,
    ) -> Result<bool, MeshApiError> {
        self.change_diagnostics
            .run(async {
                let mut tx = self
                    .pool
                    .begin()
                    .await
                    .map_err(|error| map_sql_error(error))?;
                if let Some(tag) = &filter.tag {
                    validate_name(tag)?;
                    if sqlx::query("SELECT 1 FROM mesh_tags WHERE name=?")
                        .bind(tag)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(|error| map_sql_error(error))?
                        .is_none()
                    {
                        return Err(MeshApiError::NotFound);
                    }
                }
                let access = view_access(&mut tx, actor).await?;
                if let Some(tag) = &filter.tag
                    && !access.all
                    && !access.tags.contains(tag)
                {
                    return Err(MeshApiError::Denied);
                }
                let Some(changed_tags) = &change.scopes else {
                    return Ok(true);
                };
                // Global permission authorizes a filter; it never widens that filter.
                // Scope every tag-specific invalidation to the requested view [D154, D187].
                if let Some(tag) = &filter.tag {
                    Ok(changed_tags.contains(tag))
                } else if access.all {
                    Ok(true)
                } else {
                    Ok(access.tags.iter().any(|tag| changed_tags.contains(tag)))
                }
            })
            .await
    }

    /// Find the next visible expiry without copying or paging inventory.
    ///
    /// # Errors
    /// Refuses lost view authority or storage failure while rearming a watch.
    pub async fn watch_deadline(
        &self,
        actor: &str,
        filter: &MeshFilter,
        now: i64,
    ) -> Result<Option<i64>, MeshApiError> {
        self.deadline_diagnostics.run(async {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|error| map_sql_error(error))?;
            let access = view_access(&mut tx, actor).await?;
            let all = access.all && filter.tag.is_none();
            let tags = if let Some(tag) = &filter.tag {
                if !access.all && !access.tags.contains(tag) {
                    return Err(MeshApiError::Denied);
                }
                BTreeSet::from([tag.clone()])
            } else {
                access.tags
            };
            let tags = serde_json::to_string(&tags)
                .map_err(|_| storage_error("watch tag serialization failed"))?;
            // Match the complete view, including nodes beyond the first wire page.
            // Inclusive liveness ends at last_seen + 31, exactly as snapshots do.
            sqlx::query_scalar("SELECT MIN(n.last_seen) FROM mesh_nodes AS n WHERE n.last_seen BETWEEN ? AND ? AND (? OR EXISTS(SELECT 1 FROM mesh_tag_members AS m WHERE m.node_id=n.id AND m.tag_name IN (SELECT value FROM json_each(?))))")
                .bind(now.saturating_sub(NODE_LIVE_SECONDS))
                .bind(now)
                .bind(all)
                .bind(tags)
                .fetch_one(&mut *tx)
                .await
                .map(|seen: Option<i64>| seen.and_then(|seen| seen.checked_add(NODE_LIVE_SECONDS + 1)))
                .map_err(|error| map_sql_error(error))
        }).await
    }

    /// Execute a validated action for an authenticated account.
    ///
    /// # Errors
    /// Returns sanitized input, authorization, absence, conflict, or storage errors.
    pub async fn execute(
        &self,
        actor: &str,
        action: &str,
        input: &[u8],
        now: i64,
    ) -> Result<Value, MeshApiError> {
        // Direct reads and action-adapted reads share one outage counter.
        let request = parse_action(action, input)?;
        let diagnostics = if action == "mesh.list" {
            self.list_diagnostics.clone()
        } else {
            self.action_diagnostics.for_action(action)
        };
        diagnostics
            .run(self.execute_request(actor, action, input, now, request))
            .await
    }

    /// Keep one parsed dispatch inside the entry point's diagnostic scope.
    async fn execute_request(
        &self,
        actor: &str,
        action: &str,
        input: &[u8],
        now: i64,
        request: MeshRequest,
    ) -> Result<Value, MeshApiError> {
        match request {
            MeshRequest::Default(_) => {
                let value = crate::settings::execute(
                    &self.pool,
                    &self.store,
                    actor,
                    action,
                    input,
                    now,
                    self.fresh_authority.as_deref(),
                )
                .await?;
                if action == "mesh.default.set" || action == "mesh.rotation.interval.set" {
                    self.invalidate_dataplane().await;
                }
                Ok(value)
            }
            MeshRequest::List(filter) => {
                Ok(serde_json::to_value(self.list(actor, filter, now).await?)
                    .map_err(|_| storage_error("snapshot serialization failed"))?)
            }
            MeshRequest::EnrollNode(request) => {
                let (id, revision) = self.enroll_node(actor, request, now).await?;
                Ok(json!({"node_id": id, "revision": revision}))
            }
            MeshRequest::ObserveNode(request) => {
                let revision = self.observe_node(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::RenameNode(request) => {
                let revision = self.rename_node(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::DeleteNode(request) => {
                let revision = self.delete_node(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::CreateTag(request) => {
                let revision = self.create_tag(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::RenameTag(request) => {
                let revision = self.rename_tag(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::DeleteTag(request) => {
                let revision = self.delete_tag(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::AddMember(request) => {
                let revision = self.edit_member(actor, request, true, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::RemoveMember(request) => {
                let revision = self.edit_member(actor, request, false, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::CreateGrant(request) => {
                let (id, revision) = self.create_grant(actor, request, now).await?;
                Ok(json!({"grant_id": id, "revision": revision}))
            }
            MeshRequest::MoveGrant(request) => {
                let revision = self.move_grant(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::DeleteGrant(request) => {
                let revision = self.delete_grant(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::RenameGrant(request) => {
                let revision = self.rename_grant(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::DefineRole(request) => {
                let revision = self.define_role(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
            MeshRequest::AssignRole(request) => {
                let revision = self.assign_role(actor, request, now).await?;
                Ok(json!({"revision": revision}))
            }
        }
    }

    /// Return a consistent permission-filtered Mesh snapshot.
    ///
    /// # Errors
    /// Returns `Denied` when no role action exposes the Mesh view or requested tag.
    pub async fn list(
        &self,
        actor: &str,
        filter: MeshFilter,
        now: i64,
    ) -> Result<MeshSnapshot, MeshApiError> {
        self.list_with_deadline(actor, filter, now)
            .await
            .map(|(page, _)| page)
    }

    /// Retain the earliest live-node expiry from the complete filtered view, before paging.
    ///
    /// # Errors
    /// Returns the same authorization, validation and storage errors as [`Self::list`].
    pub async fn list_with_deadline(
        &self,
        actor: &str,
        filter: MeshFilter,
        now: i64,
    ) -> Result<(MeshSnapshot, Option<i64>), MeshApiError> {
        self.list_diagnostics
            .run(async {
                let mut transaction = self
                    .pool
                    .begin()
                    .await
                    .map_err(|error| map_sql_error(error))?;
                let revision: i64 =
                    sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
                        .fetch_one(&mut *transaction)
                        .await
                        .map_err(|error| map_sql_error(error))?;
                let access = view_access(&mut transaction, actor).await?;
                let restrict_to_filter = filter.tag.is_some();
                let visible_tags = if let Some(tag) = filter.tag {
                    if !access.all && !access.tags.contains(&tag) {
                        return Err(MeshApiError::Denied);
                    }
                    if sqlx::query("SELECT 1 FROM mesh_tags WHERE name=?")
                        .bind(&tag)
                        .fetch_optional(&mut *transaction)
                        .await
                        .map_err(|error| map_sql_error(error))?
                        .is_none()
                    {
                        return Err(MeshApiError::NotFound);
                    }
                    BTreeSet::from([tag])
                } else if access.all {
                    sqlx::query_scalar::<_, String>("SELECT name FROM mesh_tags ORDER BY name")
                        .fetch_all(&mut *transaction)
                        .await
                        .map_err(|error| map_sql_error(error))?
                        .into_iter()
                        .collect()
                } else {
                    access.tags
                };
                let snapshot = read_snapshot(
                    &mut transaction,
                    revision,
                    now,
                    access.all && !restrict_to_filter,
                    &visible_tags,
                    &self.invalid_hosts,
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(|error| map_sql_error(error))?;
                let snapshot =
                    filter_snapshot(snapshot, access.all && !restrict_to_filter, &visible_tags);
                // A node is live through last_seen + 30 inclusive. The first offline
                // second is +31. Compute before paging so later-page nodes still expire.
                let deadline = snapshot
                    .nodes
                    .iter()
                    .filter(|node| node.live)
                    .filter_map(|node| {
                        node.last_seen
                            .and_then(|seen| seen.checked_add(NODE_LIVE_SECONDS + 1))
                    })
                    .min();
                // Presence is the device's first-hand reading; it marks nodes online without a stored
                // observation, and its transitions are pushed, so it adds no expiry deadline.
                let mut snapshot = snapshot;
                for node in &mut snapshot.nodes {
                    if let Some(path) = self.presence.get(node.node.id) {
                        node.live = true;
                        node.path = path;
                    }
                }
                Ok((page_snapshot(snapshot, filter.cursor)?, deadline))
            })
            .await
    }

    async fn enroll_node(
        &self,
        actor: &str,
        request: NodeEnroll,
        now: i64,
    ) -> Result<(u64, u64), MeshApiError> {
        let mut tx = self.begin_change().await?;
        authorize(&mut tx, actor, MANAGE_NODES, &[]).await?;
        if let Some(host) = &request.host_id {
            let id = uuid::Uuid::parse_str(host).map_err(|_| MeshApiError::InvalidInput)?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND revoked_at IS NULL)",
            )
            .bind(id.as_bytes().as_slice())
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?;
            if !exists {
                return Err(MeshApiError::NotFound);
            }
        }
        // Enrolment only ever adds a remote machine; the server's node comes from its own channel.
        crate::store::make_room(&mut tx, actor, None, &request.name).await?;
        // Persist allocation history independently of live rows. Explicitly imported
        // IDs also advance allocation; exhaustion refuses before any identity is issued.
        let id: i64 = sqlx::query_scalar(
            "UPDATE mesh_state SET node_id_high_water=MAX(node_id_high_water,COALESCE((SELECT MAX(id) FROM mesh_nodes),0))+1 WHERE singleton=1 AND MAX(node_id_high_water,COALESCE((SELECT MAX(id) FROM mesh_nodes),0))<? RETURNING node_id_high_water",
        )
        .bind(i64::MAX)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| map_sql_error(error))?
        .ok_or(MeshApiError::Conflict)?;
        sqlx::query("INSERT INTO mesh_nodes(id,name,public_key,last_seen,last_rtt_us,dataplane_host) VALUES (?,?,?,NULL,NULL,?)")
            .bind(id)
            .bind(&request.name)
            .bind(request.public_key.as_slice())
            .bind(&request.host_id)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?;
        if let Some(host) = &request.host_id {
            // Only explicit management authority clears removal, atomically with
            // binding. A later channel quoting a public key has no such authority [166].
            sqlx::query("DELETE FROM mesh_dataplane_removed WHERE host=?")
                .bind(host)
                .execute(&mut *tx)
                .await
                .map_err(|error| map_sql_error(error))?;
        }
        let revision = self
            .finish_change(
                tx,
                actor,
                "mesh.node.enroll",
                &request.name,
                now,
                json!({"node_id":id,"name":request.name,"host_id":request.host_id}),
                None,
            )
            .await?;
        Ok((
            u64::try_from(id).map_err(|_| storage_error("stored node id invalid"))?,
            revision,
        ))
    }

    async fn observe_node(
        &self,
        actor: &str,
        request: NodeObservation,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let id = node_id(request.node_id)?;
        let mut tx = self.begin_change().await?;
        let scopes = endpoint_scopes(&mut tx, &Endpoint::Node(NodeId(request.node_id))).await?;
        let scope_requirements = require_each_scope(&scopes);
        authorize(&mut tx, actor, MANAGE_NODES, &scope_requirements).await?;
        // Admission time precedes the writer wait; older observations may commit
        // later. Keep liveness monotonic, including the first NULL observation.
        let changed = sqlx::query(
            "UPDATE mesh_nodes SET last_seen=MAX(COALESCE(last_seen,?),?),last_rtt_us=? WHERE id=?",
        )
        .bind(now)
        .bind(now)
        .bind(
            request
                .last_rtt_us
                .map(i64::try_from)
                .transpose()
                .map_err(|_| MeshApiError::InvalidInput)?,
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|error| map_sql_error(error))?
        .rows_affected();
        if changed != 1 {
            return Err(MeshApiError::NotFound);
        }
        self.finish_change(
            tx,
            actor,
            "mesh.node.observe",
            &id.to_string(),
            now,
            json!({"node_id":id,"last_rtt_us":request.last_rtt_us}),
            Some(scopes.into_iter().collect()),
        )
        .await
    }

    async fn rename_node(
        &self,
        actor: &str,
        request: NodeRename,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let id = node_id(request.node_id)?;
        let mut tx = self.begin_change().await?;
        // Names share one global namespace. Check authority before any name lookup: refusing only a
        // hidden collision would let scoped managers confirm hostnames by comparing it with a free name.
        authorize(&mut tx, actor, MANAGE_NODES, &[]).await?;
        let scopes = endpoint_scopes(&mut tx, &Endpoint::Node(NodeId(request.node_id))).await?;
        let mut scopes = scopes;
        for moved in crate::store::make_room(&mut tx, actor, Some(id), &request.name).await? {
            let moved =
                u64::try_from(moved).map_err(|_| storage_error("stored node id invalid"))?;
            let theirs = endpoint_scopes(&mut tx, &Endpoint::Node(NodeId(moved))).await?;
            scopes.extend(theirs);
        }
        // A person's name is final: automatic naming never touches it again (store.rs `attach_named`, #236).
        let changed = sqlx::query("UPDATE mesh_nodes SET name=?,name_source='hand' WHERE id=?")
            .bind(&request.name)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?
            .rows_affected();
        if changed != 1 {
            return Err(MeshApiError::NotFound);
        }
        self.finish_change(
            tx,
            actor,
            "mesh.node.rename",
            &id.to_string(),
            now,
            json!({"node_id":id,"name":request.name}),
            Some(scopes.into_iter().collect()),
        )
        .await
    }

    async fn delete_node(
        &self,
        actor: &str,
        request: NodeIdInput,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let id = node_id(request.node_id)?;
        let mut tx = self.begin_change().await?;
        let scopes = endpoint_scopes(&mut tx, &Endpoint::Node(NodeId(request.node_id))).await?;
        let scope_requirements = require_each_scope(&scopes);
        authorize(&mut tx, actor, MANAGE_NODES, &scope_requirements).await?;
        let server: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mesh_nodes WHERE id=? AND dataplane_host='server')",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| map_sql_error(error))?;
        if server {
            return Err(MeshApiError::Denied);
        }
        // Member removal and its reconnect refusal are one writer transaction.
        // Public unbound inventory has no host capability to retire.
        sqlx::query("INSERT INTO mesh_dataplane_removed(host) SELECT dataplane_host FROM mesh_nodes WHERE id=? AND dataplane_host IS NOT NULL ON CONFLICT(host) DO NOTHING").bind(id).execute(&mut *tx).await.map_err(|error| map_sql_error(error))?;
        let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_grants WHERE (from_kind='node' AND from_value=?) OR (to_kind='node' AND to_value=?)")
            .bind(id.to_string()).bind(id.to_string()).fetch_one(&mut *tx).await.map_err(|error| map_sql_error(error))?;
        sqlx::query("DELETE FROM mesh_grants WHERE (from_kind='node' AND from_value=?) OR (to_kind='node' AND to_value=?)")
            .bind(id.to_string()).bind(id.to_string()).execute(&mut *tx).await.map_err(|error| map_sql_error(error))?;
        let changed = sqlx::query("DELETE FROM mesh_nodes WHERE id=?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?
            .rows_affected();
        if changed != 1 {
            return Err(MeshApiError::NotFound);
        }
        let revision = self
            .finish_change(
                tx,
                actor,
                "mesh.node.delete",
                &id.to_string(),
                now,
                json!({"node_id":id,"dependent_grants":grants}),
                Some(scopes.into_iter().collect()),
            )
            .await?;
        Ok(revision)
    }

    async fn create_tag(
        &self,
        actor: &str,
        request: NamedInput,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let mut tx = self.begin_change().await?;
        authorize(&mut tx, actor, MANAGE_TAGS, &[]).await?;
        sqlx::query("INSERT INTO mesh_tags(name,created_at) VALUES (?,?)")
            .bind(&request.name)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?;
        self.finish_change(
            tx,
            actor,
            "mesh.tag.create",
            &request.name,
            now,
            json!({"name":request.name}),
            None,
        )
        .await
    }

    async fn rename_tag(
        &self,
        actor: &str,
        request: RenameInput,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let mut tx = self.begin_change().await?;
        authorize(&mut tx, actor, MANAGE_TAGS, &[]).await?;
        // Renaming cascades through every member's tag metadata, including
        // snapshots viewed through a different tag on the same host.
        let mut changed_scopes = tag_member_scopes(&mut tx, &request.name).await?;
        changed_scopes.extend([request.name.clone(), request.new_name.clone()]);
        let changed = sqlx::query("UPDATE mesh_tags SET name=? WHERE name=?")
            .bind(&request.new_name)
            .bind(&request.name)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?
            .rows_affected();
        if changed != 1 {
            return Err(MeshApiError::NotFound);
        }
        sqlx::query("UPDATE mesh_grants SET from_value=? WHERE from_kind='tag' AND from_value=?")
            .bind(&request.new_name)
            .bind(&request.name)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?;
        sqlx::query("UPDATE mesh_grants SET to_value=? WHERE to_kind='tag' AND to_value=?")
            .bind(&request.new_name)
            .bind(&request.name)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?;
        self.finish_change(
            tx,
            actor,
            "mesh.tag.rename",
            &request.name,
            now,
            json!({"name":request.name,"new_name":request.new_name}),
            Some(changed_scopes),
        )
        .await
    }

    async fn delete_tag(
        &self,
        actor: &str,
        request: NamedInput,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let mut tx = self.begin_change().await?;
        authorize(&mut tx, actor, MANAGE_TAGS, &[]).await?;
        let references: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_grants WHERE (from_kind='tag' AND from_value=?) OR (to_kind='tag' AND to_value=?)")
            .bind(&request.name).bind(&request.name).fetch_one(&mut *tx).await.map_err(|error| map_sql_error(error))?;
        if references != 0 {
            return Err(MeshApiError::Conflict);
        }
        let changed = sqlx::query("DELETE FROM mesh_tags WHERE name=?")
            .bind(&request.name)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?
            .rows_affected();
        if changed != 1 {
            return Err(MeshApiError::NotFound);
        }
        self.finish_change(
            tx,
            actor,
            "mesh.tag.delete",
            &request.name,
            now,
            json!({"name":request.name}),
            None,
        )
        .await
    }

    async fn edit_member(
        &self,
        actor: &str,
        request: MembershipInput,
        add: bool,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let id = node_id(request.node_id)?;
        let mut tx = self.begin_change().await?;
        let scopes = endpoint_scopes(&mut tx, &Endpoint::Node(NodeId(request.node_id))).await?;
        let mut requirements = require_each_scope(&scopes);
        // An empty host scope cannot be claimed by adding the editor's own tag.
        // Check pre-edit memberships under the writer lock, including every affected tag.
        if requirements.is_empty() {
            requirements.push(Vec::new());
        }
        requirements.push(vec![request.tag.clone()]);
        authorize(&mut tx, actor, MANAGE_TAGS, &requirements).await?;
        // Both existing viewers and viewers gaining this host must refresh.
        let mut changed_scopes: BTreeSet<_> = scopes.into_iter().collect();
        changed_scopes.insert(request.tag.clone());
        let sql = if add {
            "INSERT INTO mesh_tag_members(tag_name,node_id) VALUES (?,?)"
        } else {
            "DELETE FROM mesh_tag_members WHERE tag_name=? AND node_id=?"
        };
        let changed = sqlx::query(sql)
            .bind(&request.tag)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?
            .rows_affected();
        if changed != 1 {
            return Err(MeshApiError::NotFound);
        }
        let (action, detail) = if add {
            (
                "mesh.tag.member.add",
                json!({"tag":request.tag,"node_id":id}),
            )
        } else {
            (
                "mesh.tag.member.remove",
                json!({"tag":request.tag,"node_id":id}),
            )
        };
        self.finish_change(
            tx,
            actor,
            action,
            &request.tag,
            now,
            detail,
            Some(changed_scopes),
        )
        .await
    }

    async fn create_grant(
        &self,
        actor: &str,
        request: GrantCreate,
        now: i64,
    ) -> Result<(u64, u64), MeshApiError> {
        let arrow = Arrow {
            id: RuleId(1),
            from: request.from,
            to: request.to,
            both_ways: request.both_ways,
            ports: request.ports.unwrap_or(TrafficPolicy::All),
        };
        arrow.validate().map_err(|_| MeshApiError::InvalidInput)?;
        let mut tx = self.begin_change().await?;
        let scopes = endpoint_scopes(&mut tx, &arrow.from).await?;
        let mut endpoint_requirements = vec![scopes];
        endpoint_requirements.push(endpoint_scopes(&mut tx, &arrow.to).await?);
        let changed_scopes = endpoint_requirements.iter().flatten().cloned().collect();
        authorize(
            &mut tx,
            actor,
            MANAGE_GRANTS,
            &grant_requirements(&endpoint_requirements),
        )
        .await?;
        let (from_kind, from_value) = endpoint_fields(&arrow.from)?;
        let (to_kind, to_value) = endpoint_fields(&arrow.to)?;
        let policy = serde_json::to_string(&arrow.ports)
            .map_err(|_| storage_error("access ports serialization failed"))?;
        let row = sqlx::query("INSERT INTO mesh_grants(name,from_kind,from_value,to_kind,to_value,both_ways,ports_json) VALUES (?,?,?,?,?,?,?) RETURNING id")
            .bind(&request.name).bind(from_kind).bind(from_value).bind(to_kind).bind(to_value)
            .bind(arrow.both_ways).bind(policy).fetch_one(&mut *tx).await.map_err(|error| map_sql_error(error))?;
        let id: i64 = row.get("id");
        let revision = self
            .finish_change(
                tx,
                actor,
                "mesh.grant.create",
                &request.name,
                now,
                json!({"name":request.name,"grant_id":id}),
                Some(changed_scopes),
            )
            .await?;
        Ok((
            u64::try_from(id).map_err(|_| storage_error("stored rule id invalid"))?,
            revision,
        ))
    }

    async fn move_grant(
        &self,
        actor: &str,
        request: GrantMove,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let mut tx = self.begin_change().await?;
        let current = read_grant_by_name(&mut tx, &request.name).await?;
        let old = match request.side {
            EndpointSide::From => &current.arrow.from,
            EndpointSide::To => &current.arrow.to,
        };
        let mut requirements = vec![endpoint_scopes(&mut tx, old).await?];
        requirements.push(endpoint_scopes(&mut tx, &request.endpoint).await?);
        let other = match request.side {
            EndpointSide::From => &current.arrow.to,
            EndpointSide::To => &current.arrow.from,
        };
        requirements.push(endpoint_scopes(&mut tx, other).await?);
        let changed_scopes = requirements.iter().flatten().cloned().collect();
        authorize(
            &mut tx,
            actor,
            MANAGE_GRANTS,
            &grant_requirements(&requirements),
        )
        .await?;
        let (kind, value) = endpoint_fields(&request.endpoint)?;
        let column = match request.side {
            EndpointSide::From => "from",
            EndpointSide::To => "to",
        };
        let sql = format!("UPDATE mesh_grants SET {column}_kind=?,{column}_value=? WHERE name=?");
        let changed = sqlx::query(&sql)
            .bind(kind)
            .bind(value)
            .bind(&request.name)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?
            .rows_affected();
        if changed != 1 {
            return Err(MeshApiError::NotFound);
        }
        self.finish_change(
            tx,
            actor,
            "mesh.grant.move",
            &request.name,
            now,
            json!({"name":request.name,"side":column}),
            Some(changed_scopes),
        )
        .await
    }

    async fn delete_grant(
        &self,
        actor: &str,
        request: NamedInput,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let mut tx = self.begin_change().await?;
        let current = read_grant_by_name(&mut tx, &request.name).await?;
        let requirements = vec![
            endpoint_scopes(&mut tx, &current.arrow.from).await?,
            endpoint_scopes(&mut tx, &current.arrow.to).await?,
        ];
        let changed_scopes = requirements.iter().flatten().cloned().collect();
        authorize(
            &mut tx,
            actor,
            MANAGE_GRANTS,
            &grant_requirements(&requirements),
        )
        .await?;
        let changed = sqlx::query("DELETE FROM mesh_grants WHERE name=?")
            .bind(&request.name)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?
            .rows_affected();
        if changed != 1 {
            return Err(MeshApiError::NotFound);
        }
        self.finish_change(
            tx,
            actor,
            "mesh.grant.delete",
            &request.name,
            now,
            json!({"name":request.name}),
            Some(changed_scopes),
        )
        .await
    }

    async fn rename_grant(
        &self,
        actor: &str,
        request: RenameInput,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let mut tx = self.begin_change().await?;
        let current = read_grant_by_name(&mut tx, &request.name).await?;
        let requirements = vec![
            endpoint_scopes(&mut tx, &current.arrow.from).await?,
            endpoint_scopes(&mut tx, &current.arrow.to).await?,
        ];
        let changed_scopes = requirements.iter().flatten().cloned().collect();
        authorize(
            &mut tx,
            actor,
            MANAGE_GRANTS,
            &grant_requirements(&requirements),
        )
        .await?;
        let changed = sqlx::query("UPDATE mesh_grants SET name=? WHERE name=?")
            .bind(&request.new_name)
            .bind(&request.name)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?
            .rows_affected();
        if changed != 1 {
            return Err(MeshApiError::NotFound);
        }
        self.finish_change(
            tx,
            actor,
            "mesh.grant.rename",
            &request.name,
            now,
            json!({"name":request.name,"new_name":request.new_name}),
            Some(changed_scopes),
        )
        .await
    }

    async fn define_role(
        &self,
        actor: &str,
        request: RoleDefinition,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let mut tx = self.begin_change().await?;
        authorize(&mut tx, actor, MANAGE_ROLES, &[]).await?;
        sqlx::query(
            "INSERT INTO mesh_roles(name,created_at) VALUES (?,?) ON CONFLICT(name) DO NOTHING",
        )
        .bind(&request.name)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|error| map_sql_error(error))?;
        sqlx::query("DELETE FROM mesh_role_actions WHERE role_name=?")
            .bind(&request.name)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?;
        if let Some(scopes) = &request.scopes {
            for scope in scopes {
                if sqlx::query("SELECT 1 FROM mesh_tags WHERE name=?")
                    .bind(scope)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|error| map_sql_error(error))?
                    .is_none()
                {
                    return Err(MeshApiError::NotFound);
                }
            }
        }
        for action in &request.actions {
            if let Some(scopes) = &request.scopes {
                for scope in scopes {
                    sqlx::query(
                        "INSERT INTO mesh_role_actions(role_name,action,scope_tag) VALUES (?,?,?)",
                    )
                    .bind(&request.name)
                    .bind(action)
                    .bind(scope)
                    .execute(&mut *tx)
                    .await
                    .map_err(|error| map_sql_error(error))?;
                }
            } else {
                sqlx::query(
                    "INSERT INTO mesh_role_actions(role_name,action,scope_tag) VALUES (?,?,NULL)",
                )
                .bind(&request.name)
                .bind(action)
                .execute(&mut *tx)
                .await
                .map_err(|error| map_sql_error(error))?;
            }
        }
        self.finish_change(
            tx,
            actor,
            "mesh.role.define",
            &request.name,
            now,
            json!({"name":request.name,"actions":request.actions}),
            None,
        )
        .await
    }

    async fn assign_role(
        &self,
        actor: &str,
        request: RoleAssignment,
        now: i64,
    ) -> Result<u64, MeshApiError> {
        let mut tx = self.begin_change().await?;
        authorize(&mut tx, actor, MANAGE_ROLES, &[]).await?;
        sqlx::query("INSERT INTO mesh_user_roles(user_id,role_name) VALUES (?,?)")
            .bind(&request.user_id)
            .bind(&request.role)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?;
        self.finish_change(
            tx,
            actor,
            "mesh.role.assign",
            &request.user_id,
            now,
            json!({"user_id":request.user_id,"role":request.role}),
            None,
        )
        .await
    }

    async fn begin_change(&self) -> Result<Transaction<'static, Sqlite>, MeshApiError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| map_sql_error(error))?;
        // The first write acquires SQLite's writer slot before permission and object reads.
        sqlx::query("UPDATE mesh_state SET revision=revision WHERE singleton=1")
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sql_error(error))?;
        Ok(tx)
    }

    async fn finish_change(
        &self,
        mut tx: Transaction<'static, Sqlite>,
        actor: &str,
        action: &str,
        resource: &str,
        now: i64,
        detail: Value,
        scopes: Option<BTreeSet<String>>,
    ) -> Result<u64, MeshApiError> {
        let revision: i64 = sqlx::query_scalar(
            "UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 RETURNING revision",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| map_sql_error(error))?;
        let detail = serde_json::to_string(&detail)
            .map_err(|_| storage_error("audit serialization failed"))?;
        sqlx::query("INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json) VALUES (?,?,?,?,?,?)")
            .bind(actor).bind(action).bind(resource).bind(revision).bind(now).bind(detail)
            .execute(&mut *tx).await.map_err(|error| map_sql_error(error))?;
        // Re-read inside the writer transaction after all waits, immediately before
        // commit. Denial rolls back inventory, revision and audit together [28].
        if let Some(token_hash) = &self.fresh_authority
            && !infraternal_plugin_api::fresh_session_tx(
                &mut tx,
                token_hash,
                actor,
                now,
                infraternal_plugin_api::ADMIN_WINDOW_SECONDS,
            )
            .await
            .map_err(|error| map_sql_error(error))?
        {
            return Err(MeshApiError::FreshRequired);
        }
        tx.commit().await.map_err(|error| map_sql_error(error))?;
        let _ = self.updates.send(MeshChange {
            revision,
            scopes,
            liveness_deadline: (action == "mesh.node.observe")
                .then(|| now.saturating_add(NODE_LIVE_SECONDS + 1)),
        });
        u64::try_from(revision).map_err(|_| storage_error("stored revision invalid"))
    }
}

#[derive(Default)]
struct ViewAccess {
    all: bool,
    tags: BTreeSet<String>,
}

async fn view_access(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
) -> Result<ViewAccess, MeshApiError> {
    let owner: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
            .bind(actor)
            .fetch_one(&mut **tx)
            .await
            .map_err(|error| map_sql_error(error))?;
    if owner {
        return Ok(ViewAccess {
            all: true,
            tags: BTreeSet::new(),
        });
    }
    let rows = sqlx::query("SELECT DISTINCT ra.action,ra.scope_tag FROM mesh_user_roles AS ur JOIN mesh_role_actions AS ra ON ra.role_name=ur.role_name WHERE ur.user_id=?")
        .bind(actor)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| map_sql_error(error))?;
    let mut access = ViewAccess::default();
    for row in rows {
        let action: String = row.get("action");
        if !ROLE_ACTIONS.contains(&action.as_str()) {
            continue;
        }
        if let Some(tag) = row.get::<Option<String>, _>("scope_tag") {
            access.tags.insert(tag);
        } else {
            access.all = true;
        }
    }
    if !access.all && access.tags.is_empty() {
        return Err(MeshApiError::Denied);
    }
    Ok(access)
}

async fn authorize(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    action: &str,
    required_scopes: &[Vec<String>],
) -> Result<(), MeshApiError> {
    let owner: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
            .bind(actor)
            .fetch_one(&mut **tx)
            .await
            .map_err(|error| map_sql_error(error))?;
    if owner {
        return Ok(());
    }
    let rows = sqlx::query("SELECT DISTINCT ra.scope_tag FROM mesh_user_roles AS ur JOIN mesh_role_actions AS ra ON ra.role_name=ur.role_name WHERE ur.user_id=? AND ra.action=?")
        .bind(actor)
        .bind(action)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| map_sql_error(error))?;
    let mut global = false;
    let mut scopes = BTreeSet::new();
    for row in rows {
        if let Some(scope) = row.get::<Option<String>, _>("scope_tag") {
            scopes.insert(scope);
        } else {
            global = true;
        }
    }
    if global
        || (!required_scopes.is_empty()
            && required_scopes
                .iter()
                .all(|set| set.iter().any(|scope| scopes.contains(scope))))
    {
        Ok(())
    } else {
        Err(MeshApiError::Denied)
    }
}

/// Require a scoped node editor to hold access to every tag the edit can affect.
fn require_each_scope(scopes: &[String]) -> Vec<Vec<String>> {
    scopes.iter().map(|scope| vec![scope.clone()]).collect()
}

/// Every machine membership is required [211]; an empty endpoint stays
/// an unsatisfiable scoped group, preserving global-only untagged access.
fn grant_requirements(endpoints: &[Vec<String>]) -> Vec<Vec<String>> {
    endpoints
        .iter()
        .flat_map(|scopes| {
            if scopes.is_empty() {
                vec![Vec::new()]
            } else {
                require_each_scope(scopes)
            }
        })
        .collect()
}

/// Collect every tag whose viewers see metadata changed by a cascading tag rename.
async fn tag_member_scopes(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
) -> Result<BTreeSet<String>, MeshApiError> {
    let tags: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT peer.tag_name FROM mesh_tag_members AS changed JOIN mesh_tag_members AS peer ON peer.node_id=changed.node_id WHERE changed.tag_name=? ORDER BY peer.tag_name",
    )
    .bind(name)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| map_sql_error(error))?;
    Ok(tags.into_iter().collect())
}

async fn endpoint_scopes(
    tx: &mut Transaction<'_, Sqlite>,
    endpoint: &Endpoint,
) -> Result<Vec<String>, MeshApiError> {
    match endpoint {
        Endpoint::Tag(name) => {
            if sqlx::query("SELECT 1 FROM mesh_tags WHERE name=?")
                .bind(name)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| map_sql_error(error))?
                .is_some()
            {
                Ok(vec![name.clone()])
            } else {
                Err(MeshApiError::NotFound)
            }
        }
        Endpoint::Node(id) => {
            let id = node_id(id.0)?;
            let node_exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mesh_nodes WHERE id=?)")
                    .bind(id)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|error| map_sql_error(error))?;
            if !node_exists {
                return Err(MeshApiError::NotFound);
            }
            sqlx::query_scalar(
                "SELECT tag_name FROM mesh_tag_members WHERE node_id=? ORDER BY tag_name",
            )
            .bind(id)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| map_sql_error(error))
        }
        Endpoint::User(_) => Err(MeshApiError::InvalidInput),
    }
}

/// Read the server's scoped mesh view, including each node's key-rotation capability.
///
/// Viewer scopes are applied before host rows are decoded, so a mesh node outside the viewer's
/// scope contributes neither a visible entry nor a projected machine name.
/// # Errors
/// Returns a database or validation error when the snapshot cannot be read safely.
async fn read_snapshot(
    tx: &mut Transaction<'_, Sqlite>,
    revision: i64,
    now: i64,
    all: bool,
    scopes: &BTreeSet<String>,
    invalid_hosts: &crate::diagnostics::InvalidHosts,
) -> Result<MeshSnapshot, MeshApiError> {
    let node_rows = sqlx::query(
        "SELECT id,name,name_source,public_key,key_rotation_supported,last_seen,last_rtt_us FROM mesh_nodes ORDER BY id",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| map_sql_error(error))?;
    let mut memberships = BTreeMap::<i64, Vec<String>>::new();
    let mut tag_members = BTreeMap::<String, Vec<NodeId>>::new();
    for row in
        sqlx::query("SELECT tag_name,node_id FROM mesh_tag_members ORDER BY tag_name,node_id")
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| map_sql_error(error))?
    {
        let tag: String = row
            .try_get("tag_name")
            .map_err(|error| map_sql_error(error))?;
        let id: i64 = row
            .try_get("node_id")
            .map_err(|error| map_sql_error(error))?;
        memberships.entry(id).or_default().push(tag.clone());
        if let Ok(id) = u64::try_from(id) {
            tag_members.entry(tag).or_default().push(NodeId(id));
        }
    }
    let mut nodes = Vec::with_capacity(node_rows.len());
    let mut omitted = BTreeSet::new();
    for row in node_rows {
        let id: i64 = row.try_get("id").map_err(|error| map_sql_error(error))?;
        let tags = memberships.remove(&id).unwrap_or_default();
        // Scope before decoding any host fields: unrelated persisted damage
        // cannot withdraw a member's inventory or produce a diagnostic for it.
        if !all && !tags.iter().any(|tag| scopes.contains(tag)) {
            continue;
        }
        if let Some(node) = decode_host(&row, id, tags, now) {
            nodes.push(node);
        } else {
            invalid_hosts.report(id);
            if let Ok(id) = u64::try_from(id) {
                omitted.insert(NodeId(id));
            }
        }
    }
    let tag_names = sqlx::query_scalar::<_, String>("SELECT name FROM mesh_tags ORDER BY name")
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| map_sql_error(error))?;
    let mut tags: Vec<MeshTag> = tag_names
        .into_iter()
        .map(|name| MeshTag {
            members: tag_members.remove(&name).unwrap_or_default(),
            name,
        })
        .collect();
    let rows = sqlx::query("SELECT id,name,from_kind,from_value,to_kind,to_value,both_ways,ports_json FROM mesh_grants ORDER BY name")
        .fetch_all(&mut **tx).await.map_err(|error| map_sql_error(error))?;
    let mut grants = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.try_get("id").map_err(|error| map_sql_error(error))?;
        let from_kind: String = row
            .try_get("from_kind")
            .map_err(|error| map_sql_error(error))?;
        let from_value: String = row
            .try_get("from_value")
            .map_err(|error| map_sql_error(error))?;
        let to_kind: String = row
            .try_get("to_kind")
            .map_err(|error| map_sql_error(error))?;
        let to_value: String = row
            .try_get("to_value")
            .map_err(|error| map_sql_error(error))?;
        let arrow = Arrow {
            id: RuleId(u64::try_from(id).map_err(|_| storage_error("stored rule id invalid"))?),
            from: parse_endpoint(&from_kind, &from_value)?,
            to: parse_endpoint(&to_kind, &to_value)?,
            both_ways: row
                .try_get("both_ways")
                .map_err(|error| map_sql_error(error))?,
            ports: serde_json::from_str(
                &row.try_get::<String, _>("ports_json")
                    .map_err(|error| map_sql_error(error))?,
            )
            .map_err(|_| storage_error("stored access ports JSON invalid"))?,
        };
        arrow
            .validate()
            .map_err(|_| storage_error("stored access rule invalid"))?;
        grants.push(MeshGrant {
            name: row.try_get("name").map_err(|error| map_sql_error(error))?,
            arrow,
        });
    }
    // Healthy owner reads retain their allocation-free filtering path. Only
    // damaged rows require pruning dangling references from the public view.
    if !omitted.is_empty() {
        for tag in &mut tags {
            tag.members.retain(|id| !omitted.contains(id));
        }
        grants.retain(|rule| {
            [&rule.arrow.from, &rule.arrow.to]
                .iter()
                .all(|endpoint| !matches!(endpoint, Endpoint::Node(id) if omitted.contains(id)))
        });
    }
    Ok(MeshSnapshot {
        revision: u64::try_from(revision).map_err(|_| storage_error("stored revision invalid"))?,
        nodes,
        tags,
        grants,
        next_cursor: None,
    })
}

/// Isolate malformed inventory rows without logging their stored contents.
fn decode_host(
    row: &sqlx::sqlite::SqliteRow,
    id: i64,
    tags: Vec<String>,
    now: i64,
) -> Option<MeshNode> {
    let host: String = row.try_get("name").ok()?;
    validate_host(&host).ok()?;
    // The name is the machine's real name, the one DNS answers to, for every viewer that gets the row at all.
    // Who may see a machine is decided by scope before decoding (`read_snapshot`): a machine outside the
    // viewer's scope has no row, so no name is projected for it and no placeholder stands in (D327, D329).
    let key: Vec<u8> = row.try_get("public_key").ok()?;
    let key_rotation_supported: bool = row.try_get("key_rotation_supported").ok()?;
    let last_seen: Option<i64> = row.try_get("last_seen").ok()?;
    let last_rtt: Option<i64> = row.try_get("last_rtt_us").ok()?;
    Some(MeshNode {
        node: Node {
            // Browser IDs must remain exact JSON integers.
            id: NodeId(
                u64::try_from(id)
                    .ok()
                    .filter(|id| *id > 0 && *id < (1 << 53))?,
            ),
            public_key: PublicKey(key.try_into().ok()?),
            host,
            tags: tags.into_iter().collect(),
        },
        key_rotation_supported,
        live: last_seen
            .is_some_and(|seen| seen <= now && seen >= now.saturating_sub(NODE_LIVE_SECONDS)),
        last_seen,
        last_rtt_us: last_rtt.map(u64::try_from).transpose().ok()?,
        path: None,
    })
}

/// Bound list replies and subscription snapshots to the Mesh scheduling limit.
///
/// # Errors
/// Refuses invalid cursors and objects that cannot fit the bounded frame budget.
pub fn page_snapshot(
    mut snapshot: MeshSnapshot,
    cursor: Option<MeshCursor>,
) -> Result<MeshSnapshot, MeshApiError> {
    let total = snapshot.nodes.len() + snapshot.tags.len() + snapshot.grants.len();
    let start = match cursor {
        Some(cursor) if cursor.revision > snapshot.revision => {
            return Err(MeshApiError::InvalidInput);
        }
        Some(cursor) if cursor.revision == snapshot.revision => {
            if cursor.offset == 0 || cursor.offset >= total {
                return Err(MeshApiError::InvalidInput);
            }
            cursor.offset
        }
        // Changed permissions or membership invalidate the old ordering. Start a
        // fresh page; clients discard their previous revision before appending it.
        _ => 0,
    };
    let mut skip = start;
    let mut used = 0;
    let (nodes, complete) = page_items(snapshot.nodes, &mut skip, &mut used)?;
    snapshot.nodes = nodes;
    let (tags, complete) = if complete {
        page_items(snapshot.tags, &mut skip, &mut used)?
    } else {
        (Vec::new(), false)
    };
    snapshot.tags = tags;
    snapshot.grants = if complete {
        page_items(snapshot.grants, &mut skip, &mut used)?.0
    } else {
        Vec::new()
    };
    let end = start + snapshot.nodes.len() + snapshot.tags.len() + snapshot.grants.len();
    snapshot.next_cursor = (end < total).then_some(MeshCursor {
        revision: snapshot.revision,
        offset: end,
    });
    Ok(snapshot)
}

/// Take a prefix in canonical order; never skip an object that did not fit.
fn page_items<T: Serialize>(
    items: Vec<T>,
    skip: &mut usize,
    used: &mut usize,
) -> Result<(Vec<T>, bool), MeshApiError> {
    let skipped = (*skip).min(items.len());
    *skip -= skipped;
    let mut page = Vec::with_capacity(items.len() - skipped);
    for item in items.into_iter().skip(skipped) {
        let mut counter = JsonByteCount(0);
        serde_json::to_writer(&mut counter, &item).map_err(|error| {
            // The counting writer's only I/O failure is its byte limit.
            storage_error(if error.is_io() {
                "stored item exceeds frame budget"
            } else {
                "page item serialization failed"
            })
        })?;
        let size = counter.0 + 1;
        if size > PAGE_ITEM_BYTES {
            // A single unrepresentable object is a sanitized service failure,
            // never an encoder error that disconnects sibling terminal streams.
            return Err(storage_error("stored item exceeds frame budget"));
        }
        if *used + size > PAGE_ITEM_BYTES {
            return Ok((page, false));
        }
        *used += size;
        page.push(item);
    }
    Ok((page, true))
}

/// Count the serializer's exact escaping and numeric output without allocating
/// a second JSON buffer for every object. Refuse an oversized object early.
struct JsonByteCount(usize);

impl std::io::Write for JsonByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = PAGE_ITEM_BYTES - self.0;
        if bytes.len() > remaining {
            return Err(std::io::Error::other("mesh object exceeds frame budget"));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn filter_snapshot(
    mut snapshot: MeshSnapshot,
    all: bool,
    scopes: &BTreeSet<String>,
) -> MeshSnapshot {
    if all {
        return snapshot;
    }
    // Host rows were scoped before decoding; finish filtering their references.
    let visible_nodes: BTreeSet<NodeId> = snapshot.nodes.iter().map(|node| node.node.id).collect();
    snapshot
        .tags
        .retain(|tag| all || scopes.contains(&tag.name));
    for tag in &mut snapshot.tags {
        tag.members.retain(|node| visible_nodes.contains(node));
    }
    snapshot.grants.retain(|grant| {
        endpoint_visible(&grant.arrow.from, &visible_nodes, scopes)
            && endpoint_visible(&grant.arrow.to, &visible_nodes, scopes)
    });
    snapshot
}

fn endpoint_visible(
    endpoint: &Endpoint,
    nodes: &BTreeSet<NodeId>,
    scopes: &BTreeSet<String>,
) -> bool {
    match endpoint {
        Endpoint::Node(id) => nodes.contains(id),
        Endpoint::Tag(name) => scopes.contains(name),
        Endpoint::User(_) => false,
    }
}

fn parse_endpoint(kind: &str, value: &str) -> Result<Endpoint, MeshApiError> {
    match kind {
        "node" => value
            .parse::<u64>()
            .map(NodeId)
            .map(Endpoint::Node)
            .map_err(|_| storage_error("stored endpoint id invalid")),
        "tag" => Ok(Endpoint::Tag(value.to_owned())),
        _ => Err(storage_error("stored endpoint kind invalid")),
    }
}

fn endpoint_fields(endpoint: &Endpoint) -> Result<(&'static str, String), MeshApiError> {
    match endpoint {
        Endpoint::Node(id) => Ok(("node", id.0.to_string())),
        Endpoint::Tag(name) => Ok(("tag", name.clone())),
        Endpoint::User(_) => Err(MeshApiError::InvalidInput),
    }
}

async fn read_grant_by_name(
    tx: &mut Transaction<'_, Sqlite>,
    name: &str,
) -> Result<MeshGrant, MeshApiError> {
    let row = sqlx::query("SELECT id,name,from_kind,from_value,to_kind,to_value,both_ways,ports_json FROM mesh_grants WHERE name=?")
        .bind(name).fetch_optional(&mut **tx).await.map_err(|error| map_sql_error(error))?.ok_or(MeshApiError::NotFound)?;
    let id: i64 = row.try_get("id").map_err(|error| map_sql_error(error))?;
    let from_kind: String = row
        .try_get("from_kind")
        .map_err(|error| map_sql_error(error))?;
    let from_value: String = row
        .try_get("from_value")
        .map_err(|error| map_sql_error(error))?;
    let to_kind: String = row
        .try_get("to_kind")
        .map_err(|error| map_sql_error(error))?;
    let to_value: String = row
        .try_get("to_value")
        .map_err(|error| map_sql_error(error))?;
    let arrow = Arrow {
        id: RuleId(u64::try_from(id).map_err(|_| storage_error("stored rule id invalid"))?),
        from: parse_endpoint(&from_kind, &from_value)?,
        to: parse_endpoint(&to_kind, &to_value)?,
        both_ways: row
            .try_get("both_ways")
            .map_err(|error| map_sql_error(error))?,
        ports: serde_json::from_str(
            &row.try_get::<String, _>("ports_json")
                .map_err(|error| map_sql_error(error))?,
        )
        .map_err(|_| storage_error("stored access ports JSON invalid"))?,
    };
    arrow
        .validate()
        .map_err(|_| storage_error("stored access rule invalid"))?;
    Ok(MeshGrant {
        name: row.try_get("name").map_err(|error| map_sql_error(error))?,
        arrow,
    })
}

#[cold]
#[inline(never)]
#[track_caller]
fn map_sql_error(error: sqlx::Error) -> MeshApiError {
    if let sqlx::Error::Database(database) = &error {
        if database.is_unique_violation() {
            return MeshApiError::Conflict;
        }
        if database.is_foreign_key_violation() {
            return MeshApiError::NotFound;
        }
    }
    storage_sql_error(error)
}
