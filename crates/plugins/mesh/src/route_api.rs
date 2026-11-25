//! The administrator's side of subnet routes (D197 M3): list advertised networks, approve, decline, revoke.
//!
//! Nodes advertise networks through the coordinator's identity probe ([`crate::store::Store::record_routes`]);
//! nothing they say is routed until an administrator approves it here. Every write is the owner's:
//! - from the web app or a remote client, the owner with a fresh passkey tap (the actions are
//!   [`Effect::Destructive`](infraternal_plugin_api::Effect::Destructive), so the socket adapter
//!   demands freshness before the call, and the transaction checks it again before commit);
//! - from a shell on the server machine, root or the server's own account over the private control
//!   socket ([`Actor::Local`]), the authority D400 gives update actions: that caller can already
//!   replace the server's binary and database, so a passkey protects nothing there.
//!
//! Approval refuses, with a sentence, any network that may never be routed or that overlaps an
//! approved one anywhere in the mesh ([`crate::policy::networks::check_routable`], then every
//! approved row, routed or not). A refusal is an answer, not an error: `{"state":"refused","reason":…}`,
//! with nothing written, so the CLI and the UI can show the reason as it is.
//!
//! Declining marks a waiting network as turned down (owner, 2026-11-25: "Decline is remembered"): it
//! stops waiting, the row outlives the node withdrawing and re-advertising it, so a machine that keeps
//! advertising does not keep asking, and a later Approve still works and clears the decline. A
//! decline grants nothing and takes nothing away, so it is an ordinary write without a passkey tap.
//!
//! Revoking deletes the approval row, every arrow that names it, and, while the node still
//! advertises the network, puts a fresh pending row in its place. The new row has a new identity, so
//! nothing that pointed at the old approval can ever grant access again.
use crate::{
    api::MeshApiError,
    diagnostics::{storage_error, storage_sql_error},
    policy::networks::{Network, NetworkRefusal, check_routable},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};

/// The action ids, shared with the descriptor and the local control socket.
pub const LIST: &str = "mesh.route.list";
/// See [`LIST`].
pub const APPROVE: &str = "mesh.route.approve";
/// See [`LIST`].
pub const REVOKE: &str = "mesh.route.revoke";
/// See [`LIST`].
pub const DECLINE: &str = "mesh.route.decline";

/// Who is acting.
#[derive(Clone, Copy, Debug)]
pub enum Actor<'a> {
    /// A signed-in account; it must be the owner. `fresh` is the session's token hash when the
    /// call came with fresh-passkey authority, rechecked inside the write transaction.
    User {
        /// The account id.
        id: &'a str,
        /// The token hash to recheck freshness with, when the adapter demanded it.
        fresh: Option<&'a str>,
    },
    /// Root or the server's account on the server machine (D400): owner authority, no passkey.
    /// The audit row names the owner account, with `"via":"local"` in its detail.
    Local,
}

/// Input of [`APPROVE`].
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approve {
    /// The router node that advertises the network.
    pub node_id: u64,
    /// The advertised network, as text such as `192.168.1.0/24`.
    pub network: Network,
    /// Masquerade the forwarded traffic (the default, D197 M3); `false` keeps the peer's mesh
    /// address as source.
    #[serde(default = "masquerade_default")]
    pub masquerade: bool,
}

/// Masquerading is on unless the administrator turns it off (D197 M3).
const fn masquerade_default() -> bool {
    true
}

/// Input of [`REVOKE`].
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Revoke {
    /// The approval's identity, as [`LIST`] shows it.
    pub route_id: u64,
}

/// Input of [`DECLINE`].
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Decline {
    /// The waiting network's identity, as [`LIST`] shows it.
    pub route_id: u64,
}

/// A parsed route request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// List every advertised or approved network.
    List,
    /// Approve one advertised network.
    Approve(Approve),
    /// Revoke one approval.
    Revoke(Revoke),
    /// Turn down one waiting network, and remember it.
    Decline(Decline),
}

/// Parse one route action strictly, before any database work.
/// # Errors
/// `InvalidInput` for an unknown action, unknown fields or a malformed network.
pub fn parse_action(action: &str, input: &[u8]) -> Result<Request, MeshApiError> {
    /// The empty object [`LIST`] takes.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    if input.len() > 4096 || input.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(MeshApiError::InvalidInput);
    }
    let parsed = match action {
        LIST => serde_json::from_slice::<Empty>(input).map(|_| Request::List),
        APPROVE => serde_json::from_slice(input).map(Request::Approve),
        REVOKE => serde_json::from_slice(input).map(Request::Revoke),
        DECLINE => serde_json::from_slice(input).map(Request::Decline),
        _ => return Err(MeshApiError::InvalidInput),
    };
    parsed.map_err(|_| MeshApiError::InvalidInput)
}

/// Run one route request. The caller invalidates the dataplane after a write that returns a
/// `revision`, so snapshots pick the change up.
/// # Errors
/// `Denied` for a non-owner, `FreshRequired` for stale passkey authority, `NotFound` for an
/// unknown route or node, and sanitized storage errors.
pub async fn execute(
    pool: &SqlitePool,
    settings: &crate::policy::model::MeshSettings,
    actor: Actor<'_>,
    request: Request,
    now: i64,
) -> Result<Value, MeshApiError> {
    let mut tx = infraternal_plugin_api::storage::begin_immediate(pool)
        .await
        .map_err(|error| storage_sql_error(error))?;
    let auditor = authorize(&mut tx, actor, now).await?;
    let value = match request {
        Request::List => {
            let value = list(&mut tx, settings).await?;
            tx.rollback()
                .await
                .map_err(|error| storage_sql_error(error))?;
            return Ok(value);
        }
        Request::Approve(approve) => {
            match approve_in(&mut tx, settings, &approve, &auditor, now).await? {
                Ok(value) => value,
                Err(reason) => {
                    tx.rollback()
                        .await
                        .map_err(|error| storage_sql_error(error))?;
                    return Ok(json!({"state": "refused", "reason": reason}));
                }
            }
        }
        Request::Revoke(revoke) => revoke_in(&mut tx, &revoke, &auditor, now).await?,
        Request::Decline(decline) => decline_in(&mut tx, &decline, &auditor, now).await?,
    };
    // Recheck freshness at the end of the writer transaction, after every wait (D28).
    authorize(&mut tx, actor, now).await?;
    tx.commit()
        .await
        .map_err(|error| storage_sql_error(error))?;
    Ok(value)
}

/// The account the audit row names, and whether the call came over the local socket.
struct Auditor {
    /// An owner account id.
    user: String,
    /// The call came from root or the server's account on the server machine.
    local: bool,
}

/// Check owner authority (and freshness, when the adapter demanded it) inside `tx`.
async fn authorize(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    actor: Actor<'_>,
    now: i64,
) -> Result<Auditor, MeshApiError> {
    match actor {
        Actor::User { id, fresh } => {
            let owner: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
                    .bind(id)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(|error| storage_sql_error(error))?;
            if !owner {
                return Err(MeshApiError::Denied);
            }
            if let Some(hash) = fresh
                && !infraternal_plugin_api::fresh_session_tx(
                    tx,
                    hash,
                    id,
                    now,
                    infraternal_plugin_api::ADMIN_WINDOW_SECONDS,
                )
                .await
                .map_err(|error| storage_sql_error(error))?
            {
                return Err(MeshApiError::FreshRequired);
            }
            Ok(Auditor {
                user: id.to_owned(),
                local: false,
            })
        }
        Actor::Local => {
            let owner: Option<String> =
                sqlx::query_scalar("SELECT id FROM users WHERE owner=1 ORDER BY id LIMIT 1")
                    .fetch_optional(&mut **tx)
                    .await
                    .map_err(|error| storage_sql_error(error))?;
            // A server without an owner has nobody to act for; finish setup first.
            let user = owner.ok_or(MeshApiError::Denied)?;
            Ok(Auditor { user, local: true })
        }
    }
}

/// Every advertised, approved or declined network, with its router's name, whether the router
/// advertises it now, and, for a waiting one, the reason an approval would be refused right now.
async fn list(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    settings: &crate::policy::model::MeshSettings,
) -> Result<Value, MeshApiError> {
    let approved = approved_networks(tx, None).await?;
    let rows = sqlx::query(
        "SELECT r.id,r.node_id,n.name,r.network,r.advertised,r.approved_at,r.approved_by,r.masquerade,r.declined_at \
         FROM mesh_routes AS r JOIN mesh_nodes AS n ON n.id=r.node_id ORDER BY r.node_id,r.network",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| storage_sql_error(error))?;
    let mut routes = Vec::new();
    for row in rows {
        let id: i64 = row
            .try_get("id")
            .map_err(|error| storage_sql_error(error))?;
        let text: String = row
            .try_get("network")
            .map_err(|error| storage_sql_error(error))?;
        let approved_at: Option<i64> = row
            .try_get("approved_at")
            .map_err(|error| storage_sql_error(error))?;
        let advertised: bool = row
            .try_get("advertised")
            .map_err(|error| storage_sql_error(error))?;
        let declined_at: Option<i64> = row
            .try_get("declined_at")
            .map_err(|error| storage_sql_error(error))?;
        let state = match (approved_at.is_some(), advertised, declined_at.is_some()) {
            (true, true, _) => "approved",
            (true, false, _) => "approved, not advertised",
            (false, _, true) => "declined",
            (false, _, false) => "waiting for approval",
        };
        let mut route = json!({
            "route_id": id,
            "node_id": row.try_get::<i64, _>("node_id").map_err(|error| storage_sql_error(error))?,
            "node": row.try_get::<String, _>("name").map_err(|error| storage_sql_error(error))?,
            "network": text,
            "state": state,
            "advertised": advertised,
            "masquerade": row.try_get::<bool, _>("masquerade").map_err(|error| storage_sql_error(error))?,
        });
        if let Some(at) = approved_at {
            route["approved_at"] = json!(at);
        }
        if approved_at.is_none() && declined_at.is_none() {
            let reason = match text.parse::<Network>() {
                Ok(network) => refusal(network, settings, &approved, None).map(|r| r.to_string()),
                Err(error) => Some(error.to_string()),
            };
            if let Some(reason) = reason {
                route["refused"] = json!(reason);
            }
        }
        routes.push(route);
    }
    Ok(json!({"routes": routes}))
}

/// Every approved network (routed or not), except the one with identity `ignore`.
async fn approved_networks(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ignore: Option<i64>,
) -> Result<Vec<crate::policy::networks::ApprovedNetwork>, MeshApiError> {
    let rows = sqlx::query(
        "SELECT id,node_id,network,masquerade FROM mesh_routes WHERE approved_at IS NOT NULL",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| storage_sql_error(error))?;
    let mut approved = Vec::new();
    for row in rows {
        let id: i64 = row
            .try_get("id")
            .map_err(|error| storage_sql_error(error))?;
        if Some(id) == ignore {
            continue;
        }
        let node: i64 = row
            .try_get("node_id")
            .map_err(|error| storage_sql_error(error))?;
        let network: String = row
            .try_get("network")
            .map_err(|error| storage_sql_error(error))?;
        let (Ok(id), Ok(node), Ok(network)) = (
            u64::try_from(id),
            u64::try_from(node),
            network.parse::<Network>(),
        ) else {
            return Err(storage_error("Mesh route invalid."));
        };
        approved.push(crate::policy::networks::ApprovedNetwork {
            id: crate::policy::networks::NetworkId(id),
            router: crate::policy::model::NodeId(node),
            network,
            masquerade: row
                .try_get("masquerade")
                .map_err(|error| storage_sql_error(error))?,
        });
    }
    Ok(approved)
}

/// Why `network` could not be approved now: the routability rules, then any overlap with an
/// approved network other than `ignore`.
fn refusal(
    network: Network,
    settings: &crate::policy::model::MeshSettings,
    approved: &[crate::policy::networks::ApprovedNetwork],
    ignore: Option<crate::policy::networks::NetworkId>,
) -> Option<NetworkRefusal> {
    if let Err(refusal) = check_routable(network, settings) {
        return Some(refusal);
    }
    approved
        .iter()
        .filter(|other| Some(other.id) != ignore)
        .find(|other| other.network.overlaps(network))
        .map(|other| NetworkRefusal::Overlap {
            network,
            approved: *other,
        })
}

/// Approve one advertised network, or say why not. `Ok(Err(reason))` is a refusal with nothing
/// written; `Ok(Ok(value))` names the approval and the new revision.
async fn approve_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    settings: &crate::policy::model::MeshSettings,
    approve: &Approve,
    auditor: &Auditor,
    now: i64,
) -> Result<Result<Value, String>, MeshApiError> {
    let node = i64::try_from(approve.node_id).map_err(|_| MeshApiError::InvalidInput)?;
    let text = approve.network.to_string();
    let row = sqlx::query(
        "SELECT id,advertised,approved_at,masquerade FROM mesh_routes WHERE node_id=? AND network=?",
    )
    .bind(node)
    .bind(&text)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| storage_sql_error(error))?;
    let Some(row) = row else {
        return Ok(Err(format!(
            "node {} does not advertise {text}; run infraternal mesh routes advertise {text} on it first",
            approve.node_id
        )));
    };
    let id: i64 = row
        .try_get("id")
        .map_err(|error| storage_sql_error(error))?;
    let advertised: bool = row
        .try_get("advertised")
        .map_err(|error| storage_sql_error(error))?;
    let approved_at: Option<i64> = row
        .try_get("approved_at")
        .map_err(|error| storage_sql_error(error))?;
    let masquerade: bool = row
        .try_get("masquerade")
        .map_err(|error| storage_sql_error(error))?;
    if approved_at.is_none() && !advertised {
        return Ok(Err(format!(
            "node {} no longer advertises {text}",
            approve.node_id
        )));
    }
    if approved_at.is_some() && masquerade == approve.masquerade {
        // Already approved as asked: nothing to write, no revision.
        return Ok(Ok(json!({"state": "approved", "route_id": id})));
    }
    let approved = approved_networks(tx, Some(id)).await?;
    if let Some(reason) = refusal(approve.network, settings, &approved, None) {
        return Ok(Err(reason.to_string()));
    }
    // Approving a declined network takes the decline back: a row is never both.
    sqlx::query("UPDATE mesh_routes SET approved_at=?,approved_by=?,masquerade=?,declined_at=NULL,declined_by=NULL WHERE id=?")
        .bind(approved_at.unwrap_or(now))
        .bind(&auditor.user)
        .bind(approve.masquerade)
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    let revision = bump(
        tx,
        auditor,
        APPROVE,
        &text,
        now,
        json!({"route_id": id, "node_id": approve.node_id, "network": text, "masquerade": approve.masquerade, "via": if auditor.local { "local" } else { "session" }}),
    )
    .await?;
    Ok(Ok(
        json!({"state": "approved", "route_id": id, "revision": revision}),
    ))
}

/// Revoke one approval: drop it, the arrows that name it, and re-list the network as waiting
/// when its node still advertises it.
async fn revoke_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    revoke: &Revoke,
    auditor: &Auditor,
    now: i64,
) -> Result<Value, MeshApiError> {
    let id = i64::try_from(revoke.route_id).map_err(|_| MeshApiError::InvalidInput)?;
    let row = sqlx::query(
        "SELECT node_id,network,advertised FROM mesh_routes WHERE id=? AND approved_at IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| storage_sql_error(error))?
    .ok_or(MeshApiError::NotFound)?;
    let node: i64 = row
        .try_get("node_id")
        .map_err(|error| storage_sql_error(error))?;
    let network: String = row
        .try_get("network")
        .map_err(|error| storage_sql_error(error))?;
    let advertised: bool = row
        .try_get("advertised")
        .map_err(|error| storage_sql_error(error))?;
    sqlx::query("DELETE FROM mesh_routes WHERE id=?")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    let arrows = sqlx::query("DELETE FROM mesh_grants WHERE to_kind='network' AND to_value=?")
        .bind(id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(|error| storage_sql_error(error))?
        .rows_affected();
    if advertised {
        sqlx::query("INSERT INTO mesh_routes(node_id,network) VALUES (?,?)")
            .bind(node)
            .bind(&network)
            .execute(&mut **tx)
            .await
            .map_err(|error| storage_sql_error(error))?;
    }
    let revision = bump(
        tx,
        auditor,
        REVOKE,
        &network,
        now,
        json!({"route_id": id, "node_id": node, "network": network, "arrows_removed": arrows, "via": if auditor.local { "local" } else { "session" }}),
    )
    .await?;
    Ok(json!({"state": "revoked", "route_id": id, "arrows_removed": arrows, "revision": revision}))
}

/// Decline one waiting network: mark it turned down so it stops waiting and is not asked about again.
/// Declining twice is answered as done without a second write. An approved network is revoked, not
/// declined (`NotFound`), so a decline can never take access away.
async fn decline_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    decline: &Decline,
    auditor: &Auditor,
    now: i64,
) -> Result<Value, MeshApiError> {
    let id = i64::try_from(decline.route_id).map_err(|_| MeshApiError::InvalidInput)?;
    let row = sqlx::query(
        "SELECT node_id,network,declined_at FROM mesh_routes WHERE id=? AND approved_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| storage_sql_error(error))?
    .ok_or(MeshApiError::NotFound)?;
    let declined: Option<i64> = row
        .try_get("declined_at")
        .map_err(|error| storage_sql_error(error))?;
    if declined.is_some() {
        return Ok(json!({"state": "declined", "route_id": id}));
    }
    let node: i64 = row
        .try_get("node_id")
        .map_err(|error| storage_sql_error(error))?;
    let network: String = row
        .try_get("network")
        .map_err(|error| storage_sql_error(error))?;
    sqlx::query("UPDATE mesh_routes SET declined_at=?,declined_by=? WHERE id=?")
        .bind(now)
        .bind(&auditor.user)
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    let revision = bump(
        tx,
        auditor,
        DECLINE,
        &network,
        now,
        json!({"route_id": id, "node_id": node, "network": network, "via": if auditor.local { "local" } else { "session" }}),
    )
    .await?;
    Ok(json!({"state": "declined", "route_id": id, "revision": revision}))
}

/// Advance the mesh revision and write the audit row for one route change.
async fn bump(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    auditor: &Auditor,
    action: &str,
    resource: &str,
    now: i64,
    detail: Value,
) -> Result<i64, MeshApiError> {
    let revision: i64 = sqlx::query_scalar(
        "UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 RETURNING revision",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| storage_sql_error(error))?;
    let detail =
        serde_json::to_string(&detail).map_err(|_| storage_error("audit serialization failed"))?;
    sqlx::query("INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json) VALUES (?,?,?,?,?,?)")
        .bind(&auditor.user)
        .bind(action)
        .bind(resource)
        .bind(revision)
        .bind(now)
        .bind(detail)
        .execute(&mut **tx)
        .await
        .map_err(|error| storage_sql_error(error))?;
    Ok(revision)
}

#[cfg(test)]
mod tests {
    //! Strict parsing before storage.
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Route requests are strict: canonical networks, no unknown fields, no other actions, objects only.
    #[test]
    fn route_requests_are_strict() {
        assert_eq!(parse_action(LIST, b"{}"), Ok(Request::List));
        assert_eq!(
            parse_action(DECLINE, br#"{"route_id":4}"#),
            Ok(Request::Decline(Decline { route_id: 4 }))
        );
        assert_eq!(
            parse_action(APPROVE, br#"{"node_id":2,"network":"192.168.1.0/24"}"#),
            Ok(Request::Approve(Approve {
                node_id: 2,
                network: "192.168.1.0/24".parse().unwrap(),
                masquerade: true,
            }))
        );
        for (action, input) in [
            (APPROVE, &br#"{"node_id":2,"network":"192.168.1.7/24"}"#[..]),
            (
                APPROVE,
                br#"{"node_id":2,"network":"192.168.1.0/24","extra":1}"#,
            ),
            (REVOKE, br#"{"route_id":"1"}"#),
            (DECLINE, br#"{"route_id":1,"why":"noise"}"#),
            (LIST, br#"{"all":true}"#),
            ("mesh.route.other", b"{}"),
            (LIST, b"[]"),
        ] {
            assert_eq!(
                parse_action(action, input),
                Err(MeshApiError::InvalidInput),
                "{action} {input:?}"
            );
        }
    }
}

/// Advertise, approve, route and revoke through real storage.
#[cfg(test)]
#[path = "route_api_tests.rs"]
mod flow_tests;
