//! Authenticates API-key action calls and applies the explicit scope boundary [16][202][303].

use crate::{auth::Auth, remote_removal::Removal, websocket::WebSocketState};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use bytes::Bytes;
use infraternal_plugin_api::{ActionDef, Operation, SocketHost};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

/// The one action catalogue for every adapter: core server actions, server-side socket
/// plugins (host inventory, canvas, ...) and the infraternal agent's compiled descriptors.
fn shared_action(state: &WebSocketState, action_id: &str) -> Option<ActionDef> {
    infraternal_plugin_api::CORE_API_ACTIONS
        .iter()
        .find(|action| action.id == action_id)
        .copied()
        .or_else(|| state.plugins.action(action_id))
        .or_else(|| state.action(action_id))
}

/// Accept one bearer value from Authorization only; duplicate headers fail closed.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty()
        || token.trim() != token
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return None;
    }
    Some(token)
}

/// Cookie-bearing requests are not part of this bearer-only API surface.
fn bearer_only(headers: &HeaderMap) -> Option<&str> {
    if headers.contains_key(header::COOKIE) {
        return None;
    }
    bearer_token(headers)
}

/// Audit rows, and the one-way ids of revoked or expired keys they name, are kept for 90
/// days. The table also holds at most `AUDIT_MAX_ROWS` rows, so even a live key at its full
/// rate limit cannot grow it without bound (J137 P2-1).
pub(crate) const AUDIT_RETENTION_SECONDS: i64 = 90 * 86_400;
const AUDIT_MAX_ROWS: i64 = 100_000;
/// No key action stays open this long: HTTP actions time out after 15 s, the bootstrap
/// stream finishes its row as soon as the batch starts, and a removal request expires after
/// 300 s. A row still `pending` after this never finished (an unpolled removal, or a server
/// restart mid-action) and is resolved as an expired denial.
const PENDING_AUDIT_SECONDS: i64 = 3600;
/// Retention runs at most this often, piggybacked on an audit write; there is no idle task.
const PRUNE_INTERVAL_SECONDS: i64 = 3600;

/// Apply the audit retention bound, expire never-finished rows, and drop long-dead keys.
pub(crate) async fn prune_audit(pool: &SqlitePool, now: i64) -> Result<(), sqlx::Error> {
    let cutoff = now.saturating_sub(AUDIT_RETENTION_SECONDS);
    let mut tx = infraternal_plugin_api::storage::begin_immediate(pool).await?;
    sqlx::query("UPDATE api_action_audit SET state='denied',result='expired',completed_at=? WHERE state='pending' AND occurred_at<?")
        .bind(now)
        .bind(now.saturating_sub(PENDING_AUDIT_SECONDS))
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM api_action_audit WHERE occurred_at<?")
        .bind(cutoff)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM api_action_audit WHERE id<=(SELECT id FROM api_action_audit ORDER BY id DESC LIMIT 1 OFFSET ?)")
        .bind(AUDIT_MAX_ROWS)
        .execute(&mut *tx)
        .await?;
    // A dead key's `expires_at` is its expiry or revocation time. Past the audit bound no
    // row names it any more, and a later call with it is simply an unknown bearer.
    sqlx::query("DELETE FROM api_keys WHERE dead=1 AND expires_at<?")
        .bind(cutoff)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

/// Calls per key per minute, shared by the HTTP route and the bootstrap stream.
const KEY_CALLS_PER_WINDOW: u16 = 30;
/// Calls per minute shared by every bearer that names no stored key. These are refused from
/// a read, never take the writer and write no audit row; the bucket only bounds that read load.
const UNKNOWN_CALLS_PER_WINDOW: u16 = 60;

/// Fixed one-minute window. A backward clock jump cannot give a key extra attempts.
#[derive(Debug, Default)]
struct RateLimit {
    start: i64,
    used: u16,
    /// One `denied` audit row per key per window, whatever the number of refusals.
    denial_audited: bool,
}

impl RateLimit {
    fn admit(&mut self, now: i64, max_calls: u16) -> bool {
        const WINDOW_SECONDS: i64 = 60;
        if self.used == 0 {
            self.start = now;
        } else if now >= self.start.saturating_add(WINDOW_SECONDS) {
            self.start = now;
            self.used = 0;
            self.denial_audited = false;
        } else if now < self.start {
            return false;
        }
        if self.used >= max_calls {
            return false;
        }
        self.used += 1;
        true
    }

    fn first_denial(&mut self) -> bool {
        !std::mem::replace(&mut self.denial_audited, true)
    }

    fn stale(&self, now: i64) -> bool {
        self.used == 0 || now >= self.start.saturating_add(60)
    }
}

#[derive(Default)]
struct Limits {
    /// Only stored keys get an entry, so random bearers cannot fill or evict this map.
    keys: HashMap<String, RateLimit>,
    unknown: RateLimit,
}

/// Safe identity for audit rows. The bearer value is never retained in the request state.
#[derive(Clone)]
pub(crate) struct AuthorizedKey {
    pub(crate) key_id: String,
    pub(crate) person_id: String,
    pub(crate) device: String,
}

/// A stored, live-looking key that passed the per-key limit but has not yet been
/// authorized for any scope.
pub(crate) struct AdmittedKey {
    key_id: String,
    person_id: String,
}

/// Shared by HTTP actions and the existing bootstrap WebSocket action.
#[derive(Clone)]
pub(crate) struct ActionGuard {
    auth: Auth,
    pool: SqlitePool,
    limits: Arc<Mutex<Limits>>,
    last_prune: Arc<std::sync::atomic::AtomicI64>,
}

impl ActionGuard {
    pub(crate) fn new(auth: Auth, pool: SqlitePool) -> Self {
        Self {
            auth,
            pool,
            limits: Arc::default(),
            last_prune: Arc::new(std::sync::atomic::AtomicI64::new(i64::MIN)),
        }
    }

    /// Identify the bearer and charge its rate limit before any authorization work.
    ///
    /// Order (J137 P2-1): one read classifies the bearer. An unknown bearer is charged to a
    /// shared bucket and refused without the writer or an audit row. A stored key is charged
    /// to its own limit next, and only then does a revoked or expired key get refused. All
    /// refusals of one key share at most one `denied` row per window. `action_id` names the
    /// requested action for that row; callers pass a catalogue id, never caller text.
    pub(crate) async fn admit_token(
        &self,
        token: &str,
        action_id: &'static str,
    ) -> Result<AdmittedKey, StatusCode> {
        let key_id = crate::auth::hash(token);
        let now = crate::runtime::unix_seconds().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let row: Option<(String, bool, i64)> =
            sqlx::query_as("SELECT user_id,dead,expires_at FROM api_keys WHERE token_hash=?")
                .bind(&key_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let Some((person_id, dead, expires_at)) = row else {
            let admitted = self
                .limits
                .lock()
                .await
                .unknown
                .admit(now, UNKNOWN_CALLS_PER_WINDOW);
            return Err(if admitted {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::TOO_MANY_REQUESTS
            });
        };
        if !self.admit(&key_id, now).await {
            self.audit_denied(&key_id, &person_id, action_id, now).await;
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        if dead || expires_at <= now {
            if !dead {
                // J90 tombstones a key whose stored expiry passed; the refusal is the point.
                let _ = self.auth.api_authorize_key_hash(&key_id, "").await;
            }
            self.audit_denied(&key_id, &person_id, action_id, now).await;
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(AdmittedKey { key_id, person_id })
    }

    /// Authorize an admitted key for one key-callable action's scope through J90.
    pub(crate) async fn authorize_admitted(
        &self,
        admitted: AdmittedKey,
        action: &ActionDef,
    ) -> Result<AuthorizedKey, StatusCode> {
        if !action.key_callable() {
            return Err(StatusCode::NOT_FOUND);
        }
        let scope = action.api_scope.ok_or(StatusCode::NOT_FOUND)?;
        let AdmittedKey { key_id, person_id } = admitted;
        match self.auth.api_authorize_context(&key_id, scope).await {
            Ok((person, device)) if person == person_id => Ok(AuthorizedKey {
                key_id,
                person_id,
                device,
            }),
            _ => {
                let now =
                    crate::runtime::unix_seconds().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                self.audit_denied(&key_id, &person_id, action.id, now).await;
                Err(StatusCode::FORBIDDEN)
            }
        }
    }

    /// Check the API key's current liveness and the scope required by one known action.
    pub(crate) async fn authorize_token(
        &self,
        token: &str,
        action: &ActionDef,
    ) -> Result<AuthorizedKey, StatusCode> {
        let admitted = self.admit_token(token, action.id).await?;
        self.authorize_admitted(admitted, action).await
    }

    /// Recheck the same key id, person and action scope without retaining the bearer value.
    pub(crate) async fn identity_is_live(&self, identity: &AuthorizedKey, scope: &str) -> bool {
        self.auth
            .api_authorize_key_hash(&identity.key_id, scope)
            .await
            .is_ok_and(|person_id| person_id == identity.person_id)
    }

    /// Charge an already authenticated streaming caller the same per-key limit as a one-shot
    /// request, then revalidate it against this message's own action scope.
    pub(crate) async fn authorize_identity(
        &self,
        identity: &AuthorizedKey,
        action: &ActionDef,
    ) -> Result<i64, StatusCode> {
        let scope = action.api_scope.ok_or(StatusCode::NOT_FOUND)?;
        let now = crate::runtime::unix_seconds().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !self.admit(&identity.key_id, now).await {
            self.audit_denied(&identity.key_id, &identity.person_id, action.id, now)
                .await;
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        if !self.identity_is_live(identity, scope).await {
            self.audit_denied(&identity.key_id, &identity.person_id, action.id, now)
                .await;
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(now)
    }

    /// Record a key action without payloads or plaintext credentials.
    pub(crate) async fn begin_audit(
        &self,
        identity: &AuthorizedKey,
        action_id: &str,
        target_id: Option<&str>,
        now: i64,
    ) -> Result<i64, StatusCode> {
        self.insert_audit(
            &identity.key_id,
            &identity.person_id,
            action_id,
            target_id,
            "pending",
            now,
        )
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }

    pub(crate) async fn finish_audit(
        &self,
        audit_id: i64,
        state: &'static str,
        result: Option<&'static str>,
        now: i64,
    ) -> Result<(), StatusCode> {
        sqlx::query("UPDATE api_action_audit SET state=?,completed_at=?,result=? WHERE id=? AND state='pending'")
            .bind(state)
            .bind(now)
            .bind(result)
            .bind(audit_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    }

    async fn admit(&self, key_id: &str, now: i64) -> bool {
        let mut limits = self.limits.lock().await;
        // Entries exist only for stored keys; the cap is a backstop, not a working limit.
        if limits.keys.len() >= 4096 {
            limits.keys.retain(|_, limit| !limit.stale(now));
        }
        if limits.keys.len() >= 4096 && !limits.keys.contains_key(key_id) {
            return false;
        }
        limits
            .keys
            .entry(key_id.to_owned())
            .or_default()
            .admit(now, KEY_CALLS_PER_WINDOW)
    }

    /// Write this key's one `denied` row for the current window; later refusals in the same
    /// window are counted by the limiter only. Scope denials and revoked or expired keys keep
    /// their owner attribution.
    async fn audit_denied(&self, key_id: &str, person_id: &str, action_id: &str, now: i64) {
        let first = self
            .limits
            .lock()
            .await
            .keys
            .get_mut(key_id)
            .is_some_and(RateLimit::first_denial);
        if first {
            let _ = self
                .insert_audit(key_id, person_id, action_id, None, "denied", now)
                .await;
        }
    }

    async fn insert_audit(
        &self,
        key_id: &str,
        person_id: &str,
        action_id: &str,
        target_id: Option<&str>,
        state: &'static str,
        now: i64,
    ) -> Result<i64, sqlx::Error> {
        let id = sqlx::query_scalar("INSERT INTO api_action_audit(key_id,person_id,action_id,target_id,state,occurred_at) VALUES(?,?,?,?,?,?) RETURNING id")
            .bind(key_id)
            .bind(person_id)
            .bind(action_id)
            .bind(target_id)
            .bind(state)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;
        self.prune_if_due(now).await;
        Ok(id)
    }

    /// One caller per interval wins the swap and prunes; a failed prune retries next interval.
    async fn prune_if_due(&self, now: i64) {
        use std::sync::atomic::Ordering;
        let last = self.last_prune.load(Ordering::Acquire);
        if now < last.saturating_add(PRUNE_INTERVAL_SECONDS)
            || self
                .last_prune
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let _ = prune_audit(&self.pool, now).await;
    }
}

/// Plugin handlers see the authenticated key identity, never its bearer plaintext or tap authority.
struct ApiActionHost {
    guard: ActionGuard,
    state: WebSocketState,
    identity: AuthorizedKey,
    scope: &'static str,
}

impl ApiActionHost {
    async fn key_is_live(&self) -> bool {
        self.guard
            .identity_is_live(&self.identity, self.scope)
            .await
    }
}

impl SocketHost for ApiActionHost {
    fn user_id(&self) -> &str {
        &self.identity.person_id
    }

    fn node_action_declared(&self, action_id: &str) -> bool {
        self.state.action(action_id).is_some()
    }

    fn token_hash(&self) -> &str {
        &self.identity.key_id
    }

    fn device_label(&self) -> Option<&str> {
        Some(&self.identity.device)
    }

    fn authorized<'a>(
        &'a self,
        operation: Operation<'a, Result<(), ()>>,
    ) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            if !self.key_is_live().await {
                return Err(());
            }
            let result = operation.await;
            if !self.key_is_live().await {
                return Err(());
            }
            result
        })
    }

    fn fresh(&self, _: i64) -> Operation<'_, bool> {
        Box::pin(async { false })
    }

    fn live(&self) -> Operation<'_, bool> {
        Box::pin(async move { self.key_is_live().await })
    }

    fn may_configure(&self) -> Operation<'_, bool> {
        Box::pin(async { false })
    }
}

struct PluginActionResult {
    ok: bool,
    value: Value,
}

async fn dispatch_plugin_action(
    api: &Api,
    action: ActionDef,
    identity: AuthorizedKey,
    input: Value,
) -> Result<PluginActionResult, StatusCode> {
    let input = serde_json::to_vec(&input).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Call {
            call_id: 1,
            action_id: action.id,
            input_json: &input,
        },
        &mut wire,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    let host: Arc<dyn SocketHost> = Arc::new(ApiActionHost {
        guard: api.guard.clone(),
        state: api.sessions.clone(),
        identity,
        scope: action.api_scope.ok_or(StatusCode::NOT_FOUND)?,
    });
    let mut plugins = crate::plugins::SocketPlugins::new(api.sessions.plugins.clone(), host);
    let mut encoded = Vec::new();
    let immediate = match plugins.dispatch(&Bytes::from(wire), &mut encoded) {
        crate::plugins::Dispatch::Queued => None,
        crate::plugins::Dispatch::Refused(wire) => Some(wire),
        crate::plugins::Dispatch::Unhandled => return Err(StatusCode::NOT_FOUND),
    };
    let response = if let Some(wire) = immediate {
        wire
    } else {
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let reply = plugins
                    .recv()
                    .await
                    .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
                if let Some(wire) = plugins.accept(reply, &mut encoded) {
                    let decoded = decode_muxed_frame(&wire).map_err(|_| StatusCode::BAD_GATEWAY)?;
                    if decoded.stream_id == 0
                        && matches!(decoded.frame, Frame::Result { call_id: 1, .. })
                    {
                        break Ok::<Bytes, StatusCode>(wire);
                    }
                }
            }
        })
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)??
    };
    let decoded = decode_muxed_frame(&response).map_err(|_| StatusCode::BAD_GATEWAY)?;
    match decoded.frame {
        Frame::Result {
            call_id: 1,
            ok,
            json,
        } if decoded.stream_id == 0 => {
            let value = serde_json::from_slice(json).map_err(|_| StatusCode::BAD_GATEWAY)?;
            Ok(PluginActionResult { ok, value })
        }
        _ => Err(StatusCode::BAD_GATEWAY),
    }
}

#[derive(Clone)]
struct Api {
    guard: ActionGuard,
    removal: Removal,
    pool: SqlitePool,
    sessions: WebSocketState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovalInput {
    host_id: Uuid,
    #[serde(default = "default_uninstall")]
    uninstall: bool,
}

fn default_uninstall() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovalStatusInput {
    request_id: String,
}

/// Mounts the bearer action adapter beside the browser handlers; each adapter calls the same
/// inventory, removal, session-snapshot and health paths used by the app.
pub(crate) fn router(
    pool: SqlitePool,
    removal: Removal,
    sessions: WebSocketState,
    guard: ActionGuard,
) -> Router {
    let api = Api {
        guard,
        removal,
        pool,
        sessions,
    };
    Router::new()
        .route("/v1/actions/{action_id}", post(action))
        .route(
            "/v1/actions/remote.host.remove/status",
            post(removal_status),
        )
        .layer(axum::extract::DefaultBodyLimit::max(32 * 1024))
        .with_state(api)
}

async fn action(
    State(api): State<Api>,
    Path(action_id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<Value>,
) -> Response {
    // This surface is bearer-only. Cookies do not establish API authority and need no CSRF path.
    let Some(token) = bearer_only(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // The key is admitted before the response depends on the catalogue: any bearer that is
    // not a live stored key gets the same 403 (or 429) for every id, so it cannot tell which
    // actions exist or are key-callable. The in-memory lookup only names the audit row.
    let action = shared_action(&api.sessions, &action_id).filter(ActionDef::key_callable);
    let admitted = match api
        .guard
        .admit_token(token, action.map_or("unknown", |action| action.id))
        .await
    {
        Ok(admitted) => admitted,
        Err(status) => return status.into_response(),
    };
    let Some(action) = action else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let identity = match api.guard.authorize_admitted(admitted, &action).await {
        Ok(identity) => identity,
        Err(status) => return status.into_response(),
    };
    let target_id = audit_target(&input);
    let target_id = target_id.as_deref();
    let Ok(now) = crate::runtime::unix_seconds() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let audit_id = match api
        .guard
        .begin_audit(&identity, &action_id, target_id, now)
        .await
    {
        Ok(audit_id) => audit_id,
        Err(status) => return status.into_response(),
    };
    let result: Result<(Json<Value>, bool), StatusCode> = match action_id.as_str() {
        "server.status" if !action.fresh_passkey => {
            server_status(&api.pool).await.map(|value| (value, true))
        }
        "sessions.list" if !action.fresh_passkey => session_list(&api, &identity.person_id)
            .await
            .map(|value| (value, true)),
        "remote.host.remove" if action.fresh_passkey => {
            start_removal(&api, token, &input, now, audit_id)
                .await
                .map(|value| (Json(value), true))
        }
        // ssh.start uses the existing bounded bootstrap WebSocket adapter.
        "ssh.start" => Err(StatusCode::BAD_REQUEST),
        _ if action.fresh_passkey => Err(StatusCode::NOT_FOUND),
        _ => dispatch_plugin_action(&api, action, identity, input)
            .await
            .map(|result| (Json(result.value), result.ok)),
    };
    match result {
        Ok((value, _)) if action_id == "remote.host.remove" => value.into_response(),
        Ok((value, true)) => {
            if api
                .guard
                .finish_audit(audit_id, "complete", None, now)
                .await
                .is_err()
            {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            value.into_response()
        }
        Ok((value, false)) => {
            let _ = api
                .guard
                .finish_audit(audit_id, "failed", Some("handler_refused"), now)
                .await;
            (StatusCode::BAD_REQUEST, value).into_response()
        }
        Err(status) => {
            let state = if status == StatusCode::TOO_MANY_REQUESTS {
                "denied"
            } else {
                "failed"
            };
            let _ = api.guard.finish_audit(audit_id, state, None, now).await;
            status.into_response()
        }
    }
}

/// The audit names a target only as a parsed host UUID, never as caller-supplied text.
fn audit_target(input: &Value) -> Option<String> {
    input
        .get("host_id")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .map(|host| host.to_string())
}

async fn server_status(pool: &SqlitePool) -> Result<Json<Value>, StatusCode> {
    let healthy = crate::runtime::server_healthy(pool).await;
    if !healthy {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(Json(json!({
        "role": "server",
        "components": [{"name":"server","state":"running","state_detail":"ready"}]
    })))
}

async fn session_list(api: &Api, person_id: &str) -> Result<Json<Value>, StatusCode> {
    let snapshot = crate::websocket::terminal_sessions_snapshot(&api.sessions, person_id)
        .await
        .map_err(|()| StatusCode::SERVICE_UNAVAILABLE)?;
    if snapshot["type"] != "terminal.sessions.snapshot" {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let sessions = snapshot["session_ids"]
        .as_array()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?
        .iter()
        .filter_map(Value::as_str)
        .map(|id| json!({"id":id,"name":id,"machine":"server"}))
        .collect::<Vec<_>>();
    Ok(Json(json!({"sessions":sessions})))
}

async fn start_removal(
    api: &Api,
    token: &str,
    input: &Value,
    now: i64,
    audit_id: i64,
) -> Result<Value, StatusCode> {
    let request: RemovalInput =
        serde_json::from_value(input.clone()).map_err(|_| StatusCode::BAD_REQUEST)?;
    api.removal
        .start_api_audited(
            token,
            request.host_id,
            request.uninstall,
            now,
            Some(audit_id),
        )
        .await
        .map_err(|_| StatusCode::FORBIDDEN)
}

async fn removal_status(
    State(api): State<Api>,
    headers: HeaderMap,
    Json(input): Json<RemovalStatusInput>,
) -> Response {
    let Some(token) = bearer_only(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let action_id = "remote.host.remove";
    let Some(action) = shared_action(&api.sessions, action_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match api.guard.authorize_token(token, &action).await {
        Ok(_) => {}
        Err(status) => return status.into_response(),
    }
    let Ok(now) = crate::runtime::unix_seconds() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match api.removal.api_status(token, &input.request_id, now).await {
        Ok(value) => Json(value).into_response(),
        Err(_) => StatusCode::FORBIDDEN.into_response(),
    }
}

/// Tests the authorization table, bearer parser and per-key admission independently of storage.
#[cfg(test)]
mod tests {
    use super::{KEY_CALLS_PER_WINDOW, RateLimit, bearer_only, bearer_token};
    use axum::http::{HeaderMap, HeaderValue, header};

    #[test]
    fn shared_descriptors_carry_api_scope_and_fresh_tap_metadata() {
        let actions = [
            (
                infraternal_plugin_remote::inventory::LIST,
                Some("hosts:read"),
                false,
            ),
            (infraternal_plugin_remote::REMOVE, Some("hosts:write"), true),
            (
                infraternal_plugin_ssh::manifest::START,
                Some("hosts:write"),
                false,
            ),
            (infraternal_plugin_remote::BOOTSTRAP_CA, None, true),
        ];
        for (action, scope, fresh_passkey) in actions {
            let value = serde_json::to_value(action).expect("serialize shared action metadata");
            assert_eq!(
                value["api_scope"],
                scope.map_or(serde_json::Value::Null, Into::into)
            );
            assert_eq!(value["fresh_passkey"], fresh_passkey);
        }
        assert_eq!(
            infraternal_plugin_api::CORE_API_ACTIONS
                .iter()
                .map(|action| action.api_scope)
                .collect::<Vec<_>>(),
            [Some("status:read"), Some("sessions:read")]
        );
    }

    /// J137 P2-2, D319: walks every compiled action definition (core, server plugins and the
    /// infraternal agent's descriptors). A destructive action reaches an API key only behind
    /// its own fresh passkey. New descriptors (canvas, MCP-visible actions) are covered
    /// without editing this test.
    #[tokio::test]
    async fn every_compiled_destructive_action_needs_a_fresh_passkey_for_keys() {
        use infraternal_plugin_api::{ActionDef, Effect};
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let runtime = crate::plugins::compiled(&pool).await.unwrap();
        let actions: Vec<ActionDef> = infraternal_plugin_api::CORE_API_ACTIONS
            .iter()
            .chain(runtime.actions())
            .chain(
                infraternal_agent::plugins::descriptors()
                    .iter()
                    .flat_map(|descriptor| descriptor.actions),
            )
            .copied()
            .collect();
        assert!(
            actions
                .iter()
                .any(|action| action.effect == Effect::Destructive),
            "the walk must see destructive actions"
        );
        assert!(actions.iter().any(|action| action.id == "remote.host.list"));
        assert!(
            actions
                .iter()
                .any(|action| action.id == "remote.host.remove")
        );
        for action in &actions {
            if action.effect == Effect::Destructive {
                assert!(
                    action.fresh_passkey || action.api_scope.is_none(),
                    "{} is destructive and key-callable without a fresh passkey",
                    action.id
                );
            }
            assert_eq!(
                action.key_callable(),
                action.api_scope.is_some()
                    && (action.effect != Effect::Destructive || action.fresh_passkey),
                "{}",
                action.id
            );
        }
    }

    #[test]
    fn bearer_tokens_are_read_only_from_one_authorization_header() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer fixture"),
        );
        assert_eq!(bearer_token(&headers), Some("fixture"));
        assert_eq!(bearer_only(&headers), Some("fixture"));
        headers.insert(header::COOKIE, HeaderValue::from_static("session=fixture"));
        assert_eq!(bearer_only(&headers), None);
        headers.remove(header::COOKIE);
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert_eq!(bearer_token(&headers), None);
        headers.remove(header::AUTHORIZATION);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic fixture"),
        );
        assert_eq!(bearer_token(&headers), None);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer key with space"),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    /// J137 P3-5: the audit keeps a target only as a parsed host UUID, never caller text.
    #[test]
    fn audit_targets_are_parsed_host_ids_only() {
        use serde_json::json;
        let host = uuid::Uuid::new_v4();
        assert_eq!(
            super::audit_target(&json!({"host_id": host.to_string().to_uppercase()})),
            Some(host.to_string())
        );
        for input in [
            json!({"host_id": "not-a-uuid"}),
            json!({"host_id": "\u{1b}[2J"}),
            json!({"host_id": 7}),
            json!({}),
        ] {
            assert_eq!(super::audit_target(&input), None, "{input}");
        }
    }

    #[test]
    fn key_action_rate_limit_is_bounded_and_expires_after_one_minute() {
        let mut limit = RateLimit::default();
        for _ in 0..30 {
            assert!(limit.admit(100, KEY_CALLS_PER_WINDOW));
        }
        assert!(!limit.admit(100, KEY_CALLS_PER_WINDOW));
        assert!(!limit.admit(99, KEY_CALLS_PER_WINDOW));
        assert!(limit.first_denial());
        assert!(!limit.first_denial());
        assert!(limit.admit(160, KEY_CALLS_PER_WINDOW));
        assert!(
            limit.first_denial(),
            "a new window may audit one denial again"
        );
    }
}
