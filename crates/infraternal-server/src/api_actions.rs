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

/// Fixed per-key window. A backward clock jump cannot give a key extra attempts.
#[derive(Debug, Default)]
struct RateLimit {
    start: i64,
    used: u16,
}

impl RateLimit {
    fn admit(&mut self, now: i64) -> bool {
        const WINDOW_SECONDS: i64 = 60;
        const MAX_CALLS: u16 = 30;
        if self.used == 0 {
            self.start = now;
        } else if now >= self.start.saturating_add(WINDOW_SECONDS) {
            self.start = now;
            self.used = 0;
        } else if now < self.start {
            return false;
        }
        if self.used >= MAX_CALLS {
            return false;
        }
        self.used += 1;
        true
    }

    fn stale(&self, now: i64) -> bool {
        self.used == 0 || now >= self.start.saturating_add(60)
    }
}

/// Safe identity for audit rows. The bearer value is never retained in the request state.
#[derive(Clone)]
pub(crate) struct AuthorizedKey {
    pub(crate) key_id: String,
    pub(crate) person_id: String,
    pub(crate) device: String,
}

/// Shared by HTTP actions and the existing bootstrap WebSocket action.
#[derive(Clone)]
pub(crate) struct ActionGuard {
    auth: Auth,
    pool: SqlitePool,
    limits: Arc<Mutex<HashMap<String, RateLimit>>>,
}

impl ActionGuard {
    pub(crate) fn new(auth: Auth, pool: SqlitePool) -> Self {
        Self {
            auth,
            pool,
            limits: Arc::default(),
        }
    }

    /// Check the API key's current liveness and the scope required by one known action.
    pub(crate) async fn authorize_token(
        &self,
        token: &str,
        action: &ActionDef,
    ) -> Result<AuthorizedKey, StatusCode> {
        let action_id = action.id;
        let scope = action.api_scope.ok_or(StatusCode::NOT_FOUND)?;
        let key_id = crate::auth::hash(token);
        let now = crate::runtime::unix_seconds().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let Ok((person_id, device)) = self.auth.api_authorize_context(token, scope).await else {
            self.audit_denied(&key_id, action_id, now).await;
            return Err(StatusCode::FORBIDDEN);
        };
        if !self.admit(&key_id, now).await {
            self.insert_audit(&key_id, &person_id, action_id, None, "denied", now)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        Ok(AuthorizedKey {
            key_id,
            person_id,
            device,
        })
    }

    /// Recheck the same key id, person and action scope without retaining the bearer value.
    pub(crate) async fn identity_is_live(&self, identity: &AuthorizedKey, scope: &str) -> bool {
        self.auth
            .api_authorize_key_hash(&identity.key_id, scope)
            .await
            .is_ok_and(|person_id| person_id == identity.person_id)
    }

    /// Revalidate an already authenticated streaming caller against this message's own action
    /// scope, then charge the same per-key limit as a one-shot API request.
    pub(crate) async fn authorize_identity(
        &self,
        identity: &AuthorizedKey,
        action: &ActionDef,
    ) -> Result<i64, StatusCode> {
        let scope = action.api_scope.ok_or(StatusCode::NOT_FOUND)?;
        let now = crate::runtime::unix_seconds().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if !self.identity_is_live(identity, scope).await {
            self.audit_denied(&identity.key_id, action.id, now).await;
            return Err(StatusCode::FORBIDDEN);
        }
        if !self.admit(&identity.key_id, now).await {
            self.insert_audit(
                &identity.key_id,
                &identity.person_id,
                action.id,
                None,
                "denied",
                now,
            )
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            return Err(StatusCode::TOO_MANY_REQUESTS);
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
        if limits.len() >= 4096 {
            limits.retain(|_, limit| !limit.stale(now));
        }
        if limits.len() >= 4096 && !limits.contains_key(key_id) {
            return false;
        }
        limits.entry(key_id.to_owned()).or_default().admit(now)
    }

    async fn audit_denied(&self, key_id: &str, action_id: &str, now: i64) {
        // Scope denials and revoked/expired known keys still retain their owner attribution.
        // An unknown random bearer has no person to attribute and creates no audit row.
        let person_id: Option<String> =
            sqlx::query_scalar("SELECT user_id FROM api_keys WHERE token_hash=?")
                .bind(key_id)
                .fetch_optional(&self.pool)
                .await
                .ok()
                .flatten();
        if let Some(person_id) = person_id {
            let _ = self
                .insert_audit(key_id, &person_id, action_id, None, "denied", now)
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
        sqlx::query_scalar("INSERT INTO api_action_audit(key_id,person_id,action_id,target_id,state,occurred_at) VALUES(?,?,?,?,?,?) RETURNING id")
            .bind(key_id)
            .bind(person_id)
            .bind(action_id)
            .bind(target_id)
            .bind(state)
            .bind(now)
            .fetch_one(&self.pool)
            .await
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
    // The credential is checked before the catalogue so an anonymous caller cannot probe ids.
    let Some(token) = bearer_only(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(action) = shared_action(&api.sessions, &action_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !action.key_callable() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let identity = match api.guard.authorize_token(token, &action).await {
        Ok(identity) => identity,
        Err(status) => return status.into_response(),
    };
    let target_id = input
        .get("host_id")
        .and_then(Value::as_str)
        .filter(|value| value.len() <= 36);
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
    use super::{RateLimit, bearer_only, bearer_token};
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

    #[test]
    fn key_action_rate_limit_is_bounded_and_expires_after_one_minute() {
        let mut limit = RateLimit::default();
        for _ in 0..30 {
            assert!(limit.admit(100));
        }
        assert!(!limit.admit(100));
        assert!(!limit.admit(99));
        assert!(limit.admit(160));
    }
}
