//! Authenticates API-key action calls and applies the explicit scope boundary [16][202][303].

use crate::{auth::Auth, remote_removal::Removal, websocket::WebSocketState};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::Engine as _;
use bytes::Bytes;
use infraternal_plugin_api::{ActionDef, DryRun, Effect, Operation, SocketHost};
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
/// days.
///
/// Invariant (J154 P2-1): a row for a changing action or a denial is never evicted before
/// then, whatever any key does afterwards. Reads (`Effect::Read`) are therefore not one row
/// per call: they are counted in `api_read_audit`, one row per key, action and minute, and
/// only that table has a row cap. Changing rows stay bounded by the per-key rate limit
/// (at most 30 a minute per key) times the 90 days; denials by one a minute per key.
pub(crate) const AUDIT_RETENTION_SECONDS: i64 = 90 * 86_400;
const READ_AUDIT_MAX_ROWS: i64 = 100_000;
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
    sqlx::query("DELETE FROM api_read_audit WHERE minute<?")
        .bind(cutoff)
        .execute(&mut *tx)
        .await?;
    // Only read summaries are capped; the oldest minutes go first.
    sqlx::query("DELETE FROM api_read_audit WHERE minute<=(SELECT minute FROM api_read_audit ORDER BY minute DESC LIMIT 1 OFFSET ?)")
        .bind(READ_AUDIT_MAX_ROWS)
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

/// How long a dry run's review token lets the real call follow it.
const REVIEW_TOKEN_SECONDS: i64 = 120;
/// Backstop for open reviews. Each key makes at most 30 calls a minute, so one key holds
/// at most 60; a full table refuses new dry runs instead of evicting open reviews.
const MAX_OPEN_REVIEWS: usize = 4096;

/// D28, J154 P2-2: a destructive key action (`DryRun::Required`) runs only after its own dry
/// run. The dry run returns a random review token. The real call presents it, and it is
/// spent on that first presentation whatever the outcome.
///
/// Invariant: a token authorizes one real call by the same key, for the same action, with
/// exactly the same input apart from `dry_run` and `review_token`, within
/// `REVIEW_TOKEN_SECONDS`. Only the token's hash is held, in memory: a restart drops every
/// open review, which only means running the dry run again.
struct Review {
    key_id: String,
    action_id: &'static str,
    binding: String,
    expires: i64,
}

#[derive(Default)]
struct Reviews {
    open: HashMap<String, Review>,
}

/// Why a real call was refused; the code is the audit result and the JSON `error`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReviewRefusal {
    /// No token: the caller skipped the dry run.
    Required,
    /// Unknown, already spent, expired, or bound to another key, action or input.
    Invalid,
}

impl ReviewRefusal {
    fn code(&self) -> &'static str {
        match self {
            Self::Required => "review_required",
            Self::Invalid => "review_invalid",
        }
    }

    fn message(&self) -> &'static str {
        match self {
            Self::Required => {
                "Run this action with dry_run true first, then send its review_token with dry_run false."
            }
            Self::Invalid => {
                "The review_token is expired, already used, or for another key, action or input. Run the dry run again."
            }
        }
    }
}

impl Reviews {
    fn issue(
        &mut self,
        key_id: &str,
        action_id: &'static str,
        binding: String,
        now: i64,
    ) -> Option<String> {
        self.open.retain(|_, review| review.expires > now);
        if self.open.len() >= MAX_OPEN_REVIEWS {
            return None;
        }
        let token =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        self.open.insert(
            crate::auth::hash(&token),
            Review {
                key_id: key_id.to_owned(),
                action_id,
                binding,
                expires: now.saturating_add(REVIEW_TOKEN_SECONDS),
            },
        );
        Some(token)
    }

    /// Spend a token. It is removed on any presentation, so a wrong guess about what it was
    /// bound to cannot be retried with the same token.
    fn spend(
        &mut self,
        token: &str,
        key_id: &str,
        action_id: &str,
        binding: &str,
        now: i64,
    ) -> Result<(), ReviewRefusal> {
        let review = self
            .open
            .remove(&crate::auth::hash(token))
            .ok_or(ReviewRefusal::Invalid)?;
        if review.expires > now
            && review.key_id == key_id
            && review.action_id == action_id
            && review.binding == binding
        {
            Ok(())
        } else {
            Err(ReviewRefusal::Invalid)
        }
    }
}

/// What a `DryRun::Required` call asks for, once its review fields are taken out of the input.
enum ReviewStep {
    /// A dry run: on success the response gets a token bound to `binding`.
    DryRun { binding: String },
    /// A real call whose token was valid and is now spent.
    Reviewed,
}

/// Split a destructive call's input into its parameters and its review fields.
///
/// `binding` is the input without `dry_run` and `review_token`, serialized with sorted keys
/// (`serde_json`'s default map), so the same parameters always give the same text. For host
/// removal that is the host id; the uninstall choice is fixed by D334, so it cannot differ
/// between the review and the removal.
fn review_fields(input: &mut Value) -> Result<(bool, Option<String>, String), StatusCode> {
    let fields = input.as_object_mut().ok_or(StatusCode::BAD_REQUEST)?;
    let token = match fields.remove("review_token") {
        None => None,
        Some(Value::String(token)) if !token.is_empty() && token.len() <= 128 => Some(token),
        Some(_) => return Err(StatusCode::BAD_REQUEST),
    };
    let dry_run = fields
        .get("dry_run")
        .and_then(Value::as_bool)
        .ok_or(StatusCode::BAD_REQUEST)?;
    let mut parameters = fields.clone();
    parameters.remove("dry_run");
    let binding = serde_json::to_string(&parameters).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok((dry_run, token, binding))
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
    reviews: Arc<Mutex<Reviews>>,
    last_prune: Arc<std::sync::atomic::AtomicI64>,
}

impl ActionGuard {
    pub(crate) fn new(auth: Auth, pool: SqlitePool) -> Self {
        Self {
            auth,
            pool,
            limits: Arc::default(),
            reviews: Arc::default(),
            last_prune: Arc::new(std::sync::atomic::AtomicI64::new(i64::MIN)),
        }
    }

    /// Classify a `DryRun::Required` call and, for a real call, spend its review token.
    async fn review_step(
        &self,
        identity: &AuthorizedKey,
        action: &ActionDef,
        input: &mut Value,
        now: i64,
    ) -> Result<Result<ReviewStep, ReviewRefusal>, StatusCode> {
        let (dry_run, token, binding) = review_fields(input)?;
        if dry_run {
            // A dry run never spends a token; carrying one is a confused caller.
            return if token.is_some() {
                Err(StatusCode::BAD_REQUEST)
            } else {
                Ok(Ok(ReviewStep::DryRun { binding }))
            };
        }
        let Some(token) = token else {
            return Ok(Err(ReviewRefusal::Required));
        };
        Ok(self
            .reviews
            .lock()
            .await
            .spend(&token, &identity.key_id, action.id, &binding, now)
            .map(|()| ReviewStep::Reviewed))
    }

    /// Issue the review token for a dry run that succeeded.
    async fn issue_review(
        &self,
        identity: &AuthorizedKey,
        action: &ActionDef,
        binding: String,
        now: i64,
    ) -> Option<String> {
        self.reviews
            .lock()
            .await
            .issue(&identity.key_id, action.id, binding, now)
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

    /// Count one finished read in its key's summary row for this minute (J154 P2-1). Reads
    /// change nothing, so a failed count withholds the answer instead of blocking the call
    /// up front: the caller turns an error here into 503.
    pub(crate) async fn record_read(
        &self,
        identity: &AuthorizedKey,
        action_id: &str,
        ok: bool,
        now: i64,
    ) -> Result<(), StatusCode> {
        let minute = now - now.rem_euclid(60);
        sqlx::query("INSERT INTO api_read_audit(key_id,person_id,action_id,minute,calls,failed) VALUES(?,?,?,?,1,?) ON CONFLICT(key_id,action_id,minute) DO UPDATE SET calls=calls+1,failed=failed+excluded.failed")
            .bind(&identity.key_id)
            .bind(&identity.person_id)
            .bind(action_id)
            .bind(minute)
            .bind(i64::from(!ok))
            .execute(&self.pool)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        self.prune_if_due(now).await;
        Ok(())
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
    /// D28 / `DryRun::Required`: every caller states whether this is the review or the removal.
    /// The route has already taken out and checked `review_token` for a removal.
    dry_run: bool,
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
        .layer(axum::extract::DefaultBodyLimit::max(32 * 1024))
        .with_state(api)
}

/// Admit a bearer-only action, enforce its review contract, and record the audited result.
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
    let Ok(now) = crate::runtime::unix_seconds() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if action.effect == Effect::Read {
        // Reads are counted per key and minute, not written one row per call (J154 P2-1).
        let result = run_action(&api, action, identity.clone(), input, now, 0).await;
        let ok = matches!(result, Ok((_, true)));
        if let Err(status) = api.guard.record_read(&identity, action.id, ok, now).await {
            return status.into_response();
        }
        return match result {
            Ok((value, true)) => value.into_response(),
            Ok((value, false)) => (StatusCode::BAD_REQUEST, value).into_response(),
            Err(status) => status.into_response(),
        };
    }
    let target_id = audit_target(&input);
    let audit_id = match api
        .guard
        .begin_audit(&identity, &action_id, target_id.as_deref(), now)
        .await
    {
        Ok(audit_id) => audit_id,
        Err(status) => return status.into_response(),
    };
    let mut input = input;
    let review = match review_gate(&api, &identity, &action, &mut input, audit_id, now).await {
        Ok(review) => review,
        Err(response) => return *response,
    };
    let result = run_action(&api, action, identity.clone(), input, now, audit_id).await;
    match result {
        // A completed host change finished its audit row in its own transaction.
        Ok((value, true))
            if matches!(
                action_id.as_str(),
                "remote.host.remove" | "remote.host.forget"
            ) && matches!(review, Some(ReviewStep::Reviewed)) =>
        {
            value.into_response()
        }
        Ok((mut value, true)) => {
            let dry_run = matches!(review, Some(ReviewStep::DryRun { .. }));
            if let Some(ReviewStep::DryRun { binding }) = review {
                let token = api
                    .guard
                    .issue_review(&identity, &action, binding, now)
                    .await;
                if attach_review(&mut value.0, token).is_none() {
                    let _ = api.guard.finish_audit(audit_id, "failed", None, now).await;
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
            }
            let result = dry_run.then_some("dry_run");
            if api
                .guard
                .finish_audit(audit_id, "complete", result, now)
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

/// D28: a destructive key action runs only with the token of its own dry run. Returns the
/// call's review step, or the finished refusal; refusals complete the open audit row.
async fn review_gate(
    api: &Api,
    identity: &AuthorizedKey,
    action: &ActionDef,
    input: &mut Value,
    audit_id: i64,
    now: i64,
) -> Result<Option<ReviewStep>, Box<Response>> {
    if action.dry_run != DryRun::Required {
        return Ok(None);
    }
    match api.guard.review_step(identity, action, input, now).await {
        Ok(Ok(step)) => Ok(Some(step)),
        Ok(Err(refusal)) => {
            let _ = api
                .guard
                .finish_audit(audit_id, "denied", Some(refusal.code()), now)
                .await;
            Err(Box::new(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": refusal.code(), "message": refusal.message()})),
                )
                    .into_response(),
            ))
        }
        Err(status) => {
            let _ = api.guard.finish_audit(audit_id, "failed", None, now).await;
            Err(Box::new(status.into_response()))
        }
    }
}

/// Add a dry run's review token to its result; `None` when either is missing.
fn attach_review(result: &mut Value, token: Option<String>) -> Option<()> {
    let fields = result.as_object_mut()?;
    fields.insert("review_token".to_owned(), token?.into());
    fields.insert("review_expires_in".to_owned(), REVIEW_TOKEN_SECONDS.into());
    Some(())
}

/// Run one authorized, key-callable action. `audit_id` is the changing action's open audit
/// row (a removal completes it in its own transaction); reads pass 0 and never use it.
async fn run_action(
    api: &Api,
    action: ActionDef,
    identity: AuthorizedKey,
    input: Value,
    now: i64,
    audit_id: i64,
) -> Result<(Json<Value>, bool), StatusCode> {
    match action.id {
        "server.status" if !action.fresh_passkey => {
            server_status(&api.pool).await.map(|value| (value, true))
        }
        "sessions.list" if !action.fresh_passkey => session_list(api, &identity.person_id)
            .await
            .map(|value| (value, true)),
        "remote.host.remove" if !action.fresh_passkey => {
            remove_host(api, &identity, &input, now, audit_id).await
        }
        "remote.host.forget" if !action.fresh_passkey => {
            forget_host(api, &identity, &input, now, audit_id).await
        }
        // ssh.start uses the existing bounded bootstrap WebSocket adapter.
        "ssh.start" => Err(StatusCode::BAD_REQUEST),
        _ if action.fresh_passkey => Err(StatusCode::NOT_FOUND),
        _ => dispatch_plugin_action(api, action, identity, input)
            .await
            .map(|result| (Json(result.value), result.ok)),
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

/// D333: a `hosts:write` key removes a host with no further tap, and `dry_run: true` first
/// shows what would be removed. D28: the route lets `dry_run: false` through only with that
/// dry run's review token. The dry run's row is completed by the caller; a removal's row is
/// completed in the removal's own transaction.
async fn remove_host(
    api: &Api,
    identity: &AuthorizedKey,
    input: &Value,
    now: i64,
    audit_id: i64,
) -> Result<(Json<Value>, bool), StatusCode> {
    let request: RemovalInput =
        serde_json::from_value(input.clone()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if request.dry_run {
        return api
            .removal
            .review_with_key(&identity.person_id, request.host_id)
            .await
            .map(|value| (Json(value), true))
            // The key was authorized above; a refusal here means the owner has no such live
            // host. 403 would read as a dead key to every client.
            .map_err(|error| match error {
                crate::auth::Error::Denied => StatusCode::NOT_FOUND,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            });
    }
    api.removal
        .remove_with_key(
            &identity.key_id,
            &identity.person_id,
            request.host_id,
            audit_id,
            now,
        )
        .await
        .map(|value| (Json(value), true))
        .map_err(|_| StatusCode::FORBIDDEN)
}

/// Route Forget through its owner/state checks; the API guard has already enforced scope and review.
async fn forget_host(
    api: &Api,
    identity: &AuthorizedKey,
    input: &Value,
    now: i64,
    audit_id: i64,
) -> Result<(Json<Value>, bool), StatusCode> {
    let request: RemovalInput =
        serde_json::from_value(input.clone()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if request.dry_run {
        return api
            .removal
            .review_forget_with_key(&identity.person_id, request.host_id)
            .await
            .map(|value| (Json(value), true))
            .map_err(|error| match error {
                crate::auth::Error::Invalid | crate::auth::Error::Denied => StatusCode::NOT_FOUND,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            });
    }
    api.removal
        .forget_with_key(
            &identity.key_id,
            &identity.person_id,
            request.host_id,
            audit_id,
            now,
        )
        .await
        .map(|value| (Json(value), true))
        // A reviewed host can become ineligible before the writer locks it. That is a
        // target conflict, not an invalid key; authority refusals retain their own status.
        .map_err(|error| match error {
            crate::auth::Error::Invalid => StatusCode::CONFLICT,
            crate::auth::Error::Denied => StatusCode::FORBIDDEN,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        })
}

/// Tests the authorization table, bearer parser and per-key admission independently of storage.
#[cfg(test)]
mod tests {
    use super::{KEY_CALLS_PER_WINDOW, RateLimit, bearer_only, bearer_token};
    use axum::http::{HeaderMap, HeaderValue, header};

    /// The shared catalogue exposes Forget only with hosts:write and a required review.
    #[test]
    #[cfg(feature = "remote")]
    fn forget_retired_host_action_requires_write_scope_and_review() {
        let forget = infraternal_plugin_remote::DESCRIPTOR
            .actions
            .iter()
            .find(|action| action.id == "remote.host.forget")
            .expect("forget is compiled");
        assert_eq!(forget.api_scope, Some("hosts:write"));
        assert!(forget.key_callable());
        assert_eq!(forget.dry_run, infraternal_plugin_api::DryRun::Required);
    }

    #[test]
    fn shared_descriptors_carry_api_scope_and_fresh_tap_metadata() {
        let actions = [
            (
                infraternal_plugin_remote::inventory::LIST,
                Some("hosts:read"),
                false,
            ),
            (
                infraternal_plugin_remote::REMOVE,
                Some("hosts:write"),
                false,
            ),
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

    /// J137 P2-2, reframed by D333: walks every compiled action definition (core, server
    /// plugins and the infraternal agent's descriptors), so new canvas or MCP-visible actions
    /// are covered without editing this test.
    /// - Actions in the per-action-tap categories carry `fresh_passkey` and no key can start
    ///   them. Among compiled actions today that is CA setup. Key approval, role changes and
    ///   recovery or passkey changes are auth routes, each with its own tap bound to that one
    ///   action (D336): `action_tap::require_tap_tx`, the approval ceremony in `devices.rs`, or
    ///   the CA ceremonies.
    /// - A destructive action that declares an API scope also declares a required dry run.
    #[tokio::test]
    async fn every_compiled_action_follows_the_d333_tap_model() {
        use infraternal_plugin_api::{ActionDef, DryRun, Effect};
        const PER_ACTION_TAP: &[&str] = &["remote.ca.bootstrap"];
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
        for id in PER_ACTION_TAP {
            let action = actions
                .iter()
                .find(|action| action.id == *id)
                .unwrap_or_else(|| panic!("{id} is compiled"));
            assert!(action.fresh_passkey, "{id} needs a tap for each run");
        }
        let removal = actions
            .iter()
            .find(|action| action.id == "remote.host.remove")
            .expect("removal is compiled");
        assert!(
            removal.key_callable(),
            "inside its scope, removal needs no further tap"
        );
        for action in &actions {
            if action.fresh_passkey {
                assert!(
                    !action.key_callable(),
                    "{} would let a key skip its tap",
                    action.id
                );
            }
            if action.effect == Effect::Destructive && action.api_scope.is_some() {
                assert_eq!(
                    action.dry_run,
                    DryRun::Required,
                    "{} is destructive and key-scoped without a required dry run",
                    action.id
                );
            }
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

    /// D28, J154 P2-2: a review token is spent once, by the same key, for the same action and
    /// input, before it expires; any presentation spends it.
    #[test]
    fn review_tokens_are_single_use_bound_and_short_lived() {
        use super::{REVIEW_TOKEN_SECONDS, ReviewRefusal, Reviews};
        let mut reviews = Reviews::default();
        let action = "remote.host.remove";
        let binding = r#"{"host_id":"a"}"#;
        let token = reviews
            .issue("key", action, binding.to_owned(), 100)
            .unwrap();
        assert_eq!(reviews.spend(&token, "key", action, binding, 101), Ok(()));
        assert_eq!(
            reviews.spend(&token, "key", action, binding, 101),
            Err(ReviewRefusal::Invalid),
            "a replay is refused"
        );
        for (key, action_id, bound, now) in [
            ("other-key", action, binding, 101),
            ("key", "ssh.start", binding, 101),
            ("key", action, r#"{"host_id":"b"}"#, 101),
            ("key", action, binding, 100 + REVIEW_TOKEN_SECONDS),
        ] {
            let token = reviews
                .issue("key", action, binding.to_owned(), 100)
                .unwrap();
            assert_eq!(
                reviews.spend(&token, key, action_id, bound, now),
                Err(ReviewRefusal::Invalid),
                "{key} {action_id} {bound} {now}"
            );
            assert_eq!(
                reviews.spend(&token, "key", action, binding, 101),
                Err(ReviewRefusal::Invalid),
                "a refused presentation spends the token"
            );
        }
        assert!(reviews.open.is_empty());
    }

    #[test]
    fn review_binding_ignores_only_the_review_fields_and_key_order() {
        use serde_json::json;
        let mut first = json!({"host_id":"a","dry_run":true,"x":1});
        let mut second = json!({"x":1,"review_token":"t","dry_run":false,"host_id":"a"});
        let (dry, token, one) = super::review_fields(&mut first).unwrap();
        assert!(dry && token.is_none());
        let (dry, token, two) = super::review_fields(&mut second).unwrap();
        assert!(!dry && token.as_deref() == Some("t"));
        assert_eq!(one, two);
        assert!(
            second.get("review_token").is_none(),
            "the handler never sees the token"
        );
        assert!(super::review_fields(&mut json!({"host_id":"a"})).is_err());
        assert!(super::review_fields(&mut json!({"dry_run":false,"review_token":7})).is_err());
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
