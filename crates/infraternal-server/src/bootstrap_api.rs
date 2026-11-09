//! Additive owner-authenticated bootstrap WebSocket; #78 runtime injects the trusted backend [63][138][139].

#[cfg(feature = "remote")]
use crate::api_actions::{ActionGuard, AuthorizedKey};
use crate::{
    auth::Auth,
    ssh_key::{SshKeySource, UnavailableSshKey},
};
use axum::{
    Json, Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use infraternal_plugin_ssh::{
    auth_once::{OneUseAuth, TargetAuth},
    bootstrap::{Batch, Bootstrap},
    model::Target,
    transport::{ConfirmationAuthority, Operation, Secret},
};
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

#[cfg(feature = "remote")]
#[path = "bootstrap_setup_api.rs"]
mod setup_api;

/// The existing authenticator is reused; runtime must provide an authorized #78 backend.
struct Api {
    auth: Auth,
    runner: Bootstrap,
    sockets: Arc<Semaphore>,
    #[cfg(feature = "remote")]
    action_guard: ActionGuard,
    #[cfg(feature = "remote")]
    setup_sockets: Arc<Semaphore>,
    ssh_key: Arc<dyn SshKeySource>,
}

#[cfg(feature = "remote")]
#[derive(Clone)]
struct ApiKeyCaller {
    identity: AuthorizedKey,
}

/// Mount an additive router with a trusted runtime backend; unavailable enrollment fails before mutation.
pub fn router(auth: &Auth, runner: Bootstrap) -> Router {
    router_with_ssh_key(auth, runner, Arc::new(UnavailableSshKey))
}

/// Share the runtime's dedicated identity source without exposing private material.
pub fn router_with_ssh_key(
    auth: &Auth,
    runner: Bootstrap,
    ssh_key: Arc<dyn SshKeySource>,
) -> Router {
    #[cfg(feature = "remote")]
    {
        router_with_ssh_key_and_action_guard(
            auth.clone(),
            runner,
            ssh_key,
            ActionGuard::new(auth.clone(), auth.pool().clone()),
        )
    }
    #[cfg(not(feature = "remote"))]
    {
        build_router_state(auth.clone(), runner, ssh_key)
    }
}

/// Mount bootstrap beside API actions while sharing their per-key rate budget.
#[cfg(feature = "remote")]
pub(crate) fn router_with_ssh_key_and_action_guard(
    auth: Auth,
    runner: Bootstrap,
    ssh_key: Arc<dyn SshKeySource>,
    action_guard: ActionGuard,
) -> Router {
    build_router_state(auth, runner, ssh_key, action_guard)
}

#[cfg(feature = "remote")]
fn build_router_state(
    auth: Auth,
    runner: Bootstrap,
    ssh_key: Arc<dyn SshKeySource>,
    action_guard: ActionGuard,
) -> Router {
    let router = Router::new().route("/v1/bootstrap/ws", get(upgrade)).route(
        "/v1/bootstrap/ssh-key",
        get(public_ssh_key).post(public_ssh_key),
    );
    #[cfg(feature = "remote")]
    let router = router.route("/v1/bootstrap/setup/ws", get(setup_api::upgrade));
    router.with_state(Arc::new(Api {
        auth,
        runner,
        ssh_key,
        action_guard,
        sockets: Arc::new(Semaphore::new(16)),
        #[cfg(feature = "remote")]
        setup_sockets: Arc::new(Semaphore::new(
            infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS,
        )),
    }))
}

#[cfg(not(feature = "remote"))]
fn build_router_state(auth: Auth, runner: Bootstrap, ssh_key: Arc<dyn SshKeySource>) -> Router {
    let router = Router::new().route("/v1/bootstrap/ws", get(upgrade)).route(
        "/v1/bootstrap/ssh-key",
        get(public_ssh_key).post(public_ssh_key),
    );
    router.with_state(Arc::new(Api {
        auth,
        runner,
        ssh_key,
        sockets: Arc::new(Semaphore::new(16)),
    }))
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Start {
        targets: Vec<Target>,
        #[serde(default)]
        credential: Option<String>,
        #[serde(default)]
        auth_once: Vec<TargetAuth>,
    },
    Retry {
        target: String,
        #[serde(default)]
        auth_once: Option<OneUseAuth>,
    },
    StartFresh {
        target: String,
        challenge: uuid::Uuid,
    },
    Replay {
        after: u64,
    },
    ConfirmHostKey {
        target: String,
        challenge: String,
        fingerprint: String,
    },
}

/// Capability plaintext belongs only to this confirmation future, never the public observation store.
struct LiveConfirmation {
    auth: Auth,
    owner: String,
    token: Secret,
}
impl ConfirmationAuthority for LiveConfirmation {
    fn authorize(&self) -> Operation<'_, ()> {
        Box::pin(async move {
            let token = std::str::from_utf8(self.token.expose()).map_err(|_| {
                infraternal_plugin_ssh::model::Failure::unsupported(
                    "The bootstrap session is unavailable.",
                )
            })?;
            let time = now().map_err(|()| {
                infraternal_plugin_ssh::model::Failure::install("The server clock is unavailable.")
            })?;
            if self
                .auth
                .bootstrap_owner(token, time)
                .await
                .is_ok_and(|owner| owner == self.owner)
            {
                Ok(())
            } else {
                Err(infraternal_plugin_ssh::model::Failure::unsupported(
                    "The bootstrap session is no longer authorized.",
                ))
            }
        })
    }
}

async fn upgrade(
    State(api): State<Arc<Api>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // A cookie with an API key claims two authorities in one request: refused in every build,
    // before any build-specific path can honour only one of them (#303, J234 P3-1).
    if headers.contains_key(header::AUTHORIZATION) && headers.contains_key(header::COOKIE) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    #[cfg(feature = "remote")]
    let (owner, token, api_key) = if headers.contains_key(header::AUTHORIZATION) {
        let Some(token) = crate::api_actions::bearer_token(&headers) else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        let action = &infraternal_plugin_ssh::manifest::START;
        let identity = match api.action_guard.authorize_token(token, action).await {
            Ok(identity) => identity,
            Err(status) => return status.into_response(),
        };
        // Only the owner adds hosts (invitation issuance refuses everyone else), so only the
        // owner's keys may hold one of the shared bootstrap sockets. A non-owner key with
        // `hosts:write` could otherwise park all of them and block the owner's add-host.
        // Rejected: a per-account share of the sockets, which still lets several non-owner
        // accounts together exhaust the pool for a call that can never succeed.
        let owner: Option<bool> = sqlx::query_scalar("SELECT owner=1 FROM users WHERE id=?")
            .bind(&identity.person_id)
            .fetch_optional(api.auth.pool())
            .await
            .unwrap_or(None);
        if owner != Some(true) {
            return StatusCode::FORBIDDEN.into_response();
        }
        (
            identity.person_id.clone(),
            Secret::new(Vec::new()),
            Some(ApiKeyCaller { identity }),
        )
    } else {
        match authenticate_headers(&api, &headers).await {
            Ok((owner, token)) => (owner, Secret::new(token.as_bytes().to_vec()), None),
            Err(status) => return status.into_response(),
        }
    };
    #[cfg(not(feature = "remote"))]
    let (owner, token) = match authenticate_headers(&api, &headers).await {
        Ok((owner, token)) => (owner, Secret::new(token.as_bytes().to_vec())),
        Err(status) => return status.into_response(),
    };
    let Ok(activity) = api.runner.activity() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(permit) = api.sockets.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    upgrade_admitted(
        ws.max_message_size(32 * 1024).max_frame_size(32 * 1024),
        api,
        owner,
        token,
        activity,
        permit,
        UpgradeContext {
            mode: SocketMode::Bootstrap,
            #[cfg(feature = "remote")]
            api_key,
        },
    )
}

/// Both socket kinds share one upgrade task type; limits and authority remain
/// with each caller. Sharing the cold upgrade avoids duplicating its task and
/// cancellation machinery for retained setup subscriptions (D243, D255).
#[derive(Clone, Copy)]
enum SocketMode {
    Bootstrap,
    #[cfg(feature = "remote")]
    Setup,
}

/// Per-upgrade mode and optional API-key caller travel together into the socket task.
struct UpgradeContext {
    mode: SocketMode,
    #[cfg(feature = "remote")]
    api_key: Option<ApiKeyCaller>,
}

#[inline(never)]
fn upgrade_admitted(
    ws: WebSocketUpgrade,
    api: Arc<Api>,
    owner: String,
    token: Secret,
    activity: infraternal_plugin_ssh::bootstrap::Activity,
    permit: tokio::sync::OwnedSemaphorePermit,
    context: UpgradeContext,
) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        // Retire stream and admission before publishing this lifetime inactive.
        let _activity = activity;
        let _permit = permit;
        let mode = context.mode;
        #[cfg(feature = "remote")]
        let api_key = context.api_key;
        let result = match mode {
            SocketMode::Bootstrap => {
                run(
                    &mut socket,
                    api.clone(),
                    owner,
                    token,
                    #[cfg(feature = "remote")]
                    api_key,
                )
                .await
            }
            #[cfg(feature = "remote")]
            SocketMode::Setup => setup_api::run(&mut socket, api, owner, token).await,
        };
        if matches!(result, Err(SocketFailure::AuthorityUnavailable)) {
            // The notification source is part of live authority. Once it is lost,
            // stop all socket work before sending the same unavailable outcome as
            // the multiplexed socket; a still-live database row cannot repair it.
            let _ = tokio::time::timeout(
                Duration::from_secs(5),
                socket.send(Message::Close(Some(CloseFrame {
                    code: 1013,
                    reason: crate::stream_close::AUTHORITY_UNAVAILABLE
                        .client_text
                        .into(),
                }))),
            )
            .await;
        }
    })
}

/// Both Settings and WebSocket admission require the exact pinned browser Origin
/// and current unlocked owner capability, including fresh revocation checks.
async fn authenticate_headers<'a>(
    api: &Api,
    headers: &'a HeaderMap,
) -> Result<(String, &'a str), StatusCode> {
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(api.auth.origin())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    // HTTP/2 may split unrelated cookies into separate fields. The shared reader
    // enforces capability uniqueness across the entire request.
    let Some(token) = crate::websocket::session_cookie(headers) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Ok(now) = now() else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(owner) = api.auth.bootstrap_owner(token, now).await else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    Ok((owner, token))
}

async fn public_ssh_key(State(api): State<Arc<Api>>, headers: HeaderMap) -> Response {
    let mut response = match api.runner.activity() {
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Ok(_activity) => {
            let mut enabled = api.runner.enabled_changes();
            let is_enabled = *enabled.borrow();
            let identity = if is_enabled {
                tokio::select! {
                    biased;
                    _ = enabled.changed() => Err(StatusCode::SERVICE_UNAVAILABLE),
                    result = authenticate_headers(&api, &headers) => result,
                }
            } else {
                Err(StatusCode::SERVICE_UNAVAILABLE)
            };
            match identity {
                Err(status) => status.into_response(),
                Ok(_) => match api.ssh_key.public_key() {
                    Ok(public) => Json(public).into_response(),
                    Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                },
            }
        }
    };
    // No proxy/browser cache may retain even public identity or authorization state.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn send(socket: &mut WebSocket, text: String) -> Result<(), ()> {
    tokio::time::timeout(
        Duration::from_secs(5),
        socket.send(Message::Text(text.into())),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

async fn authorized(api: &Api, token: &str, owner: &str) -> bool {
    let Ok(now) = now() else {
        return false;
    };
    api.auth
        .bootstrap_owner(token, now)
        .await
        .is_ok_and(|id| id == owner)
}

#[cfg(feature = "remote")]
async fn authorized_api_key(api: &Api, identity: &AuthorizedKey, owner: &str) -> bool {
    identity.person_id == owner
        && api
            .action_guard
            .identity_is_live(identity, "hosts:write")
            .await
}

/// Keep the shared socket writer available in default builds without key support.
async fn socket_authorized(
    api: &Api,
    token: &str,
    owner: &str,
    #[cfg(feature = "remote")] identity: Option<&AuthorizedKey>,
) -> bool {
    #[cfg(feature = "remote")]
    if let Some(identity) = identity {
        return authorized_api_key(api, identity, owner).await;
    }
    authorized(api, token, owner).await
}

/// Preserve the browser event shape and add raw setup detail only to bearer-key streams.
fn encode_bootstrap_event(
    event: &infraternal_plugin_ssh::model::Event,
    expose_setup_stderr: bool,
) -> Option<String> {
    if !expose_setup_stderr {
        return serde_json::to_string(event).ok();
    }
    let Some(stderr) = event
        .failure
        .as_ref()
        .and_then(|failure| failure.captured_setup_stderr())
    else {
        return serde_json::to_string(event).ok();
    };
    let mut value = serde_json::to_value(event).ok()?;
    value["failure"]["captured_stderr"] =
        serde_json::Value::String(String::from_utf8_lossy(stderr).into_owned());
    serde_json::to_string(&value).ok()
}

/// Preserve source loss across pending writes so the upgrade owner can close with 1013.
enum SocketFailure {
    Closed,
    AuthorityUnavailable,
}

impl From<()> for SocketFailure {
    fn from((): ()) -> Self {
        Self::Closed
    }
}

async fn send_live(
    socket: &mut WebSocket,
    api: &Api,
    owner: &str,
    token: &str,
    revocation: &mut crate::auth::AccountSubscription,
    encoded: Option<String>,
    #[cfg(feature = "remote")] api_key: Option<&AuthorizedKey>,
) -> Result<(), SocketFailure> {
    // Keep the same write future after another session's revocation. Dropping and
    // restarting a partially buffered frame would duplicate sequence delivery.
    // Serialize before this shared async boundary: event and error types must
    // not instantiate the full WebSocket writer and revocation loop twice.
    let mut enabled = api.runner.enabled_changes();
    if !*enabled.borrow() {
        return Err(SocketFailure::Closed);
    }
    let writing = send(socket, encoded.ok_or(())?);
    tokio::pin!(writing);
    loop {
        tokio::select! {
            biased;
            _ = enabled.changed() => return Err(SocketFailure::Closed),
            change = revocation.changed() => {
                change.map_err(|_| SocketFailure::AuthorityUnavailable)?;
                let authorized = socket_authorized(
                    api,
                    token,
                    owner,
                    #[cfg(feature = "remote")]
                    api_key,
                )
                .await;
                if !authorized { return Err(SocketFailure::Closed); }
            }
            result = &mut writing => return result.map_err(SocketFailure::from),
        }
    }
}

async fn run(
    socket: &mut WebSocket,
    api: Arc<Api>,
    owner: String,
    token: Secret,
    #[cfg(feature = "remote")] api_key: Option<ApiKeyCaller>,
) -> Result<(), SocketFailure> {
    let Ok(token) = std::str::from_utf8(token.expose()) else {
        return Ok(());
    };
    let mut enabled = api.runner.enabled_changes();
    if !*enabled.borrow() {
        return Ok(());
    }
    let mut revocation = api.auth.revocation_events(&owner);
    // Admission preceded this subscription; recheck so an intervening logout cannot be missed.
    #[cfg(feature = "remote")]
    let key_identity = api_key.as_ref().map(|caller| &caller.identity);
    let is_authorized = socket_authorized(
        &api,
        token,
        &owner,
        #[cfg(feature = "remote")]
        key_identity,
    )
    .await;
    if !is_authorized {
        return Ok(());
    }
    let mut batch: Option<Batch> = None;
    let mut changed: Option<tokio::sync::watch::Receiver<u64>> = None;
    let mut after = 0;
    // A wholly idle socket has one session-expiry deadline, not a polling loop.
    let mut expiry = Box::pin(tokio::time::sleep(Duration::from_hours(30 * 24)));
    'connection: loop {
        tokio::select! {
            biased;
            _ = enabled.changed() => break,
            () = &mut expiry => break,
            change = revocation.changed() => {
                change.map_err(|_| SocketFailure::AuthorityUnavailable)?;
                let is_authorized = socket_authorized(
                    &api,
                    token,
                    &owner,
                    #[cfg(feature = "remote")]
                    key_identity,
                )
                .await;
                if !is_authorized { break; }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                #[cfg(feature = "remote")]
                let is_authorized = if key_identity.is_some() {
                    true
                } else {
                    authorized(&api, token, &owner).await
                };
                #[cfg(not(feature = "remote"))]
                let is_authorized = authorized(&api, token, &owner).await;
                if !is_authorized { break; }
                expiry.as_mut().reset(tokio::time::Instant::now() + Duration::from_hours(30 * 24));
                let decoded = serde_json::from_str::<Request>(&text);
                // Transient private fields are now owned zeroizing buffers; no raw
                // JSON is retained by batch state, helper tasks or replay history.
                drop(text);
                #[cfg(feature = "remote")]
                let mut api_key_audit = if let Some(identity) = key_identity {
                    let action = &infraternal_plugin_ssh::manifest::START;
                    // One row per add-host target, each naming the target only by a valid
                    // host identifier. The batch admits at most 100 targets, the 32 KiB
                    // message bounds the rest, and the per-key limit bounds messages.
                    let target_ids: Vec<Option<&str>> = match decoded.as_ref() {
                        Ok(Request::Start { targets, .. }) if !targets.is_empty() && targets.len() <= 100 => targets
                            .iter()
                            .map(|target| infraternal_plugin_ssh::model::identifier(&target.id).then_some(target.id.as_str()))
                            .collect(),
                        _ => vec![None],
                    };
                    let authorized_at = match api.action_guard.authorize_identity(identity, action).await {
                        Ok(at) => at,
                        Err(status) => {
                            let error = if status == StatusCode::TOO_MANY_REQUESTS {
                                "rate_limited"
                            } else if status == StatusCode::FORBIDDEN {
                                "unauthorized"
                            } else {
                                "action_unavailable"
                            };
                            send_live(
                                socket,
                                &api,
                                &owner,
                                token,
                                &mut revocation,
                                serde_json::to_string(&serde_json::json!({"error":error})).ok(),
                                key_identity,
                            )
                            .await?;
                            break 'connection;
                        }
                    };
                    let mut audit_ids = Vec::with_capacity(target_ids.len());
                    for target_id in target_ids {
                        let Ok(audit_id) = api
                            .action_guard
                            .begin_audit(identity, action.id, target_id, authorized_at)
                            .await
                        else {
                            for audit_id in audit_ids {
                                let _ = api.action_guard.finish_audit(audit_id, "failed", Some("audit_unavailable"), authorized_at).await;
                            }
                            let event = serde_json::to_string(&serde_json::json!({"error":"action_unavailable"})).ok();
                            send_live(socket, &api, &owner, token, &mut revocation, event, key_identity).await?;
                            break 'connection;
                        };
                        audit_ids.push(audit_id);
                    }
                    Some((audit_ids, authorized_at))
                } else {
                    None
                };
                let Ok(request) = decoded else {
                    #[cfg(feature = "remote")]
                    if let Some((audit_ids, audit_time)) = api_key_audit.take() {
                        for audit_id in audit_ids {
                            let _ = api.action_guard.finish_audit(
                                audit_id,
                                "denied",
                                Some("invalid_request"),
                                audit_time,
                            ).await;
                        }
                    }
                    send_live(socket, &api, &owner, token, &mut revocation, serde_json::to_string(&serde_json::json!({"error":"invalid bootstrap request"})).ok(), #[cfg(feature = "remote")] key_identity).await?;
                    continue;
                };
                let result = match request {
                    Request::Start { targets, credential, auth_once } if batch.is_none() => {
                        #[cfg(feature = "remote")]
                        if let Some(caller) = &api_key {
                            match api_key_audit.take() {
                                None => Err(infraternal_plugin_ssh::model::Failure::install("The host action could not be recorded.")),
                                Some((audit_ids, audit_time)) => {
                                        let outcome = if credential.is_some() || !auth_once.is_empty() {
                                            Err(infraternal_plugin_ssh::model::Failure::unsupported("API-key host setup does not accept credential material."))
                                        } else if !authorized_api_key(&api, &caller.identity, &owner).await {
                                            Err(infraternal_plugin_ssh::model::Failure::unsupported("The host action is no longer authorized."))
                                        } else {
                                            api.runner.start_api_key(
                                                owner.clone(),
                                                caller.identity.key_id.clone(),
                                                targets,
                                            )
                                        };
                                        let (state, result) = if outcome.is_ok() { ("complete", None) } else { ("failed", Some("handler_refused")) };
                                        let finished_at = now().unwrap_or(audit_time);
                                        for audit_id in audit_ids {
                                            let _ = api.action_guard.finish_audit(audit_id, state, result, finished_at).await;
                                        }
                                        match outcome {
                                            Ok(started) => { changed = Some(started.subscribe()); batch = Some(started); Ok(()) }
                                            Err(error) => Err(error),
                                        }
                                }
                            }
                        } else {
                            match api.runner.start_authenticated_with_auth(owner.clone(), Secret::new(token.as_bytes().to_vec()), targets, credential, auth_once) {
                                Ok(started) => { changed = Some(started.subscribe()); batch = Some(started); Ok(()) }
                                Err(error) => Err(error)
                            }
                        }
                        #[cfg(not(feature = "remote"))]
                        match api.runner.start_authenticated_with_auth(owner.clone(), Secret::new(token.as_bytes().to_vec()), targets, credential, auth_once) {
                            Ok(started) => { changed = Some(started.subscribe()); batch = Some(started); Ok(()) }
                            Err(error) => Err(error)
                        }
                    }
                    Request::Retry { target, auth_once } => {
                        #[cfg(feature = "remote")]
                        if api_key.is_some() { Err(infraternal_plugin_ssh::model::Failure::unsupported("This follow-up action needs its own scoped request.")) }
                        else { batch.as_ref().ok_or_else(|| infraternal_plugin_ssh::model::Failure::unsupported("Start a host batch first.")).and_then(|batch| api.runner.retry_with_auth(batch, &owner, &target, auth_once)) }
                        #[cfg(not(feature = "remote"))]
                        batch.as_ref().ok_or_else(|| infraternal_plugin_ssh::model::Failure::unsupported("Start a host batch first.")).and_then(|batch| api.runner.retry_with_auth(batch, &owner, &target, auth_once))
                    }
                    Request::StartFresh {target, challenge} => {
                        #[cfg(feature = "remote")]
                        if api_key.is_some() { Err(infraternal_plugin_ssh::model::Failure::unsupported("This follow-up action needs its own scoped request.")) }
                        else { batch.as_ref().ok_or_else(|| infraternal_plugin_ssh::model::Failure::unsupported("Start a host batch first.")).and_then(|batch| api.runner.start_fresh(batch, &owner, &target, challenge)) }
                        #[cfg(not(feature = "remote"))]
                        batch.as_ref().ok_or_else(|| infraternal_plugin_ssh::model::Failure::unsupported("Start a host batch first.")).and_then(|batch| api.runner.start_fresh(batch, &owner, &target, challenge))
                    }
                    Request::ConfirmHostKey {target,challenge,fingerprint} => {
                        #[cfg(feature = "remote")]
                        let api_key_request = api_key.is_some();
                        #[cfg(not(feature = "remote"))]
                        let api_key_request = false;
                        if api_key_request {
                            Err(infraternal_plugin_ssh::model::Failure::unsupported("Host-key confirmation needs a signed-in browser session."))
                        } else if let Some(batch)=&batch {
                            let proof=LiveConfirmation {auth:api.auth.clone(),owner:owner.clone(),token:Secret::new(token.as_bytes().to_vec())};
                            let confirmed = {
                                let confirmation = api.runner.confirm_host_key(batch,&owner,&target,&challenge,&fingerprint,&proof);
                                tokio::pin!(confirmation);
                                // Keep pending lookups inside the same live socket lifetime.
                                // Revocation, expiry and disconnect must drop the lookup before publication.
                                loop {
                                    tokio::select! {
                                        biased;
                                        _ = enabled.changed() => break 'connection,
                                        () = &mut expiry => break 'connection,
                                        change = revocation.changed() => {
                                            change.map_err(|_| SocketFailure::AuthorityUnavailable)?;
                                            if !authorized(&api,token,&owner).await { break 'connection; }
                                        }
                                        incoming = socket.recv() => {
                                            match incoming {
                                                Some(Ok(Message::Text(text))) if is_same_confirmation(&text,&target,&challenge,&fingerprint) => {
                                                    // A double-click resends the very same confirmation. The reply to
                                                    // the one in flight answers both (the screen matches it by target
                                                    // and fingerprint), so say nothing: a busy error here would read
                                                    // as a failure of a trust that is about to succeed.
                                                },
                                                Some(Ok(Message::Text(_))) => {
                                                    // Refuse concurrent requests without retaining private inputs
                                                    // or cancelling the batch that owns this confirmation.
                                                    let busy = serde_json::to_string(&serde_json::json!({"error":"host-key confirmation busy; retry after confirmation"})).ok();
                                                    send_live(socket,&api,&owner,token,&mut revocation,busy, #[cfg(feature = "remote")] key_identity).await?;
                                                },
                                                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Binary(_))) => {},
                                                Some(Ok(Message::Close(_)) | Err(_)) | None => break 'connection,
                                            }
                                        }
                                        result = &mut confirmation => break result,
                                    }
                                }
                            };
                            match confirmed {
                                Ok(())=>{
                                    let reply=serde_json::to_string(&serde_json::json!({"host_key_confirmed":{"target":target,"fingerprint":fingerprint}})).ok();
                                    send_live(socket,&api,&owner,token,&mut revocation,reply, #[cfg(feature = "remote")] key_identity).await?;
                                    Ok(())
                                }
                                Err(error)=>Err(error),
                            }
                        } else {Err(infraternal_plugin_ssh::model::Failure::unsupported("Start a host batch first."))}
                    }
                    Request::Replay { after: sequence } => {
                        #[cfg(feature = "remote")]
                        if api_key.is_some() { Err(infraternal_plugin_ssh::model::Failure::unsupported("This follow-up action needs its own scoped request.")) }
                        else { after = sequence; Ok(()) }
                        #[cfg(not(feature = "remote"))]
                        { after = sequence; Ok(()) }
                    }
                    Request::Start { .. } => Err(infraternal_plugin_ssh::model::Failure::unsupported("A host batch is already running.")),
                };
                #[cfg(feature = "remote")]
                if let Some((audit_ids, audit_time)) = api_key_audit.take() {
                    let (state, result) = if result.is_ok() {
                        ("complete", None)
                    } else {
                        ("denied", Some("handler_refused"))
                    };
                    for audit_id in audit_ids {
                        let _ = api.action_guard.finish_audit(audit_id, state, result, audit_time).await;
                    }
                }
                if let Err(error) = result {
                    send_live(socket, &api, &owner, token, &mut revocation, serde_json::to_string(&serde_json::json!({"error":error})).ok(), #[cfg(feature = "remote")] key_identity).await?;
                }
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => break,
                }
            }
            () = async { match &mut changed { Some(receiver) => { let _ = receiver.changed().await; }, None => std::future::pending::<()>().await } } => {}
        }
        if let Some(batch) = &batch {
            let (oldest, events) = batch.events(after);
            if after.saturating_add(1) < oldest {
                send_live(
                    socket,
                    &api,
                    &owner,
                    token,
                    &mut revocation,
                    serde_json::to_string(&serde_json::json!({"resync":true,"oldest":oldest})).ok(),
                    #[cfg(feature = "remote")]
                    key_identity,
                )
                .await?;
            }
            for event in events {
                // Revocation interrupts a stalled five-second send too. No remote
                // mutation is admitted by a socket that has lost owner authority.
                #[cfg(feature = "remote")]
                let encoded_event = encode_bootstrap_event(&event, api_key.is_some());
                #[cfg(not(feature = "remote"))]
                let encoded_event = encode_bootstrap_event(&event, false);
                send_live(
                    socket,
                    &api,
                    &owner,
                    token,
                    &mut revocation,
                    encoded_event,
                    #[cfg(feature = "remote")]
                    key_identity,
                )
                .await?;
                after = event.sequence;
            }
        }
    }
    // Dropping Batch signals cancellation; host attempts finish their rollback.
    Ok(())
}

/// True when `text` is a `confirm-host-key` request for exactly this target, challenge and fingerprint.
///
/// Used while that confirmation is in flight: a repeat of it (a double-click) is already being answered,
/// so it is dropped instead of refused as busy. Anything else, including the same challenge with another
/// fingerprint, is not the same confirmation and keeps getting the busy error. Unparseable text is never
/// "the same".
fn is_same_confirmation(text: &str, target: &str, challenge: &str, fingerprint: &str) -> bool {
    matches!(
        serde_json::from_str::<Request>(text),
        Ok(Request::ConfirmHostKey { target: t, challenge: c, fingerprint: f })
            if t == target && c == challenge && f == fingerprint
    )
}

fn now() -> Result<i64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok())
        .ok_or(())
}

#[cfg(test)]
#[path = "bootstrap_api_tests.rs"]
mod tests;
