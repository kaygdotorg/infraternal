//! Additive owner-authenticated bootstrap WebSocket; #78 runtime injects the trusted backend [63][138][139].

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
    setup_sockets: Arc<Semaphore>,
    ssh_key: Arc<dyn SshKeySource>,
}

/// Mount an additive router with a trusted runtime backend; unavailable enrollment fails before mutation.
pub fn router(auth: Auth, runner: Bootstrap) -> Router {
    router_with_ssh_key(auth, runner, Arc::new(UnavailableSshKey))
}

/// Share the runtime's dedicated identity source without exposing private material.
pub fn router_with_ssh_key(
    auth: Auth,
    runner: Bootstrap,
    ssh_key: Arc<dyn SshKeySource>,
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
        sockets: Arc::new(Semaphore::new(16)),
        #[cfg(feature = "remote")]
        setup_sockets: Arc::new(Semaphore::new(
            infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS,
        )),
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
    let (owner, token) = match authenticate_headers(&api, &headers).await {
        Ok(identity) => identity,
        Err(status) => return status.into_response(),
    };
    let Ok(activity) = api.runner.activity() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(permit) = api.sockets.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let token = Secret::new(token.as_bytes().to_vec());
    upgrade_admitted(
        ws.max_message_size(32 * 1024).max_frame_size(32 * 1024),
        api,
        owner,
        token,
        activity,
        permit,
        SocketMode::Bootstrap,
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

#[inline(never)]
fn upgrade_admitted(
    ws: WebSocketUpgrade,
    api: Arc<Api>,
    owner: String,
    token: Secret,
    activity: infraternal_plugin_ssh::bootstrap::Activity,
    permit: tokio::sync::OwnedSemaphorePermit,
    mode: SocketMode,
) -> Response {
    ws.on_upgrade(move |mut socket| async move {
        // Retire stream and admission before publishing this lifetime inactive.
        let _activity = activity;
        let _permit = permit;
        let result = match mode {
            SocketMode::Bootstrap => run(&mut socket, api, owner, token).await,
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
                if !authorized(api, token, owner).await { return Err(SocketFailure::Closed); }
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
    if !authorized(&api, token, &owner).await {
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
                if !authorized(&api, token, &owner).await { break; }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                if !authorized(&api, token, &owner).await { break; }
                expiry.as_mut().reset(tokio::time::Instant::now() + Duration::from_hours(30 * 24));
                let decoded = serde_json::from_str::<Request>(&text);
                // Transient private fields are now owned zeroizing buffers; no raw
                // JSON is retained by batch state, helper tasks or replay history.
                drop(text);
                let Ok(request) = decoded else {
                    send_live(socket, &api, &owner, token, &mut revocation, serde_json::to_string(&serde_json::json!({"error":"invalid bootstrap request"})).ok()).await?;
                    continue;
                };
                let result = match request {
                    Request::Start { targets, credential, auth_once } if batch.is_none() => {
                        match api.runner.start_authenticated_with_auth(owner.clone(), Secret::new(token.as_bytes().to_vec()), targets, credential, auth_once) {
                            Ok(started) => { changed = Some(started.subscribe()); batch = Some(started); Ok(()) }
                            Err(error) => Err(error)
                        }
                    }
                    Request::Retry { target, auth_once } => batch.as_ref().ok_or_else(|| infraternal_plugin_ssh::model::Failure::unsupported("Start a host batch first.")).and_then(|batch| api.runner.retry_with_auth(batch, &owner, &target, auth_once)),
                    Request::StartFresh {target, challenge} => batch.as_ref().ok_or_else(|| infraternal_plugin_ssh::model::Failure::unsupported("Start a host batch first.")).and_then(|batch| api.runner.start_fresh(batch, &owner, &target, challenge)),
                    Request::ConfirmHostKey {target,challenge,fingerprint} => {
                        if let Some(batch)=&batch {
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
                                                Some(Ok(Message::Text(_))) => {
                                                    // Refuse concurrent requests without retaining private inputs
                                                    // or cancelling the batch that owns this confirmation.
                                                    let busy = serde_json::to_string(&serde_json::json!({"error":"host-key confirmation busy; retry after confirmation"})).ok();
                                                    send_live(socket,&api,&owner,token,&mut revocation,busy).await?;
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
                                    send_live(socket,&api,&owner,token,&mut revocation,reply).await?;
                                    Ok(())
                                }
                                Err(error)=>Err(error),
                            }
                        } else {Err(infraternal_plugin_ssh::model::Failure::unsupported("Start a host batch first."))}
                    }
                    Request::Replay { after: sequence } => { after = sequence; Ok(()) }
                    Request::Start { .. } => Err(infraternal_plugin_ssh::model::Failure::unsupported("A host batch is already running.")),
                };
                if let Err(error) = result {
                    send_live(socket, &api, &owner, token, &mut revocation, serde_json::to_string(&serde_json::json!({"error":error})).ok()).await?;
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
                )
                .await?;
            }
            for event in events {
                // Revocation interrupts a stalled five-second send too. No remote
                // mutation is admitted by a socket that has lost owner authority.
                send_live(
                    socket,
                    &api,
                    &owner,
                    token,
                    &mut revocation,
                    serde_json::to_string(&event).ok(),
                )
                .await?;
                after = event.sequence;
            }
        }
    }
    // Dropping Batch signals cancellation; host attempts finish their rollback.
    Ok(())
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
