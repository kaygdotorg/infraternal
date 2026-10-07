//! Additive owner-authenticated bootstrap WebSocket; #78 runtime injects the trusted backend [63][138][139].

use crate::auth::Auth;
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use infraternal_plugin_ssh::{
    bootstrap::{Batch, Bootstrap},
    model::Target,
};
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

/// The existing authenticator is reused; runtime must provide an authorized #78 backend.
struct Api {
    auth: Auth,
    runner: Bootstrap,
    sockets: Arc<Semaphore>,
}

/// Mount an additive router with a trusted runtime backend; unavailable enrollment fails before mutation.
pub fn router(auth: Auth, runner: Bootstrap) -> Router {
    Router::new()
        .route("/v1/bootstrap/ws", get(upgrade))
        .with_state(Arc::new(Api {
            auth,
            runner,
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
    },
    Retry {
        target: String,
    },
    Replay {
        after: u64,
    },
}

async fn upgrade(
    State(api): State<Arc<Api>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(api.auth.origin())
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if headers.get_all(header::COOKIE).iter().count() != 1 {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(token) = crate::websocket::session_cookie(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(now) = now() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(owner) = api.auth.bootstrap_owner(token, now).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(permit) = api.sockets.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let token = token.to_owned();
    ws.max_message_size(32 * 1024)
        .max_frame_size(32 * 1024)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            run(socket, api, owner, token).await;
        })
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

async fn send_live(
    socket: &mut WebSocket,
    api: &Api,
    owner: &str,
    token: &str,
    revocation: &mut tokio::sync::watch::Receiver<()>,
    encoded: Option<String>,
) -> Result<(), ()> {
    // Keep the same write future after another user's revocation. Dropping and
    // restarting a partially buffered frame would duplicate sequence delivery.
    // Serialize before this shared async boundary: event and error types must
    // not instantiate the full WebSocket writer and revocation loop twice.
    let writing = send(socket, encoded.ok_or(())?);
    tokio::pin!(writing);
    loop {
        tokio::select! {
            biased;
            change = revocation.changed() => {
                if change.is_err() || !authorized(api, token, owner).await { return Err(()); }
            }
            result = &mut writing => return result,
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run(mut socket: WebSocket, api: Arc<Api>, owner: String, token: String) {
    let mut revocation = api.auth.revocation_events();
    let mut batch: Option<Batch> = None;
    let mut changed: Option<tokio::sync::watch::Receiver<u64>> = None;
    let mut after = 0;
    // A wholly idle socket has one session-expiry deadline, not a polling loop.
    let mut expiry = Box::pin(tokio::time::sleep(Duration::from_hours(30 * 24)));
    loop {
        tokio::select! {
            biased;
            () = &mut expiry => break,
            _ = revocation.changed() => {
                if !authorized(&api, &token, &owner).await { break; }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                if !authorized(&api, &token, &owner).await { break; }
                expiry.as_mut().reset(tokio::time::Instant::now() + Duration::from_hours(30 * 24));
                let Ok(request) = serde_json::from_str::<Request>(&text) else {
                    if send_live(&mut socket, &api, &owner, &token, &mut revocation, serde_json::to_string(&serde_json::json!({"error":"invalid bootstrap request"})).ok()).await.is_err() { break; }
                    continue;
                };
                let result = match request {
                    Request::Start { targets, credential } if batch.is_none() => {
                        match api.runner.start(owner.clone(), targets, credential) {
                            Ok(started) => { changed = Some(started.subscribe()); batch = Some(started); Ok(()) }
                            Err(error) => Err(error)
                        }
                    }
                    Request::Retry { target } => batch.as_ref().ok_or_else(|| infraternal_plugin_ssh::model::Failure::unsupported("Start a host batch first.")).and_then(|batch| api.runner.retry(batch, &owner, &target)),
                    Request::Replay { after: sequence } => { after = sequence; Ok(()) }
                    Request::Start { .. } => Err(infraternal_plugin_ssh::model::Failure::unsupported("A host batch is already running.")),
                };
                if let Err(error) = result
                    && send_live(&mut socket, &api, &owner, &token, &mut revocation, serde_json::to_string(&serde_json::json!({"error":error})).ok()).await.is_err() { break; }
                    }
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    _ => break,
                }
            }
            () = async { match &mut changed { Some(receiver) => { let _ = receiver.changed().await; }, None => std::future::pending::<()>().await } } => {}
        }
        if let Some(batch) = &batch {
            let (oldest, events) = batch.events(after);
            if after.saturating_add(1) < oldest
                && send_live(
                    &mut socket,
                    &api,
                    &owner,
                    &token,
                    &mut revocation,
                    serde_json::to_string(&serde_json::json!({"resync":true,"oldest":oldest})).ok(),
                )
                .await
                .is_err()
            {
                break;
            }
            for event in events {
                // Revocation interrupts a stalled five-second send too. No remote
                // mutation is admitted by a socket that has lost owner authority.
                if send_live(
                    &mut socket,
                    &api,
                    &owner,
                    &token,
                    &mut revocation,
                    serde_json::to_string(&event).ok(),
                )
                .await
                .is_err()
                {
                    return;
                }
                after = event.sequence;
            }
        }
    }
    // Dropping Batch signals cancellation; host attempts finish their rollback.
}

fn now() -> Result<i64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_secs()).ok())
        .ok_or(())
}
