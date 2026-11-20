//! The browser's endpoints for upgrading a host to the root infraternal agent (D274, D376, #399).
//!
//! Same-origin only, with the session cookie, inside the browser's admin
//! window, for a host admin (the server owner who owns the host), in the
//! style of host removal's routes. Each body is at most 32 KiB, with unknown
//! fields refused. The authority checks that grant anything are repeated in
//! the promotion's own database writes (see `crate::enrollment::promotion`).
//!
//! - `POST /remote/hosts/privilege/probe {host}` → `{full, method, denied, retryAfter}`
//! - `POST /remote/hosts/privilege/begin {host}` → `{attempt, method, sealKey, expires}`
//!   or `{outcome:"locked", retryAfter}`
//! - `POST /remote/hosts/privilege/finish {attempt, sealed?}` → `{outcome, method, retryAfter}`
//!   (`sealed` is absent for passwordless sudo: consent only, D139)
//! - `POST /remote/hosts/privilege/status {attempt}` → `{state, step}`
//!
//! `sealed` is the password sealed in the browser to the host's one-use key;
//! the server can't open it, and never logs or stores it.
use crate::{
    auth::Auth,
    host_promotion::{Promotions, Refused},
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::post,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Shared state of the routes.
#[derive(Clone)]
struct Api {
    auth: Auth,
    promotions: Promotions,
    admission: Arc<Semaphore>,
}

/// A host selection.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRequest {
    host: Uuid,
}

/// The try: the attempt and, unless the way needs none, the sealed password.
/// Deliberately without Debug, so it can't be logged by accident.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishRequest {
    attempt: Uuid,
    #[serde(default)]
    sealed: Option<String>,
}

/// An attempt selection.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptRequest {
    attempt: Uuid,
}

/// Mount the routes.
pub(crate) fn router(auth: Auth, promotions: Promotions) -> Router {
    Router::new()
        .route("/remote/hosts/privilege/probe", post(probe))
        .route("/remote/hosts/privilege/begin", post(begin))
        .route("/remote/hosts/privilege/finish", post(finish))
        .route("/remote/hosts/privilege/status", post(status))
        .layer(axum::extract::DefaultBodyLimit::max(32768))
        .layer(axum::middleware::from_fn(deadline))
        .with_state(Api {
            auth,
            promotions,
            admission: Arc::new(Semaphore::new(8)),
        })
}

/// Bound every request: an elevation waits for the host's prompt and answer.
async fn deadline(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    tokio::time::timeout(std::time::Duration::from_mins(2), next.run(request))
        .await
        .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response())
}

/// The exact Origin, the session cookie's hash and the time; then the owner
/// check, a slot and the body.
async fn admit(
    api: &Api,
    incoming: axum::extract::Request,
) -> Result<(String, i64, Vec<u8>, tokio::sync::OwnedSemaphorePermit), StatusCode> {
    let (parts, body) = incoming.into_parts();
    let headers: &HeaderMap = &parts.headers;
    let mut origins = headers.get_all(header::ORIGIN).iter();
    if origins.next().and_then(|v| v.to_str().ok()) != Some(api.auth.origin())
        || origins.next().is_some()
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let token =
        crate::auth::session_cookie_from_headers(headers).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let now = crate::runtime::unix_seconds().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    api.auth
        .bootstrap_owner(token, now)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let permit = api
        .admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let bytes = axum::body::to_bytes(body, 32768)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    Ok((crate::auth::hash(token), now, bytes.to_vec(), permit))
}

/// The status for a refusal.
const fn refused(refusal: &Refused) -> StatusCode {
    match refusal {
        Refused::Forbidden => StatusCode::FORBIDDEN,
        Refused::Busy => StatusCode::CONFLICT,
        Refused::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// `probe`.
async fn probe(
    State(api): State<Api>,
    incoming: axum::extract::Request,
) -> Result<Json<Value>, StatusCode> {
    let (hash, now, bytes, _permit) = admit(&api, incoming).await?;
    let request: HostRequest =
        serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    api.promotions
        .probe(&hash, request.host, now)
        .await
        .map(Json)
        .map_err(|refusal| refused(&refusal))
}

/// `begin`.
async fn begin(
    State(api): State<Api>,
    incoming: axum::extract::Request,
) -> Result<Json<Value>, StatusCode> {
    let (hash, now, bytes, _permit) = admit(&api, incoming).await?;
    let request: HostRequest =
        serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    api.promotions
        .begin(&hash, request.host, now)
        .await
        .map(Json)
        .map_err(|refusal| refused(&refusal))
}

/// `finish`.
async fn finish(
    State(api): State<Api>,
    incoming: axum::extract::Request,
) -> Result<Json<Value>, StatusCode> {
    let (hash, now, mut bytes, _permit) = admit(&api, incoming).await?;
    let request: Result<FinishRequest, _> = serde_json::from_slice(&bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    let request = request.map_err(|_| StatusCode::BAD_REQUEST)?;
    if request
        .sealed
        .as_ref()
        .is_some_and(|sealed| sealed.len() > 4096)
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    api.promotions
        .finish(&hash, request.attempt, request.sealed, now)
        .await
        .map(Json)
        .map_err(|refusal| refused(&refusal))
}

/// `status`.
async fn status(
    State(api): State<Api>,
    incoming: axum::extract::Request,
) -> Result<Json<Value>, StatusCode> {
    let (hash, now, bytes, _permit) = admit(&api, incoming).await?;
    let request: AttemptRequest =
        serde_json::from_slice(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    api.promotions
        .status(&hash, request.attempt, now)
        .await
        .map(Json)
        .map_err(|refusal| refused(&refusal))
}
