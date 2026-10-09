//! Serves bounded same-origin administrator CA status and real passkey unlock; encrypted copies and seed never reach HTTP [168], #78.
use crate::{auth::Auth, ca_administration::CaAdministration};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    routing::post,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

#[derive(Clone)]
struct Api {
    auth: Auth,
    administration: Arc<CaAdministration>,
    admission: Arc<Semaphore>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// Parsed secret request material grants no authority. No debug, clone or
/// serialization implementation exposes its transient scoped wrapping key.
pub struct UnlockRequest {
    ceremony: String,
    proof: Value,
    scoped_key: Zeroizing<[u8; 32]>,
}

/// Parse the bounded unlock request without reflecting attacker-controlled data.
/// The HTTP authority checks remain mandatory after successful decoding.
/// # Errors
/// Refuses oversized, malformed, unknown-field or invalid-ceremony input.
pub fn decode_unlock(input: &[u8]) -> Result<UnlockRequest, crate::ca::CaError> {
    if input.len() > 32768 {
        return Err(crate::ca::CaError);
    }
    let request: UnlockRequest = serde_json::from_slice(input).map_err(|_| crate::ca::CaError)?;
    if request.ceremony.is_empty() || request.ceremony.len() > 128 {
        return Err(crate::ca::CaError);
    }
    Ok(request)
}
/// Mount only a configured private CA authority; no request can regenerate trust.
pub fn router(auth: Auth, administration: Arc<CaAdministration>) -> Router {
    Router::new()
        .route("/remote/ca/status", post(status))
        .route("/remote/ca/bootstrap/start", post(bootstrap_start))
        .route("/remote/ca/bootstrap/finish", post(bootstrap_finish))
        .route("/remote/ca/unlock/start", post(start))
        .route("/remote/ca/unlock/finish", post(finish))
        .layer(DefaultBodyLimit::max(32768))
        .layer(axum::middleware::from_fn(deadline))
        .with_state(Api {
            auth,
            administration,
            admission: Arc::new(Semaphore::new(8)),
        })
}
async fn deadline(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // Bound live-session database checks too, before reserved body capacity.
    tokio::time::timeout(std::time::Duration::from_secs(5), next.run(request))
        .await
        .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response())
}
fn request<'a>(api: &Api, headers: &'a HeaderMap) -> Result<(&'a str, i64), StatusCode> {
    if headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        != Some(api.auth.origin())
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let token =
        crate::auth::session_cookie_from_headers(headers).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|time| i64::try_from(time.as_secs()).ok())
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((token, now))
}
async fn start(State(api): State<Api>, headers: HeaderMap) -> Result<Json<Value>, StatusCode> {
    let (token, now) = request(&api, &headers)?;
    api.administration
        .status(token, now)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let _permit = api
        .admission
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    api.administration
        .start(token, now)
        .await
        .map(Json)
        .map_err(|_| StatusCode::FORBIDDEN)
}
async fn bootstrap_start(
    State(api): State<Api>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    let (token, now) = request(&api, &headers)?;
    api.administration
        .status(token, now)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let _permit = api
        .admission
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    api.administration
        .bootstrap_start(token, now)
        .await
        .map(Json)
        .map_err(|_| StatusCode::FORBIDDEN)
}
async fn bootstrap_finish(
    State(api): State<Api>,
    incoming: axum::extract::Request,
) -> Result<Json<Value>, StatusCode> {
    finish_request(api, incoming, true).await
}
async fn finish(
    State(api): State<Api>,
    incoming: axum::extract::Request,
) -> Result<Json<Value>, StatusCode> {
    finish_request(api, incoming, false).await
}
async fn finish_request(
    api: Api,
    incoming: axum::extract::Request,
    bootstrap: bool,
) -> Result<Json<Value>, StatusCode> {
    let (parts, body) = incoming.into_parts();
    let (token, now) = request(&api, &parts.headers)?;
    api.administration
        .status(token, now)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let _permit = api
        .admission
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    // Extraction must not read the body before admission. Keep the reservation
    // through reading and proof verification; cancellation or the single
    // request deadline releases it. A stalled sender cannot hold all slots.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let body = axum::body::to_bytes(body, 32768)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        // Parser errors remain static: wrapping material is never reflected.
        let body = decode_unlock(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
        if bootstrap {
            api.administration
                .bootstrap_finish(token, &body.ceremony, body.proof, body.scoped_key, now)
                .await
        } else {
            api.administration
                .finish(token, &body.ceremony, body.proof, body.scoped_key, now)
                .await
        }
        .map_err(|_| StatusCode::FORBIDDEN)?;
        Ok(Json(json!({"locked":false})))
    })
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
}
async fn status(State(api): State<Api>, headers: HeaderMap) -> Result<Json<Value>, StatusCode> {
    let (token, now) = request(&api, &headers)?;
    api.administration
        .status(token, now)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let _permit = api
        .admission
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    let locked = api
        .administration
        .status(token, now)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(Json(json!({"locked":locked})))
}
