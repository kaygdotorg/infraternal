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
        .route("/remote/ca/unlock/start", post(start))
        .route("/remote/ca/unlock/finish", post(finish))
        .layer(DefaultBodyLimit::max(32768))
        .with_state(Api {
            auth,
            administration,
            admission: Arc::new(Semaphore::new(8)),
        })
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
async fn finish(
    State(api): State<Api>,
    headers: HeaderMap,
    body: bytes::Bytes,
) -> Result<Json<Value>, StatusCode> {
    // Return a static parser error rather than Axum's JSON diagnostic, which
    // could reflect attacker-controlled wrapping material in an invalid value.
    let body = decode_unlock(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let key = body.scoped_key;
    let (token, now) = request(&api, &headers)?;
    let _permit = api
        .admission
        .try_acquire()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;
    api.administration
        .finish(token, &body.ceremony, body.proof, key, now)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(Json(json!({"locked":false})))
}
async fn status(State(api): State<Api>, headers: HeaderMap) -> Result<Json<Value>, StatusCode> {
    let (token, now) = request(&api, &headers)?;
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
