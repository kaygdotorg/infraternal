//! Serves bounded same-origin administrator CA status and real passkey unlock; encrypted copies and seed never reach HTTP [168], #78.
use crate::{auth::Auth, ca_administration::CaAdministration};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header},
    routing::post,
};
use futures_util::StreamExt;
use infraternal_shim::locked_bytes::LockedBytes;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

#[derive(Clone)]
struct Api {
    auth: Auth,
    administration: Arc<CaAdministration>,
    clock_health: Arc<crate::clock_health::ClockHealth>,
    admission: Arc<Semaphore>,
    starts: Arc<Mutex<HashMap<String, crate::runtime::SourceBucket>>>,
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
pub fn router(
    auth: Auth,
    administration: Arc<CaAdministration>,
    clock_health: Arc<crate::clock_health::ClockHealth>,
) -> Router {
    let api = Api {
        auth,
        administration,
        clock_health,
        admission: Arc::new(Semaphore::new(8)),
        starts: Arc::default(),
    };
    Router::new()
        .route("/remote/ca/status", post(status))
        .route("/remote/ca/administrators/start", post(membership_start))
        .route("/remote/ca/administrators/finish", post(membership_finish))
        .route("/remote/ca/bootstrap/start", post(bootstrap_start))
        .route("/remote/ca/bootstrap/finish", post(bootstrap_finish))
        .route("/remote/ca/unlock/start", post(start))
        .route("/remote/ca/unlock/finish", post(finish))
        .layer(DefaultBodyLimit::max(32768))
        .layer(axum::middleware::from_fn_with_state(
            api.clone(),
            start_budget,
        ))
        .layer(axum::middleware::from_fn(deadline))
        .with_state(api)
}
/// The three start routes share one budget per authenticated principal, across
/// cookies and ceremony kinds. Finish/status remain available at exhaustion.
async fn start_budget(
    State(api): State<Api>,
    incoming: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if !matches!(
        incoming.uri().path(),
        "/remote/ca/unlock/start"
            | "/remote/ca/bootstrap/start"
            | "/remote/ca/administrators/start"
    ) {
        return next.run(incoming).await;
    }
    let (token, now) = match request(&api, incoming.headers()) {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };
    let principal = match api.auth.session(token, now).await {
        Ok(session) => session.user_id,
        Err(_) => return StatusCode::FORBIDDEN.into_response(),
    };
    let mut starts = api.starts.lock().await;
    if let Err(response) = crate::runtime::admit_temporal_request(&mut starts, principal, now, 30) {
        return response.into_response();
    }
    drop(starts);
    next.run(incoming).await
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
async fn membership_start(
    State(api): State<Api>,
    incoming: axum::extract::Request,
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
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let bytes = axum::body::to_bytes(body, 32768)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        let change = decode_role_change(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
        api.administration
            .membership_start(token, change, now)
            .await
            .map(Json)
            .map_err(|_| StatusCode::FORBIDDEN)
    })
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// A bounded opaque role proof; only the consumed server-side purpose grants authority.
pub struct MembershipFinish {
    ceremony: String,
    proof: Value,
}
/// Decode one bounded purpose-bound role proof without granting authority.
/// # Errors
/// Refuses oversized JSON, unknown fields or invalid ceremony identifiers.
pub fn decode_membership_finish(input: &[u8]) -> Result<MembershipFinish, crate::ca::CaError> {
    if input.len() > 32768 {
        return Err(crate::ca::CaError);
    }
    let request: MembershipFinish =
        serde_json::from_slice(input).map_err(|_| crate::ca::CaError)?;
    if request.ceremony.is_empty() || request.ceremony.len() > 128 {
        return Err(crate::ca::CaError);
    }
    Ok(request)
}
/// Decode a bounded exact recipient and role state; authorization remains separate.
/// # Errors
/// Refuses oversized JSON, unknown fields or invalid recipient identifiers.
pub fn decode_role_change(
    input: &[u8],
) -> Result<crate::ca_administration::RoleChange, crate::ca::CaError> {
    if input.len() > 32768 {
        return Err(crate::ca::CaError);
    }
    let request: crate::ca_administration::RoleChange =
        serde_json::from_slice(input).map_err(|_| crate::ca::CaError)?;
    if request.user_id.is_empty() || request.user_id.len() > 256 {
        return Err(crate::ca::CaError);
    }
    Ok(request)
}
async fn membership_finish(
    State(api): State<Api>,
    incoming: axum::extract::Request,
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
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let bytes = axum::body::to_bytes(body, 32768)
            .await
            .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        let body = decode_membership_finish(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
        api.administration
            .membership_finish(token, &body.ceremony, body.proof, now)
            .await
            .map_err(|_| StatusCode::FORBIDDEN)?;
        Ok(Json(json!({"changed":true})))
    })
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
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
        let intake = locked_intake(body).await?;
        // Parser errors remain static: wrapping material is never reflected.
        let body = decode_unlock(&intake).map_err(|_| StatusCode::BAD_REQUEST)?;
        drop(intake);
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
async fn status(
    State(api): State<Api>,
    headers: HeaderMap,
) -> Result<Json<crate::ca_status::CaStatus>, StatusCode> {
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
    let mut status = api
        .administration
        .public_status(Some(&api.clock_health))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    status.locked = Some(locked);
    Ok(Json(status))
}

/// Copy each transport chunk into protected pages immediately after admission.
/// Transport/kernel chunks remain outside our allocator; never aggregate them
/// into another ordinary heap buffer containing the scoped wrapping key.
async fn locked_intake(body: axum::body::Body) -> Result<LockedBytes, StatusCode> {
    let mut intake = LockedBytes::new(32768).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let mut stream = body.into_data_stream();
    let mut length = 0usize;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
        let end = length
            .checked_add(chunk.len())
            .filter(|end| *end <= intake.len())
            .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
        intake[length..end].copy_from_slice(&chunk);
        length = end;
    }
    intake.truncate(length);
    Ok(intake)
}

#[cfg(test)]
mod intake_tests {
    use super::*;

    #[tokio::test]
    async fn chunked_intake_is_bounded_before_parsing() {
        let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = vec![
            Ok(bytes::Bytes::from(vec![b'x'; 16384])),
            Ok(bytes::Bytes::from(vec![b'y'; 16384])),
        ];
        let intake = locked_intake(axum::body::Body::from_stream(futures_util::stream::iter(
            chunks,
        )))
        .await
        .unwrap();
        assert_eq!(intake.len(), 32768);
        assert_eq!(intake[16383], b'x');
        assert_eq!(intake[16384], b'y');
        drop(intake);
        let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = vec![
            Ok(bytes::Bytes::from(vec![b'x'; 32768])),
            Ok(bytes::Bytes::from_static(b"x")),
        ];
        let result = locked_intake(axum::body::Body::from_stream(futures_util::stream::iter(
            chunks,
        )))
        .await;
        assert!(matches!(result, Err(StatusCode::PAYLOAD_TOO_LARGE)));
    }
}
