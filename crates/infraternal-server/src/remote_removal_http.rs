//! Bounded same-origin adapters for the remote plugin's removal action: a dry run, then the
//! removal, inside the browser's admin window [16][168], #87, D339.
//! D369 Forget uses that same window to cancel unreachable cleanup without a machine-side effect.
use crate::{auth::Auth, remote_removal::Removal};
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
#[derive(Clone)]
struct Api {
    auth: Auth,
    removal: Removal,
    admission: Arc<Semaphore>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// Public selection; parsing grants no removal authority.
pub struct Start {
    host_id: Uuid,
    #[serde(default = "default_uninstall")]
    uninstall: bool,
}
fn default_uninstall() -> bool {
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// The host and the review from its dry run, deliberately without Debug or serialization.
pub struct Finish {
    host_id: Uuid,
    review: String,
}
/// Mount the bounded same-origin removal and Forget routes with shared owner authority.
pub(crate) fn router(auth: Auth, removal: Removal) -> Router {
    Router::new()
        .route("/remote/hosts/actions", post(actions))
        .route("/remote/hosts/remove/start", post(start))
        .route("/remote/hosts/remove/finish", post(finish))
        .route("/remote/hosts/forget", post(forget))
        .layer(axum::extract::DefaultBodyLimit::max(32768))
        .layer(axum::middleware::from_fn(deadline))
        .with_state(Api {
            auth,
            removal,
            admission: Arc::new(Semaphore::new(8)),
        })
}
async fn deadline(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    tokio::time::timeout(std::time::Duration::from_secs(15), next.run(request))
        .await
        .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response())
}
fn authority<'a>(api: &Api, headers: &'a HeaderMap) -> Result<(&'a str, i64), StatusCode> {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    if origins.next().and_then(|v| v.to_str().ok()) != Some(api.auth.origin())
        || origins.next().is_some()
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let token =
        crate::auth::session_cookie_from_headers(headers).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let now = crate::runtime::unix_seconds().map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok((token, now))
}
async fn body(
    api: &Api,
    incoming: axum::extract::Request,
) -> Result<(String, i64, Vec<u8>, tokio::sync::OwnedSemaphorePermit), StatusCode> {
    let (parts, body) = incoming.into_parts();
    let (token, now) = authority(api, &parts.headers)?;
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
    Ok((token.to_owned(), now, bytes.to_vec(), permit))
}
async fn start(
    State(api): State<Api>,
    incoming: axum::extract::Request,
) -> Result<Json<Value>, StatusCode> {
    let (token, now, bytes, _permit) = body(&api, incoming).await?;
    let input = decode_start(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    api.removal
        .start(&token, input.host_id, input.uninstall, now)
        .await
        .map(Json)
        .map_err(|_| StatusCode::FORBIDDEN)
}
async fn finish(
    State(api): State<Api>,
    incoming: axum::extract::Request,
) -> Result<Json<Value>, StatusCode> {
    let (token, now, bytes, _permit) = body(&api, incoming).await?;
    let input = decode_finish(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    api.removal
        .finish_host(&token, input.host_id, &input.review, now)
        .await
        .map(Json)
        .map_err(|_| StatusCode::FORBIDDEN)
}

/// A Forget selection carries only a host UUID; the transaction derives ownership and state.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Forget {
    host_id: Uuid,
}

/// Forget only within the same-origin owner's admin window, with the existing bounded decoder.
async fn forget(
    State(api): State<Api>,
    incoming: axum::extract::Request,
) -> Result<Json<Value>, StatusCode> {
    let (token, now, bytes, _permit) = body(&api, incoming).await?;
    let input: Forget = decode(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    api.removal
        .forget_browser(&token, input.host_id, now)
        .await
        .map(Json)
        .map_err(|_| StatusCode::FORBIDDEN)
}

async fn actions(State(api): State<Api>, headers: HeaderMap) -> Result<Json<Value>, StatusCode> {
    let (token, now) = authority(&api, &headers)?;
    let session = api
        .auth
        .session(token, now)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let owner: bool = sqlx::query_scalar("SELECT owner=1 FROM users WHERE id=?")
        .bind(&session.user_id)
        .fetch_one(api.removal.pool())
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !owner {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(
        serde_json::json!({"id":infraternal_plugin_remote::REMOVE.id,"label":infraternal_plugin_remote::REMOVE.summary,"instructions":infraternal_plugin_remote::REMOVE.instructions}),
    ))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, crate::auth::Error> {
    if bytes.len() > 32768 || bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err(crate::auth::Error::Invalid);
    }
    serde_json::from_slice(bytes).map_err(|_| crate::auth::Error::Invalid)
}
/// Decode the exact bounded removal selection; authorization remains with the handler.
/// # Errors
/// Refuses positional arrays, duplicates, unknown fields and excessive input.
pub fn decode_start(bytes: &[u8]) -> Result<Start, crate::auth::Error> {
    decode(bytes)
}
/// Decode the exact bounded host and review; parsing never authorizes a mutation.
/// # Errors
/// Refuses malformed objects, duplicates, unknown fields and invalid review lengths.
pub fn decode_finish(bytes: &[u8]) -> Result<Finish, crate::auth::Error> {
    let request: Finish = decode(bytes)?;
    if request.review.is_empty() || request.review.len() > 128 {
        return Err(crate::auth::Error::Invalid);
    }
    Ok(request)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removal_parsers_refuse_positional_duplicate_and_unbounded_inputs() {
        assert!(decode_start(br#"["11111111-2222-3333-4444-555555555555",true]"#).is_err());
        assert!(decode_start(br#"{"host_id":"11111111-2222-3333-4444-555555555555","host_id":"11111111-2222-3333-4444-555555555555"}"#).is_err());
        assert!(
            decode_start(br#"{"host_id":"11111111-2222-3333-4444-555555555555"}"#)
                .unwrap()
                .uninstall
        );
        assert!(
            decode_finish(br#"{"host_id":"11111111-2222-3333-4444-555555555555","review":""}"#)
                .is_err()
        );
        assert!(decode_finish(&vec![b' '; 32769]).is_err());
    }
}
