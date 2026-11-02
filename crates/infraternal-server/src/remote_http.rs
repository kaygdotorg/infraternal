//! Serves bounded remote enrollment and owner revocation over HTTPS; signer unlock remains a separate trusted D168 adapter, #78.

use crate::{
    auth::Auth,
    ca::CaKeySource,
    enrollment::{EnrollmentStore, IssueConstraints, Mode},
    remote_enrollment::RemoteEnrollment,
};
use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::Deserialize;
use sqlx::SqlitePool;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use uuid::Uuid;

pub use infraternal_plugin_remote::enrollment::{JoinInvitation, JoinRequest, JoinResponse};

/// Server-owned public transport metadata, independent of the signer lock.
#[derive(Clone)]
pub struct EnrollmentEndpoint {
    /// DER issuer pin, never private key material.
    pub ca_der: Vec<u8>,
    /// Reachable dial-out UDP/TCP address.
    pub endpoint: std::net::SocketAddr,
    /// Certificate SAN used for both legs.
    pub server_name: String,
}

/// Trusted runtime supplies the D168 source; mounting routes never unlocks it.
#[derive(Clone)]
pub struct EnrollmentService {
    /// Configured signer or cold-locked source.
    pub source: Arc<dyn CaKeySource>,
    /// Server-selected public trust and dial-out address.
    pub endpoint: EnrollmentEndpoint,
}

#[derive(Clone)]
struct Api {
    auth: Auth,
    pool: SqlitePool,
    store: EnrollmentStore,
    source: Arc<dyn CaKeySource>,
    endpoint: EnrollmentEndpoint,
    admission: Arc<Semaphore>,
    owner_admission: Arc<Semaphore>,
    sources: Arc<crate::remote_admission::SourceSlots>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvitationRequest {
    pub(crate) host_id: Uuid,
    pub(crate) mode: Mode,
    pub(crate) execution_uid: u32,
    #[serde(default)]
    pub(crate) expected_key_digest: Option<[u8; 32]>,
}

/// SSH and HTTPS share the exact authority checks and transport revocation scope.
#[derive(Clone)]
pub(crate) struct InvitationIssuer(Api);
impl InvitationIssuer {
    pub(crate) fn new(
        auth: Auth,
        pool: SqlitePool,
        store: EnrollmentStore,
        service: EnrollmentService,
    ) -> Self {
        Self(Api {
            auth,
            pool,
            store,
            source: service.source,
            endpoint: service.endpoint,
            admission: Arc::new(Semaphore::new(8)),
            owner_admission: Arc::new(Semaphore::new(8)),
            sources: Arc::new(crate::remote_admission::SourceSlots::new(2)),
        })
    }
    /// The setup address is committed with its new host record and invitation.
    pub(crate) async fn issue_bootstrap(
        &self,
        cookie: &str,
        request: InvitationRequest,
        address: &str,
        lookup: Option<&str>,
    ) -> Result<JoinInvitation, StatusCode> {
        issue_invitation(self.0.clone(), cookie, request, Some((address, lookup))).await
    }
    /// Same authority path as initial issue, retaining existing destination metadata.
    pub(crate) async fn reissue(
        &self,
        cookie: &str,
        request: InvitationRequest,
    ) -> Result<JoinInvitation, StatusCode> {
        issue_invitation(self.0.clone(), cookie, request, None).await
    }
    pub(crate) fn ready(&self) -> bool {
        self.0.source.load().is_ok()
    }
    pub(crate) fn origin(&self) -> &str {
        self.0.auth.origin()
    }
    pub(crate) fn store(&self) -> &EnrollmentStore {
        &self.0.store
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationRequest {
    host_id: Uuid,
}

/// Build enrollment routes around the migrated runtime database and a D168 signer.
/// The listener must authenticate HTTPS before the join capability is transmitted.
pub fn router(
    auth: Auth,
    pool: SqlitePool,
    source: Arc<dyn CaKeySource>,
    endpoint: EnrollmentEndpoint,
) -> Router {
    let store = EnrollmentStore::new(pool.clone());
    router_with_store(auth, pool, store, source, endpoint)
}

/// Keep the shipping API shape stable before remote trust is configured.
/// No request can create a signer or bypass the cold-start lock [168].
pub(crate) fn unavailable_router() -> Router {
    async fn unavailable() -> StatusCode {
        StatusCode::SERVICE_UNAVAILABLE
    }
    Router::new()
        .route("/remote/invitations", post(unavailable))
        .route("/remote/join", post(unavailable))
        .route("/remote/revocations", post(unavailable))
}

/// Runtime supplies the same event scope used by its admitted host transports.
pub(crate) fn router_with_store(
    auth: Auth,
    pool: SqlitePool,
    store: EnrollmentStore,
    source: Arc<dyn CaKeySource>,
    endpoint: EnrollmentEndpoint,
) -> Router {
    let api = Api {
        auth,
        pool,
        store,
        source,
        endpoint,
        admission: Arc::new(Semaphore::new(8)),
        owner_admission: Arc::new(Semaphore::new(8)),
        sources: Arc::new(crate::remote_admission::SourceSlots::new(2)),
    };
    Router::new()
        .route("/remote/invitations", post(invite))
        .route("/remote/join", post(join))
        .route("/remote/revocations", post(revoke))
        .layer(axum::extract::DefaultBodyLimit::max(8192))
        .layer(from_fn_with_state(api.clone(), admission))
        .with_state(api)
}

async fn revoke(
    State(api): State<Api>,
    headers: HeaderMap,
    Json(request): Json<RevocationRequest>,
) -> Result<StatusCode, StatusCode> {
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(api.auth.origin()) {
        return Err(StatusCode::FORBIDDEN);
    }
    let cookie =
        crate::auth::session_cookie_from_headers(&headers).map_err(|_| StatusCode::UNAUTHORIZED)?;
    // A locked CA cannot prevent an authorized owner from cutting public host
    // authority. Never call the signer or treat this owner permission as unlock.
    api.store
        .revoke_for_session(&crate::auth::hash(cookie), request.host_id, now()?)
        .await
        .map_err(|error| match error {
            crate::enrollment::EnrollmentError::Denied => StatusCode::FORBIDDEN,
            crate::enrollment::EnrollmentError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
        })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn admission(State(api): State<Api>, request: Request, next: Next) -> Response {
    tokio::time::timeout(Duration::from_secs(5), admit_request(api, request, next))
        .await
        .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response())
}
async fn admit_request(api: Api, request: Request, next: Next) -> Response {
    let owner = request.uri().path() != "/remote/join";
    let _source = if owner {
        if request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            != Some(api.auth.origin())
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        let Ok(token) = crate::auth::session_cookie_from_headers(request.headers()) else {
            return StatusCode::UNAUTHORIZED.into_response();
        };
        let Ok(now) = now() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let Ok(session) = api.auth.session(token, now).await else {
            return StatusCode::FORBIDDEN.into_response();
        };
        let allowed = sqlx::query_scalar::<_, bool>("SELECT owner=1 FROM users WHERE id=?")
            .bind(&session.user_id)
            .fetch_optional(&api.pool)
            .await;
        if !matches!(allowed, Ok(Some(true))) {
            return StatusCode::FORBIDDEN.into_response();
        }
        None
    } else {
        let address = request
            .extensions()
            .get::<crate::runtime::ClientAddress>()
            .map(|v| v.0)
            .or_else(|| {
                request
                    .extensions()
                    .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                    .map(|v| v.0.ip())
            })
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let Some(permit) = api.sources.reserve(address) else {
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        };
        Some(permit)
    };
    let semaphore = if owner {
        &api.owner_admission
    } else {
        &api.admission
    };
    let Ok(_permit) = semaphore.try_acquire() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    // Includes body extraction: a slow upload cannot hold a signer slot indefinitely.
    tokio::time::timeout(Duration::from_secs(5), next.run(request))
        .await
        .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response())
}

fn now() -> Result<i64, StatusCode> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)
}

async fn invite(
    State(api): State<Api>,
    headers: HeaderMap,
    Json(request): Json<InvitationRequest>,
) -> Result<Json<JoinInvitation>, StatusCode> {
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(api.auth.origin()) {
        return Err(StatusCode::FORBIDDEN);
    }
    let cookie =
        crate::auth::session_cookie_from_headers(&headers).map_err(|_| StatusCode::UNAUTHORIZED)?;
    issue_invitation(api, cookie, request, None).await.map(Json)
}

async fn issue_invitation(
    api: Api,
    cookie: &str,
    request: InvitationRequest,
    destination: Option<(&str, Option<&str>)>,
) -> Result<JoinInvitation, StatusCode> {
    if request.expected_key_digest.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let now = now()?;
    let session_hash = crate::auth::hash(cookie);
    let session = api
        .auth
        .session(cookie, now)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    // Current core policy permits host enrollment to the owner. CA unlock remains
    // a separate administrator/passkey policy; this check never unlocks a signer.
    let owner: bool = sqlx::query_scalar("SELECT owner=1 FROM users WHERE id=?")
        .bind(&session.user_id)
        .fetch_one(&api.pool)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !owner || (request.mode == Mode::Rootless) == (request.execution_uid == 0) {
        return Err(StatusCode::FORBIDDEN);
    }
    // Drop rolls back every unpublished write on error or cancellation. The
    // invitation is assembled before commit, so certificate conversion cannot
    // strand a new host record either.
    let mut transaction = api
        .pool
        .begin()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    // An existing id must have exactly the same authority: collisions cannot move a host.
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) SELECT ?,?,?,?,? FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.user_id=? AND s.unlocked=1 AND s.expires>unixepoch() AND u.owner=1 ON CONFLICT(id) DO NOTHING")
        .bind(request.host_id.as_bytes().as_slice()).bind(&session.user_id).bind(request.mode.as_str())
        .bind(i64::from(request.execution_uid)).bind(now).bind(&session_hash).bind(&session.user_id).execute(&mut *transaction).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let uid: Option<i64> = sqlx::query_scalar("SELECT execution_uid FROM remote_hosts WHERE id=? AND owner_id=? AND mode=? AND revoked_at IS NULL")
        .bind(request.host_id.as_bytes().as_slice()).bind(&session.user_id).bind(request.mode.as_str())
        .fetch_optional(&mut *transaction).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if uid != Some(i64::from(request.execution_uid)) {
        return Err(StatusCode::FORBIDDEN);
    }
    let token = api
        .store
        .issue_authorized_in(
            &session.user_id,
            request.host_id,
            request.mode,
            now,
            IssueConstraints {
                session_hash: Some(&session_hash),
                expected_key_digest: request.expected_key_digest.as_ref(),
            },
            &mut transaction,
        )
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    if let Some((address, lookup)) = destination {
        // The preceding host INSERT owns SQLite's writer slot. Repeat the
        // destination check here for independently constructed adapters too.
        let occupied: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_host_bootstrap b JOIN remote_hosts h ON h.id=b.host_id WHERE h.owner_id=? AND h.revoked_at IS NULL AND (b.address=? OR (? IS NOT NULL AND b.trust_lookup=?)))")
            .bind(&session.user_id).bind(address).bind(lookup).bind(lookup)
            .fetch_one(&mut *transaction).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        if occupied {
            return Err(StatusCode::CONFLICT);
        }
        sqlx::query(
            "INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,?,?)",
        )
        .bind(request.host_id.as_bytes().as_slice())
        .bind(address)
        .bind(lookup)
        .execute(&mut *transaction)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        // Retire unless proven completion discharges this obligation. The
        // invitation acknowledgement may be cancelled after SQLite commits;
        // its retirement ownership must survive in that same transaction.
        sqlx::query("INSERT INTO remote_bootstrap_retirement_intents(host_id) VALUES(?)")
            .bind(request.host_id.as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    }
    let invitation = JoinInvitation {
        host_id: request.host_id,
        mode: request.mode,
        execution_uid: request.execution_uid,
        public_origin: api.auth.origin().to_owned(),
        token: token.secret().to_owned(),
        ca_der: B64.encode(
            api.source
                .public_issuer()
                .map(|issuer| issuer.to_der())
                .transpose()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
                .unwrap_or(api.endpoint.ca_der),
        ),
        https_system_roots: api.source.uses_system_https(),
        https_der: api
            .source
            .https_certificate()
            .map(|leaf| leaf.to_der().map(|der| B64.encode(der)))
            .transpose()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        endpoint: Some(api.endpoint.endpoint),
        server_name: api.endpoint.server_name,
    };
    transaction
        .commit()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(invitation)
}

async fn join(
    State(api): State<Api>,
    Json(request): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, StatusCode> {
    if request.csr_der.len() > 5462 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let der = B64
        .decode(&request.csr_der)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if B64.encode(&der) != request.csr_der {
        return Err(StatusCode::BAD_REQUEST);
    }
    let store = api.store;
    let certificate = RemoteEnrollment::new(api.source, store.clone())
        .join(request.host_id, request.mode, &request.token, &der, now()?)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    let identity = store
        .admit(&certificate.record.fingerprint, now()?)
        .await
        .map_err(|_| StatusCode::FORBIDDEN)?;
    Ok(Json(JoinResponse {
        certificate_der: B64.encode(certificate.der),
        execution_uid: identity.execution_uid,
    }))
}

#[cfg(test)]
#[path = "remote_http_tests.rs"]
mod tests;

/// Exact bounded removal decoders shared by HTTP and parser fuzzing.
pub use crate::remote_removal_http::{
    decode_finish as decode_removal_finish, decode_start as decode_removal_start,
};
