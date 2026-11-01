//! Same-origin HTTP adapter. Cookies are capabilities; mutation requests require the pinned Origin.
use super::{Auth, Error, Wrap};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
#[path = "account_summary_tests.rs"]
mod account_summary_tests;
#[cfg(test)]
#[path = "http_hostname_tests.rs"]
mod hostname_tests;

/// Mount the POST-only `/auth/{action}` API. TLS terminates at the configured public origin.
pub fn router(auth: Auth) -> Router {
    router_with_state(HttpState {
        auth,
        #[cfg(feature = "remote")]
        invitation_issuer: None,
    })
}

#[cfg(feature = "remote")]
/// Mount auth with the runtime's existing issuer for approved machine enrollment.
pub(crate) fn router_with_invitation_issuer(
    auth: Auth,
    invitation_issuer: Option<crate::remote_http::InvitationIssuer>,
) -> Router {
    router_with_state(HttpState {
        auth,
        invitation_issuer,
    })
}

#[derive(Clone)]
struct HttpState {
    auth: Auth,
    #[cfg(feature = "remote")]
    invitation_issuer: Option<crate::remote_http::InvitationIssuer>,
}

fn router_with_state(state: HttpState) -> Router {
    Router::new()
        .route("/auth/{action}", post(dispatch))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(axum::middleware::map_response(no_store))
        .with_state(state)
}

// One typed body per action; unknown fields (including PRF/DEK plaintext) fail closed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    token: String,
    name: Option<String>,
    username: Option<String>,
    display_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct User {
    user_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unlock {
    pending_transaction: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Logout {
    pending_transaction: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Register {
    ceremony: String,
    proof: Value,
    passkey_wrap: Wrap,
    recovery_wrap: Option<Wrap>,
    recovery_verifier: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    ceremony: String,
    proof: Value,
    device: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    user_id: Option<String>,
    username: Option<String>,
    verifier: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRotation {
    recovery_wrap: Wrap,
    recovery_verifier: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceStart {
    device: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    request: Option<super::devices::JoinMachineRequest>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    code: String,
}
/// A passkey proof for the join-approval ceremony started for `code`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveJoin {
    code: String,
    ceremony: String,
    proof: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    id: String,
}

pub(crate) fn cookie(headers: &HeaderMap) -> super::Result<&str> {
    super::cookies::session(headers)
        .map(|cookie| cookie.token)
        .ok_or(Error::Denied)
}
fn body<T: serde::de::DeserializeOwned>(value: Value) -> super::Result<T> {
    serde_json::from_value(value).map_err(|_| Error::Invalid)
}

#[derive(Serialize)]
struct AuthenticatedSession {
    #[serde(flatten)]
    session: super::Session,
    hostname: Option<String>,
}

/// Add the server's system name only to authenticated session reads.
fn authenticated_session(session: super::Session) -> AuthenticatedSession {
    AuthenticatedSession {
        session,
        hostname: nix::unistd::gethostname()
            .ok()
            .map(|name| name.to_string_lossy().trim().to_owned())
            .filter(|name| !name.is_empty()),
    }
}

fn session_cookie(token: &str, login_sequence: i64, expires: i64) -> super::Result<HeaderValue> {
    let expires_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(
            u64::try_from(expires).map_err(|_| Error::Invalid)?,
        ))
        .ok_or(Error::Invalid)?;
    let expires_text = httpdate::fmt_http_date(expires_at);
    HeaderValue::from_str(&format!(
        "__Host-infraternal-session-{login_sequence}-{expires}={token}; Expires={expires_text}; Secure; HttpOnly; SameSite=Strict; Path=/"
    ))
    .map_err(|_| Error::Invalid)
}
fn expired_session_cookie(name: &str) -> super::Result<HeaderValue> {
    HeaderValue::from_str(&format!(
        "{name}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict; Path=/"
    ))
    .map_err(|_| Error::Invalid)
}
async fn session_response(auth: &Auth, token: &str, now: i64) -> super::Result<Response> {
    let state = auth.cookie_state(token, now).await?.ok_or(Error::Denied)?;
    let mut response = Json(json!({"ok":true})).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        session_cookie(token, state.login_sequence, state.expires)?,
    );
    Ok(response)
}

/// Refresh only after a successful auth action. Per-login names make a late response harmless:
/// it can restore an older cookie, but the server still selects the newer login sequence.
async fn refresh_session_cookie(
    auth: &Auth,
    action: &str,
    headers: &HeaderMap,
    mut response: Response,
) -> Response {
    if !response.status().is_success() {
        return response;
    }
    let observed = super::cookies::observed_session_names(headers);
    if matches!(action, "registration-finish" | "login-finish" | "logout") {
        retire_observed(&mut response, observed);
        return response;
    }
    let Some(cookie) = super::cookies::session(headers) else {
        return response;
    };
    let Ok(now) = current_time(auth) else {
        return response;
    };
    match auth.cookie_state(cookie.token, now).await {
        Ok(Some(state)) => {
            let name = format!(
                "__Host-infraternal-session-{}-{}",
                state.login_sequence, state.expires
            );
            if let Ok(value) = session_cookie(cookie.token, state.login_sequence, state.expires) {
                response.headers_mut().append(header::SET_COOKIE, value);
                retire_observed_cookies(&mut response, observed, &name);
            }
        }
        Ok(None) => retire_observed(&mut response, observed),
        Err(error) => {
            tracing::warn!(error = %error, "session cookie deadline refresh failed");
        }
    }
    response
}

fn retire_observed_cookies(response: &mut Response, names: Vec<&str>, keep: &str) {
    for name in names {
        if name == keep {
            continue;
        }
        if let Ok(value) = expired_session_cookie(name) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
}

fn retire_observed(response: &mut Response, names: Vec<&str>) {
    retire_observed_cookies(response, names, "");
}

/// Refresh cookies on the other authenticated HTTP adapters that share the same browser session.
/// Static assets and WebSocket handshakes are excluded; they do not slide an HTTP session row.
pub(crate) async fn refresh_api_cookie(
    State(auth): State<Auth>,
    incoming: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = incoming.uri().path().to_owned();
    if !path.starts_with("/remote/") && !path.starts_with("/v1/") {
        return next.run(incoming).await;
    }
    let headers = incoming.headers().clone();
    let response = next.run(incoming).await;
    refresh_session_cookie(&auth, &path, &headers, response).await
}

async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn dispatch(
    State(state): State<HttpState>,
    Path(action): Path<String>,
    headers: HeaderMap,
    source: Option<Extension<crate::runtime::ClientAddress>>,
    Json(value): Json<Value>,
) -> Response {
    // The runtime's source admission always attaches the trusted address in
    // production (it refuses /auth/ requests without one). A router mounted
    // without it accounts every caller to one shared source.
    let source = source.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |Extension(address)| {
        address.0
    });
    let result = execute(
        &state.auth,
        #[cfg(feature = "remote")]
        state.invitation_issuer.as_ref(),
        &action,
        &headers,
        source,
        value,
    )
    .await;
    let response = match result {
        Ok(response) => response,
        Err(Error::Throttled) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "60")],
            Json(json!({"error":"too many requests"})),
        )
            .into_response(),
        Err(Error::Denied | Error::Webauthn) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"authorization failed"})),
        )
            .into_response(),
        Err(Error::SetupClosed) => {
            (StatusCode::NOT_FOUND, Json(json!({"error":"not found"}))).into_response()
        }
        Err(Error::Invalid | Error::Json) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":"invalid request"})),
        )
            .into_response(),
        Err(Error::Conflict) => (
            StatusCode::CONFLICT,
            Json(json!({"error":"username already exists"})),
        )
            .into_response(),
        Err(Error::RemoteUnavailable) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"enrollment unavailable"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"auth unavailable"})),
        )
            .into_response(),
    };
    refresh_session_cookie(&auth, &action, &headers, response).await
}

// Recovery authority needs a new sample after expensive verification and writer-lock waits.
pub(super) fn current_time(auth: &Auth) -> super::Result<i64> {
    #[cfg(test)]
    if let Some(now) = auth.test_http_time() {
        return Ok(now);
    }
    #[cfg(not(test))]
    let _ = auth;

    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Invalid)?
            .as_secs(),
    )
    .map_err(|_| Error::Invalid)
}

// Keep typed action dispatch together so capability and response rules can be reviewed in one place.
#[allow(clippy::too_many_lines)]
async fn execute(
    auth: &Auth,
    #[cfg(feature = "remote")] invitation_issuer: Option<&crate::remote_http::InvitationIssuer>,
    action: &str,
    headers: &HeaderMap,
    source: IpAddr,
    value: Value,
) -> super::Result<Response> {
    let now = current_time(auth)?;
    ingress(auth, action, headers, source, now).await?;
    if action == "setup-check" {
        let b: Token = body(value)?;
        auth.setup_check(&b.token, now).await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let payload = match action {
        "status" => public_status(auth, value).await?,
        "setup-start" => setup_start(auth, value, now).await?,
        "registration-finish" => {
            let b: Register = body(value)?;
            auth.require_ceremony_binding(&b.ceremony, headers).await?;
            let token = auth
                .registration_finish_clock(
                    &b.ceremony,
                    b.proof,
                    b.passkey_wrap,
                    b.recovery_wrap,
                    b.recovery_verifier,
                    || current_time(auth),
                )
                .await?;
            return session_response(auth, &token, now).await;
        }
        "login-start" => login_start(auth, headers, source, value, now).await?,
        "login-finish" => {
            let b: Login = body(value)?;
            auth.require_ceremony_binding(&b.ceremony, headers).await?;
            let token = auth
                .pending_login_finish(&b.ceremony, b.proof, &b.device, now)
                .await?;
            let mut response = session_response(auth, &token, now).await?;
            *response.body_mut() = axum::body::Body::from(serde_json::to_vec(&json!({
                "ok": true, "pending_transaction": super::sessions::pending_transaction(&token)
            }))?);
            return Ok(response);
        }
        "add-start" => auth.add_start(cookie(headers)?, now).await?,
        "account-summary" => {
            let _: Empty = body(value)?;
            auth.account_summary(cookie(headers)?, now).await?
        }
        "wraps" => auth.wraps(cookie(headers)?, now).await?,
        "unlock-session" => {
            let _: Empty = body(value)?;
            return Ok(Json(authenticated_session(
                auth.unlock_session(cookie(headers)?, now).await?,
            ))
            .into_response());
        }
        "unlock-finish" => {
            let b: Unlock = body(value)?;
            auth.unlock_finish(cookie(headers)?, &b.pending_transaction, now)
                .await?;
            // The browser can hold another tab's login by the time this reply arrives.
            // Activation changes only the matched database row, never the cookie jar.
            return Ok(Json(json!({"ok":true})).into_response());
        }
        "session" => {
            return Ok(Json(authenticated_session(
                auth.session(cookie(headers)?, now).await?,
            ))
            .into_response());
        }
        "recovery-start" | "recovery-resume" => {
            let b: Recovery = body(value)?;
            super::crypto::valid_secret(&b.verifier)?;
            let credential = super::recovery::RecoveryCredential::Verifier(b.verifier);
            let user = match (b.user_id, b.username) {
                (Some(user), None) => user,
                (None, Some(username)) => {
                    sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE username=?")
                        .bind(username)
                        .fetch_optional(&auth.pool)
                        .await?
                        .unwrap_or_default()
                }
                _ => return Err(Error::Invalid),
            };
            let (token, ready, delay) = auth
                .recovery_start_clock(
                    &user,
                    credential,
                    cookie(headers).ok(),
                    || current_time(auth),
                    action != "recovery-start",
                )
                .await?;
            json!({"token":token,"delay_seconds":delay,"ready_at":ready})
        }
        "recovery-rotate" => {
            let b: RecoveryRotation = body(value)?;
            let user = headers
                .get("x-infraternal-user")
                .and_then(|value| value.to_str().ok())
                .ok_or(Error::Denied)?;
            auth.recovery_rotate_clock(
                cookie(headers)?,
                user,
                b.recovery_wrap,
                b.recovery_verifier,
                || current_time(auth),
            )
            .await?;
            json!({"ok":true})
        }
        "recovery-status" => {
            let b: Token = body(value)?;
            auth.recovery_status(&b.token, now).await?
        }
        "recovery-ready" => {
            let b: Token = body(value)?;
            auth.recovery_ready(&b.token, now).await?
        }
        "recovery-cancel" => {
            auth.recovery_cancel(cookie(headers)?, now).await?;
            json!({"ok":true})
        }
        "device-start" => {
            let b: DeviceStart = body(value)?;
            match (b.kind.as_deref(), b.scopes, b.request) {
                (None | Some("sign_in"), Some(scopes), None) => {
                    auth.device_start(&b.device, scopes, source, now).await?
                }
                (Some("join_machine"), None, Some(request)) => {
                    auth.device_join_start(&b.device, request, source, now)
                        .await?
                }
                _ => return Err(Error::Invalid),
            }
        }
        "device-inspect" => {
            let b: Code = body(value)?;
            auth.device_inspect(cookie(headers)?, &b.code, now).await?
        }
        // Every approval (CLI sign-in, machine join) is a passkey ceremony bound to its code.
        "device-approve-start" => {
            let b: Code = body(value)?;
            auth.device_approve_start(cookie(headers)?, &b.code, now)
                .await?
        }
        "device-approve-finish" => {
            let b: ApproveJoin = body(value)?;
            auth.device_approve_finish(cookie(headers)?, &b.code, &b.ceremony, b.proof, now)
                .await?;
            json!({"ok":true})
        }
        "device-redeem" => {
            let b: Token = body(value)?;
            #[cfg(feature = "remote")]
            if auth.device_join_approved(&b.token, now).await? {
                let approval = auth.approved_device_join(&b.token, now).await?;
                let issuer = invitation_issuer.ok_or(Error::RemoteUnavailable)?;
                let invitation = issuer
                    .issue_approved_machine_join(&b.token, approval, now)
                    .await
                    .map_err(|status| match status {
                        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Error::Denied,
                        StatusCode::BAD_REQUEST => Error::Invalid,
                        _ => Error::RemoteUnavailable,
                    })?;
                return Ok(Json(invitation).into_response());
            }
            json!({"api_key":auth.device_redeem(&b.token, now).await?})
        }
        "security-settings" => {
            let _: Empty = body(value)?;
            auth.security_settings(cookie(headers)?, now).await?
        }
        "security-settings-update" => {
            let b: super::security_settings::SecuritySettings = body(value)?;
            auth.update_security_settings(cookie(headers)?, b, now)
                .await?
        }
        "api-list" => auth.api_list(cookie(headers)?, now).await?,
        "api-revoke" => {
            let b: Revoke = body(value)?;
            auth.api_revoke(cookie(headers)?, &b.id, now).await?;
            json!({"ok":true})
        }
        "logout" => {
            let b: Logout = body(value)?;
            if let Some(transaction) = b.pending_transaction {
                auth.logout_pending(cookie(headers)?, &transaction).await?;
                // A delayed cleanup reply must not clear a later login's cookie.
                return Ok(Json(json!({"ok":true})).into_response());
            }
            auth.logout(cookie(headers)?).await?;
            return Ok(Json(json!({"ok":true})).into_response());
        }
        _ => return Err(Error::Invalid),
    };
    ceremony_response(auth, action, headers, payload).await
}

/// Attach browser transaction state only to successful ceremony starts.
async fn ceremony_response(
    auth: &Auth,
    action: &str,
    headers: &HeaderMap,
    payload: Value,
) -> super::Result<Response> {
    let binding = if matches!(
        action,
        "setup-start" | "login-start" | "add-start" | "recovery-ready"
    ) {
        Some(
            auth.bind_ceremony(payload["ceremony"].as_str().ok_or(Error::Invalid)?, headers)
                .await?,
        )
    } else {
        None
    };
    let mut response = Json(payload).into_response();
    if let Some(binding) = binding {
        response.headers_mut().insert(header::SET_COOKIE, binding);
    }
    Ok(response)
}

/// The identified path is an authenticated fresh tap, never a public directory.
async fn login_start(
    auth: &Auth,
    headers: &HeaderMap,
    source: IpAddr,
    value: Value,
    now: i64,
) -> super::Result<Value> {
    let b: User = body(value)?;
    match b.user_id {
        Some(user) => {
            if auth.session(cookie(headers)?, now).await?.user_id != user {
                return Err(Error::Denied);
            }
            auth.login_start(&user, now).await
        }
        None => auth.discoverable_login_start_from(now, Some(source)).await,
    }
}

/// Accept the legacy label form or the additive username/display-name form.
async fn setup_start(auth: &Auth, value: Value, now: i64) -> super::Result<Value> {
    let b: Setup = body(value)?;
    match (b.name, b.username, b.display_name) {
        (Some(name), None, None) => auth.setup_start(&b.token, &name, now).await,
        (None, Some(username), display_name) => {
            auth.setup_start_with_identity(&b.token, &username, display_name.as_deref(), now)
                .await
        }
        _ => Err(Error::Invalid),
    }
}

async fn ingress(
    auth: &Auth,
    action: &str,
    headers: &HeaderMap,
    source: IpAddr,
    now: i64,
) -> super::Result<()> {
    // CLI approval polling uses its own bearer capability, never a browser cookie.
    if !matches!(action, "device-start" | "device-redeem")
        && headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(auth.origin())
    {
        return Err(Error::Denied);
    }
    // Revocation remains available when public request capacity is exhausted.
    if action == "logout" {
        return Ok(());
    }
    // Public device-code requests share no process-wide bucket: any caller could
    // spend it and refuse every other `up` and sign-in (#263, J122 P2). They are
    // limited per source network by the runtime's source admission, and the
    // state they create is bounded by the pending-approval caps instead.
    if matches!(action, "device-start" | "device-redeem") {
        return Ok(());
    }
    // Browser actions are budgeted per enclosing network (IPv6 /48, IPv4
    // /24), so callers from a few networks can spend only their own share and
    // never refuse a sign-in from anywhere else (#263, J145 P2-1). There is
    // no process-wide counter: any such ceiling is the same lockout at N
    // networks, and distributed floods are the reverse proxy's job (#76913).
    // IP/proxy headers are never trusted here; `source` is the runtime's.
    if crate::runtime::admit_temporal_request(
        &mut auth.ingress.lock().await.networks,
        crate::runtime::browser_network(source),
        now,
        BROWSER_PER_MINUTE,
    )
    .is_ok()
    {
        return Ok(());
    }
    // Once a network has spent its budget, a live signed-in session there
    // still gets its own per-person budget, so a flood cannot stop the owner
    // from reviewing and approving an `up` (#263, J134 P2-1). The session is
    // looked up only on this exhausted path; an invalid cookie stays throttled.
    let Ok(token) = cookie(headers) else {
        return Err(Error::Throttled);
    };
    let user = auth
        .session(token, now)
        .await
        .map_err(|_| Error::Throttled)?
        .user_id;
    let mut budget = auth.ingress.lock().await;
    crate::runtime::admit_temporal_request(&mut budget.people, user, now, BROWSER_PER_MINUTE)
        .map_err(|_| Error::Throttled)
}

/// Browser requests per minute for each enclosing network, and each person's
/// budget after that. 120 is the old server-wide figure, so no single network
/// gets less than every caller used to share.
const BROWSER_PER_MINUTE: u8 = 120;

/// Browser admission budgets; every browser action counts, including
/// authenticated reads. `networks` is keyed by enclosing network, `people` by
/// the user ID of a live session that falls back once its network is spent.
/// Both maps evict their oldest window when full.
#[derive(Default)]
pub(super) struct Ingress {
    networks: std::collections::HashMap<IpAddr, crate::runtime::SourceBucket>,
    people: std::collections::HashMap<String, crate::runtime::SourceBucket>,
}

/// Keep the unauthenticated response limited to first-run state and its local command.
async fn public_status(auth: &Auth, value: Value) -> super::Result<Value> {
    let _: Empty = body(value)?;
    let required: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM users WHERE owner=1)")
        .fetch_one(&auth.pool)
        .await?;
    Ok(json!({
        "setup_required":required,
        "setup_token_command":auth.setup_token_command(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admission_partitions_reset_without_trusting_forwarded_headers() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let auth = Auth::new(pool, "auth.example.test", "https://auth.example.test")
            .await
            .unwrap();
        let now = 1_800_000_000;
        let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example.test"),
        );
        headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        assert!(matches!(
            ingress(&auth, "login-start", &headers, source, now).await,
            Err(Error::Denied)
        ));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://auth.example.test"),
        );
        for _ in 0..120 {
            ingress(&auth, "session", &headers, source, now)
                .await
                .unwrap();
        }
        assert!(matches!(
            ingress(&auth, "login-start", &headers, source, now).await,
            Err(Error::Throttled)
        ));
        // Device-code requests skip the shared browser partition, and have no
        // process-wide partition of their own (per-source limits live in runtime).
        for _ in 0..1000 {
            ingress(&auth, "device-redeem", &HeaderMap::new(), source, now)
                .await
                .unwrap();
        }
        ingress(&auth, "device-start", &HeaderMap::new(), source, now)
            .await
            .unwrap();
        ingress(&auth, "login-start", &headers, source, now + 60)
            .await
            .unwrap();
    }
}
