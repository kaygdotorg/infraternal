//! Same-origin HTTP adapter. Cookies are capabilities; mutation requests require the pinned Origin.
use super::{Auth, Error, Wrap};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
#[path = "account_summary_tests.rs"]
mod account_summary_tests;
#[cfg(test)]
#[path = "http_hostname_tests.rs"]
mod hostname_tests;

/// Mount the POST-only `/auth/{action}` API. TLS terminates at the configured public origin.
pub fn router(auth: Auth) -> Router {
    Router::new()
        .route("/auth/{action}", post(dispatch))
        .layer(DefaultBodyLimit::max(32 * 1024))
        .layer(axum::middleware::map_response(no_store))
        .with_state(auth)
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
    /// The one per-action change this tap is for (`action_tap`, D336). Absent: a plain sign-in.
    action: Option<super::TapAction>,
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
    scopes: Vec<String>,
    /// Requested key lifetime in seconds; the server default applies when absent (D333).
    #[serde(default)]
    lifetime_seconds: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    id: String,
}

pub(crate) fn cookie(headers: &HeaderMap) -> super::Result<&str> {
    super::cookies::capability(headers, "__Host-infraternal=").ok_or(Error::Denied)
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

fn session_cookie(token: &str) -> super::Result<HeaderValue> {
    HeaderValue::from_str(&format!(
        "__Host-infraternal={token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000"
    ))
    .map_err(|_| Error::Invalid)
}
fn session_response(token: &str) -> super::Result<Response> {
    let mut response = Json(json!({"ok":true})).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(token)?);
    Ok(response)
}
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn dispatch(
    State(auth): State<Auth>,
    Path(action): Path<String>,
    headers: HeaderMap,
    Json(value): Json<Value>,
) -> Response {
    let result = execute(&auth, &action, &headers, value).await;
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
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"auth unavailable"})),
        )
            .into_response(),
    };
    // Only explicit login/registration issuance writes the auth cookie. Delayed
    // authenticated replies cannot know which login the shared jar holds now.
    response
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
    action: &str,
    headers: &HeaderMap,
    value: Value,
) -> super::Result<Response> {
    let now = current_time(auth)?;
    ingress(auth, action, headers, now).await?;
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
            return session_response(
                &auth
                    .registration_finish_clock(
                        &b.ceremony,
                        b.proof,
                        b.passkey_wrap,
                        b.recovery_wrap,
                        b.recovery_verifier,
                        || current_time(auth),
                    )
                    .await?,
            );
        }
        "login-start" => login_start(auth, headers, value, now).await?,
        "login-finish" => {
            let b: Login = body(value)?;
            auth.require_ceremony_binding(&b.ceremony, headers).await?;
            let token = auth
                .pending_login_finish(&b.ceremony, b.proof, &b.device, now)
                .await?;
            let mut response = session_response(&token)?;
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
            auth.device_start_for(&b.device, b.scopes, b.lifetime_seconds, now)
                .await?
        }
        "device-inspect" => {
            let b: Code = body(value)?;
            auth.device_inspect(cookie(headers)?, &b.code, now).await?
        }
        "device-approve" => {
            let b: Code = body(value)?;
            auth.device_approve(cookie(headers)?, &b.code, now).await?;
            json!({"ok":true})
        }
        "device-redeem" => {
            let b: Token = body(value)?;
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
    value: Value,
    now: i64,
) -> super::Result<Value> {
    let b: User = body(value)?;
    let action = b.action.as_ref();
    match b.user_id {
        Some(user) => {
            if auth.session(cookie(headers)?, now).await?.user_id != user {
                return Err(Error::Denied);
            }
            auth.login_start_for(&user, action, now).await
        }
        None => auth.discoverable_login_start_for(action, now).await,
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

async fn ingress(auth: &Auth, action: &str, headers: &HeaderMap, now: i64) -> super::Result<()> {
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
    // Two fixed partitions keep the aggregate ceiling at 180/minute. No device
    // caller can spend the 120 browser slots; IP/proxy headers are never trusted.
    let mut budget = auth.ingress.lock().await;
    if now - budget.window >= 60 {
        *budget = Ingress {
            window: now,
            ..Ingress::default()
        };
    }
    let (used, limit) = if matches!(action, "device-start" | "device-redeem") {
        (&mut budget.devices, 60)
    } else {
        (&mut budget.browser, 120)
    };
    if *used >= limit {
        return Err(Error::Throttled);
    }
    *used += 1;
    Ok(())
}

/// Fixed-size admission partitions; all HTTP actions count, including authenticated reads.
#[derive(Default)]
pub(super) struct Ingress {
    window: i64,
    browser: u32,
    devices: u32,
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
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example.test"),
        );
        headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        assert!(matches!(
            ingress(&auth, "login-start", &headers, now).await,
            Err(Error::Denied)
        ));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://auth.example.test"),
        );
        for _ in 0..120 {
            ingress(&auth, "session", &headers, now).await.unwrap();
        }
        assert!(matches!(
            ingress(&auth, "login-start", &headers, now).await,
            Err(Error::Throttled)
        ));
        for _ in 0..60 {
            ingress(&auth, "device-redeem", &HeaderMap::new(), now)
                .await
                .unwrap();
        }
        assert!(matches!(
            ingress(&auth, "device-start", &HeaderMap::new(), now).await,
            Err(Error::Throttled)
        ));
        ingress(&auth, "login-start", &headers, now + 60)
            .await
            .unwrap();
        ingress(&auth, "device-redeem", &HeaderMap::new(), now + 60)
            .await
            .unwrap();
    }
}
