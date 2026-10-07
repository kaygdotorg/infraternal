//! Pipe-only real HTTP router fixture for browser `WebAuthn` tests; binds no network port.
//! Capabilities travel only over the parent's private IPC pipe, never diagnostic logs.
use axum::{
    body::{Body, to_bytes},
    http::{Request, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use infraternal_server::auth::{Auth, router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, Write};
use tower::ServiceExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    let mut token = String::new();
    auth.bootstrap(now, |banner| {
        banner
            .lines()
            .nth(1)
            .unwrap_or_default()
            .clone_into(&mut token);
    })
    .await?;
    let app = router(auth);
    let legacy = std::env::var("AUTH_TEST_PRF_VERSION")
        .ok()
        .filter(|version| matches!(version.as_str(), "v1" | "v2"));
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{}", json!({"setup_token":token}))?;
    output.flush()?;
    for line in io::stdin().lock().lines() {
        let message: Value = serde_json::from_str(&line?)?;
        let mut request = Request::builder()
            .method("POST")
            .uri(message["path"].as_str().ok_or("missing path")?)
            .header(header::CONTENT_TYPE, "application/json");
        for name in ["origin", "cookie"] {
            if let Some(value) = message["headers"][name].as_str() {
                request = request.header(name, value);
            }
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::from(serde_json::to_vec(&message["body"])?))?)
            .await?;
        let status = response.status().as_u16();
        let headers: Vec<_> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap_or_default()))
            .collect();
        let headers = serde_json::to_value(headers)?;
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        // The IPC envelope is JSON even when HTTP deliberately has no response body.
        // Keep 204 intact so the production browser exercises its normal empty-success path.
        let mut body: Value = if status == 204 && body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)?
        };
        if status == 200
            && let Some(version) = legacy.as_deref()
        {
            legacy_input(
                &pool,
                message["path"].as_str().unwrap_or_default(),
                version,
                &mut body,
            )
            .await?;
        }
        writeln!(
            output,
            "{}",
            json!({"status":status,"headers":headers,"body":body})
        )?;
        output.flush()?;
    }
    Ok(())
}

/// Emulate an actual legacy enrollment envelope without changing production auth or ciphertext.
async fn legacy_input(
    pool: &sqlx::SqlitePool,
    path: &str,
    version: &str,
    body: &mut Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let user = if path == "/auth/setup-start" {
        body["user_id"]
            .as_str()
            .ok_or("missing enrollment user")?
            .to_owned()
    } else if path == "/auth/registration-finish" {
        sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE owner=1")
            .fetch_one(pool)
            .await?
    } else {
        return Ok(());
    };
    let context = if version == "v1" {
        "infraternal/keywrap/prf/v1".to_owned()
    } else {
        format!("infraternal/keywrap/prf/v2|{user}")
    };
    let input = B64.encode(Sha256::digest(context.as_bytes()));
    if path == "/auth/setup-start" {
        body["options"]["publicKey"]["extensions"]["prf"]["eval"]["first"] = json!(input);
    } else {
        sqlx::query("UPDATE passkeys SET prf_input=?")
            .bind(if version == "v1" { None } else { Some(input) })
            .execute(pool)
            .await?;
    }
    Ok(())
}
