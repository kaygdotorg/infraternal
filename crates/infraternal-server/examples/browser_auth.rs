//! Pipe-only real HTTP router fixture for browser `WebAuthn` tests; binds no network port.
//! Capabilities travel only over the parent's private IPC pipe, never diagnostic logs.
use axum::{
    body::{Body, to_bytes},
    http::{Request, header},
};
use infraternal_server::auth::{Auth, router};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use tower::ServiceExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    let auth = Auth::new(pool, "auth.example.test", "https://auth.example.test").await?;
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
        writeln!(
            output,
            "{}",
            json!({"status":status,"headers":headers,"body":serde_json::from_slice::<Value>(&body)?})
        )?;
        output.flush()?;
    }
    Ok(())
}
