//! Runs the production bootstrap, multiplexed socket and renderer together; diagnostic authority stays on child stdin (#189).

use super::*;
use tokio::io::AsyncWriteExt;

/// Run the browser fixture against the production bootstrap and socket routes.
pub(super) async fn run(
    f: &Fixture,
    auth: Auth,
    runner: Bootstrap,
    http: axum::Router,
    tls: axum_server::tls_openssl::OpenSSLConfig,
    ip: std::net::IpAddr,
    target: &str,
) {
    let dist = PathBuf::from(std::env::var_os("ADDHOST_BROWSER_DIST").unwrap());
    let script = PathBuf::from(std::env::var_os("ADDHOST_BROWSER_SCRIPT").unwrap());
    let (socket, _peer) = tokio::net::UnixStream::pair().unwrap();
    let state = crate::websocket::WebSocketState::new_with_hosts(
        auth.clone(),
        f.pool.clone(),
        EmbeddedAgent::from_test_socket(socket),
        f.backend.hosts.clone(),
    )
    .await
    .unwrap();
    runner.session_notifications(state.session_notifications());
    let app = http
        .merge(crate::bootstrap_api::router(&auth, runner.clone()))
        .merge(crate::websocket::router(state))
        .fallback_service(crate::web_assets::router(dist));
    let server = tokio::spawn(
        axum_server::bind(std::net::SocketAddr::new(ip, 4929))
            .acceptor(enrollment_acceptor(tls))
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>()),
    );
    let mut child = tokio::process::Command::new(
        std::env::var_os("ADDHOST_BROWSER_RUNTIME").unwrap_or_else(|| "bun".into()),
    )
    .arg(script)
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::inherit())
    .stderr(std::process::Stdio::inherit())
    .kill_on_drop(true)
    .spawn()
    .unwrap();
    // Never expose the live owner cookie in argv, a file, or diagnostic output.
    let input = Secret::new(
        serde_json::to_vec(&serde_json::json!({"cookie": f.cookie, "target": target})).unwrap(),
    );
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.expose()).await.unwrap();
    drop(input);
    drop(stdin);
    let result = tokio::time::timeout(Duration::from_secs(220), child.wait())
        .await
        .unwrap()
        .unwrap();
    if !result.success() {
        // Only fixed schema/authority existence flags survive a refusal. A
        // cancelled single-connection in-memory acquisition may replace its
        // database; neither SQL errors nor session material belongs in logs.
        let schema_present = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='users'",
        )
        .fetch_one(&f.pool)
        .await
        .is_ok_and(|count| count == 1);
        let session_present =
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sessions WHERE token_hash=?")
                .bind(crate::auth::hash(&f.cookie))
                .fetch_one(&f.pool)
                .await
                .is_ok_and(|count| count == 1);
        eprintln!(
            "FIXTURE schema_users_present={schema_present} session_present={session_present}"
        );
    }
    server.abort();
    assert!(result.success(), "production-browser timeline failed");
}
