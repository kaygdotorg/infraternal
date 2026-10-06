//! Checks the authenticated session response reports the server's actual hostname.
use super::super::{Auth, hash};
use super::router;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::sqlite::SqlitePoolOptions;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

const ORIGIN: &str = "https://auth.example.test";
const SESSION_SECONDS: i64 = 30 * 86_400;

#[tokio::test]
async fn authenticated_session_response_includes_system_hostname() {
    let pool = SqlitePoolOptions::new()
        .test_before_acquire(false)
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    let user_id = "hostname-test-user";
    let token = "s".repeat(43);
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();

    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'owner',1,'unused','owner','Owner')")
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh) VALUES (?,?,'test-device',?,?)")
        .bind(hash(&token))
        .bind(user_id)
        .bind(now + SESSION_SECONDS)
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();

    let response = router(auth)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/session")
                .header("Origin", ORIGIN)
                .header("Cookie", format!("__Host-infraternal={token}"))
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    let expected = nix::unistd::gethostname()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(payload["hostname"].as_str(), Some(expected.as_str()));
}
