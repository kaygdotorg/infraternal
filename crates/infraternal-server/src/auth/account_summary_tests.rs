//! Account setup facts stay session-scoped and contain no secret-bearing fields (#224).
use super::super::{Auth, hash};
use super::router;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tower::ServiceExt;

const NOW: i64 = 1_800_000_000;
const ORIGIN: &str = "https://auth.example.test";

fn session_token(user: &str) -> String {
    format!("{user:_<43}")
}

async fn fixture() -> (Auth, SqlitePool) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    auth.set_test_http_time(NOW);
    for (user, owner) in [("one", 1), ("two", 0)] {
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,?,?,'private-recovery-verifier',?,?)")
            .bind(user).bind(user).bind(owner).bind(user).bind(user).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh) VALUES (?,?,'browser',?,?)")
            .bind(hash(&session_token(user))).bind(user).bind(NOW+100).bind(NOW).execute(&pool).await.unwrap();
    }
    for (key, user) in [("first", "one"), ("second", "two"), ("third", "two")] {
        sqlx::query(
            "INSERT INTO passkeys(id,user_id,credential) VALUES (?,?,'private-credential')",
        )
        .bind(key)
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO wraps(user_id,kind,key_id,blob) VALUES ('one','recovery','recovery','private-ciphertext')")
        .execute(&pool).await.unwrap();
    (auth, pool)
}

async fn request(
    auth: &Auth,
    token: Option<&str>,
    origin: &str,
    body: &str,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/auth/account-summary")
        .header("Origin", origin)
        .header("Content-Type", "application/json");
    if let Some(token) = token {
        request = request.header(
            "Cookie",
            format!("__Host-infraternal={}", session_token(token)),
        );
    }
    let response = router(auth.clone())
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn summary_counts_only_the_session_account_and_has_an_exact_nonsecret_shape() {
    let (auth, pool) = fixture().await;
    for (user, count, recovery) in [("one", 1, true), ("two", 2, false)] {
        let (status, payload) = request(&auth, Some(user), ORIGIN, "{}").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            payload,
            json!({"user_id":user,"session_incarnation":super::super::session_incarnation(&session_token(user)),"passkeys":count,"recovery_set_up":recovery})
        );
    }
    sqlx::query("DELETE FROM passkeys WHERE user_id='one'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET recovery_hash='' WHERE id='one'")
        .execute(&pool)
        .await
        .unwrap();
    let (_, payload) = request(&auth, Some("one"), ORIGIN, "{}").await;
    assert_eq!(payload["passkeys"], 0);
    assert_eq!(payload["recovery_set_up"], false);
}

#[tokio::test]
async fn summary_requires_current_unlocked_same_origin_authority() {
    let (auth, pool) = fixture().await;
    for token in [None, Some("unknown")] {
        assert_eq!(
            request(&auth, token, ORIGIN, "{}").await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        request(&auth, Some("one"), "https://elsewhere.test", "{}")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&auth, Some("one"), ORIGIN, "{\"user_id\":\"two\"}")
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    for clause in ["unlocked=0", "unlocked=1,expires=1800000000"] {
        sqlx::query(&format!("UPDATE sessions SET {clause} WHERE user_id='one'"))
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            request(&auth, Some("one"), ORIGIN, "{}").await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    auth.logout(&session_token("two")).await.unwrap();
    assert_eq!(
        request(&auth, Some("two"), ORIGIN, "{}").await.0,
        StatusCode::UNAUTHORIZED
    );
}
