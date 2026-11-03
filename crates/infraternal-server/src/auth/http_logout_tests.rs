//! Logout cookie-race regressions for the HTTP adapter.
use super::super::{Auth, hash};
use super::{execute, refresh_session_cookie};
use axum::http::{HeaderMap, HeaderValue, header};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;

const ORIGIN: &str = "https://auth.example.test";
const NOW: i64 = 1_800_000_000;
const SESSION: i64 = 30 * 86_400;

/// A successful response prepared before logout must not restore its ended cookie afterward.
#[tokio::test]
async fn logout_ends_all_referenced_sessions_before_delayed_responses_refresh_cookies() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    auth.set_test_http_time(NOW);

    let user = "logout-cookie-race";
    let older = "o".repeat(43);
    let newer = "n".repeat(43);
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'owner',1,'unused','owner','Owner')")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    for (token, sequence) in [(&older, 1_i64), (&newer, 2_i64)] {
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,login_sequence,unlocked) VALUES (?,?, 'test-device', ?, ?, ?, 1)")
            .bind(hash(token))
            .bind(user)
            .bind(NOW + SESSION)
            .bind(NOW)
            .bind(sequence)
            .execute(&pool)
            .await
            .unwrap();
    }

    let older_name = format!("__Host-infraternal-session-1-{}", NOW + SESSION);
    let newer_name = format!("__Host-infraternal-session-2-{}", NOW + SESSION);
    let mut older_headers = HeaderMap::new();
    older_headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    older_headers.insert(
        header::COOKIE,
        format!("{older_name}={older}").parse().unwrap(),
    );
    let mut logout_headers = HeaderMap::new();
    logout_headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    logout_headers.insert(
        header::COOKIE,
        format!("{older_name}={older}; {newer_name}={newer}")
            .parse()
            .unwrap(),
    );

    // The first request has completed its authenticated action but has not yet
    // crossed the final response-cookie refresh boundary.
    let delayed_response = execute(&auth, "session", &older_headers, json!({}))
        .await
        .unwrap();
    let logout_response = execute(&auth, "logout", &logout_headers, json!({}))
        .await
        .unwrap();
    let _logout_response =
        refresh_session_cookie(&auth, "logout", &logout_headers, logout_response).await;

    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash IN (?, ?)")
            .bind(hash(&older))
            .bind(hash(&newer))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 0, "logout must end every cookie it was given");

    let delayed_response =
        refresh_session_cookie(&auth, "session", &older_headers, delayed_response).await;
    for value in delayed_response.headers().get_all(header::SET_COOKIE) {
        let value = value.to_str().unwrap();
        assert!(
            !value.contains(&older),
            "a response after logout must not set an ended session cookie: {value}"
        );
        assert!(
            value.starts_with(&format!("{older_name}=")) && value.contains("Max-Age=0"),
            "ended cookie may only be retired: {value}"
        );
    }
}

#[tokio::test]
async fn logout_revokes_every_presented_session_when_cookie_selection_is_ambiguous() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    auth.set_test_http_time(NOW);

    let user = "logout-ambiguous-cookies";
    let older = "a".repeat(43);
    let newer = "b".repeat(43);
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'owner',1,'unused','owner','Owner')")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    for (token, sequence) in [(&older, 1_i64), (&newer, 2_i64)] {
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,login_sequence,unlocked) VALUES (?,?, 'test-device', ?, ?, ?, 1)")
            .bind(hash(token))
            .bind(user)
            .bind(NOW + SESSION)
            .bind(NOW)
            .bind(sequence)
            .execute(&pool)
            .await
            .unwrap();
    }

    // Duplicate ordering keys make normal authentication selection ambiguous, but logout can
    // still safely revoke each bearer because it receives the tokens explicitly.
    let name = format!("__Host-infraternal-session-1-{}", NOW + SESSION);
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    headers.insert(
        header::COOKIE,
        format!("{name}={older}; {name}={newer}").parse().unwrap(),
    );

    execute(&auth, "logout", &headers, json!({})).await.unwrap();

    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash IN (?, ?)")
            .bind(hash(&older))
            .bind(hash(&newer))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        remaining, 0,
        "logout must revoke every presented session bearer"
    );
}
