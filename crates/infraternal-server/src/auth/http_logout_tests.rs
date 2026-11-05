//! Logout cookie-race regressions for the HTTP adapter.
use super::super::{Auth, hash};
use super::{execute, refresh_session_cookie};
use axum::http::{HeaderMap, HeaderValue, header};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;

/// The test server's public origin.
const ORIGIN: &str = "https://auth.example.test";
/// A fixed test time, so expiries are deterministic.
const NOW: i64 = 1_800_000_000;
/// The 30-day sliding session lifetime.
const SESSION: i64 = 30 * 86_400;

/// Call the HTTP adapter as a browser on loopback would, without an invitation issuer.
async fn run(
    auth: &Auth,
    action: &str,
    headers: &HeaderMap,
) -> super::super::Result<axum::response::Response> {
    execute(
        auth,
        #[cfg(feature = "remote")]
        None,
        action,
        headers,
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        json!({}),
    )
    .await
}

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
    let delayed_response = run(&auth, "session", &older_headers).await.unwrap();
    let logout_response = run(&auth, "logout", &logout_headers).await.unwrap();
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

/// Logout revokes every presented bearer even when two cookies share the newest ordering key.
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

    run(&auth, "logout", &headers).await.unwrap();

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

/// Logout needs no live session, so the bearers it deletes are capped: a request
/// carrying more than a browser can hold is refused before any database work.
#[tokio::test]
async fn logout_refuses_more_presented_sessions_than_the_cap_without_deleting_any() {
    use super::super::cookies::MAX_LOGOUT_SESSIONS;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    auth.set_test_http_time(NOW);

    let user = "logout-cookie-cap";
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'owner',1,'unused','owner','Owner')")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
    let live = "L".repeat(43);
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,login_sequence,unlocked) VALUES (?,?, 'test-device', ?, ?, 1, 1)")
        .bind(hash(&live))
        .bind(user)
        .bind(NOW + SESSION)
        .bind(NOW)
        .execute(&pool)
        .await
        .unwrap();
    // The live bearer plus `extra` made-up ones, each under its own generation name.
    let headers = |extra: usize| {
        let mut cookies = vec![format!(
            "__Host-infraternal-session-1-{}={live}",
            NOW + SESSION
        )];
        for index in 0..extra {
            cookies.push(format!(
                "__Host-infraternal-session-{}-{}={:0>43}",
                index + 2,
                NOW + SESSION,
                index
            ));
        }
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
        headers.insert(header::COOKIE, cookies.join("; ").parse().unwrap());
        headers
    };
    let live_rows = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sessions WHERE token_hash=?")
            .bind(hash(&live))
            .fetch_one(&pool)
            .await
            .unwrap()
    };

    let refused = run(&auth, "logout", &headers(MAX_LOGOUT_SESSIONS)).await;
    assert!(
        matches!(refused, Err(super::super::Error::Invalid)),
        "more bearers than the cap must be refused"
    );
    assert_eq!(live_rows().await, 1, "a refused logout must delete nothing");

    run(&auth, "logout", &headers(MAX_LOGOUT_SESSIONS - 1))
        .await
        .unwrap();
    assert_eq!(
        live_rows().await,
        0,
        "a logout at the cap revokes every bearer"
    );
}

/// Logging out of the selected account must not revoke another account's cookie from the same browser.
#[tokio::test]
async fn logout_does_not_revoke_a_presented_session_for_another_user() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    auth.set_test_http_time(NOW);

    for (user, owner, name) in [("current-user", 1, "Current"), ("other-user", 0, "Other")] {
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,?,?,'unused',?,?)")
            .bind(user)
            .bind(name)
            .bind(owner)
            .bind(user)
            .bind(name)
            .execute(&pool)
            .await
            .unwrap();
    }

    let current = "c".repeat(43);
    let other = "o".repeat(43);
    for (token, user, sequence) in [
        (&current, "current-user", 2_i64),
        (&other, "other-user", 1_i64),
    ] {
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

    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    headers.insert(
        header::COOKIE,
        format!(
            "__Host-infraternal-session-2-{}={current}; __Host-infraternal-session-1-{}={other}",
            NOW + SESSION,
            NOW + SESSION
        )
        .parse()
        .unwrap(),
    );
    run(&auth, "logout", &headers).await.unwrap();

    let current_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash=?")
        .bind(hash(&current))
        .fetch_one(&pool)
        .await
        .unwrap();
    let other_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash=?")
        .bind(hash(&other))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        current_rows, 0,
        "logout revokes the selected account's session"
    );
    assert_eq!(
        other_rows, 1,
        "logout must leave another user's session row untouched"
    );
}

/// With no single selected session, bearers of two accounts leave no one account to log out:
/// the request is refused and neither session ends.
#[tokio::test]
async fn ambiguous_logout_across_accounts_is_refused_without_deleting_either() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    auth.set_test_http_time(NOW);
    let first = "f".repeat(43);
    let second = "s".repeat(43);
    for (user, owner, token) in [("first-user", 1, &first), ("second-user", 0, &second)] {
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,?,?,'unused',?,?)")
            .bind(user)
            .bind(user)
            .bind(owner)
            .bind(user)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,login_sequence,unlocked) VALUES (?,?, 'test-device', ?, ?, 1, 1)")
            .bind(hash(token))
            .bind(user)
            .bind(NOW + SESSION)
            .bind(NOW)
            .execute(&pool)
            .await
            .unwrap();
    }
    // The same ordering key twice: no cookie is selected.
    let name = format!("__Host-infraternal-session-1-{}", NOW + SESSION);
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    headers.insert(
        header::COOKIE,
        format!("{name}={first}; {name}={second}").parse().unwrap(),
    );

    let refused = run(&auth, "logout", &headers).await;
    assert!(
        matches!(refused, Err(super::super::Error::Denied)),
        "bearers of two accounts name no account to log out"
    );
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash IN (?, ?)")
            .bind(hash(&first))
            .bind(hash(&second))
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, 2, "a refused logout deletes neither session");
}
