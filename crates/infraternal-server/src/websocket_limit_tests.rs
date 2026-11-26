//! The per-account connection limit's two forms, which admission errors count as reaching it (#523), the
//! per-account share of the global resume-row cap (#572), and which refused resumes may start fresh on the same
//! socket (#569).
use super::*;

/// A refused terminal's follow-up frames leave other streams alone. The socket
/// tracks at most 128 retired IDs and reclaims each place on the browser's Close.
#[test]
fn retired_streams_are_bounded_at_socket_capacity() {
    let mut ended = EndedStreams::default();
    for stream in (1..=255).step_by(2) {
        ended.insert(stream).unwrap();
    }
    assert!(ended.insert(257).is_err());
    assert!(ended.absorbs(1, &Frame::Credit { bytes: 16 }).unwrap());
    assert!(!ended.absorbs(257, &Frame::Credit { bytes: 16 }).unwrap());
    assert!(
        ended
            .absorbs(1, &Frame::Close { code: 1000, reason: "" })
            .unwrap()
    );
    ended.insert(257).unwrap();
}

/// The upgrade permit and the row check enforce one limit.
#[test]
fn connection_limit_constants_agree() {
    assert_eq!(
        i64::try_from(MAX_USER_CONNECTIONS).unwrap(),
        MAX_USER_CONNECTION_ROWS
    );
}

/// Only the two limit refusals name the limit; storage and authority failures stay generic.
#[test]
fn only_limit_refusals_count_as_the_limit() {
    assert!(is_connection_limit(&sqlx::Error::Protocol(
        CONNECTION_LIMIT_ERROR.into()
    )));
    assert!(is_connection_limit(&resume_refused(RESUME_CAPACITY_CHECK)));
    assert!(!is_connection_limit(&resume_refused("token_mismatch")));
    assert!(!is_connection_limit(&sqlx::Error::PoolTimedOut));
}

/// A stale resume starts fresh on the same socket (#569); the account's limit, an ended cookie session and storage
/// errors never do. The limit must stay a refusal so the browser keeps its still-valid capability (#523).
#[test]
fn only_stale_resume_refusals_start_fresh() {
    for check in STALE_RESUME_CHECKS {
        assert!(is_stale_resume(&resume_refused(check)), "{check}");
        assert!(!is_connection_limit(&resume_refused(check)), "{check}");
    }
    assert!(!is_stale_resume(&resume_refused(RESUME_CAPACITY_CHECK)));
    assert!(!is_stale_resume(&sqlx::Error::Protocol(
        CONNECTION_LIMIT_ERROR.into()
    )));
    assert!(!is_stale_resume(&sqlx::Error::Protocol(
        "session authority ended".into()
    )));
    assert!(!is_stale_resume(&sqlx::Error::PoolTimedOut));
}

/// An in-memory database with the auth schema and two accounts, `a` and `b`.
async fn two_accounts() -> (SqlitePool, String, String) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let mut users = Vec::new();
    for name in ["a", "b"] {
        let user = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES (?,?,?,?,0,'unused-test-hash')")
            .bind(&user).bind(name).bind(name).bind(name).execute(&pool).await.unwrap();
        users.push(user);
    }
    let b = users.pop().unwrap();
    let a = users.pop().unwrap();
    (pool, a, b)
}

/// #572 finding 4: one account that connects and drops [`MAX_RESUME_ROWS`] times inside the resume window keeps
/// only its own newest resumable rows, so another account can still open a socket. Before the fix every drop
/// kept a row and the second account was refused with "resume capacity reached".
#[tokio::test]
async fn one_accounts_churn_cannot_fill_the_global_resume_cap() {
    let (pool, a, b) = two_accounts().await;
    let now = 1_000;
    let mut last = None;
    for _ in 0..MAX_RESUME_ROWS {
        let welcome = new_connection(&pool, &a, now, None, None).await.unwrap();
        // The disconnect path's own update: the row stays resumable for the window.
        sqlx::query(
            "UPDATE websocket_connections SET active=0, expires_at=? WHERE connection_id=?",
        )
        .bind(now + i64::from(RESUME_WINDOW_SECONDS))
        .bind(welcome.connection_id.as_slice())
        .execute(&pool)
        .await
        .unwrap();
        last = Some(welcome.connection_id);
    }
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM websocket_connections WHERE user_id=?")
            .bind(&a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        retained <= MAX_USER_RESUME_ROWS,
        "account kept {retained} resume rows"
    );
    let newest: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM websocket_connections WHERE connection_id=? AND active=0",
    )
    .bind(last.unwrap().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(newest, 1, "eviction must keep the newest resumable row");
    new_connection(&pool, &b, now, None, None)
        .await
        .expect("a second account must still connect");
}

/// The global cap still refuses new sockets once many accounts together retain [`MAX_RESUME_ROWS`] rows.
#[tokio::test]
async fn global_resume_cap_remains_the_backstop() {
    let (pool, a, b) = two_accounts().await;
    let now = 1_000;
    // Rows of many other accounts, inserted directly: each stays under its own cap.
    for other in 0..MAX_RESUME_ROWS / MAX_USER_RESUME_ROWS {
        let user = format!("other-{other}");
        sqlx::query("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES (?,?,?,?,0,'unused-test-hash')")
            .bind(&user).bind(&user).bind(&user).bind(&user).execute(&pool).await.unwrap();
    }
    for index in 0..MAX_RESUME_ROWS {
        let user = format!("other-{}", index / MAX_USER_RESUME_ROWS);
        let id = uuid::Uuid::from_u128(u128::try_from(index).unwrap() + 1);
        sqlx::query("INSERT INTO websocket_connections(connection_id,token_hash,user_id,created_at,expires_at,active) VALUES (?,?,?,?,?,0)")
            .bind(id.as_bytes().as_slice())
            .bind([0_u8; 32].as_slice())
            .bind(user)
            .bind(now)
            .bind(now + 60)
            .execute(&pool)
            .await
            .unwrap();
    }
    assert!(new_connection(&pool, &a, now, None, None).await.is_err());
    assert!(new_connection(&pool, &b, now, None, None).await.is_err());
}
