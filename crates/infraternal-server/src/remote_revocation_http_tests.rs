//! Checks owner revocation, cold-signer independence and transaction-time session permission through the real HTTP router [134][168], #78.

use super::*;

/// Poll the caller independently of SQLite's worker: cancellation can occur
/// after the worker commits but before the awaiting future is scheduled again.
#[tokio::test]
async fn abandoned_revocation_write_cannot_leave_committed_authority_live() {
    use sqlx::Connection;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let (_app, store, pool, host, token) = revocation_fixture().await;
    let guard = crate::remote_guard::AuthorityGuard::admit(store.clone(), [1; 32])
        .await
        .unwrap();
    let mut observer = sqlx::SqliteConnection::connect_with(&pool.connect_options())
        .await
        .unwrap();
    let hash = crate::auth::hash(&token);
    let mut write = Box::pin(store.revoke_for_session(&hash, host, now().unwrap()));
    let mut completed = false;
    for _ in 0..32 {
        let progress = write.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        if let Poll::Ready(result) = progress {
            result.unwrap();
            completed = true;
            break;
        }
        let visible = tokio::time::timeout(Duration::from_millis(50), async {
            loop {
                let row = sqlx::query_scalar::<_, bool>(
                    "SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?",
                )
                .bind(host.as_bytes().as_slice())
                .fetch_one(&mut observer)
                .await;
                if matches!(row, Ok(true)) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await;
        if visible.is_ok() {
            break;
        }
        // Yield only this observer; the revocation future has a noop waker and
        // remains suspended until explicitly polled above, like an abandoned HTTP request.
        tokio::task::yield_now().await;
    }
    drop(write);
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        completed || revoked,
        "fixture did not reach the commit boundary"
    );
    assert!(
        !revoked || !guard.permits(),
        "cancelled caller left a committed revocation active"
    );
}

async fn revocation_fixture() -> (Router, EnrollmentStore, SqlitePool, Uuid, String) {
    let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    let instant = now().unwrap();
    sqlx::query("UPDATE remote_certificates SET not_before=?, not_after=? WHERE fingerprint=?")
        .bind(instant)
        .bind(instant + 604_800)
        .bind([1u8; 32].as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = session(&pool).await;
    let material = crate::ca::tests::test_material();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
        material.issuer().clone(),
    ));
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: "127.0.0.1:7443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    (
        router_with_store(auth, pool.clone(), store.clone(), source, endpoint),
        store,
        pool,
        host,
        token,
    )
}

#[tokio::test]
async fn cold_signer_does_not_block_owner_revocation_or_cancellation() {
    let (app, store, _pool, host, token) = revocation_fixture().await;
    let guard = crate::remote_guard::AuthorityGuard::admit(store.clone(), [1; 32])
        .await
        .unwrap();
    let body = json!({"host_id":host});
    for (cookie, origin, expected) in [
        (None, "https://auth.example.test", StatusCode::UNAUTHORIZED),
        (
            Some(token.as_str()),
            "https://foreign.test",
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            request(&app, "/remote/revocations", body.clone(), cookie, origin)
                .await
                .status(),
            expected
        );
        assert!(guard.permits());
    }
    assert_eq!(
        request(
            &app,
            "/remote/revocations",
            json!({"host_id":host,"extra":true}),
            Some(&token),
            "https://auth.example.test"
        )
        .await
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert!(guard.permits());
    assert_eq!(
        request(
            &app,
            "/remote/revocations",
            body.clone(),
            Some(&token),
            "https://auth.example.test"
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
    assert!(!guard.permits(), "204 preceded cancellation publication");
    assert!(store.admit(&[1; 32], now().unwrap()).await.is_err());
    assert_eq!(
        request(
            &app,
            "/remote/revocations",
            body,
            Some(&token),
            "https://auth.example.test"
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn revocation_rechecks_locked_expired_logged_out_and_wrong_owner_sessions() {
    let (app, store, pool, host, token) = revocation_fixture().await;
    let guard = crate::remote_guard::AuthorityGuard::admit(store.clone(), [1; 32])
        .await
        .unwrap();
    let body = json!({"host_id":host});
    sqlx::query("UPDATE sessions SET unlocked=0")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            "/remote/revocations",
            body.clone(),
            Some(&token),
            "https://auth.example.test"
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE sessions SET unlocked=1, expires=0")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            "/remote/revocations",
            body.clone(),
            Some(&token),
            "https://auth.example.test"
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE sessions SET expires=?")
        .bind(now().unwrap() + 3600)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE users SET owner=0 WHERE id='owner'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            "/remote/revocations",
            body.clone(),
            Some(&token),
            "https://auth.example.test"
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE users SET owner=1 WHERE id='owner'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('other','Other',0,'test','other','Other')").execute(&pool).await.unwrap();
    sqlx::query("UPDATE remote_hosts SET owner_id='other'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            "/remote/revocations",
            body.clone(),
            Some(&token),
            "https://auth.example.test"
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    sqlx::query("UPDATE remote_hosts SET owner_id='owner'")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM sessions")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            "/remote/revocations",
            body,
            Some(&token),
            "https://auth.example.test"
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert!(guard.permits());
}

#[tokio::test]
async fn permission_revoked_while_waiting_for_sqlite_writer_refuses_tombstone() {
    let (app, store, pool, host, token) = revocation_fixture().await;
    let guard = crate::remote_guard::AuthorityGuard::admit(store.clone(), [1; 32])
        .await
        .unwrap();
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    let blocked = tokio::spawn(async move {
        request(
            &app,
            "/remote/revocations",
            json!({"host_id":host}),
            Some(&token),
            "https://auth.example.test",
        )
        .await
        .status()
    });
    // The one-connection fixture cannot execute the request's authority write
    // until this transaction releases its connection; revoke permission first.
    sqlx::query("UPDATE sessions SET unlocked=0")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    assert_eq!(blocked.await.unwrap(), StatusCode::FORBIDDEN);
    assert!(guard.permits());
}

/// Owner revocation is the security control that cuts a compromised host. It
/// must not share its admission slots with the unauthenticated join route:
/// eight anonymous clients holding stalled `/remote/join` bodies must not turn
/// an authorized revocation into 429 [134][168], #78.
#[tokio::test]
async fn claude_review_anonymous_stalled_joins_cannot_block_owner_revocation() {
    let (app, store, _pool, host, token) = revocation_fixture().await;
    let guard = crate::remote_guard::AuthorityGuard::admit(store.clone(), [1; 32])
        .await
        .unwrap();
    let mut stalled = tokio::task::JoinSet::new();
    let body_started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let body_ready = std::sync::Arc::new(tokio::sync::Notify::new());
    for source in 1..=8 {
        let started = body_started.clone();
        let ready = body_ready.clone();
        let mut first_poll = true;
        let request = Request::builder()
            .method("POST")
            .uri("/remote/join")
            .header("content-type", "application/json")
            .extension(crate::runtime::ClientAddress(std::net::IpAddr::V4(
                std::net::Ipv4Addr::new(192, 0, 2, source),
            )))
            .body(Body::from_stream(futures_util::stream::poll_fn(
                move |_| {
                    if std::mem::take(&mut first_poll)
                        && started.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 7
                    {
                        ready.notify_one();
                    }
                    std::task::Poll::Pending::<
                        Option<std::result::Result<bytes::Bytes, std::io::Error>>,
                    >
                },
            )))
            .unwrap();
        let app = app.clone();
        stalled.spawn(async move { app.oneshot(request).await });
    }
    // Distinct canonical sources bypass the per-source cap: observing each
    // body proves all eight global anonymous slots are held before revocation.
    tokio::time::timeout(std::time::Duration::from_secs(2), body_ready.notified())
        .await
        .expect("all distributed requests must hold anonymous body slots");
    assert_eq!(body_started.load(std::sync::atomic::Ordering::SeqCst), 8);
    let status = request(
        &app,
        "/remote/revocations",
        json!({"host_id":host}),
        Some(&token),
        "https://auth.example.test",
    )
    .await
    .status();
    stalled.abort_all();
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "anonymous stalled join bodies exhausted owner revocation admission"
    );
    assert!(!guard.permits());
}
