//! Checks sequential CA ceremony admission through the real HTTP authority, #154 [168].
use super::*;

#[tokio::test]
async fn sequential_unlock_starts_require_a_temporal_budget() {
    let (f, app) = http_fixture().await;
    let started = Instant::now();
    let mut accepted = 0;
    for _ in 0..31 {
        let response = app
            .clone()
            .oneshot(ca_request(
                "/remote/ca/unlock/start",
                Some(ORIGIN),
                Some(&f.auth.session),
                "{}".into(),
            ))
            .await
            .unwrap();
        if accepted < 30 {
            assert_eq!(response.status(), StatusCode::OK);
            accepted += 1;
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(response.headers()[header::RETRY_AFTER], "60");
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(body.as_ref(), b"too many requests");
        }
    }
    println!(
        "METRIC sequential_unlock_start_requests=31 accepted={accepted} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "fixture crossed proposed rate window"
    );
    assert!(
        accepted <= 30,
        "concurrency admission must also bound sequential ceremony work"
    );
    assert!(f.source.load().is_err());
}

#[tokio::test]
async fn ca_start_budget_is_shared_by_routes_and_cookies_but_not_status_or_finish() {
    let (f, app) = http_fixture().await;
    let alternate = random();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked,passkey_id) SELECT ?,user_id,device,expires,fresh,unlocked,passkey_id FROM sessions WHERE token_hash=?")
        .bind(hash(&alternate)).bind(hash(&f.auth.session)).execute(&f.auth.auth.pool).await.unwrap();
    for _ in 0..30 {
        assert_eq!(
            app.clone()
                .oneshot(ca_request(
                    "/remote/ca/unlock/start",
                    Some(ORIGIN),
                    Some(&f.auth.session),
                    "{}".into()
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    for path in [
        "/remote/ca/unlock/start",
        "/remote/ca/bootstrap/start",
        "/remote/ca/administrators/start",
    ] {
        let response = app
            .clone()
            .oneshot(ca_request(
                path,
                Some(ORIGIN),
                Some(&alternate),
                "{}".into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "60");
    }
    assert_eq!(
        app.clone()
            .oneshot(ca_request(
                "/remote/ca/status",
                Some(ORIGIN),
                Some(&alternate),
                "{}".into()
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.oneshot(ca_request(
            "/remote/ca/unlock/finish",
            Some(ORIGIN),
            Some(&alternate),
            "{}".into()
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::BAD_REQUEST
    );
}
