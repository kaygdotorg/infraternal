//! Exercises the same-origin CA HTTP boundary using real signed proofs and private copies; errors never reflect secret-shaped input [168], #78.
use super::*;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use tower::ServiceExt;

async fn http_fixture() -> (UnlockFixture, Router) {
    let f = unlock_fixture().await;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    sqlx::query("UPDATE sessions SET fresh=?,expires=? WHERE token_hash=?")
        .bind(now)
        .bind(now + 3600)
        .bind(hash(&f.auth.session))
        .execute(&f.auth.auth.pool)
        .await
        .unwrap();
    let authority = Arc::new(CaAdministration::new(
        f.auth.auth.clone(),
        f.auth.auth.pool.clone(),
        f.source.clone(),
        Arc::new(CaCopies::new(&f.root).unwrap()),
    ));
    let clock = Arc::new(crate::clock_health::ClockHealth::default());
    let router = crate::ca_http::router(f.auth.auth.clone(), authority, clock);
    (f, router)
}
fn ca_request(
    path: &str,
    origin: Option<&str>,
    cookie: Option<&str>,
    body: String,
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, format!("__Host-infraternal={cookie}"));
    }
    request.body(Body::from(body)).unwrap()
}
#[tokio::test]
async fn ca_http_exact_origin_and_live_cookie_are_required() {
    let (f, app) = http_fixture().await;
    let unknown = random();
    for (origin, cookie, status) in [
        (None, Some(f.auth.session.as_str()), StatusCode::FORBIDDEN),
        (
            Some("https://foreign.example"),
            Some(f.auth.session.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (Some(ORIGIN), None, StatusCode::UNAUTHORIZED),
        (Some(ORIGIN), Some("invalid"), StatusCode::UNAUTHORIZED),
        (Some(ORIGIN), Some(unknown.as_str()), StatusCode::FORBIDDEN),
    ] {
        let response = app
            .clone()
            .oneshot(ca_request("/remote/ca/status", origin, cookie, "{}".into()))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }
    assert!(f.source.load().is_err());
}

#[tokio::test]
async fn ca_http_status_includes_public_root_expiry_and_unknown_clock_state() {
    let (f, app) = http_fixture().await;
    let response = app
        .oneshot(ca_request(
            "/remote/ca/status",
            Some(ORIGIN),
            Some(&f.auth.session),
            "{}".into(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let status: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(status["locked"], true);
    assert_eq!(status["initialized"], true);
    let roots = status["roots"].as_array().expect("public root metadata");
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0]["generation"], 1);
    assert!(
        roots[0]["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(roots[0]["not_after"].as_i64().is_some());
    assert_eq!(roots[0]["remaining_seconds"], Value::Null);
    assert_eq!(roots[0]["warning_level"], "unknown");
    assert!(status.get("private_key").is_none());
}

#[tokio::test]
async fn ca_http_real_passkey_unlock_returns_only_lock_status_without_a_session_cookie() {
    let (mut f, app) = http_fixture().await;
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
    assert_eq!(response.status(), StatusCode::OK);
    let start: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(start["ca"]["member"], f.auth.user);
    assert!(start["ca"].get("ciphertext").is_none());
    let proof = f.auth.software.login(&start, ORIGIN, true);
    let response = app
        .clone()
        .oneshot(ca_request(
            "/remote/ca/unlock/finish",
            Some(ORIGIN),
            Some(&f.auth.session),
            serde_json::to_string(
                &json!({"ceremony":start["ceremony"],"proof":proof,"scoped_key":vec![7u8;32]}),
            )
            .unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let result =
        serde_json::from_slice::<Value>(&response.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert!(
        result == json!({"locked":false}),
        "unexpected public lock-status response shape"
    );
    assert!(f.source.load().is_ok());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sessions")
            .fetch_one(&f.auth.auth.pool)
            .await
            .unwrap(),
        1
    );
}
#[tokio::test]
async fn ca_http_parser_is_bounded_and_errors_do_not_reflect_wrapping_material() {
    let (f, app) = http_fixture().await;
    for body in [json!({"ceremony":"fixture","proof":{},"scoped_key":"secret-shaped-invalid-value"}).to_string(),json!({"ceremony":"fixture","proof":{},"scoped_key":vec![7u8;32],"unexpected":"secret-shaped-invalid-value"}).to_string()] {
        let response=app.clone().oneshot(ca_request("/remote/ca/unlock/finish",Some(ORIGIN),Some(&f.auth.session),body)).await.unwrap();
        assert_eq!(response.status(),StatusCode::BAD_REQUEST);
        assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
    }
    assert_eq!(
        app.oneshot(ca_request(
            "/remote/ca/unlock/finish",
            Some(ORIGIN),
            Some(&f.auth.session),
            "x".repeat(32769)
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(f.source.load().is_err());
}

#[tokio::test]
async fn ca_http_refuses_origin_and_cookie_before_decoding_wrapping_material() {
    let (f, app) = http_fixture().await;
    for (origin, cookie, status) in [
        (None, Some(f.auth.session.as_str()), StatusCode::FORBIDDEN),
        (
            Some("https://foreign.example"),
            Some(f.auth.session.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (Some(ORIGIN), None, StatusCode::UNAUTHORIZED),
        (Some(ORIGIN), Some("invalid"), StatusCode::UNAUTHORIZED),
    ] {
        let response = app
            .clone()
            .oneshot(ca_request(
                "/remote/ca/unlock/finish",
                origin,
                cookie,
                "{\"scoped_key\":\"secret-shaped-invalid-value\"}".into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty()
        );
    }
    assert!(f.source.load().is_err());
}

#[tokio::test]
async fn independent_review_ca_headers_are_refused_before_reading_an_unfinished_body() {
    let (_f, app) = http_fixture().await;
    let request = Request::builder()
        .method("POST")
        .uri("/remote/ca/unlock/finish")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(futures_util::stream::pending::<
            std::result::Result<bytes::Bytes, std::io::Error>,
        >()))
        .unwrap();
    // No Origin or cookie: the response needs no body bytes, database work or
    // passkey proof. A stalled body must not retain an unauthorized operation.
    let result = tokio::time::timeout(Duration::from_secs(1), app.oneshot(request)).await;
    assert!(
        result.is_ok(),
        "header refusal waited for an unfinished request body"
    );
    assert_eq!(result.unwrap().unwrap().status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn independent_review_ca_body_reads_share_the_eight_request_admission_limit() {
    let (f, app) = http_fixture().await;
    let polled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let polled = polled.clone();
        let mut first = true;
        let body = Body::from_stream(futures_util::stream::poll_fn(move |_| {
            if first {
                first = false;
                polled.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            std::task::Poll::Pending::<Option<std::result::Result<bytes::Bytes, std::io::Error>>>
        }));
        let request = Request::builder()
            .method("POST")
            .uri("/remote/ca/unlock/finish")
            .header(header::ORIGIN, ORIGIN)
            .header(
                header::COOKIE,
                format!("__Host-infraternal={}", f.auth.session),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .unwrap();
        tasks.push(tokio::spawn(app.clone().oneshot(request)));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while polled.load(std::sync::atomic::Ordering::SeqCst) != 8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let response = app
        .oneshot(ca_request(
            "/remote/ca/status",
            Some(ORIGIN),
            Some(&f.auth.session),
            "{}".into(),
        ))
        .await
        .unwrap();
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "eight unfinished CA requests did not reserve the declared admission slots"
    );
}

/// Measures only the real router's admission/body/decoder rejection pipeline;
/// no passkey verification or network latency is included [5][40][168].
#[tokio::test]
#[ignore = "1000-request body admission diagnostic; run alone without builds"]
async fn ca_body_admission_at_1000_requests() {
    let (f, app) = http_fixture().await;
    let mut samples = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let request = ca_request(
            "/remote/ca/unlock/finish",
            Some(ORIGIN),
            Some(&f.auth.session),
            "{}".into(),
        );
        let start = std::time::Instant::now();
        let response = app.clone().oneshot(request).await.unwrap();
        samples.push(start.elapsed().as_nanos());
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    samples.sort_unstable();
    println!(
        "CA_BODY_ADMISSION n=1000 profile={} p50_ns={} p99_ns={} median_projected_ns_at1000={} payload_bound_bytes_at8={} machine={} load={}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        samples[500],
        samples[990],
        samples[500] * 1000,
        8 * 32768,
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
    );
}

/// A stalled valid-header body expires and returns its admission reservation.
#[tokio::test]
async fn ca_finish_body_deadline_returns_its_admission_slot() {
    let (f, app) = http_fixture().await;
    tokio::time::pause();
    let request = Request::builder()
        .method("POST")
        .uri("/remote/ca/unlock/finish")
        .header(header::ORIGIN, ORIGIN)
        .header(
            header::COOKIE,
            format!("__Host-infraternal={}", f.auth.session),
        )
        .body(Body::from_stream(futures_util::stream::pending::<
            std::result::Result<bytes::Bytes, std::io::Error>,
        >()))
        .unwrap();
    let result = tokio::time::timeout(Duration::from_secs(6), app.clone().oneshot(request)).await;
    tokio::time::resume();
    assert!(
        result.is_ok(),
        "stalled body has no bounded request deadline"
    );
    assert_eq!(
        result.unwrap().unwrap().status(),
        StatusCode::REQUEST_TIMEOUT
    );
    assert_eq!(
        app.oneshot(ca_request(
            "/remote/ca/status",
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

/// Provisioning is a real administrator action rather than fixture-only state.
#[tokio::test]
async fn first_machine_certificate_setup_starts_a_fresh_passkey_ceremony() {
    let (f, app) = http_fixture().await;
    let response = app
        .oneshot(ca_request(
            "/remote/ca/bootstrap/start",
            Some(ORIGIN),
            Some(&f.auth.session),
            "{}".into(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ca_status_distinguishes_initial_setup_from_locked_retained_trust() {
    let (f, retained) = http_fixture().await;
    let fresh = crate::ca_http::router(
        f.auth.auth.clone(),
        Arc::new(CaAdministration::new(
            f.auth.auth.clone(),
            f.auth.auth.pool.clone(),
            Arc::new(crate::ca_memory::MemoryCaSource::unprovisioned(None)),
            Arc::new(CaCopies::new(&f.root).unwrap()),
        )),
        Arc::new(crate::clock_health::ClockHealth::default()),
    );
    for (app, initialized) in [(retained, true), (fresh, false)] {
        let response = app
            .oneshot(ca_request(
                "/remote/ca/status",
                Some(ORIGIN),
                Some(&f.auth.session),
                "{}".into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let status: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(status["locked"], true);
        assert_eq!(status["initialized"], initialized);
        assert_eq!(
            status["roots"].as_array().unwrap().len(),
            usize::from(initialized)
        );
    }
}

#[path = "ca_http_audit_tests.rs"]
mod audit_tests;
