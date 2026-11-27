//! Public approval starts cannot grow the approvals table without bound (#263, J122 P2).
use super::*;
use crate::runtime::ClientAddress;
use axum::{extract::ConnectInfo, http::StatusCode};
use std::net::IpAddr;

async fn start(app: &axum::Router, source: IpAddr, body: &Value) -> StatusCode {
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/device-start")
                .header("content-type", "application/json")
                .extension(ClientAddress(source))
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

fn join() -> Value {
    json!({
        "kind": "join_machine",
        "device": "laptop",
        "request": {
            "host_id": Uuid::new_v4(),
            "hostname": "laptop",
            "mode": "system",
            "execution_uid": 0,
            "key_fingerprint": format!("SHA256:{}", "A".repeat(43)),
        },
    })
}

/// A standard CLI sign-in request for tests sharing the public approval budget.
fn sign_in() -> Value {
    json!({"device": "cli", "scopes": ["hosts:read"]})
}

/// A pending redeem wakes on its own approval, and a missed signal falls back to SQLite.
#[cfg(feature = "remote")]
#[tokio::test]
async fn machine_approval_wait_rechecks_durable_state_with_or_without_a_signal() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    for notify in [true, false] {
        let response = browser(&app, "device-start", None, &join()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let approval = json_body(response).await;
        let token = str_field(&approval, "poll_token");
        let code = str_field(&approval, "user_code");
        f.auth.device_inspect(&f.session, code, NOW).await.unwrap();

        let wait = if notify {
            std::time::Duration::from_secs(10)
        } else {
            std::time::Duration::from_millis(100)
        };
        let publish = async {
            if notify {
                f.auth
                    .approve_without_passkey_for_tests(&f.session, code, NOW)
                    .await
                    .unwrap();
            } else {
                sqlx::query("UPDATE approvals SET user_id=(SELECT id FROM users WHERE owner=1) WHERE token_hash=?")
                    .bind(hash(token))
                    .execute(&f.auth.pool)
                    .await
                    .unwrap();
            }
        };
        let check = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            f.auth.wait_for_device_join(token, NOW, wait),
        );
        // Poll the subscriber first and keep driving both requests so the
        // subscriber can return the fixture's single SQLite connection.
        let (checked, ()) = tokio::join!(biased; check, publish);
        checked
            .expect("approval must wake or recheck within the expected bound")
            .unwrap();
        assert!(f.auth.device_join_approved(token, NOW).await.unwrap());
    }
}

async fn rows(auth: &Auth) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM approvals")
        .fetch_one(&auth.pool)
        .await
        .unwrap()
}

fn v4(index: u32) -> IpAddr {
    IpAddr::V4((0x0a00_0000 + index).into())
}

/// One address in the `index`th IPv4 /24, so each start has its own network.
fn v4_network(index: u32) -> IpAddr {
    IpAddr::V4((0x0a00_0000 + (index << 8)).into())
}

/// Host 1 of the /64 `network` (its low 16 bits) inside /56 `subnet` of `2001:db8:7::/48`.
fn v6_in_48(subnet: u16, network: u16) -> IpAddr {
    IpAddr::V6(std::net::Ipv6Addr::new(
        0x2001,
        0xdb8,
        7,
        (subnet << 8) | (network & 0xff),
        0,
        0,
        0,
        1,
    ))
}

#[tokio::test]
async fn machine_join_start_deletes_expired_approvals() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    for index in 0..3 {
        assert_eq!(start(&app, v4(index), &join()).await, StatusCode::OK);
    }
    f.auth.set_test_http_time(NOW + 600);
    assert_eq!(start(&app, v4(3), &join()).await, StatusCode::OK);
    assert_eq!(rows(&f.auth).await, 1, "expired join approvals were kept");
}

#[tokio::test]
async fn pending_approvals_of_every_kind_share_one_server_cap() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    for index in 0..1024 {
        let body = if index % 2 == 0 { join() } else { sign_in() };
        assert_eq!(
            start(&app, v4_network(index), &body).await,
            StatusCode::OK,
            "start {index}"
        );
    }
    assert_eq!(
        start(&app, v4_network(5000), &join()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        start(&app, v4_network(5001), &sign_in()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(rows(&f.auth).await, 1024);
    // Expiry frees the whole cap again.
    f.auth.set_test_http_time(NOW + 600);
    assert_eq!(start(&app, v4_network(5000), &join()).await, StatusCode::OK);
    assert_eq!(rows(&f.auth).await, 1);
}

#[tokio::test]
async fn one_source_network_holds_at_most_five_pending_approvals() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    let host = |network: u16, host: u16| -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, 5, network, 0, 0, 0, host,
        ))
    };
    for index in 1..=5 {
        let body = if index % 2 == 0 { join() } else { sign_in() };
        assert_eq!(start(&app, host(5, index), &body).await, StatusCode::OK);
    }
    // Another host in the same /64 is the same network.
    assert_eq!(
        start(&app, host(5, 99), &join()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        start(&app, host(5, 99), &sign_in()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(start(&app, host(6, 1), &join()).await, StatusCode::OK);
    f.auth.set_test_http_time(NOW + 600);
    assert_eq!(start(&app, host(5, 99), &join()).await, StatusCode::OK);
}

/// A browser call carrying `cookie` (or none), from the app's own origin.
async fn browser(
    app: &axum::Router,
    action: &str,
    cookie: Option<&str>,
    body: &Value,
) -> axum::response::Response {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/auth/{action}"))
        .header("content-type", "application/json")
        .header("origin", ORIGIN)
        .extension(ConnectInfo(SocketAddr::new(v4(77), 5000)))
        .extension(ClientAddress(v4(77)));
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("__Host-infraternal={cookie}"));
    }
    app.clone()
        .oneshot(
            request
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Old attempts stay with their code and a restarted runtime can start a fresh machine's passkey.
#[tokio::test]
async fn first_machine_review_after_restart_has_its_own_admission() {
    let _guard = SERIAL.lock().await;
    let (pool, path) = disk_pool("device-admission-restart").await;
    let (auth, setup) = empty_with_pool(pool.clone()).await;
    let fixture = fixture_with_bootstrap(auth, setup).await;
    fixture.auth.set_test_http_time(NOW);
    let app = crate::runtime::test_auth_admission_router(fixture.auth.clone());
    let response = browser(&app, "device-start", None, &join()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let old = json!({"code": json_body(response).await["user_code"]});
    for attempt in 0..60 {
        let response = browser(&app, "device-inspect", Some(&fixture.session), &old).await;
        let expected = if attempt < 5 {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        };
        assert_eq!(
            response.status(),
            expected,
            "old machine inspection {attempt}"
        );
    }
    assert_eq!(
        browser(&app, "device-inspect", Some(&fixture.session), &old)
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let session = fixture.session.clone();
    drop(app);
    drop(fixture);

    let auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();
    auth.set_test_http_time(NOW);
    let app = crate::runtime::test_auth_admission_router(auth);
    let response = browser(&app, "device-start", None, &join()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let new = json!({"code": json_body(response).await["user_code"]});
    for _ in 0..30 {
        assert_eq!(
            browser(&app, "status", None, &json!({})).await.status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        browser(&app, "device-inspect", None, &new).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    for _ in 0..240 {
        assert_eq!(
            browser(&app, "status", Some(&session), &json!({}))
                .await
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        browser(&app, "status", Some(&session), &json!({}))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        browser(&app, "device-inspect", Some(&session), &new)
            .await
            .status(),
        StatusCode::OK
    );
    let response = browser(&app, "device-approve-start", Some(&session), &new).await;
    assert_eq!(response.status(), StatusCode::OK);
    let start = json_body(response).await;
    assert!(start["options"]["publicKey"]["challenge"].is_string());
    assert_eq!(
        browser(&app, "device-inspect", Some(&session), &old)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    println!(
        "first new join after restart returned 200 for inspection and passkey start, with the public and layout windows spent; old code retained its 401"
    );
    drop(app);
    pool.close().await;
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[tokio::test]
async fn anonymous_flood_cannot_stop_the_owner_reviewing_an_approval() {
    // J134 P2-1: anonymous callers spend the browser budget of the owner's network.
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    let started = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/device-start")
                .header("content-type", "application/json")
                .extension(ClientAddress(v4(1)))
                .body(axum::body::Body::from(join().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let started: Value =
        serde_json::from_slice(&started.into_body().collect().await.unwrap().to_bytes()).unwrap();
    // Anonymous calls from the owner's network spend its whole budget.
    for _ in 0..120 {
        assert_eq!(
            browser(&app, "status", None, &json!({})).await.status(),
            StatusCode::OK
        );
    }
    let flooded = browser(&app, "login-start", None, &json!({})).await;
    assert_eq!(flooded.status(), StatusCode::TOO_MANY_REQUESTS);
    // A made-up cookie does not escape the anonymous partition.
    assert_eq!(
        browser(&app, "session", Some("A".repeat(43).as_str()), &json!({}))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // The owner's live session still reviews the waiting `up`.
    let review = browser(
        &app,
        "device-inspect",
        Some(&f.session),
        &json!({"code": started["user_code"]}),
    )
    .await;
    assert_eq!(
        review.status(),
        StatusCode::OK,
        "owner review was throttled"
    );
    // The owner's own budget is bounded too.
    for _ in 1..120 {
        assert_eq!(
            browser(&app, "session", Some(&f.session), &json!({}))
                .await
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        browser(&app, "session", Some(&f.session), &json!({}))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn one_ipv6_allocation_cannot_fill_the_server_cap() {
    // J134 P2-2: 205 /64s inside one /48 (each in its own /56), five starts each.
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    let mut accepted = 0;
    for network in 0..205_u16 {
        for _ in 0..5 {
            if start(&app, v6_in_48(network, 0), &join()).await == StatusCode::OK {
                accepted += 1;
            }
        }
    }
    assert_eq!(accepted, 32, "one /48 holds at most 32 pending approvals");
    assert_eq!(start(&app, v4_network(9), &join()).await, StatusCode::OK);
    assert_eq!(
        start(&app, "2001:db8:8::1".parse().unwrap(), &sign_in()).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn nested_source_caps_bound_each_prefix() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    // One /56 holds 16, whichever of its /64s they come from.
    for network in 0..16 {
        assert_eq!(
            start(&app, v6_in_48(0, network), &join()).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        start(&app, v6_in_48(0, 200), &join()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Another /56 of the same /48 takes the /48's remaining 16.
    for network in 0..16 {
        assert_eq!(
            start(&app, v6_in_48(1, network), &join()).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        start(&app, v6_in_48(2, 0), &join()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // One IPv4 /24 holds 32; each of its addresses at most 5.
    for _ in 0..5 {
        assert_eq!(start(&app, v4(1), &sign_in()).await, StatusCode::OK);
    }
    assert_eq!(
        start(&app, v4(1), &sign_in()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    for host in 2..29 {
        assert_eq!(start(&app, v4(host), &sign_in()).await, StatusCode::OK);
    }
    assert_eq!(
        start(&app, v4(29), &sign_in()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(start(&app, v4_network(1), &sign_in()).await, StatusCode::OK);
    // Expiry frees every enclosing network together.
    f.auth.set_test_http_time(NOW + 600);
    assert_eq!(start(&app, v6_in_48(2, 0), &join()).await, StatusCode::OK);
    assert_eq!(start(&app, v4(29), &sign_in()).await, StatusCode::OK);
}

#[tokio::test]
async fn a_machine_name_outside_the_cli_set_is_refused() {
    // J134 P3-3: bidi overrides, zero-width and look-alike characters.
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    for (index, name) in [
        "build-\u{202e}10-dliub",
        "build\u{200b}-01",
        "build\u{2066}-01",
        "bu\u{0456}ld-01",
        "build 01",
        "build/01",
    ]
    .into_iter()
    .enumerate()
    {
        let mut body = join();
        body["request"]["hostname"] = json!(name);
        let source = v4_network(u32::try_from(index).unwrap());
        assert_eq!(
            start(&app, source, &body).await,
            StatusCode::BAD_REQUEST,
            "{name:?}"
        );
    }
    let mut body = join();
    body["request"]["hostname"] = json!("Build-01.lan_2");
    assert_eq!(start(&app, v4_network(99), &body).await, StatusCode::OK);
}

/// Start a join from its own network and inspect it as the owner; returns its codes.
async fn inspected_join(app: &axum::Router, session: &str, network: u32) -> Value {
    let started = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/device-start")
                .header("content-type", "application/json")
                .extension(ClientAddress(v4_network(network)))
                .body(axum::body::Body::from(join().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::OK);
    let started: Value =
        serde_json::from_slice(&started.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let code = json!({"code": started["user_code"]});
    assert_eq!(
        browser(app, "device-inspect", Some(session), &code)
            .await
            .status(),
        StatusCode::OK
    );
    started
}

async fn json_body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn a_machine_join_needs_a_passkey_tap_for_that_approval() {
    // J134 P3-2: a fresh login within five minutes used to approve any join.
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    let first = inspected_join(&app, &f.session, 1).await;
    let second = inspected_join(&app, &f.session, 2).await;
    let first_code = json!({"code": first["user_code"]});
    // The session is fresh (registered at NOW), yet no plain approval exists.
    assert_ne!(
        browser(&app, "device-approve", Some(&f.session), &first_code)
            .await
            .status(),
        StatusCode::OK
    );
    // A proof of an ordinary login ceremony does not approve a join either.
    let login = json_body(
        browser(
            &app,
            "login-start",
            Some(&f.session),
            &json!({"user_id": f.user}),
        )
        .await,
    )
    .await;
    let proof = f.software.login(&login, ORIGIN, true);
    let finish = |code: &Value, ceremony: &Value, proof: &Value| json!({"code": code["user_code"], "ceremony": ceremony["ceremony"], "proof": proof});
    assert_eq!(
        browser(
            &app,
            "device-approve-finish",
            Some(&f.session),
            &finish(&first, &login, &proof)
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // A ceremony started for the first code does not approve the second.
    let start = browser(&app, "device-approve-start", Some(&f.session), &first_code).await;
    assert_eq!(start.status(), StatusCode::OK);
    let start = json_body(start).await;
    let proof = f.software.login(&start, ORIGIN, true);
    assert_eq!(
        browser(
            &app,
            "device-approve-finish",
            Some(&f.session),
            &finish(&second, &start, &proof)
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // Its own code, with its own proof, approves exactly that join, once.
    assert_eq!(
        browser(
            &app,
            "device-approve-finish",
            Some(&f.session),
            &finish(&first, &start, &proof)
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert!(
        f.auth
            .device_join_approved(str_field(&first, "poll_token"), NOW)
            .await
            .unwrap()
    );
    assert!(
        !f.auth
            .device_join_approved(str_field(&second, "poll_token"), NOW)
            .await
            .unwrap()
    );
    assert_eq!(
        browser(
            &app,
            "device-approve-finish",
            Some(&f.session),
            &finish(&first, &start, &proof)
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED,
        "a ceremony is single use"
    );
}

#[tokio::test]
async fn a_join_ceremony_belongs_to_the_session_that_started_it() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    let pending = inspected_join(&app, &f.session, 1).await;
    let code = json!({"code": pending["user_code"]});
    let start =
        json_body(browser(&app, "device-approve-start", Some(&f.session), &code).await).await;
    let proof = f.software.login(&start, ORIGIN, true);
    let other = "C".repeat(43);
    let body = json!({"code": pending["user_code"], "ceremony": start["ceremony"], "proof": proof});
    assert_eq!(
        browser(&app, "device-approve-finish", Some(&other), &body)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // A code nobody inspected yet cannot start a ceremony.
    let uninspected = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/device-start")
                .header("content-type", "application/json")
                .extension(ClientAddress(v4_network(5)))
                .body(axum::body::Body::from(join().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let uninspected = json_body(uninspected).await;
    assert_eq!(
        browser(
            &app,
            "device-approve-start",
            Some(&f.session),
            &json!({"code": uninspected["user_code"]})
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    // The owner's own session still finishes it after the stranger's attempt.
    assert_eq!(
        browser(&app, "device-approve-finish", Some(&f.session), &body)
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_cli_sign_in_needs_a_passkey_tap_for_that_approval() {
    // J145 P3-3: any login within 300 s used to approve a CLI sign-in key.
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    let started = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/device-start")
                .header("content-type", "application/json")
                .extension(ClientAddress(v4_network(3)))
                .body(axum::body::Body::from(sign_in().to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let started = json_body(started).await;
    let code = json!({"code": started["user_code"]});
    // The session is fresh (registered at NOW), yet that alone approves nothing.
    assert_ne!(
        browser(&app, "device-approve", Some(&f.session), &code)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        f.auth
            .device_redeem(str_field(&started, "poll_token"), NOW)
            .await
            .is_err()
    );
    // The sign-in is approved by a tap for this code, once.
    let start = browser(&app, "device-approve-start", Some(&f.session), &code).await;
    assert_eq!(start.status(), StatusCode::OK);
    let start = json_body(start).await;
    let proof = f.software.login(&start, ORIGIN, true);
    let finish =
        json!({"code": started["user_code"], "ceremony": start["ceremony"], "proof": proof});
    assert_eq!(
        browser(&app, "device-approve-finish", Some(&f.session), &finish)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        f.auth
            .device_redeem(str_field(&started, "poll_token"), NOW)
            .await
            .is_ok()
    );
    assert_ne!(
        browser(&app, "device-approve-finish", Some(&f.session), &finish)
            .await
            .status(),
        StatusCode::OK,
        "a ceremony is single use"
    );
}

/// #559 F3: the device label is what the owner reads before approving, so labels that
/// could render as another device (bidi override, zero-width, control characters) are
/// refused for both sign-in and machine-join requests, while plain labels still start.
#[tokio::test]
async fn device_labels_that_could_mislead_the_approver_are_refused() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    // Each start comes from its own network so no per-network budget interferes.
    let mut network = 0;
    let mut source = || {
        network += 1;
        v4_network(network)
    };
    for label in [
        "cli\u{202e}gnirts",
        "lap\u{200b}top",
        "line\nbreak",
        "caf\u{e9}",
        "",
    ] {
        let mut request = sign_in();
        request["device"] = json!(label);
        assert_eq!(
            start(&app, source(), &request).await,
            StatusCode::BAD_REQUEST,
            "sign-in label {label:?} must be refused"
        );
        let mut request = join();
        request["device"] = json!(label);
        assert_eq!(
            start(&app, source(), &request).await,
            StatusCode::BAD_REQUEST,
            "join label {label:?} must be refused"
        );
    }
    let mut request = sign_in();
    request["device"] = json!("CLI device");
    assert_eq!(start(&app, source(), &request).await, StatusCode::OK);
}
