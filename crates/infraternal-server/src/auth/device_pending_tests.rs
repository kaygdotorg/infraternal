//! Public approval starts cannot grow the approvals table without bound (#263, J122 P2).
use super::*;
use crate::runtime::ClientAddress;
use axum::http::StatusCode;
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

fn sign_in() -> Value {
    json!({"device": "cli", "scopes": ["hosts:read"]})
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

#[tokio::test]
async fn anonymous_flood_cannot_stop_the_owner_reviewing_an_approval() {
    // J134 P2-1: anonymous callers spend the shared browser partition.
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
    for _ in 0..120 {
        assert_eq!(
            browser(&app, "login-start", None, &json!({}))
                .await
                .status(),
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
