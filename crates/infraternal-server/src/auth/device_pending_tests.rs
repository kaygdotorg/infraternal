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
            start(&app, v4(index), &body).await,
            StatusCode::OK,
            "start {index}"
        );
    }
    assert_eq!(
        start(&app, v4(5000), &join()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        start(&app, v4(5001), &sign_in()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(rows(&f.auth).await, 1024);
    // Expiry frees the whole cap again.
    f.auth.set_test_http_time(NOW + 600);
    assert_eq!(start(&app, v4(5000), &join()).await, StatusCode::OK);
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
