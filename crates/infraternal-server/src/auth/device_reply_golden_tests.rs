//! The device-start and device-redeem replies keep their exact bytes (#580, plan S3).
//!
//! The replies are built from the shared `infraternal-sign-in` types, which the
//! sign-in CLI and the future app parse. These tests read the raw HTTP bodies, so a
//! renamed field, a new field, a reordered key or a changed number format fails
//! here before it reaches a client.
use super::*;
use crate::runtime::ClientAddress;
use axum::http::StatusCode;
use http_body_util::BodyExt;

/// POST `body` to `/auth/<action>` as a anonymous device, returning the status and raw bytes.
async fn device_call(app: &axum::Router, action: &str, body: &Value) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(format!("/auth/{action}"))
                .header("content-type", "application/json")
                .extension(ClientAddress("203.0.113.9".parse().unwrap()))
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
}

/// A sign-in start reply is exactly `expires_in`, `poll_token`, `user_code`, in that order, and a
/// redeem reply is exactly `api_key`; nothing else is added.
#[tokio::test]
async fn sign_in_start_and_redeem_replies_have_their_golden_bytes() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);

    let (status, start) = device_call(
        &app,
        "device-start",
        &json!({"device": "cli", "scopes": ["hosts:read"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&start).unwrap();
    let token = str_field(&parsed, "poll_token");
    let code = str_field(&parsed, "user_code");
    assert_eq!(token.len(), 43);
    assert_eq!(code.len(), 16);
    let golden = format!(r#"{{"expires_in":600,"poll_token":"{token}","user_code":"{code}"}}"#);
    assert_eq!(String::from_utf8(start.clone()).unwrap(), golden);
    // The shared client type accepts exactly this reply.
    let client = infraternal_sign_in::parse_start_response(&start).unwrap();
    assert_eq!(client.user_code, code);

    f.auth
        .approve_without_passkey_for_tests(&f.session, code, NOW)
        .await
        .unwrap();
    let (status, redeem) = device_call(&app, "device-redeem", &json!({"token": token})).await;
    assert_eq!(status, StatusCode::OK);
    let parsed: Value = serde_json::from_slice(&redeem).unwrap();
    let key = str_field(&parsed, "api_key");
    assert_eq!(
        String::from_utf8(redeem.clone()).unwrap(),
        format!(r#"{{"api_key":"{key}"}}"#)
    );
    assert!(infraternal_sign_in::parse_redemption_response(&redeem).is_ok());
}
