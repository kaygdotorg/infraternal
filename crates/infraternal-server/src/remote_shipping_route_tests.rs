//! Checks normal shipping route registration without injecting a test signer, #78.

use super::super::*;
use tower::ServiceExt;

#[tokio::test]
async fn review_default_server_must_register_remote_join() {
    let data = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".cache/codex-scratch/remote-agents/shipping-route-tests")
        .join(format!("router-{}", uuid::Uuid::new_v4()));
    let config = ServerConfig {
        listen: "127.0.0.1:4748".parse().unwrap(),
        data_dir: data.clone(),
        public_origin: "https://localhost:4748".into(),
        web_root: None,
        tls: Some(TlsFiles {
            certificate: "unused.crt".into(),
            private_key: "unused.key".into(),
        }),
        behind_proxy: false,
        trusted_proxies: Vec::new(),
    };
    let (app, _, _) = build_router_core(config, Some(EmbeddedAgent::unavailable()), None, None)
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/remote/join")
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    assert_eq!(status, axum::http::StatusCode::SERVICE_UNAVAILABLE);
    for path in ["/remote/invitations", "/remote/revocations"] {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/remote/join")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED
    );
    std::fs::remove_dir_all(data).unwrap();
    assert_ne!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "shipping server has no remote enrollment endpoint"
    );
}
