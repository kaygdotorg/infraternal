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
    let (app, _, _, _, _) = build_router_core(
        config,
        Some(EmbeddedAgent::unavailable()),
        None,
        None,
        None,
        None,
        None,
    )
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

/// Independent D168 route assembly evidence uses the production router and cold
/// source; it never mounts the CA router directly or injects an unlocked signer.
#[tokio::test]
async fn independent_review_configured_server_mounts_ca_unlock_routes() {
    let data = PathBuf::from(std::env::var_os("HOME").unwrap())
        .join(".cache/codex-scratch/remote-agents-review")
        .join(format!("ca-router-{}", uuid::Uuid::new_v4()));
    let config = ServerConfig {
        listen: "127.0.0.1:4786".parse().unwrap(),
        data_dir: data.clone(),
        public_origin: "https://localhost:4786".into(),
        web_root: None,
        tls: Some(TlsFiles {
            certificate: "unused.crt".into(),
            private_key: "unused.key".into(),
        }),
        behind_proxy: false,
        trusted_proxies: Vec::new(),
    };
    let (identity, material) = crate::remote_runtime::tests::server_material_for_name("localhost");
    let issuer = material.issuer().clone();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(issuer.clone()));
    let remote = crate::remote_runtime::RemoteService {
        ca_administration: Some(crate::ca_administration::CaAdministrationConfig::new(
            source.clone(),
            data.clone(),
        )),
        enrollment: crate::remote_http::EnrollmentService {
            source,
            endpoint: crate::remote_http::EnrollmentEndpoint {
                ca_der: issuer.to_der().unwrap(),
                endpoint: "127.0.0.1:0".parse().unwrap(),
                server_name: "localhost".into(),
            },
        },
        identity: Some(identity),
        roots: vec![issuer],
        clock_health: Arc::new(crate::clock_health::ClockHealth::default()),
    };
    let (app, _, listeners, _, _) = build_router_core(
        config,
        Some(EmbeddedAgent::unavailable()),
        Some(remote.enrollment.clone()),
        Some(remote),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let mut statuses = Vec::new();
    for path in [
        "/remote/ca/status",
        "/remote/ca/unlock/start",
        "/remote/ca/unlock/finish",
    ] {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("origin", "https://localhost:4786")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        statuses.push(response.status());
    }
    drop(app);
    drop(listeners);
    std::fs::remove_dir_all(data).unwrap();
    assert_eq!(
        statuses,
        vec![axum::http::StatusCode::UNAUTHORIZED; 3],
        "configured server must expose all three cold-CA routes with cookie admission"
    );
}
