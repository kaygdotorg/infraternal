//! Exercises automatic configured custody through real startup, HTTP Settings and file-backed SQLite.
use super::*;
use crate::{
    bootstrap_runtime::{KeyInitialization, default_runner},
    ssh_key::{SshKeySource, StoredSshKey},
};
use axum::{
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode, header},
};
use std::sync::Mutex as StdMutex;
use tower::ServiceExt;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn public(router: Router, cookie: &str) -> serde_json::Value {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/bootstrap/ssh-key")
        .header(header::ORIGIN, "https://auth.example.test")
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo("127.0.0.1:4787".parse::<SocketAddr>().unwrap()));
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
}

#[tokio::test]
async fn configured_startup_generates_once_and_settings_shares_its_cold_lock() {
    let _serial = crate::auth::tests::SERIAL.lock().await;
    let directory = Directory(
        PathBuf::from("target").join(format!("ssh-startup-{}", uuid::Uuid::new_v4().simple())),
    );
    let config = ServerConfig {
        listen: "127.0.0.1:4787".parse().unwrap(),
        data_dir: directory.0.clone(),
        public_origin: "https://auth.example.test".into(),
        web_root: None,
        tls: None,
        behind_proxy: true,
        trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
    };
    let vault = crate::ssh_key::test_custody();
    let captured = Arc::new(StdMutex::new(None));
    let receiving = captured.clone();
    let data = directory.0.clone();
    let (router, setup) = build_router_with_key_setup(
        config.clone(),
        Some(EmbeddedAgent::spawn(PathBuf::from(
            "target/nonexistent-startup-fixture",
        ))),
        None,
        Some(KeyInitialization {
            vault: vault.clone(),
            factory: Box::new(move |auth, pool, source| {
                assert!(source.public_key().unwrap().locked);
                assert!(source.load().is_err());
                let runner = default_runner(&data, auth.clone(), source.clone(), None).unwrap();
                *receiving.lock().unwrap() = Some((auth, pool, source));
                runner
            }),
        }),
    )
    .await
    .unwrap();
    let (auth, pool, source) = captured.lock().unwrap().take().unwrap();
    let (_, cookie) =
        crate::auth::tests::register_over_http(&crate::auth::router(auth), &setup.unwrap()).await;
    let initial = public(router.clone(), &cookie).await;
    assert_eq!(initial["locked"], true);
    assert_eq!(
        initial["public_key"],
        source.public_key().unwrap().public_key
    );
    // This is a memory-only administrator test policy. Ordinary owner login above
    // has not unwrapped anything; production fresh administrator proof is #78's adapter.
    source.unlock_from(vault.as_ref()).unwrap();
    assert_eq!(public(router.clone(), &cookie).await["locked"], false);
    source.lock().unwrap();
    assert_eq!(public(router, &cookie).await["locked"], true);
    let cold = StoredSshKey::cold_start(&pool).await.unwrap().unwrap();
    assert_eq!(
        cold.public_key().unwrap().fingerprint,
        initial["fingerprint"]
    );
    assert!(cold.load().is_err());
    drop(pool);
    // An unconfigured restart retains the same durable public identity and stays
    // cold-locked; it cannot choose another identity or an adjacent unwrap key.
    let (restarted, setup) = build_router_with_key_setup(
        config,
        Some(EmbeddedAgent::spawn(PathBuf::from(
            "target/nonexistent-startup-fixture",
        ))),
        None,
        None,
    )
    .await
    .unwrap();
    assert!(setup.is_none());
    assert_eq!(public(restarted, &cookie).await, initial);
}
