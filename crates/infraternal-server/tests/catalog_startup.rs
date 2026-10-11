//! Preserves the production's public catalog startup adapter without touching data for invalid configuration.
use infraternal_server::{ServerConfig, ServerError, serve_with_plugin_descriptors};

#[tokio::test]
async fn explicit_catalog_startup_remains_public_and_validates_before_storage() {
    let data_dir = std::path::PathBuf::from("unused-invalid-catalog-startup");
    let config = ServerConfig {
        listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        data_dir: data_dir.clone(),
        public_origin: "http://invalid.example".into(),
        web_root: None,
        tls: None,
        behind_proxy: false,
        trusted_proxies: Vec::new(),
    };
    assert!(matches!(
        serve_with_plugin_descriptors(config, &[]).await,
        Err(ServerError::InvalidConfiguration)
    ));
    assert!(!data_dir.exists());
}
