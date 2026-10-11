//! Checks real OpenSSL startup trust, cold signing lock and bounded private-file reads without persisting a CA key (#78).

use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/remote-agents/startup")
            .join(uuid::Uuid::new_v4().to_string());
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn write(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
fn fixture() -> (Directory, RemoteStartup, ServerConfig) {
    let directory = Directory::new();
    let (identity, material) = crate::remote_runtime::tests::server_material();
    write(
        &directory.0.join("issuer.pem"),
        &material.issuer().to_pem().unwrap(),
    );
    write(
        &directory.0.join("server.pem"),
        &identity.certificate.to_pem().unwrap(),
    );
    write(
        &directory.0.join("server.key"),
        &identity.key.private_key_to_pem_pkcs8().unwrap(),
    );
    let startup = RemoteStartup {
        listen: "127.0.0.1:7443".parse().unwrap(),
        ca_dir: Some(directory.0.clone()),
    };
    let config = ServerConfig {
        listen: "127.0.0.1:4701".parse().unwrap(),
        data_dir: directory.0.join("db"),
        public_origin: "https://localhost:4701".into(),
        web_root: None,
        tls: Some(crate::TlsFiles {
            certificate: directory.0.join("server.pem"),
            private_key: directory.0.join("server.key"),
        }),
        behind_proxy: false,
        trusted_proxies: vec![],
    };
    (directory, startup, config)
}

#[test]
fn normal_cold_start_uses_public_trust_without_loading_or_generating_ca_key() {
    let (directory, startup, config) = fixture();
    let service = startup.cold_start(&config).unwrap();
    assert!(service.enrollment.source.load().is_err());
    assert_eq!(
        service.roots[0].to_der().unwrap(),
        service.enrollment.endpoint.ca_der
    );
    assert_eq!(service.enrollment.endpoint.server_name, "localhost");
    assert_eq!(service.enrollment.endpoint.endpoint, startup.listen);
    assert_eq!(std::fs::read_dir(&directory.0).unwrap().count(), 3);
    // Memory handoff stays an explicitly trusted process interface; a later cold
    // start must not infer it from retained public trust or the leaf transport key.
    assert!(
        startup
            .cold_start(&config)
            .unwrap()
            .enrollment
            .source
            .load()
            .is_err()
    );
    std::fs::remove_file(directory.0.join("issuer.pem")).unwrap();
    assert!(startup.cold_start(&config).is_err());
    assert!(!directory.0.join("issuer.pem").exists());
}

#[test]
fn wrong_issuer_key_name_or_unpinned_https_refuses_startup() {
    let (directory, mut startup, mut config) = fixture();
    config.public_origin = "https://foreign.test:4701".into();
    assert!(startup.cold_start(&config).is_err());
    config.public_origin = "https://localhost:4701".into();
    config.behind_proxy = true;
    assert!(startup.cold_start(&config).is_err());
    config.behind_proxy = false;
    startup.listen = "0.0.0.0:7443".parse().unwrap();
    assert!(startup.cold_start(&config).is_err());
    startup.listen = "127.0.0.1:7443".parse().unwrap();
    let (other, material) = crate::remote_runtime::tests::server_material();
    write(
        &directory.0.join("server.key"),
        &other.key.private_key_to_pem_pkcs8().unwrap(),
    );
    assert!(startup.cold_start(&config).is_err());
    write(
        &directory.0.join("server.pem"),
        &other.certificate.to_pem().unwrap(),
    );
    assert!(startup.cold_start(&config).is_err());
    write(
        &directory.0.join("issuer.pem"),
        &material.issuer().to_pem().unwrap(),
    );
    assert!(startup.cold_start(&config).is_ok());
}

#[test]
fn symlink_shared_oversized_or_special_trust_files_fail_closed() {
    let (directory, startup, config) = fixture();
    let issuer = directory.0.join("issuer.pem");
    std::fs::set_permissions(&issuer, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(startup.cold_start(&config).is_err());
    std::fs::set_permissions(&issuer, std::fs::Permissions::from_mode(0o600)).unwrap();
    write(&issuer, &[0; 8193]);
    assert!(startup.cold_start(&config).is_err());
    std::fs::remove_file(&issuer).unwrap();
    std::os::unix::fs::symlink(directory.0.join("server.pem"), &issuer).unwrap();
    assert!(startup.cold_start(&config).is_err());
    std::fs::remove_file(&issuer).unwrap();
    nix::unistd::mkfifo(
        &issuer,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    assert!(startup.cold_start(&config).is_err());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(startup.cold_start(&config).is_err());
}
