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

/// The startup error text of a refused cold start.
fn refusal(startup: &RemoteStartup, config: &ServerConfig) -> String {
    match startup.cold_start(config) {
        Ok(_) => panic!("startup must be refused"),
        Err(error) => error.to_string(),
    }
}

/// The J1237 finding (#595): `openssl req` leaves a certificate group or world
/// readable under the usual umask, and the refusal must say so, naming the
/// option and the mode without printing the path.
#[test]
fn a_refused_startup_names_the_file_and_the_rule_without_its_path() {
    let (directory, startup, config) = fixture();
    let certificate = directory.0.join("server.pem");
    let key = directory.0.join("server.key");
    std::fs::set_permissions(&certificate, std::fs::Permissions::from_mode(0o644)).unwrap();
    let message = refusal(&startup, &config);
    assert_eq!(
        message,
        "TLS configuration failed: the --tls-cert file has mode 0644; group and other users \
         must have no access (chmod go-rwx)"
    );
    assert!(!message.contains(directory.0.to_str().unwrap()));
    std::fs::set_permissions(&certificate, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(refusal(&startup, &config).contains("the --tls-key file has mode 0640"));
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();

    let real = directory.0.join("real.pem");
    std::fs::rename(&certificate, &real).unwrap();
    assert!(refusal(&startup, &config).contains("the --tls-cert file does not exist"));
    std::os::unix::fs::symlink(&real, &certificate).unwrap();
    assert!(refusal(&startup, &config).contains("the --tls-cert file is a symbolic link"));
    std::fs::remove_file(&certificate).unwrap();
    write(&certificate, b"not a certificate");
    assert!(
        refusal(&startup, &config).contains("the --tls-cert file does not hold a PEM certificate")
    );
    write(&certificate, &[b'a'; 8193]);
    assert!(refusal(&startup, &config).contains("the --tls-cert file is larger than 8192 bytes"));
    std::fs::rename(&real, &certificate).unwrap();

    let (other, _) = crate::remote_runtime::tests::server_material();
    let good_key = std::fs::read(&key).unwrap();
    write(&key, &other.key.private_key_to_pem_pkcs8().unwrap());
    assert!(refusal(&startup, &config).contains("the --tls-cert and --tls-key files do not match"));
    write(&key, &good_key);

    let mut foreign = config.clone();
    foreign.public_origin = "https://foreign.test:4701".into();
    let message = refusal(&startup, &foreign);
    assert!(
        message.contains("the --tls-cert file failed certificate verification (hostname mismatch)"),
        "{message}"
    );

    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        refusal(&startup, &config).contains("the CA directory (--remote-ca-dir) has mode 0755")
    );
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(startup.cold_start(&config).is_ok());
}

/// The listener without `--remote-listen` loads the two files itself; its
/// failure is explained by reading them again.
#[test]
fn a_standalone_listener_failure_is_explained() {
    let (directory, _, _) = fixture();
    let certificate = directory.0.join("server.pem");
    let key = directory.0.join("server.key");
    let explain = |certificate: &Path, key: &Path| {
        crate::tls_problem::explain_load(certificate, key).to_string()
    };
    assert_eq!(
        explain(&directory.0.join("absent.pem"), &key),
        "the --tls-cert file does not exist"
    );
    assert_eq!(
        explain(&certificate, &certificate),
        "the --tls-key file does not hold a PEM private key that can be loaded"
    );
    let (other, _) = crate::remote_runtime::tests::server_material();
    write(&key, &other.key.private_key_to_pem_pkcs8().unwrap());
    assert!(explain(&certificate, &key).contains("do not match"));
}
