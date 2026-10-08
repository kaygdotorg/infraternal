//! Checks explicit remote activation, required trust coordinates and service-install preservation without starting a listener (#78).

use super::*;
use clap::Parser;

fn parsed(arguments: &[&str]) -> super::super::ServerArgs {
    let super::super::Command::Server(args) = super::super::Cli::try_parse_from(arguments)
        .unwrap()
        .command
    else {
        panic!("server arguments required")
    };
    args
}

#[test]
fn remote_activation_is_explicit_and_ca_override_requires_listener() {
    let args = parsed(&["infraternal", "server", "--listen", "127.0.0.1:4701"]);
    assert!(args.remote.remote_listen.is_none());
    assert!(args.remote.remote_ca_dir.is_none());
    assert!(
        super::super::Cli::try_parse_from([
            "infraternal",
            "server",
            "--remote-ca-dir",
            "/unused/private/ca"
        ])
        .is_err()
    );
    let args = parsed(&[
        "infraternal",
        "server",
        "--remote-listen",
        "10.69.69.125:7443",
        "--remote-ca-dir",
        "/unused/private/ca",
    ]);
    assert_eq!(
        args.remote.remote_listen.unwrap(),
        "10.69.69.125:7443".parse().unwrap()
    );
    assert_eq!(
        args.remote.remote_ca_dir.unwrap(),
        PathBuf::from("/unused/private/ca")
    );
}

#[test]
fn service_dry_run_preserves_remote_listener_and_private_trust_path() {
    let args = parsed(&[
        "infraternal",
        "server",
        "--listen",
        "127.0.0.1:4701",
        "--tls-cert",
        "server.pem",
        "--tls-key",
        "server.key",
        "--remote-listen",
        "10.69.69.125:7443",
        "--remote-ca-dir",
        "/unused/private ca",
    ]);
    let options = super::super::InstallArgs {
        system: false,
        user: true,
        dry_run: true,
        force: false,
        name: "remote-proof".into(),
    };
    let unit = super::super::install::install(&args, &options).unwrap();
    assert!(unit.contains("--remote-listen"));
    assert!(unit.contains("10.69.69.125:7443"));
    assert!(unit.contains("--remote-ca-dir"));
    assert!(unit.contains("/unused/private ca"));
    assert!(unit.contains("KillMode=process"));
}

#[tokio::test]
async fn missing_ca_refuses_before_database_or_listener_creation() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../.scratch/missing-ca-{}",
        uuid::Uuid::new_v4()
    ));
    let config = infraternal_server::ServerConfig {
        listen: "127.0.0.1:4701".parse().unwrap(),
        data_dir: directory.join("db"),
        public_origin: "https://localhost:4701".into(),
        web_root: None,
        tls: Some(infraternal_server::TlsFiles {
            certificate: directory.join("server.pem"),
            private_key: directory.join("server.key"),
        }),
        behind_proxy: false,
        trusted_proxies: vec![],
    };
    assert!(
        serve(
            config,
            Options {
                remote_listen: Some("127.0.0.1:7443".parse().unwrap()),
                remote_ca_dir: Some(directory.join("ca"))
            }
        )
        .await
        .is_err()
    );
    assert!(!directory.exists());
}
