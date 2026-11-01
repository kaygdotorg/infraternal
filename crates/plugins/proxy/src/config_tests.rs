//! Traefik configuration must preserve mesh grants and node-local certificate identity [#281].

use super::config::{
    DnsChallenge, ListenerPorts, PublishedService, StaticConfig, detect_listener_ports,
    render_dynamic_config, render_static_config, select_listener_ports, write_config_atomic,
};
use crate::names::CertificateName;
use serde_json::Value;
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

fn mesh_service(sources: Vec<IpAddr>) -> PublishedService {
    PublishedService {
        id: "docs".to_owned(),
        hostname: "docs.build01.ssh.kayg.org".to_owned(),
        backend: "127.0.0.1:3000"
            .parse::<SocketAddr>()
            .expect("backend socket"),
        allowed_sources: sources,
        public: false,
        certificate: CertificateName::Wildcard("*.build01.ssh.kayg.org".to_owned()),
    }
}

fn static_config(public: bool) -> StaticConfig {
    StaticConfig {
        mesh_address: "100.64.0.2".parse().expect("mesh address"),
        ports: ListenerPorts {
            http: 10080,
            https: 10443,
        },
        public,
        private_ping_port: 19999,
        dynamic_directory: PathBuf::from("/var/lib/infraternal/proxy/config/dynamic"),
        dns_challenge: DnsChallenge {
            provider: "rfc2136".to_owned(),
            email: "operator@example.net".to_owned(),
            storage_path: PathBuf::from("/var/lib/infraternal/proxy/tls/acme.json"),
            ca_server: Some("https://pebble.invalid/dir".to_owned()),
        },
    }
}

#[test]
fn mesh_listener_uses_the_mesh_ip_and_disables_admin_and_usage_surfaces() {
    let rendered = render_static_config(&static_config(false)).expect("render static config");
    assert!(rendered.contains("100.64.0.2:10080"));
    assert!(rendered.contains("100.64.0.2:10443"));
    assert!(rendered.contains("127.0.0.1:19999"));
    assert!(rendered.contains("dashboard = false"));
    assert!(rendered.contains("insecure = false"));
    assert!(rendered.contains("sendAnonymousUsage = false"));
    assert!(!rendered.contains("0.0.0.0"));
    assert!(!rendered.contains("api@internal"));
}

#[test]
fn private_ping_is_routed_automatically_without_enabling_the_admin_api() {
    let rendered = render_static_config(&static_config(false)).expect("render static config");
    assert!(rendered.contains("[ping]"));
    assert!(rendered.contains("manualRouting = false"));
    assert!(rendered.contains("dashboard = false"));
    assert!(rendered.contains("insecure = false"));
}

#[test]
fn public_binding_is_explicit_and_root_and_rootless_ports_follow_the_owner_choice() {
    let root_free = select_listener_ports(true, true, true);
    assert_eq!(
        root_free,
        ListenerPorts {
            http: 80,
            https: 443
        }
    );
    assert_eq!(
        select_listener_ports(true, false, true),
        ListenerPorts {
            http: 10080,
            https: 10443,
        }
    );
    assert_eq!(
        select_listener_ports(false, true, true),
        ListenerPorts {
            http: 10080,
            https: 10443,
        }
    );

    let mesh_only = render_static_config(&static_config(false)).expect("mesh config");
    let public = render_static_config(&static_config(true)).expect("public config");
    assert!(mesh_only.contains("100.64.0.2:10443"));
    assert!(public.contains("0.0.0.0:10443"));
}

#[test]
fn rootless_port_detection_never_probes_or_selects_privileged_ports() {
    assert_eq!(
        detect_listener_ports(false, "10.77.0.1".parse().expect("mesh address"), false),
        ListenerPorts {
            http: 10080,
            https: 10443,
        }
    );
}

#[test]
fn dynamic_routes_match_one_host_and_apply_the_same_mesh_peer_grant() {
    let source = "100.64.0.5".parse().expect("mesh source");
    let bytes = render_dynamic_config(&[mesh_service(vec![source])]).expect("dynamic config");
    let config: Value = serde_json::from_slice(&bytes).expect("dynamic JSON");
    assert_eq!(
        config["http"]["routers"]["docs"]["rule"],
        "Host(`docs.build01.ssh.kayg.org`)"
    );
    assert_eq!(
        config["http"]["middlewares"]["docs-mesh-access"]["ipAllowList"]["sourceRange"][0],
        "100.64.0.5/32"
    );
    assert!(
        config["http"]["routers"]["docs"]["middlewares"][0]
            .as_str()
            .is_some_and(|middleware| middleware == "docs-mesh-access")
    );
    assert_eq!(
        config["http"]["routers"]["docs"]["tls"]["domains"][0]["main"],
        "*.build01.ssh.kayg.org"
    );
    assert!(bytes.windows(11).all(|window| window != b"X-Forwarded"));
}

#[test]
fn https_router_uses_the_exposure_id_and_http_redirect_uses_a_disjoint_key() {
    let source = "100.64.0.5".parse().expect("mesh source");
    let bytes = render_dynamic_config(&[mesh_service(vec![source])]).expect("dynamic config");
    let config: Value = serde_json::from_slice(&bytes).expect("dynamic JSON");

    assert_eq!(config["http"]["routers"]["docs"]["entryPoints"][0], "https");
    assert_eq!(
        config["http"]["routers"]["http.docs"]["entryPoints"][0],
        "http"
    );
}

#[test]
fn a_mesh_route_without_an_accepted_grant_fails_closed() {
    let error = render_dynamic_config(&[mesh_service(Vec::new())])
        .expect_err("denied route must not be rendered");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn atomic_config_writes_are_owner_only_and_replace_the_previous_snapshot() {
    let root = std::env::temp_dir().join(format!("proxy-config-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).expect("create config root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private root mode");
    let destination = root.join("dynamic.json");

    write_config_atomic(&destination, b"first").expect("write first snapshot");
    write_config_atomic(&destination, b"second").expect("replace snapshot");

    let metadata = fs::symlink_metadata(&destination).expect("config metadata");
    assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(fs::read(&destination).expect("config bytes"), b"second");
    fs::remove_dir_all(root).expect("remove config root");
}
