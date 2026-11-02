//! Traefik configuration must preserve mesh grants and node-local certificate identity [#281].

use super::config::{
    DnsChallenge, ListenerPorts, PublishedService, StaticConfig, detect_listener_ports,
    detect_mixed_listener_ports, render_dynamic_config, render_static_config,
    select_listener_ports, write_config_atomic,
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
        https_port: 10_443,
        certificate: CertificateName::Wildcard("*.build01.ssh.kayg.org".to_owned()),
    }
}

fn static_config(public: bool) -> StaticConfig {
    StaticConfig {
        mesh_address: "100.64.0.2".parse().expect("mesh address"),
        ports: ListenerPorts {
            http: 10080,
            https: 10443,
            mesh_http: None,
            mesh_https: None,
        },
        public,
        private_ping_port: 19999,
        dynamic_directory: PathBuf::from("/var/lib/infraternal/proxy/config/dynamic"),
        dns_challenge: DnsChallenge {
            provider: "rfc2136".to_owned(),
            email: "operator@example.net".to_owned(),
            storage_path: PathBuf::from("/var/lib/infraternal/proxy/tls/acme.json"),
            ca_server: Some("https://pebble.invalid/dir".to_owned()),
            resolvers: Vec::new(),
            disable_authoritative_ns_checks: false,
        },
    }
}

#[test]
fn mesh_listener_uses_the_mesh_ip_and_disables_admin_and_usage_surfaces() {
    let rendered = render_static_config(&static_config(false)).expect("render static config");
    assert!(rendered.contains("100.64.0.2:10080"));
    assert!(rendered.contains("100.64.0.2:10443"));
    assert!(rendered.contains("127.0.0.1:19999"));
    assert!(rendered.contains("sendAnonymousUsage = false"));
    assert!(!rendered.contains("0.0.0.0"));
    assert!(rendered.contains("[api]\ndashboard = false\ninsecure = false"));
    assert!(!rendered.contains("api@internal"));
}

#[test]
fn config_generation_probe_is_gated_on_the_loopback_health_entrypoint() {
    let dynamic = render_dynamic_config(&[]).expect("empty dynamic configuration");
    let dynamic: Value = serde_json::from_slice(&dynamic).expect("dynamic JSON");
    let probe = &dynamic["http"]["routers"]["infraternal-config-generation"];
    assert_eq!(probe["entryPoints"], serde_json::json!(["health"]));
    assert_eq!(probe["service"], "api@internal");
    let rule = probe["rule"].as_str().expect("generation route rule");
    assert!(rule.contains("Method(`GET`)") && rule.contains("Path(`/api/rawdata`)"));
    assert!(rule.contains("Header(`X-Infraternal-Config-Generation`, `"));
    assert!(!rule.contains("Headers("));

    let rendered_static_config =
        render_static_config(&static_config(false)).expect("private static config");
    assert!(rendered_static_config.contains("\n[api]\ndashboard = false\ninsecure = false"));
    assert!(rendered_static_config.contains("[entryPoints.health]\naddress = \"127.0.0.1:"));
}

#[test]
fn private_ping_and_generation_probe_use_only_the_loopback_api_surface() {
    let rendered = render_static_config(&static_config(false)).expect("render static config");
    assert!(rendered.contains("[ping]"));
    assert!(rendered.contains("manualRouting = false"));
    assert!(rendered.contains("[api]\ndashboard = false\ninsecure = false"));
    assert!(rendered.contains("[entryPoints.health]\naddress = \"127.0.0.1:"));
}

#[test]
fn public_binding_is_explicit_and_root_and_rootless_ports_follow_the_owner_choice() {
    let root_free = select_listener_ports(true, true, true);
    assert_eq!(
        root_free,
        ListenerPorts {
            http: 80,
            https: 443,
            mesh_http: None,
            mesh_https: None,
        }
    );
    assert_eq!(
        select_listener_ports(true, false, true),
        ListenerPorts {
            http: 10080,
            https: 10443,
            mesh_http: None,
            mesh_https: None,
        }
    );
    assert_eq!(
        select_listener_ports(false, true, true),
        ListenerPorts {
            http: 10080,
            https: 10443,
            mesh_http: None,
            mesh_https: None,
        }
    );

    let mesh_only = render_static_config(&static_config(false)).expect("mesh config");
    let public = render_static_config(&static_config(true)).expect("public config");
    assert!(mesh_only.contains("100.64.0.2:10443"));
    assert!(public.contains("0.0.0.0:10443"));
}

#[test]
fn mixed_public_and_mesh_routes_use_separate_listeners() {
    let source = "100.64.0.5".parse().expect("mesh source");
    let mesh = mesh_service(vec![source]);
    let mut public = mesh_service(Vec::new());
    public.id = "status".to_owned();
    public.hostname = "status.build01.ssh.kayg.org".to_owned();
    public.public = true;
    public.https_port = 443;

    let dynamic = render_dynamic_config(&[mesh, public]).expect("mixed dynamic config");
    let dynamic: Value = serde_json::from_slice(&dynamic).expect("dynamic JSON");
    assert_eq!(
        dynamic["http"]["routers"]["http.docs"]["entryPoints"],
        serde_json::json!(["mesh-http"])
    );
    assert_eq!(
        dynamic["http"]["routers"]["docs"]["entryPoints"],
        serde_json::json!(["mesh-https"])
    );
    assert_eq!(
        dynamic["http"]["routers"]["http.status"]["entryPoints"],
        serde_json::json!(["http"])
    );
    assert_eq!(
        dynamic["http"]["routers"]["status"]["entryPoints"],
        serde_json::json!(["https"])
    );
    assert_eq!(
        dynamic["http"]["middlewares"]["docs-https-redirect"]["redirectScheme"]["port"],
        "10443"
    );
    assert_eq!(
        dynamic["http"]["middlewares"]["status-https-redirect"]["redirectScheme"]["port"],
        "443"
    );
}

#[test]
fn mixed_public_static_config_keeps_mesh_listeners_bound_to_the_mesh_ip() {
    let mut config = static_config(true);
    config.ports = ListenerPorts {
        http: 80,
        https: 443,
        mesh_http: Some(10080),
        mesh_https: Some(10443),
    };
    let rendered = render_static_config(&config).expect("mixed static config");
    assert!(rendered.contains("[entryPoints.mesh-http]"));
    assert!(rendered.contains("100.64.0.2:10080"));
    assert!(rendered.contains("[entryPoints.mesh-https]"));
    assert!(rendered.contains("100.64.0.2:10443"));
}

#[test]
fn mixed_listener_selection_keeps_public_and_mesh_ports_disjoint() {
    let ports = detect_mixed_listener_ports(false, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        .expect("select separate rootless listeners");

    assert_eq!(ports.http, 10_080);
    assert_eq!(ports.https, 10_443);
    let mesh_http = ports.mesh_http.expect("mesh HTTP listener");
    let mesh_https = ports.mesh_https.expect("mesh HTTPS listener");
    assert_ne!(mesh_http, ports.http);
    assert_ne!(mesh_http, ports.https);
    assert_ne!(mesh_https, ports.http);
    assert_ne!(mesh_https, ports.https);
    assert_ne!(mesh_http, mesh_https);
}

#[test]
fn every_mixed_listener_port_is_allowed_by_the_mesh_firewall_backends() {
    let allowed_ranges = &infraternal_mesh::proxy_ports::PROXY_INGRESS_PORT_RANGES;
    let pairs = std::iter::once(infraternal_mesh::proxy_ports::CONVENTIONAL_LISTENER_PAIR)
        .chain(std::iter::once(
            infraternal_mesh::proxy_ports::UNPRIVILEGED_LISTENER_PAIR,
        ))
        .chain(
            infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS
                .iter()
                .copied(),
        );
    for pair in pairs {
        for port in [pair.http, pair.https] {
            assert!(
                allowed_ranges.iter().any(|range| range.contains(port)),
                "mesh ingress firewall must allow proxy port {port}"
            );
        }
    }
}

#[test]
fn explicit_dns_resolver_is_rendered_for_staging_acme_validation() {
    let mut config = static_config(false);
    config.dns_challenge.resolvers = vec!["127.0.0.1:8053".parse().expect("Pebble DNS resolver")];

    let rendered = render_static_config(&config).expect("render static config");

    assert!(rendered.contains("resolvers = [\"127.0.0.1:8053\"]"));
}

#[test]
fn synthetic_dns_validation_can_skip_authoritative_checks_and_keep_recursive_checks() {
    let mut config = static_config(false);
    config.dns_challenge.resolvers = vec!["127.0.0.1:8053".parse().expect("test DNS resolver")];
    config.dns_challenge.disable_authoritative_ns_checks = true;

    let rendered = render_static_config(&config).expect("render staging ACME config");

    assert!(rendered.contains("[certificatesResolvers.dns.acme.dnsChallenge.propagation]"));
    assert!(rendered.contains("disableANSChecks = true"));
    assert!(rendered.contains("resolvers = [\"127.0.0.1:8053\"]"));
}

#[test]
fn rootless_port_detection_never_probes_or_selects_privileged_ports() {
    assert_eq!(
        detect_listener_ports(false, "10.77.0.1".parse().expect("mesh address"), false),
        ListenerPorts {
            http: 10080,
            https: 10443,
            mesh_http: None,
            mesh_https: None,
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
    assert_eq!(
        config["http"]["middlewares"]["docs-https-redirect"]["redirectScheme"]["port"],
        "10443"
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
    let destination = root.join(crate::config::DYNAMIC_CONFIG_FILENAME);

    write_config_atomic(&destination, b"first").expect("write first snapshot");
    write_config_atomic(&destination, b"second").expect("replace snapshot");

    let metadata = fs::symlink_metadata(&destination).expect("config metadata");
    assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(fs::read(&destination).expect("config bytes"), b"second");
    fs::remove_dir_all(root).expect("remove config root");
}
