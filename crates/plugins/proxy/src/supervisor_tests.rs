//! Exercises drain, restart, and secret-safe proxy log behavior [#281, #289].

use super::supervisor::{
    DRAIN_TIMEOUT, Lifecycle, LifecycleAction, LifecyclePhase, SupervisorSettings,
    TraefikSupervisor, check_private_ping, redact_log_line,
};
use crate::{
    config::{DnsChallenge, ListenerPorts, PublishedService, StaticConfig},
    names::CertificateName,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

fn health_server(response: &'static [u8]) -> (SocketAddr, JoinHandle<()>) {
    health_server_sequence(vec![response])
}

fn health_server_sequence(responses: Vec<&'static [u8]>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind private health fixture");
    listener
        .set_nonblocking(true)
        .expect("make private fixture interruptible");
    let address = listener.local_addr().expect("health fixture address");
    let server = thread::spawn(move || {
        let expected_responses = responses.len();
        let mut served = 0;
        for response in responses {
            let deadline = Instant::now() + Duration::from_secs(1);
            let accepted = loop {
                match listener.accept() {
                    Ok(accepted) => break Some(accepted),
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break None,
                }
            };
            let Some((mut stream, _)) = accepted else {
                eprintln!(
                    "private health fixture accepted {served} of {expected_responses} expected requests"
                );
                break;
            };
            let mut request = [0_u8; 20];
            if let Err(error) = stream.read_exact(&mut request) {
                eprintln!("private health fixture could not read request: {error}");
                break;
            }
            if &request != b"GET /ping HTTP/1.1\r\n" {
                eprintln!("private health fixture received an unexpected request prefix");
                break;
            }
            if let Err(error) = stream.write_all(response) {
                eprintln!("private health fixture could not write response: {error}");
                break;
            }
            served += 1;
            eprintln!("private health fixture answered request {served}/{expected_responses}");
        }
    });
    (address, server)
}

#[test]
fn final_exposure_starts_one_ten_second_drain_then_stops_once() {
    let start = Instant::now();
    let mut lifecycle = Lifecycle::default();

    assert_eq!(lifecycle.update(1, start), LifecycleAction::Start);
    assert_eq!(lifecycle.phase(), LifecyclePhase::Starting);
    lifecycle.child_started(1, start);
    assert_eq!(lifecycle.phase(), LifecyclePhase::Running);
    assert_eq!(lifecycle.update(0, start), LifecycleAction::BeginDrain);
    assert_eq!(
        lifecycle.phase(),
        LifecyclePhase::Draining {
            deadline: start + DRAIN_TIMEOUT
        }
    );
    assert_eq!(
        lifecycle.tick(
            0,
            start + DRAIN_TIMEOUT.saturating_sub(Duration::from_millis(1)),
        ),
        LifecycleAction::Keep
    );
    assert_eq!(
        lifecycle.tick(0, start + DRAIN_TIMEOUT),
        LifecycleAction::Stop
    );
    assert_eq!(lifecycle.phase(), LifecyclePhase::Stopped);
    assert_eq!(
        lifecycle.tick(0, start + DRAIN_TIMEOUT + Duration::from_secs(1)),
        LifecycleAction::Keep
    );
}

#[test]
fn a_new_exposure_cancels_the_drain_without_restarting_the_child() {
    let start = Instant::now();
    let mut lifecycle = Lifecycle::default();
    assert_eq!(lifecycle.update(1, start), LifecycleAction::Start);
    lifecycle.child_started(1, start);
    assert_eq!(lifecycle.update(0, start), LifecycleAction::BeginDrain);

    assert_eq!(
        lifecycle.update(1, start + Duration::from_secs(4)),
        LifecycleAction::Apply
    );
    assert_eq!(lifecycle.phase(), LifecyclePhase::Running);
    assert_eq!(
        lifecycle.tick(1, start + DRAIN_TIMEOUT),
        LifecycleAction::Keep
    );
}

#[test]
fn unexpected_exits_back_off_and_never_restart_without_exposures() {
    let start = Instant::now();
    let mut lifecycle = Lifecycle::default();
    assert_eq!(lifecycle.child_exited(0, start), LifecycleAction::Keep);
    assert_eq!(lifecycle.phase(), LifecyclePhase::Stopped);

    let first_delay = Duration::from_millis(200);
    let max_delay = Duration::from_secs(30);
    assert_eq!(
        lifecycle.child_exited(1, start),
        LifecycleAction::RetryAfter(first_delay)
    );
    assert_eq!(
        lifecycle.tick(
            1,
            start + first_delay.saturating_sub(Duration::from_millis(1)),
        ),
        LifecycleAction::Keep
    );
    assert_eq!(
        lifecycle.tick(1, start + first_delay),
        LifecycleAction::Start
    );
    lifecycle.child_started(1, start + first_delay);

    let mut now = start + first_delay;
    let mut delay = first_delay * 2;
    for _ in 0..10 {
        let action = lifecycle.child_exited(1, now);
        assert_eq!(action, LifecycleAction::RetryAfter(delay));
        assert!(delay <= max_delay);
        now += delay;
        assert_eq!(lifecycle.tick(1, now), LifecycleAction::Start);
        lifecycle.child_started(1, now);
        delay = delay.saturating_mul(2).min(max_delay);
    }
}

#[test]
fn provider_values_are_redacted_before_a_log_line_is_emitted() {
    let line = "provider failed for dns token=secret-value-123";
    let redacted = redact_log_line(line, &["secret-value-123"]);
    assert!(!redacted.contains("secret-value-123"));
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn authorization_cookie_and_query_credentials_are_redacted_without_known_values() {
    let line = "request failed Authorization: Bearer header-secret Cookie: session=cookie-secret url=https://dns.invalid/?api_key=query-secret";
    let redacted = redact_log_line(line, &[]);

    for secret in ["header-secret", "cookie-secret", "query-secret"] {
        assert!(!redacted.contains(secret), "credential leaked: {secret}");
    }
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn private_health_ping_accepts_a_success_response() {
    let (address, server) = health_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
    check_private_ping(address, Duration::from_secs(1)).expect("healthy private ping");
    server.join().expect("health fixture thread");
}

#[test]
fn private_health_ping_rejects_non_loopback_addresses() {
    assert_eq!(
        check_private_ping(
            "192.0.2.1:19999".parse().expect("non-loopback address"),
            Duration::from_millis(1),
        )
        .expect_err("health probe must never leave loopback")
        .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn private_health_ping_rejects_an_unhealthy_response() {
    let (address, server) =
        health_server(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
    assert!(check_private_ping(address, Duration::from_secs(1)).is_err());
    server.join().expect("health fixture thread");
}

#[test]
fn live_process_without_a_healthy_private_ping_is_reported_unhealthy() {
    const HEALTHY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    const UNHEALTHY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
    let root = std::env::temp_dir().join(format!("proxy-unhealthy-{}", uuid::Uuid::new_v4()));
    let state = root.join("state");
    std::fs::create_dir_all(&state).expect("create supervisor state");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private fixture root");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("private fixture state");

    let executable = root.join("fake-traefik");
    std::fs::write(&executable, b"#!/bin/sh\nexec /bin/sleep 60\n").expect("write fake Traefik");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500))
        .expect("private executable mode");
    let acme_storage = state.join("acme.json");
    std::fs::write(&acme_storage, b"{}").expect("write persistent ACME fixture");
    std::fs::set_permissions(&acme_storage, std::fs::Permissions::from_mode(0o600))
        .expect("private ACME mode");

    let (health_address, health_server) = health_server_sequence(vec![HEALTHY, UNHEALTHY]);
    let settings = SupervisorSettings {
        executable,
        static_config_path: state.join("static.toml"),
        dynamic_config_path: state.join("dynamic.json"),
        static_config: StaticConfig {
            mesh_address: "10.77.0.1".parse().expect("mesh address"),
            ports: ListenerPorts {
                http: 10080,
                https: 10443,
            },
            public: false,
            private_ping_port: health_address.port(),
            dynamic_directory: state,
            dns_challenge: DnsChallenge {
                provider: "httpreq".to_owned(),
                email: "operator@example.test".to_owned(),
                storage_path: acme_storage,
                ca_server: Some("https://127.0.0.1:14000/dir".to_owned()),
            },
        },
        provider_files: Vec::new(),
        private_ping_address: health_address,
        startup_timeout: Duration::from_secs(2),
    };
    let log = std::sync::Arc::new(|_: String| {});
    let supervisor = TraefikSupervisor::start(settings, log).expect("start idle supervisor");
    let service = PublishedService {
        id: "docs".to_owned(),
        hostname: "docs.n1.example.test".to_owned(),
        backend: "127.0.0.1:3000".parse().expect("backend"),
        allowed_sources: vec!["10.77.0.2".parse().expect("mesh peer")],
        public: false,
        certificate: CertificateName::Wildcard("*.n1.example.test".to_owned()),
    };
    supervisor
        .replace(vec![service])
        .expect("start one process for the route");
    let healthy = supervisor
        .is_running()
        .expect("read process and private health state");
    health_server.join().expect("join private health fixture");
    drop(supervisor);
    std::fs::remove_dir_all(root).expect("remove supervisor fixture");

    assert!(
        !healthy,
        "a live child with a failed private ping is unhealthy"
    );
}

#[test]
fn owned_supervisor_starts_on_first_exposure_drains_routes_and_keeps_acme_state() {
    let root = std::env::temp_dir().join(format!("proxy-supervisor-{}", uuid::Uuid::new_v4()));
    let state = root.join("state");
    std::fs::create_dir_all(&state).expect("create supervisor state");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private fixture root");
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
        .expect("private fixture state");

    let executable = root.join("fake-traefik");
    std::fs::write(&executable, b"#!/bin/sh\nexec /bin/sleep 60\n").expect("write fake Traefik");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500))
        .expect("private executable mode");
    let acme_storage = state.join("acme.json");
    std::fs::write(&acme_storage, b"{}").expect("write persistent ACME fixture");
    std::fs::set_permissions(&acme_storage, std::fs::Permissions::from_mode(0o600))
        .expect("private ACME mode");

    let response: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let (health_address, health_server) = health_server_sequence(vec![response; 4]);
    let dynamic_directory = state.clone();
    let settings = SupervisorSettings {
        executable,
        static_config_path: state.join("static.toml"),
        dynamic_config_path: state.join("dynamic.json"),
        static_config: StaticConfig {
            mesh_address: "10.77.0.1".parse().expect("mesh address"),
            ports: ListenerPorts {
                http: 10080,
                https: 10443,
            },
            public: false,
            private_ping_port: health_address.port(),
            dynamic_directory,
            dns_challenge: DnsChallenge {
                provider: "httpreq".to_owned(),
                email: "operator@example.test".to_owned(),
                storage_path: acme_storage.clone(),
                ca_server: Some("https://127.0.0.1:14000/dir".to_owned()),
            },
        },
        provider_files: Vec::new(),
        private_ping_address: health_address,
        startup_timeout: Duration::from_secs(2),
    };
    let log = std::sync::Arc::new(|_: String| {});
    let supervisor = TraefikSupervisor::start(settings, log).expect("start idle supervisor");
    assert!(!supervisor.is_running().expect("read initial process state"));

    let service = PublishedService {
        id: "docs".to_owned(),
        hostname: "docs.n1.example.test".to_owned(),
        backend: "127.0.0.1:3000".parse().expect("backend"),
        allowed_sources: vec!["10.77.0.2".parse().expect("mesh peer")],
        public: false,
        certificate: CertificateName::Wildcard("*.n1.example.test".to_owned()),
    };
    let listener_ports = supervisor
        .replace(vec![service.clone()])
        .expect("start one process for the first route")
        .expect("started listener ports");
    assert_eq!(
        listener_ports,
        ListenerPorts {
            http: 10_080,
            https: 10_443,
        }
    );
    assert!(supervisor.is_running().expect("process after first route"));
    let dynamic_path = state.join("dynamic.json");
    let dynamic = std::fs::read_to_string(&dynamic_path).expect("read published route");
    assert!(dynamic.contains("docs.n1.example.test"));

    supervisor
        .replace(Vec::new())
        .expect("remove final route and begin drain")
        .expect("draining listener ports");
    assert!(supervisor.is_running().expect("process during drain"));
    let empty = std::fs::read_to_string(&dynamic_path).expect("read empty route snapshot");
    assert!(!empty.contains("docs.n1.example.test"));

    supervisor
        .replace(vec![service])
        .expect("new exposure cancels drain")
        .expect("resumed listener ports");
    assert!(supervisor.is_running().expect("process after drain cancel"));
    health_server.join().expect("join private health fixture");
    drop(supervisor);
    assert_eq!(
        std::fs::read(&acme_storage).expect("retain ACME state"),
        b"{}"
    );
    std::fs::remove_dir_all(root).expect("remove supervisor fixture");
}
