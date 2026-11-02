//! Exercises drain, restart, and secret-safe proxy log behavior [#281, #289].

use super::supervisor::{
    DRAIN_TIMEOUT, Lifecycle, LifecycleAction, LifecyclePhase, SupervisorSettings, TraefikChild,
    TraefikSupervisor, check_private_ping, redact_log_line,
};
use crate::{
    config::{
        DYNAMIC_CONFIG_FILENAME, DnsChallenge, ListenerPorts, PublishedService, StaticConfig,
    },
    names::CertificateName,
};
use std::{
    env,
    io::{BufRead, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
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
        while served < expected_responses {
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
            let Some((stream, _)) = accepted else {
                eprintln!(
                    "private health fixture accepted {served} of {expected_responses} expected requests"
                );
                break;
            };
            let mut request = std::io::BufReader::new(stream);
            let mut request_line = String::new();
            if let Err(error) = request.read_line(&mut request_line) {
                eprintln!("private health fixture could not read request: {error}");
                break;
            }
            loop {
                let mut line = String::new();
                if request.read_line(&mut line).is_err() || line.is_empty() || line == "\r\n" {
                    break;
                }
            }
            let response = if request_line.starts_with("GET /api/rawdata ") {
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".as_slice()
            } else if request_line.starts_with("GET /ping ") {
                responses[served]
            } else {
                eprintln!("private health fixture received an unexpected request");
                break;
            };
            if let Err(error) = request.get_mut().write_all(response) {
                eprintln!("private health fixture could not write response: {error}");
                break;
            }
            if request_line.starts_with("GET /ping ") {
                served += 1;
                eprintln!("private health fixture answered request {served}/{expected_responses}");
            }
        }
    });
    (address, server)
}

#[cfg(target_os = "linux")]
#[test]
fn abrupt_parent_helper_exits() {
    let Some(root) = env::var_os("PROXY_CRASH_HELPER_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let executable = root.join("fake-traefik");
    let config = root.join("traefik.toml");
    let pid_file = root.join("child.pid");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nexec /bin/sleep 60\n",
            pid_file.display()
        ),
    )
    .expect("write child fixture");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500))
        .expect("set private executable mode");
    std::fs::write(&config, b"{}").expect("write config fixture");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
        .expect("set private config mode");

    let log = std::sync::Arc::new(|_: String| {});
    let _child = TraefikChild::spawn(&executable, &config, &[], log).expect("spawn child");
    let deadline = Instant::now() + Duration::from_secs(3);
    while !pid_file.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        pid_file.exists(),
        "fake child did not record its process id"
    );
    std::process::exit(0);
}

#[cfg(target_os = "linux")]
#[test]
fn abrupt_infraternal_parent_exit_stops_the_traefik_child() {
    let root = std::env::temp_dir().join(format!("proxy-crash-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).expect("create crash fixture");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("set private fixture mode");

    let helper = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "supervisor_tests::abrupt_parent_helper_exits",
            "--nocapture",
        ])
        .env("PROXY_CRASH_HELPER_ROOT", &root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run abrupt-exit fixture");
    assert!(
        helper.success(),
        "abrupt-exit fixture did not start the child"
    );

    let child_pid = std::fs::read_to_string(root.join("child.pid"))
        .expect("child pid file")
        .parse::<u32>()
        .expect("child process id");
    let child_proc = PathBuf::from(format!("/proc/{child_pid}/stat"));
    let deadline = Instant::now() + Duration::from_secs(3);
    let stopped = loop {
        match std::fs::read_to_string(&child_proc) {
            Ok(stat) => {
                let state = stat
                    .rsplit_once(") ")
                    .and_then(|(_, rest)| rest.chars().next());
                if state == Some('Z') {
                    break true;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break true,
            Err(_) => {}
        }
        if Instant::now() >= deadline {
            break false;
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !stopped {
        let _ = Command::new("kill")
            .args(["-KILL", &child_pid.to_string()])
            .status();
    }
    std::fs::remove_dir_all(root).expect("remove crash fixture");
    assert!(stopped, "Traefik kept serving after its parent exited");
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
        static_config_path: root.join("static.toml"),
        dynamic_config_path: state.join(DYNAMIC_CONFIG_FILENAME),
        static_config: StaticConfig {
            mesh_address: "10.77.0.1".parse().expect("mesh address"),
            ports: ListenerPorts {
                http: 10080,
                https: 10443,
                mesh_http: Some(10081),
                mesh_https: Some(10444),
            },
            private_ping_port: health_address.port(),
            dynamic_directory: state,
            dns_challenge: DnsChallenge {
                provider: "httpreq".to_owned(),
                email: "operator@example.test".to_owned(),
                storage_path: acme_storage,
                ca_server: Some("https://127.0.0.1:14000/dir".to_owned()),
                resolvers: Vec::new(),
                disable_authoritative_ns_checks: false,
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
        https_port: 10_443,
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
fn mesh_grant_revocation_removes_the_route_before_narrowing_its_allowlist() {
    let root = std::env::temp_dir().join(format!("proxy-revocation-{}", uuid::Uuid::new_v4()));
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
    let dynamic_path = state.join(DYNAMIC_CONFIG_FILENAME);
    let probe = generation_probe_server(dynamic_path.clone(), false);
    let settings = generation_probe_settings(&root, &state, executable, probe.address);
    let supervisor = TraefikSupervisor::start(settings, std::sync::Arc::new(|_: String| {}))
        .expect("start idle supervisor");
    let mut service = PublishedService {
        id: "docs".to_owned(),
        hostname: "docs.n1.example.test".to_owned(),
        backend: "127.0.0.1:3000".parse().expect("backend"),
        allowed_sources: vec![
            "10.77.0.2".parse().expect("first granted peer"),
            "10.77.0.3".parse().expect("second granted peer"),
        ],
        public: false,
        https_port: 10_443,
        certificate: CertificateName::Wildcard("*.n1.example.test".to_owned()),
    };
    supervisor
        .replace(vec![service.clone()])
        .expect("start one process for the authorized route");
    service.allowed_sources = vec!["10.77.0.3".parse().expect("remaining granted peer")];

    thread::scope(|scope| {
        let (result_sender, result_receiver) = mpsc::channel();
        let update = scope.spawn(move || {
            result_sender
                .send(supervisor.replace(vec![service]))
                .expect("send route replacement result");
        });

        let observation = probe
            .pending_snapshot
            .recv_timeout(Duration::from_secs(2))
            .expect("supervisor must await the route-removal generation");
        assert!(
            observation
                .headers
                .to_ascii_lowercase()
                .contains("x-infraternal-config-generation:"),
            "generation probe must identify the snapshot it is checking"
        );
        assert!(
            !observation.snapshot.contains("docs.n1.example.test"),
            "the previously authorized route must be removed while the narrower grant is pending"
        );
        assert!(
            result_receiver.try_recv().is_err(),
            "revocation must remain unacknowledged until Traefik confirms route removal"
        );

        probe
            .release_pending
            .send(())
            .expect("release applied generation");
        result_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("route update response")
            .expect("confirm the narrowed route snapshot")
            .expect("listener ports");
        update.join().expect("finish route update");
    });

    let final_snapshot = std::fs::read_to_string(dynamic_path).expect("read narrowed route");
    assert!(final_snapshot.contains("docs.n1.example.test"));
    assert!(final_snapshot.contains("10.77.0.3/32"));
    assert!(!final_snapshot.contains("10.77.0.2/32"));
    drop(probe);
    std::fs::remove_dir_all(root).expect("remove supervisor fixture");
}

#[test]
fn unconfirmed_route_removal_stops_the_proxy_and_returns_a_timeout() {
    let root = std::env::temp_dir().join(format!("proxy-config-timeout-{}", uuid::Uuid::new_v4()));
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
    let dynamic_path = state.join(DYNAMIC_CONFIG_FILENAME);
    let probe = generation_probe_server(dynamic_path, true);
    let supervisor = TraefikSupervisor::start(
        generation_probe_settings(&root, &state, executable, probe.address),
        std::sync::Arc::new(|_: String| {}),
    )
    .expect("start idle supervisor");
    let service = PublishedService {
        id: "docs".to_owned(),
        hostname: "docs.n1.example.test".to_owned(),
        backend: "127.0.0.1:3000".parse().expect("backend"),
        allowed_sources: vec!["10.77.0.2".parse().expect("mesh peer")],
        public: false,
        https_port: 10_443,
        certificate: CertificateName::Wildcard("*.n1.example.test".to_owned()),
    };
    supervisor
        .replace(vec![service])
        .expect("start one process for the authorized route");

    let error = supervisor
        .replace(Vec::new())
        .expect_err("an unconfirmed empty route snapshot must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        !supervisor.is_running().expect("observe stopped proxy"),
        "an unconfirmed revocation must stop the child and deny all routes"
    );
    drop(supervisor);
    drop(probe);
    std::fs::remove_dir_all(root).expect("remove supervisor fixture");
}

struct ConfigGenerationObservation {
    headers: String,
    snapshot: String,
}

struct GenerationProbe {
    address: SocketAddr,
    pending_snapshot: mpsc::Receiver<ConfigGenerationObservation>,
    release_pending: mpsc::Sender<()>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Drop for GenerationProbe {
    fn drop(&mut self) {
        let _ = self.release_pending.send(());
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn generation_probe_server(
    dynamic_path: PathBuf,
    reject_after_first_generation: bool,
) -> GenerationProbe {
    use std::sync::atomic::{AtomicBool, Ordering};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind private generation probe");
    listener
        .set_nonblocking(true)
        .expect("make private probe interruptible");
    let address = listener.local_addr().expect("generation probe address");
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let worker_stop = std::sync::Arc::clone(&stop);
    let (pending_sender, pending_snapshot) = mpsc::channel();
    let (release_pending, released) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut generation_requests = 0;
        while !worker_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let mut request = std::io::BufReader::new(stream);
                    let mut request_line = String::new();
                    if request.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut headers = String::new();
                    loop {
                        let mut line = String::new();
                        if request.read_line(&mut line).is_err() || line.is_empty() {
                            break;
                        }
                        if line == "\r\n" {
                            break;
                        }
                        headers.push_str(&line);
                    }
                    if request_line.starts_with("GET /api/rawdata ") {
                        generation_requests += 1;
                        if generation_requests == 2 && !reject_after_first_generation {
                            let snapshot = std::fs::read_to_string(&dynamic_path)
                                .expect("read staged route-removal snapshot");
                            let _ = pending_sender
                                .send(ConfigGenerationObservation { headers, snapshot });
                            let _ = released.recv_timeout(Duration::from_secs(3));
                        }
                    }
                    let response = if request_line.starts_with("GET /ping ") {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                            .as_slice()
                    } else if reject_after_first_generation && generation_requests > 1 {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .as_slice()
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".as_slice()
                    };
                    let _ = request.get_mut().write_all(response);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    });
    GenerationProbe {
        address,
        pending_snapshot,
        release_pending,
        stop,
        worker: Some(worker),
    }
}

fn generation_probe_settings(
    root: &Path,
    state: &Path,
    executable: PathBuf,
    address: SocketAddr,
) -> SupervisorSettings {
    let acme_storage = state.join("acme.json");
    std::fs::write(&acme_storage, b"{}").expect("write persistent ACME fixture");
    std::fs::set_permissions(&acme_storage, std::fs::Permissions::from_mode(0o600))
        .expect("private ACME mode");
    SupervisorSettings {
        executable,
        static_config_path: root.join("static.toml"),
        dynamic_config_path: state.join(DYNAMIC_CONFIG_FILENAME),
        static_config: StaticConfig {
            mesh_address: "10.77.0.1".parse().expect("mesh address"),
            ports: ListenerPorts {
                http: 10_080,
                https: 10_443,
                mesh_http: Some(10_081),
                mesh_https: Some(10_444),
            },
            private_ping_port: address.port(),
            dynamic_directory: state.to_owned(),
            dns_challenge: DnsChallenge {
                provider: "httpreq".to_owned(),
                email: "operator@example.test".to_owned(),
                storage_path: acme_storage,
                ca_server: Some("https://127.0.0.1:14000/dir".to_owned()),
                resolvers: Vec::new(),
                disable_authoritative_ns_checks: false,
            },
        },
        provider_files: Vec::new(),
        private_ping_address: address,
        startup_timeout: Duration::from_secs(2),
    }
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
        static_config_path: root.join("static.toml"),
        dynamic_config_path: state.join(DYNAMIC_CONFIG_FILENAME),
        static_config: StaticConfig {
            mesh_address: "10.77.0.1".parse().expect("mesh address"),
            ports: ListenerPorts {
                http: 10080,
                https: 10443,
                mesh_http: Some(10081),
                mesh_https: Some(10444),
            },
            private_ping_port: health_address.port(),
            dynamic_directory,
            dns_challenge: DnsChallenge {
                provider: "httpreq".to_owned(),
                email: "operator@example.test".to_owned(),
                storage_path: acme_storage.clone(),
                ca_server: Some("https://127.0.0.1:14000/dir".to_owned()),
                resolvers: Vec::new(),
                disable_authoritative_ns_checks: false,
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
        // The route starts with the controller's fallback. The supervisor must
        // replace it with the selected listener before rendering a redirect.
        https_port: 443,
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
            mesh_http: Some(10_081),
            mesh_https: Some(10_444),
        }
    );
    assert!(supervisor.is_running().expect("process after first route"));
    let dynamic_path = state.join(DYNAMIC_CONFIG_FILENAME);
    let dynamic = std::fs::read_to_string(&dynamic_path).expect("read published route");
    assert!(dynamic.contains("docs.n1.example.test"));
    assert!(
        dynamic.contains("\"port\":\"10444\""),
        "HTTP redirect must use the selected HTTPS listener port: {dynamic}"
    );

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
