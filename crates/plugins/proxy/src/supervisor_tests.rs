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

/// Lay out a supervisor fixture with the production directory policy for this process.
///
/// As root the child-readable directories become 0750 owned by the agent with the
/// child's group, exactly as the agent prepares them; rootless they stay 0700.
/// Returns the dynamic-config directory and the agent-only lock directory.
fn supervisor_fixture(root: &Path) -> (PathBuf, PathBuf) {
    let state = root.join("state");
    std::fs::create_dir_all(&state).expect("create supervisor state");
    for directory in [root, state.as_path()] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .expect("private fixture directory");
        crate::controller::ensure_proxy_directory(directory).expect("child-readable directory");
    }
    let private = root.join("private");
    crate::controller::ensure_private_directory(&private).expect("agent-only lock directory");
    (state, private)
}

/// Install a fake Traefik with the executable policy the supervisor enforces.
fn fake_traefik(path: &Path, script: &[u8]) {
    std::fs::write(path, script).expect("write fake Traefik");
    if crate::identity::rootful() {
        let (_, group) = crate::identity::child_ids().expect("proxy identity");
        nix::unistd::chown(path, None, Some(nix::unistd::Gid::from_raw(group)))
            .expect("hand fake Traefik to the child group");
    }
    let mode = if crate::identity::rootful() {
        0o550
    } else {
        0o500
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("executable fixture mode");
}

/// Create the ACME storage file the way the agent does.
fn acme_fixture(state: &Path) -> PathBuf {
    let path = state.join("acme.json");
    crate::controller::ensure_private_file(&path).expect("ACME storage fixture");
    path
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
    // The child may run as the proxy identity, so it reports through its own output.
    fake_traefik(
        &executable,
        b"#!/bin/sh\nprintf 'child-pid=%s\\n' \"$$\"\nexec /bin/sleep 60\n",
    );
    crate::config::write_proxy_config_atomic(&config, b"{}").expect("write config fixture");
    let pid_file = root.join("child.pid");
    let (reported, received) = std::sync::mpsc::channel();
    let log = std::sync::Arc::new(move |line: String| {
        if let Some(pid) = line.strip_prefix("child-pid=") {
            let _ = reported.send(pid.to_owned());
        }
    });

    let _child = TraefikChild::spawn(&executable, &config, &[], log).expect("spawn child");
    let pid = received
        .recv_timeout(Duration::from_secs(3))
        .expect("fake child did not report its process id");
    std::fs::write(&pid_file, pid).expect("record child process id");
    std::process::exit(0);
}

#[cfg(target_os = "linux")]
#[test]
fn abrupt_infraternal_parent_exit_stops_the_traefik_child() {
    let root = std::env::temp_dir().join(format!("proxy-crash-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).expect("create crash fixture");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("set private fixture mode");
    crate::controller::ensure_proxy_directory(&root).expect("child-readable fixture directory");

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
    let survivor = if stopped {
        String::new()
    } else {
        let status =
            std::fs::read_to_string(child_proc.with_file_name("status")).unwrap_or_default();
        let _ = Command::new("kill")
            .args(["-KILL", &child_pid.to_string()])
            .status();
        status
            .lines()
            .filter(|line| {
                [
                    "State",
                    "PPid",
                    "Uid",
                    "Gid",
                    "SigBlk",
                    "SigIgn",
                    "NoNewPrivs",
                ]
                .iter()
                .any(|field| line.starts_with(field))
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    std::fs::remove_dir_all(root).expect("remove crash fixture");
    assert!(
        stopped,
        "Traefik kept serving after its parent exited: {survivor}"
    );
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
fn newline_terminated_provider_values_are_redacted_after_log_normalization() {
    let line = "provider error included secret-value-123";

    for secret in ["secret-value-123\n", "secret-value-123\r\n"] {
        let redacted = redact_log_line(line, &[secret]);
        assert!(!redacted.contains("secret-value-123"));
        assert!(redacted.contains("[REDACTED]"));
    }
}

#[test]
fn provider_values_are_redacted_as_the_dns_client_trims_them() {
    // The DNS client trims all surrounding whitespace from a `*_FILE` value before use.
    let line = "provider error included secret-value-123 in its request";
    for secret in [
        "secret-value-123 \n",
        "\tsecret-value-123",
        " secret-value-123\u{a0}",
        "\u{2003}secret-value-123\r\n ",
    ] {
        let redacted = redact_log_line(line, &[secret]);
        assert!(
            !redacted.contains("secret-value-123"),
            "{secret:?} leaked: {redacted}"
        );
    }
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
    let (state, lock_directory) = supervisor_fixture(&root);

    let executable = root.join("fake-traefik");
    fake_traefik(&executable, b"#!/bin/sh\nexec /bin/sleep 60\n");
    let acme_storage = acme_fixture(&state);

    let (health_address, health_server) = health_server_sequence(vec![HEALTHY, UNHEALTHY]);
    let settings = SupervisorSettings {
        executable,
        static_config_path: root.join("static.toml"),
        lock_directory: lock_directory.clone(),
        dynamic_config_path: state.join(DYNAMIC_CONFIG_FILENAME),
        static_config: StaticConfig {
            mesh_address: "10.77.0.1".parse().expect("mesh address"),
            public_bind_address: "127.0.0.1".parse().expect("rootless public bind"),
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
    let (state, lock_directory) = supervisor_fixture(&root);

    let executable = root.join("fake-traefik");
    fake_traefik(&executable, b"#!/bin/sh\nexec /bin/sleep 60\n");
    let dynamic_path = state.join(DYNAMIC_CONFIG_FILENAME);
    let probe = generation_probe_server(dynamic_path.clone(), false);
    let settings =
        generation_probe_settings(&root, &state, &lock_directory, executable, probe.address);
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
    let (state, lock_directory) = supervisor_fixture(&root);

    let executable = root.join("fake-traefik");
    fake_traefik(&executable, b"#!/bin/sh\nexec /bin/sleep 60\n");
    let dynamic_path = state.join(DYNAMIC_CONFIG_FILENAME);
    let probe = generation_probe_server(dynamic_path, true);
    let supervisor = TraefikSupervisor::start(
        generation_probe_settings(&root, &state, &lock_directory, executable, probe.address),
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
    lock_directory: &Path,
    executable: PathBuf,
    address: SocketAddr,
) -> SupervisorSettings {
    let acme_storage = acme_fixture(state);
    SupervisorSettings {
        executable,
        static_config_path: root.join("static.toml"),
        lock_directory: lock_directory.to_owned(),
        dynamic_config_path: state.join(DYNAMIC_CONFIG_FILENAME),
        static_config: StaticConfig {
            mesh_address: "10.77.0.1".parse().expect("mesh address"),
            public_bind_address: "127.0.0.1".parse().expect("rootless public bind"),
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
    let (state, lock_directory) = supervisor_fixture(&root);

    let executable = root.join("fake-traefik");
    fake_traefik(&executable, b"#!/bin/sh\nexec /bin/sleep 60\n");
    let acme_storage = acme_fixture(&state);

    let response: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let (health_address, health_server) = health_server_sequence(vec![response; 4]);
    let dynamic_directory = state.clone();
    let settings = SupervisorSettings {
        executable,
        static_config_path: root.join("static.toml"),
        lock_directory: lock_directory.clone(),
        dynamic_config_path: state.join(DYNAMIC_CONFIG_FILENAME),
        static_config: StaticConfig {
            mesh_address: "10.77.0.1".parse().expect("mesh address"),
            public_bind_address: "127.0.0.1".parse().expect("rootless public bind"),
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

#[cfg(target_os = "linux")]
#[test]
fn the_parent_death_signal_survives_the_credential_drop() {
    let root = std::env::temp_dir().join(format!("proxy-pdeathsig-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).expect("create probe fixture");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("private probe fixture");
    crate::controller::ensure_proxy_directory(&root).expect("child-readable probe fixture");
    // The signal is per thread, so the probe must read it on the exec'd main thread: a small
    // interpreter does, where a test harness would answer from a worker thread.
    let python = std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|directory| directory.join("python3"))
                .find(|candidate| candidate.is_file())
        })
        .expect("python3 on PATH");
    let executable = root.join("fake-traefik");
    fake_traefik(
        &executable,
        format!(
            "#!/bin/sh\nexec '{}' -c 'import ctypes; value = ctypes.c_int(); ctypes.CDLL(None).prctl(2, ctypes.byref(value), 0, 0, 0); print(\"pdeathsig=%d\" % value.value, flush=True)'\n",
            python.display()
        )
        .as_bytes(),
    );
    let config = root.join("traefik.toml");
    crate::config::write_proxy_config_atomic(&config, b"{}").expect("write config fixture");
    let (lines, received) = mpsc::channel();
    let log = std::sync::Arc::new(move |line: String| {
        // Match anywhere: a line may carry other output before the marker.
        if let Some((_, signal)) = line.split_once("pdeathsig=") {
            let _ = lines.send(signal.trim().to_owned());
        }
    });

    let mut child = TraefikChild::spawn(&executable, &config, &[], log).expect("spawn probe");
    let signal = received.recv_timeout(Duration::from_secs(10));
    child.stop().expect("stop probe");
    std::fs::remove_dir_all(root).expect("remove probe fixture");
    assert_eq!(
        signal.expect("probe reported its parent-death signal"),
        (nix::sys::signal::Signal::SIGKILL as i32).to_string(),
        "the child must die with the infraternal agent, also after dropping to the proxy identity"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_new_supervisor_stops_an_orphan_that_holds_the_child_lock() {
    let root = std::env::temp_dir().join(format!("proxy-orphan-{}", uuid::Uuid::new_v4()));
    let (state, lock_directory) = supervisor_fixture(&root);
    let executable = root.join("fake-traefik");
    fake_traefik(&executable, b"#!/bin/sh\nexec /bin/sleep 60\n");
    // Plant an orphan exactly as an agent crash leaves one: a process that still holds the
    // child lock through an inherited descriptor after its owner is gone.
    let lock_path = lock_directory.join(".traefik-child.lock");
    std::fs::write(&lock_path, b"").expect("create child lock");
    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))
        .expect("private child lock");
    let mut orphan = Command::new("/bin/sh")
        .args([
            "-c",
            "exec 9<\"$1\" && flock -n 9 && echo held && exec /bin/sleep 60",
            "orphan",
        ])
        .arg(&lock_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("start planted orphan");
    let mut held = String::new();
    std::io::BufReader::new(orphan.stdout.as_mut().expect("orphan output"))
        .read_line(&mut held)
        .expect("orphan holds the lock");
    assert_eq!(held.trim(), "held");

    let probe = generation_probe_server(state.join(DYNAMIC_CONFIG_FILENAME), false);
    let started = TraefikSupervisor::start(
        generation_probe_settings(&root, &state, &lock_directory, executable, probe.address),
        std::sync::Arc::new(|_: String| {}),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let orphan_exit = loop {
        if let Some(status) = orphan.try_wait().expect("observe orphan") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = orphan.kill();
            let _ = orphan.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    drop(started);
    drop(probe);
    std::fs::remove_dir_all(root).expect("remove orphan fixture");
    assert!(
        orphan_exit.is_some(),
        "a stale proxy child holding the child lock must be stopped on start"
    );
}
