//! Proves mesh-source filtering, exact routing, and DNS-01 issuance in an isolated namespace [#281].

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    reason = "Integration fixture failures should identify the exact operation that failed."
)]

use infraternal_plugin_proxy::{
    config::{
        DYNAMIC_CONFIG_FILENAME, DnsChallenge, ListenerPorts, PublishedService, StaticConfig,
    },
    names::CertificateName,
    supervisor::{SupervisorSettings, TraefikSupervisor},
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    env,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const TEST_NAME: &str = "namespace_serves_a_granted_mesh_backend_with_pebble_dns01";
const BACKEND_BODY: &[u8] = b"proxy-test-backend";

/// Run the integration inside a fresh user and network namespace with loopback only.
#[test]
#[ignore = "requires the pinned Pebble fixture from scripts/test-proxy-pebble.sh"]
fn namespace_serves_a_granted_mesh_backend_with_pebble_dns01() {
    if env::var_os("INFRATERNAL_PROXY_E2E_NAMESPACE").is_some() {
        run_namespace_case();
        return;
    }

    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--fork"])
        .arg(env::current_exe().expect("test executable path"))
        .arg("--exact")
        .arg(TEST_NAME)
        .arg("--ignored")
        .arg("--nocapture")
        .env("INFRATERNAL_PROXY_E2E_NAMESPACE", "1")
        .status()
        .expect("start isolated proxy namespace");
    assert!(
        status.success(),
        "isolated proxy integration failed: {status}"
    );
}

#[allow(
    clippy::too_many_lines,
    reason = "The e2e scenario keeps namespace, ACME, route, and TLS lifetimes visible together."
)]
fn run_namespace_case() {
    run("ip", &["link", "set", "lo", "up"]);
    let links = Command::new("ip")
        .args(["-json", "link", "show"])
        .output()
        .expect("inspect isolated namespace links");
    let links: Value = serde_json::from_slice(&links.stdout).expect("parse namespace links");
    assert_eq!(links.as_array().map(Vec::len), Some(1));
    assert_eq!(
        links[0]["ifname"], "lo",
        "test namespace must have no external link"
    );
    for address in ["100.64.0.1/24", "100.64.0.2/24", "100.64.0.3/24"] {
        run("ip", &["address", "add", address, "dev", "lo"]);
    }

    let pebble = required_path("INFRATERNAL_PROXY_E2E_PEBBLE");
    let challenge_server = required_path("INFRATERNAL_PROXY_E2E_CHALLTESTSRV");
    let fixture_root = required_path("INFRATERNAL_PROXY_E2E_PEBBLE_ROOT");
    let pebble_ca = required_path("INFRATERNAL_PROXY_E2E_PEBBLE_CA");
    let traefik = required_path("INFRATERNAL_PROXY_E2E_TRAEFIK");
    for path in [&pebble, &challenge_server, &pebble_ca, &traefik] {
        assert!(
            path.is_file(),
            "missing test executable or certificate: {}",
            path.display()
        );
    }

    let root = env::temp_dir().join(format!("proxy-pebble-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).expect("create isolated proxy fixture");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("make isolated proxy fixture private");
    let state = root.join("state");
    fs::create_dir(&state).expect("create private proxy state");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
        .expect("make proxy state private");

    let challenge = TestProcess::start(Command::new(challenge_server).args([
        "-dns01",
        "127.0.0.1:8053",
        "-http01",
        "",
        "-https01",
        "",
        "-tlsalpn01",
        "",
        "-management",
        "127.0.0.1:8055",
    ]));
    wait_for_tcp("127.0.0.1:8055".parse().expect("management address"));

    let pebble_config = fixture_root.join("test/config/pebble-config.json");
    let pebble = TestProcess::start(
        Command::new(pebble)
            .current_dir(&fixture_root)
            .arg("-config")
            .arg(pebble_config)
            .arg("-dnsserver")
            .arg("127.0.0.1:8053")
            .env("PEBBLE_VA_NOSLEEP", "1"),
    );
    wait_for_tcp("127.0.0.1:14000".parse().expect("ACME address"));
    wait_for_tcp("127.0.0.1:15000".parse().expect("Pebble management address"));
    let issued_certificate_root = private_file(
        &root.join("pebble-issued-root.pem"),
        &fetch_pebble_issued_root(&pebble_ca),
    );

    let adapter = start_httpreq_adapter();
    let backend = start_backend();
    let endpoint_file = private_file(
        &root.join("dns-provider-endpoint"),
        adapter.value.as_bytes(),
    );
    let storage_path = root.join("acme.json");
    let _storage = private_file(&storage_path, b"{}");
    let health_port = free_loopback_port();
    let executable = write_ca_wrapper(&root.join("traefik-with-pebble-ca"), &pebble_ca, &traefik);
    let log_tail = Arc::new(Mutex::new(VecDeque::new()));
    let captured_log_tail = Arc::clone(&log_tail);

    let supervisor = TraefikSupervisor::start(
        SupervisorSettings {
            executable,
            static_config_path: root.join("traefik.toml"),
            dynamic_config_path: state.join(DYNAMIC_CONFIG_FILENAME),
            static_config: StaticConfig {
                mesh_address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                ports: ListenerPorts {
                    http: 10080,
                    https: 10443,
                    mesh_http: None,
                    mesh_https: None,
                },
                public: false,
                private_ping_port: health_port,
                dynamic_directory: state.clone(),
                dns_challenge: DnsChallenge {
                    provider: "httpreq".to_owned(),
                    email: "proxy-test@example.org".to_owned(),
                    storage_path: storage_path.clone(),
                    ca_server: Some("https://127.0.0.1:14000/dir".to_owned()),
                    resolvers: vec!["127.0.0.1:8053".parse().expect("Pebble DNS resolver")],
                    disable_authoritative_ns_checks: true,
                },
            },
            provider_files: vec![("HTTPREQ_ENDPOINT".to_owned(), endpoint_file)],
            private_ping_address: SocketAddr::from(([127, 0, 0, 1], health_port)),
            startup_timeout: Duration::from_secs(20),
        },
        Arc::new(move |line| {
            if let Ok(mut lines) = captured_log_tail.lock() {
                if lines.len() == 64 {
                    lines.pop_front();
                }
                lines.push_back(line);
            }
        }),
    )
    .expect("start the node-local Traefik owner");

    let hostname = "docs.node.example.org";
    supervisor
        .replace(vec![PublishedService {
            id: "docs".to_owned(),
            hostname: hostname.to_owned(),
            backend: backend.address,
            allowed_sources: vec!["100.64.0.2".parse().expect("granted mesh peer")],
            public: false,
            certificate: CertificateName::Wildcard("*.node.example.org".to_owned()),
        }])
        .expect("publish one granted mesh service")
        .expect("published listener ports");

    let deadline = Instant::now() + Duration::from_secs(45);
    let mut response = None;
    let mut last_curl_failure = String::new();
    while Instant::now() < deadline {
        let attempt = curl_request("100.64.0.2", hostname, &issued_certificate_root, true);
        if attempt.status.success() && response_status(&attempt.stdout) == Some(200) {
            response = Some(attempt.stdout);
            break;
        }
        last_curl_failure = format!(
            "exit={:?}, http={:?}, stderr={}",
            attempt.status.code(),
            response_status(&attempt.stdout),
            String::from_utf8_lossy(&attempt.stderr).trim()
        );
        thread::sleep(Duration::from_millis(500));
    }
    let Some(response) = response else {
        let unverified = curl_request("100.64.0.2", hostname, &issued_certificate_root, false);
        let unverified_curl = format!(
            "exit={:?}, http={:?}, backend_body={}, stderr={}",
            unverified.status.code(),
            response_status(&unverified.stdout),
            unverified
                .stdout
                .windows(BACKEND_BODY.len())
                .any(|window| window == BACKEND_BODY),
            String::from_utf8_lossy(&unverified.stderr).trim()
        );
        let captured_logs = log_tail.lock().map_or_else(
            |_| "Traefik log buffer was poisoned".to_owned(),
            |lines| lines.iter().cloned().collect::<Vec<_>>().join("\n"),
        );
        let adapter_failures = adapter.errors.lock().map_or_else(
            |_| "HTTPREQ error buffer was poisoned".to_owned(),
            |errors| errors.iter().cloned().collect::<Vec<_>>().join("; "),
        );
        panic!(
            "Pebble DNS-01 certificate and mesh route became ready; HTTPREQ calls={}; adapter errors={adapter_failures}; last verified curl={last_curl_failure}; unverified curl={unverified_curl}; Traefik logs:\n{captured_logs}",
            adapter.requests.load(Ordering::Relaxed)
        );
    };
    let response = String::from_utf8(response).expect("backend response is UTF-8");
    assert!(response.contains("proxy-test-backend"));
    assert!(
        fs::metadata(&storage_path)
            .expect("ACME storage persists")
            .len()
            > 2
    );

    let denied = curl_request("100.64.0.3", hostname, &issued_certificate_root, true);
    assert_eq!(response_status(&denied.stdout), Some(403));
    let unknown_host = curl_request(
        "100.64.0.2",
        "other.node.example.org",
        &issued_certificate_root,
        true,
    );
    assert_eq!(response_status(&unknown_host.stdout), Some(404));

    drop(supervisor);
    drop(backend);
    drop(adapter);
    drop(pebble);
    drop(challenge);
    fs::remove_dir_all(root).expect("remove isolated proxy fixture");
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(
        env::var_os(name).unwrap_or_else(|| panic!("{name} must be set by the test script")),
    )
}

fn fetch_pebble_issued_root(service_ca: &Path) -> Vec<u8> {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "2",
            "--max-time",
            "5",
            "--cacert",
        ])
        .arg(service_ca)
        .args([
            "--resolve",
            "localhost:15000:127.0.0.1",
            "https://localhost:15000/roots/0",
        ])
        .output()
        .expect("fetch Pebble's ephemeral ACME root certificate");
    assert!(
        output.status.success()
            && output.stdout.starts_with(b"-----BEGIN CERTIFICATE-----"),
        "Pebble management endpoint did not return a certificate: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    output.stdout
}

fn run(program: &str, arguments: &[&str]) {
    let status = Command::new(program)
        .args(arguments)
        .status()
        .unwrap_or_else(|error| panic!("start {program}: {error}"));
    assert!(
        status.success(),
        "{program} {arguments:?} failed with {status}"
    );
}

fn private_file(path: &Path, bytes: &[u8]) -> PathBuf {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|error| panic!("create private test file {}: {error}", path.display()));
    file.write_all(bytes).expect("write private test file");
    path.to_owned()
}

fn free_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("allocate test health port")
        .local_addr()
        .expect("read test health port")
        .port()
}

fn write_ca_wrapper(destination: &Path, ca_file: &Path, traefik: &Path) -> PathBuf {
    let script = format!(
        "#!/bin/sh\nSSL_CERT_FILE={} TRAEFIK_LOG_LEVEL=DEBUG exec {} \"$@\"\n",
        shell_quote(ca_file),
        shell_quote(traefik)
    );
    let wrapper = private_file(destination, script.as_bytes());
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o500))
        .expect("set test wrapper executable mode");
    wrapper
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

struct TestProcess(Child);

impl TestProcess {
    fn start(command: &mut Command) -> Self {
        Self(
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("start isolated ACME fixture process"),
        )
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        if !self.0.try_wait().is_ok_and(|status| status.is_some()) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn wait_for_tcp(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("test service did not listen on {address}");
}

struct Worker {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct Backend {
    address: SocketAddr,
    _worker: Worker,
}

fn start_backend() -> Backend {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test backend");
    let address = listener.local_addr().expect("read backend address");
    listener.set_nonblocking(true).expect("nonblocking backend");
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let join = thread::spawn(move || {
        while !worker_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut request = [0_u8; 2048];
                    let _ = stream.read(&mut request);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        BACKEND_BODY.len()
                    );
                    let _ = stream.write_all(BACKEND_BODY);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    Backend {
        address,
        _worker: Worker {
            stop,
            join: Some(join),
        },
    }
}

struct HttpReqAdapter {
    value: String,
    requests: Arc<AtomicUsize>,
    errors: Arc<Mutex<VecDeque<String>>>,
    _worker: Worker,
}

fn start_httpreq_adapter() -> HttpReqAdapter {
    let listener = TcpListener::bind("127.0.0.1:8054").expect("bind DNS provider fixture");
    listener
        .set_nonblocking(true)
        .expect("nonblocking DNS provider fixture");
    let requests = Arc::new(AtomicUsize::new(0));
    let worker_requests = Arc::clone(&requests);
    let errors = Arc::new(Mutex::new(VecDeque::new()));
    let worker_errors = Arc::clone(&errors);
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let join = thread::spawn(move || {
        while !worker_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _)) => {
                    worker_requests.fetch_add(1, Ordering::Relaxed);
                    if let Err(error) = handle_httpreq(stream)
                        && let Ok(mut errors) = worker_errors.lock()
                    {
                        if errors.len() == 16 {
                            let _ = errors.pop_front();
                        }
                        errors.push_back(error.to_string());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });
    HttpReqAdapter {
        value: "http://127.0.0.1:8054".to_owned(),
        requests,
        errors,
        _worker: Worker {
            stop,
            join: Some(join),
        },
    }
}

fn handle_httpreq(mut stream: TcpStream) -> io::Result<()> {
    let result = read_http_json(&mut stream).and_then(|(path, body)| {
        let request: Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
        let fqdn = request["fqdn"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DNS challenge has no name"))?;
        let host = if fqdn.ends_with('.') {
            fqdn.to_owned()
        } else {
            format!("{fqdn}.")
        };
        let (endpoint, update) = if path == "/present" {
            (
                "/set-txt",
                json!({
                    "host": host,
                    "value": request["value"].as_str().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "DNS challenge has no value")
                    })?,
                }),
            )
        } else if path == "/cleanup" {
            ("/clear-txt", json!({"host": host}))
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected DNS provider path",
            ));
        };
        let body = serde_json::to_vec(&update).map_err(io::Error::other)?;
        let mut management = TcpStream::connect("127.0.0.1:8055")?;
        write!(
            management,
            "POST {endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )?;
        management.write_all(&body)?;
        let mut response = String::new();
        management.read_to_string(&mut response)?;
        if !response.starts_with("HTTP/1.1 200") && !response.starts_with("HTTP/1.0 200") {
            return Err(io::Error::other("Pebble challenge server refused DNS update"));
        }
        Ok(())
    });
    let status = if result.is_ok() {
        "200 OK"
    } else {
        "500 Internal Server Error"
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    result
}

fn read_http_json(stream: &mut TcpStream) -> io::Result<(String, Vec<u8>)> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut received = Vec::new();
    let mut chunk = [0_u8; 4096];
    let (header_end, content_length) = loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short provider request",
            ));
        }
        received.extend_from_slice(&chunk[..count]);
        if received.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "provider request too large",
            ));
        }
        if let Some(header_end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&received[..header_end]).map_err(io::Error::other)?;
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing content length")
                })?;
            if content_length > 16 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "provider body too large",
                ));
            }
            if received.len() >= header_end + 4 + content_length {
                break (header_end, content_length);
            }
        }
    };
    while received.len() < header_end + 4 + content_length {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "short provider body",
            ));
        }
        received.extend_from_slice(&chunk[..count]);
    }
    let first_line = std::str::from_utf8(&received[..header_end])
        .map_err(io::Error::other)?
        .lines()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request line"))?;
    let path = first_line
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing request path"))?
        .to_owned();
    Ok((
        path,
        received[header_end + 4..header_end + 4 + content_length].to_vec(),
    ))
}

fn curl_request(
    source: &str,
    hostname: &str,
    ca_file: &Path,
    verify_certificate: bool,
) -> std::process::Output {
    let mut command = Command::new("curl");
    command.args([
        "--silent",
        "--show-error",
        "--interface",
        source,
        "--resolve",
    ]);
    command.arg(format!("{hostname}:443:100.64.0.1"));
    if verify_certificate {
        command.args(["--cacert"]).arg(ca_file);
    } else {
        command.args(["--insecure", "--verbose"]);
    }
    command
        .args([
            "--connect-timeout",
            "2",
            "--max-time",
            "5",
            "--write-out",
            "\n%{http_code}",
        ])
        .arg(format!("https://{hostname}/"))
        .output()
        .expect("run isolated HTTPS request")
}

fn response_status(bytes: &[u8]) -> Option<u16> {
    std::str::from_utf8(bytes)
        .ok()?
        .rsplit_once('\n')?
        .1
        .trim()
        .parse()
        .ok()
}
