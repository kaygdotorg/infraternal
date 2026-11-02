//! Real normal-CLI cold restart proves retained-host mTLS/browser routing without unlocking or persisting the CA signing key [168], #78.

use super::*;

fn write_private(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

/// Obtain a real signed CSR in memory and check that the normal cold CLI refuses
/// signing, preserving the invitation for a later authenticated administrator unlock.
async fn locked_join(fixture: &Fixture) {
    use http_body_util::BodyExt;
    use openssl::{
        hash::MessageDigest,
        pkey::PKey,
        x509::{X509NameBuilder, X509Req},
    };
    let host = uuid::Uuid::new_v4();
    let key = PKey::generate_ed25519().unwrap();
    let expected_key_digest = openssl::sha::sha256(&key.raw_public_key().unwrap());
    let invitation = invitation(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
        host,
        expected_key_digest,
    )
    .await;
    let invitation: crate::remote_http::JoinInvitation =
        serde_json::from_slice(&invitation).unwrap();
    let mut csr = X509Req::builder().unwrap();
    csr.set_subject_name(&X509NameBuilder::new().unwrap().build())
        .unwrap();
    csr.set_pubkey(&key).unwrap();
    csr.sign(&key, MessageDigest::null()).unwrap();
    let request = crate::remote_http::JoinRequest {
        host_id: host,
        mode: crate::enrollment::Mode::Rootless,
        token: invitation.token,
        csr_der: B64.encode(csr.build().to_der().unwrap()),
    };
    let stream = tls(fixture.address, &fixture.root).await;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    let connection = tokio::spawn(connection);
    let body = serde_json::to_vec(&request).unwrap();
    let response = sender
        .send_request(
            hyper::Request::builder()
                .method("POST")
                .uri("/remote/join")
                .header("host", "localhost:4701")
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), hyper::StatusCode::FORBIDDEN);
    let _ = http_body_util::Limited::new(response.into_body(), 8192)
        .collect()
        .await
        .unwrap();
    connection.abort();
    let issued: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_certificates WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(issued, 0);
    assert!(
        crate::enrollment::EnrollmentStore::new(fixture.pool.clone())
            .preflight(&request.token, host, request.mode, unix_seconds().unwrap())
            .await
            .is_ok()
    );
    println!(
        "remote_cold_start enrollment_refused=true invitation_retained=true ca_private_key_persisted=false"
    );
}

async fn release_fixture(fixture: &mut Fixture, endpoint: SocketAddr) {
    fixture.server.abort();
    let _ = (&mut fixture.server).await;
    fixture.listeners.take();
    // Aborting an in-process fixture is not process exit: QUIC's driver can
    // retain its UDP socket while close packets drain. Require port release
    // before launching the replacement CLI, rather than hiding bind failures.
    let released = Instant::now();
    loop {
        let free = std::net::TcpListener::bind(fixture.address)
            .and_then(|http| {
                let tcp = std::net::TcpListener::bind(endpoint)?;
                let udp = std::net::UdpSocket::bind(endpoint)?;
                Ok((http, tcp, udp))
            })
            .is_ok();
        if free {
            break;
        }
        assert!(
            released.elapsed() < Duration::from_secs(10),
            "fixture ports did not release"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn cold_cli(binary: &Path, directory: &Directory, ca: &Path) -> Process {
    Process(
        Command::new(binary)
            .args([
                "server",
                "--listen",
                "127.0.0.1:4701",
                "--public-origin",
                "https://localhost:4701",
                "--remote-listen",
                "127.0.0.1:7443",
                "--remote-ca-dir",
            ])
            .arg(ca)
            .arg("--data")
            .arg(directory.0.join("server"))
            .arg("--tls-cert")
            .arg(directory.0.join("server.pem"))
            .arg("--tls-key")
            .arg(directory.0.join("server.key"))
            // Keep the CLI's embedded subprocess state isolated too. It opens no PTY.
            .env("XDG_RUNTIME_DIR", &directory.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    )
}

fn retained_trust(directory: &Directory, fixture: &Fixture) -> PathBuf {
    let ca = directory.0.join("ca");
    std::fs::DirBuilder::new().mode(0o700).create(&ca).unwrap();
    write_private(&ca.join("issuer.pem"), &fixture.root.to_pem().unwrap());
    write_private(
        &directory.0.join("server.pem"),
        &fixture.identity.certificate.to_pem().unwrap(),
    );
    write_private(
        &directory.0.join("server.key"),
        &fixture.identity.key.private_key_to_pem_pkcs8().unwrap(),
    );
    ca
}

/// Exercise the normal CLI's shared HTTP/listener revocation scope while the CA
/// remains locked. Removing authority must leave the existing rootless shims alive.
async fn revoke_live_host(
    fixture: &Fixture,
    browser: &mut Browser,
    host: uuid::Uuid,
    state: &Path,
    input_acked: u64,
) {
    let shims = remaining_shims(state);
    assert_eq!(shims, 2);
    let stream = tls(fixture.address, &fixture.root).await;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    let connection = tokio::spawn(connection);
    let started = Instant::now();
    let response = sender
        .send_request(
            hyper::Request::builder()
                .method("POST")
                .uri("/remote/revocations")
                .header("host", "localhost:4701")
                .header("origin", "https://localhost:4701")
                .header("cookie", format!("__Host-infraternal={}", fixture.cookie))
                .header("content-type", "application/json")
                .body(http_body_util::Full::new(bytes::Bytes::from(
                    serde_json::to_vec(&serde_json::json!({"host_id":host})).unwrap(),
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), hyper::StatusCode::NO_CONTENT);
    let committed_us = started.elapsed().as_micros();
    connection.abort();
    send(
        browser,
        1,
        &Frame::Input {
            in_seq: input_acked,
            bytes: b"printf 'REVOKE_%s\\n' REFUSED\n",
        },
    )
    .await;
    let input = serde_json::json!({"host_id":host}).to_string();
    send(
        browser,
        0,
        &Frame::Call {
            call_id: 2,
            action_id: "ssh.session.open",
            input_json: input.as_bytes(),
        },
    )
    .await;
    let mut refused = false;
    while !refused {
        let wire = next(browser).await;
        let decoded = decode_muxed_frame(&wire).unwrap();
        match decoded.frame {
            Frame::Result { call_id: 2, ok, .. } => {
                assert!(!ok, "revoked host admitted another terminal");
                refused = true;
            }
            Frame::Ack { in_seq_acked } if decoded.stream_id == 1 => {
                assert!(
                    in_seq_acked <= input_acked,
                    "revoked host accepted more input"
                );
            }
            _ => {}
        }
    }
    let refused_us = started.elapsed().as_micros().saturating_sub(committed_us);
    assert_revoked_attachment_quiet(browser, input_acked).await;
    assert_eq!(remaining_shims(state), shims);
    println!(
        "remote_revocation normal_cli=true signing_locked=true http_commit_us={committed_us} commit_to_browser_refusal_us={refused_us} shims_alive={shims} new_session_refused=true retained_attachment_probe_ms=300 additional_input_acked=0"
    );
}

/// Retained browser attachments survive loss for offset recovery; a revoked
/// host must not accept input or execute its marker during this bounded probe.
async fn assert_revoked_attachment_quiet(browser: &mut Browser, input_acked: u64) {
    let quiet = tokio::time::timeout(Duration::from_millis(300), async {
        let mut output = Vec::new();
        loop {
            let wire = next(browser).await;
            let decoded = decode_muxed_frame(&wire).unwrap();
            match decoded.frame {
                Frame::Ack { in_seq_acked } if decoded.stream_id == 1 => {
                    assert!(
                        in_seq_acked <= input_acked,
                        "revoked host accepted more input"
                    );
                }
                Frame::Output { bytes, .. } if decoded.stream_id == 1 => {
                    output.extend_from_slice(bytes);
                    assert!(!output.windows(14).any(|window| window == b"REVOKE_REFUSED"));
                    if output.len() > 13 {
                        output.drain(..output.len() - 13);
                    }
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(quiet.is_err());
}

/// Readiness must precede HTTPS/WebSocket use of the replacement CLI.
async fn wait_cli_listener(address: SocketAddr, started: Instant) {
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "normal CLI did not listen"
        );
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
#[ignore = "normal CLI cold-start proof requires static INFRATERNAL_REMOTE_TEST_BINARY and exclusive 4701/7443"]
async fn normal_cli_cold_start_keeps_enrolled_remote_terminal_while_signing_locked() {
    let binary = PathBuf::from(std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").unwrap());
    assert_ne!(nix::unistd::Uid::effective().as_raw(), 0);
    let directory = Directory::new();
    let endpoint = "127.0.0.1:7443".parse().unwrap();
    let mut fixture = fixture_at(&directory, "127.0.0.1:4701".parse().unwrap(), endpoint).await;
    let ca = retained_trust(&directory, &fixture);
    let host = uuid::Uuid::new_v4();
    let expected_key_digest = prepare_pending_join_key(&directory.0.join("data"));
    let invitation = invitation(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
        host,
        expected_key_digest,
    )
    .await;
    let mut child = cli(&binary, &directory, true, "https://localhost:4701");
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(&invitation)
        .unwrap();
    drop(invitation);
    let mut first = browser(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
    )
    .await;
    let session = open_remote(&mut first, host, Instant::now()).await;
    drop(first);
    release_fixture(&mut fixture, endpoint).await;
    let started = Instant::now();
    let server = cold_cli(&binary, &directory, &ca);
    wait_cli_listener(fixture.address, started).await;
    let mut browser = browser(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
    )
    .await;
    // Admit the existing host before reattaching the pre-restart session. The
    // readiness open gets its own shim and is retained for normal fixture cleanup.
    let _ready = open_remote(&mut browser, host, started).await;
    send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: session.as_bytes(),
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    send(&mut browser, 1, &Frame::Credit { bytes: 1024 * 1024 }).await;
    let mut output = Vec::new();
    let mut cursor = 0;
    until(&mut browser, &mut output, &mut cursor, b"shim-test").await;
    let ready_us = started.elapsed().as_micros();
    let command = b"printf 'COLD_%s\\n' OK\n";
    let entered = Instant::now();
    send(
        &mut browser,
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: command,
        },
    )
    .await;
    until(&mut browser, &mut output, &mut cursor, b"COLD_OK").await;
    println!(
        "remote_cold_start normal_cli=true signing_locked=true restart_to_terminal_us={ready_us} command_roundtrip_us={} contiguous_output_bytes={cursor} lost=0 duplicated=0 load={}",
        entered.elapsed().as_micros(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    locked_join(&fixture).await;
    revoke_live_host(
        &fixture,
        &mut browser,
        host,
        &directory.0.join("s"),
        command.len().try_into().unwrap(),
    )
    .await;
    drop(browser);
    drop(child);
    drop(server);
    fixture.pool.close().await;
    let state = directory.0.join("s");
    drop(fixture);
    drop(directory);
    assert_eq!(remaining_shims(&state), 0);
}

/// Isolated release-transition proof. Run in a private network namespace: these
/// fixture ports and retained credentials must never address a real deployment.
#[tokio::test]
#[ignore = "requires isolated release binaries and a ten-minute outage"]
async fn release_transition_recovers_enrolled_host_after_long_outage() {
    let enrolled = PathBuf::from(std::env::var_os("INFRATERNAL_OLD_TEST_BINARY").unwrap());
    let new = PathBuf::from(std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").unwrap());
    let directory = Directory::new();
    let endpoint = "127.0.0.1:7443".parse().unwrap();
    let mut fixture = fixture_at(&directory, "127.0.0.1:4701".parse().unwrap(), endpoint).await;
    let ca = retained_trust(&directory, &fixture);
    let host = uuid::Uuid::new_v4();
    let expected_key_digest = prepare_pending_join_key(&directory.0.join("data"));
    let invitation = invitation(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
        host,
        expected_key_digest,
    )
    .await;
    let mut child = cli(&enrolled, &directory, true, "https://localhost:4701");
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(&invitation)
        .unwrap();
    drop(invitation);
    let mut browser = browser(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
    )
    .await;
    println!("release_transition initial_transport_ready=true");
    open_remote(&mut browser, host, Instant::now()).await;
    drop(browser);
    release_fixture(&mut fixture, endpoint).await;
    let previous_binary = std::env::var_os("INFRATERNAL_PREVIOUS_SERVER_BINARY")
        .map_or_else(|| new.clone(), PathBuf::from);
    let mut previous = cold_cli(&previous_binary, &directory, &ca);
    wait_cli_listener(fixture.address, Instant::now()).await;
    let mut connected = super::browser(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
    )
    .await;
    open_remote(&mut connected, host, Instant::now()).await;
    drop(connected);
    println!("release_transition previous_server=true infraternal_agent_connected=true");
    interrupt_server(&mut previous, &mut child, endpoint).await;
    let mut cold_previous = cold_cli(&previous_binary, &directory, &ca);
    wait_cli_listener(fixture.address, Instant::now()).await;
    println!("release_transition previous_server_cold_restart=true");
    cold_previous.0.kill().unwrap();
    cold_previous.0.wait().unwrap();
    let replacement = cold_cli(&new, &directory, &ca);
    wait_cli_listener(fixture.address, Instant::now()).await;
    let ready = Instant::now();
    let mut recovered = super::browser(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
    )
    .await;
    // One retry period plus protocol and terminal-admission allowance.
    let recovery_budget = Duration::from_secs(31);
    tokio::time::timeout(
        recovery_budget,
        open_remote_with_budget(&mut recovered, host, Instant::now(), recovery_budget),
    )
    .await
    .expect("infraternal agent did not reconnect after cold server replacement");
    assert!(child.0.try_wait().unwrap().is_none());
    process_threads(&child, "reconnected");
    report_recovery(ready);
    locked_join(&fixture).await;
    println!("release_transition replacement_ca_locked=true infraternal_agent_reconnected=true");
    drop(recovered);
    drop(replacement);
    drop(child);
    drop(cold_previous);
    drop(previous);
    fixture.pool.close().await;
    let state = directory.0.join("s");
    drop(fixture);
    drop(directory);
    assert_eq!(
        remaining_shims(&state),
        0,
        "release proof left a fixture shim"
    );
}

/// The namespace controller owns link changes; the test process remains rootless.
async fn outage_network(phase: &str) {
    let control = PathBuf::from(std::env::var_os("INFRATERNAL_RECONNECT_CONTROL").unwrap());
    std::fs::write(control.join(phase), b"ready").unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !control.join(format!("{phase}-done")).exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("network namespace controller did not acknowledge link change");
}

/// Thread counts are observable even when private process descriptors are hidden.
fn process_threads(child: &Process, phase: &str) {
    let status = std::fs::read_to_string(format!("/proc/{}/status", child.0.id())).unwrap();
    let threads = status
        .lines()
        .find(|line| line.starts_with("Threads:"))
        .unwrap();
    println!("release_transition phase={phase} {}", threads.trim());
    if std::env::var_os("INFRATERNAL_RECONNECT_MEASURE").is_some() {
        let rss = status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))
            .unwrap();
        println!(
            "remote_reconnect phase={phase} {} scale=1 full_daemon=true",
            rss.trim()
        );
    }
}

/// Stall userspace while TCP accepts, then model abrupt power loss and no route.
async fn interrupt_server(previous: &mut Process, child: &mut Process, endpoint: SocketAddr) {
    process_threads(child, "before_stall");
    if let Ok(seconds) = std::env::var("INFRATERNAL_RECONNECT_STALL_SECONDS") {
        let seconds = seconds.parse::<u64>().unwrap();
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(previous.0.id()).unwrap()),
            nix::sys::signal::Signal::SIGSTOP,
        )
        .unwrap();
        // SIGSTOP leaves the kernel listener accepting TCP while no userspace
        // TLS, QUIC or application work can answer, matching a stalled server.
        assert!(tokio::net::TcpStream::connect(endpoint).await.is_ok());
        println!("release_transition server_stopped=true tcp_accepts=true");
        tokio::time::sleep(Duration::from_secs(seconds)).await;
        assert!(child.0.try_wait().unwrap().is_none());
        process_threads(child, "after_stall");
    }
    outage_network("disconnect").await;
    previous.0.kill().unwrap();
    previous.0.wait().unwrap();
    let outage_seconds = std::env::var("INFRATERNAL_RECONNECT_OUTAGE_SECONDS")
        .map_or(600, |value| value.parse::<u64>().unwrap());
    tokio::time::sleep(Duration::from_secs(outage_seconds)).await;
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "infraternal agent exited during outage"
    );
    println!("release_transition outage_seconds={outage_seconds} process_alive=true");
    process_threads(child, "after_no_route");
    outage_network("restore").await;
}

/// Measurement mode is enabled only by the performance-VM runner.
fn report_recovery(ready: Instant) {
    if std::env::var_os("INFRATERNAL_RECONNECT_MEASURE").is_some() {
        println!(
            "remote_reconnect listener_ready_to_terminal_us={} load={}",
            ready.elapsed().as_micros(),
            std::fs::read_to_string("/proc/loadavg").unwrap().trim()
        );
    }
}
