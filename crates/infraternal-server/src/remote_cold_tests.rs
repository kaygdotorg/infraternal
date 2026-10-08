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
    let invitation = invitation(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
        host,
    )
    .await;
    let invitation: crate::remote_http::JoinInvitation =
        serde_json::from_slice(&invitation).unwrap();
    let key = PKey::generate_ed25519().unwrap();
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
    let invitation = invitation(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
        host,
    )
    .await;
    let mut child = cli(&binary, &directory, true);
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
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "normal CLI did not listen"
        );
        if tokio::net::TcpStream::connect(fixture.address)
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
    drop(browser);
    drop(child);
    drop(server);
    fixture.pool.close().await;
    let state = directory.0.join("s");
    drop(fixture);
    drop(directory);
    assert_eq!(remaining_shims(&state), 0);
}
