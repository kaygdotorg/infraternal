//! Proves fresh CA setup, private-stdin local infraternal agent enrollment, live renewal and immediate transport revocation in a configured release process [168], #78.
use super::*;
use infraternal_agent::{remote_quic, remote_tls::Identity};
use infraternal_protocol::{Frame, encode_frame_into};

fn local_process(
    binary: &std::path::Path,
    root: &std::path::Path,
    join: Option<&Value>,
) -> ShippingServer {
    let mut command = Command::new(binary);
    command
        .args(["--json", "agent", "--data"])
        .arg(root.join("local-node"));
    if join.is_some() {
        command.args(["join", "https://10.69.69.125:4701/remote/join"]);
    } else {
        command.arg("run");
    }
    let mut child = command
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .stdin(if join.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    if let Some(invitation) = join {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(invitation).unwrap())
            .unwrap();
    }
    ShippingServer(child)
}
async fn wait_identity(
    process: &mut ShippingServer,
    path: &std::path::Path,
    previous: Option<&str>,
) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "local infraternal agent exited"
            );
            if let Ok(bytes) = std::fs::read(path)
                && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                && previous
                    .is_none_or(|previous| value["certificate_der"].as_str() != Some(previous))
            {
                return value;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap()
}
async fn bootstrap_server(binary: &std::path::Path) -> (UnlockFixture, X509, ShippingServer, u128) {
    let (mut f, https_root) = shipping_fixture().await;
    let ca = f.root.join("fresh-ca");
    // Existing HTTPS trust belongs to server setup. The fresh machine CA starts
    // with no issuer or key; the production handler creates every CA file.
    let server = shipping_start_with_ca(binary, &f.root, &ca).await;
    let began = Instant::now();
    let (status, start) = shipping_post(
        &https_root,
        &f.auth.session,
        "/remote/ca/bootstrap/start",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let salt = B64.decode(start["ca"]["salt"].as_str().unwrap()).unwrap();
    let mut scoped = [0; 32];
    Hkdf::<Sha256>::new(Some(&salt), &f.auth.dek)
        .expand(
            format!("infraternal/ca-wrap/v1|{}|1", f.auth.user).as_bytes(),
            &mut scoped,
        )
        .unwrap();
    let proof = f.auth.software.login(&start, ORIGIN, true);
    let (status, _) = shipping_post(
        &https_root,
        &f.auth.session,
        "/remote/ca/bootstrap/finish",
        json!({"ceremony":start["ceremony"],"proof":proof,"scoped_key":scoped}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let elapsed = began.elapsed().as_micros();
    drop(server);
    let server = shipping_start_with_ca(binary, &f.root, &ca).await;
    let (status, locked) =
        shipping_post(&https_root, &f.auth.session, "/remote/ca/status", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(locked, json!({"locked":true}));
    let (status, start) = shipping_post(
        &https_root,
        &f.auth.session,
        "/remote/ca/bootstrap/start",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(start["ca"]["operation"], "unlock");
    let proof = f.auth.software.login(&start, ORIGIN, true);
    let (status, unlocked) = shipping_post(
        &https_root,
        &f.auth.session,
        "/remote/ca/bootstrap/finish",
        json!({"ceremony":start["ceremony"],"proof":proof,"scoped_key":scoped}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(unlocked, json!({"locked":false}));
    (f, https_root, server, elapsed)
}
// Retain both stream handles until revocation: dropping either control stream
// here would disconnect the peer before the owner mutation is measured.
async fn revocation_observer(
    invitation: &Value,
    renewed: &Value,
) -> (
    quinn::Endpoint,
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
) {
    let issuer =
        X509::from_der(&B64.decode(invitation["ca_der"].as_str().unwrap()).unwrap()).unwrap();
    let identity = Identity {
        certificate: X509::from_der(
            &B64.decode(renewed["certificate_der"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap(),
        key: PKey::private_key_from_pkcs8(
            &B64.decode(renewed["key_der"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
    };
    let mut peer = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    peer.set_default_client_config(remote_quic::client_config(&identity, &[issuer]).unwrap());
    let connection = peer
        .connect("10.69.69.125:7443".parse().unwrap(), "auth.example.test")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    let mut hello = Vec::new();
    encode_frame_into(
        &Frame::Hello {
            version: 1,
            caps: remote_quic::REMOTE_WRITER_BINDING,
            client_info: "revocation observer",
        },
        &mut hello,
    )
    .unwrap();
    send.write_all(&hello).await.unwrap();
    let mut greeting = [0; 1024];
    assert!(
        tokio::time::timeout(Duration::from_secs(5), receive.read(&mut greeting))
            .await
            .unwrap()
            .unwrap()
            .is_some()
    );
    (peer, connection, send, receive)
}

#[tokio::test]
#[ignore = "configured release E2E requires INFRATERNAL_REMOTE_TEST_BINARY and exclusive4701/7443"]
async fn fresh_release_bootstrap_join_renew_revoke_cuts_a_live_connection() {
    let binary = PathBuf::from(std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").unwrap());
    let (f, https_root, server, bootstrap_us) = bootstrap_server(&binary).await;
    let host = Uuid::new_v4();
    let (status,invitation)=shipping_post(&https_root,&f.auth.session,"/remote/invitations",json!({"host_id":host,"mode":"rootless","execution_uid":nix::unistd::Uid::effective().as_raw()})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(invitation["https_der"].is_string());
    let identity_path = f.root.join("local-node/identity.json");
    let began = Instant::now();
    let mut joined = local_process(&binary, &f.root, Some(&invitation));
    let original = wait_identity(&mut joined, &identity_path, None).await;
    let join_us = began.elapsed().as_micros();
    drop(joined);
    // Age only the public ledger half-life metadata to exercise the real normal
    // scheduler today, without waiting 84h or changing seven-day certificates.
    // Reconnect reads the aged lease; renewal uses the same live control stream.
    sqlx::query("UPDATE remote_certificates SET not_before=not_before-302400,not_after=not_after-302400 WHERE host_id=?")
        .bind(host.as_bytes().as_slice()).execute(&f.auth.auth.pool).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let began = Instant::now();
    let mut local = local_process(&binary, &f.root, None);
    let renewed = wait_identity(
        &mut local,
        &identity_path,
        original["certificate_der"].as_str(),
    )
    .await;
    let renewal_us = began.elapsed().as_micros();
    assert!(
        original["key_der"] == renewed["key_der"],
        "renewal replaced the local key"
    );
    let (peer, connection, _send, _receive) = revocation_observer(&invitation, &renewed).await;
    assert!(
        connection.close_reason().is_none(),
        "revocation observer was already disconnected"
    );
    let began = Instant::now();
    let (status, _) = shipping_post(
        &https_root,
        &f.auth.session,
        "/remote/revocations",
        json!({"host_id":host}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let closed = tokio::time::timeout(Duration::from_secs(2), connection.closed())
        .await
        .unwrap();
    assert!(matches!(
        closed,
        quinn::ConnectionError::ApplicationClosed(_)
    ));
    let revoke_us = began.elapsed().as_micros();
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.auth.pool)
            .await
            .unwrap();
    assert!(revoked);
    peer.close(0u32.into(), b"");
    drop(local);
    drop(server);
    println!(
        "REMOTE_BOOTSTRAP_E2E cold_restart_locked=true retained_copy_unlock=true bootstrap_us={bootstrap_us} join_cli_to_durable_identity_us={join_us} renewal_reconnect_to_durable_identity_us={renewal_us} revoke_to_live_quic_close_us={revoke_us} rootless=true fixture_signer_injected=false aged_public_half_life_fixture=true host_key_retained=true machine={} cores={} load={}",
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
