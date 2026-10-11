//! Verifies the configured release CLI's cold-locked real passkey/encrypted-copy flow, without a fixture signer in the server process [168], #78.
use super::*;
use axum::http::{StatusCode, header};
use openssl::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::{X509, store::X509StoreBuilder},
};
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    process::{Child, Command, Stdio},
};
struct ShippingServer(Child);
impl Drop for ShippingServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn private_write(path: &std::path::Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
async fn shipping_post(root: &X509, cookie: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
    connector.set_verify(SslVerifyMode::PEER);
    let mut trust = X509StoreBuilder::new().unwrap();
    trust.add_cert(root.clone()).unwrap();
    connector.set_cert_store(trust.build());
    let ssl = connector
        .build()
        .configure()
        .unwrap()
        .into_ssl("auth.example.test")
        .unwrap();
    let socket = tokio::net::TcpStream::connect("10.69.69.125:4701")
        .await
        .unwrap();
    socket.set_nodelay(true).unwrap();
    let mut tls = tokio_openssl::SslStream::new(ssl, socket).unwrap();
    std::pin::Pin::new(&mut tls).connect().await.unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .unwrap();
    let task = tokio::spawn(connection);
    let request = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, "localhost")
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, format!("__Host-infraternal={cookie}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            serde_json::to_vec(&body).unwrap(),
        )))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    task.abort();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}
async fn shipping_start(binary: &std::path::Path, root: &std::path::Path) -> ShippingServer {
    shipping_start_with_ca(binary, root, root).await
}
async fn shipping_start_with_ca(
    binary: &std::path::Path,
    root: &std::path::Path,
    ca: &std::path::Path,
) -> ShippingServer {
    let child = Command::new(binary)
        .arg("server")
        .args([
            "--listen",
            "10.69.69.125:4701",
            "--remote-listen",
            "10.69.69.125:7443",
            "--public-origin",
            ORIGIN,
        ])
        .arg("--data")
        .arg(root.join("db"))
        .arg("--remote-ca-dir")
        .arg(ca)
        .arg("--tls-cert")
        .arg(root.join("server.pem"))
        .arg("--tls-key")
        .arg(root.join("server.key"))
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = ShippingServer(child);
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let exited = server.0.try_wait().unwrap();
            assert!(exited.is_none(), "configured shipping server exited before readiness: status={exited:?}, retained_machine_trust={}", ca.join("active").exists());
            if tokio::net::TcpStream::connect("10.69.69.125:4701")
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    server
}
async fn shipping_fixture() -> (UnlockFixture, X509) {
    let mut f = unlock_fixture().await;
    for name in ["db", "runtime", "xdg-data"] {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(f.root.join(name))
            .unwrap();
    }
    let database = f.root.join("db/infraternal.sqlite");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&database)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    let auth = Auth::new(pool, "auth.example.test", ORIGIN).await.unwrap();
    let mut token = String::new();
    auth.bootstrap(NOW, |banner| {
        token = banner.lines().nth(1).unwrap().to_owned();
    })
    .await
    .unwrap();
    CaCopies::new(&f.root)
        .unwrap()
        .remove(&f.auth.user, 1)
        .unwrap();
    f.auth = fixture_with_auth(auth, token).await;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    sqlx::query("UPDATE sessions SET fresh=?,expires=? WHERE token_hash=?")
        .bind(now)
        .bind(now + 3600)
        .bind(hash(&f.auth.session))
        .execute(&f.auth.auth.pool)
        .await
        .unwrap();
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (identity, material) =
        crate::remote_runtime::tests::server_material_for_name("auth.example.test");
    let root = material.issuer().clone();
    private_write(&f.root.join("issuer.pem"), &root.to_pem().unwrap());
    private_write(
        &f.root.join("server.pem"),
        &identity.certificate.to_pem().unwrap(),
    );
    private_write(
        &f.root.join("server.key"),
        &identity.key.private_key_to_pem_pkcs8().unwrap(),
    );
    let wrapped = WrappedCa::seal(&material, &f.auth.user, 1, &[3; 32], &[7; 32]).unwrap();
    CaCopies::new(&f.root)
        .unwrap()
        .publish(&f.auth.user, 1, &wrapped)
        .unwrap();
    (f, root)
}
#[tokio::test]
#[ignore = "configured release CLI proof needs INFRATERNAL_REMOTE_TEST_BINARY and exclusive4701/7443"]
async fn configured_release_cli_cold_lock_real_passkey_unlock_and_cold_restart() {
    assert_ne!(
        nix::unistd::Uid::effective().as_raw(),
        0,
        "rootless shipping proof required"
    );
    let binary = PathBuf::from(
        std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY")
            .expect("configured release binary required"),
    );
    let (mut f, root) = shipping_fixture().await;
    let server = shipping_start(&binary, &f.root).await;
    let host = Uuid::new_v4();
    let invitation = json!({"host_id":host,"mode":"rootless","execution_uid":nix::unistd::Uid::effective().as_raw()});
    let (status, issued) =
        shipping_post(&root, &f.auth.session, "/remote/invitations", invitation).await;
    assert_eq!(status, StatusCode::OK);
    let key = PKey::generate_ed25519().unwrap();
    let mut csr = openssl::x509::X509Req::builder().unwrap();
    csr.set_subject_name(&openssl::x509::X509NameBuilder::new().unwrap().build())
        .unwrap();
    csr.set_pubkey(&key).unwrap();
    csr.sign(&key, MessageDigest::null()).unwrap();
    let join = json!({"host_id":host,"mode":"rootless","token":issued["token"],"csr_der":B64.encode(csr.build().to_der().unwrap())});
    assert_eq!(
        shipping_post(&root, &f.auth.session, "/remote/join", join.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, lock) =
        shipping_post(&root, &f.auth.session, "/remote/ca/status", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        lock == json!({"locked":true}),
        "cold CLI lock state incorrect"
    );
    let (status, start) =
        shipping_post(&root, &f.auth.session, "/remote/ca/unlock/start", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let proof = f.auth.software.login(&start, ORIGIN, true);
    let (status, lock) = shipping_post(
        &root,
        &f.auth.session,
        "/remote/ca/unlock/finish",
        json!({"ceremony":start["ceremony"],"proof":proof,"scoped_key":vec![7u8;32]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        lock == json!({"locked":false}),
        "real passkey did not unlock shipping CLI"
    );
    assert_eq!(
        shipping_post(&root, &f.auth.session, "/remote/join", join.clone())
            .await
            .0,
        StatusCode::OK
    );
    drop(server);
    let restarted = shipping_start(&binary, &f.root).await;
    let (status, lock) =
        shipping_post(&root, &f.auth.session, "/remote/ca/status", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        lock == json!({"locked":true}),
        "cold restart inherited signing unlock from disk"
    );
    let invitation = json!({"host_id":Uuid::new_v4(),"mode":"rootless","execution_uid":nix::unistd::Uid::effective().as_raw()});
    let (status, issued) = shipping_post(
        &root,
        &f.auth.session,
        "/remote/invitations",
        invitation.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let cold_join = json!({"host_id":invitation["host_id"],"mode":"rootless","token":issued["token"],"csr_der":join["csr_der"]});
    assert_eq!(
        shipping_post(&root, &f.auth.session, "/remote/join", cold_join)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    drop(restarted);
    println!(
        "configured_release_cli rootless=true cold_lock=true real_passkey_unlock=true encrypted_copy=true fixture_signer_injected=false enrollment_unlock=true cold_restart_locked=true"
    );
}

#[path = "ca_bootstrap_cli_tests.rs"]
mod bootstrap_cli;
