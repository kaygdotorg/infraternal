//! Exercises the real enrollment router with SQLite, real signed CSR, host uid binding and a cold-locked CA, #78.

use super::*;
use axum::{body::Body, http::Request};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as FINGERPRINT_B64};
use http_body_util::BodyExt;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{X509NameBuilder, X509Req},
};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::remote_device_tests::RingDevice;

/// Retains structured join diagnostics for assertions without installing a global subscriber.
#[derive(Clone, Default)]
struct JoinLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for JoinLog {
    /// Append only the structured event being asserted by this test.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    /// The in-memory capture has no buffered destination.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Supplies the same bounded test capture to each tracing event.
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for JoinLog {
    type Writer = Self;
    /// Share the test's event buffer without installing global logging.
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

/// An anonymous join refusal identifies its failed phase without exposing its capability or CSR.
#[tokio::test]
async fn join_refusal_logs_a_safe_reason() {
    let (_, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let material = crate::ca::tests::test_material();
    let app = router(
        auth,
        pool,
        Arc::new(Signer(material.clone())),
        EnrollmentEndpoint {
            ca_der: material.issuer().to_der().unwrap(),
            endpoint: "127.0.0.1:4443".parse().unwrap(),
            server_name: "localhost".into(),
        },
    );
    let capture = JoinLog::default();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .json()
        .with_writer(capture.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let capability = "x".repeat(43);
    let encoded_csr = B64.encode(csr(&PKey::generate_ed25519().unwrap()));
    let response = request(
        &app,
        "/remote/join",
        json!({
            "host_id": host, "mode": "rootless", "token": capability, "csr_der": encoded_csr,
        }),
        None,
        "",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("remote_join_refused"), "{text}");
    assert!(text.contains("invitation"), "{text}");
    assert!(!text.contains(&capability));
    assert!(!text.contains(&encoded_csr));
}

fn csr(key: &openssl::pkey::PKey<openssl::pkey::Private>) -> Vec<u8> {
    let mut builder = X509Req::builder().unwrap();
    builder
        .set_subject_name(&X509NameBuilder::new().unwrap().build())
        .unwrap();
    builder.set_pubkey(key).unwrap();
    builder.sign(key, MessageDigest::null()).unwrap();
    builder.build().to_der().unwrap()
}

async fn session(pool: &SqlitePool) -> String {
    let token = "B".repeat(43);
    let now = now().unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,'owner','test',?,?,1)")
        .bind(crate::auth::hash(&token)).bind(now+3600).bind(now).execute(pool).await.unwrap();
    token
}

async fn request(
    app: &Router,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    origin: &str,
) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("origin", origin);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", format!("__Host-infraternal={cookie}"));
    }
    app.clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

struct Signer(crate::ca::CaMaterial);
impl CaKeySource for Signer {
    fn load(&self) -> Result<crate::ca::CaMaterial, crate::ca::CaError> {
        Ok(self.0.clone())
    }
}

struct Administrator(crate::ca::CaMaterial);
impl crate::ca_memory::AdministratorCaUnlock for Administrator {
    fn unlock(&self) -> Result<crate::ca::CaMaterial, crate::ca::CaError> {
        Ok(self.0.clone())
    }
}

async fn assert_invitation_admission(app: &Router, invitation: &Value, token: &str) {
    for (cookie, origin, status) in [
        (None, "https://auth.example.test", StatusCode::UNAUTHORIZED),
        (
            Some(token),
            "https://evil.example.test",
            StatusCode::FORBIDDEN,
        ),
    ] {
        assert_eq!(
            request(
                app,
                "/remote/invitations",
                invitation.clone(),
                cookie,
                origin
            )
            .await
            .status(),
            status
        );
    }
}

async fn assert_bound_join_response(
    app: &Router,
    store: &EnrollmentStore,
    key: &PKey<Private>,
    join: Value,
) {
    let response = request(app, "/remote/join", join.clone(), None, "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let response: JoinResponse =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(response.execution_uid, 1002);
    let der = B64.decode(response.certificate_der).unwrap();
    assert!(
        openssl::x509::X509::from_der(&der)
            .unwrap()
            .public_key()
            .unwrap()
            .public_eq(key)
    );
    assert_eq!(
        store
            // Admission observes time after issuance, including a slow test host.
            .admit(&openssl::sha::sha256(&der), now().unwrap())
            .await
            .unwrap()
            .execution_uid,
        1002
    );
    assert_eq!(
        request(app, "/remote/join", join, None, "").await.status(),
        StatusCode::FORBIDDEN
    );
}

/// An invitation is bound to its key digest, used once, keeps its token while the CA is locked, and publishes the
/// public origin plus the direct QUIC endpoint (#146).
#[tokio::test]
async fn enrollment_http_is_bound_single_use_and_preserves_token_while_locked() {
    let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = session(&pool).await;
    let material = crate::ca::tests::test_material();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
        material.issuer().clone(),
    ));
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: "127.0.0.1:7443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    let app = router(auth, pool.clone(), source.clone(), endpoint);
    let key = PKey::generate_ed25519().unwrap();
    let key_digest = openssl::sha::sha256(&key.raw_public_key().unwrap());
    let unbound = request(
        &app,
        "/remote/invitations",
        json!({"host_id":host,"mode":"rootless","execution_uid":1002}),
        Some(&token),
        "https://auth.example.test",
    )
    .await;
    assert_eq!(unbound.status(), StatusCode::BAD_REQUEST);
    let invitation = json!({"host_id":host,"mode":"rootless","execution_uid":1002,"expected_key_digest":key_digest});
    assert_invitation_admission(&app, &invitation, &token).await;
    let response = request(
        &app,
        "/remote/invitations",
        invitation.clone(),
        Some(&token),
        "https://auth.example.test",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let published: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(published["public_origin"], "https://auth.example.test");
    // The direct QUIC listener is published again; the HTTPS origin stays the fallback (#146).
    assert!(published["endpoint"].is_string());
    let joined: JoinInvitation = serde_json::from_value(published).unwrap();
    assert_eq!(joined.execution_uid, 1002);
    assert_eq!(
        joined.ca_der,
        B64.encode(material.issuer().to_der().unwrap())
    );
    assert_eq!(
        request(
            &app,
            "/remote/invitations",
            // Keep this second request bound so it exercises single use rather
            // than failing the key-binding validation first.
            json!({"host_id":host,"mode":"rootless","execution_uid":1003,"expected_key_digest":key_digest}),
            Some(&token),
            "https://auth.example.test"
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let join = json!({"host_id":host,"mode":"rootless","token":joined.token,"csr_der":B64.encode(csr(&key))});
    assert_eq!(
        request(&app, "/remote/join", join.clone(), None, "")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    source.unlock_from(&Administrator(material)).unwrap();
    let mut oversized = join.clone();
    oversized["csr_der"] = json!("A".repeat(5463));
    assert_eq!(
        request(&app, "/remote/join", oversized, None, "")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_bound_join_response(&app, &store, &key, join).await;
}

async fn issue_bound_machine_invitation(
    app: &Router,
    token: &str,
    host_id: Uuid,
    key: &PKey<Private>,
) -> JoinInvitation {
    let response = request(
        app,
        "/remote/invitations",
        json!({
            "host_id": host_id,
            "mode": "rootful",
            "execution_uid": 0,
            "expected_key_digest": openssl::sha::sha256(&key.raw_public_key().unwrap()),
        }),
        Some(token),
        "https://auth.example.test",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn machine_invitation_spends_capability_after_key_mismatch() {
    let (_, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = session(&pool).await;
    let material = crate::ca::tests::test_material();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
        material.issuer().clone(),
    ));
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: "127.0.0.1:4443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    let app = router(auth, pool.clone(), source.clone(), endpoint);
    let host_id = Uuid::new_v4();
    let approved_key = PKey::generate_ed25519().unwrap();
    let invitation = issue_bound_machine_invitation(&app, &token, host_id, &approved_key).await;
    assert_eq!(invitation.host_id, host_id);
    assert_eq!(invitation.mode, Mode::Rootful);
    assert_eq!(invitation.execution_uid, 0);

    let other_key = PKey::generate_ed25519().unwrap();
    let response = request(
        &app,
        "/remote/join",
        json!({
            "host_id": host_id,
            "mode": "rootful",
            "token": invitation.token,
            "csr_der": B64.encode(csr(&other_key)),
        }),
        None,
        "",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a copied invitation cannot enroll a different key"
    );
    let consumed: bool = sqlx::query_scalar(
        "SELECT consumed_at IS NOT NULL FROM remote_join_tokens WHERE host_id=?",
    )
    .bind(host_id.as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(consumed, "a definitive key mismatch spends the invitation");
    let api_keys: i64 = sqlx::query_scalar("SELECT count(*) FROM api_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(api_keys, 0, "machine approval does not mint an API key");
}

#[tokio::test]
async fn machine_invitation_redeems_with_the_approved_public_key() {
    let (_, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = session(&pool).await;
    let material = crate::ca::tests::test_material();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
        material.issuer().clone(),
    ));
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: "127.0.0.1:4443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    let app = router(auth, pool.clone(), source.clone(), endpoint);
    let host_id = Uuid::new_v4();
    let approved_key = PKey::generate_ed25519().unwrap();
    let invitation = issue_bound_machine_invitation(&app, &token, host_id, &approved_key).await;
    source.unlock_from(&Administrator(material)).unwrap();
    assert_eq!(
        request(
            &app,
            "/remote/join",
            json!({
                "host_id": host_id,
                "mode": "rootful",
                "token": invitation.token,
                "csr_der": B64.encode(csr(&approved_key)),
            }),
            None,
            "",
        )
        .await
        .status(),
        StatusCode::OK,
        "the approved machine key can redeem its invitation"
    );
    let api_keys: i64 = sqlx::query_scalar("SELECT count(*) FROM api_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(api_keys, 0, "machine approval does not mint an API key");
}

/// Keep approval, replay, pending predecessor rejoin and key binding in one real HTTP lifecycle.
#[tokio::test]
async fn device_code_machine_join_returns_the_same_key_bound_receipt_on_retry() {
    let (store, pool, old_host) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = session(&pool).await;
    // The enrollment router uses wall time, so the approval's issue time must
    // not be in its future when this lifecycle reaches /remote/join.
    let now = super::now().unwrap();
    auth.set_test_http_time(now);
    // A reinstall gets a fresh host id. Old same-name tombstones and unfinished
    // removal must keep denying their old identities without denying the new one.
    sqlx::query("UPDATE remote_hosts SET hostname='laptop' WHERE id=?")
        .bind(old_host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO remote_login_cleanup(host_id,person_id,confirmed) VALUES(?,'owner',0)",
    )
    .bind(old_host.as_bytes().as_slice())
    .execute(&pool)
    .await
    .unwrap();
    let removed_host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at,revoked_at,hostname) VALUES(?,'owner','rootful',0,100,200,'laptop')")
        .bind(removed_host.as_bytes().as_slice()).execute(&pool).await.unwrap();
    let material = crate::ca::tests::test_material();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
        material.issuer().clone(),
    ));
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: "127.0.0.1:4443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    let issuer = InvitationIssuer::new(
        auth.clone(),
        pool.clone(),
        store.clone(),
        EnrollmentService {
            source: source.clone(),
            endpoint: endpoint.clone(),
        },
    );
    let app = crate::auth::router_with_invitation_issuer(auth.clone(), Some(issuer)).merge(
        router_with_store(
            auth.clone(),
            pool.clone(),
            store.clone(),
            source.clone(),
            endpoint,
        ),
    );
    let host_id = Uuid::new_v4();
    let key = PKey::generate_ed25519().unwrap();
    let key_digest = openssl::sha::sha256(&key.raw_public_key().unwrap());
    let key_fingerprint = format!("SHA256:{}", FINGERPRINT_B64.encode(key_digest));
    let start = request(
        &app,
        "/auth/device-start",
        json!({
            "kind": "join_machine",
            "device": "laptop",
            "request": {
                "host_id": host_id,
                "hostname": "laptop",
                "mode": "system",
                "execution_uid": 0,
                "key_fingerprint": key_fingerprint.clone(),
            },
        }),
        None,
        "https://auth.example.test",
    )
    .await;
    assert_eq!(start.status(), StatusCode::OK);
    let approval: Value =
        serde_json::from_slice(&start.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(approval["expires_in"], 600);

    let inspected = request(
        &app,
        "/auth/device-inspect",
        json!({"code":approval["user_code"]}),
        Some(&token),
        "https://auth.example.test",
    )
    .await;
    assert_eq!(inspected.status(), StatusCode::OK);
    let inspected: Value =
        serde_json::from_slice(&inspected.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        inspected,
        json!({
            "kind": "join_machine",
            "hostname": "laptop",
            "mode": "system",
            "key_fingerprint": key_fingerprint,
        })
    );
    // The bound passkey ceremony itself is covered by the auth tests; this
    // test is about what redemption does after an approval.
    auth.approve_without_passkey_for_tests(&token, approval["user_code"].as_str().unwrap(), now)
        .await
        .unwrap();

    let redeem = json!({"token":approval["poll_token"]});
    let response = request(&app, "/auth/device-redeem", redeem.clone(), None, "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let first: JoinInvitation =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(first.host_id, host_id);
    assert_eq!(first.mode, Mode::Rootful);
    assert_eq!(first.execution_uid, 0);
    // A device-code join carries the server's direct QUIC listener exactly as
    // an Add-host invitation does: App Windows lanes exist only on QUIC, so a
    // Mac approved by code would otherwise link over HTTPS for ever (#146, D349).
    assert_eq!(
        first.endpoint,
        Some("127.0.0.1:4443".parse().unwrap()),
        "the approved machine learns the direct endpoint"
    );
    let receipt_expiry: i64 =
        sqlx::query_scalar("SELECT expires_at FROM remote_join_tokens WHERE host_id=?")
            .bind(host_id.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(receipt_expiry, now + 600);
    let stored_key_digest: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT expected_key_digest FROM remote_join_tokens WHERE host_id=?")
            .bind(host_id.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(stored_key_digest.as_deref(), Some(key_digest.as_slice()));

    auth.set_test_http_time(now + 123);
    let response = request(&app, "/auth/device-redeem", redeem, None, "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let retry: JoinInvitation =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        retry.token, first.token,
        "the ten-minute receipt is exact-key stable"
    );
    let retry_expiry: i64 =
        sqlx::query_scalar("SELECT expires_at FROM remote_join_tokens WHERE host_id=?")
            .bind(host_id.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        retry_expiry, receipt_expiry,
        "poll retry cannot extend the receipt"
    );
    let api_keys: i64 = sqlx::query_scalar("SELECT count(*) FROM api_keys")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(api_keys, 0, "machine approval does not mint an API key");

    source.unlock_from(&Administrator(material)).unwrap();
    let capture = JoinLog::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(capture.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    assert_eq!(
        request(
            &app,
            "/remote/join",
            json!({
                "host_id": host_id, "mode": "rootful", "token": first.token,
                "csr_der": B64.encode(csr(&key)),
            }),
            None,
            ""
        )
        .await
        .status(),
        StatusCode::OK,
        "a newly approved key joins even while its previous same-name hosts are removed or pending: {}",
        String::from_utf8(capture.0.lock().unwrap().clone()).unwrap()
    );
    let pending: i64 =
        sqlx::query_scalar("SELECT confirmed FROM remote_login_cleanup WHERE host_id=?")
            .bind(old_host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        pending, 0,
        "a reinstall must not clear the old identity's denial"
    );
    let revoked: Option<i64> = sqlx::query_scalar("SELECT revoked_at FROM remote_hosts WHERE id=?")
        .bind(removed_host.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        revoked,
        Some(200),
        "the old tombstone must survive the new join"
    );

    auth.set_test_http_time(now + 601);
    assert_eq!(
        request(
            &app,
            "/auth/device-redeem",
            json!({"token":approval["poll_token"]}),
            None,
            ""
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED,
        "the exact-key receipt expires with the original approval"
    );
}

#[tokio::test]
async fn invitation_publication_rechecks_session_after_host_creation() {
    let (_, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = "B".repeat(43);
    let now = now().unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,'owner','test',?,?,1)")
        .bind(crate::auth::hash(&token)).bind(now+3600).bind(now).execute(&pool).await.unwrap();
    // A real SQLite trigger revokes authority between the HTTP session read
    // and invitation publication, without scheduler/timing assumptions.
    sqlx::query("CREATE TRIGGER logout_before_invitation BEFORE INSERT ON remote_hosts BEGIN DELETE FROM sessions; END")
        .execute(&pool).await.unwrap();
    let source = Arc::new(crate::ca::tests::source(true));
    let endpoint = EnrollmentEndpoint {
        ca_der: Vec::new(),
        endpoint: "127.0.0.1:7443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    let app = router(auth, pool.clone(), source, endpoint);
    let host = Uuid::new_v4();
    let response = request(
        &app,
        "/remote/invitations",
        json!({"host_id":host,"mode":"rootless","execution_uid":1002,"expected_key_digest":vec![7u8;32]}),
        Some(&token),
        "https://auth.example.test",
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let invitations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_join_tokens WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(invitations, 0);
}

fn process_cost() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat.split_whitespace().collect();
    (
        rss,
        fields[13].parse::<u64>().unwrap() + fields[14].parse::<u64>().unwrap(),
    )
}

#[tokio::test]
#[ignore = "explicit real HTTP-adapter/SQLite signing measurement at 1000 hosts; not transport or whole-daemon evidence"]
async fn enrollment_api_at_1000_hosts() {
    let (_, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = session(&pool).await;
    let material = crate::ca::tests::test_material();
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: "127.0.0.1:7443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    let app = router(auth, pool, Arc::new(Signer(material)), endpoint);
    let key = PKey::generate_ed25519().unwrap();
    let csr = B64.encode(csr(&key));
    let (before_rss, before_ticks) = process_cost();
    let mut times = Vec::new();
    let mut certificates = Vec::new();
    for _ in 0..1000 {
        let host = Uuid::new_v4();
        let started = std::time::Instant::now();
        let invitation = request(
            &app,
            "/remote/invitations",
            json!({"host_id":host,"mode":"rootless","execution_uid":1002}),
            Some(&token),
            "https://auth.example.test",
        )
        .await;
        assert_eq!(invitation.status(), StatusCode::OK);
        let invitation: JoinInvitation =
            serde_json::from_slice(&invitation.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let response = request(
            &app,
            "/remote/join",
            json!({"host_id":host,"mode":"rootless","token":invitation.token,"csr_der":csr}),
            None,
            "",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: JoinResponse =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        certificates.push(B64.decode(response.certificate_der).unwrap());
        times.push(started.elapsed().as_micros());
    }
    times.sort_unstable();
    let (after_rss, after_ticks) = process_cost();
    println!(
        "enrollment_api_diagnostic n=1000 invitation_and_redemption_p50_us={} p99_us={} cpu_ticks={} rss_delta_kib={} retained_certificate_der_bytes={} machine=infraternal-dev load={} excludes=tls,quic,daemon,live_renewal",
        times[500],
        times[990],
        after_ticks - before_ticks,
        after_rss.saturating_sub(before_rss),
        certificates.iter().map(Vec::len).sum::<usize>(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}

#[path = "remote_revocation_http_tests.rs"]
mod revocation;

/// J137 P3-3: a key's expiry is judged by the clock read inside the writer transaction. The
/// test clock stands in for the time after a wait on the writer: the key expired meanwhile,
/// so the call tombstones it and is refused instead of renewing it from a stale timestamp.
#[tokio::test]
async fn a_key_that_expires_while_waiting_for_the_writer_is_not_renewed() {
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let wall = now().unwrap();
    let key_hash = crate::auth::hash("fixture-expiring-key-never-print");
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,'owner','fixture-cli','[\"hosts:write\"]',?,?,0)")
        .bind(&key_hash)
        .bind(wall - 7200)
        .bind(wall + 30)
        .execute(&pool)
        .await
        .unwrap();
    auth.set_test_http_time(wall + 60);
    let issuer = InvitationIssuer::new(
        auth,
        pool.clone(),
        store,
        EnrollmentService {
            source: Arc::new(crate::ca::tests::source(true)),
            endpoint: EnrollmentEndpoint {
                ca_der: Vec::new(),
                endpoint: "127.0.0.1:7443".parse().unwrap(),
                server_name: "localhost".into(),
            },
        },
    );
    let refused = issuer
        .reissue_api_key(
            &key_hash,
            InvitationRequest {
                host_id: Uuid::new_v4(),
                mode: Mode::Rootless,
                execution_uid: 1002,
                expected_key_digest: Some([7; 32]),
            },
        )
        .await;
    assert_eq!(refused.err(), Some(StatusCode::FORBIDDEN));
    let (dead, expires_at): (bool, i64) =
        sqlx::query_as("SELECT dead,expires_at FROM api_keys WHERE token_hash=?")
            .bind(&key_hash)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(dead, "the expired key was renewed instead of tombstoned");
    assert_eq!(expires_at, wall + 30);
}

/// #559 F1: a device-code machine join may only publish a receipt for the host row its own
/// approval created. A promoted host has no join-token row left (the root handover deletes
/// it), so before this check a passkey-approved request naming that host's id got a fresh
/// receipt, and its own key then joined as a second active certificate for the host.
#[tokio::test]
async fn device_code_machine_join_cannot_name_an_existing_host() {
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    // The state a finished root handover leaves: a live root host with no
    // join-token row. (Mode changes only through a promotion, so the row is
    // seeded directly in its final form.)
    let existing = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at,hostname) VALUES(?,'owner','rootful',0,100,'laptop')")
        .bind(existing.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = session(&pool).await;
    let now = super::now().unwrap();
    auth.set_test_http_time(now);
    let material = crate::ca::tests::test_material();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
        material.issuer().clone(),
    ));
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: "127.0.0.1:4443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    let issuer = InvitationIssuer::new(
        auth.clone(),
        pool.clone(),
        store.clone(),
        EnrollmentService {
            source: source.clone(),
            endpoint: endpoint.clone(),
        },
    );
    let app = crate::auth::router_with_invitation_issuer(auth.clone(), Some(issuer)).merge(
        router_with_store(auth.clone(), pool.clone(), store, source, endpoint),
    );
    let key = PKey::generate_ed25519().unwrap();
    let key_digest = openssl::sha::sha256(&key.raw_public_key().unwrap());
    let start = request(
        &app,
        "/auth/device-start",
        json!({
            "kind": "join_machine",
            "device": "laptop",
            "request": {
                "host_id": existing,
                "hostname": "laptop",
                "mode": "system",
                "execution_uid": 0,
                "key_fingerprint": format!("SHA256:{}", FINGERPRINT_B64.encode(key_digest)),
            },
        }),
        None,
        "https://auth.example.test",
    )
    .await;
    assert_eq!(start.status(), StatusCode::OK);
    let approval: Value =
        serde_json::from_slice(&start.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let inspected = request(
        &app,
        "/auth/device-inspect",
        json!({"code":approval["user_code"]}),
        Some(&token),
        "https://auth.example.test",
    )
    .await;
    assert_eq!(inspected.status(), StatusCode::OK);
    auth.approve_without_passkey_for_tests(&token, approval["user_code"].as_str().unwrap(), now)
        .await
        .unwrap();
    let response = request(
        &app,
        "/auth/device-redeem",
        json!({"token":approval["poll_token"]}),
        None,
        "",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "an approval must not publish a receipt for a host it did not create"
    );
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_join_tokens WHERE host_id=?")
            .bind(existing.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(receipts, 0, "no receipt exists for the existing host");
}

/// Start, inspect, approve and redeem one device-code machine join for `host`,
/// the way `infraternal up` and the owner's approval page do, at the auth
/// clock's current time. Returns the redeem response.
async fn approve_and_redeem_machine_join(
    app: &Router,
    auth: &Auth,
    session: &str,
    host: Uuid,
    (mode, execution_uid): (&str, u32),
    key: &PKey<Private>,
    now: i64,
) -> Response {
    let key_digest = openssl::sha::sha256(&key.raw_public_key().unwrap());
    let start = request(
        app,
        "/auth/device-start",
        json!({
            "kind": "join_machine",
            "device": "laptop",
            "request": {
                "host_id": host,
                "hostname": "laptop",
                "mode": mode,
                "execution_uid": execution_uid,
                "key_fingerprint": format!("SHA256:{}", FINGERPRINT_B64.encode(key_digest)),
            },
        }),
        None,
        "https://auth.example.test",
    )
    .await;
    assert_eq!(start.status(), StatusCode::OK);
    let approval: Value =
        serde_json::from_slice(&start.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let inspected = request(
        app,
        "/auth/device-inspect",
        json!({"code":approval["user_code"]}),
        Some(session),
        "https://auth.example.test",
    )
    .await;
    assert_eq!(inspected.status(), StatusCode::OK);
    auth.approve_without_passkey_for_tests(session, approval["user_code"].as_str().unwrap(), now)
        .await
        .unwrap();
    request(
        app,
        "/auth/device-redeem",
        json!({"token":approval["poll_token"]}),
        None,
        "",
    )
    .await
}

/// #559 F1, for a host that a device-code approval itself created: after the
/// host joins and is promoted to root (which deletes its join-token row), a
/// later approval naming the same id must not get a receipt. Only the
/// `created_at` match refuses it here, since the row is device-approved. The
/// owner's own re-enrolment of that promoted host (an invitation, as SSH
/// setup's Retry uses, #230) must still work.
#[tokio::test]
async fn a_promoted_device_approved_host_refuses_a_later_approval_but_rejoins_by_invitation() {
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = session(&pool).await;
    let material = crate::ca::tests::test_material();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
        material.issuer().clone(),
    ));
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: "127.0.0.1:4443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    let issuer = InvitationIssuer::new(
        auth.clone(),
        pool.clone(),
        store.clone(),
        EnrollmentService {
            source: source.clone(),
            endpoint: endpoint.clone(),
        },
    );
    let app = crate::auth::router_with_invitation_issuer(auth.clone(), Some(issuer)).merge(
        router_with_store(auth.clone(), pool.clone(), store, source.clone(), endpoint),
    );
    source.unlock_from(&Administrator(material)).unwrap();
    // /remote/join reads wall time, so the first approval starts a minute
    // before it: its receipt is still live when the host joins.
    let now = super::now().unwrap();
    let host = Uuid::new_v4();
    let host_key = PKey::generate_ed25519().unwrap();
    auth.set_test_http_time(now - 60);
    let first = approve_and_redeem_machine_join(
        &app,
        &auth,
        &token,
        host,
        ("user", 1002),
        &host_key,
        now - 60,
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first: JoinInvitation =
        serde_json::from_slice(&first.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let joined = request(
        &app,
        "/remote/join",
        json!({
            "host_id": host, "mode": "rootless", "token": first.token,
            "csr_der": B64.encode(csr(&host_key)),
        }),
        None,
        "",
    )
    .await;
    assert_eq!(joined.status(), StatusCode::OK, "the approved host joins");
    // The writes of a finished root handover that matter here
    // (`remote_promotion::handover`): the row becomes root, and its join-token
    // row, the only other guard against a second receipt, is deleted. The
    // mode trigger allows that change only while an `enrolled` promotion
    // from this uid exists, so one is seeded in that state and then handed
    // over; its successor certificate is irrelevant to this check.
    let attempt = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO remote_host_promotions(attempt,host_id,person,method,account,from_uid,\
         from_fingerprint,link_generation,state,rooted,successor_fingerprint,successor_key,\
         started_at,expires_at) VALUES(?,?,'owner','sudo','person',1002,?,?,'enrolled',1,?,?,?,?)",
    )
    .bind(attempt.as_bytes().as_slice())
    .bind(host.as_bytes().as_slice())
    .bind([1_u8; 32].as_slice())
    .bind([2_u8; 16].as_slice())
    .bind([3_u8; 32].as_slice())
    .bind([4_u8; 32].as_slice())
    .bind(now - 30)
    .bind(now + 600)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE remote_hosts SET mode='rootful',execution_uid=0 WHERE id=?")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE remote_host_promotions SET state='handed_over',ended_at=? WHERE attempt=?")
        .bind(now - 20)
        .bind(attempt.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM remote_join_tokens WHERE host_id=?")
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();

    auth.set_test_http_time(now);
    let attacker_key = PKey::generate_ed25519().unwrap();
    let later = approve_and_redeem_machine_join(
        &app,
        &auth,
        &token,
        host,
        ("system", 0),
        &attacker_key,
        now,
    )
    .await;
    assert_eq!(
        later.status(),
        StatusCode::UNAUTHORIZED,
        "a later approval must not publish a receipt for a host an earlier approval created"
    );
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_join_tokens WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(receipts, 0, "no receipt exists for the promoted host");

    let invitation = issue_bound_machine_invitation(&app, &token, host, &host_key).await;
    let rejoined = request(
        &app,
        "/remote/join",
        json!({
            "host_id": host, "mode": "rootful", "token": invitation.token,
            "csr_der": B64.encode(csr(&host_key)),
        }),
        None,
        "",
    )
    .await;
    assert_eq!(
        rejoined.status(),
        StatusCode::OK,
        "the owner can still re-enrol the promoted host with its own key"
    );
}

/// The router and stores a device join runs against, with the CA unlocked.
async fn device_app() -> (Router, Auth, SqlitePool, EnrollmentStore, String) {
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let auth = Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    let token = session(&pool).await;
    let material = crate::ca::tests::test_material();
    let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
        material.issuer().clone(),
    ));
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: "127.0.0.1:4443".parse().unwrap(),
        server_name: "localhost".into(),
    };
    let issuer = InvitationIssuer::new(
        auth.clone(),
        pool.clone(),
        store.clone(),
        EnrollmentService {
            source: source.clone(),
            endpoint: endpoint.clone(),
        },
    );
    let app = crate::auth::router_with_invitation_issuer(auth.clone(), Some(issuer)).merge(
        router_with_store(
            auth.clone(),
            pool.clone(),
            store.clone(),
            source.clone(),
            endpoint,
        ),
    );
    source.unlock_from(&Administrator(material)).unwrap();
    (app, auth, pool, store, token)
}

/// Start a device-code `join_machine` approval with `body` as its request, return the response.
async fn start_join(app: &Router, body: Value) -> Response {
    request(
        app,
        "/auth/device-start",
        json!({"kind": "join_machine", "device": "iphone", "request": body}),
        None,
        "https://auth.example.test",
    )
    .await
}

/// #580 P5, end to end: an iPhone's P-256 key joins as a `device`. The owner's approval
/// binds the key, redemption publishes a host row with no uid, the ring-signed CSR is
/// admitted and certified, and the certificate admits the device as a device and as nothing
/// that runs terminals.
#[tokio::test]
async fn a_device_joins_with_its_p256_key_and_is_admitted_only_as_a_device() {
    let (app, auth, pool, _store, token) = device_app().await;
    // /remote/join reads wall time, so the approval is stamped at the wall clock.
    let now = super::now().unwrap();
    auth.set_test_http_time(now);
    let device = RingDevice::new();
    let host = Uuid::new_v4();
    let start = start_join(
        &app,
        json!({
            "host_id": host, "hostname": "kayg-iphone", "mode": "device",
            "key_fingerprint": device.fingerprint(),
        }),
    )
    .await;
    assert_eq!(start.status(), StatusCode::OK);
    let approval: Value =
        serde_json::from_slice(&start.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let inspected = request(
        &app,
        "/auth/device-inspect",
        json!({"code":approval["user_code"]}),
        Some(&token),
        "https://auth.example.test",
    )
    .await;
    assert_eq!(inspected.status(), StatusCode::OK);
    let inspected: Value =
        serde_json::from_slice(&inspected.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(inspected["mode"], "device");
    assert_eq!(inspected["key_fingerprint"], device.fingerprint());
    auth.approve_without_passkey_for_tests(&token, approval["user_code"].as_str().unwrap(), now)
        .await
        .unwrap();
    let redeemed = request(
        &app,
        "/auth/device-redeem",
        json!({"token": approval["poll_token"]}),
        None,
        "",
    )
    .await;
    assert_eq!(redeemed.status(), StatusCode::OK);
    let invitation: JoinInvitation =
        serde_json::from_slice(&redeemed.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!((invitation.host_id, invitation.mode), (host, Mode::Device));
    // The host row: a device, no uid, named as it asked, bound to its approved key.
    let row: (String, Option<i64>, i64, Option<String>) = sqlx::query_as(
        "SELECT mode, execution_uid, device_approved, hostname FROM remote_hosts WHERE id=?",
    )
    .bind(host.as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, ("device".into(), None, 1, Some("kayg-iphone".into())));
    let bound: (String, Vec<u8>) = sqlx::query_as(
        "SELECT key_algorithm, expected_key_digest FROM remote_join_tokens WHERE host_id=?",
    )
    .bind(host.as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (bound.0.as_str(), bound.1),
        ("p256", device.digest().to_vec())
    );

    // A request for another key is refused, whatever its signature.
    let other = RingDevice::new();
    let refused = request(
        &app,
        "/remote/join",
        json!({"host_id": host, "mode": "device", "token": invitation.token,
               "csr_der": B64.encode(other.csr())}),
        None,
        "",
    )
    .await;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "another key");
    // The refusal spent the invitation, so the device re-approves (a new receipt) to join.
    let spent = request(
        &app,
        "/remote/join",
        json!({"host_id": host, "mode": "device", "token": invitation.token,
               "csr_der": B64.encode(device.csr())}),
        None,
        "",
    )
    .await;
    assert_eq!(spent.status(), StatusCode::FORBIDDEN, "a spent invitation");
}

/// The same flow, joined successfully: the ring-signed CSR yields a P-256 leaf that the server
/// admits as a device, and the wire answers uid 0 as the filler for "no uid".
#[tokio::test]
async fn a_ring_signed_device_csr_is_certified_and_admitted() {
    let (app, auth, pool, store, token) = device_app().await;
    let now = super::now().unwrap();
    auth.set_test_http_time(now);
    let device = RingDevice::new();
    let host = Uuid::new_v4();
    let start = start_join(
        &app,
        json!({"host_id": host, "hostname": "kayg-iphone", "mode": "device",
               "key_fingerprint": device.fingerprint()}),
    )
    .await;
    let approval: Value =
        serde_json::from_slice(&start.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let inspected = request(
        &app,
        "/auth/device-inspect",
        json!({"code":approval["user_code"]}),
        Some(&token),
        "https://auth.example.test",
    )
    .await;
    assert_eq!(inspected.status(), StatusCode::OK);
    auth.approve_without_passkey_for_tests(&token, approval["user_code"].as_str().unwrap(), now)
        .await
        .unwrap();
    let invitation: JoinInvitation = serde_json::from_slice(
        &request(
            &app,
            "/auth/device-redeem",
            json!({"token": approval["poll_token"]}),
            None,
            "",
        )
        .await
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes(),
    )
    .unwrap();
    let joined = request(
        &app,
        "/remote/join",
        json!({"host_id": host, "mode": "device", "token": invitation.token,
               "csr_der": B64.encode(device.csr())}),
        None,
        "",
    )
    .await;
    assert_eq!(joined.status(), StatusCode::OK);
    let joined: JoinResponse =
        serde_json::from_slice(&joined.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(joined.execution_uid, 0, "the wire's filler for no uid");
    let leaf = openssl::x509::X509::from_der(&B64.decode(joined.certificate_der).unwrap()).unwrap();
    let leaf_key = leaf.public_key().unwrap().ec_key().unwrap();
    let group = leaf_key.group();
    let mut context = openssl::bn::BigNumContext::new().unwrap();
    assert_eq!(
        leaf_key
            .public_key()
            .to_bytes(
                group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut context
            )
            .unwrap(),
        device.point(),
        "the certificate certifies the device's own key"
    );
    // The certificate's window starts at the join's own wall-clock second, which may be after `now`.
    let joined_at = super::now().unwrap();
    let fingerprint: [u8; 32] = leaf
        .digest(MessageDigest::sha256())
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap();
    assert_eq!(
        store.admit_device(&fingerprint, joined_at).await.unwrap().host,
        host
    );
    assert!(
        store.admit(&fingerprint, joined_at).await.is_err(),
        "the terminal host guard refuses a device certificate"
    );
    let certificate_uid: Option<i64> =
        sqlx::query_scalar("SELECT execution_uid FROM remote_certificates WHERE fingerprint=?")
            .bind(fingerprint.as_slice())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(certificate_uid, None);
}

/// Every refusal on the way in, each red: a device request that carries a uid, a host request
/// that carries none, an unknown mode, the owner-invitation endpoint with `device`, and a join
/// that names the `device` mode with a host invitation or the reverse.
#[tokio::test]
async fn device_requests_that_do_not_fit_the_mode_are_refused() {
    let (app, auth, pool, _store, token) = device_app().await;
    let now = super::now().unwrap();
    auth.set_test_http_time(now);
    let device = RingDevice::new();
    for body in [
        json!({"host_id": Uuid::new_v4(), "hostname": "p", "mode": "device", "execution_uid": 0,
               "key_fingerprint": device.fingerprint()}),
        json!({"host_id": Uuid::new_v4(), "hostname": "p", "mode": "device", "execution_uid": 501,
               "key_fingerprint": device.fingerprint()}),
        json!({"host_id": Uuid::new_v4(), "hostname": "p", "mode": "system",
               "key_fingerprint": device.fingerprint()}),
        json!({"host_id": Uuid::new_v4(), "hostname": "p", "mode": "user",
               "key_fingerprint": device.fingerprint()}),
        json!({"host_id": Uuid::new_v4(), "hostname": "p", "mode": "phone",
               "key_fingerprint": device.fingerprint()}),
    ] {
        let response = start_join(&app, body.clone()).await;
        assert_ne!(response.status(), StatusCode::OK, "{body} was accepted");
    }
    // The owner-invitation endpoint makes invitations for hosts that run the agent; never a device.
    for uid in [0, 501] {
        let invited = request(
            &app,
            "/remote/invitations",
            json!({"host_id": Uuid::new_v4(), "mode": "device", "execution_uid": uid,
                   "expected_key_digest": device.digest()}),
            Some(&token),
            "https://auth.example.test",
        )
        .await;
        assert_eq!(invited.status(), StatusCode::FORBIDDEN, "uid {uid}");
    }
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_hosts WHERE mode='device'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(devices, 0, "no refusal left a device row behind");
}
