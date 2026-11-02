//! Exercises the real enrollment router with SQLite, real signed CSR, host uid binding and a cold-locked CA, #78.

use super::*;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    x509::{X509NameBuilder, X509Req},
};
use serde_json::{Value, json};
use tower::ServiceExt;

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
    assert!(published.get("endpoint").is_none());
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
            json!({"host_id":host,"mode":"rootless","execution_uid":1003}),
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
    let response = request(&app, "/remote/join", join.clone(), None, "").await;
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
            .public_eq(&key)
    );
    assert_eq!(
        store
            // Admission observes the time after issuance, including a slow test host.
            .admit(&openssl::sha::sha256(&der), now().unwrap())
            .await
            .unwrap()
            .execution_uid,
        1002
    );
    assert_eq!(
        request(&app, "/remote/join", join, None, "").await.status(),
        StatusCode::FORBIDDEN
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
