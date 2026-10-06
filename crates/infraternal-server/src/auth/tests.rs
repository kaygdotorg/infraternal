//! Defensive tests with a real ES256 software authenticator and a browser-side PRF/keywrap double.
//! No verifier is mocked: CBOR attestation, client data, flags and signatures enter webauthn-rs.
use super::*;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_cbor_2::Value as Cbor;
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqlitePoolOptions;
use std::{collections::BTreeMap, time::Instant};
use tower::ServiceExt;

static SERIAL: Mutex<()> = Mutex::const_new(());
const NOW: i64 = 1_800_000_000;
const ORIGIN: &str = "https://auth.example.test";

struct Software {
    key: PKey<Private>,
    id: Vec<u8>,
    prf_key: PKey<Private>,
    counter: u32,
}
impl Software {
    fn new() -> Self {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        Self {
            key: PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap(),
            id: rand::random::<[u8; 32]>().to_vec(),
            prf_key: PKey::hmac(&rand::random::<[u8; 32]>()).unwrap(),
            counter: 0,
        }
    }
    fn client_data(start: &Value, kind: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"type":kind,"challenge":start["options"]["publicKey"]["challenge"],"origin":origin,"crossOrigin":false})).unwrap()
    }
    fn auth_data(&self, flags: u8) -> Vec<u8> {
        let mut data = Sha256::digest(b"auth.example.test").to_vec();
        data.push(flags);
        data.extend_from_slice(&self.counter.to_be_bytes());
        data
    }
    fn registration(&self, start: &Value, origin: &str, uv: bool) -> Value {
        assert_eq!(
            start["options"]["publicKey"]["authenticatorSelection"]["residentKey"],
            "required"
        );
        assert_eq!(
            start["options"]["publicKey"]["authenticatorSelection"]["userVerification"],
            "required"
        );
        let ec = self.key.ec_key().unwrap();
        let mut x = BigNum::new().unwrap();
        let mut y = BigNum::new().unwrap();
        ec.public_key()
            .affine_coordinates_gfp(
                ec.group(),
                &mut x,
                &mut y,
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
        let key = Cbor::Map(BTreeMap::from([
            (Cbor::Integer(1), Cbor::Integer(2)),
            (Cbor::Integer(3), Cbor::Integer(-7)),
            (Cbor::Integer(-1), Cbor::Integer(1)),
            (Cbor::Integer(-2), Cbor::Bytes(x.to_vec_padded(32).unwrap())),
            (Cbor::Integer(-3), Cbor::Bytes(y.to_vec_padded(32).unwrap())),
        ]));
        let mut data = self.auth_data(if uv { 0x45 } else { 0x41 });
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&u16::try_from(self.id.len()).unwrap().to_be_bytes());
        data.extend_from_slice(&self.id);
        data.extend_from_slice(&serde_cbor_2::to_vec(&key).unwrap());
        let attestation = Cbor::Map(BTreeMap::from([
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(BTreeMap::new())),
            (Cbor::Text("authData".into()), Cbor::Bytes(data)),
        ]));
        json!({"id":B64.encode(&self.id),"rawId":B64.encode(&self.id),"type":"public-key","response":{"clientDataJSON":B64.encode(Self::client_data(start,"webauthn.create",origin)),"attestationObject":B64.encode(serde_cbor_2::to_vec(&attestation).unwrap()),"transports":["internal"]},"extensions":{"credProps":{"rk":true}}})
    }
    fn login(&mut self, start: &Value, origin: &str, uv: bool) -> Value {
        assert_eq!(
            start["options"]["publicKey"]["userVerification"],
            "required"
        );
        self.counter += 1;
        let data = self.auth_data(if uv { 5 } else { 1 });
        let client = Self::client_data(start, "webauthn.get", origin);
        let mut message = data.clone();
        message.extend_from_slice(&Sha256::digest(&client));
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
        signer.update(&message).unwrap();
        json!({"id":B64.encode(&self.id),"rawId":B64.encode(&self.id),"type":"public-key","response":{"clientDataJSON":B64.encode(client),"authenticatorData":B64.encode(data),"signature":B64.encode(signer.sign_to_vec().unwrap()),"userHandle":null},"extensions":{}})
    }
    fn prf(&self, start: &Value) -> Vec<u8> {
        let salt = B64
            .decode(
                start["options"]["publicKey"]["extensions"]["prf"]["eval"]["first"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        // The software client applies WebAuthn's PRF domain prefix before hmac-secret.
        let mut input = b"WebAuthn PRF\0".to_vec();
        input.extend_from_slice(&salt);
        let mut signer = Signer::new(MessageDigest::sha256(), &self.prf_key).unwrap();
        signer.update(&Sha256::digest(&input)).unwrap();
        signer.sign_to_vec().unwrap()
    }
}
fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap()
}
fn aad(user: &str, kind: &str) -> Vec<u8> {
    format!("infraternal/keywrap/v1|{user}|{kind}").into_bytes()
}
fn browser_wrap(ikm: &[u8], dek: &[u8], user: &str, kind: &str) -> Wrap {
    let salt = rand::random::<[u8; 32]>();
    let nonce = rand::random::<[u8; 12]>();
    let aad = aad(user, kind);
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(Some(&salt), ikm)
        .expand(&aad, &mut key)
        .unwrap();
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: dek,
                aad: &aad,
            },
        )
        .unwrap();
    Wrap {
        salt: B64.encode(salt),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    }
}
fn unwrap_browser(
    ikm: &[u8],
    wrap: &Wrap,
    user: &str,
    kind: &str,
) -> std::result::Result<Vec<u8>, aes_gcm::Error> {
    let salt = B64.decode(&wrap.salt).unwrap();
    let nonce = B64.decode(&wrap.nonce).unwrap();
    let ciphertext = B64.decode(&wrap.ciphertext).unwrap();
    let aad = aad(user, kind);
    let mut key = [0; 32];
    Hkdf::<Sha256>::new(Some(&salt), ikm)
        .expand(&aad, &mut key)
        .unwrap();
    Aes256Gcm::new_from_slice(&key).unwrap().decrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: &ciphertext,
            aad: &aad,
        },
    )
}
fn recovery_ikm(words: &str) -> Vec<u8> {
    bip39::Mnemonic::parse_in(bip39::Language::English, words)
        .unwrap()
        .to_entropy()
}
struct Fixture {
    auth: Auth,
    software: Software,
    user: String,
    session: String,
    words: String,
    dek: [u8; 32],
}
async fn empty() -> (Auth, String) {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let auth = Auth::new(pool, "auth.example.test", ORIGIN).await.unwrap();
    let mut token = String::new();
    auth.bootstrap(NOW, |banner| token = banner.lines().nth(1).unwrap().into())
        .await
        .unwrap();
    (auth, token)
}
async fn fixture() -> Fixture {
    let (auth, token) = empty().await;
    let start = auth.setup_start(&token, "owner", NOW).await.unwrap();
    let user = str_field(&start, "user_id").to_owned();
    let words = str_field(&start, "recovery_words").to_owned();
    let software = Software::new();
    let dek = rand::random::<[u8; 32]>();
    let pw = browser_wrap(&software.prf(&start), &dek, &user, "passkey");
    let rw = browser_wrap(&recovery_ikm(&words), &dek, &user, "recovery");
    let session = auth
        .registration_finish(
            str_field(&start, "ceremony"),
            software.registration(&start, ORIGIN, true),
            pw,
            Some(rw),
            NOW,
        )
        .await
        .unwrap();
    assert!(auth.setup_start(&token, "attacker", NOW).await.is_err());
    Fixture {
        auth,
        software,
        user,
        session,
        words,
        dek,
    }
}
async fn finish_replacement(f: &Fixture, start: &Value, software: &Software, now: i64) -> String {
    let old: Wrap = serde_json::from_value(start["old_recovery_wrap"].clone()).unwrap();
    let dek = unwrap_browser(&recovery_ikm(&f.words), &old, &f.user, "recovery").unwrap();
    assert_eq!(dek, f.dek);
    let pw = browser_wrap(&software.prf(start), &dek, &f.user, "passkey");
    let rw = browser_wrap(
        &recovery_ikm(str_field(start, "recovery_words")),
        &dek,
        &f.user,
        "recovery",
    );
    f.auth
        .registration_finish(
            str_field(start, "ceremony"),
            software.registration(start, ORIGIN, true),
            pw,
            Some(rw),
            now,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn ceremony_prf_wraps_and_optional_second_passkey() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let start = f.auth.login_start(&f.user, NOW + 1).await.unwrap();
    let prf = f.software.prf(&start);
    let wraps = f.auth.wraps(&f.session, NOW + 1).await.unwrap();
    let wrap: Wrap = serde_json::from_value(
        wraps
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["kind"] == "passkey")
            .unwrap()["wrap"]
            .clone(),
    )
    .unwrap();
    assert_eq!(
        unwrap_browser(&prf, &wrap, &f.user, "passkey").unwrap(),
        f.dek
    );
    assert!(unwrap_browser(&prf, &wrap, &Uuid::new_v4().to_string(), "passkey").is_err());
    assert!(unwrap_browser(&rand::random::<[u8; 32]>(), &wrap, &f.user, "passkey").is_err());
    let proof = f.software.login(&start, ORIGIN, true);
    let session = f
        .auth
        .login_finish(
            str_field(&start, "ceremony"),
            proof.clone(),
            "phone",
            NOW + 1,
        )
        .await
        .unwrap();
    assert_eq!(
        f.auth.session(&session, NOW + 2).await.unwrap().device,
        "phone"
    );
    assert!(
        f.auth
            .login_finish(str_field(&start, "ceremony"), proof, "phone", NOW + 2)
            .await
            .is_err()
    );
    let add = f.auth.add_start(&session, NOW + 3).await.unwrap();
    assert!(add["recovery_words"].is_null());
    let second = Software::new();
    let pw = browser_wrap(&second.prf(&add), &f.dek, &f.user, "passkey");
    f.auth
        .registration_finish(
            str_field(&add, "ceremony"),
            second.registration(&add, ORIGIN, true),
            pw,
            None,
            NOW + 3,
        )
        .await
        .unwrap();
    assert!(f.auth.add_start(&session, NOW + 4).await.is_err());
    assert_eq!(f.auth.passkeys(&f.user).await.unwrap().len(), 2);
    assert_eq!(
        f.auth
            .wraps(&session, NOW + 4)
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[tokio::test]
async fn rejected_origin_uv_challenge_signature_prf_and_expired_ceremonies() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    for (origin, uv) in [("https://evil.example.test", true), (ORIGIN, false)] {
        let start = f.auth.login_start(&f.user, NOW).await.unwrap();
        let proof = f.software.login(&start, origin, uv);
        assert!(
            f.auth
                .login_finish(str_field(&start, "ceremony"), proof, "phone", NOW)
                .await
                .is_err()
        );
    }
    let a = f.auth.login_start(&f.user, NOW).await.unwrap();
    let b = f.auth.login_start(&f.user, NOW).await.unwrap();
    let proof = f.software.login(&a, ORIGIN, true);
    assert!(
        f.auth
            .login_finish(str_field(&b, "ceremony"), proof, "phone", NOW)
            .await
            .is_err()
    );
    let start = f.auth.login_start(&f.user, NOW).await.unwrap();
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["response"]["signature"] = json!(B64.encode([0; 64]));
    assert!(
        f.auth
            .login_finish(str_field(&start, "ceremony"), proof, "phone", NOW)
            .await
            .is_err()
    );
    let start = f.auth.login_start(&f.user, NOW).await.unwrap();
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["extensions"]["prf"] = json!({"results":{"first":B64.encode(f.software.prf(&start))}});
    assert!(matches!(
        f.auth
            .login_finish(str_field(&start, "ceremony"), proof, "phone", NOW)
            .await,
        Err(Error::Invalid)
    ));
    let start = f.auth.login_start(&f.user, NOW).await.unwrap();
    let proof = f.software.login(&start, ORIGIN, true);
    assert!(
        f.auth
            .login_finish(
                str_field(&start, "ceremony"),
                proof,
                "phone",
                NOW + CEREMONY
            )
            .await
            .is_err()
    );
    let add = f.auth.add_start(&f.session, NOW).await.unwrap();
    let software = Software::new();
    let wrap = browser_wrap(&software.prf(&add), &f.dek, &f.user, "passkey");
    assert!(
        f.auth
            .registration_finish(
                str_field(&add, "ceremony"),
                software.registration(&add, "https://evil.example.test", true),
                wrap,
                None,
                NOW
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn setup_expiry_single_announcement_and_parallel_redemption() {
    let _guard = SERIAL.lock().await;
    let (auth, token) = empty().await;
    auth.bootstrap(NOW, |_| panic!("setup token announced twice"))
        .await
        .unwrap();
    assert!(auth.setup_start(&token, "owner", NOW + DAY).await.is_err());
    let a = auth.setup_start(&token, "owner", NOW).await.unwrap();
    let b = auth.setup_start(&token, "owner", NOW).await.unwrap();
    let software = Software::new();
    let dek = rand::random::<[u8; 32]>();
    for (start, succeeds) in [(&a, true), (&b, false)] {
        let user = str_field(start, "user_id");
        let pw = browser_wrap(&software.prf(start), &dek, user, "passkey");
        let rw = browser_wrap(
            &recovery_ikm(str_field(start, "recovery_words")),
            &dek,
            user,
            "recovery",
        );
        let result = auth
            .registration_finish(
                str_field(start, "ceremony"),
                software.registration(start, ORIGIN, true),
                pw,
                Some(rw),
                NOW,
            )
            .await;
        assert_eq!(result.is_ok(), succeeds);
    }
    auth.bootstrap(NOW + 2 * DAY, |_| panic!("owner caused reannouncement"))
        .await
        .unwrap();
    let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE owner=1")
        .fetch_one(&auth.pool)
        .await
        .unwrap();
    assert_eq!(owners, 1);
}

#[tokio::test]
async fn recovery_delay_cancel_and_replacement_revokes_every_capability() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    assert!(
        f.auth
            .recovery_start(
                &f.user,
                bip39::Mnemonic::generate(24).unwrap().to_string(),
                NOW
            )
            .await
            .is_err()
    );
    let token = f
        .auth
        .recovery_start(&f.user, f.words.clone(), NOW)
        .await
        .unwrap();
    assert!(f.auth.recovery_ready(&token, NOW + DAY - 1).await.is_err());
    assert!(
        f.auth
            .recovery_start(&f.user, f.words.clone(), NOW + 1)
            .await
            .is_err()
    );
    let start = f.auth.recovery_ready(&token, NOW + DAY).await.unwrap();
    f.auth.recovery_cancel(&f.session, NOW + DAY).await.unwrap();
    assert!(f.auth.recovery_ready(&token, NOW + DAY).await.is_err());
    let second = Software::new();
    let pw = browser_wrap(&second.prf(&start), &f.dek, &f.user, "passkey");
    let rw = browser_wrap(
        &recovery_ikm(str_field(&start, "recovery_words")),
        &f.dek,
        &f.user,
        "recovery",
    );
    assert!(
        f.auth
            .registration_finish(
                str_field(&start, "ceremony"),
                second.registration(&start, ORIGIN, true),
                pw,
                Some(rw),
                NOW + DAY
            )
            .await
            .is_err()
    );
    let token = f
        .auth
        .recovery_start(&f.user, f.words.clone(), NOW + DAY)
        .await
        .unwrap();
    let start = f.auth.recovery_ready(&token, NOW + 2 * DAY).await.unwrap();
    let session = finish_replacement(&f, &start, &second, NOW + 2 * DAY).await;
    assert!(f.auth.session(&f.session, NOW + 2 * DAY).await.is_err());
    assert!(f.auth.recovery_ready(&token, NOW + 2 * DAY).await.is_err());
    assert!(
        f.auth
            .recovery_start(&f.user, f.words, NOW + 2 * DAY)
            .await
            .is_err()
    );
    assert_eq!(f.auth.passkeys(&f.user).await.unwrap().len(), 1);
    assert!(f.auth.session(&session, NOW + 2 * DAY).await.is_ok());
}

#[tokio::test]
async fn sessions_slide_but_fresh_tap_does_not_and_device_keys_are_scoped() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    assert!(f.auth.session(&random(), NOW).await.is_err());
    f.auth.session(&f.session, NOW + SESSION - 1).await.unwrap();
    assert!(
        f.auth
            .session(&f.session, NOW + 2 * SESSION - 2)
            .await
            .is_ok()
    );
    assert!(
        f.auth
            .session(&f.session, NOW + 3 * SESSION - 2)
            .await
            .is_err()
    );
    // New fixture avoids resurrecting an expired record for the device API assertions.
    let f = fixture().await;
    let approval = f
        .auth
        .device_start("cli", vec!["hosts:read".into()], NOW)
        .await
        .unwrap();
    assert!(
        f.auth
            .device_redeem(str_field(&approval, "poll_token"), NOW)
            .await
            .is_err()
    );
    assert!(
        f.auth
            .device_redeem(str_field(&approval, "user_code"), NOW)
            .await
            .is_err()
    );
    assert_eq!(
        f.auth
            .device_inspect(&f.session, str_field(&approval, "user_code"), NOW)
            .await
            .unwrap()["scopes"],
        json!(["hosts:read"])
    );
    f.auth
        .device_approve(&f.session, str_field(&approval, "user_code"), NOW)
        .await
        .unwrap();
    let key = f
        .auth
        .device_redeem(str_field(&approval, "poll_token"), NOW)
        .await
        .unwrap();
    assert_eq!(
        f.auth.api_authorize(&key, "hosts:read").await.unwrap(),
        f.user
    );
    assert!(
        f.auth
            .api_authorize(&key, "terminal:connect")
            .await
            .is_err()
    );
    assert!(
        f.auth
            .device_redeem(str_field(&approval, "poll_token"), NOW)
            .await
            .is_err()
    );
    assert!(f.auth.add_start(&f.session, NOW + FRESH).await.is_err());
    f.auth
        .api_revoke(&f.session, &hash(&key), NOW + 1)
        .await
        .unwrap();
    assert!(f.auth.api_authorize(&key, "hosts:read").await.is_err());
    assert!(
        f.auth
            .device_start("cli", vec!["admin".into()], NOW)
            .await
            .is_err()
    );
    let approval = f
        .auth
        .device_start("cli", vec!["hosts:read".into()], NOW)
        .await
        .unwrap();
    assert!(
        f.auth
            .device_approve(&f.session, str_field(&approval, "user_code"), NOW + 600)
            .await
            .is_err()
    );
    let stored: String = sqlx::query_scalar("SELECT recovery_hash FROM users WHERE id=?")
        .bind(&f.user)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert!(stored.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
    assert!(!stored.contains(&f.words));
    f.auth.logout(&f.session).await.unwrap();
    assert!(f.auth.session(&f.session, NOW).await.is_err());
}

#[tokio::test]
async fn http_csrf_cookie_flags_body_limit_and_latency_evidence() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let router = router(f.auth.clone());
    let request = |origin: &str| {
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/session")
            .header("Origin", origin)
            .header("Cookie", format!("__Host-infraternal={}", f.session))
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap()
    };
    assert_eq!(
        router
            .clone()
            .oneshot(request("https://evil.example.test"))
            .await
            .unwrap()
            .status(),
        axum::http::StatusCode::UNAUTHORIZED
    );
    // Synthetic timestamps do not match wall time; use a fresh real-time session for HTTP.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    sqlx::query("UPDATE sessions SET expires=?,fresh=?")
        .bind(now + SESSION)
        .bind(now)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let response = router.clone().oneshot(request(ORIGIN)).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let cookie = response.headers()["set-cookie"].to_str().unwrap();
    for flag in [
        "Secure",
        "HttpOnly",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=2592000",
    ] {
        assert!(cookie.contains(flag));
    }
    assert!(!cookie.contains("Domain="));
    let wraps_request = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/wraps")
        .header("Origin", ORIGIN)
        .header("Cookie", format!("__Host-infraternal={}", f.session))
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from("{}"))
        .unwrap();
    let wraps_response = router.clone().oneshot(wraps_request).await.unwrap();
    assert!(wraps_response.headers().contains_key("set-cookie"));

    assert_eq!(response.headers()["cache-control"], "no-store");
    let oversized = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/device-start")
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from("x".repeat(33 * 1024)))
        .unwrap();
    assert_eq!(
        router.oneshot(oversized).await.unwrap().status(),
        axum::http::StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut samples = Vec::new();
    for _ in 0..200 {
        let start = Instant::now();
        f.auth.session(&f.session, now).await.unwrap();
        samples.push(start.elapsed().as_micros());
    }
    samples.sort_unstable();
    eprintln!(
        "auth session SQLite memory: n=200 p50={}us p99={}us",
        samples[100], samples[198]
    );
    let start = Instant::now();
    verify_recovery(
        f.words.clone(),
        sqlx::query_scalar("SELECT recovery_hash FROM users WHERE id=?")
            .bind(&f.user)
            .fetch_one(&f.auth.pool)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    eprintln!(
        "auth Argon2id verification: {}ms (m=19456KiB,t=2,p=1)",
        start.elapsed().as_millis()
    );
}

#[tokio::test]
async fn concurrent_owner_and_optional_passkey_enrollment_fail_closed() {
    let _guard = SERIAL.lock().await;
    let (auth, token) = empty().await;
    let (a, b) = tokio::join!(
        auth.setup_start(&token, "owner", NOW),
        auth.setup_start(&token, "owner", NOW)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let one = Software::new();
    let two = Software::new();
    let dek = rand::random::<[u8; 32]>();
    let finish = |start: Value, software: Software| {
        let auth = auth.clone();
        async move {
            let user = str_field(&start, "user_id");
            let pw = browser_wrap(&software.prf(&start), &dek, user, "passkey");
            let rw = browser_wrap(
                &recovery_ikm(str_field(&start, "recovery_words")),
                &dek,
                user,
                "recovery",
            );
            auth.registration_finish(
                str_field(&start, "ceremony"),
                software.registration(&start, ORIGIN, true),
                pw,
                Some(rw),
                NOW,
            )
            .await
        }
    };
    let (first, second) = tokio::join!(finish(a, one), finish(b, two));
    assert_ne!(first.is_ok(), second.is_ok());
    let f = fixture().await;
    let (a, b) = tokio::join!(
        f.auth.add_start(&f.session, NOW),
        f.auth.add_start(&f.session, NOW)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    let one = Software::new();
    let two = Software::new();
    let pw = browser_wrap(&one.prf(&a), &f.dek, &f.user, "passkey");
    let other = browser_wrap(&two.prf(&b), &f.dek, &f.user, "passkey");
    let (first, second) = tokio::join!(
        f.auth.registration_finish(
            str_field(&a, "ceremony"),
            one.registration(&a, ORIGIN, true),
            pw,
            None,
            NOW
        ),
        f.auth.registration_finish(
            str_field(&b, "ceremony"),
            two.registration(&b, ORIGIN, true),
            other,
            None,
            NOW
        )
    );
    assert_ne!(first.is_ok(), second.is_ok());
    assert_eq!(f.auth.passkeys(&f.user).await.unwrap().len(), 2);
}

#[tokio::test]
async fn recovery_expiry_revocation_and_cross_user_isolation() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let approval = f
        .auth
        .device_start("cli", vec!["hosts:read".into()], NOW)
        .await
        .unwrap();
    f.auth
        .device_approve(&f.session, str_field(&approval, "user_code"), NOW)
        .await
        .unwrap();
    let api_key = f
        .auth
        .device_redeem(str_field(&approval, "poll_token"), NOW)
        .await
        .unwrap();
    let token = f
        .auth
        .recovery_start(&f.user, f.words.clone(), NOW)
        .await
        .unwrap();
    assert!(f.auth.recovery_ready(&token, NOW + 2 * DAY).await.is_err());
    let token = f
        .auth
        .recovery_start(&f.user, f.words.clone(), NOW + 2 * DAY)
        .await
        .unwrap();
    let start = f.auth.recovery_ready(&token, NOW + 3 * DAY).await.unwrap();
    let replacement = Software::new();
    finish_replacement(&f, &start, &replacement, NOW + 3 * DAY).await;
    assert!(f.auth.api_authorize(&api_key, "hosts:read").await.is_err());
    let login = f.auth.login_start(&f.user, NOW + 3 * DAY).await.unwrap();
    assert!(
        f.auth
            .login_finish(
                str_field(&login, "ceremony"),
                f.software.login(&login, ORIGIN, true),
                "stolen",
                NOW + 3 * DAY
            )
            .await
            .is_err()
    );
    let other = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES (?,'other',0,'unused')")
        .bind(&other)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let mut tx = f.auth.pool.begin().await.unwrap();
    let other_token = random();
    insert_session(&mut tx, &other_token, &other, "other device", NOW)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(f.auth.wraps(&other_token, NOW).await.unwrap(), json!([]));
    assert_eq!(f.auth.api_list(&other_token, NOW).await.unwrap(), json!([]));
}

#[tokio::test]
async fn stale_counters_recovery_cancellation_and_wrap_tampering() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let a = f.auth.login_start(&f.user, NOW).await.unwrap();
    let b = f.auth.login_start(&f.user, NOW).await.unwrap();
    let old = f.software.login(&a, ORIGIN, true);
    let new = f.software.login(&b, ORIGIN, true);
    f.auth
        .login_finish(str_field(&b, "ceremony"), new, "phone", NOW)
        .await
        .unwrap();
    assert!(
        f.auth
            .login_finish(str_field(&a, "ceremony"), old, "phone", NOW)
            .await
            .is_err()
    );
    let start = f.auth.login_start(&f.user, NOW).await.unwrap();
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["response"]["userHandle"] = json!(B64.encode(Uuid::new_v4().as_bytes()));
    assert!(
        f.auth
            .login_finish(str_field(&start, "ceremony"), proof, "phone", NOW)
            .await
            .is_err()
    );
    let start = f.auth.add_start(&f.session, NOW).await.unwrap();
    let software = Software::new();
    f.auth.logout(&f.session).await.unwrap();
    let wrap = browser_wrap(&software.prf(&start), &f.dek, &f.user, "passkey");
    assert!(
        f.auth
            .registration_finish(
                str_field(&start, "ceremony"),
                software.registration(&start, ORIGIN, true),
                wrap,
                None,
                NOW
            )
            .await
            .is_err()
    );
    let mut wrap = browser_wrap(&rand::random::<[u8; 32]>(), &f.dek, &f.user, "passkey");
    wrap.nonce = B64.encode([0; 11]);
    assert!(wrap.validate().is_err());
    let material = rand::random::<[u8; 32]>();
    let mut wrap = browser_wrap(&material, &f.dek, &f.user, "passkey");
    let mut ciphertext = B64.decode(&wrap.ciphertext).unwrap();
    ciphertext[0] ^= 1;
    wrap.ciphertext = B64.encode(ciphertext);
    assert!(unwrap_browser(&material, &wrap, &f.user, "passkey").is_err());
}
#[tokio::test]
async fn review_old_words_race_rotation() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let first = f
        .auth
        .recovery_start(&f.user, f.words.clone(), NOW)
        .await
        .unwrap();
    let pause = Arc::new(RecoveryPause::default());
    *f.auth.recovery_pause.lock().await = Some(pause.clone());
    let auth = f.auth.clone();
    let user = f.user.clone();
    let old_words = f.words.clone();
    let request =
        tokio::spawn(async move { auth.recovery_start(&user, old_words, NOW + DAY).await });
    // Pause after actual Argon2 verification, then commit the complete replacement.
    pause.verified.notified().await;
    let start = f.auth.recovery_ready(&first, NOW + DAY).await.unwrap();
    let replacement = Software::new();
    let words = str_field(&start, "recovery_words").to_owned();
    f.auth
        .registration_finish(
            str_field(&start, "ceremony"),
            replacement.registration(&start, ORIGIN, true),
            browser_wrap(&replacement.prf(&start), &f.dek, &f.user, "passkey"),
            Some(browser_wrap(
                &recovery_ikm(&words),
                &f.dek,
                &f.user,
                "recovery",
            )),
            NOW + DAY,
        )
        .await
        .unwrap();
    pause.resume.notify_one();
    assert!(
        matches!(request.await.unwrap(), Err(Error::Denied)),
        "revoked recovery words created an authorized request after replacement"
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recovery")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(f.auth.session(&f.session, NOW + DAY).await.is_err());
    assert!(
        f.auth
            .recovery_start(&f.user, words, NOW + DAY)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn review_invalid_device_polling_exhausts_browser_budget() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = router(f.auth.clone());
    for index in 0..120 {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/auth/device-redeem")
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(r#"{"token":"invalid"}"#))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        if index < 60 {
            assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        } else {
            assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(response.headers()["retry-after"], "60");
        }
    }
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/login-start")
        .header("Origin", ORIGIN)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&json!({"user_id":f.user})).unwrap(),
        ))
        .unwrap();
    assert_eq!(
        app.oneshot(request).await.unwrap().status(),
        axum::http::StatusCode::OK,
        "unauthenticated CLI polling denied a legitimate browser login"
    );
}
