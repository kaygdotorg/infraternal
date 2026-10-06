//! Defensive tests with a real ES256 software authenticator and a browser-side PRF/keywrap double.
//! No verifier is mocked: CBOR attestation, client data, flags and signatures enter webauthn-rs.
use super::*;
use crate::{
    embedded::EmbeddedAgent,
    runtime::{ServerConfig, TlsFiles, router_with_agent},
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, Stream, StreamExt};
use hkdf::Hkdf;
use http_body_util::BodyExt;
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
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
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{Message, client::IntoClientRequest},
};
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
async fn setup_restart_rotation_expiry_and_parallel_redemption() {
    let _guard = SERIAL.lock().await;
    let (auth, old_token) = empty().await;
    let mut token = String::new();
    auth.bootstrap(NOW, |banner| token = banner.lines().nth(1).unwrap().into())
        .await
        .unwrap();
    assert!(
        !token.is_empty(),
        "restart must issue a fresh setup capability"
    );
    assert!(token != old_token, "setup capability must rotate");
    assert!(auth.setup_start(&old_token, "owner", NOW).await.is_err());
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
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'other',0,'unused','other','Other')")
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

/// Drives setup, passkey registration, both wire legs, and a dropped/resumed browser connection.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn server_setup_terminal_echo_and_resume_preserve_offsets_once() {
    let _guard = SERIAL.lock().await;
    let data_dir = std::env::temp_dir().join(format!("infraternal-ws-{}", rand::random::<u64>()));
    let (server_agent_socket, agent_socket) = UnixStream::pair().expect("agent socketpair");
    let input_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let stub_count = input_count.clone();
    let stub = tokio::spawn(test_leg_b_agent(agent_socket, stub_count));
    let (app, setup_token) = router_with_agent(
        ServerConfig {
            listen: "127.0.0.1:0".parse().expect("listen address"),
            data_dir: data_dir.clone(),
            public_origin: ORIGIN.to_owned(),
            web_root: None,
            tls: Some(TlsFiles {
                certificate: PathBuf::from("unused.crt"),
                private_key: PathBuf::from("unused.key"),
            }),
            behind_proxy: false,
            trusted_proxies: Vec::new(),
        },
        EmbeddedAgent::from_test_socket(server_agent_socket),
    )
    .await
    .expect("server router");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener");
    let address = listener.local_addr().expect("listener address");
    let serving_app = app.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            serving_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    let unauthenticated = match connect_async(test_ws_request_without_cookie(address)).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => response.status(),
        Err(error) => panic!("unexpected unauthenticated websocket error: {error}"),
        Ok(_) => panic!("unauthenticated websocket upgraded"),
    };
    assert_eq!(unauthenticated, axum::http::StatusCode::UNAUTHORIZED);
    let (user_id, cookie) = register_over_http(&app, &setup_token).await;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(SqliteConnectOptions::new().filename(data_dir.join("infraternal.sqlite")))
        .await
        .expect("test database connection");

    let (mut first, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .expect("first websocket");
    assert_server_hello(&mut first).await;
    client_ws_send(
        &mut first,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "software-authenticator-test",
        },
    )
    .await;
    let (connection_id, resume_token) = read_welcome(&mut first).await;
    client_ws_send(
        &mut first,
        0,
        &Frame::Call {
            call_id: 7,
            action_id: "terminal.open",
            input_json: br#"{"cols":80,"rows":24,"px_w":0,"px_h":0}"#,
        },
    )
    .await;
    let open = read_client_frame(&mut first).await;
    let decoded = decode_muxed_frame(&open).expect("terminal.open result frame");
    let session_id = match decoded.frame {
        Frame::Result {
            call_id: 7,
            ok: true,
            json,
        } => decode_test_session_id(str_field(
            &serde_json::from_slice(json).expect("terminal.open result JSON"),
            "session_id",
        )),
        _ => panic!("server did not return terminal.open result"),
    };
    assert_eq!(
        decode_muxed_frame(&open).expect("result frame").stream_id,
        0
    );

    client_ws_send(
        &mut first,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    let attached = read_client_frame(&mut first).await;
    assert!(matches!(
        decode_muxed_frame(&attached)
            .expect("attach acknowledgement")
            .frame,
        Frame::Ack { in_seq_acked: 0 }
    ));
    client_ws_send(&mut first, 1, &Frame::Credit { bytes: 4 }).await;
    client_ws_send(
        &mut first,
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: b"echo hi\n",
        },
    )
    .await;
    let (first_output, input_acknowledged) = read_partial_terminal(&mut first).await;
    assert_eq!(first_output, b"echo");
    assert!(input_acknowledged);
    drop(first);
    wait_connection_inactive(&pool, &connection_id).await;
    let acked_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT input_acked_u64 FROM terminal_sessions WHERE user_id=? AND id=?",
    )
    .bind(&user_id)
    .bind(session_id.as_slice())
    .fetch_one(&pool)
    .await
    .expect("persisted terminal input offset");
    assert_eq!(
        u64::from_be_bytes(acked_bytes.try_into().expect("eight-byte offset")),
        8
    );

    let (mut resumed, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .expect("resumed websocket");
    assert_server_hello(&mut resumed).await;
    client_ws_send(
        &mut resumed,
        0,
        &Frame::Hello {
            version: 1,
            caps: 1,
            client_info: "software-authenticator-test",
        },
    )
    .await;
    client_ws_send(
        &mut resumed,
        0,
        &Frame::Resume {
            connection_id: &connection_id,
            resume_token: &resume_token,
        },
    )
    .await;
    let (resumed_id, rotated_token) = read_welcome(&mut resumed).await;
    assert_eq!(resumed_id, connection_id);
    assert_ne!(rotated_token, resume_token);
    client_ws_send(
        &mut resumed,
        1,
        &Frame::AttachTerm {
            session_id: &session_id,
            last_out_seq: 4,
            last_in_seq: 8,
        },
    )
    .await;
    let attached = read_client_frame(&mut resumed).await;
    assert!(matches!(
        decode_muxed_frame(&attached)
            .expect("resumed attach acknowledgement")
            .frame,
        Frame::Ack { in_seq_acked: 8 }
    ));
    client_ws_send(&mut resumed, 1, &Frame::Credit { bytes: 1024 }).await;
    client_ws_send(
        &mut resumed,
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: b"echo hi\n",
        },
    )
    .await;
    let remaining = read_terminal_output(&mut resumed).await;
    let mut complete_output = first_output;
    complete_output.extend_from_slice(&remaining);
    assert_eq!(complete_output, b"echo hi\r\nhi\r\n");
    assert_eq!(input_count.load(std::sync::atomic::Ordering::Relaxed), 1);
    client_ws_send(
        &mut resumed,
        1,
        &Frame::Close {
            code: 1000,
            reason: "detach",
        },
    )
    .await;

    let logout = axum::http::Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .header(axum::http::header::ORIGIN, ORIGIN)
        .header(axum::http::header::COOKIE, &cookie)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from("{}"))
        .expect("logout request");
    let mut logout = logout;
    logout
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            49152,
        ))));
    assert_eq!(
        app.clone()
            .oneshot(logout)
            .await
            .expect("logout response")
            .status(),
        axum::http::StatusCode::OK
    );
    client_ws_send(
        &mut resumed,
        0,
        &Frame::Call {
            call_id: 8,
            action_id: "terminal.open",
            input_json: br#"{"cols":80,"rows":24,"px_w":0,"px_h":0}"#,
        },
    )
    .await;
    let unauthorized_call = read_client_frame(&mut resumed).await;
    match decode_muxed_frame(&unauthorized_call)
        .expect("unauthorized call result")
        .frame
    {
        Frame::Result {
            call_id: 8,
            ok: false,
            json,
        } => assert_eq!(json, br#"{"error":"unauthorized"}"#),
        _ => panic!("revoked session still authorized a call"),
    }

    drop(resumed);
    server.abort();
    let _ = server.await;
    stub.abort();
    let _ = stub.await;
    drop(app);
    pool.close().await;
    std::fs::remove_dir_all(data_dir).expect("remove temporary server data");
}

pub(crate) async fn register_over_http(app: &axum::Router, setup_token: &str) -> (String, String) {
    let (status, _, start) = http_post_json(
        app,
        "setup-start",
        json!({"token":setup_token,"name":"owner"}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let user_id = str_field(&start, "user_id").to_owned();
    let words = str_field(&start, "recovery_words").to_owned();
    let software = Software::new();
    let dek = rand::random::<[u8; 32]>();
    let passkey_wrap = browser_wrap(&software.prf(&start), &dek, &user_id, "passkey");
    let recovery_wrap = browser_wrap(&recovery_ikm(&words), &dek, &user_id, "recovery");
    let proof = software.registration(&start, ORIGIN, true);
    let (status, headers, _) = http_post_json(
        app,
        "registration-finish",
        json!({
            "ceremony":start["ceremony"],
            "proof":proof,
            "passkey_wrap":passkey_wrap,
            "recovery_wrap":recovery_wrap,
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let cookie = headers
        .get(axum::http::header::SET_COOKIE)
        .expect("registered session cookie")
        .to_str()
        .expect("cookie header")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned();
    (user_id, cookie)
}

async fn http_post_json(
    app: &axum::Router,
    action: &str,
    value: Value,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Value) {
    http_post_json_with_optional_cookie(app, action, value, None).await
}

async fn http_post_json_with_cookie(
    app: &axum::Router,
    action: &str,
    value: Value,
    cookie: &str,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Value) {
    http_post_json_with_optional_cookie(app, action, value, Some(cookie)).await
}

async fn http_post_json_with_optional_cookie(
    app: &axum::Router,
    action: &str,
    value: Value,
    cookie: Option<&str>,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/auth/{action}"))
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .header(axum::http::header::ORIGIN, ORIGIN);
    if let Some(cookie) = cookie {
        builder = builder.header(axum::http::header::COOKIE, cookie);
    }
    let mut request = builder
        .body(axum::body::Body::from(
            serde_json::to_vec(&value).expect("HTTP JSON"),
        ))
        .expect("auth HTTP request");
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::from((
            [127, 0, 0, 1],
            49152,
        ))));
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("auth HTTP response");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("auth HTTP body")
        .to_bytes();
    let value = serde_json::from_slice(&body).expect("auth JSON response");
    (status, headers, value)
}

fn test_ws_request(
    address: SocketAddr,
    cookie: &str,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let mut request = format!("ws://{address}/v1/ws")
        .into_client_request()
        .expect("websocket request");
    request.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static(ORIGIN),
    );
    request.headers_mut().insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(cookie).expect("session cookie"),
    );
    request
}

fn test_ws_request_without_cookie(
    address: SocketAddr,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    let mut request = format!("ws://{address}/v1/ws")
        .into_client_request()
        .expect("unauthenticated websocket request");
    request.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static(ORIGIN),
    );
    request
}

async fn assert_server_hello<S>(socket: &mut S)
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let wire = read_client_frame(socket).await;
    let decoded = decode_muxed_frame(&wire).expect("server Hello frame");
    assert_eq!(decoded.stream_id, 0);
    assert!(matches!(decoded.frame, Frame::Hello { version: 1, .. }));
}

async fn read_welcome<S>(socket: &mut S) -> ([u8; 16], [u8; 32])
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let wire = read_client_frame(socket).await;
    let decoded = decode_muxed_frame(&wire).expect("Welcome frame");
    assert_eq!(decoded.stream_id, 0);
    match decoded.frame {
        Frame::Welcome {
            connection_id,
            resume_token,
            resume_window_seconds,
        } => {
            assert_eq!(resume_window_seconds, 120);
            (*connection_id, *resume_token)
        }
        _ => panic!("server did not send Welcome"),
    }
}

async fn client_ws_send<S>(socket: &mut S, stream_id: u32, frame: &Frame<'_>)
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::fmt::Debug,
{
    let mut encoded = Vec::with_capacity(128);
    encode_muxed_frame_into(stream_id, frame, &mut encoded).expect("encode websocket frame");
    socket
        .send(Message::Binary(Bytes::from(encoded)))
        .await
        .expect("send websocket frame");
}

async fn read_client_frame<S>(socket: &mut S) -> Bytes
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    loop {
        match socket
            .next()
            .await
            .expect("websocket message")
            .expect("websocket frame")
        {
            Message::Binary(bytes) => return bytes,
            Message::Ping(bytes) => socket
                .send(Message::Pong(bytes))
                .await
                .expect("websocket pong"),
            Message::Pong(_) | Message::Frame(_) => {}
            Message::Close(_) => panic!("server closed websocket unexpectedly"),
            Message::Text(_) => panic!("server sent a text websocket message"),
        }
    }
}

async fn read_partial_terminal<S>(socket: &mut S) -> (Vec<u8>, bool)
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let mut output = Vec::new();
    let mut input_acknowledged = false;
    while output.is_empty() || !input_acknowledged {
        let wire = read_client_frame(socket).await;
        let decoded = decode_muxed_frame(&wire).expect("terminal response frame");
        match decoded.frame {
            Frame::Ack { in_seq_acked: 8 } => input_acknowledged = true,
            Frame::Output { out_seq: 0, bytes } => output.extend_from_slice(bytes),
            _ => {}
        }
    }
    (output, input_acknowledged)
}

async fn read_terminal_output<S>(socket: &mut S) -> Vec<u8>
where
    S: Stream<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    loop {
        let wire = read_client_frame(socket).await;
        let decoded = decode_muxed_frame(&wire).expect("resumed terminal frame");
        if let Frame::Output { out_seq: 4, bytes } = decoded.frame {
            return bytes.to_vec();
        }
    }
}

fn decode_test_session_id(value: &str) -> [u8; 16] {
    assert_eq!(value.len(), 32);
    let mut session = [0_u8; 16];
    for (index, byte) in session.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).expect("session id hex");
    }
    session
}

async fn wait_connection_inactive(pool: &sqlx::SqlitePool, id: &[u8; 16]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let active: Option<i64> =
            sqlx::query_scalar("SELECT active FROM websocket_connections WHERE connection_id=?")
                .bind(id.as_slice())
                .fetch_optional(pool)
                .await
                .expect("resume row query");
        if active == Some(0) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "socket did not enter resume state"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Test-only leg-B implementation: it returns one deterministic session and resumes a fixed PTY transcript.
#[allow(clippy::too_many_lines)]
async fn test_leg_b_agent(
    mut socket: UnixStream,
    input_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    const OUTPUT: &[u8] = b"echo hi\r\nhi\r\n";
    let mut receive = BytesMut::with_capacity(1024);
    let hello = read_leg_b_frame(&mut socket, &mut receive)
        .await
        .expect("server Hello");
    assert!(matches!(
        decode_muxed_frame(&hello).expect("Hello frame").frame,
        Frame::Hello { version: 1, .. }
    ));
    leg_b_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "test-agent-stub",
        },
    )
    .await;

    let session_id = [0x42; 16];
    let session_id_json = "42".repeat(16);
    let mut terminal_stream = None;
    let mut output_cursor = 0_usize;
    let mut input_acked = 0_u64;
    let mut credit = 0_u64;
    let mut command_seen = false;
    loop {
        let Some(wire) = read_leg_b_frame(&mut socket, &mut receive).await else {
            return;
        };
        let Ok(decoded) = decode_muxed_frame(&wire) else {
            return;
        };
        let stream_id = decoded.stream_id;
        match decoded.frame {
            Frame::Call {
                call_id,
                action_id: "terminal.open",
                ..
            } => {
                let json = serde_json::to_vec(&json!({"session_id":session_id_json}))
                    .expect("stub result JSON");
                leg_b_send(
                    &mut socket,
                    0,
                    &Frame::Result {
                        call_id,
                        ok: true,
                        json: &json,
                    },
                )
                .await;
            }
            Frame::AttachTerm {
                session_id: received,
                last_out_seq,
                last_in_seq,
            } => {
                assert_eq!(*received, session_id);
                terminal_stream = Some(stream_id);
                output_cursor = usize::try_from(last_out_seq).expect("output offset");
                input_acked = input_acked.max(last_in_seq);
                credit = 0;
            }
            Frame::Credit { bytes } => {
                credit = credit.saturating_add(u64::from(bytes));
                stub_flush_output(
                    &mut socket,
                    terminal_stream,
                    &mut output_cursor,
                    &mut credit,
                    command_seen,
                    OUTPUT,
                )
                .await;
            }
            Frame::Input { in_seq, bytes } => {
                input_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let end = in_seq + u64::try_from(bytes.len()).expect("input length");
                if end > input_acked {
                    assert!(in_seq <= input_acked);
                    input_acked = end;
                    command_seen = true;
                }
                leg_b_send(
                    &mut socket,
                    stream_id,
                    &Frame::Ack {
                        in_seq_acked: input_acked,
                    },
                )
                .await;
                stub_flush_output(
                    &mut socket,
                    terminal_stream,
                    &mut output_cursor,
                    &mut credit,
                    command_seen,
                    OUTPUT,
                )
                .await;
            }
            Frame::Close { .. } if terminal_stream == Some(stream_id) => {
                terminal_stream = None;
                credit = 0;
            }
            _ => {}
        }
    }
}

async fn stub_flush_output(
    socket: &mut UnixStream,
    stream: Option<u32>,
    cursor: &mut usize,
    credit: &mut u64,
    command_seen: bool,
    output: &[u8],
) {
    let Some(stream) = stream else {
        return;
    };
    if !command_seen || *credit == 0 || *cursor >= output.len() {
        return;
    }
    let available = usize::try_from(*credit).unwrap_or(usize::MAX);
    let end = cursor.saturating_add(available).min(output.len());
    let start_seq = u64::try_from(*cursor).expect("stub output sequence");
    let bytes = &output[*cursor..end];
    leg_b_send(
        socket,
        stream,
        &Frame::Output {
            out_seq: start_seq,
            bytes,
        },
    )
    .await;
    *credit -= u64::try_from(bytes.len()).expect("stub output length");
    *cursor = end;
}

async fn read_leg_b_frame(socket: &mut UnixStream, receive: &mut BytesMut) -> Option<Bytes> {
    let mut scratch = [0_u8; 4096];
    loop {
        match decode_muxed_frame(receive) {
            Ok(decoded) => return Some(receive.split_to(decoded.wire_len).freeze()),
            Err(infraternal_protocol::DecodeError::Incomplete) => {}
            Err(_) => return None,
        }
        let read = socket.read(&mut scratch).await.ok()?;
        if read == 0 {
            return None;
        }
        receive.extend_from_slice(&scratch[..read]);
    }
}

async fn leg_b_send(socket: &mut UnixStream, stream_id: u32, frame: &Frame<'_>) {
    let mut encoded = Vec::with_capacity(128);
    encode_muxed_frame_into(stream_id, frame, &mut encoded).expect("encode leg-B frame");
    socket.write_all(&encoded).await.expect("write leg-B frame");
}

/// Different owner handles must never share the new enrollment PRF input.
#[tokio::test]
async fn enrollment_prf_input_is_user_bound() {
    let _guard = SERIAL.lock().await;
    let (auth, token) = empty().await;
    let a = auth.setup_start(&token, "owner", NOW).await.unwrap();
    let b = auth.setup_start(&token, "owner", NOW).await.unwrap();
    assert_ne!(a["user_id"], b["user_id"]);
    assert_ne!(
        a["options"]["publicKey"]["extensions"]["prf"],
        b["options"]["publicKey"]["extensions"]["prf"],
        "PRF input must be per-user"
    );
}

/// Resident assertions bind the discovered handle to a live credential and latest counter.
#[tokio::test]
async fn discoverable_login_handle_credential_counter_and_replay() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let start = f.auth.discoverable_login_start(NOW).await.unwrap();
    assert_eq!(start["options"]["publicKey"]["allowCredentials"], json!([]));
    assert_eq!(start["options"]["publicKey"]["extensions"], json!({}));
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["response"]["userHandle"] =
        json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
    let token = f
        .auth
        .login_finish(
            str_field(&start, "ceremony"),
            proof.clone(),
            "resident",
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(f.auth.session(&token, NOW).await.unwrap().user_id, f.user);
    assert!(
        f.auth
            .login_finish(str_field(&start, "ceremony"), proof, "resident", NOW)
            .await
            .is_err()
    );
    for handle in [
        Value::Null,
        json!(B64.encode([1_u8; 15])),
        json!(B64.encode(Uuid::new_v4().as_bytes())),
    ] {
        let start = f.auth.discoverable_login_start(NOW).await.unwrap();
        let mut proof = f.software.login(&start, ORIGIN, true);
        proof["response"]["userHandle"] = handle;
        assert!(
            f.auth
                .login_finish(str_field(&start, "ceremony"), proof, "resident", NOW)
                .await
                .is_err()
        );
    }
    let start = f.auth.discoverable_login_start(NOW).await.unwrap();
    let mut stranger = Software::new();
    let mut proof = stranger.login(&start, ORIGIN, true);
    proof["response"]["userHandle"] =
        json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
    assert!(
        f.auth
            .login_finish(str_field(&start, "ceremony"), proof, "resident", NOW)
            .await
            .is_err()
    );
    // A new challenge with the same nonzero counter must fail against current storage.
    f.software.counter = 0;
    let start = f.auth.discoverable_login_start(NOW).await.unwrap();
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["response"]["userHandle"] =
        json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
    assert!(
        f.auth
            .login_finish(str_field(&start, "ceremony"), proof, "resident", NOW)
            .await
            .is_err()
    );
}

/// Legacy ciphertext retains v1 while new credentials expose their exact user-bound input.
#[tokio::test]
async fn authenticated_prf_metadata_preserves_legacy_envelopes() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let wraps = f.auth.wraps(&f.session, NOW).await.unwrap();
    let entries = wraps.as_array().unwrap();
    assert_eq!(
        entries
            .iter()
            .find(|entry| entry["kind"] == "passkey")
            .unwrap()["prf_input"],
        prf_salt(Some(&f.user))
    );
    assert!(
        entries
            .iter()
            .find(|entry| entry["kind"] == "recovery")
            .unwrap()["prf_input"]
            .is_null()
    );
    let legacy_start =
        json!({"options":{"publicKey":{"extensions":{"prf":{"eval":{"first":prf_salt(None)}}}}}});
    let old_wrap = browser_wrap(&f.software.prf(&legacy_start), &f.dek, &f.user, "passkey");
    sqlx::query("UPDATE passkeys SET prf_input=NULL WHERE user_id=?")
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE wraps SET blob=? WHERE user_id=? AND kind='passkey'")
        .bind(serde_json::to_string(&old_wrap).unwrap())
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let login = f.auth.login_start(&f.user, NOW).await.unwrap();
    assert_eq!(
        login["options"]["publicKey"]["extensions"]["prf"]["eval"]["first"],
        prf_salt(None)
    );
    let wraps = f.auth.wraps(&f.session, NOW).await.unwrap();
    let entry = wraps
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["kind"] == "passkey")
        .unwrap();
    assert_eq!(entry["prf_input"], prf_salt(None));
    let wrap: Wrap = serde_json::from_value(entry["wrap"].clone()).unwrap();
    assert!(
        unwrap_browser(&f.software.prf(&login), &wrap, &f.user, "passkey").unwrap() == f.dek,
        "legacy envelope must unwrap the original key"
    );
}

/// Public status reveals exactly one flag; HTTP resident login establishes the resolved session.
#[tokio::test]
async fn public_status_and_discoverable_http_login() {
    let _guard = SERIAL.lock().await;
    let (auth, _) = empty().await;
    let app = router(auth);
    let (status, headers, body) = http_post_json(&app, "status", json!({})).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body, json!({"setup_required":true}));
    assert_eq!(headers[axum::http::header::CACHE_CONTROL], "no-store");
    assert_eq!(
        http_post_json(&app, "status", json!({"extra":true}))
            .await
            .0,
        axum::http::StatusCode::BAD_REQUEST
    );
    let mut f = fixture().await;
    let app = router(f.auth.clone());
    assert_eq!(
        http_post_json(&app, "status", json!({})).await.2,
        json!({"setup_required":false})
    );
    let (status, _, start) = http_post_json(&app, "login-start", json!({})).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(start["options"]["publicKey"]["allowCredentials"], json!([]));
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["response"]["userHandle"] =
        json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
    let (status, headers, _) = http_post_json(
        &app,
        "login-finish",
        json!({"ceremony":start["ceremony"],"proof":proof,"device":"resident browser"}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let cookie = headers[axum::http::header::SET_COOKIE].to_str().unwrap();
    let token = cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("__Host-infraternal=")
        .unwrap();
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    assert_eq!(f.auth.session(token, now).await.unwrap().user_id, f.user);
}

/// New setup callers identify the passkey separately from the human-facing label.
#[tokio::test]
async fn setup_start_accepts_username_and_display_name() {
    let (auth, setup_token) = empty().await;
    let app = router(auth.clone());
    let (status, _, default_body) = http_post_json(
        &app,
        "setup-start",
        json!({"token":setup_token,"username":"ada_default"}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(
        default_body["options"]["publicKey"]["user"]["displayName"],
        "ada_default"
    );

    let (status, _, body) = http_post_json(
        &app,
        "setup-start",
        json!({
            "token":setup_token,
            "username":"ada",
            "display_name":"Ada Lovelace"
        }),
    )
    .await;

    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["options"]["publicKey"]["user"]["name"], "ada");
    assert_eq!(
        body["options"]["publicKey"]["user"]["displayName"],
        "Ada Lovelace"
    );

    let user_id = str_field(&body, "user_id").to_owned();
    let words = str_field(&body, "recovery_words").to_owned();
    let software = Software::new();
    let dek = rand::random::<[u8; 32]>();
    let passkey_wrap = browser_wrap(&software.prf(&body), &dek, &user_id, "passkey");
    let recovery_wrap = browser_wrap(&recovery_ikm(&words), &dek, &user_id, "recovery");
    let (status, headers, _) = http_post_json(
        &app,
        "registration-finish",
        json!({
            "ceremony":body["ceremony"],
            "proof":software.registration(&body, ORIGIN, true),
            "passkey_wrap":passkey_wrap,
            "recovery_wrap":recovery_wrap
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let cookie = headers[axum::http::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let (status, _, session) =
        http_post_json_with_cookie(&app, "session", json!({}), &cookie).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(session["user_id"], user_id);
    assert_eq!(session["username"], "ada");
    assert_eq!(session["display_name"], "Ada Lovelace");
}

/// Enrollment rejects invalid usernames, overlong labels and an account-name collision.
#[tokio::test]
async fn setup_identity_validation_and_uniqueness() {
    let (auth, setup_token) = empty().await;
    for username in ["a", "Ada", "ada.name", "has space", "ümlaut"] {
        assert!(matches!(
            auth.setup_start_with_identity(&setup_token, username, None, NOW)
                .await,
            Err(Error::Invalid)
        ));
    }
    let too_long = "x".repeat(33);
    assert!(matches!(
        auth.setup_start_with_identity(&setup_token, &too_long, None, NOW)
            .await,
        Err(Error::Invalid)
    ));
    let too_many_display_chars = "é".repeat(65);
    assert!(matches!(
        auth.setup_start_with_identity(&setup_token, "ada", Some(&too_many_display_chars), NOW)
            .await,
        Err(Error::Invalid)
    ));

    let other = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?, 'taken', 0, 'unused', 'taken', 'Taken')")
        .bind(other)
        .execute(&auth.pool)
        .await
        .unwrap();
    assert!(matches!(
        auth.setup_start_with_identity(&setup_token, "taken", None, NOW)
            .await,
        Err(Error::Conflict)
    ));
}

/// The account identity migration adds persisted, unique usernames and display names.
#[tokio::test]
async fn account_identity_schema_has_unique_usernames_and_display_names() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let _auth = Auth::new(pool.clone(), "auth.example.test", ORIGIN)
        .await
        .unwrap();

    let columns: Vec<String> = sqlx::query("PRAGMA table_info(users)")
        .fetch_all(&pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get("name"))
        .collect();
    assert!(columns.iter().any(|column| column == "username"));
    assert!(columns.iter().any(|column| column == "display_name"));

    let username_index: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_index_list('users') WHERE name='users_username_unique'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(username_index, 1);
}

/// Existing labels stay visible while invalid and duplicate names receive stable identities.
#[tokio::test]
async fn account_identity_migration_backfills_legacy_users() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::raw_sql(
        "CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, owner INTEGER NOT NULL, recovery_hash TEXT NOT NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let legacy = [
        ("11111111-1111-4111-8111-111111111111", "Ada".to_owned()),
        ("22222222-2222-4222-8222-222222222222", "ADA".to_owned()),
        (
            "33333333-3333-4333-8333-333333333333",
            "bad name!".to_owned(),
        ),
        ("44444444-4444-4444-8444-444444444444", "x".repeat(70)),
    ];
    for (id, name) in &legacy {
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES (?, ?, 0, 'unused')")
            .bind(id)
            .bind(name)
            .execute(&pool)
            .await
            .unwrap();
    }

    sqlx::raw_sql(include_str!("../../migrations/0006_user_identity.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let rows = sqlx::query("SELECT id,username,display_name FROM users ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    let usernames: Vec<String> = rows.iter().map(|row| row.get("username")).collect();
    assert_eq!(usernames.len(), 4);
    assert_eq!(
        usernames
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
    assert!(
        usernames
            .iter()
            .all(|username| (2..=32).contains(&username.len())
                && username.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'-')))
    );
    assert_eq!(rows[0].get::<String, _>("display_name"), "Ada");
    assert_eq!(rows[1].get::<String, _>("display_name"), "ADA");
    assert_eq!(rows[3].get::<String, _>("display_name").chars().count(), 64);
}

/// Release-only scale evidence; no authenticator signing cost is included in server finish latency.
#[tokio::test]
#[ignore = "run --release --ignored --nocapture without concurrent builds"]
async fn discoverable_latency_at_pending_capacity() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let second = Software::new();
    let add = f.auth.add_start(&f.session, NOW).await.unwrap();
    f.auth
        .registration_finish(
            str_field(&add, "ceremony"),
            second.registration(&add, ORIGIN, true),
            browser_wrap(&second.prf(&add), &f.dek, &f.user, "passkey"),
            None,
            NOW,
        )
        .await
        .unwrap();
    println!(
        "auth scale: owners=1 passkeys=2 pending_limit=1024 arch={} load={}",
        std::env::consts::ARCH,
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    let mut now = NOW;
    for identified in [true, false] {
        for prefill in [0, 824] {
            now += CEREMONY + 1;
            for _ in 0..prefill {
                benchmark_start(&f, identified, now).await;
            }
            let rss_before = resident_kib();
            let mut samples = Vec::with_capacity(200);
            for _ in 0..200 {
                let clock = Instant::now();
                benchmark_start(&f, identified, now).await;
                samples.push(clock.elapsed());
            }
            let (p50, p99) = latency_us(&mut samples);
            println!(
                "challenge mode={} pending={}..{} n=200 p50_us={p50} p99_us={p99} rss_before_kib={rss_before} rss_after_kib={}",
                if identified {
                    "identified"
                } else {
                    "discoverable"
                },
                prefill,
                prefill + 200,
                resident_kib()
            );
            assert_eq!(f.auth.pending.lock().await.logins.len(), prefill + 200);
            if !identified {
                assert!(
                    p99 < 1000,
                    "discoverable challenge exceeded local 1 ms budget"
                );
            }
            if prefill == 824 {
                assert!(
                    f.auth.discoverable_login_start(now).await.is_err(),
                    "pending capacity must fail closed"
                );
            }
        }
    }
    println!(
        "pending inline bytes/unit={} bytes/1024={} (excludes heap/hash-table allocations)",
        std::mem::size_of::<Login>(),
        1024 * std::mem::size_of::<Login>()
    );
    now += CEREMONY + 1;
    for _ in 0..1023 {
        f.auth.discoverable_login_start(now).await.unwrap();
    }
    let mut samples = Vec::with_capacity(200);
    for _ in 0..200 {
        let start = f.auth.discoverable_login_start(now).await.unwrap();
        let mut proof = f.software.login(&start, ORIGIN, true);
        proof["response"]["userHandle"] =
            json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
        let clock = Instant::now();
        f.auth
            .login_finish(str_field(&start, "ceremony"), proof, "benchmark", now)
            .await
            .unwrap();
        samples.push(clock.elapsed());
    }
    let (p50, p99) = latency_us(&mut samples);
    println!(
        "signed discoverable finish pending=1024 n=200 p50_us={p50} p99_us={p99} (SQLite memory + real ES256 verifier)"
    );
    assert!(
        p99 < 10_000,
        "discoverable finish exceeded local 10 ms budget"
    );
}

/// Measure either retained identified admission or the new identity-free path through the same facade.
async fn benchmark_start(f: &Fixture, identified: bool, now: i64) {
    if identified {
        f.auth.login_start(&f.user, now).await.unwrap();
    } else {
        f.auth.discoverable_login_start(now).await.unwrap();
    }
}

/// Nearest-rank percentiles from monotonic durations, sorted outside the timed section.
fn latency_us(samples: &mut [Duration]) -> (u128, u128) {
    samples.sort_unstable();
    let rank = |percent: usize| samples[(samples.len() * percent).div_ceil(100) - 1].as_micros();
    (rank(50), rank(99))
}

/// Whole-process resident memory, not an isolated allocation measurement.
fn resident_kib() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}
