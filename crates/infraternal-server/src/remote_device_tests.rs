//! The `device` host mode (#580 P5): a phone is a host row with no uid that joins the mesh, renews
//! and is removed, and is never admitted where terminals, logins or session lists are decided.
//!
//! The client in these tests is [`RingDevice`], a P-256 key signed by ring: the stand-in for an
//! iPhone's Secure Enclave key and for the client core, so the server's OpenSSL checks run against
//! bytes that it did not produce itself.

use crate::{
    enrollment::{EnrollmentStore, Mode},
    identity_key::KeyAlgorithm,
    remote_enrollment::RemoteEnrollment,
};
use base64::Engine;
use std::sync::Arc;
use uuid::Uuid;

/// DER `tag`, length and `body`, with the length forms a CSR needs (short, one and two bytes).
pub(crate) fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match body.len() {
        0..=127 => out.push(u8::try_from(body.len()).unwrap()),
        128..=255 => out.extend([0x81, u8::try_from(body.len()).unwrap()]),
        length => {
            out.push(0x82);
            out.extend(u16::try_from(length).unwrap().to_be_bytes());
        }
    }
    out.extend(body);
    out
}

/// A software P-256 identity signed by ring: the stand-in for an iPhone's Secure Enclave key and
/// for the client core that will hold it. Its CSR is built byte by byte, so it is not the server's
/// own OpenSSL encoding being echoed back.
pub(crate) struct RingDevice {
    pair: ring::signature::EcdsaKeyPair,
    random: ring::rand::SystemRandom,
}

impl RingDevice {
    /// A fresh key.
    pub(crate) fn new() -> Self {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        let random = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random)
                .unwrap();
        Self { pair, random }
    }

    /// The 65-byte uncompressed point.
    pub(crate) fn point(&self) -> Vec<u8> {
        use ring::signature::KeyPair;
        self.pair.public_key().as_ref().to_vec()
    }

    /// The device's key digest: SHA-256 of the point.
    pub(crate) fn digest(&self) -> [u8; 32] {
        openssl::sha::sha256(&self.point())
    }

    /// The `SHA256:` fingerprint the approval page shows.
    pub(crate) fn fingerprint(&self) -> String {
        format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(self.digest())
        )
    }

    /// A PKCS#10 request for the key: `ecdsa-with-SHA256`, a DER signature.
    pub(crate) fn csr(&self) -> Vec<u8> {
        let ec_public_key = [6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1];
        let prime256v1 = [6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];
        let ecdsa_sha256 = [6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2];
        let mut point = vec![0];
        point.extend(self.point());
        let spki = der(
            0x30,
            &[
                der(0x30, &[ec_public_key.as_slice(), &prime256v1].concat()),
                der(3, &point),
            ]
            .concat(),
        );
        let info = der(
            0x30,
            &[vec![2, 1, 0, 0x30, 0], spki, vec![0xa0, 0]].concat(),
        );
        let mut signature = vec![0];
        signature.extend(self.pair.sign(&self.random, &info).unwrap().as_ref());
        der(
            0x30,
            &[info, der(0x30, &ecdsa_sha256), der(3, &signature)].concat(),
        )
    }
}

/// The fixed clock the store-level tests use.
const NOW: i64 = 1_800_000_000;

/// A migrated database with a device host that has joined with `device`'s key at [`NOW`]:
/// its store, pool, host id and certificate fingerprint.
async fn joined(device: &RingDevice) -> (EnrollmentStore, sqlx::SqlitePool, Uuid, [u8; 32]) {
    let (store, pool, host) = crate::enrollment::authority::tests::device_host().await;
    let secret = crate::enrollment::authority::tests::device_receipt(
        &store,
        &pool,
        host,
        (Mode::Device, KeyAlgorithm::P256),
        &device.digest(),
        NOW,
    )
    .await
    .unwrap();
    let signed = service(&store)
        .join(host, Mode::Device, &secret, &device.csr(), NOW)
        .await
        .unwrap();
    (store, pool, host, signed.record.fingerprint)
}

/// The enrollment service over an unlocked test CA.
fn service(store: &EnrollmentStore) -> RemoteEnrollment<crate::ca::tests::MemorySource> {
    RemoteEnrollment::new(Arc::new(crate::ca::tests::source(true)), store.clone())
}

/// Red tests for admission. A device certificate is admitted as a device while live, and the host
/// guard (the one that decides terminals and logins), cleanup admission and a host's own
/// certificate each refuse the other kind.
#[tokio::test]
async fn a_device_certificate_is_admitted_only_as_a_device_and_only_while_live() {
    let device = RingDevice::new();
    let (store, pool, host, fingerprint) = joined(&device).await;
    let admitted = store.admit_device(&fingerprint, NOW).await.unwrap();
    assert_eq!((admitted.host, admitted.not_after), (host, NOW + 604_800));
    assert!(
        store.admit(&fingerprint, NOW).await.is_err(),
        "no terminals"
    );
    assert!(
        store.admit_cleanup(&fingerprint, NOW).await.is_err(),
        "no cleanup link: a device has nothing to uninstall"
    );
    assert!(
        store.admit_device(&fingerprint, NOW - 1).await.is_err(),
        "not before its window"
    );
    assert!(
        store
            .admit_device(&fingerprint, NOW + 604_800)
            .await
            .is_err(),
        "not after its window"
    );
    assert!(
        store.admit_device(&[0xee; 32], NOW).await.is_err(),
        "unknown"
    );
    // A rootless host's certificate is not a device's, whatever the key.
    let (host_store, _, _) = crate::enrollment::authority::tests::enrolled().await;
    assert!(host_store.admit_device(&[1; 32], 100).await.is_err());
    // Revocation of the certificate, then of the host, each end it.
    sqlx::query("UPDATE remote_certificates SET revoked_at=? WHERE fingerprint=?")
        .bind(NOW)
        .bind(fingerprint.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.admit_device(&fingerprint, NOW).await.is_err());
    sqlx::query("UPDATE remote_certificates SET revoked_at=NULL WHERE fingerprint=?")
        .bind(fingerprint.as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.admit_device(&fingerprint, NOW).await.is_ok());
    sqlx::query("UPDATE remote_hosts SET revoked_at=? WHERE id=?")
        .bind(NOW)
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(store.admit_device(&fingerprint, NOW).await.is_err());
}

/// A device renews its certificate with its own key and refuses every other request: another
/// P-256 key, an Ed25519 key, and a renewal presented after the host's removal.
#[tokio::test]
async fn a_device_renews_with_its_own_p256_key_only() {
    let device = RingDevice::new();
    let (store, pool, host, fingerprint) = joined(&device).await;
    let later = NOW + 302_400;
    let other = RingDevice::new();
    assert!(
        service(&store)
            .renew(&fingerprint, &other.csr(), later)
            .await
            .is_err(),
        "another key"
    );
    let ed25519 = openssl::pkey::PKey::generate_ed25519().unwrap();
    let mut builder = openssl::x509::X509Req::builder().unwrap();
    builder.set_pubkey(&ed25519).unwrap();
    builder
        .sign(&ed25519, openssl::hash::MessageDigest::null())
        .unwrap();
    assert!(
        service(&store)
            .renew(&fingerprint, &builder.build().to_der().unwrap(), later)
            .await
            .is_err(),
        "an Ed25519 request for a P-256 identity"
    );
    let renewed = service(&store)
        .renew(&fingerprint, &device.csr(), later)
        .await
        .unwrap();
    assert_eq!(renewed.record.public_key.algorithm(), KeyAlgorithm::P256);
    let stored: (String, Option<i64>) = sqlx::query_as(
        "SELECT key_algorithm, execution_uid FROM remote_certificates WHERE fingerprint=?",
    )
    .bind(renewed.record.fingerprint.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored, ("p256".into(), None));
    assert_eq!(
        store
            .admit_device(&renewed.record.fingerprint, later)
            .await
            .unwrap()
            .host,
        host
    );
    // Removal ends the renewal chain: neither certificate renews or is admitted.
    sqlx::query("UPDATE remote_hosts SET revoked_at=? WHERE id=?")
        .bind(later)
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        service(&store)
            .renew(&renewed.record.fingerprint, &device.csr(), later + 1)
            .await
            .is_err()
    );
}

/// The server's own questions about "may this host run a terminal or take a login" answer no for
/// a device: the login grant, the preferred-account check and the terminal session record each
/// refuse it, like a host that does not exist.
#[tokio::test]
async fn a_device_has_no_logins_and_no_terminal_sessions() {
    let (_store, pool, device) = crate::enrollment::authority::tests::device_host().await;
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,'owner','test',?,0,1)")
        .bind(crate::auth::hash("t"))
        .bind(i64::MAX / 2)
        .execute(&pool)
        .await
        .unwrap();
    let ordinary = Uuid::from_u128(6);
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootless',1002,100)")
        .bind(ordinary.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    // The login grant of the owner is a full one on a host, and nothing on a device.
    let mut connection = pool.acquire().await.unwrap();
    crate::login_access::add_owner_defaults(&mut connection, "owner")
        .await
        .unwrap();
    let on_host = crate::login_access::grant_in(&mut connection, "owner", Some(ordinary))
        .await
        .unwrap();
    assert!(on_host.any_account, "the control: a host grants the owner");
    let on_device = crate::login_access::grant_in(&mut connection, "owner", Some(device))
        .await
        .unwrap();
    assert_eq!(
        on_device,
        infraternal_plugin_api::login_access::LoginGrant::default()
    );
    drop(connection);
    // A terminal session row is never created for a device, by the one INSERT every open uses.
    let auth = crate::auth::Auth::new(
        pool.clone(),
        "auth.example.test",
        "https://auth.example.test",
    )
    .await
    .unwrap();
    for (host, expected) in [(ordinary, true), (device, false)] {
        let recorded = crate::terminal_session_record::record(
            &auth,
            &pool,
            crate::terminal_session_record::NewSession {
                session_id: *host.as_bytes(),
                user_id: "owner",
                host: Some(host.as_bytes().to_vec()),
                session_token: "t",
                now: NOW,
            },
        )
        .await;
        assert_eq!(recorded, expected, "{host}");
    }
}
