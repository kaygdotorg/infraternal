//! Joins bounded CSR proof, server-owned signing and atomic public authority; network adapters supply pinned channels [64][133], #78.

use crate::{
    ca::{CaKeySource, CertificateAuthority, SignedCertificate},
    csr::ValidatedCsr,
    enrollment::{EnrollmentStore, Mode},
    identity_key::KeyAlgorithm,
};
use openssl::memcmp;
use std::sync::Arc;
use uuid::Uuid;

/// Adapters expose content-free errors; neither capability nor CSR enters diagnostics.
#[derive(Debug, thiserror::Error)]
#[error("remote enrollment refused")]
pub struct RemoteEnrollmentError;

/// Report the refused phase without including the invitation, CSR, key or storage error.
fn join_refused(host: Uuid, reason: &'static str) -> RemoteEnrollmentError {
    tracing::debug!(event = "remote_join_refused", host_id = %host, reason, "Machine join refused");
    RemoteEnrollmentError
}

/// One live unlock source and SQLite authority; constructing the adapter never unlocks the CA.
pub struct RemoteEnrollment<S: CaKeySource + ?Sized> {
    source: Arc<S>,
    store: EnrollmentStore,
}

impl<S: CaKeySource + ?Sized + 'static> RemoteEnrollment<S> {
    /// Use the configured signing source and already-migrated public authority.
    #[must_use]
    pub fn new(source: Arc<S>, store: EnrollmentStore) -> Self {
        Self { source, store }
    }

    /// Builds the certificate authority from the configured source. Fails with an opaque error while the signing key is locked.
    fn signer(&self) -> Result<CertificateAuthority, RemoteEnrollmentError> {
        CertificateAuthority::from_source(self.source.as_ref()).map_err(|_| RemoteEnrollmentError)
    }

    /// Preflight public authority before CSR/signing; send DER only after atomic commit.
    /// The caller must authenticate the enrollment server before supplying a capability.
    /// # Errors
    /// Refuses malformed CSR, invalid host/mode/invitation, unavailable CA or failed storage.
    pub async fn join(
        &self,
        host: Uuid,
        mode: Mode,
        token: &str,
        csr_der: &[u8],
        now: i64,
    ) -> Result<SignedCertificate, RemoteEnrollmentError> {
        // A root upgrade's successor joins the same way, with a token its
        // promotion issued instead of the host's invitation (D376, #399).
        // Its certificate is recorded as a successor, not as the host.
        // The invitation names the one algorithm its key uses (#580): Ed25519
        // for every host, P-256 only for a `device` join. A successor is a
        // root host agent, so always Ed25519.
        let (expected_key_digest, algorithm, successor) =
            match self.store.preflight_key(token, host, mode, now).await {
                Ok((digest, algorithm)) => (digest, algorithm, false),
                Err(_) if mode == Mode::Rootful => (
                    Some(
                        self.store
                            .preflight_successor(token, host, now)
                            .await
                            .map_err(|_| join_refused(host, "invitation_or_promotion"))?,
                    ),
                    KeyAlgorithm::Ed25519,
                    true,
                ),
                Err(_) => return Err(join_refused(host, "invitation")),
            };
        let csr =
            ValidatedCsr::parse_as(csr_der, algorithm).map_err(|_| join_refused(host, "csr"))?;
        // The digest is per algorithm: for Ed25519 the SHA-256 of the raw key,
        // as every existing invitation bound it.
        let actual_key_digest = csr
            .identity_key()
            .map_err(|_| join_refused(host, "public_key"))?
            .digest();
        let matches = expected_key_digest
            .as_ref()
            .is_some_and(|expected| memcmp::eq(expected, &actual_key_digest));
        if !matches {
            // A successor token dies with its promotion; only an invitation
            // is spent here.
            if !successor {
                let _ = self.store.consume_refused(token, host, mode, now).await;
            }
            return Err(join_refused(host, "key_binding"));
        }
        #[cfg(test)]
        let certificate_started = std::time::Instant::now();
        #[cfg(test)]
        let certificate_started_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let certificate = self
            .signer()
            .map_err(|_| join_refused(host, "signer_locked_or_unavailable"))?
            .sign_host(host, &csr, now)
            .map_err(|_| join_refused(host, "signing"))?;
        #[cfg(test)]
        if std::env::var_os("ADDHOST_RETRY_PHASE_TIMING").is_some() {
            let epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            println!(
                "TIMELINE source=server step=certificate_sign state=start epoch_ms={:.3}",
                certificate_started_epoch.as_secs_f64() * 1000.0
            );
            println!(
                "TIMELINE source=server step=certificate_sign state=end epoch_ms={:.3}",
                epoch.as_secs_f64() * 1000.0
            );
            println!(
                "METRIC breakit2 step=certificate_sign elapsed_ms={:.3} ok=true",
                certificate_started.elapsed().as_secs_f64() * 1000.0
            );
        }
        if successor {
            self.store
                .redeem_successor(token, host, now, &certificate.record)
                .await
                .map_err(|_| join_refused(host, "redeem_successor"))?;
        } else {
            self.store
                .redeem(token, host, mode, now, &certificate.record)
                .await
                .map_err(|_| join_refused(host, "redeem_invitation"))?;
        }
        Ok(certificate)
    }

    /// Renew over an authenticated live channel, using its exact admitted predecessor.
    /// # Errors
    /// Refuses altered keys, expired/revoked authority, invalid CSR or unavailable issuer/storage.
    pub async fn renew(
        &self,
        predecessor: &[u8; 32],
        csr_der: &[u8],
        now: i64,
    ) -> Result<SignedCertificate, RemoteEnrollmentError> {
        // A host or a device renews the same way; the key algorithm below is
        // read from the predecessor's own certificate, not chosen by the caller.
        let host = match self.store.admit(predecessor, now).await {
            Ok(identity) => identity.host,
            Err(_) => {
                self.store
                    .admit_device(predecessor, now)
                    .await
                    .map_err(|_| RemoteEnrollmentError)?
                    .host
            }
        };
        if csr_der.len() > 4096 {
            return Err(RemoteEnrollmentError);
        }
        // A renewal keeps the predecessor's key, so its CSR is parsed in that
        // key's algorithm (#580); the atomic write then requires the same key.
        let algorithm = self
            .store
            .certificate_key(predecessor)
            .await
            .map_err(|_| RemoteEnrollmentError)?
            .algorithm();
        let source = self.source.clone();
        let csr_der = csr_der.to_vec();
        let certificate = tokio::task::spawn_blocking(move || {
            let csr =
                ValidatedCsr::parse_as(&csr_der, algorithm).map_err(|_| RemoteEnrollmentError)?;
            CertificateAuthority::from_source(source.as_ref())
                .map_err(|_| RemoteEnrollmentError)?
                .sign_host(host, &csr, now)
                .map_err(|_| RemoteEnrollmentError)
        })
        .await
        .map_err(|_| RemoteEnrollmentError)??;
        // The atomic write rechecks authority and key equality after signing;
        // a revocation between admission and publication cannot return authority.
        self.store
            .renew(predecessor, &certificate.record, now)
            .await
            .map_err(|_| RemoteEnrollmentError)?;
        Ok(certificate)
    }
}

/// Join and renewal tests: key binding, replay, and the per-algorithm rules of #580.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use openssl::{
        hash::MessageDigest,
        pkey::{PKey, Private},
        x509::{X509NameBuilder, X509Req},
    };
    use sha2::{Digest, Sha256};

    fn csr() -> Vec<u8> {
        let key = PKey::generate_ed25519().unwrap();
        csr_for(&key)
    }

    fn csr_for(key: &PKey<Private>) -> Vec<u8> {
        let mut builder = X509Req::builder().unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_subject_name(&X509NameBuilder::new().unwrap().build())
            .unwrap();
        builder.sign(key, MessageDigest::null()).unwrap();
        builder.build().to_der().unwrap()
    }

    async fn issue_bound_key(
        store: &EnrollmentStore,
        host: Uuid,
        key: &PKey<Private>,
        now: i64,
    ) -> crate::enrollment::JoinToken {
        let digest: [u8; 32] = Sha256::digest(key.raw_public_key().unwrap()).into();
        store
            .issue("owner", host, Mode::Rootless, now, &digest)
            .await
            .unwrap()
    }

    struct CountingCaSource {
        source: Arc<dyn CaKeySource>,
        loads: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CaKeySource for CountingCaSource {
        fn load(&self) -> Result<crate::ca::CaMaterial, crate::ca::CaError> {
            self.loads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.source.load()
        }
    }

    #[tokio::test]
    async fn substituted_csr_is_refused_before_signing_or_commit() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let now = 1_800_000_000;
        let expected_key = PKey::generate_ed25519().unwrap();
        let replacement_key = PKey::generate_ed25519().unwrap();
        let token = issue_bound_key(&store, host, &expected_key, now).await;

        let loads = Arc::new(AtomicUsize::new(0));
        let source = Arc::new(CountingCaSource {
            source: Arc::new(crate::ca::tests::source(true)),
            loads: loads.clone(),
        });
        let service = RemoteEnrollment::new(source, store.clone());
        let result = service
            .join(
                host,
                Mode::Rootless,
                token.secret(),
                &csr_for(&replacement_key),
                now,
            )
            .await;
        let committed: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_certificates")
            .fetch_one(&pool)
            .await
            .unwrap();
        let consumed: bool = sqlx::query_scalar(
            "SELECT consumed_at IS NOT NULL FROM remote_join_tokens WHERE host_id=?",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(
            result.err().map(|error| error.to_string()).as_deref(),
            Some("remote enrollment refused"),
            "a substituted key must receive the content-free refusal",
        );
        assert_eq!(committed, 1, "refusal must not commit a certificate");
        assert_eq!(loads.load(Ordering::Relaxed), 0, "refusal precedes signing");
        assert!(
            consumed,
            "a definitive key mismatch consumes its capability"
        );
    }

    #[tokio::test]
    async fn matching_csr_succeeds_with_bound_invitation() {
        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let now = 1_800_000_000;
        let key = PKey::generate_ed25519().unwrap();
        let token = issue_bound_key(&store, host, &key, now).await;
        let service =
            RemoteEnrollment::new(Arc::new(crate::ca::tests::source(true)), store.clone());

        let signed = service
            .join(host, Mode::Rootless, token.secret(), &csr_for(&key), now)
            .await
            .unwrap();
        let admitted = store.admit(&signed.record.fingerprint, now).await.unwrap();
        let committed: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_certificates")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(admitted.host, host);
        assert_eq!(
            committed, 2,
            "the matching CSR commits exactly one certificate"
        );
    }

    #[tokio::test]
    async fn replayed_matching_csr_is_refused() {
        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let now = 1_800_000_000;
        let key = PKey::generate_ed25519().unwrap();
        let token = issue_bound_key(&store, host, &key, now).await;
        let service =
            RemoteEnrollment::new(Arc::new(crate::ca::tests::source(true)), store.clone());
        let request = csr_for(&key);

        service
            .join(host, Mode::Rootless, token.secret(), &request, now)
            .await
            .unwrap();
        assert!(
            service
                .join(host, Mode::Rootless, token.secret(), &request, now)
                .await
                .is_err()
        );
        let committed: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_certificates")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(committed, 2, "replay cannot add another certificate");
    }

    #[tokio::test]
    async fn legacy_unbound_invitation_is_refused_and_consumed_before_signing() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counted(AtomicUsize);
        impl CaKeySource for Counted {
            fn load(&self) -> Result<crate::ca::CaMaterial, crate::ca::CaError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(crate::ca::CaError)
            }
        }

        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let now = 1_800_000_000;
        let key = PKey::generate_ed25519().unwrap();
        let token = issue_bound_key(&store, host, &key, now).await;
        sqlx::query("UPDATE remote_join_tokens SET expected_key_digest=NULL WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        let source = Arc::new(Counted(AtomicUsize::new(0)));
        let service = RemoteEnrollment::new(source.clone(), store.clone());

        let error = service
            .join(host, Mode::Rootless, token.secret(), &csr_for(&key), now)
            .await
            .err()
            .expect("an invitation without a key binding is refused");
        let committed: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_certificates")
            .fetch_one(&pool)
            .await
            .unwrap();
        let consumed: bool = sqlx::query_scalar(
            "SELECT consumed_at IS NOT NULL FROM remote_join_tokens WHERE host_id=?",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(error.to_string(), "remote enrollment refused");
        assert_eq!(source.0.load(Ordering::Relaxed), 0);
        assert_eq!(committed, 1);
        assert!(consumed);
    }

    #[tokio::test]
    async fn invalid_invitations_never_load_the_private_signer() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counted(AtomicUsize);
        impl CaKeySource for Counted {
            fn load(&self) -> Result<crate::ca::CaMaterial, crate::ca::CaError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(crate::ca::CaError)
            }
        }
        let (store, _, host) = crate::enrollment::authority::tests::enrolled().await;
        let source = Arc::new(Counted(AtomicUsize::new(0)));
        let service = RemoteEnrollment::new(source.clone(), store.clone());
        let now = 1_800_000_000;
        let key = PKey::generate_ed25519().unwrap();
        let token = issue_bound_key(&store, host, &key, now).await;
        let request = csr_for(&key);
        let unknown = "A".repeat(43);
        for (identity, mode, secret, instant) in [
            (host, Mode::Rootless, "bad", now),
            (host, Mode::Rootless, unknown.as_str(), now),
            (Uuid::new_v4(), Mode::Rootless, token.secret(), now),
            (host, Mode::Rootful, token.secret(), now),
            (host, Mode::Rootless, token.secret(), now - 1),
            (host, Mode::Rootless, token.secret(), now + 900),
        ] {
            assert!(
                service
                    .join(identity, mode, secret, &request, instant)
                    .await
                    .is_err()
            );
        }
        store.revoke("owner", host, now).await.unwrap();
        assert!(
            service
                .join(host, Mode::Rootless, token.secret(), &request, now)
                .await
                .is_err()
        );
        assert_eq!(source.0.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn invalid_csr_does_not_burn_token_and_join_returns_only_committed_authority() {
        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let key = PKey::generate_ed25519().unwrap();
        let token = issue_bound_key(&store, host, &key, 1_800_000_000).await;
        let service =
            RemoteEnrollment::new(Arc::new(crate::ca::tests::source(true)), store.clone());
        assert!(
            service
                .join(
                    host,
                    Mode::Rootless,
                    token.secret(),
                    b"malformed",
                    1_800_000_000
                )
                .await
                .is_err()
        );
        let request = csr_for(&key);
        let signed = service
            .join(
                host,
                Mode::Rootless,
                token.secret(),
                &request,
                1_800_000_000,
            )
            .await
            .unwrap();
        let admitted = store
            .admit(&signed.record.fingerprint, 1_800_000_000)
            .await
            .unwrap();
        assert_eq!(admitted.host, host);
        assert_eq!(admitted.execution_uid, 1002);
        assert!(
            service
                .join(
                    host,
                    Mode::Rootless,
                    token.secret(),
                    &request,
                    1_800_000_000
                )
                .await
                .is_err()
        );
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_certificates")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, 2); // Fixture predecessor and exactly one real joined identity.
        let renewed = service
            .renew(&signed.record.fingerprint, &request, 1_800_086_400)
            .await
            .unwrap();
        assert!(
            store
                .admit(&signed.record.fingerprint, 1_800_086_400)
                .await
                .is_ok()
        );
        assert!(
            store
                .admit(&renewed.record.fingerprint, 1_800_086_400)
                .await
                .is_ok()
        );
        assert!(
            service
                .renew(&signed.record.fingerprint, &csr(), 1_800_086_400)
                .await
                .is_err()
        );
        store.revoke("owner", host, 1_800_086_401).await.unwrap();
        assert!(
            service
                .renew(&renewed.record.fingerprint, &request, 1_800_086_402)
                .await
                .is_err()
        );
    }
    struct Administrator(crate::ca::CaMaterial);
    impl crate::ca_memory::AdministratorCaUnlock for Administrator {
        fn unlock(&self) -> Result<crate::ca::CaMaterial, crate::ca::CaError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn cold_locked_signer_preserves_admission_and_token_until_authenticated_unlock() {
        use crate::ca_memory::MemoryCaSource;
        use std::sync::Arc;
        let (store, _, host) = crate::enrollment::authority::tests::enrolled().await;
        let material = crate::ca::tests::test_material();
        let source = Arc::new(MemoryCaSource::cold_start(material.issuer().clone()));
        let service = RemoteEnrollment::new(source.clone(), store.clone());
        let now = 1_800_000_000;
        let key = PKey::generate_ed25519().unwrap();
        let token = issue_bound_key(&store, host, &key, now).await;
        let request = csr_for(&key);
        assert!(
            service
                .join(host, Mode::Rootless, token.secret(), &request, now)
                .await
                .is_err()
        );
        source.unlock_from(&Administrator(material)).unwrap();
        let signed = service
            .join(host, Mode::Rootless, token.secret(), &request, now)
            .await
            .unwrap();
        // Cold restart has the same public trust and ledger, with no inherited secret.
        let cold = Arc::new(MemoryCaSource::cold_start(source.issuer().unwrap()));
        let restarted = RemoteEnrollment::new(cold, store.clone());
        assert!(
            store
                .admit(&signed.record.fingerprint, now + 302_400)
                .await
                .is_ok()
        );
        assert!(
            restarted
                .renew(&signed.record.fingerprint, &request, now + 302_400)
                .await
                .is_err()
        );
        assert!(
            store
                .admit(&signed.record.fingerprint, now + 302_401)
                .await
                .is_ok()
        );
        // The live source remains usable; no terminal authority is removed by locking a signer.
        assert!(
            service
                .renew(&signed.record.fingerprint, &request, now + 302_400)
                .await
                .is_ok()
        );
    }

    /// A fresh software P-256 key: the stand-in for an iPhone's Secure Enclave key.
    fn p256_key() -> PKey<Private> {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap()
    }

    /// A P-256 request signed with `ecdsa-with-SHA256`, as a device sends it.
    fn p256_csr_for(key: &PKey<Private>) -> Vec<u8> {
        let mut builder = X509Req::builder().unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .set_subject_name(&X509NameBuilder::new().unwrap().build())
            .unwrap();
        builder.sign(key, MessageDigest::sha256()).unwrap();
        builder.build().to_der().unwrap()
    }

    /// The device digest of a P-256 key: SHA-256 of its 65-byte uncompressed point.
    fn p256_digest(key: &PKey<Private>) -> [u8; 32] {
        let public = PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
        crate::identity_key::IdentityKey::from_public_key(&public)
            .unwrap()
            .digest()
    }

    /// The pairs a device join may use, and the one a host may use.
    const DEVICE: (Mode, KeyAlgorithm) = (Mode::Device, KeyAlgorithm::P256);

    /// #580 P3/P5: a device invitation admits exactly its P-256 key, the stored
    /// certificate records the 65-byte point as `p256` and no uid, and the device
    /// is admitted as a device, never as a host with terminals.
    #[tokio::test]
    async fn device_invitation_admits_its_p256_key() {
        let (store, pool, host) = crate::enrollment::authority::tests::device_host().await;
        let now = 1_800_000_000;
        let key = p256_key();
        let secret = crate::enrollment::authority::tests::device_receipt(
            &store,
            &pool,
            host,
            DEVICE,
            &p256_digest(&key),
            now,
        )
        .await
        .unwrap();
        let service =
            RemoteEnrollment::new(Arc::new(crate::ca::tests::source(true)), store.clone());
        let signed = service
            .join(host, Mode::Device, &secret, &p256_csr_for(&key), now)
            .await
            .unwrap();
        assert_eq!(signed.record.public_key.algorithm(), KeyAlgorithm::P256);
        let stored: (String, Vec<u8>, Option<i64>) = sqlx::query_as(
            "SELECT key_algorithm, public_key, execution_uid FROM remote_certificates WHERE fingerprint=?",
        )
        .bind(signed.record.fingerprint.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(stored.0, "p256");
        assert_eq!(stored.1, signed.record.public_key.as_bytes());
        assert_eq!(stored.1.len(), 65);
        assert_eq!(stored.2, None, "a device certificate carries no uid");
        let leaf = openssl::x509::X509::from_der(&signed.der).unwrap();
        assert!(leaf.public_key().unwrap().public_eq(&key));
        assert_eq!(
            store
                .admit_device(&signed.record.fingerprint, now)
                .await
                .unwrap()
                .host,
            host
        );
        assert!(
            store.admit(&signed.record.fingerprint, now).await.is_err(),
            "the host guard (terminals, logins) never admits a device"
        );
        assert_eq!(
            store.host_key_digest(host).await.unwrap(),
            Some(p256_digest(&key)),
            "the device key's digest is the one its approval bound"
        );
    }

    /// #580 P3, Q4: a host invitation never admits a P-256 key, even one whose
    /// digest it was bound to, and a device invitation never admits an Ed25519
    /// key. Each refusal records no certificate.
    #[tokio::test]
    async fn cross_algorithm_joins_are_refused() {
        for device_invitation in [false, true] {
            let now = 1_800_000_000;
            let p256 = p256_key();
            let ed25519 = PKey::generate_ed25519().unwrap();
            let (store, pool, host, mode, secret, csr) = if device_invitation {
                let (store, pool, host) = crate::enrollment::authority::tests::device_host().await;
                // A device receipt cannot be written for an Ed25519 key at all, so it
                // binds the P-256 digest and the join is sent an Ed25519 request.
                let secret = crate::enrollment::authority::tests::device_receipt(
                    &store,
                    &pool,
                    host,
                    DEVICE,
                    &p256_digest(&p256),
                    now,
                )
                .await
                .unwrap();
                (store, pool, host, Mode::Device, secret, csr_for(&ed25519))
            } else {
                let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
                let token = store
                    .issue("owner", host, Mode::Rootless, now, &p256_digest(&p256))
                    .await
                    .unwrap();
                (
                    store,
                    pool,
                    host,
                    Mode::Rootless,
                    token.secret().to_owned(),
                    p256_csr_for(&p256),
                )
            };
            let service =
                RemoteEnrollment::new(Arc::new(crate::ca::tests::source(true)), store.clone());
            assert!(
                service.join(host, mode, &secret, &csr, now).await.is_err(),
                "device invitation {device_invitation}: the other algorithm was admitted"
            );
            let committed: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM remote_certificates WHERE host_id=? AND key_algorithm=?",
            )
            .bind(host.as_bytes().as_slice())
            .bind(if device_invitation { "ed25519" } else { "p256" })
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(committed, 0, "the refused key left no certificate");
        }
    }

    /// #580 Q4, red tests for the pairing: only a device holds P-256, and a
    /// device holds nothing else. The receipt writer, the invitation writer and
    /// the join each refuse the other pairings, and a device is never invited as a host.
    #[tokio::test]
    async fn only_a_device_pairs_with_p256() {
        let now = 1_800_000_000;
        let key = p256_key();
        let digest = p256_digest(&key);
        let (store, pool, host) = crate::enrollment::authority::tests::device_host().await;
        for pairing in [
            (Mode::Device, KeyAlgorithm::Ed25519),
            (Mode::Rootless, KeyAlgorithm::P256),
            (Mode::Rootful, KeyAlgorithm::P256),
            (Mode::Rootless, KeyAlgorithm::Ed25519),
        ] {
            assert!(
                crate::enrollment::authority::tests::device_receipt(
                    &store, &pool, host, pairing, &digest, now
                )
                .await
                .is_err(),
                "{pairing:?} was published for a device host"
            );
        }
        assert!(
            store
                .issue("owner", host, Mode::Device, now, &digest)
                .await
                .is_err(),
            "an owner-requested invitation never makes a device invitation"
        );
        let secret = crate::enrollment::authority::tests::device_receipt(
            &store, &pool, host, DEVICE, &digest, now,
        )
        .await
        .unwrap();
        let service =
            RemoteEnrollment::new(Arc::new(crate::ca::tests::source(true)), store.clone());
        for mode in [Mode::Rootless, Mode::Rootful] {
            assert!(
                service
                    .join(host, mode, &secret, &p256_csr_for(&key), now)
                    .await
                    .is_err(),
                "a device invitation redeemed as {mode:?}"
            );
        }
        // The wrong-mode attempts did not spend it; the right one still joins.
        assert!(
            service
                .join(host, Mode::Device, &secret, &p256_csr_for(&key), now)
                .await
                .is_ok()
        );
    }

    /// The atomic redeem itself refuses a certificate whose algorithm differs
    /// from the invitation's, even when the key digest matches: the check does
    /// not depend on the join's parse alone.
    #[tokio::test]
    async fn redeem_requires_the_invitation_algorithm() {
        let (store, _pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let now = 1_800_000_000;
        let key = p256_key();
        let token = store
            .issue("owner", host, Mode::Rootless, now, &p256_digest(&key))
            .await
            .unwrap();
        let service =
            RemoteEnrollment::new(Arc::new(crate::ca::tests::source(true)), store.clone());
        let csr =
            crate::csr::ValidatedCsr::parse_as(&p256_csr_for(&key), KeyAlgorithm::P256).unwrap();
        let signed = service
            .signer()
            .unwrap()
            .sign_host(host, &csr, now)
            .unwrap();
        assert!(
            store
                .redeem(token.secret(), host, Mode::Rootless, now, &signed.record)
                .await
                .is_err()
        );
    }
}
