//! Joins bounded CSR proof, server-owned signing and atomic public authority; network adapters supply pinned channels [64][133], #78.

use crate::{
    ca::{CaKeySource, CertificateAuthority, SignedCertificate},
    csr::ValidatedCsr,
    enrollment::{EnrollmentStore, Mode},
};
use openssl::memcmp;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// Adapters expose content-free errors; neither capability nor CSR enters diagnostics.
#[derive(Debug, thiserror::Error)]
#[error("remote enrollment refused")]
pub struct RemoteEnrollmentError;

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
        let expected_key_digest = self
            .store
            .preflight(token, host, mode, now)
            .await
            .map_err(|_| RemoteEnrollmentError)?;
        let csr = ValidatedCsr::parse(csr_der).map_err(|_| RemoteEnrollmentError)?;
        let public_key = csr
            .key()
            .raw_public_key()
            .map_err(|_| RemoteEnrollmentError)?;
        let actual_key_digest = Sha256::digest(public_key);
        let matches = expected_key_digest
            .as_ref()
            .is_some_and(|expected| memcmp::eq(expected, actual_key_digest.as_slice()));
        if !matches {
            let _ = self.store.consume_refused(token, host, mode, now).await;
            return Err(RemoteEnrollmentError);
        }
        #[cfg(test)]
        let certificate_started = std::time::Instant::now();
        #[cfg(test)]
        let certificate_started_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let certificate = self
            .signer()?
            .sign_host(host, &csr, now)
            .map_err(|_| RemoteEnrollmentError)?;
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
        self.store
            .redeem(token, host, mode, now, &certificate.record)
            .await
            .map_err(|_| RemoteEnrollmentError)?;
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
        let identity = self
            .store
            .admit(predecessor, now)
            .await
            .map_err(|_| RemoteEnrollmentError)?;
        if csr_der.len() > 4096 {
            return Err(RemoteEnrollmentError);
        }
        let source = self.source.clone();
        let csr_der = csr_der.to_vec();
        let certificate = tokio::task::spawn_blocking(move || {
            let csr = ValidatedCsr::parse(&csr_der).map_err(|_| RemoteEnrollmentError)?;
            CertificateAuthority::from_source(source.as_ref())
                .map_err(|_| RemoteEnrollmentError)?
                .sign_host(identity.host, &csr, now)
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
}
