//! Recovers an expired host certificate without relaxing ordinary mTLS admission (#285).

use crate::{
    ca::{CaKeySource, CertificateAuthority},
    clock_health::ClockHealth,
    csr::ValidatedCsr,
    enrollment::EnrollmentStore,
};
use infraternal_agent::{channel::Channel, remote_tls::TcpTls};
use infraternal_plugin_remote::remote_recovery::{
    RecoveryRequest, RecoveryResponse, RecoveryTranscript, csr_digest, request_id, transcript,
};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey},
    sign::Verifier,
};
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

const RECOVERY_GRACE: i64 = 90 * 24 * 60 * 60;
const CHALLENGE_LIFETIME: i64 = 5 * 60;
const MAX_SOURCE_ATTEMPTS: u16 = 24;
const MAX_HOST_ATTEMPTS: u16 = 12;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_SOURCE_BUCKETS: usize = 4096;
const MAX_HOST_BUCKETS: usize = 10_000;
const MAX_SIGNATURE_BYTES: usize = 64;

/// Bound unauthenticated recovery traffic before CSR signature verification or CA signing.
#[derive(Default)]
pub(crate) struct Limiter {
    sources: Mutex<HashMap<IpAddr, Bucket>>,
    hosts: Mutex<HashMap<Uuid, Bucket>>,
}

#[derive(Clone, Copy)]
struct Bucket {
    start: Instant,
    attempts: u16,
}

impl Limiter {
    fn admit(&self, source: IpAddr, host: Uuid) -> bool {
        let now = Instant::now();
        bucket_admits(
            &self.sources,
            source,
            now,
            MAX_SOURCE_BUCKETS,
            MAX_SOURCE_ATTEMPTS,
        ) && bucket_admits(&self.hosts, host, now, MAX_HOST_BUCKETS, MAX_HOST_ATTEMPTS)
    }
}

fn bucket_admits<K: Eq + std::hash::Hash + Copy>(
    buckets: &Mutex<HashMap<K, Bucket>>,
    key: K,
    now: Instant,
    cap: usize,
    limit: u16,
) -> bool {
    let Ok(mut buckets) = buckets.lock() else {
        return false;
    };
    if let Some(bucket) = buckets.get_mut(&key) {
        if now.duration_since(bucket.start) >= RATE_WINDOW {
            *bucket = Bucket {
                start: now,
                attempts: 1,
            };
            return true;
        }
        bucket.attempts = bucket.attempts.saturating_add(1);
        return bucket.attempts <= limit;
    }
    if buckets.len() >= cap {
        buckets.retain(|_, bucket| now.duration_since(bucket.start) < RATE_WINDOW);
        if buckets.len() >= cap {
            return false;
        }
    }
    buckets.insert(
        key,
        Bucket {
            start: now,
            attempts: 1,
        },
    );
    true
}

/// Owns the one-request recovery service; callers never pass its channel into host admission.
pub(crate) struct Service {
    store: EnrollmentStore,
    source: Arc<dyn CaKeySource>,
    clock: Arc<ClockHealth>,
    limiter: Arc<Limiter>,
}

impl Service {
    /// Bind recovery to the existing authority store, unlock source and server clock.
    #[must_use]
    pub(crate) fn new(
        store: EnrollmentStore,
        source: Arc<dyn CaKeySource>,
        clock: Arc<ClockHealth>,
        limiter: Arc<Limiter>,
    ) -> Self {
        Self {
            store,
            source,
            clock,
            limiter,
        }
    }

    /// Consume at most one challenge and one proof, then retire the restricted TLS channel.
    pub(crate) async fn serve(&self, channel: TcpTls, source: IpAddr) {
        let exchange = async {
            let request =
                infraternal_plugin_remote::remote_recovery::read_request(&channel).await?;
            let response = self.process(source, request).await;
            infraternal_plugin_remote::remote_recovery::write_response(&channel, &response).await?;
            if matches!(response, RecoveryResponse::Challenge { .. }) {
                let request =
                    infraternal_plugin_remote::remote_recovery::read_request(&channel).await?;
                let response = self.process(source, request).await;
                infraternal_plugin_remote::remote_recovery::write_response(&channel, &response)
                    .await?;
            }
            Ok::<(), io::Error>(())
        };
        let _ = tokio::time::timeout(Duration::from_secs(20), exchange).await;
        channel.retire();
    }

    async fn process(&self, source: IpAddr, request: RecoveryRequest) -> RecoveryResponse {
        let host = match &request {
            RecoveryRequest::Challenge { host_id, .. } | RecoveryRequest::Prove { host_id, .. } => {
                *host_id
            }
        };
        if !self.limiter.admit(source, host) {
            return RecoveryResponse::Denied;
        }
        let Some(now) = self.clock.current_epoch() else {
            return RecoveryResponse::Denied;
        };
        match self.process_at(request, now).await {
            Ok(response) => response,
            Err(Denied) => RecoveryResponse::Denied,
        }
    }

    async fn process_at(
        &self,
        request: RecoveryRequest,
        now: i64,
    ) -> Result<RecoveryResponse, Denied> {
        match request {
            RecoveryRequest::Challenge {
                host_id,
                predecessor_fingerprint,
                request_id,
                csr_digest,
            } => {
                self.challenge_at(
                    host_id,
                    predecessor_fingerprint,
                    request_id,
                    csr_digest,
                    now,
                )
                .await
            }
            RecoveryRequest::Prove {
                host_id,
                predecessor_fingerprint,
                request_id,
                challenge,
                csr_der,
                signature,
            } => {
                self.prove_at(
                    host_id,
                    predecessor_fingerprint,
                    request_id,
                    challenge,
                    csr_der,
                    signature,
                    now,
                )
                .await
            }
        }
    }

    async fn challenge_at(
        &self,
        host: Uuid,
        predecessor: [u8; 32],
        request: [u8; 32],
        digest: [u8; 32],
        now: i64,
    ) -> Result<RecoveryResponse, Denied> {
        if request != request_id(host, &predecessor, &digest) {
            return Err(Denied);
        }
        let pool = &self.store.0;
        let identity: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT c.public_key,c.not_after FROM remote_certificates c \
             JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.not_before<=? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL",
        )
        .bind(predecessor.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(pool)
        .await
        .map_err(|_| Denied)?;
        let (public_key, not_after) = identity.ok_or(Denied)?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| Denied)?;
        let public_key_fingerprint = openssl::sha::sha256(&public_key);
        let expires_at = now.checked_add(CHALLENGE_LIFETIME).ok_or(Denied)?;
        let mut transaction = infraternal_plugin_api::storage::begin_immediate(pool)
            .await
            .map_err(|_| Denied)?;
        let identity: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT c.public_key,c.not_after FROM remote_certificates c \
             JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.not_before<=? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL",
        )
        .bind(predecessor.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        let (stored_public_key, stored_not_after) = identity.ok_or(Denied)?;
        if stored_public_key.as_slice() != public_key.as_slice() || stored_not_after != not_after {
            return Err(Denied);
        }
        let existing: Option<(
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            i64,
            i64,
            i64,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )> = sqlx::query_as(
            "SELECT request_id,csr_digest,challenge,issuer_fingerprint,issuer_generation,predecessor_not_after,expires_at,certificate_der,certificate_fingerprint \
             FROM remote_certificate_recovery WHERE predecessor_fingerprint=?",
        )
        .bind(predecessor.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        if let Some((
            stored_request,
            stored_digest,
            stored_nonce,
            stored_issuer,
            generation,
            stored_not_after,
            expires,
            certificate,
            certificate_fingerprint,
        )) = existing
        {
            if certificate.is_some() {
                if stored_request.as_slice() == request.as_slice()
                    && stored_digest.as_slice() == digest.as_slice()
                    && stored_not_after == not_after
                {
                    let fingerprint = certificate_fingerprint.ok_or(Denied)?;
                    let available: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id \
                         WHERE c.fingerprint=? AND c.host_id=? AND c.revoked_at IS NULL AND h.revoked_at IS NULL)",
                    )
                    .bind(fingerprint)
                    .bind(host.as_bytes().as_slice())
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|_| Denied)?;
                    if !available {
                        return Err(Denied);
                    }
                    // A start frame never discloses a cached leaf. The enrolled
                    // host must repeat the proof over the durable transcript.
                    let challenge: [u8; 32] =
                        stored_nonce.as_slice().try_into().map_err(|_| Denied)?;
                    let issuer_fingerprint: [u8; 32] =
                        stored_issuer.as_slice().try_into().map_err(|_| Denied)?;
                    let issuer_generation = u64::try_from(generation).map_err(|_| Denied)?;
                    return Ok(RecoveryResponse::Challenge {
                        challenge,
                        public_key_fingerprint,
                        issuer_fingerprint,
                        issuer_generation,
                        not_after,
                    });
                }
                return Err(Denied);
            }
            let issuer = active_issuer(self.source.as_ref())?;
            if stored_request.as_slice() == request.as_slice()
                && stored_digest.as_slice() == digest.as_slice()
                && expires > now
                && stored_issuer.as_slice() == issuer.fingerprint.as_slice()
                && stored_not_after == not_after
                && u64::try_from(generation).ok() == Some(issuer.generation)
            {
                let challenge: [u8; 32] = stored_nonce.try_into().map_err(|_| Denied)?;
                return Ok(RecoveryResponse::Challenge {
                    challenge,
                    public_key_fingerprint,
                    issuer_fingerprint: issuer.fingerprint,
                    issuer_generation: issuer.generation,
                    not_after,
                });
            }
            // An unproved challenge cannot reserve this predecessor. Replacing it
            // lets the enrolled host recover if another source guessed the request fields.
            sqlx::query(
                "DELETE FROM remote_certificate_recovery WHERE predecessor_fingerprint=? \
                 AND certificate_der IS NULL",
            )
            .bind(predecessor.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| Denied)?;
        }
        if !eligible(now, not_after) {
            return Err(Denied);
        }
        let issuer = active_issuer(self.source.as_ref())?;
        let nonce = rand::random::<[u8; 32]>();
        sqlx::query(
            "INSERT INTO remote_certificate_recovery \
             (host_id,predecessor_fingerprint,request_id,csr_digest,challenge,public_key_fingerprint, \
              issuer_fingerprint,issuer_generation,predecessor_not_after,expires_at) \
             VALUES (?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(host.as_bytes().as_slice())
        .bind(predecessor.as_slice())
        .bind(request.as_slice())
        .bind(digest.as_slice())
        .bind(nonce.as_slice())
        .bind(public_key_fingerprint.as_slice())
        .bind(issuer.fingerprint.as_slice())
        .bind(i64::try_from(issuer.generation).map_err(|_| Denied)?)
        .bind(not_after)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        transaction.commit().await.map_err(|_| Denied)?;
        Ok(RecoveryResponse::Challenge {
            challenge: nonce,
            public_key_fingerprint,
            issuer_fingerprint: issuer.fingerprint,
            issuer_generation: issuer.generation,
            not_after,
        })
    }

    async fn prove_at(
        &self,
        host: Uuid,
        predecessor: [u8; 32],
        request: [u8; 32],
        challenge: [u8; 32],
        csr_der: Vec<u8>,
        signature: Vec<u8>,
        now: i64,
    ) -> Result<RecoveryResponse, Denied> {
        if request != request_id(host, &predecessor, &csr_digest(&csr_der))
            || csr_der.len() > 4096
            || signature.len() != MAX_SIGNATURE_BYTES
            || now < 0
        {
            return Err(Denied);
        }
        let csr = ValidatedCsr::parse(&csr_der).map_err(|_| Denied)?;
        let public_key: [u8; 32] = csr
            .key()
            .raw_public_key()
            .map_err(|_| Denied)?
            .try_into()
            .map_err(|_| Denied)?;
        let pool = &self.store.0;
        let operation: Option<(
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            i64,
            i64,
            i64,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        )> = sqlx::query_as(
            "SELECT r.csr_digest,r.challenge,r.public_key_fingerprint,r.issuer_fingerprint, \
             r.issuer_generation,r.predecessor_not_after,r.expires_at,r.certificate_der,r.certificate_fingerprint \
             FROM remote_certificate_recovery r WHERE r.host_id=? AND r.predecessor_fingerprint=? \
             AND r.request_id=?",
        )
        .bind(host.as_bytes().as_slice())
        .bind(predecessor.as_slice())
        .bind(request.as_slice())
        .fetch_optional(pool)
        .await
        .map_err(|_| Denied)?;
        let Some((
            digest,
            stored_challenge,
            public_key_fingerprint,
            issuer_fingerprint,
            generation,
            not_after,
            expires_at,
            certificate,
            certificate_fingerprint,
        )) = operation
        else {
            return Err(Denied);
        };
        let actual_digest = csr_digest(&csr_der);
        if digest.as_slice() != actual_digest.as_slice()
            || stored_challenge.as_slice() != challenge.as_slice()
            || (certificate.is_none() && (expires_at <= now || !eligible(now, not_after)))
        {
            return Err(Denied);
        }
        let key_fingerprint = openssl::sha::sha256(&public_key);
        if public_key_fingerprint.as_slice() != key_fingerprint.as_slice() {
            return Err(Denied);
        }
        let registered: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT c.public_key,c.not_after FROM remote_certificates c \
             JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.not_before<=? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL",
        )
        .bind(predecessor.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(pool)
        .await
        .map_err(|_| Denied)?;
        let (registered_key, registered_not_after) = registered.ok_or(Denied)?;
        if registered_key.as_slice() != public_key.as_slice() || registered_not_after != not_after {
            return Err(Denied);
        }
        let generation = u64::try_from(generation).map_err(|_| Denied)?;
        let issuer_fingerprint: [u8; 32] = issuer_fingerprint.try_into().map_err(|_| Denied)?;
        let challenge: [u8; 32] = stored_challenge.try_into().map_err(|_| Denied)?;
        let csr_digest = csr_digest(&csr_der);
        let transcript = transcript(RecoveryTranscript {
            host_id: host,
            predecessor_fingerprint: &predecessor,
            request_id: &request,
            csr_digest: &csr_digest,
            challenge: &challenge,
            public_key_fingerprint: &key_fingerprint,
            issuer_fingerprint: &issuer_fingerprint,
            issuer_generation: generation,
            not_after,
        });
        let public_key =
            PKey::public_key_from_raw_bytes(&public_key, Id::ED25519).map_err(|_| Denied)?;
        let mut verifier = Verifier::new_without_digest(&public_key).map_err(|_| Denied)?;
        // Ed25519 verifies the complete transcript in one operation; streaming updates are unsupported.
        if !verifier
            .verify_oneshot(&signature, &transcript)
            .map_err(|_| Denied)?
        {
            return Err(Denied);
        }
        if let Some(certificate_der) = certificate {
            let fingerprint = certificate_fingerprint.ok_or(Denied)?;
            let available: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id \
                 WHERE c.fingerprint=? AND c.host_id=? AND c.revoked_at IS NULL AND h.revoked_at IS NULL)",
            )
            .bind(fingerprint)
            .bind(host.as_bytes().as_slice())
            .fetch_one(pool)
            .await
            .map_err(|_| Denied)?;
            if !available {
                return Err(Denied);
            }
            return Ok(RecoveryResponse::Certificate { certificate_der });
        }
        let issuer = active_issuer(self.source.as_ref())?;
        if issuer.fingerprint != issuer_fingerprint || issuer.generation != generation {
            return Err(Denied);
        }
        let issued_at = self.clock.current_epoch().ok_or(Denied)?;
        if !eligible(issued_at, not_after) {
            return Err(Denied);
        }
        let signed = issuer
            .authority
            .sign_host(host, &csr, issued_at)
            .map_err(|_| Denied)?;
        let current_issuer = active_issuer(self.source.as_ref())?;
        if current_issuer.fingerprint != issuer.fingerprint
            || current_issuer.generation != issuer.generation
        {
            return Err(Denied);
        }
        // The final time sample catches a backward jump or a grace-window boundary
        // crossed during CSR verification and signing before durable authority changes.
        let committed_at = self.clock.current_epoch().ok_or(Denied)?;
        if !eligible(committed_at, not_after) {
            return Err(Denied);
        }
        self.commit_certificate(
            host,
            predecessor,
            request,
            challenge,
            &csr_der,
            &signed,
            committed_at,
        )
        .await
    }

    async fn commit_certificate(
        &self,
        host: Uuid,
        predecessor: [u8; 32],
        request: [u8; 32],
        challenge: [u8; 32],
        csr_der: &[u8],
        signed: &crate::ca::SignedCertificate,
        now: i64,
    ) -> Result<RecoveryResponse, Denied> {
        let mut transaction = infraternal_plugin_api::storage::begin_immediate(&self.store.0)
            .await
            .map_err(|_| Denied)?;
        let operation: Option<(Vec<u8>, Vec<u8>, i64, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT csr_digest,challenge,expires_at,certificate_der,certificate_fingerprint FROM remote_certificate_recovery \
             WHERE host_id=? AND predecessor_fingerprint=? AND request_id=?",
        )
        .bind(host.as_bytes().as_slice())
        .bind(predecessor.as_slice())
        .bind(request.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        let Some((digest, stored_challenge, expires_at, certificate, certificate_fingerprint)) =
            operation
        else {
            return Err(Denied);
        };
        let actual_digest = csr_digest(csr_der);
        if digest.as_slice() != actual_digest.as_slice()
            || stored_challenge.as_slice() != challenge.as_slice()
        {
            return Err(Denied);
        }
        if let Some(certificate_der) = certificate {
            let fingerprint = certificate_fingerprint.ok_or(Denied)?;
            let available: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_hosts h JOIN remote_certificates old ON old.host_id=h.id \
                 JOIN remote_certificates issued ON issued.host_id=h.id \
                 WHERE h.id=? AND h.revoked_at IS NULL AND old.fingerprint=? AND old.revoked_at IS NULL \
                 AND issued.fingerprint=? AND issued.revoked_at IS NULL)",
            )
            .bind(host.as_bytes().as_slice())
            .bind(predecessor.as_slice())
            .bind(fingerprint)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| Denied)?;
            if !available {
                return Err(Denied);
            }
            return Ok(RecoveryResponse::Certificate { certificate_der });
        }
        if expires_at <= now {
            return Err(Denied);
        }
        let old: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT c.public_key,c.not_after FROM remote_certificates c \
             JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.not_before<=? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL",
        )
        .bind(predecessor.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        let (old_key, not_after) = old.ok_or(Denied)?;
        if !eligible(now, not_after)
            || old_key.as_slice() != signed.record.public_key.as_slice()
            || signed.record.not_before > now
            || signed.record.not_after <= now
            || signed.record.not_after - signed.record.not_before != 604_800
        {
            return Err(Denied);
        }
        let encoded = sqlx::query(
            "UPDATE remote_certificate_recovery SET certificate_fingerprint=?,certificate_der=?,completed_at=? \
             WHERE host_id=? AND predecessor_fingerprint=? AND request_id=? AND certificate_der IS NULL \
             AND EXISTS (SELECT 1 FROM remote_hosts h JOIN remote_certificates c ON c.host_id=h.id \
               WHERE h.id=? AND h.revoked_at IS NULL AND c.fingerprint=? AND c.revoked_at IS NULL)",
        )
        .bind(signed.record.fingerprint.as_slice())
        .bind(&signed.der)
        .bind(now)
        .bind(host.as_bytes().as_slice())
        .bind(predecessor.as_slice())
        .bind(request.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(predecessor.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| Denied)?
        .rows_affected();
        if encoded != 1 {
            return Err(Denied);
        }
        let inserted = sqlx::query(
            "INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after) \
             SELECT ?,h.id,?,?,?,? FROM remote_hosts h JOIN remote_certificates old ON old.host_id=h.id \
             WHERE h.id=? AND h.revoked_at IS NULL AND old.fingerprint=? AND old.revoked_at IS NULL",
        )
        .bind(signed.record.fingerprint.as_slice())
        .bind(signed.record.issuer_fingerprint.as_slice())
        .bind(signed.record.public_key.as_slice())
        .bind(signed.record.not_before)
        .bind(signed.record.not_after)
        .bind(host.as_bytes().as_slice())
        .bind(predecessor.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| Denied)?
        .rows_affected();
        if inserted != 1 {
            return Err(Denied);
        }
        transaction.commit().await.map_err(|_| Denied)?;
        self.store.2.publish();
        Ok(RecoveryResponse::Certificate {
            certificate_der: signed.der.clone(),
        })
    }
}

struct ActiveIssuer {
    authority: CertificateAuthority,
    fingerprint: [u8; 32],
    generation: u64,
}

fn active_issuer(source: &dyn CaKeySource) -> Result<ActiveIssuer, Denied> {
    let material = source.load().map_err(|_| Denied)?;
    let certificate = material.issuer().clone();
    let authority = CertificateAuthority::from_material(material).map_err(|_| Denied)?;
    let fingerprint: [u8; 32] = certificate
        .digest(MessageDigest::sha256())
        .map_err(|_| Denied)?
        .as_ref()
        .try_into()
        .map_err(|_| Denied)?;
    let generation = source
        .public_roots()
        .into_iter()
        .find_map(|(generation, root)| {
            (generation > 0
                && root
                    .digest(MessageDigest::sha256())
                    .is_ok_and(|digest| digest.as_ref() == fingerprint.as_slice()))
            .then_some(generation)
        })
        .ok_or(Denied)?;
    if i64::try_from(generation).is_err() {
        return Err(Denied);
    }
    Ok(ActiveIssuer {
        authority,
        fingerprint,
        generation,
    })
}

struct Denied;

/// Check the inclusive expiry-to-grace window using server time.
#[must_use]
pub fn eligible(now: i64, not_after: i64) -> bool {
    now >= 0
        && not_after >= 0
        && now >= not_after
        && not_after
            .checked_add(RECOVERY_GRACE)
            .is_some_and(|deadline| now <= deadline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_uses_server_time_and_accepts_the_exact_ninety_day_boundary() {
        let not_after = 1_800_000_000_i64;
        let last_eligible = not_after + RECOVERY_GRACE;

        assert!(!eligible(not_after - 1, not_after));
        assert!(eligible(not_after, not_after));
        assert!(eligible(last_eligible, not_after));
        assert!(!eligible(last_eligible + 1, not_after));
        assert!(!eligible(i64::MAX, i64::MAX - 1));
        assert!(!eligible(-1, not_after));
        assert!(!eligible(not_after, -1));
    }

    #[test]
    fn limiter_bounds_attempts_per_key_with_a_monotonic_window() {
        let now = Instant::now();
        let source = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let buckets = Mutex::new(HashMap::new());
        assert!(bucket_admits(&buckets, source, now, 4, 2));
        assert!(bucket_admits(&buckets, source, now, 4, 2));
        assert!(!bucket_admits(&buckets, source, now, 4, 2));
        assert!(bucket_admits(&buckets, source, now + RATE_WINDOW, 4, 2));
    }

    #[tokio::test]
    async fn uncertain_clock_denies_recovery_before_consulting_signing_material() {
        use crate::ca::{CaError, CaKeySource, CaMaterial};
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountedSource(AtomicUsize);
        impl CaKeySource for CountedSource {
            fn load(&self) -> Result<CaMaterial, CaError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Err(CaError)
            }
        }

        let (store, _, host) = crate::enrollment::authority::tests::enrolled().await;
        let source = Arc::new(CountedSource(AtomicUsize::new(0)));
        let service = Service::new(
            store,
            source.clone(),
            Arc::new(ClockHealth::default()),
            Arc::new(Limiter::default()),
        );
        let predecessor = [1; 32];
        let digest = [2; 32];
        let response = service
            .process(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                RecoveryRequest::Challenge {
                    host_id: host,
                    predecessor_fingerprint: predecessor,
                    request_id: request_id(host, &predecessor, &digest),
                    csr_digest: digest,
                },
            )
            .await;
        assert!(matches!(response, RecoveryResponse::Denied));
        assert_eq!(source.0.load(Ordering::Relaxed), 0);
    }
}
