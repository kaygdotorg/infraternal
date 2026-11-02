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

#[derive(Clone, Copy)]
struct ChallengeInput {
    host: Uuid,
    predecessor: [u8; 32],
    request: [u8; 32],
    digest: [u8; 32],
    now: i64,
}

struct ProofRequest {
    host: Uuid,
    predecessor: [u8; 32],
    request: [u8; 32],
    challenge: [u8; 32],
    csr_der: Vec<u8>,
    signature: Vec<u8>,
}

struct RegisteredIdentity {
    fingerprint: [u8; 32],
    not_after: i64,
}

#[derive(sqlx::FromRow)]
struct ChallengeOperationRow {
    request_id: Vec<u8>,
    csr_digest: Vec<u8>,
    challenge: Vec<u8>,
    issuer_fingerprint: Vec<u8>,
    issuer_generation: i64,
    predecessor_not_after: i64,
    expires_at: i64,
    certificate_der: Option<Vec<u8>>,
    certificate_fingerprint: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct ProofOperationRow {
    csr_digest: Vec<u8>,
    challenge: Vec<u8>,
    public_key_fingerprint: Vec<u8>,
    issuer_fingerprint: Vec<u8>,
    issuer_generation: i64,
    predecessor_not_after: i64,
    expires_at: i64,
    certificate_der: Option<Vec<u8>>,
    certificate_fingerprint: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct CommittedCertificateRow {
    csr_digest: Vec<u8>,
    challenge: Vec<u8>,
    expires_at: i64,
    certificate_der: Option<Vec<u8>>,
    certificate_fingerprint: Option<Vec<u8>>,
}

struct VerifiedProof {
    issuer_fingerprint: [u8; 32],
    issuer_generation: u64,
    not_after: i64,
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
                self.challenge_at(ChallengeInput {
                    host: host_id,
                    predecessor: predecessor_fingerprint,
                    request: request_id,
                    digest: csr_digest,
                    now,
                })
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
                    ProofRequest {
                        host: host_id,
                        predecessor: predecessor_fingerprint,
                        request: request_id,
                        challenge,
                        csr_der,
                        signature,
                    },
                    now,
                )
                .await
            }
        }
    }

    async fn challenge_at(&self, input: ChallengeInput) -> Result<RecoveryResponse, Denied> {
        if input.request != request_id(input.host, &input.predecessor, &input.digest) {
            return Err(Denied);
        }
        let pool = &self.store.0;
        let mut transaction = infraternal_plugin_api::storage::begin_immediate(pool)
            .await
            .map_err(|_| Denied)?;
        let identity: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT c.public_key,c.not_after FROM remote_certificates c \
             JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.not_before<=? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL",
        )
        .bind(input.predecessor.as_slice())
        .bind(input.host.as_bytes().as_slice())
        .bind(input.now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        let (public_key, not_after) = identity.ok_or(Denied)?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| Denied)?;
        let identity = RegisteredIdentity {
            fingerprint: openssl::sha::sha256(&public_key),
            not_after,
        };
        let expires_at = input.now.checked_add(CHALLENGE_LIFETIME).ok_or(Denied)?;
        let existing: Option<ChallengeOperationRow> = sqlx::query_as(
            "SELECT request_id,csr_digest,challenge,issuer_fingerprint,issuer_generation, \
             predecessor_not_after,expires_at,certificate_der,certificate_fingerprint \
             FROM remote_certificate_recovery WHERE predecessor_fingerprint=?",
        )
        .bind(input.predecessor.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        if let Some(existing) = existing
            && let Some(response) = self
                .resume_challenge(&mut *transaction, input, &identity, existing)
                .await?
        {
            return Ok(response);
        }
        if !eligible(input.now, identity.not_after) {
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
        .bind(input.host.as_bytes().as_slice())
        .bind(input.predecessor.as_slice())
        .bind(input.request.as_slice())
        .bind(input.digest.as_slice())
        .bind(nonce.as_slice())
        .bind(identity.fingerprint.as_slice())
        .bind(i64::try_from(issuer.generation).map_err(|_| Denied)?)
        .bind(identity.not_after)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        transaction.commit().await.map_err(|_| Denied)?;
        Ok(challenge_response(
            nonce,
            identity.fingerprint,
            issuer.fingerprint,
            issuer.generation,
            identity.not_after,
        ))
    }

    async fn resume_challenge(
        &self,
        connection: &mut sqlx::SqliteConnection,
        input: ChallengeInput,
        identity: &RegisteredIdentity,
        existing: ChallengeOperationRow,
    ) -> Result<Option<RecoveryResponse>, Denied> {
        if existing.certificate_der.is_some() {
            if existing.request_id.as_slice() != input.request.as_slice()
                || existing.csr_digest.as_slice() != input.digest.as_slice()
                || existing.predecessor_not_after != identity.not_after
            {
                return Err(Denied);
            }
            let fingerprint = existing.certificate_fingerprint.ok_or(Denied)?;
            let available: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id \
                 WHERE c.fingerprint=? AND c.host_id=? AND c.revoked_at IS NULL AND h.revoked_at IS NULL)",
            )
            .bind(fingerprint)
            .bind(input.host.as_bytes().as_slice())
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| Denied)?;
            if !available {
                return Err(Denied);
            }
            let challenge = existing
                .challenge
                .as_slice()
                .try_into()
                .map_err(|_| Denied)?;
            let issuer_fingerprint = existing
                .issuer_fingerprint
                .as_slice()
                .try_into()
                .map_err(|_| Denied)?;
            let generation = u64::try_from(existing.issuer_generation).map_err(|_| Denied)?;
            return Ok(Some(challenge_response(
                challenge,
                identity.fingerprint,
                issuer_fingerprint,
                generation,
                identity.not_after,
            )));
        }
        let issuer = active_issuer(self.source.as_ref())?;
        if existing.request_id.as_slice() == input.request.as_slice()
            && existing.csr_digest.as_slice() == input.digest.as_slice()
            && existing.expires_at > input.now
            && existing.issuer_fingerprint.as_slice() == issuer.fingerprint.as_slice()
            && existing.predecessor_not_after == identity.not_after
            && u64::try_from(existing.issuer_generation).ok() == Some(issuer.generation)
        {
            let challenge = existing
                .challenge
                .as_slice()
                .try_into()
                .map_err(|_| Denied)?;
            return Ok(Some(challenge_response(
                challenge,
                identity.fingerprint,
                issuer.fingerprint,
                issuer.generation,
                identity.not_after,
            )));
        }
        // An unproved challenge cannot reserve this predecessor. A malformed replacement
        // is discarded only when it has no completed certificate.
        sqlx::query(
            "DELETE FROM remote_certificate_recovery WHERE predecessor_fingerprint=? \
             AND certificate_der IS NULL",
        )
        .bind(input.predecessor.as_slice())
        .execute(&mut *connection)
        .await
        .map_err(|_| Denied)?;
        Ok(None)
    }

    async fn prove_at(&self, request: ProofRequest, now: i64) -> Result<RecoveryResponse, Denied> {
        if now < 0 {
            return Err(Denied);
        }
        let (csr, public_key) = validate_proof_request(&request)?;
        let operation = self.load_proof_operation(&request).await?;
        let verified = self
            .verify_proof(&request, &operation, &public_key, now)
            .await?;
        if let Some(certificate_der) = operation.certificate_der {
            let fingerprint = operation.certificate_fingerprint.ok_or(Denied)?;
            self.require_issued_certificate(&request, &fingerprint)
                .await?;
            return Ok(RecoveryResponse::Certificate { certificate_der });
        }
        let issuer = active_issuer(self.source.as_ref())?;
        if issuer.fingerprint != verified.issuer_fingerprint
            || issuer.generation != verified.issuer_generation
        {
            return Err(Denied);
        }
        let issued_at = self.clock.current_epoch().ok_or(Denied)?;
        if !eligible(issued_at, verified.not_after) {
            return Err(Denied);
        }
        let signed = issuer
            .authority
            .sign_host(request.host, &csr, issued_at)
            .map_err(|_| Denied)?;
        let current_issuer = active_issuer(self.source.as_ref())?;
        if current_issuer.fingerprint != issuer.fingerprint
            || current_issuer.generation != issuer.generation
        {
            return Err(Denied);
        }
        // The final time sample catches a backward jump or grace-window boundary
        // crossed during CSR verification and signing before durable authority changes.
        let committed_at = self.clock.current_epoch().ok_or(Denied)?;
        if !eligible(committed_at, verified.not_after) {
            return Err(Denied);
        }
        self.commit_certificate(&request, &signed, committed_at)
            .await
    }

    async fn load_proof_operation(
        &self,
        request: &ProofRequest,
    ) -> Result<ProofOperationRow, Denied> {
        sqlx::query_as(
            "SELECT csr_digest,challenge,public_key_fingerprint,issuer_fingerprint, \
             issuer_generation,predecessor_not_after,expires_at,certificate_der,certificate_fingerprint \
             FROM remote_certificate_recovery WHERE host_id=? AND predecessor_fingerprint=? \
             AND request_id=?",
        )
        .bind(request.host.as_bytes().as_slice())
        .bind(request.predecessor.as_slice())
        .bind(request.request.as_slice())
        .fetch_optional(&self.store.0)
        .await
        .map_err(|_| Denied)?
        .ok_or(Denied)
    }

    async fn verify_proof(
        &self,
        request: &ProofRequest,
        operation: &ProofOperationRow,
        public_key: &[u8; 32],
        now: i64,
    ) -> Result<VerifiedProof, Denied> {
        let actual_digest = csr_digest(&request.csr_der);
        if operation.csr_digest.as_slice() != actual_digest.as_slice()
            || operation.challenge.as_slice() != request.challenge.as_slice()
            || (operation.certificate_der.is_none()
                && (operation.expires_at <= now || !eligible(now, operation.predecessor_not_after)))
        {
            return Err(Denied);
        }
        let key_fingerprint = openssl::sha::sha256(public_key);
        if operation.public_key_fingerprint.as_slice() != key_fingerprint.as_slice() {
            return Err(Denied);
        }
        self.require_registered_identity(request, public_key, operation.predecessor_not_after, now)
            .await?;
        let issuer_generation = u64::try_from(operation.issuer_generation).map_err(|_| Denied)?;
        let issuer_fingerprint: [u8; 32] = operation
            .issuer_fingerprint
            .as_slice()
            .try_into()
            .map_err(|_| Denied)?;
        let challenge: [u8; 32] = operation
            .challenge
            .as_slice()
            .try_into()
            .map_err(|_| Denied)?;
        let transcript = transcript(RecoveryTranscript {
            host_id: request.host,
            predecessor_fingerprint: &request.predecessor,
            request_id: &request.request,
            csr_digest: &actual_digest,
            challenge: &challenge,
            public_key_fingerprint: &key_fingerprint,
            issuer_fingerprint: &issuer_fingerprint,
            issuer_generation,
            not_after: operation.predecessor_not_after,
        });
        let public_key =
            PKey::public_key_from_raw_bytes(public_key, Id::ED25519).map_err(|_| Denied)?;
        let mut verifier = Verifier::new_without_digest(&public_key).map_err(|_| Denied)?;
        // Ed25519 verifies the complete transcript in one operation; streaming updates are unsupported.
        if !verifier
            .verify_oneshot(&request.signature, &transcript)
            .map_err(|_| Denied)?
        {
            return Err(Denied);
        }
        Ok(VerifiedProof {
            issuer_fingerprint,
            issuer_generation,
            not_after: operation.predecessor_not_after,
        })
    }

    async fn require_registered_identity(
        &self,
        request: &ProofRequest,
        public_key: &[u8; 32],
        not_after: i64,
        now: i64,
    ) -> Result<(), Denied> {
        let registered: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT c.public_key,c.not_after FROM remote_certificates c \
             JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.not_before<=? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL",
        )
        .bind(request.predecessor.as_slice())
        .bind(request.host.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&self.store.0)
        .await
        .map_err(|_| Denied)?;
        let (registered_key, registered_not_after) = registered.ok_or(Denied)?;
        if registered_key.as_slice() == public_key.as_slice() && registered_not_after == not_after {
            Ok(())
        } else {
            Err(Denied)
        }
    }

    async fn require_issued_certificate(
        &self,
        request: &ProofRequest,
        fingerprint: &[u8],
    ) -> Result<(), Denied> {
        let available: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.revoked_at IS NULL AND h.revoked_at IS NULL)",
        )
        .bind(fingerprint)
        .bind(request.host.as_bytes().as_slice())
        .fetch_one(&self.store.0)
        .await
        .map_err(|_| Denied)?;
        available.then_some(()).ok_or(Denied)
    }

    async fn commit_certificate(
        &self,
        request: &ProofRequest,
        signed: &crate::ca::SignedCertificate,
        now: i64,
    ) -> Result<RecoveryResponse, Denied> {
        let mut transaction = infraternal_plugin_api::storage::begin_immediate(&self.store.0)
            .await
            .map_err(|_| Denied)?;
        let operation: Option<CommittedCertificateRow> = sqlx::query_as(
            "SELECT csr_digest,challenge,expires_at,certificate_der,certificate_fingerprint FROM remote_certificate_recovery \
             WHERE host_id=? AND predecessor_fingerprint=? AND request_id=?",
        )
        .bind(request.host.as_bytes().as_slice())
        .bind(request.predecessor.as_slice())
        .bind(request.request.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        let operation = operation.ok_or(Denied)?;
        if operation.csr_digest.as_slice() != csr_digest(&request.csr_der).as_slice()
            || operation.challenge.as_slice() != request.challenge.as_slice()
        {
            return Err(Denied);
        }
        if let Some(certificate_der) = operation.certificate_der {
            let fingerprint = operation.certificate_fingerprint.ok_or(Denied)?;
            require_recorded_certificate(&mut *transaction, request, &fingerprint).await?;
            return Ok(RecoveryResponse::Certificate { certificate_der });
        }
        if operation.expires_at <= now {
            return Err(Denied);
        }
        let old: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT c.public_key,c.not_after FROM remote_certificates c \
             JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.not_before<=? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL",
        )
        .bind(request.predecessor.as_slice())
        .bind(request.host.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        let (old_key, not_after) = old.ok_or(Denied)?;
        validate_signed_leaf(&old_key, not_after, signed, now)?;
        let encoded = sqlx::query(
            "UPDATE remote_certificate_recovery SET certificate_fingerprint=?,certificate_der=?,completed_at=? \
             WHERE host_id=? AND predecessor_fingerprint=? AND request_id=? AND certificate_der IS NULL \
             AND EXISTS (SELECT 1 FROM remote_hosts h JOIN remote_certificates c ON c.host_id=h.id \
               WHERE h.id=? AND h.revoked_at IS NULL AND c.fingerprint=? AND c.revoked_at IS NULL)",
        )
        .bind(signed.record.fingerprint.as_slice())
        .bind(&signed.der)
        .bind(now)
        .bind(request.host.as_bytes().as_slice())
        .bind(request.predecessor.as_slice())
        .bind(request.request.as_slice())
        .bind(request.host.as_bytes().as_slice())
        .bind(request.predecessor.as_slice())
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
        .bind(request.host.as_bytes().as_slice())
        .bind(request.predecessor.as_slice())
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

fn validate_proof_request(request: &ProofRequest) -> Result<(ValidatedCsr, [u8; 32]), Denied> {
    if request.request
        != request_id(
            request.host,
            &request.predecessor,
            &csr_digest(&request.csr_der),
        )
        || request.csr_der.len() > 4096
        || request.signature.len() != MAX_SIGNATURE_BYTES
    {
        return Err(Denied);
    }
    let csr = ValidatedCsr::parse(&request.csr_der).map_err(|_| Denied)?;
    let public_key = csr
        .key()
        .raw_public_key()
        .map_err(|_| Denied)?
        .try_into()
        .map_err(|_| Denied)?;
    Ok((csr, public_key))
}

async fn require_recorded_certificate(
    connection: &mut sqlx::SqliteConnection,
    request: &ProofRequest,
    fingerprint: &[u8],
) -> Result<(), Denied> {
    let available: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM remote_hosts h JOIN remote_certificates old ON old.host_id=h.id \
         JOIN remote_certificates issued ON issued.host_id=h.id \
         WHERE h.id=? AND h.revoked_at IS NULL AND old.fingerprint=? AND old.revoked_at IS NULL \
         AND issued.fingerprint=? AND issued.revoked_at IS NULL)",
    )
    .bind(request.host.as_bytes().as_slice())
    .bind(request.predecessor.as_slice())
    .bind(fingerprint)
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| Denied)?;
    available.then_some(()).ok_or(Denied)
}

fn validate_signed_leaf(
    old_key: &[u8],
    not_after: i64,
    signed: &crate::ca::SignedCertificate,
    now: i64,
) -> Result<(), Denied> {
    if !eligible(now, not_after)
        || old_key != signed.record.public_key.as_slice()
        || signed.record.not_before > now
        || signed.record.not_after <= now
        || signed.record.not_after - signed.record.not_before != 604_800
    {
        Err(Denied)
    } else {
        Ok(())
    }
}

struct ActiveIssuer {
    authority: CertificateAuthority,
    fingerprint: [u8; 32],
    generation: u64,
}

fn challenge_response(
    challenge: [u8; 32],
    public_key_fingerprint: [u8; 32],
    issuer_fingerprint: [u8; 32],
    issuer_generation: u64,
    not_after: i64,
) -> RecoveryResponse {
    RecoveryResponse::Challenge {
        challenge,
        public_key_fingerprint,
        issuer_fingerprint,
        issuer_generation,
        not_after,
    }
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
