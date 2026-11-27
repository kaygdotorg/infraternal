//! Recovers an expired host certificate without relaxing ordinary mTLS admission (#285).

use crate::{
    ca::{CaKeySource, CertificateAuthority},
    clock_health::ClockHealth,
    csr::ValidatedCsr,
    enrollment::EnrollmentStore,
    identity_key::{IdentityKey, KeyAlgorithm},
};
use infraternal_agent::{channel::Channel, remote_tls::TcpTls};
use infraternal_plugin_remote::remote_recovery::{
    RecoveryRequest, RecoveryResponse, RecoveryTranscript, challenge_message, csr_digest,
    request_id, transcript,
};
use openssl::hash::MessageDigest;
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

/// An expired host may recover for exactly 90 days after its certificate's notAfter, by server time (#285).
const RECOVERY_GRACE: i64 = 90 * 24 * 60 * 60;
/// A recovery challenge must be answered within five minutes.
const CHALLENGE_LIFETIME: i64 = 5 * 60;
/// Only the predecessor key can open an operation, so this cap bounds one host's own
/// retries with different CSRs. It is not what keeps other parties out.
const MAX_PENDING_OPERATIONS_PER_HOST: i64 = 4;
/// Recovery requests one source address may make per window, before any work.
const MAX_SOURCE_ATTEMPTS: u16 = 24;
/// Signed recovery requests one host may make per window.
const MAX_HOST_ATTEMPTS: u16 = 12;
/// The rate window for both budgets.
const RATE_WINDOW: Duration = Duration::from_secs(60);
/// Most source addresses tracked at once; past it, only expired buckets are dropped and new sources wait.
const MAX_SOURCE_BUCKETS: usize = 4096;
/// Most hosts tracked at once, with the same rule.
const MAX_HOST_BUCKETS: usize = 10_000;
/// The longest predecessor signature either identity algorithm produces: an
/// Ed25519 signature is 64 bytes, a DER P-256 one at most 72 (#580). Longer
/// input is refused before storage is read; each key then checks its own shape.
const MAX_SIGNATURE_BYTES: usize = KeyAlgorithm::P256.max_signature_bytes();

/// Bound recovery traffic in two stages.
///
/// The per-source budget runs before any work. The per-host budget runs only after a
/// request is signed by that host's predecessor key, so a party that knows the public
/// host fields cannot spend it and lock the real host out.
#[derive(Default)]
pub(crate) struct Limiter {
    sources: Mutex<HashMap<IpAddr, Bucket>>,
    hosts: Mutex<HashMap<Uuid, Bucket>>,
}

/// Attempts counted since the start of one rate window.
#[derive(Clone, Copy)]
struct Bucket {
    start: Instant,
    attempts: u16,
}

impl Limiter {
    /// Charge the source network before any parsing or storage work. An IPv6
    /// caller is charged to its /64, the same network unit as auth (#263), so
    /// one routed /64 can neither reset its budget by rotating addresses nor
    /// fill the 4,096-entry table and deny recovery to every new source (#572).
    fn admit_source(&self, source: IpAddr) -> bool {
        bucket_admits(
            &self.sources,
            crate::runtime::device_source(source),
            Instant::now(),
            MAX_SOURCE_BUCKETS,
            MAX_SOURCE_ATTEMPTS,
        )
    }

    /// Charge a host only for requests its predecessor key has signed.
    fn admit_host(&self, host: Uuid) -> bool {
        bucket_admits(
            &self.hosts,
            host,
            Instant::now(),
            MAX_HOST_BUCKETS,
            MAX_HOST_ATTEMPTS,
        )
    }
}

/// Count one attempt for `key`, starting a new window when the old one has passed. A full map first drops expired
/// buckets, then refuses new keys rather than evicting live ones.
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

/// A challenge request after its public fields were parsed, with the server time it is judged at.
#[derive(Clone)]
struct ChallengeInput {
    host: Uuid,
    predecessor: [u8; 32],
    request: [u8; 32],
    digest: [u8; 32],
    signature: Vec<u8>,
    now: i64,
}

/// A proof request: the CSR and the predecessor key's signature over the challenge transcript.
struct ProofRequest {
    host: Uuid,
    predecessor: [u8; 32],
    request: [u8; 32],
    challenge: [u8; 32],
    csr_der: Vec<u8>,
    signature: Vec<u8>,
}

/// The registered predecessor certificate the request names.
struct RegisteredIdentity {
    fingerprint: [u8; 32],
    not_after: i64,
}

/// The stored recovery operation a repeated challenge request is compared against.
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

/// The stored recovery operation a proof must match.
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

/// What a replayed proof is checked against once its certificate was committed.
#[derive(sqlx::FromRow)]
struct CommittedCertificateRow {
    csr_digest: Vec<u8>,
    challenge: Vec<u8>,
    expires_at: i64,
    certificate_der: Option<Vec<u8>>,
    certificate_fingerprint: Option<Vec<u8>>,
}

/// The issuer and lifetime a proof was verified against.
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

    /// Answer one recovery request. The source budget and a trusted server clock come first; every failure is the same
    /// opaque denial.
    async fn process(&self, source: IpAddr, request: RecoveryRequest) -> RecoveryResponse {
        if !self.limiter.admit_source(source) {
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

    /// Route a parsed request to the challenge or proof step at server time `now`.
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
                request_signature,
            } => {
                self.challenge_at(ChallengeInput {
                    host: host_id,
                    predecessor: predecessor_fingerprint,
                    request: request_id,
                    digest: csr_digest,
                    signature: request_signature,
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

    /// Issue or resume a challenge. The request must be signed by the predecessor key before any per-host state changes.
    async fn challenge_at(&self, input: ChallengeInput) -> Result<RecoveryResponse, Denied> {
        if input.request != request_id(input.host, &input.predecessor, &input.digest) {
            return Err(Denied);
        }
        // Authenticate before any per-host state changes: the host ID and predecessor
        // fingerprint are public, so an unsigned request could otherwise fill the
        // pending operations and the host budget, and lock the real host out.
        let retired = self.authenticate_challenge(&input).await?;
        if !self.limiter.admit_host(input.host) {
            return Err(Denied);
        }
        if retired {
            return Ok(RecoveryResponse::Retired);
        }
        let pool = &self.store.0;
        let mut transaction = infraternal_plugin_api::storage::begin_immediate(pool)
            .await
            .map_err(|_| Denied)?;
        let identity = registered_identity(&mut transaction, &input).await?;
        sqlx::query(
            "DELETE FROM remote_certificate_recovery WHERE host_id=? \
             AND certificate_der IS NULL AND expires_at<=?",
        )
        .bind(input.host.as_bytes().as_slice())
        .bind(input.now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        if let Some(operation) = existing_operation(&mut transaction, &input).await? {
            let response = self
                .resume_challenge(&mut transaction, &input, &identity, operation)
                .await;
            transaction.commit().await.map_err(|_| Denied)?;
            return response;
        }
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM remote_certificate_recovery \
             WHERE host_id=? AND certificate_der IS NULL AND expires_at>?",
        )
        .bind(input.host.as_bytes().as_slice())
        .bind(input.now)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        if pending >= MAX_PENDING_OPERATIONS_PER_HOST {
            transaction.commit().await.map_err(|_| Denied)?;
            return Err(Denied);
        }
        let expires_at = input.now.checked_add(CHALLENGE_LIFETIME).ok_or(Denied)?;
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
        .bind(issuer.fingerprint.as_slice())
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

    /// Verify the predecessor key's signature and return whether its installation is retired.
    ///
    /// This plain read takes no write lock, so unsigned traffic, already bounded per
    /// source, cannot serialize writers. The transactional lookup in `challenge_at`
    /// still rechecks revocation and the validity window before it records anything.
    async fn authenticate_challenge(&self, input: &ChallengeInput) -> Result<bool, Denied> {
        if input.signature.len() > MAX_SIGNATURE_BYTES {
            return Err(Denied);
        }
        let (algorithm, public_key, revoked): (String, Vec<u8>, bool) = sqlx::query_as(
            "SELECT c.key_algorithm, c.public_key, c.revoked_at IS NOT NULL OR h.revoked_at IS NOT NULL
             FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id
             WHERE c.fingerprint=? AND c.host_id=?",
        )
        .bind(input.predecessor.as_slice())
        .bind(input.host.as_bytes().as_slice())
        .fetch_optional(&self.store.0)
        .await
        .map_err(|_| Denied)?
        .ok_or(Denied)?;
        // The predecessor signs in its own algorithm (#580): Ed25519 for hosts,
        // P-256 for devices.
        let public_key = IdentityKey::from_stored(&algorithm, &public_key).ok_or(Denied)?;
        let message = challenge_message(
            input.host,
            &input.predecessor,
            &input.request,
            &input.digest,
        );
        if !public_key.verify(&message, &input.signature) {
            return Err(Denied);
        }
        if !revoked {
            return Ok(false);
        }
        if self
            .store
            .installation_retired(&input.predecessor)
            .await
            .map_err(|_| Denied)?
        {
            return Ok(true);
        }
        Err(Denied)
    }

    /// Answer a repeated challenge request: return the committed certificate's challenge, or the same unexpired challenge
    /// for the same CSR and issuer. Any mismatch is denied.
    async fn resume_challenge(
        &self,
        connection: &mut sqlx::SqliteConnection,
        input: &ChallengeInput,
        identity: &RegisteredIdentity,
        existing: ChallengeOperationRow,
    ) -> Result<RecoveryResponse, Denied> {
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
            return Ok(challenge_response(
                challenge,
                identity.fingerprint,
                issuer_fingerprint,
                generation,
                identity.not_after,
            ));
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
            return Ok(challenge_response(
                challenge,
                identity.fingerprint,
                issuer.fingerprint,
                issuer.generation,
                identity.not_after,
            ));
        }
        Err(Denied)
    }

    /// Verify a proof, sign a 7-day leaf for the predecessor's key and commit it, or replay the committed certificate.
    async fn prove_at(&self, request: ProofRequest, now: i64) -> Result<RecoveryResponse, Denied> {
        if now < 0 {
            return Err(Denied);
        }
        let (csr, public_key) = validate_proof_request(&request)?;
        let operation = self.load_proof_operation(&request).await?;
        let verified = self
            .verify_proof(&request, &operation, &public_key, now)
            .await?;
        // Charged only after the proof verifies; see `Limiter`.
        if !self.limiter.admit_host(request.host) {
            return Err(Denied);
        }
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

    /// Load the stored operation this proof answers.
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

    /// Check the proof against its operation: the CSR digest, the challenge, its lifetime, the issuer and the predecessor
    /// key's signature over the transcript.
    async fn verify_proof(
        &self,
        request: &ProofRequest,
        operation: &ProofOperationRow,
        public_key: &IdentityKey,
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
        let key_fingerprint = public_key.digest();
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
        if !public_key.verify(&transcript, &request.signature) {
            return Err(Denied);
        }
        Ok(VerifiedProof {
            issuer_fingerprint,
            issuer_generation,
            not_after: operation.predecessor_not_after,
        })
    }

    /// The proof's key must still be the registered key of the named predecessor certificate, with the same notAfter.
    /// Key and algorithm are compared together, so a proof can only continue an
    /// identity of its own algorithm (#580).
    async fn require_registered_identity(
        &self,
        request: &ProofRequest,
        public_key: &IdentityKey,
        not_after: i64,
        now: i64,
    ) -> Result<(), Denied> {
        let registered: Option<(String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT c.key_algorithm,c.public_key,c.not_after FROM remote_certificates c \
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
        let (algorithm, registered_key, registered_not_after) = registered.ok_or(Denied)?;
        let registered_key = IdentityKey::from_stored(&algorithm, &registered_key).ok_or(Denied)?;
        if registered_key == *public_key && registered_not_after == not_after {
            Ok(())
        } else {
            Err(Denied)
        }
    }

    /// The certificate recorded for this operation must still be live, and its host unrevoked.
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

    /// In one transaction: store the signed leaf on its operation, record it as a host certificate, and drop the
    /// predecessor's other pending operations, so only the proved request survives.
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
            require_recorded_certificate(&mut transaction, request, &fingerprint).await?;
            return Ok(RecoveryResponse::Certificate { certificate_der });
        }
        if operation.expires_at <= now {
            return Err(Denied);
        }
        let old: Option<(String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT c.key_algorithm,c.public_key,c.not_after FROM remote_certificates c \
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
        let (algorithm, old_key, not_after) = old.ok_or(Denied)?;
        let old_key = IdentityKey::from_stored(&algorithm, &old_key).ok_or(Denied)?;
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
            "INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,key_algorithm,not_before,not_after,role,execution_uid) \
             SELECT ?,h.id,?,?,?,?,?,'active',h.execution_uid FROM remote_hosts h JOIN remote_certificates old ON old.host_id=h.id \
             WHERE h.id=? AND h.revoked_at IS NULL AND old.fingerprint=? AND old.revoked_at IS NULL \
             AND old.role='active' AND old.execution_uid IS h.execution_uid",
        )
        .bind(signed.record.fingerprint.as_slice())
        .bind(signed.record.issuer_fingerprint.as_slice())
        .bind(signed.record.public_key.as_bytes())
        .bind(signed.record.public_key.algorithm().as_str())
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
        sqlx::query(
            "DELETE FROM remote_certificate_recovery WHERE host_id=? AND predecessor_fingerprint=? \
             AND request_id<>? AND certificate_der IS NULL",
        )
        .bind(request.host.as_bytes().as_slice())
        .bind(request.predecessor.as_slice())
        .bind(request.request.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| Denied)?;
        transaction.commit().await.map_err(|_| Denied)?;
        self.store.2.publish();
        Ok(RecoveryResponse::Certificate {
            certificate_der: signed.der.clone(),
        })
    }
}

/// Parse a proof's CSR and key and check the request ID, sizes and key type before any storage is read.
///
/// Recovery keeps the predecessor's key, and storage is not read yet, so the
/// CSR is admitted in whichever of the two identity shapes it has (#580).
/// That choice grants nothing by itself: every later step compares this key,
/// algorithm included, with the registered predecessor's, and verifies the
/// signature in that algorithm.
fn validate_proof_request(request: &ProofRequest) -> Result<(ValidatedCsr, IdentityKey), Denied> {
    if request.request
        != request_id(
            request.host,
            &request.predecessor,
            &csr_digest(&request.csr_der),
        )
        || request.csr_der.len() > 4096
    {
        return Err(Denied);
    }
    let csr = ValidatedCsr::parse(&request.csr_der)
        .or_else(|_| ValidatedCsr::parse_as(&request.csr_der, KeyAlgorithm::P256))
        .map_err(|_| Denied)?;
    if request.signature.len() > csr.algorithm().max_signature_bytes() {
        return Err(Denied);
    }
    let public_key = csr.identity_key().map_err(|_| Denied)?;
    Ok((csr, public_key))
}

/// Inside the commit transaction, the predecessor and the issued certificate must both still be unrevoked.
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

/// The leaf must carry the predecessor's key (and algorithm), be valid now and last exactly 7 days, inside the recovery window.
fn validate_signed_leaf(
    old_key: &IdentityKey,
    not_after: i64,
    signed: &crate::ca::SignedCertificate,
    now: i64,
) -> Result<(), Denied> {
    if !eligible(now, not_after)
        || *old_key != signed.record.public_key
        || signed.record.not_before > now
        || signed.record.not_after <= now
        || signed.record.not_after - signed.record.not_before != 604_800
    {
        Err(Denied)
    } else {
        Ok(())
    }
}

/// The CA that signs recovery leaves, with the issuer fingerprint and generation a proof is bound to.
struct ActiveIssuer {
    authority: CertificateAuthority,
    fingerprint: [u8; 32],
    generation: u64,
}

/// Read the registered, unrevoked predecessor identity inside the challenge transaction
/// and require the server-time recovery window.
async fn registered_identity(
    connection: &mut sqlx::SqliteConnection,
    input: &ChallengeInput,
) -> Result<RegisteredIdentity, Denied> {
    let (algorithm, public_key, not_after): (String, Vec<u8>, i64) = sqlx::query_as(
        "SELECT c.key_algorithm,c.public_key,c.not_after FROM remote_certificates c \
         JOIN remote_hosts h ON h.id=c.host_id \
         WHERE c.fingerprint=? AND c.host_id=? AND c.not_before<=? \
         AND c.revoked_at IS NULL AND h.revoked_at IS NULL",
    )
    .bind(input.predecessor.as_slice())
    .bind(input.host.as_bytes().as_slice())
    .bind(input.now)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| Denied)?
    .ok_or(Denied)?;
    let public_key = IdentityKey::from_stored(&algorithm, &public_key).ok_or(Denied)?;
    if !eligible(input.now, not_after) {
        return Err(Denied);
    }
    Ok(RegisteredIdentity {
        // The key's digest in its own algorithm, as the client's transcript names it.
        fingerprint: public_key.digest(),
        not_after,
    })
}

/// Find the operation this challenge resumes: the exact request first, then the one
/// committed certificate for its predecessor, which only an identical request may read.
async fn existing_operation(
    connection: &mut sqlx::SqliteConnection,
    input: &ChallengeInput,
) -> Result<Option<ChallengeOperationRow>, Denied> {
    let exact: Option<ChallengeOperationRow> = sqlx::query_as(
        "SELECT request_id,csr_digest,challenge,issuer_fingerprint,issuer_generation, \
         predecessor_not_after,expires_at,certificate_der,certificate_fingerprint \
         FROM remote_certificate_recovery WHERE host_id=? AND predecessor_fingerprint=? \
         AND request_id=?",
    )
    .bind(input.host.as_bytes().as_slice())
    .bind(input.predecessor.as_slice())
    .bind(input.request.as_slice())
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| Denied)?;
    if exact.is_some() {
        return Ok(exact);
    }
    sqlx::query_as(
        "SELECT request_id,csr_digest,challenge,issuer_fingerprint,issuer_generation, \
         predecessor_not_after,expires_at,certificate_der,certificate_fingerprint \
         FROM remote_certificate_recovery WHERE host_id=? AND predecessor_fingerprint=? \
         AND certificate_der IS NOT NULL",
    )
    .bind(input.host.as_bytes().as_slice())
    .bind(input.predecessor.as_slice())
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| Denied)
}

/// The challenge response sent to the host.
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

/// The current issuer, or a denial while the CA is locked.
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

/// The single, uninformative recovery failure.
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

/// Recovery window, rate limits, challenge authentication and proof replacement checks.
#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        pkey::{PKey, Private},
        sign::Signer,
        x509::{X509NameBuilder, X509Req},
    };
    use std::sync::Arc;

    /// The per-host pending-operation cap the tests exercise.
    const TEST_PENDING_LIMIT: usize = 4;

    /// A CA source that is always unlocked.
    struct Unlocked(crate::ca::CaMaterial);

    impl crate::ca_memory::AdministratorCaUnlock for Unlocked {
        fn unlock(&self) -> Result<crate::ca::CaMaterial, crate::ca::CaError> {
            Ok(self.0.clone())
        }
    }

    /// An enrolled host with an expired certificate, its key and an unlocked recovery service.
    struct RecoveryFixture {
        service: Service,
        pool: sqlx::SqlitePool,
        host: Uuid,
        predecessor: [u8; 32],
        identity_key: PKey<Private>,
        csr_der: Vec<u8>,
        now: i64,
    }

    /// Build the fixture: enroll a host, expire its certificate and start the clock monitor.
    async fn recovery_fixture() -> RecoveryFixture {
        recovery_fixture_with(PKey::generate_ed25519().unwrap()).await
    }

    /// A software P-256 key: the stand-in for an iPhone's Secure Enclave identity key (#580).
    fn p256_key() -> PKey<Private> {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap()
    }

    /// Sign `message` the way the key's owner does: Ed25519 over the whole
    /// message, P-256 as DER ECDSA over its SHA-256.
    fn sign_with(key: &PKey<Private>, message: &[u8]) -> Vec<u8> {
        let mut signer = if key.id() == openssl::pkey::Id::ED25519 {
            Signer::new_without_digest(key).unwrap()
        } else {
            Signer::new(MessageDigest::sha256(), key).unwrap()
        };
        signer.sign_oneshot_to_vec(message).unwrap()
    }

    /// The digest the recovery transcript names for `key`, in its own algorithm.
    fn key_fingerprint(key: &PKey<Private>) -> [u8; 32] {
        let public = PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
        IdentityKey::from_public_key(&public).unwrap().digest()
    }

    /// The fixture for an identity held by `identity_key`, Ed25519 or P-256.
    async fn recovery_fixture_with(identity_key: PKey<Private>) -> RecoveryFixture {
        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        // Only a device holds a P-256 key (#580), and the schema enforces it.
        if identity_key.id() != openssl::pkey::Id::ED25519 {
            crate::enrollment::authority::tests::into_device(&pool, host).await;
        }
        let clock = Arc::new(ClockHealth::default());
        clock.start_monitor();
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let material = crate::ca::tests::test_material();
        let source = Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
            material.issuer().clone(),
        ));
        source.unlock_from(&Unlocked(material.clone())).unwrap();

        let ed25519 = identity_key.id() == openssl::pkey::Id::ED25519;
        let mut request = X509Req::builder().unwrap();
        request
            .set_subject_name(&X509NameBuilder::new().unwrap().build())
            .unwrap();
        request.set_pubkey(&identity_key).unwrap();
        let digest = if ed25519 {
            MessageDigest::null()
        } else {
            MessageDigest::sha256()
        };
        request.sign(&identity_key, digest).unwrap();
        let csr_der = request.build().to_der().unwrap();
        let algorithm = if ed25519 {
            KeyAlgorithm::Ed25519
        } else {
            KeyAlgorithm::P256
        };
        let csr = ValidatedCsr::parse_as(&csr_der, algorithm).unwrap();
        let signed = CertificateAuthority::from_material(material.clone())
            .unwrap()
            .sign_host(host, &csr, now - 604_800)
            .unwrap();
        sqlx::query("DELETE FROM remote_certificates WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after,execution_uid,key_algorithm) VALUES(?1,?2,?3,?4,?5,?6,(SELECT execution_uid FROM remote_hosts WHERE id=?2),?7)")
            .bind(signed.record.fingerprint.as_slice())
            .bind(host.as_bytes().as_slice())
            .bind(signed.record.issuer_fingerprint.as_slice())
            .bind(signed.record.public_key.as_bytes())
            .bind(signed.record.not_before)
            .bind(signed.record.not_after)
            .bind(algorithm.as_str())
            .execute(&pool)
            .await
            .unwrap();

        let service = Service::new(store, source, clock.clone(), Arc::new(Limiter::default()));
        tokio::time::timeout(std::time::Duration::from_secs(6), async {
            while !clock.is_healthy() {
                // sleep: `ClockHealth` has no change notification; poll its 1 s sampler within the bound.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        RecoveryFixture {
            service,
            pool,
            host,
            predecessor: signed.record.fingerprint,
            identity_key,
            csr_der,
            now,
        }
    }

    /// A challenge signed by `key`; the registered predecessor key unless a test forges one.
    fn challenge_signed_by(
        fixture: &RecoveryFixture,
        key: &PKey<Private>,
        digest: [u8; 32],
    ) -> ChallengeInput {
        let request = request_id(fixture.host, &fixture.predecessor, &digest);
        let message = challenge_message(fixture.host, &fixture.predecessor, &request, &digest);
        let signature = sign_with(key, &message);
        ChallengeInput {
            host: fixture.host,
            predecessor: fixture.predecessor,
            request,
            digest,
            signature,
            now: fixture.now,
        }
    }

    /// A challenge request for `digest`, signed by the host's predecessor key.
    fn challenge_input(fixture: &RecoveryFixture, digest: [u8; 32]) -> ChallengeInput {
        challenge_signed_by(fixture, &fixture.identity_key, digest)
    }

    /// Expired hosts learn retirement only after proving the exact predecessor key.
    #[tokio::test]
    async fn expired_retirement_requires_the_predecessor_signature() {
        let fixture = recovery_fixture().await;
        let store = &fixture.service.store;
        store
            .revoke("owner", fixture.host, fixture.now)
            .await
            .unwrap();
        let digest = csr_digest(&fixture.csr_der);
        let wrong_key = PKey::generate_ed25519().unwrap();
        let refused = fixture
            .service
            .challenge_at(challenge_signed_by(&fixture, &wrong_key, digest))
            .await;
        assert!(refused.is_err());
        let retired = fixture
            .service
            .challenge_at(challenge_input(&fixture, digest))
            .await;
        assert!(matches!(retired, Ok(RecoveryResponse::Retired)));
    }

    /// The challenge, issuer fingerprint, generation and notAfter from a challenge response.
    fn challenge_receipt(response: &RecoveryResponse) -> ([u8; 32], [u8; 32], u64, i64) {
        match response {
            RecoveryResponse::Challenge {
                challenge,
                issuer_fingerprint,
                issuer_generation,
                not_after,
                ..
            } => (
                *challenge,
                *issuer_fingerprint,
                *issuer_generation,
                *not_after,
            ),
            RecoveryResponse::Denied | RecoveryResponse::Retired => {
                panic!("eligible identity did not receive a challenge")
            }
            RecoveryResponse::Certificate { .. } => {
                panic!("challenge request returned a certificate")
            }
        }
    }

    /// Run a challenge that must be accepted.
    async fn accepted_challenge(service: &Service, input: ChallengeInput) -> RecoveryResponse {
        match service.challenge_at(input).await {
            Ok(response) => response,
            Err(Denied) => panic!("eligible challenge request was denied"),
        }
    }

    /// The wire request for a challenge input.
    fn challenge_request(input: &ChallengeInput) -> RecoveryRequest {
        RecoveryRequest::Challenge {
            host_id: input.host,
            predecessor_fingerprint: input.predecessor,
            request_id: input.request,
            csr_digest: input.digest,
            request_signature: input.signature.clone(),
        }
    }

    /// How many unproved, unexpired operations the fixture host has.
    async fn pending_count(fixture: &RecoveryFixture) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM remote_certificate_recovery WHERE host_id=? AND certificate_der IS NULL AND expires_at>? ")
            .bind(fixture.host.as_bytes().as_slice())
            .bind(fixture.now)
            .fetch_one(&fixture.pool)
            .await
            .unwrap()
    }

    /// A second, different unproved challenge for the same predecessor leaves the first operation as it was.
    #[tokio::test]
    async fn a_different_unproved_challenge_preserves_the_original_operation() {
        let fixture = recovery_fixture().await;
        let original_digest = csr_digest(&fixture.csr_der);
        let original = challenge_input(&fixture, original_digest);
        let original_response = accepted_challenge(&fixture.service, original.clone()).await;
        let (original_nonce, _, _, _) = challenge_receipt(&original_response);

        let replacement = challenge_input(&fixture, [9; 32]);
        let replacement_response = accepted_challenge(&fixture.service, replacement).await;
        assert!(matches!(
            replacement_response,
            RecoveryResponse::Challenge { .. }
        ));
        assert_eq!(pending_count(&fixture).await, 2);

        let stored_nonce: Vec<u8> = sqlx::query_scalar(
            "SELECT challenge FROM remote_certificate_recovery WHERE host_id=? AND request_id=?",
        )
        .bind(fixture.host.as_bytes().as_slice())
        .bind(original.request.as_slice())
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert_eq!(stored_nonce.as_slice(), original_nonce.as_slice());
    }

    /// A challenge signed by any key but the predecessor's is denied and stores nothing.
    #[tokio::test]
    async fn a_challenge_not_signed_by_the_predecessor_key_records_nothing() {
        let fixture = recovery_fixture().await;
        let digest = csr_digest(&fixture.csr_der);
        let stranger = PKey::generate_ed25519().unwrap();
        let forged = challenge_signed_by(&fixture, &stranger, digest);
        assert!(fixture.service.challenge_at(forged).await.is_err());
        let mut truncated = challenge_input(&fixture, digest);
        truncated.signature.truncate(32);
        assert!(fixture.service.challenge_at(truncated).await.is_err());
        assert_eq!(pending_count(&fixture).await, 0);
    }

    /// Forged challenges spend neither the host's budget nor its pending slots, so the real host still recovers.
    #[tokio::test]
    async fn forged_challenges_cannot_lock_the_registered_host_out() {
        let fixture = recovery_fixture().await;
        let stranger = PKey::generate_ed25519().unwrap();
        // Every forged request arrives from its own address, so only per-host state
        // (rate budget and pending operations) could be exhausted by them.
        for index in 0..=u32::from(MAX_HOST_ATTEMPTS) {
            let digest = [u8::try_from(index + 1).unwrap(); 32];
            let forged = challenge_signed_by(&fixture, &stranger, digest);
            let source = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + index));
            fixture
                .service
                .process(source, challenge_request(&forged))
                .await;
        }
        let genuine = challenge_input(&fixture, csr_digest(&fixture.csr_der));
        let response = fixture
            .service
            .process(
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                challenge_request(&genuine),
            )
            .await;
        assert!(
            matches!(response, RecoveryResponse::Challenge { .. }),
            "forged challenges locked the registered host out of recovery"
        );
        assert_eq!(pending_count(&fixture).await, 1);
    }

    /// Pending challenges per host are capped, and a new one never evicts an existing one.
    #[tokio::test]
    async fn pending_challenges_are_bounded_per_host_without_evicting_existing_ones() {
        let fixture = recovery_fixture().await;
        for index in 0..TEST_PENDING_LIMIT {
            let digest = [u8::try_from(index + 1).unwrap(); 32];
            let result = fixture
                .service
                .challenge_at(challenge_input(&fixture, digest))
                .await;
            assert!(matches!(result, Ok(RecoveryResponse::Challenge { .. })));
        }

        let overflow = fixture
            .service
            .challenge_at(challenge_input(&fixture, [99; 32]))
            .await;
        assert!(
            overflow.is_err(),
            "the per-host pending limit must reject overflow"
        );
        assert_eq!(
            pending_count(&fixture).await,
            i64::try_from(TEST_PENDING_LIMIT).unwrap()
        );
    }

    /// A valid proof removes the predecessor's other pending challenges.
    #[tokio::test]
    async fn a_valid_proof_replaces_other_pending_challenges_for_its_predecessor() {
        let fixture = recovery_fixture().await;
        let digest = csr_digest(&fixture.csr_der);
        let input = challenge_input(&fixture, digest);
        let response = accepted_challenge(&fixture.service, input.clone()).await;
        let (challenge, issuer_fingerprint, issuer_generation, not_after) =
            challenge_receipt(&response);

        let sibling_digest = [77; 32];
        let sibling_request = request_id(fixture.host, &fixture.predecessor, &sibling_digest);
        let public_key = fixture.identity_key.raw_public_key().unwrap();
        let public_key_fingerprint = openssl::sha::sha256(&public_key);
        sqlx::query("INSERT INTO remote_certificate_recovery(host_id,predecessor_fingerprint,request_id,csr_digest,challenge,public_key_fingerprint,issuer_fingerprint,issuer_generation,predecessor_not_after,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(fixture.host.as_bytes().as_slice())
            .bind(fixture.predecessor.as_slice())
            .bind(sibling_request.as_slice())
            .bind(sibling_digest.as_slice())
            .bind([88; 32].as_slice())
            .bind(public_key_fingerprint.as_slice())
            .bind(issuer_fingerprint.as_slice())
            .bind(i64::try_from(issuer_generation).unwrap())
            .bind(not_after)
            .bind(fixture.now + CHALLENGE_LIFETIME)
            .execute(&fixture.pool)
            .await
            .unwrap();

        let proof_transcript = transcript(RecoveryTranscript {
            host_id: fixture.host,
            predecessor_fingerprint: &fixture.predecessor,
            request_id: &input.request,
            csr_digest: &digest,
            challenge: &challenge,
            public_key_fingerprint: &public_key_fingerprint,
            issuer_fingerprint: &issuer_fingerprint,
            issuer_generation,
            not_after,
        });
        let mut signer = Signer::new_without_digest(&fixture.identity_key).unwrap();
        let signature = signer.sign_oneshot_to_vec(&proof_transcript).unwrap();
        let proof = ProofRequest {
            host: fixture.host,
            predecessor: fixture.predecessor,
            request: input.request,
            challenge,
            csr_der: fixture.csr_der.clone(),
            signature,
        };
        let Ok((_, public_key)) = validate_proof_request(&proof) else {
            panic!("proof request should be valid");
        };
        let Ok(operation) = fixture.service.load_proof_operation(&proof).await else {
            panic!("proof challenge should still exist");
        };
        let Ok(verified) = fixture
            .service
            .verify_proof(&proof, &operation, &public_key, fixture.now)
            .await
        else {
            panic!("proof transcript should match its stored challenge");
        };
        let Ok(issuer) = active_issuer(fixture.service.source.as_ref()) else {
            panic!("the test CA should remain available");
        };
        assert_eq!(issuer.fingerprint, verified.issuer_fingerprint);
        assert_eq!(issuer.generation, verified.issuer_generation);
        let result = fixture.service.prove_at(proof, fixture.now).await;
        assert!(matches!(result, Ok(RecoveryResponse::Certificate { .. })));

        let sibling: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM remote_certificate_recovery WHERE host_id=? AND request_id=?",
        )
        .bind(fixture.host.as_bytes().as_slice())
        .bind(sibling_request.as_slice())
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert_eq!(
            sibling, 0,
            "a verified proof should retire sibling challenges"
        );
        assert_eq!(pending_count(&fixture).await, 0);
    }

    /// A pending removal may recover only to deliver cleanup; ordinary authority stays denied
    /// and the transport expires at exactly 300 seconds despite its new seven-day certificate.
    #[tokio::test]
    async fn recovered_pending_removal_has_only_cleanup_admission_for_three_hundred_seconds() {
        use crate::remote_guard::AuthorityGuard;
        let fixture = recovery_fixture().await;
        let person = Uuid::new_v4();
        sqlx::query("UPDATE users SET owner=0 WHERE id='owner'")
            .execute(&fixture.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES(?,'cleanup-owner',1,'test','cleanup-owner','Cleanup Owner')")
            .bind(person.to_string()).execute(&fixture.pool).await.unwrap();
        sqlx::query("UPDATE remote_hosts SET owner_id=? WHERE id=?")
            .bind(person.to_string())
            .bind(fixture.host.as_bytes().as_slice())
            .execute(&fixture.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO remote_host_removals(host_id,owner_id,requested_at,uninstall,host_cleanup) VALUES(?,?,?,1,'unreachable')")
            .bind(fixture.host.as_bytes().as_slice()).bind(person.to_string()).bind(fixture.now)
            .execute(&fixture.pool).await.unwrap();
        sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id,confirmed) VALUES(?,?,0)")
            .bind(fixture.host.as_bytes().as_slice())
            .bind(person.to_string())
            .execute(&fixture.pool)
            .await
            .unwrap();
        assert!(
            fixture
                .service
                .store
                .admit_cleanup(&fixture.predecessor, fixture.now)
                .await
                .is_err()
        );
        let digest = csr_digest(&fixture.csr_der);
        let input = challenge_input(&fixture, digest);
        let response = accepted_challenge(&fixture.service, input.clone()).await;
        let (challenge, issuer_fingerprint, issuer_generation, not_after) =
            challenge_receipt(&response);
        let public_key_fingerprint =
            openssl::sha::sha256(&fixture.identity_key.raw_public_key().unwrap());
        let proof_transcript = transcript(RecoveryTranscript {
            host_id: fixture.host,
            predecessor_fingerprint: &fixture.predecessor,
            request_id: &input.request,
            csr_digest: &digest,
            challenge: &challenge,
            public_key_fingerprint: &public_key_fingerprint,
            issuer_fingerprint: &issuer_fingerprint,
            issuer_generation,
            not_after,
        });
        let signature = Signer::new_without_digest(&fixture.identity_key)
            .unwrap()
            .sign_oneshot_to_vec(&proof_transcript)
            .unwrap();
        let response = fixture
            .service
            .prove_at(
                ProofRequest {
                    host: fixture.host,
                    predecessor: fixture.predecessor,
                    request: input.request,
                    challenge,
                    csr_der: fixture.csr_der.clone(),
                    signature,
                },
                fixture.now,
            )
            .await;
        let Ok(RecoveryResponse::Certificate {
            certificate_der, ..
        }) = response
        else {
            panic!("pending cleanup must still recover its expired identity");
        };
        let certificate = openssl::x509::X509::from_der(&certificate_der).unwrap();
        let fingerprint: [u8; 32] = certificate
            .digest(MessageDigest::sha256())
            .unwrap()
            .as_ref()
            .try_into()
            .unwrap();
        let (leaf_start, leaf_end): (i64, i64) = sqlx::query_as(
            "SELECT not_before,not_after FROM remote_certificates WHERE fingerprint=?",
        )
        .bind(fingerprint.as_slice())
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert_eq!(leaf_end - leaf_start, 604_800);
        let store = fixture.service.store.clone();
        assert!(store.admit(&fingerprint, leaf_start).await.is_err());
        assert!(
            AuthorityGuard::admit(store.clone(), fingerprint)
                .await
                .is_err()
        );
        let (cleanup, cleanup_person) =
            store.admit_cleanup(&fingerprint, leaf_start).await.unwrap();
        assert_eq!(cleanup.host, fixture.host);
        assert_eq!(cleanup_person, person);
        let issuer = active_issuer(fixture.service.source.as_ref())
            .unwrap_or_else(|_| panic!("test signer unlocked"));
        let renewal = issuer
            .authority
            .sign_host(
                fixture.host,
                &ValidatedCsr::parse(&fixture.csr_der).unwrap(),
                leaf_start + 1,
            )
            .unwrap();
        assert!(
            store
                .renew(&fingerprint, &renewal.record, leaf_start + 1)
                .await
                .is_err()
        );

        tokio::time::pause();
        let admitting = AuthorityGuard::admit_transport(store, fingerprint);
        tokio::pin!(admitting);
        // Keep the paused runtime runnable while SQLite responds: automatic timer
        // advancement must not consume any part of the admission's exact budget.
        let guard = loop {
            tokio::select! {
                biased;
                result = &mut admitting => break result.unwrap(),
                () = tokio::task::yield_now() => {},
            }
        };
        assert_eq!(guard.cleanup_person(), Some(person));
        assert!(guard.admit_operation().await.is_err());
        assert!(guard.permits());
        tokio::time::advance(Duration::from_secs(299)).await;
        assert!(
            guard.permits(),
            "cleanup must retain its full bounded delivery window"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            !guard.permits(),
            "seven-day recovery must not extend the cleanup cap"
        );
        assert!(guard.write_permit().await.is_err());
        guard.cancelled().await;
    }

    /// The recovery window uses server time and includes the exact 90-day boundary.
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

    /// The limiter counts attempts per key and resets after the monotonic window.
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

    /// #572 finding 5: addresses rotating inside one IPv6 /64 share one source
    /// budget, while another /64 keeps its own.
    #[test]
    fn source_budget_is_shared_by_one_ipv6_slash_64() {
        let limiter = Limiter::default();
        for host in 0..MAX_SOURCE_ATTEMPTS {
            let source = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, host));
            assert!(limiter.admit_source(source), "attempt {host} refused early");
        }
        let rotated = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 9, 9, 9, 9));
        assert!(
            !limiter.admit_source(rotated),
            "a new address in the same /64 got a fresh budget"
        );
        let neighbour = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1));
        assert!(limiter.admit_source(neighbour));
    }

    /// An untrusted server clock denies recovery before the CA material is consulted.
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
                    request_signature: vec![0; 64],
                },
            )
            .await;
        assert!(matches!(response, RecoveryResponse::Denied));
        assert_eq!(source.0.load(Ordering::Relaxed), 0);
    }

    /// Run a full recovery (challenge, then proof) for the fixture's own key,
    /// with `proof_signature` rewriting the proof's signature, and return the result.
    async fn recover(
        fixture: &RecoveryFixture,
        proof_signature: fn(Vec<u8>) -> Vec<u8>,
    ) -> Result<RecoveryResponse, Denied> {
        let digest = csr_digest(&fixture.csr_der);
        let input = challenge_input(fixture, digest);
        let response = accepted_challenge(&fixture.service, input.clone()).await;
        let (challenge, issuer_fingerprint, issuer_generation, not_after) =
            challenge_receipt(&response);
        let public_key_fingerprint = key_fingerprint(&fixture.identity_key);
        let proof_transcript = transcript(RecoveryTranscript {
            host_id: fixture.host,
            predecessor_fingerprint: &fixture.predecessor,
            request_id: &input.request,
            csr_digest: &digest,
            challenge: &challenge,
            public_key_fingerprint: &public_key_fingerprint,
            issuer_fingerprint: &issuer_fingerprint,
            issuer_generation,
            not_after,
        });
        let signature = proof_signature(sign_with(&fixture.identity_key, &proof_transcript));
        fixture
            .service
            .prove_at(
                ProofRequest {
                    host: fixture.host,
                    predecessor: fixture.predecessor,
                    request: input.request,
                    challenge,
                    csr_der: fixture.csr_der.clone(),
                    signature,
                },
                fixture.now,
            )
            .await
    }

    /// #580 P4: an expired P-256 device identity recovers with its own key,
    /// proved by DER ECDSA signatures, and the new leaf keeps the key as `p256`.
    #[tokio::test]
    async fn an_expired_p256_identity_recovers_with_its_own_key() {
        let fixture = recovery_fixture_with(p256_key()).await;
        let Ok(RecoveryResponse::Certificate { certificate_der }) =
            recover(&fixture, |signature| signature).await
        else {
            panic!("a P-256 identity did not recover");
        };
        let leaf = openssl::x509::X509::from_der(&certificate_der).unwrap();
        assert!(leaf.public_key().unwrap().public_eq(&fixture.identity_key));
        let fingerprint = leaf.digest(MessageDigest::sha256()).unwrap();
        let stored: (String, Vec<u8>) = sqlx::query_as(
            "SELECT key_algorithm, public_key FROM remote_certificates WHERE fingerprint=?",
        )
        .bind(fingerprint.as_ref())
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert_eq!(stored.0, "p256");
        assert_eq!(stored.1.len(), 65);
    }

    /// A P-256 identity's challenge and proof are refused in any other shape:
    /// an Ed25519 signature, a raw `r || s` signature, or one over 72 bytes.
    #[tokio::test]
    async fn p256_recovery_refuses_foreign_and_noncanonical_signatures() {
        let fixture = recovery_fixture_with(p256_key()).await;
        let digest = csr_digest(&fixture.csr_der);
        let stranger = PKey::generate_ed25519().unwrap();
        assert!(
            fixture
                .service
                .challenge_at(challenge_signed_by(&fixture, &stranger, digest))
                .await
                .is_err(),
            "an Ed25519 signature authenticated a P-256 identity"
        );
        let mut raw = challenge_input(&fixture, digest);
        let parsed = openssl::ecdsa::EcdsaSig::from_der(&raw.signature).unwrap();
        raw.signature = [
            parsed.r().to_vec_padded(32).unwrap(),
            parsed.s().to_vec_padded(32).unwrap(),
        ]
        .concat();
        assert!(fixture.service.challenge_at(raw).await.is_err());
        let mut long = challenge_input(&fixture, digest);
        long.signature.resize(73, 0);
        assert!(fixture.service.challenge_at(long).await.is_err());
        assert_eq!(pending_count(&fixture).await, 0);
        let raw_proof = recover(&fixture, |signature| {
            let parsed = openssl::ecdsa::EcdsaSig::from_der(&signature).unwrap();
            [
                parsed.r().to_vec_padded(32).unwrap(),
                parsed.s().to_vec_padded(32).unwrap(),
            ]
            .concat()
        })
        .await;
        assert!(raw_proof.is_err(), "a raw r||s proof signature recovered");
    }

    /// A proof can only continue the predecessor's own algorithm: a P-256 CSR
    /// cannot recover an Ed25519 identity, even signed by a key the host holds.
    #[tokio::test]
    async fn a_p256_csr_cannot_recover_an_ed25519_identity() {
        let mut fixture = recovery_fixture().await;
        let device_key = p256_key();
        let mut request = X509Req::builder().unwrap();
        request
            .set_subject_name(&X509NameBuilder::new().unwrap().build())
            .unwrap();
        request.set_pubkey(&device_key).unwrap();
        request.sign(&device_key, MessageDigest::sha256()).unwrap();
        fixture.csr_der = request.build().to_der().unwrap();
        // The challenge is signed by the real Ed25519 predecessor; only the proof's key differs.
        let digest = csr_digest(&fixture.csr_der);
        let input = challenge_input(&fixture, digest);
        let response = accepted_challenge(&fixture.service, input.clone()).await;
        let (challenge, issuer_fingerprint, issuer_generation, not_after) =
            challenge_receipt(&response);
        let public_key_fingerprint = key_fingerprint(&device_key);
        let proof_transcript = transcript(RecoveryTranscript {
            host_id: fixture.host,
            predecessor_fingerprint: &fixture.predecessor,
            request_id: &input.request,
            csr_digest: &digest,
            challenge: &challenge,
            public_key_fingerprint: &public_key_fingerprint,
            issuer_fingerprint: &issuer_fingerprint,
            issuer_generation,
            not_after,
        });
        let response = fixture
            .service
            .prove_at(
                ProofRequest {
                    host: fixture.host,
                    predecessor: fixture.predecessor,
                    request: input.request,
                    challenge,
                    csr_der: fixture.csr_der.clone(),
                    signature: sign_with(&device_key, &proof_transcript),
                },
                fixture.now,
            )
            .await;
        assert!(response.is_err());
        let issued: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_certificates")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
        assert_eq!(issued, 1, "no certificate was issued");
    }
}
