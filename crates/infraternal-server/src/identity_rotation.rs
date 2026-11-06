//! Persists server-challenged host key transitions and retires predecessors only after candidate mTLS admission [285].

use crate::{
    ca::{CaKeySource, CertificateAuthority},
    csr::ValidatedCsr,
    enrollment::EnrollmentStore,
};
use infraternal_plugin_remote::identity_rotation::{
    Acknowledgment, CandidateCertificate, Challenge, Proof,
};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey},
    rand::rand_bytes,
    sign::Verifier,
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{io, sync::Arc, time::Duration};
use uuid::Uuid;

/// A host rotates its identity key once this long after its last completed rotation (7 days).
const ROTATION_PERIOD_SECS: i64 = 604_800;
/// An issued candidate certificate is sent again at most once an hour while the predecessor keeps reconnecting.
const CANDIDATE_REDELIVERY_SECS: i64 = 3_600;
/// Upper bound on a stored or delivered candidate certificate, well above a real Ed25519 leaf.
const MAX_CANDIDATE_CERTIFICATE_DER: usize = 8192;
/// Caps concurrent candidate verification and signing. A proof over the cap is refused, not queued.
static SIGNING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

/// A single server-authenticated action for the enrolled host.
pub(crate) enum Action {
    /// Persisted challenge; the old host key signs candidate CSR possession.
    Challenge(Challenge),
    /// Previously committed candidate certificate; safe to redeliver on retry.
    Certificate(CandidateCertificate),
    /// Candidate mTLS has been admitted and predecessor certificates are revoked.
    Acknowledgment(Acknowledgment),
}

/// Rotation transaction adapter over the existing host certificate ledger.
#[derive(Clone)]
pub(crate) struct Service {
    store: EnrollmentStore,
    source: Arc<dyn CaKeySource>,
}

/// One host's persisted rotation row: the phase, the challenge it answers and the candidate it produced.
#[derive(Clone)]
struct Operation {
    host: Uuid,
    sequence: i64,
    last_completed_at: i64,
    phase: String,
    id: Option<Vec<u8>>,
    challenge: Option<Vec<u8>>,
    predecessor_fingerprint: Option<Vec<u8>>,
    predecessor_public_key: Option<Vec<u8>>,
    issuer_fingerprint: Option<Vec<u8>>,
    issuer_generation: Option<i64>,
    csr_digest: Option<Vec<u8>>,
    candidate_public_key: Option<Vec<u8>>,
    candidate_fingerprint: Option<Vec<u8>>,
    candidate_certificate: Option<Vec<u8>>,
    candidate_attempted_at: Option<i64>,
}

/// Candidate proof material kept outside the database transaction while CPU-bound signing runs.
struct CandidateProof {
    source: Arc<dyn CaKeySource>,
    csr_der: Vec<u8>,
    old_signature: Vec<u8>,
    challenge: Challenge,
    predecessor: [u8; 32],
    host: Uuid,
    now: i64,
}

/// The verified key and certificate returned by the bounded signing worker.
struct VerifiedCandidate {
    public_key: [u8; 32],
    signed: crate::ca::SignedCertificate,
}

/// All values that bind an issued certificate to one durable rotation transition.
struct IssuedCertificate<'a> {
    host: Uuid,
    current_fingerprint: &'a [u8; 32],
    predecessor: &'a [u8; 32],
    challenge: &'a Challenge,
    csr_digest: [u8; 32],
    public_key: [u8; 32],
    der: &'a [u8],
    record: &'a crate::enrollment::CertificateRecord,
    now: i64,
}

impl Service {
    /// Bind to existing durable enrollment authority and the current CA source.
    pub(crate) fn new(store: EnrollmentStore, source: Arc<dyn CaKeySource>) -> Self {
        Self { store, source }
    }

    /// Read database time and either resume the one pending operation or start a due one.
    /// # Errors
    /// Refuses missing/revoked hosts, malformed persisted state or unavailable storage.
    pub(crate) async fn next_action(
        &self,
        host: Uuid,
        current_fingerprint: [u8; 32],
    ) -> io::Result<Option<Action>> {
        let now = self.database_now().await?;
        let operation = self.load_or_seed(host).await?;
        let current_key = self.current_key(host, &current_fingerprint, now).await?;
        match operation.phase.as_str() {
            "complete" => {
                let due = operation
                    .last_completed_at
                    .checked_add(ROTATION_PERIOD_SECS)
                    .is_some_and(|at| now >= at);
                if !due {
                    return Ok(None);
                }
                let Some(challenge) = self
                    .start(host, &current_fingerprint, &current_key, now, &operation)
                    .await?
                else {
                    return Ok(None);
                };
                Ok(Some(Action::Challenge(challenge)))
            }
            "challenged" => {
                if operation.predecessor_public_key.as_deref() != Some(current_key.as_slice())
                    || self.source.load().is_err()
                {
                    return Ok(None);
                }
                Ok(Some(Action::Challenge(operation.challenge()?)))
            }
            "issued" => {
                if operation.candidate_public_key.as_deref() == Some(current_key.as_slice()) {
                    let acknowledgment = self
                        .commit_candidate(host, &current_fingerprint, &current_key, now, &operation)
                        .await?;
                    return Ok(Some(Action::Acknowledgment(acknowledgment)));
                }
                if operation.predecessor_public_key.as_deref() != Some(current_key.as_slice()) {
                    return Ok(None);
                }
                let candidate_not_after = self
                    .candidate_not_after(host, operation.candidate_fingerprint.as_deref())
                    .await?;
                if candidate_not_after.is_some_and(|not_after| not_after <= now) {
                    if self.source.load().is_err() {
                        return Ok(None);
                    }
                    Ok(Some(Action::Challenge(operation.challenge()?)))
                } else {
                    let retry_after = operation
                        .candidate_attempted_at
                        .map(|attempted_at| {
                            attempted_at
                                .checked_add(CANDIDATE_REDELIVERY_SECS)
                                .ok_or_else(denied)
                        })
                        .transpose()?
                        .unwrap_or(0);
                    if retry_after > now || !self.mark_candidate_attempt(&operation, now).await? {
                        return Ok(None);
                    }
                    Ok(Some(Action::Certificate(
                        operation.candidate_certificate()?,
                    )))
                }
            }
            "committed" => {
                if operation.candidate_public_key.as_deref() != Some(current_key.as_slice()) {
                    return Ok(None);
                }
                Ok(Some(Action::Acknowledgment(operation.acknowledgment()?)))
            }
            _ => Err(denied()),
        }
    }

    /// Delay until the persisted schedule is due; an active operation is actionable now.
    /// # Errors
    /// Refuses missing/revoked hosts, malformed persisted state or unavailable storage.
    pub(crate) async fn next_delay(&self, host: Uuid) -> io::Result<Duration> {
        let now = self.database_now().await?;
        let operation = self.load_or_seed(host).await?;
        if operation.phase != "complete" {
            return Ok(Duration::ZERO);
        }
        let due = operation
            .last_completed_at
            .checked_add(ROTATION_PERIOD_SECS)
            .ok_or_else(denied)?;
        Ok(Duration::from_secs(
            u64::try_from(due.saturating_sub(now)).map_err(|_| denied())?,
        ))
    }

    /// Claim a due redelivery before sending the same certificate again.
    /// A predecessor that reconnects remains available while candidate admission is retried.
    async fn mark_candidate_attempt(&self, operation: &Operation, now: i64) -> io::Result<bool> {
        let retry_before = now
            .checked_sub(CANDIDATE_REDELIVERY_SECS)
            .ok_or_else(denied)?;
        let changed = sqlx::query(
            "UPDATE remote_identity_rotation SET candidate_attempted_at=? \
             WHERE host_id=? AND phase='issued' AND operation_id=? AND sequence=? \
             AND (candidate_attempted_at IS NULL OR candidate_attempted_at<=?)",
        )
        .bind(now)
        .bind(operation.host.as_bytes().as_slice())
        .bind(operation.id.as_deref().ok_or_else(denied)?)
        .bind(operation.sequence)
        .bind(retry_before)
        .execute(&self.store.0)
        .await
        .map_err(|_| denied())?
        .rows_affected();
        Ok(changed == 1)
    }

    /// Verify old-key authorization and candidate CSR possession before recording issuance.
    /// The same operation and CSR digest return the exact saved certificate on retry.
    /// # Errors
    /// Refuses stale/replayed challenges, altered proofs, locked CA or changed host authority.
    pub(crate) async fn accept_proof(
        &self,
        host: Uuid,
        current_fingerprint: [u8; 32],
        proof: Proof,
    ) -> io::Result<Vec<u8>> {
        if proof.csr_der.is_empty() || proof.csr_der.len() > 4096 || proof.old_signature.len() != 64
        {
            return Err(denied());
        }
        let _permit = SIGNING.try_acquire().map_err(|_| denied())?;
        let now = self.database_now().await?;
        let operation = self.read_operation(host).await?.ok_or_else(denied)?;
        let challenge = operation.challenge()?;
        if proof.operation_id != challenge.operation_id || proof.sequence != challenge.sequence {
            return Err(denied());
        }
        let predecessor = operation
            .predecessor_public_key
            .as_deref()
            .ok_or_else(denied)?;
        let predecessor: [u8; 32] = predecessor.try_into().map_err(|_| denied())?;
        if self.current_key(host, &current_fingerprint, now).await? != predecessor {
            return Err(denied());
        }
        let digest: [u8; 32] = Sha256::digest(&proof.csr_der).into();
        if operation.phase == "issued" {
            if operation.csr_digest.as_deref() != Some(digest.as_slice()) {
                return Err(denied());
            }
            let not_after = self
                .candidate_not_after(host, operation.candidate_fingerprint.as_deref())
                .await?;
            if not_after.is_some_and(|not_after| not_after > now) {
                return Ok(operation.candidate_certificate()?.certificate_der);
            }
        } else if operation.phase != "challenged" {
            return Err(denied());
        }
        let candidate_proof = CandidateProof {
            source: self.source.clone(),
            csr_der: proof.csr_der,
            old_signature: proof.old_signature,
            challenge: challenge.clone(),
            predecessor,
            host,
            now,
        };
        let signed =
            tokio::task::spawn_blocking(move || verify_and_sign_candidate(&candidate_proof))
                .await
                .map_err(|_| denied())??;
        let candidate_public_key = signed.public_key;
        let signed = signed.signed;
        if signed.record.issuer_fingerprint != challenge.issuer_fingerprint
            || signed.record.public_key != candidate_public_key
            || signed.der.len() > MAX_CANDIDATE_CERTIFICATE_DER
        {
            return Err(denied());
        }
        self.persist_issued(IssuedCertificate {
            host,
            current_fingerprint: &current_fingerprint,
            predecessor: &predecessor,
            challenge: &challenge,
            csr_digest: digest,
            public_key: candidate_public_key,
            der: &signed.der,
            record: &signed.record,
            now,
        })
        .await
    }

    /// Mark host-side durable promotion only after the authenticated Ack action returns.
    /// # Errors
    /// Refuses mismatched operation, candidate identity or a revoked host.
    pub(crate) async fn acknowledge(
        &self,
        host: Uuid,
        current_fingerprint: [u8; 32],
        acknowledgment: Acknowledgment,
    ) -> io::Result<()> {
        let now = self.database_now().await?;
        let mut tx = self.store.0.begin().await.map_err(|_| denied())?;
        let row = sqlx::query(
            "UPDATE remote_identity_rotation SET phase='complete',last_completed_at=? \
             WHERE host_id=? AND phase='committed' AND operation_id=? AND sequence=? \
             AND EXISTS(SELECT 1 FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id \
               WHERE c.fingerprint=? AND c.host_id=remote_identity_rotation.host_id \
               AND c.public_key=remote_identity_rotation.candidate_public_key AND c.not_before<=? \
               AND c.not_after>? AND c.revoked_at IS NULL AND h.revoked_at IS NULL)",
        )
        .bind(now)
        .bind(host.as_bytes().as_slice())
        .bind(acknowledgment.operation_id.as_bytes().as_slice())
        .bind(i64::try_from(acknowledgment.sequence).map_err(|_| denied())?)
        .bind(current_fingerprint.as_slice())
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| denied())?
        .rows_affected();
        if row != 1 {
            let completed: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_identity_rotation r \
                 JOIN remote_certificates c ON c.host_id=r.host_id \
                 WHERE r.host_id=? AND r.phase='complete' AND r.operation_id=? AND r.sequence=? \
                 AND c.fingerprint=? AND c.public_key=r.candidate_public_key \
                 AND c.not_before<=? AND c.not_after>? AND c.revoked_at IS NULL)",
            )
            .bind(host.as_bytes().as_slice())
            .bind(acknowledgment.operation_id.as_bytes().as_slice())
            .bind(i64::try_from(acknowledgment.sequence).map_err(|_| denied())?)
            .bind(current_fingerprint.as_slice())
            .bind(now)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| denied())?;
            if !completed {
                return Err(denied());
            }
        }
        tx.commit().await.map_err(|_| denied())?;
        Ok(())
    }

    /// Persist a fresh challenge for a due host, bound to the current key, issuer and next sequence.
    /// Returns `None` while the CA is locked, because no candidate could be signed.
    async fn start(
        &self,
        host: Uuid,
        current_fingerprint: &[u8; 32],
        current_key: &[u8; 32],
        now: i64,
        operation: &Operation,
    ) -> io::Result<Option<Challenge>> {
        let Ok(material) = self.source.load() else {
            return Ok(None);
        };
        let issuer_fingerprint: [u8; 32] = material
            .issuer()
            .digest(MessageDigest::sha256())
            .map_err(|_| denied())?
            .as_ref()
            .try_into()
            .map_err(|_| denied())?;
        drop(material);
        let issuer_generation = self.source.issuer_generation();
        let sequence = operation.sequence.checked_add(1).ok_or_else(denied)?;
        let sequence_u64 = u64::try_from(sequence).map_err(|_| denied())?;
        let mut nonce = [0_u8; 32];
        rand_bytes(&mut nonce).map_err(|_| denied())?;
        let operation_id = Uuid::new_v4();
        let challenge = Challenge {
            host_id: host,
            operation_id,
            sequence: sequence_u64,
            challenge: nonce,
            predecessor_fingerprint: *current_fingerprint,
            issuer_fingerprint,
            issuer_generation,
        };
        let mut tx = self.store.0.begin().await.map_err(|_| denied())?;
        let changed = sqlx::query(
            "UPDATE remote_identity_rotation SET sequence=?,phase='challenged',operation_id=?, \
             challenge=?,predecessor_fingerprint=?,predecessor_public_key=?,issuer_fingerprint=?, \
             issuer_generation=?,started_at=?,csr_digest=NULL,candidate_public_key=NULL, \
             candidate_fingerprint=NULL,candidate_certificate=NULL,candidate_attempted_at=NULL \
             WHERE host_id=? AND phase='complete' AND sequence=? AND last_completed_at<=? \
             AND EXISTS(SELECT 1 FROM remote_hosts h WHERE h.id=remote_identity_rotation.host_id AND h.revoked_at IS NULL) \
             AND EXISTS(SELECT 1 FROM remote_certificates c WHERE c.fingerprint=? AND c.host_id=remote_identity_rotation.host_id \
               AND c.public_key=? AND c.not_before<=? AND c.not_after>? AND c.revoked_at IS NULL)",
        )
        .bind(sequence)
        .bind(operation_id.as_bytes().as_slice())
        .bind(nonce.as_slice())
        .bind(current_fingerprint.as_slice())
        .bind(current_key.as_slice())
        .bind(issuer_fingerprint.as_slice())
        .bind(i64::try_from(issuer_generation).map_err(|_| denied())?)
        .bind(now)
        .bind(host.as_bytes().as_slice())
        .bind(operation.sequence)
        .bind(now.checked_sub(ROTATION_PERIOD_SECS).ok_or_else(denied)?)
        .bind(current_fingerprint.as_slice())
        .bind(current_key.as_slice())
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| denied())?
        .rows_affected();
        if changed != 1 {
            tx.rollback().await.map_err(|_| denied())?;
            return Ok(None);
        }
        tx.commit().await.map_err(|_| denied())?;
        Ok(Some(challenge))
    }

    /// These writes form one idempotent authority transition and must commit together.
    async fn persist_issued(&self, issued: IssuedCertificate<'_>) -> io::Result<Vec<u8>> {
        let IssuedCertificate {
            host,
            current_fingerprint,
            predecessor,
            challenge,
            csr_digest,
            public_key: candidate,
            der,
            record,
            now,
        } = issued;
        let mut tx = self.store.0.begin().await.map_err(|_| denied())?;
        let operation = self
            .read_operation_in(&mut tx, host)
            .await?
            .ok_or_else(denied)?;
        if operation.challenge()? != *challenge
            || (operation.phase == "issued"
                && operation.csr_digest.as_deref() != Some(csr_digest.as_slice()))
            || !matches!(operation.phase.as_str(), "challenged" | "issued")
        {
            return Err(denied());
        }
        let current_matches: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.public_key=? AND c.not_before<=? AND c.not_after>? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL)",
        )
        .bind(current_fingerprint.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(predecessor.as_slice())
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| denied())?;
        if !current_matches {
            return Err(denied());
        }
        if operation.phase == "issued" {
            let stored_candidate = operation
                .candidate_public_key
                .as_deref()
                .ok_or_else(denied)?;
            if stored_candidate != candidate {
                return Err(denied());
            }
            let fingerprint = operation
                .candidate_fingerprint
                .as_deref()
                .ok_or_else(denied)?;
            let stored_certificate = operation
                .candidate_certificate
                .as_ref()
                .ok_or_else(denied)?
                .clone();
            let still_valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id \
                 WHERE c.host_id=? AND c.fingerprint=? AND c.public_key=? AND c.not_before<=? AND c.not_after>? \
                 AND c.revoked_at IS NULL AND h.revoked_at IS NULL)",
            )
            .bind(host.as_bytes().as_slice())
            .bind(fingerprint)
            .bind(candidate.as_slice())
            .bind(now)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| denied())?;
            if still_valid {
                tx.rollback().await.map_err(|_| denied())?;
                return Ok(stored_certificate);
            }
        }
        sqlx::query(
            "UPDATE remote_certificates SET revoked_at=COALESCE(revoked_at,?) \
             WHERE host_id=? AND public_key=? AND fingerprint<>? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(host.as_bytes().as_slice())
        .bind(candidate.as_slice())
        .bind(record.fingerprint.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| denied())?;
        sqlx::query(
            "INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after) \
             SELECT ?,h.id,?,?,?,? FROM remote_hosts h WHERE h.id=? AND h.revoked_at IS NULL \
             ON CONFLICT(fingerprint) DO NOTHING",
        )
        .bind(record.fingerprint.as_slice())
        .bind(record.issuer_fingerprint.as_slice())
        .bind(record.public_key.as_slice())
        .bind(record.not_before)
        .bind(record.not_after)
        .bind(host.as_bytes().as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| denied())?;
        let updated = sqlx::query(
            "UPDATE remote_identity_rotation SET phase='issued',csr_digest=?,candidate_public_key=?, \
             candidate_fingerprint=?,candidate_certificate=?,candidate_attempted_at=? \
             WHERE host_id=? AND operation_id=? \
             AND sequence=? AND phase IN ('challenged','issued') \
             AND EXISTS(SELECT 1 FROM remote_hosts h WHERE h.id=remote_identity_rotation.host_id AND h.revoked_at IS NULL)",
        )
        .bind(csr_digest.as_slice())
        .bind(candidate.as_slice())
        .bind(record.fingerprint.as_slice())
        .bind(der)
        .bind(now)
        .bind(host.as_bytes().as_slice())
        .bind(challenge.operation_id.as_bytes().as_slice())
        .bind(i64::try_from(challenge.sequence).map_err(|_| denied())?)
        .execute(&mut *tx)
        .await
        .map_err(|_| denied())?
        .rows_affected();
        if updated != 1 {
            return Err(denied());
        }
        tx.commit().await.map_err(|_| denied())?;
        Ok(der.to_vec())
    }

    /// Record that the candidate was admitted over mTLS: revoke the predecessor key's certificates and mark the
    /// operation committed, so the next connection receives the acknowledgment.
    async fn commit_candidate(
        &self,
        host: Uuid,
        current_fingerprint: &[u8; 32],
        candidate: &[u8; 32],
        now: i64,
        operation: &Operation,
    ) -> io::Result<Acknowledgment> {
        let mut tx = self.store.0.begin().await.map_err(|_| denied())?;
        let predecessor = operation
            .predecessor_public_key
            .as_deref()
            .ok_or_else(denied)?;
        let candidate_admitted: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.public_key=? AND c.not_before<=? AND c.not_after>? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL)",
        )
        .bind(current_fingerprint.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(candidate.as_slice())
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| denied())?;
        if !candidate_admitted {
            return Err(denied());
        }
        sqlx::query(
            "UPDATE remote_certificates SET revoked_at=COALESCE(revoked_at,?) \
             WHERE host_id=? AND public_key=? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(host.as_bytes().as_slice())
        .bind(predecessor)
        .execute(&mut *tx)
        .await
        .map_err(|_| denied())?;
        let changed = sqlx::query(
            "UPDATE remote_identity_rotation SET phase='committed' WHERE host_id=? AND phase='issued' \
             AND operation_id=? AND sequence=? AND candidate_public_key=? \
             AND EXISTS(SELECT 1 FROM remote_hosts h WHERE h.id=remote_identity_rotation.host_id AND h.revoked_at IS NULL)",
        )
        .bind(host.as_bytes().as_slice())
        .bind(operation.id.as_deref().ok_or_else(denied)?)
        .bind(operation.sequence)
        .bind(candidate.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| denied())?
        .rows_affected();
        if changed != 1 && operation.phase != "committed" {
            return Err(denied());
        }
        tx.commit().await.map_err(|_| denied())?;
        operation.acknowledgment()
    }

    /// The public key of the host's live, unrevoked certificate with this fingerprint.
    async fn current_key(
        &self,
        host: Uuid,
        fingerprint: &[u8; 32],
        now: i64,
    ) -> io::Result<[u8; 32]> {
        let public: Vec<u8> = sqlx::query_scalar(
            "SELECT c.public_key FROM remote_certificates c JOIN remote_hosts h ON h.id=c.host_id \
             WHERE c.fingerprint=? AND c.host_id=? AND c.not_before<=? AND c.not_after>? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL",
        )
        .bind(fingerprint.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(now)
        .bind(now)
        .fetch_optional(&self.store.0)
        .await
        .map_err(|_| denied())?
        .ok_or_else(denied)?;
        public.try_into().map_err(|_| denied())
    }

    /// When the issued candidate certificate expires, if one was issued.
    async fn candidate_not_after(
        &self,
        host: Uuid,
        fingerprint: Option<&[u8]>,
    ) -> io::Result<Option<i64>> {
        let Some(fingerprint) = fingerprint else {
            return Ok(None);
        };
        sqlx::query_scalar(
            "SELECT not_after FROM remote_certificates WHERE host_id=? AND fingerprint=?",
        )
        .bind(host.as_bytes().as_slice())
        .bind(fingerprint)
        .fetch_optional(&self.store.0)
        .await
        .map_err(|_| denied())
    }

    /// The database clock, the one clock every rotation decision uses.
    async fn database_now(&self) -> io::Result<i64> {
        sqlx::query_scalar("SELECT unixepoch()")
            .fetch_one(&self.store.0)
            .await
            .map_err(|_| denied())
    }

    /// Read the host's rotation row, first creating it as completed at enrollment for an unrevoked host.
    /// A row whose completion lies in the future is refused rather than trusted.
    async fn load_or_seed(&self, host: Uuid) -> io::Result<Operation> {
        let now: i64 = self.database_now().await?;
        sqlx::query(
            "INSERT OR IGNORE INTO remote_identity_rotation(host_id,last_completed_at,phase) \
             SELECT id,created_at,'complete' FROM remote_hosts WHERE id=? AND revoked_at IS NULL",
        )
        .bind(host.as_bytes().as_slice())
        .execute(&self.store.0)
        .await
        .map_err(|_| denied())?;
        self.read_operation(host)
            .await?
            .filter(|operation| operation.last_completed_at <= now)
            .ok_or_else(denied)
    }

    /// Read the host's rotation row outside a transaction.
    async fn read_operation(&self, host: Uuid) -> io::Result<Option<Operation>> {
        let row = sqlx::query(
            "SELECT sequence,last_completed_at,phase,operation_id,challenge,predecessor_fingerprint, \
             predecessor_public_key,issuer_fingerprint,issuer_generation,csr_digest,candidate_public_key, \
             candidate_fingerprint,candidate_certificate,candidate_attempted_at \
             FROM remote_identity_rotation WHERE host_id=?",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_optional(&self.store.0)
        .await
        .map_err(|_| denied())?;
        row.map(|row| operation_from_row(&row, host)).transpose()
    }

    /// Read the host's rotation row inside `tx`, so the caller decides on the state it then writes.
    async fn read_operation_in(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        host: Uuid,
    ) -> io::Result<Option<Operation>> {
        let row = sqlx::query(
            "SELECT sequence,last_completed_at,phase,operation_id,challenge,predecessor_fingerprint, \
             predecessor_public_key,issuer_fingerprint,issuer_generation,csr_digest,candidate_public_key, \
             candidate_fingerprint,candidate_certificate,candidate_attempted_at \
             FROM remote_identity_rotation WHERE host_id=?",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| denied())?;
        row.map(|row| operation_from_row(&row, host)).transpose()
    }
}

/// Check that the CSR's key is new and that the predecessor key signed the challenge and CSR, then sign the leaf.
/// Runs on the bounded blocking worker because both steps are CPU-bound.
fn verify_and_sign_candidate(proof: &CandidateProof) -> io::Result<VerifiedCandidate> {
    let csr = ValidatedCsr::parse(&proof.csr_der).map_err(|_| denied())?;
    let public_key: [u8; 32] = csr
        .key()
        .raw_public_key()
        .map_err(|_| denied())?
        .try_into()
        .map_err(|_| denied())?;
    if public_key == proof.predecessor {
        return Err(denied());
    }
    let predecessor =
        PKey::public_key_from_raw_bytes(&proof.predecessor, Id::ED25519).map_err(|_| denied())?;
    let transcript =
        infraternal_plugin_remote::identity_rotation::transcript(&proof.challenge, &proof.csr_der)?;
    let mut verifier = Verifier::new_without_digest(&predecessor).map_err(|_| denied())?;
    if !verifier
        .verify_oneshot(&proof.old_signature, &transcript)
        .map_err(|_| denied())?
    {
        return Err(denied());
    }
    let material = proof.source.load().map_err(|_| denied())?;
    let issuer_fingerprint: [u8; 32] = material
        .issuer()
        .digest(MessageDigest::sha256())
        .map_err(|_| denied())?
        .as_ref()
        .try_into()
        .map_err(|_| denied())?;
    if issuer_fingerprint != proof.challenge.issuer_fingerprint
        || proof.source.issuer_generation() != proof.challenge.issuer_generation
    {
        return Err(denied());
    }
    drop(material);
    let signed = CertificateAuthority::from_source(proof.source.as_ref())
        .map_err(|_| denied())?
        .sign_host(proof.host, &csr, proof.now)
        .map_err(|_| denied())?;
    Ok(VerifiedCandidate { public_key, signed })
}

impl Operation {
    /// Rebuild the persisted challenge exactly as it was first sent.
    fn challenge(&self) -> io::Result<Challenge> {
        let operation_id =
            Uuid::from_slice(self.id.as_deref().ok_or_else(denied)?).map_err(|_| denied())?;
        let challenge: [u8; 32] = self
            .challenge
            .as_deref()
            .ok_or_else(denied)?
            .try_into()
            .map_err(|_| denied())?;
        Ok(Challenge {
            host_id: self.host,
            operation_id,
            sequence: u64::try_from(self.sequence).map_err(|_| denied())?,
            challenge,
            predecessor_fingerprint: self
                .predecessor_fingerprint
                .as_deref()
                .ok_or_else(denied)?
                .try_into()
                .map_err(|_| denied())?,
            issuer_fingerprint: self
                .issuer_fingerprint
                .as_deref()
                .ok_or_else(denied)?
                .try_into()
                .map_err(|_| denied())?,
            issuer_generation: u64::try_from(self.issuer_generation.ok_or_else(denied)?)
                .map_err(|_| denied())?,
        })
    }

    /// The candidate certificate stored for this operation, for redelivery.
    fn candidate_certificate(&self) -> io::Result<CandidateCertificate> {
        Ok(CandidateCertificate {
            operation_id: Uuid::from_slice(self.id.as_deref().ok_or_else(denied)?)
                .map_err(|_| denied())?,
            sequence: u64::try_from(self.sequence).map_err(|_| denied())?,
            certificate_der: self
                .candidate_certificate
                .clone()
                .filter(|der| !der.is_empty() && der.len() <= MAX_CANDIDATE_CERTIFICATE_DER)
                .ok_or_else(denied)?,
        })
    }

    /// The acknowledgment that tells the host its candidate is now its identity.
    fn acknowledgment(&self) -> io::Result<Acknowledgment> {
        Ok(Acknowledgment {
            operation_id: Uuid::from_slice(self.id.as_deref().ok_or_else(denied)?)
                .map_err(|_| denied())?,
            sequence: u64::try_from(self.sequence).map_err(|_| denied())?,
        })
    }
}

/// Decode one `remote_identity_rotation` row.
fn operation_from_row(row: &sqlx::sqlite::SqliteRow, host: Uuid) -> io::Result<Operation> {
    Ok(Operation {
        host,
        sequence: row.try_get("sequence").map_err(|_| denied())?,
        last_completed_at: row.try_get("last_completed_at").map_err(|_| denied())?,
        phase: row.try_get("phase").map_err(|_| denied())?,
        id: row.try_get("operation_id").map_err(|_| denied())?,
        challenge: row.try_get("challenge").map_err(|_| denied())?,
        predecessor_fingerprint: row
            .try_get("predecessor_fingerprint")
            .map_err(|_| denied())?,
        predecessor_public_key: row
            .try_get("predecessor_public_key")
            .map_err(|_| denied())?,
        issuer_fingerprint: row.try_get("issuer_fingerprint").map_err(|_| denied())?,
        issuer_generation: row.try_get("issuer_generation").map_err(|_| denied())?,
        csr_digest: row.try_get("csr_digest").map_err(|_| denied())?,
        candidate_public_key: row.try_get("candidate_public_key").map_err(|_| denied())?,
        candidate_fingerprint: row.try_get("candidate_fingerprint").map_err(|_| denied())?,
        candidate_certificate: row.try_get("candidate_certificate").map_err(|_| denied())?,
        candidate_attempted_at: row
            .try_get("candidate_attempted_at")
            .map_err(|_| denied())?,
    })
}

/// Every refusal looks the same to the host, so it learns nothing about which check failed.
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    //! Rotation retries retain the first candidate certificate for an operation.

    use super::*;
    use openssl::{
        hash::MessageDigest,
        pkey::PKey,
        x509::{X509NameBuilder, X509Req},
    };

    /// One flow checks restart, throttled redelivery, and exact-certificate idempotency together.
    #[tokio::test]
    async fn candidate_delivery_is_throttled_after_predecessor_reconnect() {
        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let now: i64 = sqlx::query_scalar("SELECT unixepoch()")
            .fetch_one(&pool)
            .await
            .unwrap();
        let old_fingerprint = [1_u8; 32];
        let old_public_key = [3_u8; 32];
        sqlx::query("UPDATE remote_hosts SET created_at=? WHERE id=?")
            .bind(now - ROTATION_PERIOD_SECS - 1)
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE remote_certificates SET not_before=?,not_after=? WHERE fingerprint=?")
            .bind(now)
            .bind(now + ROTATION_PERIOD_SECS)
            .bind(old_fingerprint.as_slice())
            .execute(&pool)
            .await
            .unwrap();

        let source = Arc::new(crate::ca::tests::source(true));
        let service = Service::new(store.clone(), source.clone());
        let operation = service.load_or_seed(host).await.unwrap();
        let challenge = service
            .start(host, &old_fingerprint, &old_public_key, now, &operation)
            .await
            .unwrap()
            .unwrap();

        let candidate_key = PKey::generate_ed25519().unwrap();
        let mut request = X509Req::builder().unwrap();
        request
            .set_subject_name(&X509NameBuilder::new().unwrap().build())
            .unwrap();
        request.set_pubkey(&candidate_key).unwrap();
        request.sign(&candidate_key, MessageDigest::null()).unwrap();
        let csr_der = request.build().to_der().unwrap();
        let csr = ValidatedCsr::parse(&csr_der).unwrap();
        let candidate_public_key = candidate_key.raw_public_key().unwrap().try_into().unwrap();
        let authority = CertificateAuthority::from_source(source.as_ref()).unwrap();
        let first = authority.sign_host(host, &csr, now).unwrap();
        service
            .persist_issued(IssuedCertificate {
                host,
                current_fingerprint: &old_fingerprint,
                predecessor: &old_public_key,
                challenge: &challenge,
                csr_digest: Sha256::digest(&csr_der).into(),
                public_key: candidate_public_key,
                der: &first.der,
                record: &first.record,
                now,
            })
            .await
            .unwrap();

        let restored = Service::new(store, source.clone());
        assert!(
            restored
                .next_action(host, old_fingerprint)
                .await
                .unwrap()
                .is_none(),
            "the predecessor must stay connected after a candidate was already offered"
        );

        let retry_before = now - CANDIDATE_REDELIVERY_SECS - 1;
        sqlx::query("UPDATE remote_identity_rotation SET candidate_attempted_at=? WHERE host_id=?")
            .bind(retry_before)
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        let Some(Action::Certificate(redelivery)) =
            restored.next_action(host, old_fingerprint).await.unwrap()
        else {
            panic!("elapsed delivery retry must resend the stored candidate certificate");
        };
        assert_eq!(redelivery.certificate_der, first.der);
        assert!(
            service
                .next_action(host, old_fingerprint)
                .await
                .unwrap()
                .is_none(),
            "a due retry must be claimed once and suppressed on concurrent reconnect"
        );

        let retry = authority.sign_host(host, &csr, now).unwrap();
        assert_ne!(
            first.der, retry.der,
            "the fixture must make distinct leaf bytes"
        );
        service
            .persist_issued(IssuedCertificate {
                host,
                current_fingerprint: &old_fingerprint,
                predecessor: &old_public_key,
                challenge: &challenge,
                csr_digest: Sha256::digest(&csr_der).into(),
                public_key: candidate_public_key,
                der: &retry.der,
                record: &retry.record,
                now,
            })
            .await
            .unwrap();

        let persisted: Vec<u8> = sqlx::query_scalar(
            "SELECT candidate_certificate FROM remote_identity_rotation WHERE host_id=?",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            persisted, first.der,
            "retry must return the exact leaf committed by the first accepted proof"
        );
    }
}
