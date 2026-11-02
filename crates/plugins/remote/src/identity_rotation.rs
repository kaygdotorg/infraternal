//! Builds old-key proof for a server-challenged host identity transition [285].

use crate::remote_tls::Identity;
use openssl::{
    asn1::Asn1Time,
    hash::{MessageDigest, hash},
    pkey::{Id, PKey, Private},
    sign::Signer,
    stack::Stack,
    x509::{X509, X509NameBuilder, X509Req, X509StoreContext, store::X509StoreBuilder},
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{Arc, RwLock},
};
use uuid::Uuid;

const DOMAIN: &[u8] = b"infraternal/1 host-key-rotation\0";
const MAX_CSR_DER: usize = 4096;

/// Server state bound to the active certificate before the host creates a candidate.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    /// Stable SAN identity shared by both certificates.
    pub host_id: Uuid,
    /// Idempotency key stored by the server before it sends this challenge.
    pub operation_id: Uuid,
    /// Monotonic host key epoch selected by the server.
    pub sequence: u64,
    /// Fresh server nonce.
    pub challenge: [u8; 32],
    /// Exact active certificate whose key authorizes this transition.
    pub predecessor_fingerprint: [u8; 32],
    /// Signing issuer pinned by the running server during this transition.
    pub issuer_fingerprint: [u8; 32],
    /// Monotonic CA generation selected by the server.
    pub issuer_generation: u64,
}

/// Candidate CSR and proof made by the still-active identity key.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    /// Echoes the durable operation key.
    pub operation_id: Uuid,
    /// Echoes the durable key epoch.
    pub sequence: u64,
    /// PKCS#10 proof of possession for the candidate Ed25519 key.
    pub csr_der: Vec<u8>,
    /// Signature by the registered predecessor over the entire transition.
    pub old_signature: Vec<u8>,
}

/// Candidate certificate sent only after the server has durably accepted a proof.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCertificate {
    /// Echoes the persistent operation key.
    pub operation_id: Uuid,
    /// Echoes the server-selected monotonic key epoch.
    pub sequence: u64,
    /// Seven-day client certificate for the candidate public key.
    pub certificate_der: Vec<u8>,
}

/// Server acknowledgment sent only after candidate mTLS admission commits.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgment {
    /// Idempotency key retained on both peers through reconnect.
    pub operation_id: Uuid,
    /// Monotonic host identity epoch.
    pub sequence: u64,
}

/// Public completion marker retained so a repeated acknowledgment remains safe.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CompletedRotation {
    /// Completed transition's operation ID.
    pub operation_id: Uuid,
    /// Completed identity epoch.
    pub sequence: u64,
    /// Candidate leaf fingerprint acknowledged by the server.
    pub certificate_fingerprint: [u8; 32],
}

/// Private candidate material loaded from the mode-0600 local identity store.
pub struct PendingRotation {
    /// Server challenge this candidate answers.
    pub challenge: Challenge,
    /// Candidate Ed25519 PKCS#8 bytes; callers must keep them local.
    pub candidate_key_pkcs8: Vec<u8>,
    /// Certificate DER after issuance; absent before the server's certificate action.
    pub candidate_certificate_der: Option<Vec<u8>>,
}

/// Persisted local rotation state, never sent over the authenticated channel.
pub struct RotationStorage {
    /// An unfinished candidate retained beside the active identity.
    pub pending: Option<PendingRotation>,
    /// Last durable promotion, used to accept a repeated server acknowledgment.
    pub completed: Option<CompletedRotation>,
}

/// Atomic local publication for an identity candidate and its commit marker.
pub trait RotationPublisher: Send + Sync {
    /// Read bounded pending/completed state from the private identity store.
    /// # Errors
    /// Unsafe paths, malformed state or storage failure.
    fn load(&self) -> io::Result<RotationStorage>;
    /// Fsync the candidate private key before its CSR is returned.
    /// # Errors
    /// Stale identity or failed atomic publication.
    fn store_candidate(&self, challenge: &Challenge, key_pkcs8: &[u8]) -> io::Result<()>;
    /// Fsync the issued certificate beside both identities before reconnect.
    /// # Errors
    /// Wrong operation, changed candidate or failed atomic publication.
    fn store_certificate(&self, operation_id: Uuid, der: &[u8]) -> io::Result<()>;
    /// Promote only after candidate mTLS acknowledgment; clear the old private key atomically.
    /// # Errors
    /// Wrong operation or failed atomic publication.
    fn promote(&self, completed: &CompletedRotation) -> io::Result<()>;
}

struct Pending {
    challenge: Challenge,
    predecessor: Identity,
    candidate: PKey<Private>,
    certificate: Option<X509>,
}

struct State {
    pending: Option<Pending>,
    completed: Option<CompletedRotation>,
}

/// Holds old-key proof state until a candidate mTLS acknowledgment is durable.
#[derive(Clone)]
pub struct IdentityRotation {
    state: Arc<RwLock<State>>,
    roots: Vec<X509>,
    publisher: Arc<dyn RotationPublisher>,
}

impl IdentityRotation {
    /// Restore any candidate without promoting or dropping the predecessor.
    /// # Errors
    /// Refuses malformed stored keys/certificates, mismatched challenges or unsafe storage.
    pub fn new(
        predecessor: &Identity,
        roots: &[X509],
        publisher: Arc<dyn RotationPublisher>,
    ) -> io::Result<(Self, Identity)> {
        let storage = publisher.load()?;
        let completed = storage.completed;
        let pending = if let Some(persisted) = storage.pending {
            let challenge = persisted.challenge;
            if challenge.sequence == 0
                || host_id(&predecessor.certificate)? != challenge.host_id
                || !predecessor
                    .certificate
                    .public_key()
                    .map_err(|_| denied())?
                    .public_eq(&predecessor.key)
            {
                return Err(denied());
            }
            let candidate = PKey::private_key_from_pkcs8(&persisted.candidate_key_pkcs8)
                .map_err(|_| denied())?;
            if candidate.id() != Id::ED25519 {
                return Err(denied());
            }
            let certificate = persisted
                .candidate_certificate_der
                .map(|der| {
                    if der.is_empty() || der.len() > MAX_CSR_DER * 2 {
                        return Err(denied());
                    }
                    let certificate = X509::from_der(&der).map_err(|_| denied())?;
                    if certificate.to_der().map_err(|_| denied())? != der {
                        return Err(denied());
                    }
                    validate_certificate(&certificate, &candidate, &challenge, roots, false)?;
                    Ok(certificate)
                })
                .transpose()?;
            Some(Pending {
                challenge,
                predecessor: Identity {
                    certificate: predecessor.certificate.clone(),
                    key: predecessor.key.clone(),
                },
                candidate,
                certificate,
            })
        } else {
            None
        };
        let now = Asn1Time::days_from_now(0).map_err(|_| denied())?;
        let current = pending.as_ref().and_then(|pending| {
            pending
                .certificate
                .as_ref()
                .filter(|certificate| {
                    certificate.not_before() <= now.as_ref()
                        && certificate.not_after() > now.as_ref()
                })
                .map(|certificate| Identity {
                    certificate: certificate.clone(),
                    key: pending.candidate.clone(),
                })
        });
        Ok((
            Self {
                state: Arc::new(RwLock::new(State { pending, completed })),
                roots: roots.to_vec(),
                publisher,
            },
            current.unwrap_or_else(|| Identity {
                certificate: predecessor.certificate.clone(),
                key: predecessor.key.clone(),
            }),
        ))
    }

    /// Whether a server acknowledgment may be retried for the last promotion.
    #[must_use]
    pub fn supports_rotation(&self) -> bool {
        true
    }

    /// Return the saved predecessor only while the persisted candidate is active.
    /// This is a process-local reconnect fallback; it never changes the active identity.
    /// # Errors
    /// Refuses poisoned state or invalid certificate encoding.
    pub fn predecessor_for(&self, active: &Identity) -> io::Result<Option<Identity>> {
        let state = self.state.try_read().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
            std::sync::TryLockError::Poisoned(_) => denied(),
        })?;
        let Some(pending) = state.pending.as_ref() else {
            return Ok(None);
        };
        let Some(candidate_certificate) = pending.certificate.as_ref() else {
            return Ok(None);
        };
        if candidate_certificate.to_der().map_err(|_| denied())?
            != active.certificate.to_der().map_err(|_| denied())?
            || !pending.candidate.public_eq(&active.key)
        {
            return Ok(None);
        }
        Ok(Some(Identity {
            certificate: pending.predecessor.certificate.clone(),
            key: pending.predecessor.key.clone(),
        }))
    }

    /// Handle the three server-only identity rotation actions.
    /// # Errors
    /// Refuses malformed, stale, unbound or unpersistable rotation state.
    pub fn action(
        &self,
        identity: &Arc<RwLock<Identity>>,
        action: &str,
        input: &[u8],
    ) -> io::Result<Vec<u8>> {
        if input.len() > crate::remote_renewal::MAX_RENEWAL_JSON {
            return Err(denied());
        }
        match action {
            "transport.csr.rotate" => self.proof(identity, input),
            "transport.identity.rotate.certificate" => self.certificate(identity, input),
            "transport.identity.rotate.ack" => self.acknowledge(identity, input),
            _ => Err(denied()),
        }
    }

    fn proof(&self, current: &Arc<RwLock<Identity>>, input: &[u8]) -> io::Result<Vec<u8>> {
        let challenge: Challenge = serde_json::from_slice(input).map_err(|_| denied())?;
        if challenge.sequence == 0 || challenge.issuer_generation == 0 {
            return Err(denied());
        }
        let mut state = self.state.write().map_err(|_| denied())?;
        if state.pending.is_none() {
            let predecessor = current.read().map_err(|_| denied())?;
            validate_initial_predecessor(&predecessor, &challenge)?;
            if state
                .completed
                .as_ref()
                .is_some_and(|completed| challenge.sequence <= completed.sequence)
            {
                return Err(denied());
            }
            let candidate = PKey::generate_ed25519().map_err(|_| denied())?;
            let encoded = candidate.private_key_to_pkcs8().map_err(|_| denied())?;
            self.publisher.store_candidate(&challenge, &encoded)?;
            state.pending = Some(Pending {
                challenge: challenge.clone(),
                predecessor: Identity {
                    certificate: predecessor.certificate.clone(),
                    key: predecessor.key.clone(),
                },
                candidate,
                certificate: None,
            });
        }
        let pending = state.pending.as_ref().ok_or_else(denied)?;
        if pending.challenge != challenge {
            return Err(denied());
        }
        serde_json::to_vec(&prove(
            &pending.predecessor,
            &pending.candidate,
            &pending.challenge,
        )?)
        .map_err(|_| denied())
    }

    fn certificate(&self, current: &Arc<RwLock<Identity>>, input: &[u8]) -> io::Result<Vec<u8>> {
        let update: CandidateCertificate = serde_json::from_slice(input).map_err(|_| denied())?;
        if update.certificate_der.is_empty() || update.certificate_der.len() > 8192 {
            return Err(denied());
        }
        let certificate = X509::from_der(&update.certificate_der).map_err(|_| denied())?;
        if certificate.to_der().map_err(|_| denied())? != update.certificate_der {
            return Err(denied());
        }
        let mut state = self.state.write().map_err(|_| denied())?;
        let pending = state.pending.as_mut().ok_or_else(denied)?;
        if pending.challenge.operation_id != update.operation_id
            || pending.challenge.sequence != update.sequence
        {
            return Err(denied());
        }
        validate_certificate(
            &certificate,
            &pending.candidate,
            &pending.challenge,
            &self.roots,
            true,
        )?;
        self.publisher
            .store_certificate(update.operation_id, &update.certificate_der)?;
        pending.certificate = Some(certificate.clone());
        let mut current = current.write().map_err(|_| denied())?;
        current.certificate = certificate;
        current.key = pending.candidate.clone();
        serde_json::to_vec(&serde_json::json!({})).map_err(|_| denied())
    }

    fn acknowledge(&self, current: &Arc<RwLock<Identity>>, input: &[u8]) -> io::Result<Vec<u8>> {
        let acknowledgment: Acknowledgment = serde_json::from_slice(input).map_err(|_| denied())?;
        let mut state = self.state.write().map_err(|_| denied())?;
        if state.pending.is_none()
            && state.completed.as_ref().is_some_and(|completed| {
                completed.operation_id == acknowledgment.operation_id
                    && completed.sequence == acknowledgment.sequence
            })
        {
            return serde_json::to_vec(&serde_json::json!({})).map_err(|_| denied());
        }
        let pending = state.pending.as_ref().ok_or_else(denied)?;
        let certificate = pending.certificate.as_ref().ok_or_else(denied)?;
        let completed = CompletedRotation {
            operation_id: pending.challenge.operation_id,
            sequence: pending.challenge.sequence,
            certificate_fingerprint: fingerprint(certificate)?,
        };
        if completed.operation_id != acknowledgment.operation_id
            || completed.sequence != acknowledgment.sequence
        {
            return Err(denied());
        }
        self.publisher.promote(&completed)?;
        state.pending = None;
        state.completed = Some(completed);
        // Rebuild the active snapshot after the old key has been dropped from persisted state.
        let active = current.read().map_err(|_| denied())?;
        if !active
            .certificate
            .public_key()
            .map_err(|_| denied())?
            .public_eq(&active.key)
        {
            return Err(denied());
        }
        serde_json::to_vec(&serde_json::json!({})).map_err(|_| denied())
    }

    /// Keep an in-memory candidate certificate aligned with ordinary half-life renewal.
    /// The durable publisher has already written the new certificate before this is called.
    /// # Errors
    /// Refuses a certificate for a different candidate key or host.
    pub fn renewed_certificate(&self, certificate: &X509) -> io::Result<()> {
        let mut state = self.state.write().map_err(|_| denied())?;
        if let Some(pending) = state.pending.as_mut()
            && pending.certificate.is_some()
            && certificate
                .public_key()
                .map_err(|_| denied())?
                .public_eq(&pending.candidate)
            && host_id(certificate)? == pending.challenge.host_id
        {
            pending.certificate = Some(certificate.clone());
        }
        Ok(())
    }
}

/// Construct a candidate CSR for an already accepted challenge.
///
/// A persisted operation may resume after the same identity key receives a
/// renewed certificate. `IdentityRotation::proof` pins a newly received
/// challenge to the exact active leaf before persisting its candidate; a
/// resumed proof keeps the original leaf fingerprint in its transcript while
/// checking that the current certificate still belongs to this host and key.
///
/// # Errors
/// Refuses invalid challenges, non-Ed25519 keys and OpenSSL failures.
pub fn prove(
    current: &Identity,
    candidate: &PKey<Private>,
    challenge: &Challenge,
) -> io::Result<Proof> {
    if challenge.sequence == 0 || candidate.id() != Id::ED25519 {
        return Err(denied());
    }
    if host_id(&current.certificate)? != challenge.host_id {
        return Err(denied());
    }

    let mut request = X509Req::builder().map_err(|_| denied())?;
    request
        .set_subject_name(&X509NameBuilder::new().map_err(|_| denied())?.build())
        .map_err(|_| denied())?;
    request.set_pubkey(candidate).map_err(|_| denied())?;
    request
        .sign(candidate, MessageDigest::null())
        .map_err(|_| denied())?;
    let csr_der = request.build().to_der().map_err(|_| denied())?;
    if csr_der.len() > MAX_CSR_DER {
        return Err(denied());
    }
    let transcript = transcript(challenge, &csr_der)?;
    if !current
        .certificate
        .public_key()
        .map_err(|_| denied())?
        .public_eq(&current.key)
    {
        return Err(denied());
    }
    let mut signer = Signer::new_without_digest(&current.key).map_err(|_| denied())?;
    let old_signature = signer
        .sign_oneshot_to_vec(&transcript)
        .map_err(|_| denied())?;
    Ok(Proof {
        operation_id: challenge.operation_id,
        sequence: challenge.sequence,
        csr_der,
        old_signature,
    })
}

fn validate_initial_predecessor(current: &Identity, challenge: &Challenge) -> io::Result<()> {
    if host_id(&current.certificate)? != challenge.host_id
        || fingerprint(&current.certificate)? != challenge.predecessor_fingerprint
        || !current
            .certificate
            .public_key()
            .map_err(|_| denied())?
            .public_eq(&current.key)
    {
        return Err(denied());
    }
    Ok(())
}

/// Build the byte-exact domain-separated proof transcript used by both peers.
///
/// # Errors
/// Refuses an invalid key epoch or oversized CSR.
pub fn transcript(challenge: &Challenge, csr_der: &[u8]) -> io::Result<Vec<u8>> {
    if challenge.sequence == 0
        || challenge.issuer_generation == 0
        || csr_der.is_empty()
        || csr_der.len() > MAX_CSR_DER
    {
        return Err(denied());
    }
    let digest = hash(MessageDigest::sha256(), csr_der).map_err(|_| denied())?;
    let mut message = Vec::with_capacity(DOMAIN.len() + 16 + 32 + 16 + 8 + 32 + 32 + 8 + 32);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(challenge.host_id.as_bytes());
    message.extend_from_slice(challenge.predecessor_fingerprint.as_slice());
    message.extend_from_slice(challenge.operation_id.as_bytes());
    message.extend_from_slice(&challenge.sequence.to_le_bytes());
    message.extend_from_slice(&challenge.challenge);
    message.extend_from_slice(&challenge.issuer_fingerprint);
    message.extend_from_slice(&challenge.issuer_generation.to_le_bytes());
    message.extend_from_slice(digest.as_ref());
    Ok(message)
}

fn validate_certificate(
    certificate: &X509,
    candidate: &PKey<Private>,
    challenge: &Challenge,
    roots: &[X509],
    require_current: bool,
) -> io::Result<()> {
    if candidate.id() != Id::ED25519
        || !certificate
            .public_key()
            .map_err(|_| denied())?
            .public_eq(candidate)
        || host_id(certificate)? != challenge.host_id
        || certificate
            .not_before()
            .diff(certificate.not_after())
            .map_err(|_| denied())?
            .days
            != 7
        || certificate
            .not_before()
            .diff(certificate.not_after())
            .map_err(|_| denied())?
            .secs
            != 0
    {
        return Err(denied());
    }
    let root = roots
        .iter()
        .find(|root| fingerprint(root).is_ok_and(|value| value == challenge.issuer_fingerprint))
        .ok_or_else(denied)?;
    let mut trust = X509StoreBuilder::new().map_err(|_| denied())?;
    trust.add_cert(root.clone()).map_err(|_| denied())?;
    trust
        .set_purpose(openssl::x509::X509PurposeId::SSL_CLIENT)
        .map_err(|_| denied())?;
    trust
        .set_flags(openssl::x509::verify::X509VerifyFlags::NO_CHECK_TIME)
        .map_err(|_| denied())?;
    let trust = trust.build();
    let chain = Stack::<X509>::new().map_err(|_| denied())?;
    let now = Asn1Time::days_from_now(0).map_err(|_| denied())?;
    let mut context = X509StoreContext::new().map_err(|_| denied())?;
    if (require_current
        && (certificate.not_before() > now.as_ref() || certificate.not_after() <= now.as_ref()))
        || !context
            .init(
                &trust,
                certificate,
                &chain,
                openssl::x509::X509StoreContextRef::verify_cert,
            )
            .map_err(|_| denied())?
    {
        return Err(denied());
    }
    Ok(())
}

fn fingerprint(certificate: &X509) -> io::Result<[u8; 32]> {
    certificate
        .digest(MessageDigest::sha256())
        .map_err(|_| denied())?
        .as_ref()
        .try_into()
        .map_err(|_| denied())
}

fn host_id(certificate: &openssl::x509::X509) -> io::Result<Uuid> {
    let names = certificate.subject_alt_names().ok_or_else(denied)?;
    if names.len() != 1 {
        return Err(denied());
    }
    let uri = names[0].uri().ok_or_else(denied)?;
    Uuid::parse_str(
        uri.strip_prefix("urn:infraternal:host:")
            .ok_or_else(denied)?,
    )
    .map_err(|_| denied())
}

fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        sign::Verifier,
        x509::{
            X509,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        },
    };

    fn host_identity(root: &Identity, host: Uuid) -> Identity {
        let key = PKey::generate_ed25519().unwrap();
        host_identity_with_key(root, host, key, 4)
    }

    fn host_identity_with_key(
        root: &Identity,
        host: Uuid,
        key: PKey<Private>,
        serial: u32,
    ) -> Identity {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "test host").unwrap();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name.build()).unwrap();
        builder
            .set_issuer_name(root.certificate.subject_name())
            .unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(7).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder
            .append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
            .unwrap();
        let san = {
            let context = builder.x509v3_context(Some(&root.certificate), None);
            SubjectAlternativeName::new()
                .uri(&format!("urn:infraternal:host:{host}"))
                .build(&context)
                .unwrap()
        };
        builder.append_extension(san).unwrap();
        builder.sign(&root.key, MessageDigest::null()).unwrap();
        Identity {
            certificate: builder.build(),
            key,
        }
    }

    fn challenge(identity: &Identity) -> Challenge {
        Challenge {
            host_id: Uuid::from_u128(42),
            operation_id: Uuid::from_u128(43),
            sequence: 1,
            challenge: [7; 32],
            predecessor_fingerprint: identity
                .certificate
                .digest(MessageDigest::sha256())
                .unwrap()
                .as_ref()
                .try_into()
                .unwrap(),
            issuer_fingerprint: [8; 32],
            issuer_generation: 9,
        }
    }

    #[test]
    fn proof_transcript_binds_issuer_fingerprint_and_generation() {
        let root = crate::remote_tls::tests::root();
        let host = Uuid::from_u128(42);
        let current = host_identity(&root, host);
        let candidate = PKey::generate_ed25519().unwrap();
        let mut challenge = challenge(&current);
        challenge.host_id = host;
        let proof = prove(&current, &candidate, &challenge).unwrap();
        let public = current.certificate.public_key().unwrap();

        let signed_transcript = transcript(&challenge, &proof.csr_der).unwrap();
        let mut verifier = Verifier::new_without_digest(&public).unwrap();
        assert!(
            verifier
                .verify_oneshot(&proof.old_signature, &signed_transcript)
                .unwrap()
        );

        let mut changed = challenge.clone();
        changed.issuer_fingerprint[0] ^= 1;
        let changed_transcript = transcript(&changed, &proof.csr_der).unwrap();
        let mut verifier = Verifier::new_without_digest(&public).unwrap();
        assert!(
            !verifier
                .verify_oneshot(&proof.old_signature, &changed_transcript)
                .unwrap()
        );

        let mut changed = challenge;
        changed.issuer_generation += 1;
        let changed_transcript = transcript(&changed, &proof.csr_der).unwrap();
        let mut verifier = Verifier::new_without_digest(&public).unwrap();
        assert!(
            !verifier
                .verify_oneshot(&proof.old_signature, &changed_transcript)
                .unwrap()
        );
    }

    #[test]
    fn pending_proof_survives_predecessor_certificate_renewal() {
        let root = crate::remote_tls::tests::root();
        let host = Uuid::from_u128(42);
        let predecessor = host_identity(&root, host);
        let renewed = host_identity_with_key(&root, host, predecessor.key.clone(), 5);
        assert_ne!(
            fingerprint(&predecessor.certificate).unwrap(),
            fingerprint(&renewed.certificate).unwrap()
        );

        let candidate = PKey::generate_ed25519().unwrap();
        let challenge = challenge(&predecessor);
        let proof = prove(&renewed, &candidate, &challenge)
            .expect("the renewed leaf retains the predecessor key for the saved challenge");
        let transcript = transcript(&challenge, &proof.csr_der).unwrap();
        let public = renewed.certificate.public_key().unwrap();
        let mut verifier = Verifier::new_without_digest(&public).unwrap();
        assert!(
            verifier
                .verify_oneshot(&proof.old_signature, &transcript)
                .unwrap()
        );
    }

    #[test]
    fn new_challenge_requires_the_exact_predecessor_certificate() {
        let root = crate::remote_tls::tests::root();
        let host = Uuid::from_u128(42);
        let predecessor = host_identity(&root, host);
        let renewed = host_identity_with_key(&root, host, predecessor.key.clone(), 5);
        let challenge = challenge(&predecessor);

        assert!(validate_initial_predecessor(&predecessor, &challenge).is_ok());
        assert!(validate_initial_predecessor(&renewed, &challenge).is_err());
    }
}
