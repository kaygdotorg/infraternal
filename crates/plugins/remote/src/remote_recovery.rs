//! Versioned, content-bounded messages for restricted expired-certificate recovery (#285).

use serde::{Deserialize, Serialize};
use std::{io, time::Duration};
use uuid::Uuid;

use crate::{channel::Channel, remote_tls};

/// One JSON message is bounded before decoding, independent of certificate size.
pub const MAX_FRAME_BYTES: usize = 32 * 1024;

/// Recovery requests never carry a reusable credential. Both requests are signed by the
/// predecessor key, so a party that knows only public host fields cannot open an operation.
#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryRequest {
    /// Begin or resume one idempotent operation and bind its CSR digest.
    Challenge {
        host_id: Uuid,
        predecessor_fingerprint: [u8; 32],
        request_id: [u8; 32],
        csr_digest: [u8; 32],
        /// Ed25519 signature by the predecessor key over [`challenge_message`].
        request_signature: Vec<u8>,
    },
    /// Prove possession of the registered key and provide the bounded signed CSR.
    Prove {
        host_id: Uuid,
        predecessor_fingerprint: [u8; 32],
        request_id: [u8; 32],
        challenge: [u8; 32],
        csr_der: Vec<u8>,
        signature: Vec<u8>,
    },
}

/// The same denial shape covers unknown, revoked, locked and out-of-window hosts.
#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryResponse {
    /// A one-use server nonce and the public fields covered by the transcript.
    Challenge {
        challenge: [u8; 32],
        public_key_fingerprint: [u8; 32],
        issuer_fingerprint: [u8; 32],
        issuer_generation: u64,
        not_after: i64,
    },
    /// The exact committed seven-day certificate, safe to retry after a lost reply.
    Certificate { certificate_der: Vec<u8> },
    /// No authority or detailed reason is returned.
    Denied,
}

/// Hash the request fields into a stable id so process restarts repeat the same operation.
#[must_use]
pub fn request_id(
    host_id: Uuid,
    predecessor_fingerprint: &[u8; 32],
    csr_digest: &[u8; 32],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 16 + 32 + 32);
    input.extend_from_slice(b"infraternal/remote-recovery/request/v1\0");
    input.extend_from_slice(host_id.as_bytes());
    input.extend_from_slice(predecessor_fingerprint);
    input.extend_from_slice(csr_digest);
    openssl::sha::sha256(&input)
}

/// Canonical bytes the predecessor key signs to open a recovery operation.
///
/// The server verifies this before it spends per-host budget or records a challenge.
/// Without it, anyone who knows the host ID and the predecessor fingerprint could fill
/// the host's pending operations and its rate budget, and lock the real host out.
/// Replaying a captured request only resumes the same idempotent operation; the
/// separate proof transcript still binds issuance to a fresh server nonce.
#[must_use]
pub fn challenge_message(
    host_id: Uuid,
    predecessor_fingerprint: &[u8; 32],
    request_id: &[u8; 32],
    csr_digest: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(48 + 16 + 32 * 3);
    bytes.extend_from_slice(b"infraternal/remote-recovery/challenge/v1\0");
    bytes.extend_from_slice(host_id.as_bytes());
    bytes.extend_from_slice(predecessor_fingerprint);
    bytes.extend_from_slice(request_id);
    bytes.extend_from_slice(csr_digest);
    bytes
}

/// Public transcript fields signed by the registered key during recovery.
#[derive(Clone, Copy)]
pub struct RecoveryTranscript<'a> {
    /// Stable registered host identity.
    pub host_id: Uuid,
    /// Fingerprint of the expired certificate being replaced.
    pub predecessor_fingerprint: &'a [u8; 32],
    /// Idempotent operation identifier bound to the CSR.
    pub request_id: &'a [u8; 32],
    /// Digest of the candidate CSR.
    pub csr_digest: &'a [u8; 32],
    /// One-use server challenge.
    pub challenge: &'a [u8; 32],
    /// Fingerprint of the registered identity key.
    pub public_key_fingerprint: &'a [u8; 32],
    /// Fingerprint of the CA issuer that signs the replacement leaf.
    pub issuer_fingerprint: &'a [u8; 32],
    /// Generation of that issuer.
    pub issuer_generation: u64,
    /// Expiry of the predecessor certificate.
    pub not_after: i64,
}

/// Produce the canonical domain-separated bytes both sides sign and verify.
#[must_use]
pub fn transcript(fields: RecoveryTranscript<'_>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 16 + 32 * 6 + 16);
    bytes.extend_from_slice(b"infraternal/remote-recovery/proof/v1\0");
    bytes.extend_from_slice(fields.host_id.as_bytes());
    bytes.extend_from_slice(fields.predecessor_fingerprint);
    bytes.extend_from_slice(fields.request_id);
    bytes.extend_from_slice(fields.csr_digest);
    bytes.extend_from_slice(fields.challenge);
    bytes.extend_from_slice(fields.public_key_fingerprint);
    bytes.extend_from_slice(fields.issuer_fingerprint);
    bytes.extend_from_slice(&fields.issuer_generation.to_be_bytes());
    bytes.extend_from_slice(&fields.not_after.to_be_bytes());
    bytes
}

/// Hash a canonical CSR before it crosses the unauthenticated recovery transport.
#[must_use]
pub fn csr_digest(csr_der: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(csr_der)
}

/// Run the versioned recovery exchange over the certificate-free recovery ALPN.
/// The returned leaf remains untrusted until its caller verifies and durably publishes it.
/// # Errors
/// Refuses malformed identity metadata, unknown roots, denied recovery, oversized frames,
/// and transport or TLS failures.
pub async fn exchange(
    address: std::net::SocketAddr,
    server_name: &str,
    identity: &remote_tls::Identity,
    roots: &[openssl::x509::X509],
) -> io::Result<openssl::x509::X509> {
    if roots.is_empty() || roots.len() > 16 {
        return Err(denied());
    }
    let proof = prepare_proof(identity)?;
    let config = remote_tls::recovery_client_config(roots)?;
    let connection = remote_tls::dial_recovery(address, server_name, &config).await?;

    let mut signer =
        openssl::sign::Signer::new_without_digest(&identity.key).map_err(|_| denied())?;
    // Ed25519 signs the complete message in one operation; streaming updates are unsupported.
    let request_signature = signer
        .sign_oneshot_to_vec(&challenge_message(
            proof.host_id,
            &proof.predecessor_fingerprint,
            &proof.request_id,
            &proof.csr_digest,
        ))
        .map_err(|_| denied())?;
    let challenge_request = RecoveryRequest::Challenge {
        host_id: proof.host_id,
        predecessor_fingerprint: proof.predecessor_fingerprint,
        request_id: proof.request_id,
        csr_digest: proof.csr_digest,
        request_signature,
    };
    write_request(&connection.channel, &challenge_request).await?;
    let challenge_response = read_response(&connection.channel).await?;
    let (challenge, issuer_fingerprint, issuer_generation, not_after) = match challenge_response {
        RecoveryResponse::Certificate { certificate_der } => {
            return canonical_certificate(&certificate_der);
        }
        RecoveryResponse::Challenge {
            challenge,
            public_key_fingerprint,
            issuer_fingerprint,
            issuer_generation,
            not_after,
        } => {
            if public_key_fingerprint != proof.public_key_fingerprint
                || issuer_generation == 0
                || not_after != proof.not_after
                || !roots.iter().any(|root| {
                    root.digest(openssl::hash::MessageDigest::sha256())
                        .is_ok_and(|digest| digest.as_ref() == issuer_fingerprint.as_slice())
                })
            {
                return Err(denied());
            }
            (challenge, issuer_fingerprint, issuer_generation, not_after)
        }
        RecoveryResponse::Denied => return Err(denied()),
    };
    let transcript = transcript(RecoveryTranscript {
        host_id: proof.host_id,
        predecessor_fingerprint: &proof.predecessor_fingerprint,
        request_id: &proof.request_id,
        csr_digest: &proof.csr_digest,
        challenge: &challenge,
        public_key_fingerprint: &proof.public_key_fingerprint,
        issuer_fingerprint: &issuer_fingerprint,
        issuer_generation,
        not_after,
    });
    let mut signer =
        openssl::sign::Signer::new_without_digest(&identity.key).map_err(|_| denied())?;
    // Ed25519 consumes the complete transcript in one operation; streaming updates are unsupported.
    let signature = signer
        .sign_oneshot_to_vec(&transcript)
        .map_err(|_| denied())?;
    write_request(
        &connection.channel,
        &RecoveryRequest::Prove {
            host_id: proof.host_id,
            predecessor_fingerprint: proof.predecessor_fingerprint,
            request_id: proof.request_id,
            challenge,
            csr_der: proof.csr_der,
            signature,
        },
    )
    .await?;
    match read_response(&connection.channel).await? {
        RecoveryResponse::Certificate { certificate_der } => {
            canonical_certificate(&certificate_der)
        }
        RecoveryResponse::Challenge { .. } | RecoveryResponse::Denied => Err(denied()),
    }
}

/// What the host sends to recover: its ID, the predecessor certificate, a fresh CSR for the same key and the request
/// ID that binds them.
struct ClientProof {
    host_id: Uuid,
    predecessor_fingerprint: [u8; 32],
    request_id: [u8; 32],
    csr_digest: [u8; 32],
    csr_der: Vec<u8>,
    public_key_fingerprint: [u8; 32],
    not_after: i64,
}

/// Build the recovery proof material from the current (expired) identity. Only Ed25519 identities can recover.
fn prepare_proof(identity: &remote_tls::Identity) -> io::Result<ClientProof> {
    use openssl::{
        hash::MessageDigest,
        pkey::Id,
        x509::{X509NameBuilder, X509Req},
    };

    if identity.key.id() != Id::ED25519 {
        return Err(denied());
    }
    let host_id = host_id(&identity.certificate)?;
    let predecessor_fingerprint = identity
        .certificate
        .digest(MessageDigest::sha256())
        .map_err(|_| denied())?
        .as_ref()
        .try_into()
        .map_err(|_| denied())?;
    let public_key = identity.key.raw_public_key().map_err(|_| denied())?;
    let public_key_fingerprint = openssl::sha::sha256(&public_key);
    let mut csr = X509Req::builder().map_err(|_| denied())?;
    csr.set_subject_name(&X509NameBuilder::new().map_err(|_| denied())?.build())
        .map_err(|_| denied())?;
    csr.set_pubkey(&identity.key).map_err(|_| denied())?;
    csr.sign(&identity.key, MessageDigest::null())
        .map_err(|_| denied())?;
    let csr_der = csr.build().to_der().map_err(|_| denied())?;
    if csr_der.len() > 4096 {
        return Err(denied());
    }
    let csr_digest = csr_digest(&csr_der);
    Ok(ClientProof {
        host_id,
        predecessor_fingerprint,
        request_id: request_id(host_id, &predecessor_fingerprint, &csr_digest),
        csr_digest,
        csr_der,
        public_key_fingerprint,
        not_after: epoch_seconds(identity.certificate.not_after())?,
    })
}

/// The host ID from the certificate's single `urn:infraternal:host:` URI name.
fn host_id(certificate: &openssl::x509::X509) -> io::Result<Uuid> {
    let mut host = None;
    for name in certificate.subject_alt_names().ok_or_else(denied)? {
        let Some(uri) = name.uri() else { continue };
        let Some(value) = uri.strip_prefix("urn:infraternal:host:") else {
            continue;
        };
        if host.is_some() {
            return Err(denied());
        }
        host = Some(Uuid::parse_str(value).map_err(|_| denied())?);
    }
    host.ok_or_else(denied)
}

/// Seconds since the Unix epoch for an ASN.1 time.
fn epoch_seconds(time: &openssl::asn1::Asn1TimeRef) -> io::Result<i64> {
    let epoch = openssl::asn1::Asn1Time::from_unix(0).map_err(|_| denied())?;
    let difference = epoch.diff(time).map_err(|_| denied())?;
    i64::from(difference.days)
        .checked_mul(86_400)
        .and_then(|days| days.checked_add(i64::from(difference.secs)))
        .ok_or_else(denied)
}

/// Parse a certificate only if its DER is canonical and within the size bound.
fn canonical_certificate(der: &[u8]) -> io::Result<openssl::x509::X509> {
    if der.len() > 8192 {
        return Err(denied());
    }
    let certificate = openssl::x509::X509::from_der(der).map_err(|_| denied())?;
    if certificate.to_der().map_err(|_| denied())? != der {
        return Err(denied());
    }
    Ok(certificate)
}

/// Read one bounded recovery request frame.
/// # Errors
/// Refuses malformed length prefixes, oversized frames and transport errors.
pub async fn read_request<C: Channel + ?Sized>(channel: &C) -> io::Result<RecoveryRequest> {
    let payload = read_frame(channel).await?;
    serde_json::from_slice(&payload).map_err(|_| denied())
}

/// Write one bounded recovery response frame.
/// # Errors
/// Refuses oversized responses or transport errors.
pub async fn write_response<C: Channel + ?Sized>(
    channel: &C,
    response: &RecoveryResponse,
) -> io::Result<()> {
    let payload = serde_json::to_vec(response).map_err(|_| denied())?;
    write_frame(channel, &payload).await
}

/// Write one bounded recovery request frame.
async fn write_request<C: Channel + ?Sized>(
    channel: &C,
    request: &RecoveryRequest,
) -> io::Result<()> {
    let payload = serde_json::to_vec(request).map_err(|_| denied())?;
    write_frame(channel, &payload).await
}

/// Read one bounded recovery response frame.
///
/// # Errors
/// Refuses malformed length prefixes, oversized frames and transport errors.
pub async fn read_response<C: Channel + ?Sized>(channel: &C) -> io::Result<RecoveryResponse> {
    let payload = read_frame(channel).await?;
    serde_json::from_slice(&payload).map_err(|_| denied())
}

/// Write one length-prefixed frame with a 5 s bound; empty or oversized payloads are refused.
async fn write_frame<C: Channel + ?Sized>(channel: &C, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(denied());
    }
    let length = u32::try_from(payload.len()).map_err(|_| denied())?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    tokio::time::timeout(Duration::from_secs(5), channel.write(&frame))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
}

/// Read one length-prefixed frame, refusing an oversized length before reading the payload.
async fn read_frame<C: Channel + ?Sized>(channel: &C) -> io::Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut length = [0; 4];
        read_exact(channel, &mut length).await?;
        let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| denied())?;
        if length == 0 || length > MAX_FRAME_BYTES {
            return Err(denied());
        }
        let mut payload = vec![0; length];
        read_exact(channel, &mut payload).await?;
        Ok(payload)
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}

/// Fill `target` completely from the channel, or fail.
async fn read_exact<C: Channel + ?Sized>(channel: &C, mut target: &mut [u8]) -> io::Result<()> {
    while !target.is_empty() {
        let read = channel.read(target).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        target = &mut target[read..];
    }
    Ok(())
}

/// Every refusal is the same opaque error.
fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

/// Transcript binding, frame bounds and time conversion checks for certificate recovery.
#[cfg(test)]
mod tests {
    use super::*;

    /// ASN.1 times convert to Unix seconds counted from the epoch.
    #[test]
    fn unix_time_conversion_uses_time_after_epoch() {
        let expected = 1_900_000_000;
        let time = openssl::asn1::Asn1Time::from_unix(expected).unwrap();
        assert_eq!(epoch_seconds(time.as_ref()).unwrap(), expected);
    }

    /// The request ID and the proof transcript change when any public field changes.
    #[test]
    fn request_identity_and_proof_transcript_bind_every_public_field() {
        let host = Uuid::from_u128(42);
        let old = [1; 32];
        let csr = [2; 32];
        let request = request_id(host, &old, &csr);
        assert_eq!(request, request_id(host, &old, &csr));
        assert_ne!(request, request_id(host, &[3; 32], &csr));
        assert_ne!(request, request_id(host, &old, &[3; 32]));

        let challenge = [4; 32];
        let public_key = [5; 32];
        let issuer = [6; 32];
        let base_fields = RecoveryTranscript {
            host_id: host,
            predecessor_fingerprint: &old,
            request_id: &request,
            csr_digest: &csr,
            challenge: &challenge,
            public_key_fingerprint: &public_key,
            issuer_fingerprint: &issuer,
            issuer_generation: 7,
            not_after: 8,
        };
        let base = transcript(base_fields);
        for changed in [
            transcript(RecoveryTranscript {
                host_id: Uuid::from_u128(43),
                ..base_fields
            }),
            transcript(RecoveryTranscript {
                predecessor_fingerprint: &[3; 32],
                ..base_fields
            }),
            transcript(RecoveryTranscript {
                request_id: &[3; 32],
                ..base_fields
            }),
            transcript(RecoveryTranscript {
                csr_digest: &[3; 32],
                ..base_fields
            }),
            transcript(RecoveryTranscript {
                challenge: &[3; 32],
                ..base_fields
            }),
            transcript(RecoveryTranscript {
                public_key_fingerprint: &[3; 32],
                ..base_fields
            }),
            transcript(RecoveryTranscript {
                issuer_fingerprint: &[3; 32],
                ..base_fields
            }),
            transcript(RecoveryTranscript {
                issuer_generation: 8,
                ..base_fields
            }),
            transcript(RecoveryTranscript {
                not_after: 9,
                ..base_fields
            }),
        ] {
            assert_ne!(base, changed);
        }
        assert!(base.starts_with(b"infraternal/remote-recovery/proof/v1\0"));
    }

    /// The challenge message covers every request field under its own signing domain.
    #[test]
    fn challenge_message_binds_every_request_field_under_its_own_domain() {
        let host = Uuid::from_u128(42);
        let old = [1; 32];
        let csr = [2; 32];
        let request = request_id(host, &old, &csr);
        let base = challenge_message(host, &old, &request, &csr);
        assert_eq!(base, challenge_message(host, &old, &request, &csr));
        for changed in [
            challenge_message(Uuid::from_u128(43), &old, &request, &csr),
            challenge_message(host, &[3; 32], &request, &csr),
            challenge_message(host, &old, &[3; 32], &csr),
            challenge_message(host, &old, &request, &[3; 32]),
        ] {
            assert_ne!(base, changed);
        }
        // A challenge signature can never be replayed as a proof signature.
        assert!(base.starts_with(b"infraternal/remote-recovery/challenge/v1\0"));
    }

    /// An in-memory channel over a duplex stream.
    struct Duplex(tokio::sync::Mutex<tokio::io::DuplexStream>);

    impl Channel for Duplex {
        async fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
            use tokio::io::AsyncReadExt;
            self.0.lock().await.read(bytes).await
        }

        async fn write(&self, bytes: &[u8]) -> io::Result<()> {
            use tokio::io::AsyncWriteExt;
            self.0.lock().await.write_all(bytes).await
        }
    }

    /// The parser refuses unknown fields and oversized frames before decoding them.
    #[tokio::test]
    async fn recovery_parser_rejects_unknown_fields_and_oversized_frames_before_decode() {
        let (channel, mut peer) = tokio::io::duplex(4096);
        let channel = Duplex(tokio::sync::Mutex::new(channel));
        let mut unknown = serde_json::to_vec(&RecoveryRequest::Challenge {
            host_id: Uuid::from_u128(42),
            predecessor_fingerprint: [1; 32],
            request_id: [2; 32],
            csr_digest: [3; 32],
            request_signature: vec![4; 64],
        })
        .unwrap();
        unknown.pop();
        unknown.extend_from_slice(b",\"unexpected\":true}");
        let length = u32::try_from(unknown.len()).unwrap().to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut peer, &length)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut peer, &unknown)
            .await
            .unwrap();
        assert!(read_request(&channel).await.is_err());

        let (channel, mut peer) = tokio::io::duplex(64);
        let channel = Duplex(tokio::sync::Mutex::new(channel));
        let length = u32::try_from(MAX_FRAME_BYTES + 1).unwrap().to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut peer, &length)
            .await
            .unwrap();
        assert!(read_request(&channel).await.is_err());
    }
}
