//! Versioned, content-bounded messages for restricted expired-certificate recovery (#285).

use serde::{Deserialize, Serialize};
use std::{io, time::Duration};
use uuid::Uuid;

use crate::{channel::Channel, remote_tls};

/// One JSON message is bounded before decoding, independent of certificate size.
pub const MAX_FRAME_BYTES: usize = 32 * 1024;

/// Recovery requests never carry a reusable credential; the second request proves the old key.
#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryRequest {
    /// Begin or resume one idempotent operation and bind its CSR digest.
    Challenge {
        host_id: Uuid,
        predecessor_fingerprint: [u8; 32],
        request_id: [u8; 32],
        csr_digest: [u8; 32],
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

/// Produce the canonical domain-separated bytes both sides sign and verify.
#[must_use]
pub fn transcript(
    host_id: Uuid,
    predecessor_fingerprint: &[u8; 32],
    request_id: &[u8; 32],
    csr_digest: &[u8; 32],
    challenge: &[u8; 32],
    public_key_fingerprint: &[u8; 32],
    issuer_fingerprint: &[u8; 32],
    issuer_generation: u64,
    not_after: i64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 16 + 32 * 6 + 16);
    bytes.extend_from_slice(b"infraternal/remote-recovery/proof/v1\0");
    bytes.extend_from_slice(host_id.as_bytes());
    bytes.extend_from_slice(predecessor_fingerprint);
    bytes.extend_from_slice(request_id);
    bytes.extend_from_slice(csr_digest);
    bytes.extend_from_slice(challenge);
    bytes.extend_from_slice(public_key_fingerprint);
    bytes.extend_from_slice(issuer_fingerprint);
    bytes.extend_from_slice(&issuer_generation.to_be_bytes());
    bytes.extend_from_slice(&not_after.to_be_bytes());
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
    use openssl::{
        hash::MessageDigest,
        pkey::Id,
        x509::{X509NameBuilder, X509Req},
    };

    if roots.is_empty() || roots.len() > 16 || identity.key.id() != Id::ED25519 {
        return Err(denied());
    }
    let host_id = host_id(&identity.certificate)?;
    let predecessor_fingerprint: [u8; 32] = identity
        .certificate
        .digest(MessageDigest::sha256())
        .map_err(|_| denied())?
        .as_ref()
        .try_into()
        .map_err(|_| denied())?;
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
    let request_id = request_id(host_id, &predecessor_fingerprint, &csr_digest);
    let config = remote_tls::recovery_client_config(roots)?;
    let connection = remote_tls::dial_recovery(address, server_name, &config).await?;

    let challenge_request = RecoveryRequest::Challenge {
        host_id,
        predecessor_fingerprint,
        request_id,
        csr_digest,
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
            let public_key = identity.key.raw_public_key().map_err(|_| denied())?;
            if public_key_fingerprint != openssl::sha::sha256(&public_key)
                || issuer_generation == 0
                || not_after != epoch_seconds(identity.certificate.not_after())?
                || !roots.iter().any(|root| {
                    root.digest(MessageDigest::sha256())
                        .is_ok_and(|digest| digest.as_ref() == issuer_fingerprint.as_slice())
                })
            {
                return Err(denied());
            }
            (
                challenge,
                issuer_fingerprint,
                issuer_generation,
                not_after,
            )
        }
        RecoveryResponse::Denied => return Err(denied()),
    };
    let public_key = identity.key.raw_public_key().map_err(|_| denied())?;
    let public_key_fingerprint = openssl::sha::sha256(&public_key);
    let transcript = transcript(
        host_id,
        &predecessor_fingerprint,
        &request_id,
        &csr_digest,
        &challenge,
        &public_key_fingerprint,
        &issuer_fingerprint,
        issuer_generation,
        not_after,
    );
    let mut signer = openssl::sign::Signer::new_without_digest(&identity.key).map_err(|_| denied())?;
    signer.update(&transcript).map_err(|_| denied())?;
    let signature = signer.sign_to_vec().map_err(|_| denied())?;
    write_request(
        &connection.channel,
        &RecoveryRequest::Prove {
            host_id,
            predecessor_fingerprint,
            request_id,
            challenge,
            csr_der,
            signature,
        },
    )
    .await?;
    match read_response(&connection.channel).await? {
        RecoveryResponse::Certificate { certificate_der } => canonical_certificate(&certificate_der),
        RecoveryResponse::Challenge { .. } | RecoveryResponse::Denied => Err(denied()),
    }
}

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

fn epoch_seconds(time: &openssl::asn1::Asn1TimeRef) -> io::Result<i64> {
    let epoch = openssl::asn1::Asn1Time::from_unix(0).map_err(|_| denied())?;
    let difference = time.diff(epoch.as_ref()).map_err(|_| denied())?;
    i64::from(difference.days)
        .checked_mul(86_400)
        .and_then(|days| days.checked_add(i64::from(difference.secs)))
        .ok_or_else(denied)
}

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

async fn write_request<C: Channel + ?Sized>(
    channel: &C,
    request: &RecoveryRequest,
) -> io::Result<()> {
    let payload = serde_json::to_vec(request).map_err(|_| denied())?;
    write_frame(channel, &payload).await
}

async fn read_response<C: Channel + ?Sized>(channel: &C) -> io::Result<RecoveryResponse> {
    let payload = read_frame(channel).await?;
    serde_json::from_slice(&payload).map_err(|_| denied())
}

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

fn denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_identity_and_proof_transcript_bind_every_public_field() {
        let host = Uuid::from_u128(42);
        let old = [1; 32];
        let csr = [2; 32];
        let request = request_id(host, &old, &csr);
        assert_eq!(request, request_id(host, &old, &csr));
        assert_ne!(request, request_id(host, &[3; 32], &csr));
        assert_ne!(request, request_id(host, &old, &[3; 32]));

        let base = transcript(host, &old, &request, &csr, &[4; 32], &[5; 32], &[6; 32], 7, 8);
        for changed in [
            transcript(Uuid::from_u128(43), &old, &request, &csr, &[4; 32], &[5; 32], &[6; 32], 7, 8),
            transcript(host, &[3; 32], &request, &csr, &[4; 32], &[5; 32], &[6; 32], 7, 8),
            transcript(host, &old, &[3; 32], &csr, &[4; 32], &[5; 32], &[6; 32], 7, 8),
            transcript(host, &old, &request, &[3; 32], &[4; 32], &[5; 32], &[6; 32], 7, 8),
            transcript(host, &old, &request, &csr, &[3; 32], &[5; 32], &[6; 32], 7, 8),
            transcript(host, &old, &request, &csr, &[4; 32], &[3; 32], &[6; 32], 7, 8),
            transcript(host, &old, &request, &csr, &[4; 32], &[5; 32], &[3; 32], 7, 8),
            transcript(host, &old, &request, &csr, &[4; 32], &[5; 32], &[6; 32], 8, 8),
            transcript(host, &old, &request, &csr, &[4; 32], &[5; 32], &[6; 32], 7, 9),
        ] {
            assert_ne!(base, changed);
        }
        assert!(base.starts_with(b"infraternal/remote-recovery/proof/v1\0"));
    }

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

    #[tokio::test]
    async fn recovery_parser_rejects_unknown_fields_and_oversized_frames_before_decode() {
        let (channel, mut peer) = tokio::io::duplex(4096);
        let channel = Duplex(tokio::sync::Mutex::new(channel));
        let mut unknown = serde_json::to_vec(&RecoveryRequest::Challenge {
            host_id: Uuid::from_u128(42),
            predecessor_fingerprint: [1; 32],
            request_id: [2; 32],
            csr_digest: [3; 32],
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
        let length = u32::try_from(MAX_FRAME_BYTES + 1)
            .unwrap()
            .to_be_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut peer, &length)
            .await
            .unwrap();
        assert!(read_request(&channel).await.is_err());
    }
}
