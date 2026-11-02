//! Proves the retained host key and validates atomic certificate publication on the authenticated control stream [133][168], #78.

use crate::remote_tls::Identity;
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    x509::{X509, X509NameBuilder, X509Req, X509StoreContext, store::X509StoreBuilder},
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    sync::{Arc, RwLock},
};

/// Additive Hello capability: only peers with this bit receive renewal actions.
pub use infraternal_plugin_api::channel::LIVE_RENEWAL;
/// Bound before decoding JSON as well as after decoding the DER field.
pub use infraternal_plugin_api::channel::MAX_CONTROL_JSON as MAX_RENEWAL_JSON;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsrProof {
    pub csr_der: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateUpdate {
    pub certificate_der: Vec<u8>,
}

/// Decode bounded proof JSON; accepted bytes still require PKCS10 verification.
/// # Errors
/// Oversized JSON/DER, malformed fields or unknown fields.
pub fn decode_proof(input: &[u8]) -> io::Result<CsrProof> {
    if input.len() > MAX_RENEWAL_JSON {
        return Err(denied());
    }
    let proof: CsrProof = serde_json::from_slice(input).map_err(|_| denied())?;
    if proof.csr_der.len() > 4096 {
        return Err(denied());
    }
    Ok(proof)
}

/// Decode bounded public identity JSON; this grants no certificate authority.
/// # Errors
/// Oversized JSON/DER, malformed fields or unknown fields.
pub fn decode_certificate(input: &[u8]) -> io::Result<CertificateUpdate> {
    if input.len() > MAX_RENEWAL_JSON {
        return Err(denied());
    }
    let update: CertificateUpdate = serde_json::from_slice(input).map_err(|_| denied())?;
    if update.certificate_der.len() > 8192 {
        return Err(denied());
    }
    Ok(update)
}

/// Installation adapter durably publishes public identity before success is acknowledged.
pub trait CertificatePublisher: Send + Sync {
    /// Fsync and atomically replace the installation's certificate.
    /// # Errors
    /// Unsafe paths, invalid metadata, serialization or publication failure.
    fn publish(&self, certificate: &X509) -> io::Result<()>;
}

/// One process owns the current leaf; reconnects read the acknowledged replacement.
#[derive(Clone)]
pub struct RenewalIdentity {
    identity: Arc<RwLock<Identity>>,
    roots: Vec<X509>,
    publisher: Arc<dyn CertificatePublisher>,
    rotation: Option<crate::identity_rotation::IdentityRotation>,
}
impl RenewalIdentity {
    /// Retain the host key, public pins and the installation publication adapter.
    #[must_use]
    pub fn new(
        identity: &Identity,
        roots: &[X509],
        publisher: Arc<dyn CertificatePublisher>,
    ) -> Self {
        Self {
            identity: Arc::new(RwLock::new(Identity {
                certificate: identity.certificate.clone(),
                key: identity.key.clone(),
            })),
            roots: roots.to_vec(),
            publisher,
            rotation: None,
        }
    }
    /// Enable rotation only when the installation supplies durable private-state publication.
    /// # Errors
    /// Refuses malformed or inconsistent pending rotation state.
    pub fn enable_identity_rotation(
        &mut self,
        publisher: Arc<dyn crate::identity_rotation::RotationPublisher>,
    ) -> io::Result<()> {
        let predecessor = self.current()?;
        let (rotation, current) =
            crate::identity_rotation::IdentityRotation::new(&predecessor, &self.roots, publisher)?;
        *self.identity.write().map_err(|_| denied())? = current;
        self.rotation = Some(rotation);
        Ok(())
    }

    /// Whether the installed host can durably stage and acknowledge a candidate key.
    #[must_use]
    pub fn supports_identity_rotation(&self) -> bool {
        self.rotation
            .as_ref()
            .is_some_and(crate::identity_rotation::IdentityRotation::supports_rotation)
    }
    /// Return the retained predecessor only while an unacknowledged candidate is active.
    /// # Errors
    /// Refuses poisoned or concurrently publishing identity state.
    pub fn predecessor_for(&self) -> io::Result<Option<Identity>> {
        let Some(rotation) = &self.rotation else {
            return Ok(None);
        };
        rotation.predecessor_for(&self.current()?)
    }
    /// Snapshot the current acknowledged leaf without exposing the key to the peer.
    /// # Errors
    /// Refuses poisoned identity state; returns `WouldBlock` during publication.
    pub fn current(&self) -> io::Result<Identity> {
        // A publisher may be waiting for storage while holding the writer.
        // Reconnect runs on an async executor: never park that executor on this
        // synchronous lock, or its timeout/watchdog cannot run either.
        let identity = self.identity.try_read().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
            std::sync::TryLockError::Poisoned(_) => denied(),
        })?;
        Ok(Identity {
            certificate: identity.certificate.clone(),
            key: identity.key.clone(),
        })
    }
    /// Recover an expired certificate without presenting it to the normal mTLS listener.
    /// The response is checked against pinned roots and published before reconnect can use it.
    /// # Errors
    /// Refuses unavailable or denied recovery, invalid certificate metadata, changed identity,
    /// transport failure, or failed durable publication.
    pub async fn recover(
        &self,
        address: std::net::SocketAddr,
        server_name: &str,
    ) -> io::Result<()> {
        let current = self.current()?;
        let certificate =
            crate::remote_recovery::exchange(address, server_name, &current, &self.roots).await?;
        let verify_at = epoch_seconds(certificate.not_before())?;
        let mut identity = self.identity.try_write().map_err(|error| match error {
            std::sync::TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
            std::sync::TryLockError::Poisoned(_) => denied(),
        })?;
        if identity
            .certificate
            .digest(MessageDigest::sha256())
            .map_err(|_| denied())?
            .as_ref()
            != current
                .certificate
                .digest(MessageDigest::sha256())
                .map_err(|_| denied())?
                .as_ref()
        {
            return Err(denied());
        }
        validate_at(&certificate, &identity, &self.roots, Some(verify_at), true)?;
        self.publisher.publish(&certificate)?;
        identity.certificate = certificate;
        Ok(())
    }
    /// Only the pinned server can invoke these two control actions.
    /// # Errors
    /// Malformed/oversized input, altered host/key, invalid issuer/purpose/validity or failed publication.
    pub fn action(&self, action: &str, input: &[u8]) -> io::Result<Vec<u8>> {
        if input.len() > MAX_RENEWAL_JSON {
            return Err(denied());
        }
        if matches!(
            action,
            "transport.csr.rotate"
                | "transport.identity.rotate.certificate"
                | "transport.identity.rotate.ack"
        ) {
            return self.rotation.as_ref().ok_or_else(denied)?.action(
                &self.identity,
                action,
                input,
            );
        }
        match action {
            "transport.csr" => {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Empty {}
                serde_json::from_slice::<Empty>(input).map_err(|_| denied())?;
                let identity = self.current()?;
                let mut request = X509Req::builder().map_err(|_| denied())?;
                request
                    .set_subject_name(&X509NameBuilder::new().map_err(|_| denied())?.build())
                    .map_err(|_| denied())?;
                request.set_pubkey(&identity.key).map_err(|_| denied())?;
                request
                    .sign(&identity.key, MessageDigest::null())
                    .map_err(|_| denied())?;
                serde_json::to_vec(&CsrProof {
                    csr_der: request.build().to_der().map_err(|_| denied())?,
                })
                .map_err(|_| denied())
            }
            "transport.certificate" => {
                let update = decode_certificate(input)?;
                let certificate = X509::from_der(&update.certificate_der).map_err(|_| denied())?;
                if certificate.to_der().map_err(|_| denied())? != update.certificate_der {
                    return Err(denied());
                }
                let mut identity = self.identity.write().map_err(|_| denied())?;
                validate(&certificate, &identity, &self.roots)?;
                // Validation and publication serialize with reconnect snapshots.
                // A failed fsync/rename leaves process authority unchanged.
                self.publisher.publish(&certificate)?;
                identity.certificate = certificate;
                if let Some(rotation) = &self.rotation {
                    rotation.renewed_certificate(&identity.certificate)?;
                }
                Ok(b"{}".to_vec())
            }
            _ => Err(denied()),
        }
    }
}

fn validate(certificate: &X509, identity: &Identity, roots: &[X509]) -> io::Result<()> {
    validate_at(certificate, identity, roots, None, false)
}

fn validate_at(
    certificate: &X509,
    identity: &Identity,
    roots: &[X509],
    verify_at: Option<i64>,
    recovering: bool,
) -> io::Result<()> {
    let mut trust = X509StoreBuilder::new().map_err(|_| denied())?;
    for issuer in roots {
        trust.add_cert(issuer.clone()).map_err(|_| denied())?;
    }
    trust
        .set_purpose(openssl::x509::X509PurposeId::SSL_CLIENT)
        .map_err(|_| denied())?;
    if let Some(verify_at) = verify_at {
        let mut parameters = openssl::x509::verify::X509VerifyParam::new().map_err(|_| denied())?;
        parameters.set_time(verify_at);
        trust.set_param(&parameters).map_err(|_| denied())?;
    }
    let chain = openssl::stack::Stack::new().map_err(|_| denied())?;
    if !X509StoreContext::new()
        .map_err(|_| denied())?
        .init(
            &trust.build(),
            certificate,
            &chain,
            openssl::x509::X509StoreContextRef::verify_cert,
        )
        .map_err(|_| denied())?
        || !certificate
            .public_key()
            .map_err(|_| denied())?
            .public_eq(&identity.key)
        || host_uri(certificate)? != host_uri(&identity.certificate)?
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
        || certificate.not_after() <= identity.certificate.not_after()
        || (recovering && certificate.not_before() < identity.certificate.not_after())
    {
        return Err(denied());
    }
    Ok(())
}

fn epoch_seconds(time: &openssl::asn1::Asn1TimeRef) -> io::Result<i64> {
    let epoch = Asn1Time::from_unix(0).map_err(|_| denied())?;
    let difference = epoch.diff(time).map_err(|_| denied())?;
    i64::from(difference.days)
        .checked_mul(86_400)
        .and_then(|days| days.checked_add(i64::from(difference.secs)))
        .ok_or_else(denied)
}
fn host_uri(certificate: &X509) -> io::Result<String> {
    let names = certificate.subject_alt_names().ok_or_else(denied)?;
    if names.len() != 1 {
        return Err(denied());
    }
    names[0].uri().map(str::to_owned).ok_or_else(denied)
}
/// Refuse an expired local identity before another dial attempt, rather than retrying it forever.
/// # Errors
/// Invalid clock/certificate or expired identity.
pub fn require_current(identity: &Identity) -> io::Result<()> {
    let now = Asn1Time::days_from_now(0).map_err(|_| denied())?;
    if identity.certificate.not_after() <= now.as_ref()
        || identity.certificate.not_before() > now.as_ref()
    {
        return Err(denied());
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
    fn unix_time_conversion_uses_time_after_epoch() {
        let expected = 1_900_000_000;
        let time = Asn1Time::from_unix(expected).unwrap();
        assert_eq!(epoch_seconds(time.as_ref()).unwrap(), expected);
    }

    struct Publisher;
    impl CertificatePublisher for Publisher {
        fn publish(&self, _: &X509) -> io::Result<()> {
            Ok(())
        }
    }

    /// Publication can hold the writer while storage is slow. Snapshotting from
    /// an async reconnect task must yield an error, never park its runtime thread.
    #[test]
    fn credential_snapshot_does_not_block_async_reconnect() {
        let ca = crate::remote_tls::tests::root();
        let identity = crate::remote_tls::tests::leaf(&ca, false);
        let renewal = RenewalIdentity::new(&identity, &[ca.certificate], Arc::new(Publisher));
        let writer = renewal.identity.write().unwrap();
        let reading = renewal.clone();
        let (done, completion) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            done.send(reading.current().map(|_| ()).map_err(|error| error.kind()))
                .unwrap();
        });
        let result = completion.recv_timeout(std::time::Duration::from_secs(5));
        // Release the fixture writer even if the regression blocks the reader.
        drop(writer);
        thread.join().unwrap();
        assert_eq!(result.unwrap(), Err(io::ErrorKind::WouldBlock));
    }
}
