//! Verifies signed SSH certificates before current mesh/login admission [D235,D289].
//!
//! The registration index uses the complete signed certificate, rather than a
//! public-key fingerprint or a caller-selected serial/key identifier. The engine
//! calls this only after verifying possession of the certificate's private key.

use std::net::IpAddr;

use russh::keys::{
    Certificate,
    ssh_key::{Fingerprint, certificate::CertType},
};
use sha2::{Digest, Sha256};

use crate::mesh_admission::{
    CertificateClaims, CurrentAccess, LoginRequest, Refusal, admit_certificate_claims,
};

/// Current registration, resolved from authority rather than SSH request text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub person: String,
    pub source_node: u64,
    pub source_address: IpAddr,
}

/// The caller holds one guard through verification, admission and session open.
pub trait CertificateAccess: CurrentAccess {
    fn trusted_ca(&self) -> &Fingerprint;
    fn identity(&self, certificate_digest: &[u8; 32]) -> Option<Identity>;
}

/// Hash the entire signed certificate, including its options and validity.
/// # Errors
/// Rejects a certificate that cannot be encoded by the engine.
pub fn digest(certificate: &Certificate) -> Result<[u8; 32], Refusal> {
    let bytes = certificate.to_bytes().map_err(|_| Refusal::InvalidClaims)?;
    Ok(Sha256::digest(bytes).into())
}

/// Verify signature, issuer, person principal and exact source, then both access checks.
///
/// `request` contains the observed peer and resolved OS account. It is distinct
/// from the signed person principal: explicit login rules may allow a person to
/// use an account whose name differs from theirs. No key-id/serial convention
/// creates authority. A later session open must call this again.
/// # Errors
/// Returns fixed internal refusal codes; never expose these to an unsigned peer.
pub fn verify(
    access: &impl CertificateAccess,
    certificate: &Certificate,
    request: LoginRequest<'_>,
    now: u64,
) -> Result<Identity, Refusal> {
    let fingerprint = digest(certificate)?;
    let identity = access.identity(&fingerprint).ok_or(Refusal::Revoked)?;
    if certificate.cert_type() != CertType::User
        || !certificate
            .valid_principals()
            .iter()
            .any(|principal| principal == &identity.person)
        || certificate.validate_at(now, [access.trusted_ca()]).is_err()
        || certificate.critical_options().len() != 1
        || !certificate
            .critical_options()
            .get("source-address")
            .is_some_and(|source| exact_source(source, identity.source_address))
    {
        return Err(Refusal::InvalidClaims);
    }
    admit_certificate_claims(
        access,
        &CertificateClaims {
            fingerprint,
            person: &identity.person,
            source_node: identity.source_node,
            source_address: identity.source_address,
            valid_after: certificate.valid_after(),
            valid_before: certificate.valid_before(),
        },
        request,
        now,
    )?;
    Ok(identity)
}

fn exact_source(source: &str, expected: IpAddr) -> bool {
    let (address, prefix) = source
        .split_once('/')
        .map_or((source, None), |(address, prefix)| (address, Some(prefix)));
    address.parse::<IpAddr>() == Ok(expected)
        && prefix.is_none_or(|prefix| prefix == if expected.is_ipv4() { "32" } else { "128" })
}

#[cfg(test)]
#[path = "mesh_certificate_tests.rs"]
mod tests;
