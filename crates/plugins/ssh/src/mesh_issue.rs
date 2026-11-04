//! Builds the person and host SSH certificates that mesh SSH trusts [D235, D289], #221.
//!
//! This module owns the certificate *shape*; the server's CA owns the key. The
//! caller passes a signing function over the certificate body, so the CA key
//! never leaves the server's CA module and this crate never holds it.
//!
//! Invariants (security review):
//! - A person certificate has exactly one principal (the person's stable ID),
//!   exactly one critical option, `source-address=<one mesh address>/32` (or
//!   `/128`), and only the `permit-pty` extension. `mesh_certificate::verify`
//!   on the target refuses anything else, so the two must change together.
//! - Lifetime is between one hour and 24 hours (D235 Q2b). The validity start
//!   is set back by [`CLOCK_SKEW`] for clock differences between server and
//!   target, and the end is measured from that start, so the whole interval
//!   never exceeds the target's 24-hour admission bound.
//! - A host certificate always names at least one principal: an empty list
//!   would be valid for every host name.
//! - Every certificate is validated against the named CA key right after
//!   signing, so a signer that is not that CA is caught before anything is
//!   handed out.
//! - The signer only ever receives a body that starts with
//!   [`CERTIFICATE_BODY_PREFIX`]; the server's CA checks that prefix too, so
//!   the shared Ed25519 key cannot be used through this path to sign
//!   anything else (an X.509 body starts with a DER `0x30`).

use russh::keys::{
    Algorithm, HashAlg,
    signature::{self, Signer},
    ssh_key::{
        Signature,
        certificate::{Builder, CertType},
        public::{Ed25519PublicKey, KeyData},
    },
};
/// The key and certificate types callers of the issuer handle, re-exported
/// so they need no direct dependency on the SSH engine.
pub use russh::keys::{Certificate, PublicKey};
use std::net::IpAddr;

/// Longest certificate lifetime (D235 Q2b), also the default.
pub const MAX_LIFETIME: u64 = 24 * 60 * 60;
/// Shortest administrator-selectable lifetime (D235 Q2b).
pub const MIN_LIFETIME: u64 = 60 * 60;
/// How far the validity start is set back for clock differences.
pub const CLOCK_SKEW: u64 = 5 * 60;
/// Every Ed25519 SSH certificate body starts with its type name as an SSH
/// string: a four-byte length (32) and `ssh-ed25519-cert-v01@openssh.com`.
pub const CERTIFICATE_BODY_PREFIX: &[u8] = b"\0\0\0\x20ssh-ed25519-cert-v01@openssh.com";

/// The CA's signing function: an Ed25519 signature over `body`, or `None`
/// when the CA is locked or refuses.
pub type SignBody<'a> = dyn Fn(&[u8]) -> Option<[u8; 64]> + 'a;

/// Content-free: issuance failures never carry key material or names.
#[derive(Debug, PartialEq, Eq)]
pub struct IssueError;
impl std::fmt::Display for IssueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SSH certificate unavailable")
    }
}
impl std::error::Error for IssueError {}

/// What a person certificate binds: a key, a person and the one mesh address
/// of the node it was issued to.
pub struct PersonRequest<'a> {
    pub subject: &'a PublicKey,
    /// The person's stable ID, never a username or display name.
    pub person: &'a str,
    pub source_address: IpAddr,
    /// Trusted server time, Unix seconds.
    pub now: u64,
    pub lifetime: u64,
}

/// What a host certificate binds: the host's key and its mesh names and addresses.
pub struct HostRequest<'a> {
    pub subject: &'a PublicKey,
    pub principals: &'a [String],
    pub now: u64,
    pub lifetime: u64,
}

/// Adapts the caller's signing function to the certificate builder.
struct CaSigner<'a> {
    public: Ed25519PublicKey,
    sign: &'a SignBody<'a>,
}
impl Signer<Signature> for CaSigner<'_> {
    fn try_sign(&self, body: &[u8]) -> Result<Signature, signature::Error> {
        if !body.starts_with(CERTIFICATE_BODY_PREFIX) {
            return Err(signature::Error::new());
        }
        let bytes = (self.sign)(body).ok_or_else(signature::Error::new)?;
        Signature::new(Algorithm::Ed25519, bytes.to_vec()).map_err(|_| signature::Error::new())
    }
}
impl From<&CaSigner<'_>> for KeyData {
    fn from(signer: &CaSigner<'_>) -> Self {
        Self::Ed25519(signer.public)
    }
}

/// A builder with a random nonce and a validity set back by [`CLOCK_SKEW`].
fn builder(subject: &PublicKey, now: u64, lifetime: u64) -> Result<Builder, IssueError> {
    if !(MIN_LIFETIME..=MAX_LIFETIME).contains(&lifetime) {
        return Err(IssueError);
    }
    let start = now.checked_sub(CLOCK_SKEW).ok_or(IssueError)?;
    let end = start.checked_add(lifetime).ok_or(IssueError)?;
    Builder::new_with_random_nonce(
        &mut russh::keys::key::safe_rng(),
        subject.key_data().clone(),
        start,
        end,
    )
    .map_err(|_| IssueError)
}

/// Sign with the CA and validate the result against that same CA key.
fn sign(builder: Builder, ca: [u8; 32], sign: &SignBody<'_>) -> Result<Certificate, IssueError> {
    let signer = CaSigner {
        public: Ed25519PublicKey(ca),
        sign,
    };
    let certificate = builder.sign(&signer).map_err(|_| IssueError)?;
    let fingerprint = KeyData::from(&signer).fingerprint(HashAlg::Sha256);
    certificate
        .validate_at(certificate.valid_after(), [&fingerprint])
        .map_err(|_| IssueError)?;
    Ok(certificate)
}

/// A person certificate for mesh SSH, signed by the CA whose Ed25519 public
/// key is `ca`.
///
/// # Errors
/// Refuses an empty person, a lifetime outside 1–24 h, a locked CA or a
/// signature that does not verify under `ca`.
pub fn person_certificate(
    ca: [u8; 32],
    sign_body: &SignBody<'_>,
    request: &PersonRequest<'_>,
) -> Result<Certificate, IssueError> {
    if request.person.is_empty() {
        return Err(IssueError);
    }
    let prefix = if request.source_address.is_ipv4() {
        32
    } else {
        128
    };
    let mut builder = builder(request.subject, request.now, request.lifetime)?;
    builder
        .cert_type(CertType::User)
        .and_then(|builder| builder.key_id(format!("infraternal person {}", request.person)))
        .and_then(|builder| builder.valid_principal(request.person))
        .and_then(|builder| {
            builder.critical_option(
                "source-address",
                format!("{}/{prefix}", request.source_address),
            )
        })
        .and_then(|builder| builder.extension("permit-pty", ""))
        .map_err(|_| IssueError)?;
    sign(builder, ca, sign_body)
}

/// A host certificate for a node's embedded SSH server, so clients trust it
/// through `@cert-authority` with no host-key prompt (D235 Q2).
///
/// # Errors
/// Refuses no principals, a lifetime outside 1–24 h, a locked CA or a
/// signature that does not verify under `ca`.
pub fn host_certificate(
    ca: [u8; 32],
    sign_body: &SignBody<'_>,
    request: &HostRequest<'_>,
) -> Result<Certificate, IssueError> {
    if request.principals.is_empty() || request.principals.iter().any(String::is_empty) {
        return Err(IssueError);
    }
    let mut builder = builder(request.subject, request.now, request.lifetime)?;
    builder
        .cert_type(CertType::Host)
        .and_then(|builder| builder.key_id("infraternal host"))
        .map_err(|_| IssueError)?;
    for principal in request.principals {
        builder
            .valid_principal(principal.clone())
            .map_err(|_| IssueError)?;
    }
    sign(builder, ca, sign_body)
}

/// Check an issued person certificate again, independently of how it was
/// built: user type, exactly one principal, exactly one `source-address` for
/// one address, only `permit-pty`, lifetime 1–24 h (J181 M6).
///
/// # Errors
/// Refuses any other shape.
pub fn check_person(certificate: &Certificate) -> Result<(), IssueError> {
    let options = certificate.critical_options();
    let single_address = options.len() == 1
        && options.get("source-address").is_some_and(|source| {
            source.split_once('/').is_some_and(|(address, prefix)| {
                address
                    .parse::<IpAddr>()
                    .is_ok_and(|address| prefix == if address.is_ipv4() { "32" } else { "128" })
            })
        });
    let extensions = certificate.extensions();
    if certificate.cert_type() == CertType::User
        && certificate.valid_principals().len() == 1
        && !certificate.valid_principals()[0].is_empty()
        && single_address
        && extensions.len() == 1
        && extensions.get("permit-pty").is_some_and(String::is_empty)
        && lifetime_ok(certificate)
    {
        Ok(())
    } else {
        Err(IssueError)
    }
}

/// Check an issued host certificate again: host type, at least one non-empty
/// principal, no options or extensions, lifetime 1–24 h (J181 M6).
///
/// # Errors
/// Refuses any other shape.
pub fn check_host(certificate: &Certificate) -> Result<(), IssueError> {
    if certificate.cert_type() == CertType::Host
        && !certificate.valid_principals().is_empty()
        && certificate
            .valid_principals()
            .iter()
            .all(|principal| !principal.is_empty())
        && certificate.critical_options().is_empty()
        && certificate.extensions().is_empty()
        && lifetime_ok(certificate)
    {
        Ok(())
    } else {
        Err(IssueError)
    }
}

/// Whether the validity interval is between [`MIN_LIFETIME`] and [`MAX_LIFETIME`].
fn lifetime_ok(certificate: &Certificate) -> bool {
    certificate
        .valid_before()
        .checked_sub(certificate.valid_after())
        .is_some_and(|lifetime| (MIN_LIFETIME..=MAX_LIFETIME).contains(&lifetime))
}

#[cfg(test)]
#[path = "mesh_issue_tests.rs"]
mod tests;
