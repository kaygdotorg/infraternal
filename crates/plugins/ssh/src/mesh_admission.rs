//! Checks authenticated certificate claims against current mesh and login access [D235], #221.
//!
//! This is the authorization boundary AFTER protocol verification, not a
//! certificate parser or signature verifier. The SSH adapter must first verify
//! the trusted issuer, user-certificate type, principal, critical options and
//! possession of its key. No production adapter is wired until the protocol
//! engine is selected and every shell path enforces login access together.

use std::net::IpAddr;

/// Upper bound for issued person certificates; issuance defaults to this value.
pub const MAX_CERTIFICATE_SECONDS: u64 = 24 * 60 * 60;

/// Public, authenticated fields extracted by the protocol adapter.
/// Source binding is an exact address, not a client-selected network prefix.
#[derive(Clone, Copy)]
pub struct CertificateClaims<'a> {
    /// Digest of the entire signed certificate, not its client-controlled serial.
    pub fingerprint: [u8; 32],
    /// The person the certificate was issued to.
    pub person: &'a str,
    /// Mesh node the certificate is bound to.
    pub source_node: u64,
    /// The one exact client address the certificate is valid from.
    pub source_address: IpAddr,
    /// First valid second (Unix time, inclusive).
    pub valid_after: u64,
    /// End of validity (Unix time, exclusive).
    pub valid_before: u64,
}

/// Socket observation and resolved target account, never client environment data.
#[derive(Clone, Copy)]
pub struct LoginRequest<'a> {
    /// Peer address seen on the accepted TCP connection.
    pub source_address: IpAddr,
    /// Mesh node of the host being logged into.
    pub target_node: u64,
    /// Local OS account the target host resolved for this login.
    pub target_account: &'a str,
}

/// One current authority view held under admission/revocation serialization.
///
/// Implementations must not cache a successful admission across authentications
/// or channel opens. Keep the authority guard alive through session creation;
/// releasing it after this function and before opening a session leaves a
/// revocation race. Missing or unreadable authority returns None/false.
pub trait CurrentAccess {
    /// Resolve an observed address through applied, admitted mesh membership.
    fn source_node(&self, address: IpAddr) -> Option<u64>;

    /// Require this exact certificate digest to be bound to this person, source
    /// node and address, with its person, node AND account link still enabled.
    /// A valid signature alone does not satisfy this check.
    fn certificate_current(&self, certificate: &CertificateClaims<'_>) -> bool;

    /// Evaluate current network access for the original SSH TCP/22 service.
    /// The redirect listener's internal port never enters this check.
    fn network_access(&self, source_node: u64, target_node: u64, tcp_port: u16) -> bool;

    /// Evaluate explicit person-to-host/account login rules with no hidden
    /// administrator exception; the account was resolved by the target host.
    fn login_access(&self, person: &str, target_node: u64, account: &str) -> bool;
}

/// Fixed internal reason codes. Adapters must not expose identity diagnostics
/// to unauthenticated peers; audit may record the reason without key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Empty person or account, or a certificate that failed protocol-level checks.
    InvalidClaims,
    /// Lifetime is zero, reversed or over [`MAX_CERTIFICATE_SECONDS`], or `now` is outside it.
    CertificateTime,
    /// Peer address differs from the certificate's, or maps to a different mesh node.
    Source,
    /// The certificate is not currently registered or one of its links is disabled.
    Revoked,
    /// Mesh network rules do not allow source node to reach the target on TCP/22.
    NetworkAccess,
    /// No explicit login rule lets this person use the target account.
    LoginAccess,
}

/// Validate authenticated claims and both access checks for one admission.
/// `now` is trusted Unix time from the host, never supplied by the SSH peer.
/// No reusable session permission is returned; later channel opens recheck.
///
/// # Errors
/// Refuses invalid time/source bindings, unavailable/revoked identity, or either
/// missing access permission. Protocol verification is a caller precondition.
pub fn admit_certificate_claims(
    access: &impl CurrentAccess,
    certificate: &CertificateClaims<'_>,
    request: LoginRequest<'_>,
    now: u64,
) -> Result<(), Refusal> {
    if certificate.person.is_empty() || request.target_account.is_empty() {
        return Err(Refusal::InvalidClaims);
    }
    // Subtraction is checked: a reversed interval must not wrap into a valid
    // duration. The end is exclusive, including exactly the expiry second.
    let lifetime = certificate
        .valid_before
        .checked_sub(certificate.valid_after)
        .filter(|seconds| (1..=MAX_CERTIFICATE_SECONDS).contains(seconds));
    if lifetime.is_none() || now < certificate.valid_after || now >= certificate.valid_before {
        return Err(Refusal::CertificateTime);
    }
    if request.source_address != certificate.source_address
        || access.source_node(request.source_address) != Some(certificate.source_node)
    {
        return Err(Refusal::Source);
    }
    if !access.certificate_current(certificate) {
        return Err(Refusal::Revoked);
    }
    if !access.network_access(certificate.source_node, request.target_node, 22) {
        return Err(Refusal::NetworkAccess);
    }
    if !access.login_access(
        certificate.person,
        request.target_node,
        request.target_account,
    ) {
        return Err(Refusal::LoginAccess);
    }
    Ok(())
}

#[cfg(test)]
#[path = "mesh_admission_tests.rs"]
mod tests;
