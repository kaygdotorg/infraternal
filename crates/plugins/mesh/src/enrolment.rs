//! Binds saved Mesh state to the public identity of the enrolled host.

use serde::{Deserialize, Serialize};

/// The enrolment a saved configuration belongs to (#265 P2-1, #325).
///
/// A configuration is trusted only for the coordinator, host and infraternal
/// agent identity that received it. If the Mac is re-enrolled (another
/// coordinator, another host id or a new agent key) while its state directory
/// survives, restoring the old peers would re-install another mesh's keys and
/// routes and refuse every update from the new coordinator. Each field is
/// public: a SHA-256 of a certificate or public key, or the host id.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrolment {
    /// SHA-256 (hex) of the issuing coordinator's CA certificate, DER.
    coordinator: String,
    /// Host id the coordinator issued at enrolment.
    host: String,
    /// SHA-256 (hex) of the infraternal agent's mTLS public key, DER.
    agent_key: String,
}

impl Enrolment {
    /// Bind to the identity in `identity.json`, given its public parts.
    #[must_use]
    pub fn new(coordinator_ca_der: &[u8], host: &str, agent_public_key_der: &[u8]) -> Self {
        Self {
            coordinator: hex(&openssl::sha::sha256(coordinator_ca_der)),
            host: host.to_owned(),
            agent_key: hex(&openssl::sha::sha256(agent_public_key_der)),
        }
    }
}

/// Encode a public fingerprint in lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Why a Linux Mesh enrollment cannot be bound to this installation.
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
#[error("{} {}", .summary(), .recovery())]
pub enum MachineBindingError {
    /// The current installation has no persistent machine ID.
    MissingId,
    /// The saved fingerprint belongs to a different Linux installation.
    ForeignMachine,
    /// The old record has no fingerprint to establish where it was created.
    UnboundRecord,
}

#[cfg(target_os = "linux")]
impl MachineBindingError {
    /// Explain why the binding was refused without exposing either machine ID.
    #[must_use]
    pub fn summary(&self) -> &'static str {
        match self {
            Self::MissingId => "This Linux installation has no persistent machine ID.",
            Self::ForeignMachine => {
                "Saved Mesh state belongs to a different machine or an earlier Linux installation."
            }
            Self::UnboundRecord => "Saved Mesh state has no machine binding.",
        }
    }

    /// Give the operator the matching recovery action.
    #[must_use]
    pub fn recovery(&self) -> &'static str {
        match self {
            Self::MissingId => "Configure a persistent /etc/machine-id, then try again.",
            Self::ForeignMachine | Self::UnboundRecord => {
                "Use Add host to re-enroll this installation with a fresh state directory."
            }
        }
    }
}
