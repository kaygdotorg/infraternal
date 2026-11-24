//! The key algorithms a host or device identity may use (#580, client-core plan §7).
//!
//! Every Linux and macOS host proves its leg-B identity with an Ed25519 key.
//! An iPhone keeps its identity key in the Secure Enclave, which holds only
//! ECDSA P-256 keys, so the server learns a second algorithm. Which identities
//! may use which algorithm is policy decided by the caller (an invitation
//! names the one algorithm its key must use); this module only names them.

/// The signature algorithm of an identity key.
///
/// The stored spelling ([`KeyAlgorithm::as_str`]) is what the database's
/// `key_algorithm` columns hold, so it must never change for an existing variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// Ed25519 (RFC 8410): every host identity, and the only algorithm before #580.
    Ed25519,
    /// ECDSA over P-256 with SHA-256 (RFC 5480, RFC 5758): device identities
    /// whose key lives in a Secure Enclave.
    P256,
}

impl KeyAlgorithm {
    /// The canonical stored spelling: `ed25519` or `p256`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::P256 => "p256",
        }
    }

    /// Reads a stored spelling back. Anything but the two canonical spellings
    /// is `None`, so a corrupted row fails closed instead of picking a default.
    #[must_use]
    pub fn from_stored(stored: &str) -> Option<Self> {
        match stored {
            "ed25519" => Some(Self::Ed25519),
            "p256" => Some(Self::P256),
            _ => None,
        }
    }
}

/// Tests for this module's types, for both algorithms.
#[cfg(test)]
mod tests {
    use super::KeyAlgorithm;

    /// The stored spellings round-trip, and near misses are refused rather than mapped.
    #[test]
    fn stored_spellings_round_trip_and_near_misses_are_refused() {
        for algorithm in [KeyAlgorithm::Ed25519, KeyAlgorithm::P256] {
            assert_eq!(
                KeyAlgorithm::from_stored(algorithm.as_str()),
                Some(algorithm)
            );
        }
        for stored in ["", "Ed25519", "P256", "p-256", "ecdsa", "ed25519 "] {
            assert_eq!(KeyAlgorithm::from_stored(stored), None, "{stored:?}");
        }
    }
}
