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

    /// The longest signature this algorithm produces: 64 bytes for Ed25519,
    /// 72 for a DER ECDSA P-256 signature (two 33-byte INTEGERs and their headers).
    /// Callers refuse longer input before any storage is read.
    #[must_use]
    pub const fn max_signature_bytes(self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::P256 => 72,
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

/// A validated public identity key, in the raw form the database stores.
///
/// - `Ed25519`: the 32-byte key (RFC 8032), as every certificate stored before #580.
/// - `P256`: the 65-byte uncompressed SEC1 point `04 || X || Y`, checked to lie
///   on the curve when it is built from bytes.
///
/// Its [`IdentityKey::digest`] is SHA-256 of exactly those bytes. For Ed25519
/// that is the digest invitations and approvals have always bound, so existing
/// invitations stay valid. A P-256 digest covers 65 bytes and an Ed25519 one
/// 32, so no key of one algorithm can carry the other's digest.
#[derive(Clone, PartialEq, Eq)]
pub enum IdentityKey {
    /// A host key: the raw Ed25519 public key.
    Ed25519([u8; 32]),
    /// A device key: the uncompressed P-256 point.
    P256([u8; 65]),
}

impl std::fmt::Debug for IdentityKey {
    /// Public keys are not secret, but they are long; print the algorithm and digest prefix.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let digest = self.digest();
        write!(
            formatter,
            "IdentityKey({}, sha256:{:02x}{:02x}{:02x}{:02x}…)",
            self.algorithm().as_str(),
            digest[0],
            digest[1],
            digest[2],
            digest[3]
        )
    }
}

impl IdentityKey {
    /// The key's algorithm.
    #[must_use]
    pub fn algorithm(&self) -> KeyAlgorithm {
        match self {
            Self::Ed25519(_) => KeyAlgorithm::Ed25519,
            Self::P256(_) => KeyAlgorithm::P256,
        }
    }

    /// The raw bytes the database stores in `public_key`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(key) => key,
            Self::P256(point) => point,
        }
    }

    /// SHA-256 of [`Self::as_bytes`]: the key digest invitations, approvals
    /// and recovery bind (see the type's docs for why it cannot collide across algorithms).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(self.as_bytes()).into()
    }

    /// Builds a key from `bytes` of `algorithm`, or `None` unless they are
    /// exactly that algorithm's raw form. A P-256 point must also be
    /// uncompressed and lie on the curve, so a stored key that OpenSSL would
    /// refuse later is refused here first.
    #[must_use]
    pub fn from_raw(algorithm: KeyAlgorithm, bytes: &[u8]) -> Option<Self> {
        match algorithm {
            KeyAlgorithm::Ed25519 => bytes.try_into().ok().map(Self::Ed25519),
            KeyAlgorithm::P256 => {
                let point: [u8; 65] = bytes.try_into().ok()?;
                let key = Self::P256(point);
                (point[0] == 4 && key.to_public_key().is_some()).then_some(key)
            }
        }
    }

    /// Builds a key from a row's `key_algorithm` and `public_key` columns, or
    /// `None` when either is not canonical. Callers treat `None` as a refusal.
    #[must_use]
    pub fn from_stored(algorithm: &str, bytes: &[u8]) -> Option<Self> {
        Self::from_raw(KeyAlgorithm::from_stored(algorithm)?, bytes)
    }

    /// Reads an OpenSSL public key of either algorithm. Anything else (another
    /// curve, RSA, X25519) is `None`.
    #[must_use]
    pub fn from_public_key<T: openssl::pkey::HasPublic>(
        key: &openssl::pkey::PKeyRef<T>,
    ) -> Option<Self> {
        use openssl::pkey::Id;
        match key.id() {
            Id::ED25519 => Self::from_raw(KeyAlgorithm::Ed25519, &key.raw_public_key().ok()?),
            Id::EC => {
                let ec = key.ec_key().ok()?;
                if ec.group().curve_name() != Some(openssl::nid::Nid::X9_62_PRIME256V1) {
                    return None;
                }
                let mut context = openssl::bn::BigNumContext::new().ok()?;
                let point = ec
                    .public_key()
                    .to_bytes(
                        ec.group(),
                        openssl::ec::PointConversionForm::UNCOMPRESSED,
                        &mut context,
                    )
                    .ok()?;
                Self::from_raw(KeyAlgorithm::P256, &point)
            }
            _ => None,
        }
    }

    /// Whether `signature` is this key's signature over `message`.
    ///
    /// Ed25519 takes exactly 64 bytes and signs the whole message (RFC 8032).
    /// P-256 takes one strict DER `ECDSA-Sig-Value` of at most 72 bytes over
    /// SHA-256 of the message, the form a Secure Enclave and ring produce; the
    /// fixed-width `r || s` form is refused. Any other input is `false`, never an error.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        use openssl::{hash::MessageDigest, sign::Verifier};
        let shape = match self {
            Self::Ed25519(_) => signature.len() == 64,
            Self::P256(_) => crate::csr::ecdsa_signature_is_der(signature),
        };
        if !shape {
            return false;
        }
        let Some(key) = self.to_public_key() else {
            return false;
        };
        let verifier = match self {
            // Ed25519 verifies the complete message in one operation.
            Self::Ed25519(_) => Verifier::new_without_digest(&key),
            Self::P256(_) => Verifier::new(MessageDigest::sha256(), &key),
        };
        verifier
            .and_then(|mut verifier| verifier.verify_oneshot(signature, message))
            .unwrap_or(false)
    }

    /// The OpenSSL public key for verifying signatures, or `None` if the bytes
    /// are not a valid key (for P-256: not a point on the curve).
    #[must_use]
    pub fn to_public_key(&self) -> Option<openssl::pkey::PKey<openssl::pkey::Public>> {
        match self {
            Self::Ed25519(key) => {
                openssl::pkey::PKey::public_key_from_raw_bytes(key, openssl::pkey::Id::ED25519).ok()
            }
            Self::P256(point) => {
                let group =
                    openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
                        .ok()?;
                let mut context = openssl::bn::BigNumContext::new().ok()?;
                // `from_bytes` refuses points that are not on the curve.
                let point = openssl::ec::EcPoint::from_bytes(&group, point, &mut context).ok()?;
                let key = openssl::ec::EcKey::from_public_key(&group, &point).ok()?;
                key.check_key().ok()?;
                openssl::pkey::PKey::from_ec_key(key).ok()
            }
        }
    }
}

/// Tests for this module's types, for both algorithms.
#[cfg(test)]
mod tests {
    use super::{IdentityKey, KeyAlgorithm};

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

    /// A software P-256 key's 65-byte point: the stand-in for a Secure Enclave key.
    fn p256_point() -> Vec<u8> {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let key = openssl::ec::EcKey::generate(&group).unwrap();
        let mut context = openssl::bn::BigNumContext::new().unwrap();
        key.public_key()
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut context,
            )
            .unwrap()
    }

    /// Keys round-trip through their stored form, OpenSSL and back, and the
    /// Ed25519 digest is the SHA-256 of the raw key that invitations always bound.
    #[test]
    fn keys_round_trip_and_keep_the_ed25519_digest() {
        use sha2::{Digest, Sha256};
        let ed25519 = openssl::pkey::PKey::generate_ed25519().unwrap();
        let raw = ed25519.raw_public_key().unwrap();
        let key = IdentityKey::from_stored("ed25519", &raw).unwrap();
        assert_eq!(key.digest(), <[u8; 32]>::from(Sha256::digest(&raw)));
        assert_eq!(
            IdentityKey::from_public_key(&key.to_public_key().unwrap()),
            Some(key)
        );
        let point = p256_point();
        let key = IdentityKey::from_stored("p256", &point).unwrap();
        assert_eq!(key.algorithm(), KeyAlgorithm::P256);
        assert_eq!(key.as_bytes(), point.as_slice());
        assert_eq!(key.digest(), <[u8; 32]>::from(Sha256::digest(&point)));
        assert_eq!(
            IdentityKey::from_public_key(&key.to_public_key().unwrap()),
            Some(key)
        );
    }

    /// Bytes of the wrong length or algorithm, compressed points and points
    /// off the curve are refused, and other curves never become identity keys.
    #[test]
    fn wrong_lengths_forms_and_curves_are_refused() {
        let point = p256_point();
        assert!(IdentityKey::from_stored("ed25519", &point).is_none());
        assert!(IdentityKey::from_stored("p256", &point[..32]).is_none());
        assert!(IdentityKey::from_stored("p256", &[[4].as_slice(), &[0; 64]].concat()).is_none());
        let mut compressed = point.clone();
        compressed[0] = 2;
        assert!(IdentityKey::from_stored("p256", &compressed).is_none());
        let mut off_curve = point;
        off_curve[64] ^= 1;
        assert!(IdentityKey::from_stored("p256", &off_curve).is_none());
        assert!(IdentityKey::from_stored("rsa", &[0; 32]).is_none());
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP384R1).unwrap();
        let p384 = openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap())
            .unwrap();
        assert!(IdentityKey::from_public_key(&p384).is_none());
        let x25519 = openssl::pkey::PKey::generate_x25519().unwrap();
        assert!(IdentityKey::from_public_key(&x25519).is_none());
    }

    /// Signatures verify only under their own key and algorithm, in their
    /// canonical shape: a ring P-256 signature verifies, a raw `r || s` one,
    /// a flipped bit and an Ed25519 signature on a P-256 key do not.
    #[test]
    fn signatures_verify_only_in_their_own_shape() {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
        let random = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random)
                .unwrap();
        let key = IdentityKey::from_raw(KeyAlgorithm::P256, pair.public_key().as_ref()).unwrap();
        let message = b"infraternal recovery transcript";
        let signature = pair.sign(&random, message).unwrap().as_ref().to_vec();
        assert!(signature.len() <= KeyAlgorithm::P256.max_signature_bytes());
        assert!(key.verify(message, &signature));
        assert!(!key.verify(b"another transcript", &signature));
        let mut flipped = signature.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(!key.verify(message, &flipped));
        let parsed = openssl::ecdsa::EcdsaSig::from_der(&signature).unwrap();
        let raw = [
            parsed.r().to_vec_padded(32).unwrap(),
            parsed.s().to_vec_padded(32).unwrap(),
        ]
        .concat();
        assert!(!key.verify(message, &raw));
        assert!(!key.verify(message, &[signature.as_slice(), &[0]].concat()));

        let ed25519 = openssl::pkey::PKey::generate_ed25519().unwrap();
        let ed_signature = openssl::sign::Signer::new_without_digest(&ed25519)
            .unwrap()
            .sign_oneshot_to_vec(message)
            .unwrap();
        let ed_key =
            IdentityKey::from_raw(KeyAlgorithm::Ed25519, &ed25519.raw_public_key().unwrap())
                .unwrap();
        assert!(ed_key.verify(message, &ed_signature));
        assert!(!key.verify(message, &ed_signature));
        assert!(!ed_key.verify(message, &signature));
        assert!(!ed_key.verify(message, &ed_signature[..63]));
    }
}
