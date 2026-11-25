//! The node's leg-B identity as TLS sees it: a certificate chain plus
//! something that can sign with the matching private key (#580, plan §2).
//!
//! Hosts keep their Ed25519 identity key as a PKCS#8 document and wrap it in
//! [`Ed25519Pkcs8`]. An iPhone's key lives in the Secure Enclave and can never
//! be exported, so the TLS client never asks for private key bytes: it only
//! asks an [`IdentitySigner`] to sign. [`ClientIdentity::certified_key`] turns
//! the pair into the form rustls (and so quinn) uses for client certificates.
//!
//! How to use it: build a [`ClientIdentity`] once per loaded identity and hand
//! it to [`crate::quic::client_config_with_liveness`]. The signer is shared,
//! so one identity serves every connection the host dials.

use rustls::{
    SignatureAlgorithm, SignatureScheme,
    pki_types::{CertificateDer, SubjectPublicKeyInfoDer},
    sign::{CertifiedKey, Signer, SigningKey},
};
use std::{fmt, sync::Arc};

/// Which signature algorithm an identity key uses. It decides the TLS
/// signature scheme and, later, the CSR's algorithm identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// Ed25519, the key every Linux and macOS host has today.
    Ed25519,
    /// ECDSA on P-256 with SHA-256, the only kind a Secure Enclave holds.
    EcdsaP256Sha256,
}

impl KeyAlgorithm {
    /// The TLS 1.3 signature scheme a key of this algorithm signs with.
    #[must_use]
    pub const fn tls_scheme(self) -> SignatureScheme {
        match self {
            Self::Ed25519 => SignatureScheme::ED25519,
            Self::EcdsaP256Sha256 => SignatureScheme::ECDSA_NISTP256_SHA256,
        }
    }

    /// The signature algorithm rustls files a key of this kind under.
    #[must_use]
    pub const fn tls_algorithm(self) -> SignatureAlgorithm {
        match self {
            Self::Ed25519 => SignatureAlgorithm::ED25519,
            Self::EcdsaP256Sha256 => SignatureAlgorithm::ECDSA,
        }
    }
}

/// Signing failed. It carries no detail on purpose, so no key material or
/// platform error text can reach a log line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignError;

impl fmt::Display for SignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the identity key could not sign")
    }
}

impl std::error::Error for SignError {}

/// Signs with the identity key. Implementations hold the key, or a handle to
/// it, and never hand it out.
pub trait IdentitySigner: Send + Sync + fmt::Debug {
    /// The key's algorithm; it decides the TLS and CSR signature schemes.
    fn algorithm(&self) -> KeyAlgorithm;
    /// The key's `SubjectPublicKeyInfo` DER, which both the CSR and the key
    /// fingerprint use, and which must match the certificate's.
    fn public_key_spki(&self) -> Vec<u8>;
    /// Sign `message`. Ed25519 returns the 64-byte signature; P-256 returns a
    /// DER ECDSA signature over SHA-256(message).
    /// # Errors
    /// The key is unavailable or refused to sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// A node's leg-B identity: its certificate chain (leaf first) and the
/// signer for the leaf's key.
#[derive(Clone, Debug)]
pub struct ClientIdentity {
    /// The leaf certificate first, then any intermediates, as DER.
    pub chain: Vec<CertificateDer<'static>>,
    /// Signs with the private key that belongs to the leaf.
    pub signer: Arc<dyn IdentitySigner>,
}

impl ClientIdentity {
    /// The chain and signer in rustls's form, for a client certificate
    /// resolver.
    ///
    /// It refuses a chain whose leaf names a different public key than the
    /// signer, exactly as rustls refuses a mismatched private key. A leaf
    /// whose key rustls cannot compare is accepted, as rustls accepts it.
    /// # Errors
    /// An empty chain, an unparsable leaf, or a key that does not match it.
    pub fn certified_key(&self) -> Result<CertifiedKey, rustls::Error> {
        let key = CertifiedKey::new(
            self.chain.clone(),
            Arc::new(SignerKey(Arc::clone(&self.signer))),
        );
        match key.keys_match() {
            Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {
                Ok(key)
            }
            Err(error) => Err(error),
        }
    }
}

/// Adapts an [`IdentitySigner`] to rustls's `SigningKey`, so a TLS client can
/// authenticate without the private key bytes.
#[derive(Debug)]
struct SignerKey(Arc<dyn IdentitySigner>);

impl SigningKey for SignerKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // The same rule as rustls's own keys: sign only with the one scheme
        // this key has, and only if the peer offered it.
        let scheme = self.0.algorithm().tls_scheme();
        offered.contains(&scheme).then(|| {
            Box::new(SchemeSigner {
                key: Arc::clone(&self.0),
                scheme,
            }) as Box<dyn Signer>
        })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.0.public_key_spki()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm().tls_algorithm()
    }
}

/// One handshake's signer: the identity key and the scheme it was chosen for.
#[derive(Debug)]
struct SchemeSigner {
    key: Arc<dyn IdentitySigner>,
    scheme: SignatureScheme,
}

impl Signer for SchemeSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.key
            .sign(message)
            .map_err(|_| rustls::Error::General("identity signing failed".into()))
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410): a SEQUENCE
/// holding the algorithm `1.3.101.112` and a BIT STRING of the 32-byte key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// An Ed25519 identity key loaded from a PKCS#8 document, the form hosts keep
/// in their identity file. Signing is deterministic, so it gives the same
/// signatures as rustls's own Ed25519 key over the same document.
pub struct Ed25519Pkcs8 {
    pair: ring::signature::Ed25519KeyPair,
}

impl Ed25519Pkcs8 {
    /// Load the key from PKCS#8 DER, version 1 (seed only, as OpenSSL writes
    /// it) or version 2 (seed and public key, checked against each other).
    /// # Errors
    /// The document is not an Ed25519 PKCS#8 key.
    pub fn from_pkcs8(document: &[u8]) -> Result<Self, SignError> {
        // The same loader rustls's ring provider uses for Ed25519 PKCS#8 keys.
        ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(document)
            .map(|pair| Self { pair })
            .map_err(|_| SignError)
    }
}

impl fmt::Debug for Ed25519Pkcs8 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material; the public half is enough to tell keys apart.
        use ring::signature::KeyPair;
        formatter
            .debug_struct("Ed25519Pkcs8")
            .field("public_key", &self.pair.public_key())
            .finish()
    }
}

impl IdentitySigner for Ed25519Pkcs8 {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Ed25519
    }

    fn public_key_spki(&self) -> Vec<u8> {
        use ring::signature::KeyPair;
        let mut spki = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
        spki.extend_from_slice(&ED25519_SPKI_PREFIX);
        spki.extend_from_slice(self.pair.public_key().as_ref());
        spki
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.pair.sign(message).as_ref().to_vec())
    }
}

/// A P-256 identity key held in memory, for tests only: Linux test clients
/// stand in for an iPhone with it (#580). Devices keep their key in the
/// Secure Enclave and hosts use Ed25519, so no shipped build compiles this
/// (it exists only under `cfg(test)` and the `test-support` feature).
#[cfg(any(test, feature = "test-support"))]
pub struct SoftwareP256 {
    pair: ring::signature::EcdsaKeyPair,
    random: ring::rand::SystemRandom,
}

#[cfg(any(test, feature = "test-support"))]
impl SoftwareP256 {
    /// A fresh random key.
    /// # Errors
    /// The system random source failed.
    pub fn generate() -> Result<Self, SignError> {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        let random = ring::rand::SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
            .map_err(|_| SignError)?;
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &random)
                .map_err(|_| SignError)?;
        Ok(Self { pair, random })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl fmt::Debug for SoftwareP256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ring::signature::KeyPair;
        formatter
            .debug_struct("SoftwareP256")
            .field("public_key", &self.pair.public_key())
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl IdentitySigner for SoftwareP256 {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EcdsaP256Sha256
    }

    fn public_key_spki(&self) -> Vec<u8> {
        use ring::signature::KeyPair;
        let mut spki = crate::csr::P256_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(self.pair.public_key().as_ref());
        spki
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        self.pair
            .sign(&self.random, message)
            .map(|signature| signature.as_ref().to_vec())
            .map_err(|_| SignError)
    }
}

/// Tests for the Ed25519 signer and the rustls adapter, with keys made by ring.
#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ED25519, UnparsedPublicKey};

    /// A fresh Ed25519 PKCS#8 v2 document.
    fn document() -> Vec<u8> {
        let random = ring::rand::SystemRandom::new();
        ring::signature::Ed25519KeyPair::generate_pkcs8(&random)
            .unwrap()
            .as_ref()
            .to_vec()
    }

    /// Signatures verify against the public key inside the SPKI it reports.
    #[test]
    fn ed25519_signatures_verify_against_its_spki() {
        let key = Ed25519Pkcs8::from_pkcs8(&document()).unwrap();
        let spki = key.public_key_spki();
        assert_eq!(spki.len(), 44);
        assert_eq!(spki[..12], ED25519_SPKI_PREFIX);
        let signature = key.sign(b"leg b").unwrap();
        UnparsedPublicKey::new(&ED25519, &spki[12..])
            .verify(b"leg b", &signature)
            .unwrap();
    }

    /// Anything that is not an Ed25519 PKCS#8 document is refused.
    #[test]
    fn non_ed25519_documents_are_refused() {
        assert_eq!(Ed25519Pkcs8::from_pkcs8(b"").unwrap_err(), SignError);
        let random = ring::rand::SystemRandom::new();
        let p256 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &random,
        )
        .unwrap();
        assert!(Ed25519Pkcs8::from_pkcs8(p256.as_ref()).is_err());
    }

    /// The adapter signs only with the key's own scheme, and only when offered.
    #[test]
    fn adapter_chooses_only_the_offered_matching_scheme() {
        let key = SignerKey(Arc::new(Ed25519Pkcs8::from_pkcs8(&document()).unwrap()));
        assert_eq!(key.algorithm(), SignatureAlgorithm::ED25519);
        assert!(
            key.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
                .is_none()
        );
        let signer = key
            .choose_scheme(&[
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
            ])
            .unwrap();
        assert_eq!(signer.scheme(), SignatureScheme::ED25519);
        assert_eq!(signer.sign(b"x").unwrap().len(), 64);
    }

    /// Debug output names the type and the public key only.
    #[test]
    fn debug_output_has_no_private_key() {
        let key = Ed25519Pkcs8::from_pkcs8(&document()).unwrap();
        let text = format!("{key:?}");
        assert!(text.starts_with("Ed25519Pkcs8 { public_key: "));
    }
}
