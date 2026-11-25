//! The join's certification request (PKCS#10), built by hand and signed
//! through an [`IdentitySigner`] (#580, plan §2, owner answer Q2).
//!
//! A Secure Enclave key can sign but never be exported, so no X.509 library
//! that wants the private key can build this request. It is small enough to
//! write directly: the request is exactly the shape the server's CSR parser
//! (`infraternal-server/src/csr.rs`) admits, and nothing else:
//!
//! ```text
//! CertificationRequest ::= SEQUENCE {
//!   certificationRequestInfo SEQUENCE {
//!     version       INTEGER 0,
//!     subject       SEQUENCE {}            -- empty: the server names the host
//!     subjectPKInfo <the signer's SPKI, verbatim>,
//!     attributes    [0] {}                 -- present and empty
//!   },
//!   signatureAlgorithm  id-Ed25519 | ecdsa-with-SHA256 (no parameters),
//!   signature           BIT STRING (0 unused bits) <signer's signature>
//! }
//! ```
//!
//! How to use it: [`certification_request`] returns the DER the join sends
//! (base64url, as `JoinRequest::csr_der`). [`key_digest`] is the key
//! fingerprint the approval page shows and the invitation binds: SHA-256 of
//! the raw public key (the 32 Ed25519 bytes, or the 65-byte uncompressed
//! P-256 point).
//!
//! Invariant: the SPKI is checked against its algorithm's exact encoding
//! before anything is signed, so a signer reporting a malformed key cannot
//! make this module sign a request the server would refuse anyway.

use crate::identity::{IdentitySigner, KeyAlgorithm, SignError};

/// DER prefix of a P-256 `SubjectPublicKeyInfo` (RFC 5480): `id-ecPublicKey`
/// on the named curve `prime256v1`, then a 66-byte BIT STRING holding one
/// zero "unused bits" byte and the uncompressed point (`04 || X || Y`).
pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The request's signature `AlgorithmIdentifier`, as a whole DER SEQUENCE.
/// Ed25519 is `id-Ed25519`; P-256 is `ecdsa-with-SHA256`. Both without
/// parameters, as RFC 8410 and RFC 5758 require.
fn signature_algorithm(algorithm: KeyAlgorithm) -> &'static [u8] {
    match algorithm {
        KeyAlgorithm::Ed25519 => &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70],
        KeyAlgorithm::EcdsaP256Sha256 => &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ],
    }
}

/// The raw public key inside `signer`'s SPKI: 32 bytes for Ed25519, the
/// 65-byte uncompressed point for P-256.
/// # Errors
/// The SPKI is not exactly its algorithm's encoding (wrong prefix, wrong
/// length, or a compressed P-256 point).
pub fn raw_public_key(signer: &dyn IdentitySigner) -> Result<Vec<u8>, SignError> {
    let spki = signer.public_key_spki();
    let raw = match signer.algorithm() {
        KeyAlgorithm::Ed25519 => spki
            .strip_prefix(ED25519_SPKI_PREFIX.as_slice())
            .filter(|key| key.len() == 32),
        KeyAlgorithm::EcdsaP256Sha256 => spki
            .strip_prefix(P256_SPKI_PREFIX.as_slice())
            .filter(|point| point.len() == 65 && point[0] == 0x04),
    };
    raw.map(<[u8]>::to_vec).ok_or(SignError)
}

/// The key fingerprint the approval page shows and the join invitation binds
/// (`expected_key_digest`): SHA-256 of [`raw_public_key`].
/// # Errors
/// The refusals of [`raw_public_key`].
pub fn key_digest(signer: &dyn IdentitySigner) -> Result<[u8; 32], SignError> {
    let digest = ring::digest::digest(&ring::digest::SHA256, &raw_public_key(signer)?);
    digest.as_ref().try_into().map_err(|_| SignError)
}

/// A PKCS#10 request for `signer`'s key, signed by it, as DER.
/// # Errors
/// A malformed SPKI ([`raw_public_key`]) or a failed signature.
pub fn certification_request(signer: &dyn IdentitySigner) -> Result<Vec<u8>, SignError> {
    raw_public_key(signer)?;
    let algorithm = signer.algorithm();
    let mut info = vec![0x02, 0x01, 0x00, 0x30, 0x00];
    info.extend_from_slice(&signer.public_key_spki());
    info.extend_from_slice(&[0xa0, 0x00]);
    let info = der(0x30, &info);
    let signature = signer.sign(&info)?;
    // Ed25519 signatures are 64 bytes; a DER ECDSA-Sig-Value on P-256 is at
    // most 72. Anything else is not a signature of this key.
    let plausible = match algorithm {
        KeyAlgorithm::Ed25519 => signature.len() == 64,
        KeyAlgorithm::EcdsaP256Sha256 => (8..=72).contains(&signature.len()),
    };
    if !plausible {
        return Err(SignError);
    }
    let mut bits = Vec::with_capacity(signature.len() + 1);
    bits.push(0);
    bits.extend_from_slice(&signature);
    let mut body = info;
    body.extend_from_slice(signature_algorithm(algorithm));
    body.extend_from_slice(&der(0x03, &bits));
    Ok(der(0x30, &body))
}

/// One DER element: `tag`, the shortest length form, then `content`.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let length = content.len();
    let mut out = Vec::with_capacity(length + 4);
    out.push(tag);
    if length < 0x80 {
        // Short form: the length itself, below 128.
        out.push(u8::try_from(length).unwrap_or(0));
    } else {
        let bytes = length.to_be_bytes();
        let skip = bytes.iter().take_while(|byte| **byte == 0).count();
        let octets = &bytes[skip..];
        out.push(0x80 | u8::try_from(octets.len()).unwrap_or(0));
        out.extend_from_slice(octets);
    }
    out.extend_from_slice(content);
    out
}

/// Tests for the request's exact bytes and signatures, with keys made by ring.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Ed25519Pkcs8, SoftwareP256};
    use ring::signature::{ECDSA_P256_SHA256_ASN1, ED25519, UnparsedPublicKey};

    /// Splits off one DER element of `tag` from the front of `input`.
    fn take<'a>(input: &mut &'a [u8], tag: u8) -> &'a [u8] {
        assert_eq!(input[0], tag);
        let (length, header) = if input[1] < 0x80 {
            (usize::from(input[1]), 2)
        } else {
            let count = usize::from(input[1] & 0x7f);
            let mut length = 0usize;
            for byte in &input[2..2 + count] {
                length = (length << 8) | usize::from(*byte);
            }
            (length, 2 + count)
        };
        let (element, rest) = input[header..].split_at(length);
        *input = rest;
        element
    }

    /// Takes a request apart: the signed info (with its header), the
    /// signature algorithm body and the signature bytes.
    fn parts(request: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut outer = request;
        let mut body = take(&mut outer, 0x30);
        assert_eq!(outer, b"");
        let before = body;
        let info = take(&mut body, 0x30);
        let info_der = before[..before.len() - body.len()].to_vec();
        let mut fields = info;
        assert_eq!(take(&mut fields, 0x02), [0]);
        assert_eq!(take(&mut fields, 0x30), b"");
        take(&mut fields, 0x30);
        assert_eq!(take(&mut fields, 0xa0), b"");
        assert_eq!(fields, b"");
        let algorithm = take(&mut body, 0x30).to_vec();
        let bits = take(&mut body, 0x03);
        assert_eq!(body, b"");
        assert_eq!(bits[0], 0);
        (info_der, algorithm, bits[1..].to_vec())
    }

    /// A P-256 request carries the signer's SPKI verbatim and an
    /// `ecdsa-with-SHA256` signature that verifies over the request info.
    #[test]
    fn p256_request_is_signed_by_its_own_key() {
        let signer = SoftwareP256::generate().unwrap();
        let request = certification_request(&signer).unwrap();
        let (info, algorithm, signature) = parts(&request);
        assert_eq!(
            algorithm,
            [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]
        );
        let point = raw_public_key(&signer).unwrap();
        assert_eq!(point.len(), 65);
        let spki = signer.public_key_spki();
        assert!(info.windows(spki.len()).any(|window| window == spki));
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point)
            .verify(&info, &signature)
            .unwrap();
    }

    /// An Ed25519 request has the 64-byte signature and `id-Ed25519`.
    #[test]
    fn ed25519_request_is_signed_by_its_own_key() {
        let random = ring::rand::SystemRandom::new();
        let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let signer = Ed25519Pkcs8::from_pkcs8(document.as_ref()).unwrap();
        let request = certification_request(&signer).unwrap();
        let (info, algorithm, signature) = parts(&request);
        assert_eq!(algorithm, [0x06, 0x03, 0x2b, 0x65, 0x70]);
        assert_eq!(signature.len(), 64);
        UnparsedPublicKey::new(&ED25519, raw_public_key(&signer).unwrap())
            .verify(&info, &signature)
            .unwrap();
    }

    /// The digest is SHA-256 of the raw key, the form the server binds.
    #[test]
    fn key_digest_hashes_the_raw_point() {
        let signer = SoftwareP256::generate().unwrap();
        let expected =
            ring::digest::digest(&ring::digest::SHA256, &raw_public_key(&signer).unwrap());
        assert_eq!(key_digest(&signer).unwrap(), expected.as_ref());
    }

    /// A signer whose SPKI is not its algorithm's exact encoding, or whose
    /// signature has an impossible length, gets no request.
    #[test]
    fn malformed_keys_and_signatures_are_refused() {
        /// A signer that reports a fixed SPKI and signature.
        #[derive(Debug)]
        struct Fake(KeyAlgorithm, Vec<u8>, Vec<u8>);
        impl IdentitySigner for Fake {
            fn algorithm(&self) -> KeyAlgorithm {
                self.0
            }
            fn public_key_spki(&self) -> Vec<u8> {
                self.1.clone()
            }
            fn sign(&self, _: &[u8]) -> Result<Vec<u8>, SignError> {
                Ok(self.2.clone())
            }
        }
        let good = SoftwareP256::generate().unwrap().public_key_spki();
        let mut compressed = good.clone();
        compressed[26] = 0x02;
        for fake in [
            Fake(KeyAlgorithm::EcdsaP256Sha256, compressed, vec![0x30; 70]),
            Fake(
                KeyAlgorithm::EcdsaP256Sha256,
                good[..90].to_vec(),
                vec![0x30; 70],
            ),
            Fake(KeyAlgorithm::Ed25519, good.clone(), vec![0; 64]),
            Fake(KeyAlgorithm::EcdsaP256Sha256, good.clone(), vec![0x30; 73]),
            Fake(KeyAlgorithm::EcdsaP256Sha256, good.clone(), Vec::new()),
        ] {
            assert_eq!(certification_request(&fake).unwrap_err(), SignError);
        }
    }

    /// Lengths of 128 and more use the long form with the fewest octets.
    #[test]
    fn der_lengths_are_minimal() {
        assert_eq!(der(0x04, &[0; 127])[..2], [0x04, 0x7f]);
        assert_eq!(der(0x04, &[0; 128])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(der(0x04, &[0; 300])[..4], [0x04, 0x82, 0x01, 0x2c]);
    }
}
