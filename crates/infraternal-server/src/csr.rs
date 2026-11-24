//! Bounded proof-of-possession admission for host CSRs; request identity and extensions confer no authority [133], #78.
//!
//! Two key shapes are admitted, each only when the caller asks for it:
//! Ed25519 (every host, [`ValidatedCsr::parse`]) and ECDSA P-256 with
//! SHA-256 (device identities held in a Secure Enclave, #580), through
//! [`ValidatedCsr::parse_as`]. The caller always knows which one it expects,
//! from the invitation or the identity being continued, so this module never
//! picks an algorithm from the request itself.

use crate::identity_key::{IdentityKey, KeyAlgorithm};
use openssl::{
    ec::PointConversionForm,
    nid::Nid,
    pkey::{Id, PKey, Public},
    x509::X509Req,
};

/// Maximum encoded PKCS10 request, checked before invoking OpenSSL.
pub const MAX_CSR_DER: usize = 4096;

/// Admission errors contain no request bytes or crypto-library diagnostic text.
#[derive(Debug, thiserror::Error)]
#[error("host CSR refused")]
pub struct CsrError;

/// A verified public key of the algorithm the caller asked for; callers supply host identity independently.
pub struct ValidatedCsr {
    key: PKey<Public>,
    algorithm: KeyAlgorithm,
}

impl ValidatedCsr {
    /// Validate one bounded PKCS10 DER request for an Ed25519 host key before certificate construction.
    /// # Errors
    /// Rejects malformed, oversized, noncanonical or unauthenticated requests,
    /// and every key that is not Ed25519.
    pub fn parse(der: &[u8]) -> Result<Self, CsrError> {
        Self::parse_as(der, KeyAlgorithm::Ed25519)
    }

    /// Validate one bounded PKCS10 DER request whose key must use `expected`.
    ///
    /// For [`KeyAlgorithm::P256`] the request must carry an `id-ecPublicKey`
    /// key on the named curve `prime256v1` as a 65-byte uncompressed point,
    /// signed with `ecdsa-with-SHA256` (parameters absent, RFC 5758) as a
    /// strict DER `ECDSA-Sig-Value`. The same nesting, length and canonical-form
    /// rules apply as for Ed25519. A request whose shape mixes the two (an
    /// Ed25519 signature algorithm on a P-256 key, or the reverse) is refused.
    ///
    /// High-S signatures are accepted: a Secure Enclave does not normalise S,
    /// and a mauled signature only yields another CSR for the same key, which
    /// grants nothing without a fresh proof from the private key.
    /// # Errors
    /// Rejects malformed, oversized, noncanonical or unauthenticated requests,
    /// and every key of another algorithm or curve.
    pub fn parse_as(der: &[u8], expected: KeyAlgorithm) -> Result<Self, CsrError> {
        validate_envelope(der, expected)?;
        let request = X509Req::from_der(der).map_err(|_| CsrError)?;
        let key = request.public_key().map_err(|_| CsrError)?;
        if request.version() != 0
            || !key_has_algorithm(&key, expected)
            || !request.verify(&key).map_err(|_| CsrError)?
            || request.to_der().map_err(|_| CsrError)? != der
        {
            return Err(CsrError);
        }
        Ok(Self {
            key,
            algorithm: expected,
        })
    }

    /// Only the verified key crosses into certificate construction.
    #[must_use]
    pub fn key(&self) -> &PKey<Public> {
        &self.key
    }

    /// The algorithm of [`Self::key`]: always the one the caller asked for.
    #[must_use]
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// The verified key in its stored form, for the certificate record and key digests.
    /// # Errors
    /// Never in practice: admission already pinned the key's exact encoding.
    /// It still fails closed rather than panicking if OpenSSL disagrees.
    pub fn identity_key(&self) -> Result<IdentityKey, CsrError> {
        IdentityKey::from_public_key(&self.key)
            .filter(|key| key.algorithm() == self.algorithm)
            .ok_or(CsrError)
    }
}

/// Whether OpenSSL's decoded `key` is of `algorithm`: an Ed25519 key, or an
/// EC key on P-256 whose point re-encodes to 65 uncompressed bytes. The
/// envelope already pinned the encoded form; this checks OpenSSL read the same.
fn key_has_algorithm(key: &PKey<Public>, algorithm: KeyAlgorithm) -> bool {
    match algorithm {
        KeyAlgorithm::Ed25519 => key.id() == Id::ED25519,
        KeyAlgorithm::P256 => {
            key.id() == Id::EC
                && key.ec_key().is_ok_and(|ec| {
                    ec.group().curve_name() == Some(Nid::X9_62_PRIME256V1)
                        && openssl::bn::BigNumContext::new().is_ok_and(|mut context| {
                            ec.public_key()
                                .to_bytes(
                                    ec.group(),
                                    PointConversionForm::UNCOMPRESSED,
                                    &mut context,
                                )
                                .is_ok_and(|point| point.len() == 65)
                        })
                })
        }
    }
}

// OpenSSL caches signed request-info bytes, so re-encoding cannot establish
// shortest nested lengths or mandatory PKCS10 fields. This allocation-free
// preflight bounds nesting before OpenSSL parses and verifies possession.
/// Checks the outer shape of the request before OpenSSL sees it: at most [`MAX_CSR_DER`] bytes, a single SEQUENCE with no trailing bytes, a bounded nesting depth, version 0, shortest-form lengths, and exactly `algorithm`'s key and signature encodings.
fn validate_envelope(der: &[u8], algorithm: KeyAlgorithm) -> Result<(), CsrError> {
    if der.len() > MAX_CSR_DER {
        return Err(CsrError);
    }
    let mut input = der;
    let outer = take(&mut input, 0x30)?;
    if !input.is_empty() {
        return Err(CsrError);
    }
    validate_tree(outer, 0)?;
    let mut slots = outer;
    let mut info = take(&mut slots, 0x30)?;
    if take(&mut info, 2)? != [0] {
        return Err(CsrError);
    }
    take(&mut info, 0x30)?; // Requested name has no certificate authority.
    let mut spki = take(&mut info, 0x30)?;
    if take(&mut spki, 0x30)? != key_algorithm_identifier(algorithm) {
        return Err(CsrError);
    }
    let key = take(&mut spki, 3)?;
    if !spki.is_empty() || !key_encoding_is_exact(key, algorithm) {
        return Err(CsrError);
    }
    let attributes = take(&mut info, 0xa0)?;
    validate_set(attributes)?; // Implicit SET OF attributes is mandatory, even empty.
    if !info.is_empty() {
        return Err(CsrError);
    }
    if take(&mut slots, 0x30)? != signature_algorithm_identifier(algorithm) {
        return Err(CsrError);
    }
    let signature = take(&mut slots, 3)?;
    if !slots.is_empty() || !signature_encoding_is_exact(signature, algorithm) {
        return Err(CsrError);
    }
    Ok(())
}

/// The body of the `SubjectPublicKeyInfo` `AlgorithmIdentifier` for `algorithm`.
///
/// Ed25519 is `id-Ed25519` with parameters absent, as RFC 8410 requires.
/// P-256 is `id-ecPublicKey` with the named curve `prime256v1` as its only
/// parameter (RFC 5480): explicit curve parameters are never accepted.
fn key_algorithm_identifier(algorithm: KeyAlgorithm) -> &'static [u8] {
    match algorithm {
        KeyAlgorithm::Ed25519 => &[6, 3, 0x2b, 0x65, 0x70],
        KeyAlgorithm::P256 => &[
            6, 7, 0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1, // id-ecPublicKey
            6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7, // prime256v1
        ],
    }
}

/// The body of the request's signature `AlgorithmIdentifier` for `algorithm`.
///
/// Ed25519 signs with `id-Ed25519`, parameters absent (RFC 8410). P-256 signs
/// with `ecdsa-with-SHA256`, whose parameters RFC 5758 requires to be absent;
/// no other digest is accepted.
fn signature_algorithm_identifier(algorithm: KeyAlgorithm) -> &'static [u8] {
    match algorithm {
        KeyAlgorithm::Ed25519 => key_algorithm_identifier(KeyAlgorithm::Ed25519),
        KeyAlgorithm::P256 => &[6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2],
    }
}

/// Whether the key BIT STRING body is exactly `algorithm`'s raw key: no unused
/// bits, then 32 Ed25519 bytes, or a 65-byte uncompressed P-256 point
/// (`04 || X || Y`). Compressed (`02`/`03`) and hybrid (`06`/`07`) points are
/// refused, so one key has exactly one admitted spelling.
fn key_encoding_is_exact(key: &[u8], algorithm: KeyAlgorithm) -> bool {
    match algorithm {
        KeyAlgorithm::Ed25519 => key.len() == 33 && key[0] == 0,
        KeyAlgorithm::P256 => key.len() == 66 && key[0] == 0 && key[1] == 4,
    }
}

/// Whether the signature BIT STRING body is exactly one `algorithm` signature
/// with no unused bits: 64 Ed25519 bytes, or one DER `ECDSA-Sig-Value`
/// (`SEQUENCE { INTEGER r, INTEGER s }`) of at most 72 bytes.
fn signature_encoding_is_exact(signature: &[u8], algorithm: KeyAlgorithm) -> bool {
    match algorithm {
        KeyAlgorithm::Ed25519 => signature.len() == 65 && signature[0] == 0,
        KeyAlgorithm::P256 => {
            signature.len() <= 73
                && signature.first() == Some(&0)
                && ecdsa_signature_is_der(&signature[1..])
        }
    }
}

/// Whether `der` is one strict DER ECDSA P-256 signature and nothing else:
/// a SEQUENCE of exactly two INTEGERs, each minimal, positive, non-zero and at
/// most 33 bytes (a 32-byte value plus one sign octet), 72 bytes at most in
/// all. OpenSSL also checks the values are below the group order when it verifies.
pub(crate) fn ecdsa_signature_is_der(der: &[u8]) -> bool {
    /// Reads one INTEGER and checks it is a canonical positive P-256 scalar.
    fn scalar(input: &mut &[u8]) -> bool {
        take(input, 2).is_ok_and(|value| {
            value.len() <= 33
                && value != [0]
                && value[0] & 0x80 == 0
                && validate_value(2, value).is_ok()
        })
    }
    let mut input = der;
    let Ok(mut pair) = take(&mut input, 0x30) else {
        return false;
    };
    der.len() <= 72 && input.is_empty() && scalar(&mut pair) && scalar(&mut pair) && pair.is_empty()
}

/// Reads one element that must have `tag` from the front of `input`, moves `input` past it and returns its body. Fails on any other tag.
fn take<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8], CsrError> {
    if input.first() != Some(&tag) {
        return Err(CsrError);
    }
    let (_, body, rest) = element(input)?;
    *input = rest;
    Ok(body)
}

// Size <=4096 implies at most two length octets. Reject high-tag encodings:
// PKCS10 names/attributes and Ed25519 fields need none of them.
/// Splits off the first DER element and returns its tag, its body and the bytes after it. Rejects multi-byte tags, non-shortest or oversized lengths, and truncated input.
fn element(input: &[u8]) -> Result<(u8, &[u8], &[u8]), CsrError> {
    let tag = *input.first().ok_or(CsrError)?;
    if tag & 0x1f == 0x1f || tag == 0 {
        return Err(CsrError);
    }
    let first = *input.get(1).ok_or(CsrError)?;
    let (header, length) = match first {
        0..=127 => (2, usize::from(first)),
        0x81 => {
            let length = usize::from(*input.get(2).ok_or(CsrError)?);
            if length < 128 {
                return Err(CsrError);
            }
            (3, length)
        }
        0x82 => {
            let length = usize::from(u16::from_be_bytes([
                *input.get(2).ok_or(CsrError)?,
                *input.get(3).ok_or(CsrError)?,
            ]));
            if length < 256 {
                return Err(CsrError);
            }
            (4, length)
        }
        _ => return Err(CsrError),
    };
    let body = input.get(header..header + length).ok_or(CsrError)?;
    Ok((tag, body, &input[header + length..]))
}

/// Checks a DER SET is sorted by encoded bytes, as canonical DER requires.
fn validate_set(mut input: &[u8]) -> Result<(), CsrError> {
    let mut previous: &[u8] = &[];
    while !input.is_empty() {
        let (_, _, rest) = element(input)?;
        let encoded = &input[..input.len() - rest.len()];
        if previous > encoded {
            return Err(CsrError);
        }
        previous = encoded;
        input = rest;
    }
    Ok(())
}

/// Walks the whole structure up to depth 16, rejecting non-canonical constructed or primitive forms and unknown context-specific types, so no ignored attribute can hide a non-canonical encoding.
fn validate_tree(mut input: &[u8], depth: u8) -> Result<(), CsrError> {
    if depth > 16 {
        return Err(CsrError);
    }
    while !input.is_empty() {
        let (tag, body, rest) = element(input)?;
        // DER has no constructed strings. BER forms accepted and cached by
        // OpenSSL must not evade canonical admission through ignored attributes.
        if tag & 0xc0 == 0 && (tag & 0x20 != 0) != matches!(tag & 0x1f, 16 | 17) {
            return Err(CsrError);
        }
        // This CSR profile accepts universal values and only PKCS10's outer
        // implicit attributes SET. Unknown implicit types cannot be validated
        // without their schema; accepting them would claim canonicality blindly.
        if tag & 0xc0 != 0 && !(tag == 0xa0 && depth == 1) {
            return Err(CsrError);
        }
        if tag & 0x20 != 0 {
            if tag == 0x31 {
                validate_set(body)?;
            }
            validate_tree(body, depth + 1)?;
        } else {
            validate_value(tag, body)?;
        }
        input = rest;
    }
    Ok(())
}

// Validate accepted universal value types; attributes are ignored, not trusted.
/// Checks that a universal-type value is in its single canonical DER form, for example minimal integers and `0x00`/`0xff` booleans.
fn validate_value(tag: u8, body: &[u8]) -> Result<(), CsrError> {
    match tag {
        1 => {
            if body != [0] && body != [0xff] {
                return Err(CsrError);
            }
        }
        2 | 10 => {
            if body.is_empty()
                || (body.len() > 1
                    && ((body[0] == 0 && body[1] & 0x80 == 0)
                        || (body[0] == 0xff && body[1] & 0x80 != 0)))
            {
                return Err(CsrError);
            }
        }
        3 => {
            let unused = *body.first().ok_or(CsrError)?;
            if unused > 7
                || (body.len() == 1 && unused != 0)
                || (unused != 0 && body.last().ok_or(CsrError)? & ((1 << unused) - 1) != 0)
            {
                return Err(CsrError);
            }
        }
        4 => {} // Extension OCTET STRING contents are opaque, never copied.
        5 => {
            if !body.is_empty() {
                return Err(CsrError);
            }
        }
        6 => {
            if body.is_empty() || body.last().ok_or(CsrError)? & 0x80 != 0 {
                return Err(CsrError);
            }
            let mut start = true;
            for byte in body {
                if start && *byte == 0x80 {
                    return Err(CsrError);
                }
                start = byte & 0x80 == 0;
            }
        }
        12 => {
            std::str::from_utf8(body).map_err(|_| CsrError)?;
        }
        18 => {
            if !body.iter().all(|b| b.is_ascii_digit() || *b == b' ') {
                return Err(CsrError);
            }
        }
        19 => {
            if !body
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(b))
            {
                return Err(CsrError);
            }
        }
        22 => {
            if !body.is_ascii() {
                return Err(CsrError);
            }
        }
        28 => {
            if !body.len().is_multiple_of(4)
                || !body.as_chunks::<4>().0.iter().all(|bytes| {
                    char::from_u32(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                        .is_some()
                })
            {
                return Err(CsrError);
            }
        }
        30 => {
            if !body.len().is_multiple_of(2)
                || body.as_chunks::<2>().0.iter().any(|bytes| {
                    (0xd800..=0xdfff).contains(&u16::from_be_bytes([bytes[0], bytes[1]]))
                })
            {
                return Err(CsrError);
            }
        }
        // Reject REAL, time and legacy string types instead of writing
        // unrelated canonicalizers for ignored requested attributes.
        _ => return Err(CsrError),
    }
    Ok(())
}

/// Admission and refusal tests for both identity shapes, with requests signed over their exact request-info bytes.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use openssl::{
        hash::MessageDigest,
        pkey::Private,
        x509::{X509NameBuilder, X509Req},
    };

    fn request(key: &PKey<Private>, version: i32) -> Vec<u8> {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "untrusted host identity")
            .unwrap();
        let mut builder = X509Req::builder().unwrap();
        builder.set_version(version).unwrap();
        builder.set_subject_name(&name.build()).unwrap();
        builder.set_pubkey(key).unwrap();
        builder
            .sign(
                key,
                if key.id() == openssl::pkey::Id::ED25519 {
                    MessageDigest::null()
                } else {
                    MessageDigest::sha256()
                },
            )
            .unwrap();
        builder.build().to_der().unwrap()
    }

    // Sign the exact request-info bytes: mutating a builder's DER afterward
    // would only exercise signature failure, hiding OpenSSL's encoding cache.
    fn signed_shape(
        nonminimal: bool,
        attributes: bool,
        null_parameters: bool,
        attribute: &[u8],
    ) -> Vec<u8> {
        fn sequence(body: &[u8]) -> Vec<u8> {
            let mut encoded = if body.len() < 128 {
                vec![0x30, u8::try_from(body.len()).unwrap()]
            } else {
                vec![0x30, 0x81, u8::try_from(body.len()).unwrap()]
            };
            encoded.extend_from_slice(body);
            encoded
        }
        let key = PKey::generate_ed25519().unwrap();
        let mut info_body = vec![2, 1, 0, 0x30, 0];
        info_body.extend(key.public_key_to_der().unwrap());
        if attributes {
            info_body.extend([0xa0, u8::try_from(attribute.len()).unwrap()]);
            info_body.extend(attribute);
        }
        let mut info = sequence(&info_body);
        if nonminimal {
            info.insert(1, 0x81);
        }
        let signature = openssl::sign::Signer::new_without_digest(&key)
            .unwrap()
            .sign_oneshot_to_vec(&info)
            .unwrap();
        let algorithm = if null_parameters {
            vec![0x30, 7, 6, 3, 0x2b, 0x65, 0x70, 5, 0]
        } else {
            vec![0x30, 5, 6, 3, 0x2b, 0x65, 0x70]
        };
        let mut body = info;
        body.extend(algorithm);
        body.extend([3, 65, 0]);
        body.extend(signature);
        sequence(&body)
    }

    #[test]
    fn signed_cached_noncanonical_or_incomplete_shapes_are_refused() {
        assert!(ValidatedCsr::parse(&signed_shape(false, true, false, &[])).is_ok());
        for parameters in [
            (true, true, false),
            (false, false, false),
            (false, true, true),
        ] {
            let der = signed_shape(parameters.0, parameters.1, parameters.2, &[]);
            let request = X509Req::from_der(&der).unwrap();
            assert!(request.verify(&request.public_key().unwrap()).unwrap());
            assert_eq!(request.to_der().unwrap(), der);
            assert!(ValidatedCsr::parse(&der).is_err(), "shape {parameters:?}");
        }
    }

    #[test]
    fn signed_constructed_primitive_attribute_is_refused() {
        let attribute = [0x30, 11, 6, 2, 0x2a, 3, 0x31, 5, 0x24, 3, 4, 1, b'A'];
        let der = signed_shape(false, true, false, &attribute);
        let request = X509Req::from_der(&der).unwrap();
        assert!(request.verify(&request.public_key().unwrap()).unwrap());
        assert_eq!(request.to_der().unwrap(), der);
        assert!(ValidatedCsr::parse(&der).is_err());
    }

    #[test]
    fn signed_noncanonical_ignored_values_are_refused() {
        for attribute in [
            vec![
                0x30, 0x10, 6, 2, 0x2a, 3, 0x31, 0x0a, 0x30, 8, 0x0a, 2, 0, 1, 4, 2, b'A', b'A',
            ],
            vec![0x30, 9, 6, 2, 0x2a, 3, 0x31, 3, 0x0c, 1, 0xff],
        ] {
            let der = signed_shape(false, true, false, &attribute);
            let request = X509Req::from_der(&der).unwrap();
            assert!(request.verify(&request.public_key().unwrap()).unwrap());
            assert_eq!(request.to_der().unwrap(), der);
            assert!(ValidatedCsr::parse(&der).is_err());
        }
    }

    #[test]
    fn verified_host_key_is_admitted_without_trusting_requested_identity() {
        let key = PKey::generate_ed25519().unwrap();
        let der = request(&key, 0);
        let validated = ValidatedCsr::parse(&der).unwrap();
        assert_eq!(
            validated.key().raw_public_key().unwrap(),
            key.raw_public_key().unwrap()
        );
    }

    #[test]
    fn incomplete_suffix_oversized_forged_and_wrong_algorithm_requests_are_refused() {
        let key = PKey::generate_ed25519().unwrap();
        let der = request(&key, 0);
        for end in 0..der.len() {
            assert!(ValidatedCsr::parse(&der[..end]).is_err());
        }
        for suffix in [vec![0], der.clone()] {
            let mut suffixed = der.clone();
            suffixed.extend(suffix);
            assert!(ValidatedCsr::parse(&suffixed).is_err());
        }
        let mut forged = der.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(ValidatedCsr::parse(&forged).is_err());
        assert!(ValidatedCsr::parse(&vec![0; 4097]).is_err());
        let mut wrong_version = der.clone();
        let version = wrong_version
            .windows(3)
            .position(|bytes| bytes == [2, 1, 0])
            .unwrap();
        wrong_version[version + 2] = 1;
        assert!(ValidatedCsr::parse(&wrong_version).is_err());
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let ec = PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap();
        assert!(ValidatedCsr::parse(&request(&ec, 0)).is_err());
    }
    #[test]
    fn nonminimal_outer_lengths_and_real_oversized_requests_are_refused() {
        let key = PKey::generate_ed25519().unwrap();
        let der = request(&key, 0);
        assert_eq!(der[1], 0x81);
        let mut long_length = vec![0x30, 0x82, 0, der[2]];
        long_length.extend_from_slice(&der[3..]);
        assert!(ValidatedCsr::parse(&long_length).is_err());
        let mut name = X509NameBuilder::new().unwrap();
        for _ in 0..100 {
            name.append_entry_by_text("OU", "untrusted untrusted untrusted untrusted untrusted")
                .unwrap();
        }
        let mut builder = X509Req::builder().unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_subject_name(&name.build()).unwrap();
        builder.sign(&key, MessageDigest::null()).unwrap();
        let large = builder.build().to_der().unwrap();
        assert!(large.len() > 4096);
        assert!(ValidatedCsr::parse(&large).is_err());
    }

    /// Encodes one DER element with the shortest length form, as the envelope requires.
    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        match body.len() {
            0..=127 => encoded.push(u8::try_from(body.len()).unwrap()),
            128..=255 => encoded.extend([0x81, u8::try_from(body.len()).unwrap()]),
            length => {
                encoded.push(0x82);
                encoded.extend(u16::try_from(length).unwrap().to_be_bytes());
            }
        }
        encoded.extend_from_slice(body);
        encoded
    }

    /// A fresh software P-256 key: the stand-in for a Secure Enclave key in these tests.
    fn p256_key() -> PKey<Private> {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap()
    }

    /// The 65-byte uncompressed point of a P-256 key, or its 33-byte compressed form.
    fn p256_point(key: &PKey<Private>, form: PointConversionForm) -> Vec<u8> {
        let ec = key.ec_key().unwrap();
        let mut context = openssl::bn::BigNumContext::new().unwrap();
        ec.public_key()
            .to_bytes(ec.group(), form, &mut context)
            .unwrap()
    }

    /// The parts of a hand-built P-256 request that a refusal test varies.
    /// Each shape is signed over its own request-info bytes, so OpenSSL alone
    /// would accept it; only the envelope can refuse it.
    struct P256Shape {
        /// The `SubjectPublicKeyInfo` algorithm body.
        key_algorithm: Vec<u8>,
        /// The raw point placed after the BIT STRING's unused-bits octet.
        point: Vec<u8>,
        /// The signature algorithm body.
        signature_algorithm: Vec<u8>,
        /// The digest the software key signs with.
        digest: MessageDigest,
        /// Rewrites the DER signature before it is placed in the BIT STRING.
        mangle: fn(Vec<u8>) -> Vec<u8>,
    }

    impl P256Shape {
        /// The shape a Secure Enclave key produces: the only one admitted.
        fn admitted(key: &PKey<Private>) -> Self {
            Self {
                key_algorithm: key_algorithm_identifier(KeyAlgorithm::P256).to_vec(),
                point: p256_point(key, PointConversionForm::UNCOMPRESSED),
                signature_algorithm: signature_algorithm_identifier(KeyAlgorithm::P256).to_vec(),
                digest: MessageDigest::sha256(),
                mangle: |signature| signature,
            }
        }

        /// Builds and signs the request with `key`.
        fn build(&self, key: &PKey<Private>) -> Vec<u8> {
            let mut point = vec![0];
            point.extend(&self.point);
            let spki = der(
                0x30,
                &[der(0x30, &self.key_algorithm), der(3, &point)].concat(),
            );
            let info = der(
                0x30,
                &[vec![2, 1, 0, 0x30, 0], spki, vec![0xa0, 0]].concat(),
            );
            let mut signer = openssl::sign::Signer::new(self.digest, key).unwrap();
            let signature = (self.mangle)(signer.sign_oneshot_to_vec(&info).unwrap());
            let mut bits = vec![0];
            bits.extend(signature);
            der(
                0x30,
                &[info, der(0x30, &self.signature_algorithm), der(3, &bits)].concat(),
            )
        }
    }

    /// A P-256 request is admitted only when the caller asks for P-256, and
    /// its verified key is the signer's; the Ed25519 entry point still refuses it.
    #[test]
    fn p256_request_is_admitted_only_as_p256() {
        let key = p256_key();
        for der in [request(&key, 0), P256Shape::admitted(&key).build(&key)] {
            let validated = ValidatedCsr::parse_as(&der, KeyAlgorithm::P256).unwrap();
            assert_eq!(validated.algorithm(), KeyAlgorithm::P256);
            assert!(validated.key().public_eq(&key));
            assert!(ValidatedCsr::parse(&der).is_err());
            assert!(ValidatedCsr::parse_as(&der, KeyAlgorithm::Ed25519).is_err());
        }
        let ed25519 = request(&PKey::generate_ed25519().unwrap(), 0);
        assert_eq!(
            ValidatedCsr::parse(&ed25519).unwrap().algorithm(),
            KeyAlgorithm::Ed25519
        );
        assert!(ValidatedCsr::parse_as(&ed25519, KeyAlgorithm::P256).is_err());
    }

    /// A request signed by a second, independent implementation (ring, which
    /// the client core signs with) passes the server's OpenSSL verification,
    /// so the two agree on the DER signature encoding.
    #[test]
    fn p256_request_signed_by_ring_is_admitted() {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
        let random = ring::rand::SystemRandom::new();
        for _ in 0..32 {
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &random)
                    .unwrap();
            let mut point = vec![0];
            point.extend(pair.public_key().as_ref());
            let spki = der(
                0x30,
                &[
                    der(0x30, key_algorithm_identifier(KeyAlgorithm::P256)),
                    der(3, &point),
                ]
                .concat(),
            );
            let info = der(
                0x30,
                &[vec![2, 1, 0, 0x30, 0], spki, vec![0xa0, 0]].concat(),
            );
            let mut bits = vec![0];
            bits.extend(pair.sign(&random, &info).unwrap().as_ref());
            let csr = der(
                0x30,
                &[
                    info,
                    der(0x30, signature_algorithm_identifier(KeyAlgorithm::P256)),
                    der(3, &bits),
                ]
                .concat(),
            );
            assert!(ValidatedCsr::parse_as(&csr, KeyAlgorithm::P256).is_ok());
        }
    }

    /// Every mixed or non-canonical P-256 shape is refused even though its
    /// signature verifies: compressed and hybrid points, Ed25519 identifiers on
    /// a P-256 key, other digests, curve parameters, and signature encodings
    /// with padding, long lengths, trailing bytes or unused bits.
    #[test]
    fn mixed_and_noncanonical_p256_shapes_are_refused() {
        let key = p256_key();
        let admitted = P256Shape::admitted(&key).build(&key);
        assert!(ValidatedCsr::parse_as(&admitted, KeyAlgorithm::P256).is_ok());
        let ed25519_identifier = key_algorithm_identifier(KeyAlgorithm::Ed25519).to_vec();
        let mut shapes: Vec<(&str, P256Shape)> = Vec::new();
        let mut compressed = P256Shape::admitted(&key);
        compressed.point = p256_point(&key, PointConversionForm::COMPRESSED);
        shapes.push(("compressed point", compressed));
        let mut hybrid = P256Shape::admitted(&key);
        hybrid.point = p256_point(&key, PointConversionForm::HYBRID);
        shapes.push(("hybrid point", hybrid));
        let mut ed_signature = P256Shape::admitted(&key);
        ed_signature
            .signature_algorithm
            .clone_from(&ed25519_identifier);
        shapes.push(("Ed25519 signature algorithm on a P-256 key", ed_signature));
        let mut ed_key = P256Shape::admitted(&key);
        ed_key.key_algorithm = ed25519_identifier;
        shapes.push(("Ed25519 key algorithm with a P-256 point", ed_key));
        let mut sha384 = P256Shape::admitted(&key);
        sha384.digest = MessageDigest::sha384();
        sha384.signature_algorithm = vec![6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3];
        shapes.push(("ecdsa-with-SHA384", sha384));
        let mut null_parameters = P256Shape::admitted(&key);
        null_parameters.signature_algorithm.extend([5, 0]);
        shapes.push(("NULL signature parameters", null_parameters));
        let mut no_curve = P256Shape::admitted(&key);
        no_curve.key_algorithm.truncate(9);
        shapes.push(("id-ecPublicKey without a named curve", no_curve));
        let mut padded = P256Shape::admitted(&key);
        padded.mangle = |signature| {
            // r gains a redundant leading zero: still the same value, not minimal DER.
            let (r_length, r) = (usize::from(signature[3]), &signature[4..]);
            let mut r_padded = vec![0];
            r_padded.extend(&r[..r_length]);
            der(0x30, &[der(2, &r_padded), r[r_length..].to_vec()].concat())
        };
        shapes.push(("non-minimal r", padded));
        let mut long_length = P256Shape::admitted(&key);
        long_length.mangle = |signature| {
            let mut long = vec![0x30, 0x81];
            long.extend(&signature[1..]);
            long
        };
        shapes.push(("long-form signature length", long_length));
        let mut trailing = P256Shape::admitted(&key);
        trailing.mangle = |mut signature| {
            signature.push(0);
            signature
        };
        shapes.push(("trailing byte after the signature", trailing));
        let mut raw = P256Shape::admitted(&key);
        raw.mangle = |signature| {
            // The fixed-width r||s form some APIs return instead of DER.
            let signature = openssl::ecdsa::EcdsaSig::from_der(&signature).unwrap();
            [
                signature.r().to_vec_padded(32).unwrap(),
                signature.s().to_vec_padded(32).unwrap(),
            ]
            .concat()
        };
        shapes.push(("raw r||s signature", raw));
        for (name, shape) in shapes {
            let der = shape.build(&key);
            assert!(
                ValidatedCsr::parse_as(&der, KeyAlgorithm::P256).is_err(),
                "{name} was admitted"
            );
            assert!(
                ValidatedCsr::parse(&der).is_err(),
                "{name} was admitted as Ed25519"
            );
        }
        // The signature BIT STRING is the request's last element; its
        // unused-bits octet follows the tag and the one-byte length.
        let mut outer = admitted.as_slice();
        let mut slots = take(&mut outer, 0x30).unwrap();
        take(&mut slots, 0x30).unwrap();
        take(&mut slots, 0x30).unwrap();
        let mut unused_bits = admitted.clone();
        unused_bits[admitted.len() - slots.len() + 2] = 1;
        assert!(ValidatedCsr::parse_as(&unused_bits, KeyAlgorithm::P256).is_err());
        for end in 0..admitted.len() {
            assert!(ValidatedCsr::parse_as(&admitted[..end], KeyAlgorithm::P256).is_err());
        }
        let mut forged = admitted;
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(ValidatedCsr::parse_as(&forged, KeyAlgorithm::P256).is_err());
    }

    /// The ECDSA signature check accepts only one strict DER pair of positive scalars.
    #[test]
    fn ecdsa_signature_shape_is_strict_der() {
        let scalar = [0x11; 32];
        let high = [[0].as_slice(), &[0x80; 32]].concat();
        let good = der(0x30, &[der(2, &scalar), der(2, &high)].concat());
        assert!(ecdsa_signature_is_der(&good));
        for bad in [
            der(0x30, &der(2, &scalar)),
            der(
                0x30,
                &[der(2, &scalar), der(2, &scalar), der(2, &scalar)].concat(),
            ),
            der(0x30, &[der(2, &[0]), der(2, &scalar)].concat()),
            der(0x30, &[der(2, &[0x80; 32]), der(2, &scalar)].concat()),
            der(0x30, &[der(2, &[0, 0x11]), der(2, &scalar)].concat()),
            der(0x30, &[der(2, &[0x11; 34]), der(2, &scalar)].concat()),
            der(0x30, &[der(4, &scalar), der(2, &scalar)].concat()),
            [good.as_slice(), &[0]].concat(),
            Vec::new(),
        ] {
            assert!(!ecdsa_signature_is_der(&bad), "{bad:02x?}");
        }
    }
}
