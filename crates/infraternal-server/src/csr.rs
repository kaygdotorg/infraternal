//! Bounded proof-of-possession admission for host CSRs; request identity and extensions confer no authority [133], #78.

use openssl::{
    pkey::{Id, PKey, Public},
    x509::X509Req,
};

/// Maximum encoded PKCS10 request, checked before invoking OpenSSL.
pub const MAX_CSR_DER: usize = 4096;

/// Admission errors contain no request bytes or crypto-library diagnostic text.
#[derive(Debug, thiserror::Error)]
#[error("host CSR refused")]
pub struct CsrError;

/// A verified Ed25519 public key; callers supply host identity independently.
pub struct ValidatedCsr {
    key: PKey<Public>,
}

impl ValidatedCsr {
    /// Validate one bounded PKCS10 DER request before certificate construction.
    /// # Errors
    /// Rejects malformed, oversized, noncanonical or unauthenticated requests.
    pub fn parse(der: &[u8]) -> Result<Self, CsrError> {
        validate_envelope(der)?;
        let request = X509Req::from_der(der).map_err(|_| CsrError)?;
        let key = request.public_key().map_err(|_| CsrError)?;
        if request.version() != 0
            || key.id() != Id::ED25519
            || !request.verify(&key).map_err(|_| CsrError)?
            || request.to_der().map_err(|_| CsrError)? != der
        {
            return Err(CsrError);
        }
        Ok(Self { key })
    }

    /// Only the verified key crosses into certificate construction.
    #[must_use]
    pub fn key(&self) -> &PKey<Public> {
        &self.key
    }
}

// OpenSSL caches signed request-info bytes, so re-encoding cannot establish
// shortest nested lengths or mandatory PKCS10 fields. This allocation-free
// preflight bounds nesting before OpenSSL parses and verifies possession.
/// Checks the outer shape of the request before OpenSSL sees it: at most [`MAX_CSR_DER`] bytes, a single SEQUENCE with no trailing bytes, a bounded nesting depth, version 0, shortest-form lengths and an Ed25519 key algorithm with no parameters.
fn validate_envelope(der: &[u8]) -> Result<(), CsrError> {
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
    ed25519_algorithm(&mut spki)?;
    let key = take(&mut spki, 3)?;
    if key.len() != 33 || key[0] != 0 || !spki.is_empty() {
        return Err(CsrError);
    }
    let attributes = take(&mut info, 0xa0)?;
    validate_set(attributes)?; // Implicit SET OF attributes is mandatory, even empty.
    if !info.is_empty() {
        return Err(CsrError);
    }
    ed25519_algorithm(&mut slots)?;
    let signature = take(&mut slots, 3)?;
    if signature.len() != 65 || signature[0] != 0 || !slots.is_empty() {
        return Err(CsrError);
    }
    Ok(())
}

/// Accepts only the Ed25519 algorithm identifier with parameters absent, as RFC 8410 requires.
fn ed25519_algorithm(input: &mut &[u8]) -> Result<(), CsrError> {
    // RFC 8410 requires absent parameters, including in signature algorithms.
    if take(input, 0x30)? != [6, 3, 0x2b, 0x65, 0x70] {
        return Err(CsrError);
    }
    Ok(())
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
}
