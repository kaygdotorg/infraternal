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

// OpenSSL's d2i entry point accepts a prefix and leaves suffixes unconsumed.
// Bound the whole request first, requiring one definite, shortest-length SEQUENCE.
// OpenSSL remains the PKCS10 parser and signature verifier; no requested fields
// besides its public key are ever copied into certificates.
fn validate_envelope(der: &[u8]) -> Result<(), CsrError> {
    if der.len() > MAX_CSR_DER || der.first() != Some(&0x30) {
        return Err(CsrError);
    }
    let first = *der.get(1).ok_or(CsrError)?;
    let (header, length) = match first {
        0..=127 => (2, usize::from(first)),
        0x81 => {
            let length = usize::from(*der.get(2).ok_or(CsrError)?);
            if length < 128 {
                return Err(CsrError);
            }
            (3, length)
        }
        0x82 => {
            let length = usize::from(u16::from_be_bytes([
                *der.get(2).ok_or(CsrError)?,
                *der.get(3).ok_or(CsrError)?,
            ]));
            if length < 256 {
                return Err(CsrError);
            }
            (4, length)
        }
        _ => return Err(CsrError),
    };
    if header + length != der.len() {
        return Err(CsrError);
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
