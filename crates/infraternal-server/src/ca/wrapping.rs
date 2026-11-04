//! Seals Ed25519 CA seed copies for one administrator membership and issuer; plaintext never enters persistence or diagnostics [168], #78.

use super::{CaError, CaMaterial};
use openssl::{
    hash::MessageDigest,
    pkey::Id,
    symm::{Cipher, Crypter, Mode, encrypt_aead},
    x509::X509,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Public binding fields are also authenticated as AEAD associated data.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedCa {
    /// SHA-256 digest of the issuer certificate this copy belongs to (32 bytes).
    pub(crate) issuer_fingerprint: Vec<u8>,
    /// Administrator this copy was sealed for.
    pub(crate) member: String,
    /// Membership generation the copy was sealed for; always at least 1.
    pub(crate) epoch: u64,
    /// Public salt for the browser's key derivation (32 bytes).
    pub(crate) salt: Vec<u8>,
    /// Random AES-GCM nonce (12 bytes).
    nonce: Vec<u8>,
    /// Encrypted 32-byte Ed25519 seed followed by its 16-byte tag (48 bytes).
    ciphertext: Vec<u8>,
}
impl WrappedCa {
    /// Decode only a bounded, fully shaped encrypted copy; contents grant no authority.
    /// # Errors
    /// Rejects oversized JSON, malformed bindings, unknown fields or invalid field lengths.
    pub fn decode(bytes: &[u8]) -> Result<Self, CaError> {
        if bytes.len() > 8192 {
            return Err(CaError);
        }
        let copy: Self = serde_json::from_slice(bytes).map_err(|_| CaError)?;
        if copy.member.is_empty()
            || copy.member.len() > 256
            || copy.epoch == 0
            || copy.issuer_fingerprint.len() != 32
            || copy.salt.len() != 32
            || copy.nonce.len() != 12
            || copy.ciphertext.len() != 48
        {
            return Err(CaError);
        }
        Ok(copy)
    }

    /// Return only the public salt used by the browser's scoped wrapping-key derivation.
    /// # Errors
    /// Refuses a malformed salt before it can become an unlock challenge input.
    pub fn salt(&self) -> Result<[u8; 32], CaError> {
        self.salt.as_slice().try_into().map_err(|_| CaError)
    }

    /// Encrypt a seed for one membership using a browser-derived, domain-separated key.
    /// # Errors
    /// Rejects missing bindings, incompatible keys or cryptographic failure.
    pub fn seal(
        material: &CaMaterial,
        member: &str,
        epoch: u64,
        salt: &[u8; 32],
        scoped_key: &[u8; 32],
    ) -> Result<Self, CaError> {
        if member.is_empty() || member.len() > 256 || epoch == 0 || material.key.id() != Id::ED25519
        {
            return Err(CaError);
        }
        super::CertificateAuthority::from_material(material.clone())?;
        let seed = Zeroizing::new(material.key.raw_private_key().map_err(|_| CaError)?);
        if seed.len() != 32 {
            return Err(CaError);
        }
        let fingerprint = material
            .issuer
            .digest(MessageDigest::sha256())
            .map_err(|_| CaError)?;
        let mut wrapped = Self {
            issuer_fingerprint: fingerprint.to_vec(),
            member: member.into(),
            epoch,
            salt: salt.to_vec(),
            nonce: vec![0; 12],
            ciphertext: Vec::new(),
        };
        openssl::rand::rand_bytes(&mut wrapped.nonce).map_err(|_| CaError)?;
        let mut tag = [0; 16];
        wrapped.ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            scoped_key,
            Some(&wrapped.nonce),
            &wrapped.binding()?,
            &seed,
            &mut tag,
        )
        .map_err(|_| CaError)?;
        drop(seed);
        wrapped.ciphertext.extend_from_slice(&tag);
        Ok(wrapped)
    }
    /// Authenticate and restore one copy against its retained public issuer.
    /// # Errors
    /// Refuses altered bindings, malformed ciphertext or failed authentication.
    pub fn open(
        &self,
        issuer: &X509,
        member: &str,
        epoch: u64,
        scoped_key: &[u8; 32],
    ) -> Result<CaMaterial, CaError> {
        if member.is_empty()
            || member.len() > 256
            || epoch == 0
            || self.member != member
            || self.epoch != epoch
            || self.salt.len() != 32
            || self.nonce.len() != 12
            || self.ciphertext.len() != 48
            || self.issuer_fingerprint.as_slice()
                != issuer
                    .digest(MessageDigest::sha256())
                    .map_err(|_| CaError)?
                    .as_ref()
        {
            return Err(CaError);
        }
        // GCM emits unauthenticated plaintext before final tag verification.
        // Own that buffer in Zeroizing before either update or finalize can fail.
        let cipher = Cipher::aes_256_gcm();
        let mut decrypt = Crypter::new(cipher, Mode::Decrypt, scoped_key, Some(&self.nonce))
            .map_err(|_| CaError)?;
        decrypt.aad_update(&self.binding()?).map_err(|_| CaError)?;
        decrypt
            .set_tag(&self.ciphertext[32..])
            .map_err(|_| CaError)?;
        let mut seed = Zeroizing::new(vec![0; 32 + cipher.block_size()]);
        let written = decrypt
            .update(&self.ciphertext[..32], &mut seed)
            .map_err(|_| CaError)?;
        let count = written
            + decrypt
                .finalize(&mut seed[written..])
                .map_err(|_| CaError)?;
        if count != 32 {
            return Err(CaError);
        }
        let key = CaMaterial::key_from_seed(&seed[..count])?;
        drop(seed);
        let material = CaMaterial::new(key, issuer.clone());
        super::CertificateAuthority::from_material(material.clone())?;
        Ok(material)
    }
    /// Associated data that AES-GCM authenticates with the seed: a version label, the
    /// member name (length-prefixed), the generation, the issuer fingerprint and the
    /// salt. Changing any public field of a copy therefore makes `open` fail.
    fn binding(&self) -> Result<Vec<u8>, CaError> {
        let length = u16::try_from(self.member.len()).map_err(|_| CaError)?;
        let mut bytes = b"infraternal-ca-copy-v1\0".to_vec();
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(self.member.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.issuer_fingerprint);
        bytes.extend_from_slice(&self.salt);
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "wrapping_tests.rs"]
mod tests;
