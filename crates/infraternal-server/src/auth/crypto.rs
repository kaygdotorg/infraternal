//! Random capabilities, hashed storage and bounded off-executor Argon2 recovery checks.
use super::{B64, Engine, Error, Result};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use sha2::{Digest, Sha256};

pub(super) fn random() -> String {
    B64.encode(rand::random::<[u8; 32]>())
}
pub(super) fn hash(value: &str) -> String {
    B64.encode(Sha256::digest(value.as_bytes()))
}
pub(super) fn prf_salt() -> String {
    B64.encode(Sha256::digest(b"infraternal/keywrap/prf/v1"))
}
static ARGON_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
pub(super) async fn recovery_hash(words: String) -> Result<String> {
    let permit = ARGON_SLOTS.try_acquire().map_err(|_| Error::Denied)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let salt =
            SaltString::encode_b64(&rand::random::<[u8; 16]>()).map_err(|_| Error::Invalid)?;
        Argon2::default()
            .hash_password(words.as_bytes(), &salt)
            .map(|v| v.to_string())
            .map_err(|_| Error::Invalid)
    })
    .await
    .map_err(|_| Error::Invalid)?
}
