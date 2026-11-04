//! Random capabilities, hashed storage and bounded off-executor Argon2 recovery checks.
use super::{B64, Engine, Error, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use sha2::{Digest, Sha256};

pub(crate) fn random() -> String {
    B64.encode(rand::random::<[u8; 32]>())
}
pub(crate) fn hash(value: &str) -> String {
    B64.encode(Sha256::digest(value.as_bytes()))
}
/// Domain-separated public session label. It is neither the bearer nor its database lookup hash.
pub(crate) fn session_incarnation(token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"infraternal/layout/session-incarnation/v1\0");
    digest.update(token.as_bytes());
    B64.encode(digest.finalize())
}
pub(super) fn prf_salt(user: Option<&str>) -> String {
    // Stored v1/v2 envelopes keep their original input; never relabel ciphertext.
    let context = user.map_or_else(
        || "infraternal/keywrap/prf/v1".to_owned(),
        |user| format!("infraternal/keywrap/prf/v2|{user}"),
    );
    B64.encode(Sha256::digest(context.as_bytes()))
}
/// Stable public input [D108]: credential PRF secrets remain distinct; envelope AAD is unchanged.
pub(super) fn constant_prf_input() -> String {
    B64.encode(Sha256::digest(b"infraternal/keywrap/prf/v3"))
}
// Capacity is account/version independent and retryable. Exhaustion is never
// reported as a credential denial. Only independent verifier material is admitted.
static ARGON_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
pub(super) async fn recovery_hash(words: String) -> Result<String> {
    let permit = ARGON_SLOTS.try_acquire().map_err(|_| Error::Throttled)?;
    hash_with_permit(words, permit).await
}
/// Fixtures wait for bounded work rather than turning scheduler contention into
/// a credential failure. Production admission above deliberately remains retryable.
#[cfg(test)]
pub(super) async fn recovery_hash_fixture(words: String) -> Result<String> {
    // Parallel fixture creation must leave one production verifier slot free;
    // otherwise a recovery test can receive 429 before reaching its pause hook.
    static FIXTURES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let _fixture = FIXTURES.acquire().await.map_err(|_| Error::Invalid)?;
    let permit = ARGON_SLOTS.acquire().await.map_err(|_| Error::Invalid)?;
    hash_with_permit(words, permit).await
}
async fn hash_with_permit(
    words: String,
    permit: tokio::sync::SemaphorePermit<'static>,
) -> Result<String> {
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
#[cfg(test)]
pub(super) async fn verify_recovery(words: String, stored: String) -> Result<()> {
    let permit = ARGON_SLOTS.try_acquire().map_err(|_| Error::Throttled)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, &words)
            .map_err(|_| Error::Denied)?;
        if mnemonic.word_count() != 24 {
            return Err(Error::Denied);
        }
        let hash = PasswordHash::new(&stored).map_err(|_| Error::Denied)?;
        Argon2::default()
            .verify_password(mnemonic.to_string().as_bytes(), &hash)
            .map_err(|_| Error::Denied)
    })
    .await
    .map_err(|_| Error::Denied)?
}

/// Verify the domain-separated browser authentication secret, never a mnemonic or wrap key.
pub(super) async fn verify_secret(secret: String, stored: String) -> Result<()> {
    valid_secret(&secret)?;
    let permit = ARGON_SLOTS.try_acquire().map_err(|_| Error::Throttled)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let hash = PasswordHash::new(&stored).map_err(|_| Error::Denied)?;
        Argon2::default()
            .verify_password(secret.as_bytes(), &hash)
            .map_err(|_| Error::Denied)
    })
    .await
    .map_err(|_| Error::Denied)?
}

pub(super) fn valid_secret(secret: &str) -> Result<()> {
    let bytes = B64.decode(secret).map_err(|_| Error::Denied)?;
    if bytes.len() != 32 || B64.encode(bytes) != secret {
        return Err(Error::Denied);
    }
    Ok(())
}

#[cfg(test)]
mod verifier_tests {
    use super::*;
    #[tokio::test]
    async fn recovery_capacity_denial_is_not_a_legacy_credential_signal() {
        let _guard = super::super::tests::SERIAL.lock().await;
        let secret = B64.encode(rand::random::<[u8; 32]>());
        let stored = recovery_hash(secret.clone()).await.unwrap();
        let _slots = ARGON_SLOTS.acquire_many(2).await.unwrap();
        // A 401 makes an explicitly selected older-key browser try phrase migration.
        // Global capacity is independent of account/version and must be retryable 429.
        assert!(matches!(
            verify_secret(secret.clone(), stored).await,
            Err(Error::Throttled)
        ));
        assert!(matches!(recovery_hash(secret).await, Err(Error::Throttled)));
    }

    #[tokio::test]
    async fn fixture_waits_while_production_hashing_refuses_capacity() {
        let _guard = super::super::tests::SERIAL.lock().await;
        let slots = ARGON_SLOTS.acquire_many(2).await.unwrap();
        let mut fixture = tokio::spawn(recovery_hash_fixture(random()));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut fixture)
                .await
                .is_err()
        );
        assert!(matches!(
            recovery_hash(random()).await,
            Err(Error::Throttled)
        ));
        drop(slots);
        assert!(fixture.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn browser_secret_hashing_is_canonical_and_bounded() {
        let _guard = super::super::tests::SERIAL.lock().await;
        let secret = B64.encode(rand::random::<[u8; 32]>());
        let stored = recovery_hash(secret.clone()).await.unwrap();
        assert!(verify_secret(secret, stored.clone()).await.is_ok());
        assert!(
            verify_secret(B64.encode(rand::random::<[u8; 32]>()), stored.clone())
                .await
                .is_err()
        );
        assert!(verify_secret("not-a-secret".into(), stored).await.is_err());
    }
}
