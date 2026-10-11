//! Exercises durable encrypted SSH custody, concurrent first initialization, and cold-lock identity preservation.

use super::*;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use std::sync::atomic::{AtomicUsize, Ordering};

async fn database() -> SqlitePool {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    pool
}

pub(super) struct Vault {
    wrapping: Secret,
    seals: AtomicUsize,
}
impl Vault {
    pub(super) fn new() -> Self {
        Self {
            wrapping: Secret::new(rand::random::<[u8; 32]>().to_vec()),
            seals: AtomicUsize::new(0),
        }
    }
}
impl SshKeyVault for Vault {
    fn seal(&self, material: &SshKeyMaterial) -> Result<Vec<u8>, SshKeyError> {
        self.seals.fetch_add(1, Ordering::Relaxed);
        let nonce = rand::random::<[u8; 12]>();
        let mut tag = [0; 16];
        let pem = material.private_pem()?;
        let encrypted = encrypt_aead(
            Cipher::aes_256_gcm(),
            self.wrapping.expose(),
            Some(&nonce),
            b"infraternal/server-ssh/test-v1",
            pem.expose(),
            &mut tag,
        )
        .map_err(|_| SshKeyError)?;
        let mut envelope = nonce.to_vec();
        envelope.extend(encrypted);
        envelope.extend(tag);
        Ok(envelope)
    }
}
impl AdministratorSshKeyUnlock for Vault {
    fn unlock(&self, envelope: &[u8]) -> Result<SshKeyMaterial, SshKeyError> {
        if envelope.len() < 28 {
            return Err(SshKeyError);
        }
        let pem = decrypt_aead(
            Cipher::aes_256_gcm(),
            self.wrapping.expose(),
            Some(&envelope[..12]),
            b"infraternal/server-ssh/test-v1",
            &envelope[12..envelope.len() - 16],
            &envelope[envelope.len() - 16..],
        )
        .map(Secret::new)
        .map_err(|_| SshKeyError)?;
        SshKeyMaterial::from_pem(&pem)
    }
}

#[tokio::test]
async fn first_start_is_wrapped_once_and_every_cold_start_is_locked() {
    let pool = database().await;
    let vault = Vault::new();
    assert!(StoredSshKey::cold_start(&pool).await.unwrap().is_none());
    let source = StoredSshKey::initialize(&pool, &vault).await.unwrap();
    let public = source.public_key().unwrap();
    assert!(public.locked);
    assert!(source.load().is_err());
    assert!(public.public_key.starts_with("ssh-ed25519 "));
    assert_eq!(public.fingerprint.len(), 50);
    source.unlock_from(&vault).unwrap();
    let material = source.load().unwrap();
    let pem = material.private_pem().unwrap();
    let stored: Vec<u8> = sqlx::query_scalar("SELECT envelope FROM server_ssh_key")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        !stored
            .windows(pem.expose().len())
            .any(|w| w == pem.expose())
    );
    assert!(!source.public_key().unwrap().locked);
    let restarted = StoredSshKey::initialize(&pool, &vault).await.unwrap();
    assert_eq!(vault.seals.load(Ordering::Relaxed), 1);
    assert_eq!(
        restarted.public_key().unwrap().public_key,
        public.public_key
    );
    assert!(restarted.load().is_err());
    assert!(restarted.public_key().unwrap().locked);
    assert!(restarted.unlock_from(&Vault::new()).is_err());
    assert!(restarted.load().is_err());
    restarted.unlock_from(&vault).unwrap();
    assert_eq!(
        restarted.load().unwrap().public().unwrap(),
        material.public().unwrap()
    );
    source.lock().unwrap();
    assert!(source.load().is_err());
    assert!(source.public_key().unwrap().locked);
}

#[tokio::test]
async fn concurrent_initialization_retains_one_identity_and_unwrap_cannot_replace_it() {
    struct WrongKey;
    impl AdministratorSshKeyUnlock for WrongKey {
        fn unlock(&self, _: &[u8]) -> Result<SshKeyMaterial, SshKeyError> {
            SshKeyMaterial::generate()
        }
    }
    let pool = database().await;
    let vault = Vault::new();
    let (a, b) = tokio::join!(
        StoredSshKey::initialize(&pool, &vault),
        StoredSshKey::initialize(&pool, &vault)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(
        a.public_key().unwrap().public_key,
        b.public_key().unwrap().public_key
    );
    a.unlock_from(&vault).unwrap();
    assert!(b.unlock_from(&WrongKey).is_err());
    assert!(b.load().is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM server_ssh_key")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn unavailable_or_empty_custody_publishes_no_key() {
    struct Empty;
    impl SshKeyVault for Empty {
        fn seal(&self, _: &SshKeyMaterial) -> Result<Vec<u8>, SshKeyError> {
            Ok(Vec::new())
        }
    }
    let pool = database().await;
    assert!(StoredSshKey::initialize(&pool, &Empty).await.is_err());
    assert!(StoredSshKey::cold_start(&pool).await.unwrap().is_none());
    assert!(UnavailableSshKey.load().is_err());
    assert!(UnavailableSshKey.public_key().is_err());
}

#[tokio::test]
async fn update_handoff_preserves_unlocked_identity_but_cold_restart_does_not() {
    let pool = database().await;
    let vault = Vault::new();
    let source = StoredSshKey::initialize(&pool, &vault).await.unwrap();
    assert!(source.handoff().is_err());
    source.unlock_from(&vault).unwrap();
    let public = source.public_key().unwrap();
    let replacement = StoredSshKey::from_handoff(source.handoff().unwrap()).unwrap();
    assert_eq!(
        replacement.public_key().unwrap().public_key,
        public.public_key
    );
    assert!(!replacement.public_key().unwrap().locked);
    source.lock().unwrap();
    assert!(source.load().is_err());
    assert!(replacement.load().is_ok());
    replacement.lock().unwrap();
    let restart = StoredSshKey::cold_start(&pool).await.unwrap().unwrap();
    assert!(restart.load().is_err());
    assert_eq!(restart.public_key().unwrap().public_key, public.public_key);
}

#[tokio::test]
async fn malformed_existing_storage_is_refused_without_generating_a_replacement() {
    let pool = database().await;
    let vault = Vault::new();
    let source = StoredSshKey::initialize(&pool, &vault).await.unwrap();
    let public = source.public_key().unwrap().public_key;
    sqlx::query("PRAGMA ignore_check_constraints=ON")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE server_ssh_key SET envelope=x''")
        .execute(&pool)
        .await
        .unwrap();
    assert!(StoredSshKey::initialize(&pool, &vault).await.is_err());
    assert_eq!(vault.seals.load(Ordering::Relaxed), 1);
    let raw: Vec<u8> = sqlx::query_scalar("SELECT public_key FROM server_ssh_key")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(raw, source.public);
    assert_eq!(source.public_key().unwrap().public_key, public);
}

#[test]
fn material_refuses_invalid_pem_and_non_ed25519_algorithms() {
    assert!(SshKeyMaterial::from_pem(&Secret::new(b"invalid private material".to_vec())).is_err());
    let rsa = openssl::rsa::Rsa::generate(2048).unwrap();
    let pem = PKey::from_rsa(rsa)
        .unwrap()
        .private_key_to_pem_pkcs8()
        .unwrap();
    assert!(SshKeyMaterial::from_pem(&Secret::new(pem)).is_err());
}

#[tokio::test]
async fn lock_during_administrator_unwrap_cannot_reinstall_private_material() {
    struct LockDuringUnwrap<'a> {
        source: &'a StoredSshKey,
        vault: &'a Vault,
    }
    impl AdministratorSshKeyUnlock for LockDuringUnwrap<'_> {
        fn unlock(&self, envelope: &[u8]) -> Result<SshKeyMaterial, SshKeyError> {
            let material = self.vault.unlock(envelope)?;
            // Deterministically interleave an explicit lock after authorization
            // and decryption, before the source can install returned material.
            self.source.lock()?;
            Ok(material)
        }
    }
    let pool = database().await;
    let vault = Vault::new();
    let source = StoredSshKey::initialize(&pool, &vault).await.unwrap();
    let adapter = LockDuringUnwrap {
        source: &source,
        vault: &vault,
    };
    assert!(
        source.unlock_from(&adapter).is_err(),
        "stale unlock must not win an explicit lock"
    );
    assert!(source.load().is_err());
    assert!(source.public_key().unwrap().locked);
    source.unlock_from(&vault).unwrap();
    assert!(source.load().is_ok());
}

#[tokio::test]
async fn lock_generation_exhaustion_never_wraps_into_an_unlocked_source() {
    let pool = database().await;
    let vault = Vault::new();
    let source = StoredSshKey::initialize(&pool, &vault).await.unwrap();
    source.unlock_from(&vault).unwrap();
    source.material.write().unwrap().generation = Some(u64::MAX);
    source.lock().unwrap();
    assert!(source.load().is_err());
    assert!(source.unlock_from(&vault).is_err());
    source.lock().unwrap();
    assert!(source.unlock_from(&vault).is_err());
    assert!(source.public_key().unwrap().locked);
}
