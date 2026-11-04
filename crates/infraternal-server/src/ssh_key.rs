//! Owns the dedicated D183 SSH identity; administrator envelopes and cold locks follow the D168 CA custody boundary.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use infraternal_plugin_ssh::transport::{Credentials, Secret};
use openssl::pkey::{Id, PKey, Private};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::sync::RwLock;

/// No paths, plaintext or underlying crypto diagnostics escape this boundary.
#[derive(Debug, thiserror::Error)]
#[error("server SSH key unavailable")]
pub struct SshKeyError;

/// Private key material has no serialization, Debug or disk constructor.
#[derive(Clone)]
pub struct SshKeyMaterial(PKey<Private>);
impl SshKeyMaterial {
    /// Generate the dedicated identity independently of the operating system's SSH files.
    /// # Errors
    /// Returns a content-free error if the existing crypto engine cannot generate Ed25519.
    pub fn generate() -> Result<Self, SshKeyError> {
        PKey::generate_ed25519().map(Self).map_err(|_| SshKeyError)
    }

    /// Restore only administrator-unwrapped Ed25519 material in memory.
    /// # Errors
    /// Refuses other algorithms and invalid private material.
    pub fn from_pem(pem: &Secret) -> Result<Self, SshKeyError> {
        let key = PKey::private_key_from_pem(pem.expose()).map_err(|_| SshKeyError)?;
        if key.id() != Id::ED25519 {
            return Err(SshKeyError);
        }
        Ok(Self(key))
    }

    /// The vault wraps this buffer immediately; never persist it or put it in argv.
    /// # Errors
    /// Returns a content-free error if key export fails.
    pub fn private_pem(&self) -> Result<Secret, SshKeyError> {
        self.0
            .private_key_to_pem_pkcs8()
            .map(Secret::new)
            .map_err(|_| SshKeyError)
    }

    /// Raw 32-byte Ed25519 public key.
    fn public(&self) -> Result<Vec<u8>, SshKeyError> {
        self.0.raw_public_key().map_err(|_| SshKeyError)
    }

    /// Transfer a zeroizing copy only to the scoped private SSH helper pipe.
    /// # Errors
    /// Returns a content-free key export failure.
    pub fn credentials(&self) -> Result<Credentials, SshKeyError> {
        Ok(Credentials::PrivateKey {
            key: self.private_pem()?,
            passphrase: None,
        })
    }
}

/// #78's administrator-envelope adapter supplies encryption custody. It must
/// wrap for current administrators, never persist a plaintext adjacent unlock key.
pub trait SshKeyVault: Send + Sync {
    /// Encrypt dedicated material for authorized administrator passkey recipients.
    /// # Errors
    /// Missing recipients or failed protection refuse publication.
    fn seal(&self, material: &SshKeyMaterial) -> Result<Vec<u8>, SshKeyError>;
}

/// Recheck administrator role and fresh passkey proof before returning plaintext.
/// Owner status or an ordinary unlocked browser session alone is insufficient.
pub trait AdministratorSshKeyUnlock {
    /// Unwrap the exact retained envelope after administrator authorization.
    /// # Errors
    /// Refuses denied/revoked authorization and failed decryption.
    fn unlock(&self, envelope: &[u8]) -> Result<SshKeyMaterial, SshKeyError>;
}

/// One key source shared by Settings and lazy bootstrap authentication.
pub trait SshKeySource: Send + Sync {
    /// Public metadata is available independently of cold-start signing locks.
    /// # Errors
    /// Refuses absent custody or invalid public state.
    fn public_key(&self) -> Result<PublicSshKey, SshKeyError>;
    /// Obtain only currently unlocked material; never read an ambient SSH identity.
    /// # Errors
    /// Missing/cold-locked material fails closed.
    fn load(&self) -> Result<SshKeyMaterial, SshKeyError>;
}

/// Settings may copy only this public half while the private key is locked.
#[derive(Clone, Serialize)]
pub struct PublicSshKey {
    /// The public key in `ssh-ed25519 <base64> infraternal-server` form, safe to paste into an authorized-keys file.
    pub public_key: String,
    /// SHA-256 fingerprint of the key, shown as `SHA256:<base64>`.
    pub fingerprint: String,
    /// True while the private half is locked and cannot sign.
    pub locked: bool,
}

/// A source retains opaque ciphertext on disk, unlocked material only in process memory.
pub struct StoredSshKey {
    public: Vec<u8>,
    envelope: Vec<u8>,
    material: RwLock<KeyState>,
}

/// Each explicit lock invalidates any unwrap already in progress. Exhausting the
/// generation counter leaves the source permanently locked instead of wrapping.
struct KeyState {
    generation: Option<u64>,
    material: Option<SshKeyMaterial>,
}

/// Automatic updates carry unlocked material only in memory; no disk, Debug or serde constructor.
pub struct SshKeyHandoff {
    public: Vec<u8>,
    envelope: Vec<u8>,
    material: SshKeyMaterial,
}

impl StoredSshKey {
    /// Trusted configured startup creates the dedicated key once, then starts locked.
    /// Concurrent startup uses the durable single-winner insert, never replaces an identity.
    /// # Errors
    /// Refuses unavailable administrator custody or inconsistent stored metadata.
    pub async fn initialize(
        pool: &SqlitePool,
        vault: &dyn SshKeyVault,
    ) -> Result<Self, SshKeyError> {
        if let Some(source) = Self::cold_start(pool).await? {
            return Ok(source);
        }
        let generated = SshKeyMaterial::generate()?;
        let public = generated.public()?;
        let envelope = vault.seal(&generated)?;
        if envelope.is_empty() || envelope.len() > 65536 {
            return Err(SshKeyError);
        }
        sqlx::query("INSERT INTO server_ssh_key(singleton,public_key,envelope) VALUES(1,?,?) ON CONFLICT(singleton) DO NOTHING")
            .bind(public).bind(envelope).execute(pool).await.map_err(|_| SshKeyError)?;
        // Always reload the winning row, including when another startup won.
        Self::cold_start(pool).await?.ok_or(SshKeyError)
    }

    /// Ordinary cold startup reads public metadata/ciphertext without decrypting it.
    /// # Errors
    /// Refuses malformed storage; absence is distinct from an existing corrupt key.
    pub async fn cold_start(pool: &SqlitePool) -> Result<Option<Self>, SshKeyError> {
        let row = sqlx::query("SELECT public_key,envelope FROM server_ssh_key WHERE singleton=1")
            .fetch_optional(pool)
            .await
            .map_err(|_| SshKeyError)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let public: Vec<u8> = row.try_get("public_key").map_err(|_| SshKeyError)?;
        let envelope: Vec<u8> = row.try_get("envelope").map_err(|_| SshKeyError)?;
        if public.len() != 32 || envelope.is_empty() || envelope.len() > 65536 {
            return Err(SshKeyError);
        }
        Ok(Some(Self {
            public,
            envelope,
            material: RwLock::new(KeyState {
                generation: Some(0),
                material: None,
            }),
        }))
    }

    /// Install only the administrator-unwrapped key matching retained public identity.
    /// # Errors
    /// Refuses authorization failures, changed identities or poisoned state.
    pub fn unlock_from(&self, adapter: &impl AdministratorSshKeyUnlock) -> Result<(), SshKeyError> {
        let generation = self
            .material
            .read()
            .map_err(|_| SshKeyError)?
            .generation
            .ok_or(SshKeyError)?;
        let material = adapter.unlock(&self.envelope)?;
        if material.public()? != self.public {
            return Err(SshKeyError);
        }
        let mut state = self.material.write().map_err(|_| SshKeyError)?;
        if state.generation != Some(generation) {
            return Err(SshKeyError);
        }
        state.material = Some(material);
        Ok(())
    }

    /// The CA lifecycle adapter locks both sources together; existing SSH operations
    /// finish with their scoped credentials, while new operations cannot load this key.
    /// # Errors
    /// Refuses poisoned state.
    pub fn lock(&self) -> Result<(), SshKeyError> {
        let mut state = self.material.write().map_err(|_| SshKeyError)?;
        state.material = None;
        state.generation = state
            .generation
            .and_then(|generation| generation.checked_add(1));
        Ok(())
    }

    /// Retain the old process's key while transferring a reference to its replacement.
    /// # Errors
    /// Cold-locked or poisoned state cannot produce a private handoff.
    pub fn handoff(&self) -> Result<SshKeyHandoff, SshKeyError> {
        Ok(SshKeyHandoff {
            public: self.public.clone(),
            envelope: self.envelope.clone(),
            material: self.load()?,
        })
    }

    /// Accept only the process-owned update/rollback handoff, matching retained identity.
    /// # Errors
    /// Refuses inconsistent public/private metadata.
    pub fn from_handoff(handoff: SshKeyHandoff) -> Result<Self, SshKeyError> {
        if handoff.material.public()? != handoff.public {
            return Err(SshKeyError);
        }
        Ok(Self {
            public: handoff.public,
            envelope: handoff.envelope,
            material: RwLock::new(KeyState {
                generation: Some(0),
                material: Some(handoff.material),
            }),
        })
    }
}

impl SshKeySource for StoredSshKey {
    fn public_key(&self) -> Result<PublicSshKey, SshKeyError> {
        // SSH public blob: two length-prefixed strings, fixed Ed25519 name and key.
        let mut blob = Vec::with_capacity(51);
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&self.public);
        Ok(PublicSshKey {
            public_key: format!("ssh-ed25519 {} infraternal-server", B64.encode(&blob)),
            fingerprint: format!(
                "SHA256:{}",
                B64.encode(Sha256::digest(&blob)).trim_end_matches('=')
            ),
            locked: self
                .material
                .read()
                .map_err(|_| SshKeyError)?
                .material
                .is_none(),
        })
    }
    fn load(&self) -> Result<SshKeyMaterial, SshKeyError> {
        self.material
            .read()
            .map_err(|_| SshKeyError)?
            .material
            .clone()
            .ok_or(SshKeyError)
    }
}

/// Missing #78 custody cannot be substituted with local identity files or fresh plaintext.
pub struct UnavailableSshKey;
impl SshKeySource for UnavailableSshKey {
    fn public_key(&self) -> Result<PublicSshKey, SshKeyError> {
        Err(SshKeyError)
    }
    fn load(&self) -> Result<SshKeyMaterial, SshKeyError> {
        Err(SshKeyError)
    }
}

#[cfg(test)]
#[path = "ssh_key_tests.rs"]
mod tests;

/// Reuse the authenticated-encryption fixture; it is not a production unlock policy.
#[cfg(test)]
pub(crate) fn test_custody() -> std::sync::Arc<impl SshKeyVault + AdministratorSshKeyUnlock> {
    std::sync::Arc::new(tests::Vault::new())
}
