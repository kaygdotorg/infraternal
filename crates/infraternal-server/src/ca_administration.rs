//! Authorizes CA unlock through a purpose-bound real passkey ceremony and current explicit administrator generation [168], #78.
use crate::{
    auth::Auth,
    ca::{CaError, CaKeySource, CaMaterial},
    ca_copies::CaCopies,
    ca_membership::{Membership, require_binding, require_live},
    ca_memory::{AdministratorCaUnlock, MemoryCaSource},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::hash::MessageDigest;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, Semaphore};
use zeroize::Zeroizing;

mod bootstrap;
mod roles;

/// Startup carries public trust and private encrypted-copy storage into runtime
/// auth wiring. Constructing this configuration never unlocks the signing source.
#[derive(Clone)]
pub struct CaAdministrationConfig {
    source: Arc<MemoryCaSource>,
    directory: PathBuf,
    pub(crate) bootstrap: Option<crate::ca_bootstrap::BootstrapConfig>,
}
impl CaAdministrationConfig {
    /// Associate the cold memory source with its checked private copy store.
    #[must_use]
    pub fn new(source: Arc<MemoryCaSource>, directory: PathBuf) -> Self {
        Self {
            source,
            directory,
            bootstrap: None,
        }
    }
    /// Share the configured process-only signer with the trusted exec lifecycle
    /// adapter. This never reads an encrypted copy or authorizes an HTTP unlock.
    #[must_use]
    pub fn memory_source(&self) -> Arc<MemoryCaSource> {
        self.source.clone()
    }

    pub(crate) fn with_runtime(
        &self,
        auth: Auth,
        pool: SqlitePool,
        hosts: crate::remote_runtime::RemoteHosts,
        store: crate::enrollment::EnrollmentStore,
    ) -> Result<Arc<CaAdministration>, CaError> {
        let copies = Arc::new(CaCopies::new(&self.directory)?);
        let mut authority = CaAdministration::new(auth, pool, self.source.clone(), copies);
        authority.bootstrap = self.bootstrap.clone().map(|config| {
            Arc::new(crate::ca_bootstrap::BootstrapRuntime::new(
                config, hosts, store,
            ))
        });
        Ok(Arc::new(authority))
    }
    /// Create one runtime authority using its actual migrated auth/database state.
    /// # Errors
    /// Refuses unsafe encrypted-copy storage instead of silently disabling unlock.
    pub fn with_auth(
        &self,
        auth: Auth,
        pool: SqlitePool,
    ) -> Result<Arc<CaAdministration>, CaError> {
        let copies = Arc::new(CaCopies::new(&self.directory)?);
        Ok(Arc::new(CaAdministration::new(
            auth,
            pool,
            self.source.clone(),
            copies,
        )))
    }
}

/// Explicit generation-changing role mutation; no owner flag mirrors membership.
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleChange {
    pub user_id: String,
    pub administrator: bool,
}
struct PendingUnlock {
    session_hash: String,
    membership: Membership,
    expires: i64,
    salt: Option<[u8; 32]>,
    role: Option<RoleChange>,
}
/// One shipping server's CA authority. Signing stays locked until a verified
/// current administrator decrypts their generation-bound private copy.
pub struct CaAdministration {
    auth: Auth,
    pool: SqlitePool,
    source: Arc<MemoryCaSource>,
    copies: Arc<CaCopies>,
    pending: Mutex<HashMap<String, PendingUnlock>>,
    crypto: Arc<Semaphore>,
    pub(crate) bootstrap: Option<Arc<crate::ca_bootstrap::BootstrapRuntime>>,
}
impl CaAdministration {
    // A process-owned mutation retains admission and the writer transaction if
    // HTTP disconnects. The purpose registry is consumed before this clone exists.
    fn operation(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            pool: self.pool.clone(),
            source: self.source.clone(),
            copies: self.copies.clone(),
            pending: Mutex::default(),
            crypto: self.crypto.clone(),
            bootstrap: self.bootstrap.clone(),
        }
    }

    fn copy_store(&self) -> Result<Arc<CaCopies>, CaError> {
        self.bootstrap.as_ref().map_or_else(
            || Ok(self.copies.clone()),
            |runtime| {
                let active = runtime.config.directory.join("active");
                if active.try_exists().map_err(|_| CaError)? {
                    Ok(Arc::new(CaCopies::new(&active)?))
                } else {
                    Ok(self.copies.clone())
                }
            },
        )
    }

    /// Read lock status only for a current, live administrator credential session.
    /// # Errors
    /// Refuses missing/revoked administrator authority or storage failures.
    pub async fn status(&self, token: &str, now: i64) -> Result<bool, CaError> {
        let mut tx = self.pool.begin().await.map_err(|_| CaError)?;
        require_live(&mut tx, &crate::auth::hash(token), now).await?;
        tx.rollback().await.map_err(|_| CaError)?;
        Ok(*self.source.subscribe_locked().borrow())
    }

    /// Whether public trust was retained, independently of the private signing key's lock state.
    ///
    /// # Errors
    /// Refuses an unavailable in-memory trust store.
    pub fn initialized(&self) -> Result<bool, CaError> {
        Ok(self.source.retained_issuer()?.is_some())
    }

    /// Return public-only issuer metadata after the caller has authorized a live administrator.
    ///
    /// # Errors
    /// Fails if the public trust source cannot provide its retained issuer.
    pub fn public_status(
        &self,
        clock: Option<&crate::clock_health::ClockHealth>,
    ) -> Result<crate::ca_status::CaStatus, CaError> {
        crate::ca_status::from_source(Some(self.source.as_ref()), clock)
    }

    /// Wire the real auth verifier, database and private copy store to one cold signer.
    #[must_use]
    pub fn new(
        auth: Auth,
        pool: SqlitePool,
        source: Arc<MemoryCaSource>,
        copies: Arc<CaCopies>,
    ) -> Self {
        Self {
            auth,
            pool,
            source,
            copies,
            pending: Mutex::new(HashMap::new()),
            crypto: Arc::new(Semaphore::new(8)),
            bootstrap: None,
        }
    }
    /// Start a single-use unlock proof for this exact live browser and role generation.
    /// # Errors
    /// Refuses non-administrators, expired/revoked sessions or excess pending ceremonies.
    pub async fn start(&self, token: &str, now: i64) -> Result<Value, CaError> {
        let session_hash = crate::auth::hash(token);
        let mut tx = self.pool.begin().await.map_err(|_| CaError)?;
        let membership = require_live(&mut tx, &session_hash, now).await?;
        tx.rollback().await.map_err(|_| CaError)?;
        let generation = u64::try_from(membership.generation()).map_err(|_| CaError)?;
        let copies = self.copy_store()?;
        let member = membership.user().to_owned();
        let permit = self
            .crypto
            .clone()
            .try_acquire_owned()
            .map_err(|_| CaError)?;
        let salt = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            copies.read(&member, generation)?.salt()
        })
        .await
        .map_err(|_| CaError)??;
        let fingerprint = self
            .source
            .issuer()?
            .digest(MessageDigest::sha256())
            .map_err(|_| CaError)?;
        let metadata = json!({"member":membership.user(),"generation":generation,"salt":B64.encode(salt),"issuer_fingerprint":B64.encode(fingerprint)});
        let mut pending = self.pending.lock().await;
        pending.retain(|_, entry| entry.expires > now);
        if pending.len() >= 1024 {
            return Err(CaError);
        }
        let mut start = self
            .auth
            .login_start(membership.user(), now)
            .await
            .map_err(|_| CaError)?;
        let id = start["ceremony"].as_str().ok_or(CaError)?.to_owned();
        // This private registry is the purpose binding. Ordinary login endpoints can
        // consume the underlying challenge but cannot produce a CA unlock operation.
        start["ca"] = metadata;
        pending.insert(
            id,
            PendingUnlock {
                session_hash,
                membership,
                expires: now.checked_add(300).ok_or(CaError)?,
                salt: None,
                role: None,
            },
        );
        Ok(start)
    }
    /// Verify a fresh passkey proof, decrypt a private copy and install under the
    /// SQLite writer lock that serializes role, credential and session revocation.
    /// # Errors
    /// Refuses foreign/expired/replayed ceremonies, bad passkeys or wrong wrapping keys.
    pub async fn finish(
        &self,
        token: &str,
        id: &str,
        proof: Value,
        scoped_key: Zeroizing<[u8; 32]>,
        now: i64,
    ) -> Result<(), CaError> {
        // Cancellation can drop this future at any await. Keep the custody event
        // outside the operation so even an interrupted proof has a safe outcome.
        let mut audit = UnlockAudit {
            user: None,
            outcome: "cancelled",
            installed: false,
        };
        let result = self
            .finish_audited(token, id, proof, scoped_key, now, &mut audit)
            .await;
        audit.outcome = if result.is_ok() {
            "unlocked"
        } else if audit.installed {
            "unlocked_error"
        } else {
            "refused"
        };
        result
    }

    async fn finish_audited(
        &self,
        token: &str,
        id: &str,
        proof: Value,
        scoped_key: Zeroizing<[u8; 32]>,
        now: i64,
        audit: &mut UnlockAudit,
    ) -> Result<(), CaError> {
        let session_hash = crate::auth::hash(token);
        let entry = {
            let mut pending = self.pending.lock().await;
            let entry = pending.get(id).ok_or(CaError)?;
            if !openssl::memcmp::eq(entry.session_hash.as_bytes(), session_hash.as_bytes()) {
                return Err(CaError);
            }
            // Attribute only a server-held ceremony bound to this exact session;
            // foreign/replayed IDs never become attacker-supplied audit identities.
            audit.user = Some(entry.membership.user().to_owned());
            pending.remove(id).ok_or(CaError)?
        };
        if entry.expires <= now || entry.salt.is_some() || entry.role.is_some() {
            return Err(CaError);
        }
        let verified = self
            .auth
            .verify_passkey(id, proof, now)
            .await
            .map_err(|_| CaError)?;
        let copies = self.copy_store()?;
        let issuer = self.source.issuer()?;
        let member = entry.membership.user().to_owned();
        let generation = u64::try_from(entry.membership.generation()).map_err(|_| CaError)?;
        // Private file I/O and authenticated decryption never block the reactor or
        // hold SQLite's writer lock. A canceled request owns no temporary session;
        // its blocking task/result still drops all transient signing material.
        // Keep the owned admission in the blocking task even if HTTP cancels.
        let permit = self
            .crypto
            .clone()
            .try_acquire_owned()
            .map_err(|_| CaError)?;
        let material = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            copies
                .read(&member, generation)?
                .open(&issuer, &member, generation, &scoped_key)
        })
        .await
        .map_err(|_| CaError)??;
        let mut tx = self.pool.begin().await.map_err(|_| CaError)?;
        let original = require_live(&mut tx, &session_hash, now).await?;
        require_binding(&original, &entry.membership)?;
        let registered =
            sqlx::query_scalar::<_, i64>("SELECT 1 FROM passkeys WHERE user_id=? AND id=?")
                .bind(verified.user())
                .bind(verified.credential())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| CaError)?;
        if registered.is_none() {
            return Err(CaError);
        }
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|time| i64::try_from(time.as_secs()).ok())
            .ok_or(CaError)?;
        let live_now = now.max(wall);
        // The credential query can suspend. Re-read the original session with
        // live time immediately before installation, still under the same writer lock.
        let original = require_live(&mut tx, &session_hash, live_now).await?;
        require_binding(&original, &entry.membership)?;
        if verified.user() != original.user()
            || verified.verified_at() > live_now
            || verified.verified_at() <= live_now - 300
            || verified.expires() <= live_now
            || entry.expires <= live_now
        {
            return Err(CaError);
        }
        self.source.unlock_from(&VerifiedMaterial(material))?;
        // Installation is synchronous. Mark custody before rollback can suspend,
        // fail or be canceled, so none of those paths reports a locked signer.
        audit.installed = true;
        // No authority changes are made by unlock. Retain the writer lock through
        // installation; rollback then lets a following revocation commit.
        tx.rollback().await.map_err(|_| CaError)
    }
}
struct VerifiedMaterial(CaMaterial);
impl AdministratorCaUnlock for VerifiedMaterial {
    fn unlock(&self) -> Result<CaMaterial, CaError> {
        Ok(self.0.clone())
    }
}

/// Content-free completion evidence; proof, token and wrapping material cannot
/// enter this guard. Drop also records cancellation without an idle audit task.
struct UnlockAudit {
    user: Option<String>,
    outcome: &'static str,
    installed: bool,
}
impl Drop for UnlockAudit {
    fn drop(&mut self) {
        let outcome = if self.installed && self.outcome == "cancelled" {
            "unlocked_cancelled"
        } else {
            self.outcome
        };
        tracing::info!(
            event = "server_ca_unlock",
            user = self.user.as_deref().unwrap_or("<unattributed>"),
            unix_seconds = crate::runtime::unix_seconds().unwrap_or(0),
            outcome,
            "server CA unlock"
        );
    }
}
