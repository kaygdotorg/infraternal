//! Holds the D168 cold-start lock and process-only update handoff; authentication adapters authorize administrator passkey unlocks, #78.

use crate::ca::{CaError, CaKeySource, CaMaterial, CertificateAuthority};
use openssl::x509::X509;
use std::sync::RwLock;
use tokio::sync::watch;

/// Initialize the provider's persistent private-key storage before any server
/// key is generated or imported, including the inherited update signer.
/// # Errors
/// Root servers refuse missing locking or dump exclusion. Development under an
/// unprivileged account continues with a warning if OS protection is unavailable.
pub fn initialize_private_key_memory() -> Result<(), crate::ServerError> {
    enforce_private_key_memory(
        infraternal_shim::openssl_secure::initialize(),
        nix::unistd::geteuid().is_root(),
    )
}

/// Applies the memory-protection result for private keys. As root it refuses to continue without locked memory and core-dump exclusion; as an unprivileged development account it only warns.
fn enforce_private_key_memory(protection: i32, root: bool) -> Result<(), crate::ServerError> {
    if protection == 1 {
        return Ok(());
    }
    if root {
        return Err(crate::ServerError::PrivateKeyMemory);
    }
    tracing::warn!(
        "OpenSSL secure heap protection unavailable; non-root server private key pages may be unlocked"
    );
    Ok(())
}

/// Authentication adapter must check current administrator membership and the
/// successful passkey ceremony before unwrapping that administrator's envelope.
/// Implementations fail closed on role revocation, bad proof or failed decrypt.
/// This boundary never accepts an owner boolean as a substitute for a role.
pub trait AdministratorCaUnlock {
    /// Supply private material only after current administrator passkey proof.
    /// # Errors
    /// Refuses missing/revoked authorization, invalid envelope or failed unwrap.
    fn unlock(&self) -> Result<CaMaterial, CaError>;
}

/// Process-only secret transfer for automatic update/rollback. Deliberately
/// has no Debug, serialization or disk constructor; the exec channel lives in `ca_handoff`.
pub struct CaHandoff {
    material: CaMaterial,
    https: Option<X509>,
    https_system: bool,
}

/// One issuer's public trust survives cold starts independently of its signing key.
/// Notifications are changes, not a timer; callers add administrator delivery.
pub struct MemoryCaSource {
    issuer: RwLock<Option<X509>>,
    https: Option<X509>,
    https_system: bool,
    material: RwLock<Option<CaMaterial>>,
    locked: watch::Sender<bool>,
}

impl MemoryCaSource {
    /// Start with public trust only; never infer an unlock from encrypted state.
    #[must_use]
    pub fn cold_start(issuer: X509) -> Self {
        let (locked, _) = watch::channel(true);
        Self {
            issuer: RwLock::new(Some(issuer)),
            https: None,
            https_system: false,
            material: RwLock::new(None),
            locked,
        }
    }

    /// Retain independent HTTPS enrollment trust on a provisioned cold start.
    #[must_use]
    pub fn cold_start_with_https(issuer: X509, https: X509) -> Self {
        let mut source = Self::cold_start(issuer);
        source.https = Some(https);
        source
    }

    /// A reverse proxy's HTTPS trust comes from the host system trust store.
    #[must_use]
    pub fn cold_start_with_system_https(issuer: X509) -> Self {
        let mut source = Self::cold_start(issuer);
        source.https_system = true;
        source
    }

    /// Public certificate verification never requires a signing unlock [168].
    /// # Errors
    /// Refuses unprovisioned or poisoned public trust.
    pub fn issuer(&self) -> Result<X509, CaError> {
        self.retained_issuer()?.ok_or(CaError)
    }
    /// Preserve the distinction between first setup and unavailable public state.
    pub(crate) fn retained_issuer(&self) -> Result<Option<X509>, CaError> {
        Ok(self.issuer.read().map_err(|_| CaError)?.clone())
    }
    /// Durable public publication survives failed signing installation. This
    /// never changes signing material or the cold-start lock notification.
    pub(crate) fn retain_published_issuer(&self, published: X509) -> Result<(), CaError> {
        let mut issuer = self.issuer.write().map_err(|_| CaError)?;
        if let Some(current) = &*issuer
            && current.to_der().map_err(|_| CaError)? != published.to_der().map_err(|_| CaError)?
        {
            return Err(CaError);
        }
        *issuer = Some(published);
        Ok(())
    }

    /// An explicitly configured server can await its first passkey-authorized
    /// provisioning without inventing a trust anchor or touching a private key.
    #[must_use]
    pub fn unprovisioned(https: Option<X509>) -> Self {
        let (locked, _) = watch::channel(true);
        Self {
            issuer: RwLock::new(None),
            https_system: https.is_none(),
            https,
            material: RwLock::new(None),
            locked,
        }
    }

    /// Publish the first issuer only after durable encrypted copies exist.
    /// # Errors
    /// Refuses replacing retained trust or inconsistent signing material.
    pub(crate) fn provision(&self, material: CaMaterial) -> Result<(), CaError> {
        CertificateAuthority::from_material(material.clone())?;
        self.retain_published_issuer(material.issuer().clone())?;
        *self.material.write().map_err(|_| CaError)? = Some(material);
        self.locked.send_replace(false);
        Ok(())
    }

    /// Subscribe to signer lock changes without an idle worker or polling loop.
    #[must_use]
    pub fn subscribe_locked(&self) -> watch::Receiver<bool> {
        self.locked.subscribe()
    }

    /// Unlock through a trusted current administrator/passkey policy adapter.
    /// # Errors
    /// Refuses failed authentication, changed issuer, malformed material or poison.
    pub fn unlock_from(&self, adapter: &impl AdministratorCaUnlock) -> Result<(), CaError> {
        self.install(adapter.unlock()?)
    }

    /// Retain signing in the old process while transferring a reference in memory.
    /// # Errors
    /// Locked or poisoned state cannot produce a secret handoff.
    pub fn handoff(&self) -> Result<CaHandoff, CaError> {
        Ok(CaHandoff {
            material: self.load()?,
            https: self.https.clone(),
            https_system: self.https_system,
        })
    }

    /// Accept only a validated process-only automatic-update/rollback handoff.
    /// # Errors
    /// Refuses inconsistent issuer/key material; caller falls back to cold start.
    pub fn from_handoff(handoff: CaHandoff) -> Result<Self, CaError> {
        let mut source = Self::cold_start(handoff.material.issuer().clone());
        source.https = handoff.https;
        source.https_system = handoff.https_system;
        source.install(handoff.material)?;
        Ok(source)
    }

    /// Unlocks the source with `material`. The material must be a valid CA whose issuer certificate is byte-identical to the one this source already trusts; anything else is refused. The key is stored before the unlocked event is sent, so no signer can see "unlocked" without a key.
    pub(crate) fn install(&self, material: CaMaterial) -> Result<(), CaError> {
        CertificateAuthority::from_material(material.clone())?;
        if material.issuer().to_der().map_err(|_| CaError)?
            != self.issuer()?.to_der().map_err(|_| CaError)?
        {
            return Err(CaError);
        }
        // Publish the material before its notification; concurrent signers can
        // never observe an "unlocked" event without the corresponding key.
        *self.material.write().map_err(|_| CaError)? = Some(material);
        self.locked.send_replace(false);
        Ok(())
    }
}

impl CaKeySource for MemoryCaSource {
    fn uses_system_https(&self) -> bool {
        self.https_system
    }
    fn public_issuer(&self) -> Option<X509> {
        self.issuer().ok()
    }
    fn https_certificate(&self) -> Option<X509> {
        self.https.clone()
    }
    fn subscribe_locked(&self) -> Option<watch::Receiver<bool>> {
        Some(MemoryCaSource::subscribe_locked(self))
    }
    fn load(&self) -> Result<CaMaterial, CaError> {
        self.material
            .read()
            .map_err(|_| CaError)?
            .clone()
            .ok_or(CaError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::{CaError, CaKeySource, CaMaterial, CertificateAuthority};

    #[test]
    fn unavailable_secure_heap_refuses_root_and_warns_for_nonroot() {
        const NAME: &str =
            "ca_memory::tests::unavailable_secure_heap_refuses_root_and_warns_for_nonroot";
        if std::env::var_os("INFRATERNAL_CA_HEAP_ZERO_LOCK").is_some() {
            let protection = infraternal_shim::openssl_secure::initialize();
            assert_eq!(protection, 2, "heap exists but OS locking is unavailable");
            assert!(enforce_private_key_memory(protection, true).is_err());
            assert!(enforce_private_key_memory(0, true).is_err());
            assert!(enforce_private_key_memory(protection, false).is_ok());
            assert_eq!(
                initialize_private_key_memory().is_err(),
                nix::unistd::geteuid().is_root()
            );
            return;
        }
        let output = std::process::Command::new("python3")
            .args(["-c", "import os,resource,sys; resource.setrlimit(resource.RLIMIT_MEMLOCK,(0,0)); os.environ['INFRATERNAL_CA_HEAP_ZERO_LOCK']='1'; os.execv(sys.argv[1],[sys.argv[1],'--exact',sys.argv[2],'--nocapture'])"])
            .arg(std::env::current_exe().unwrap()).arg(NAME)
            .stdin(std::process::Stdio::null()).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    struct Administrator(bool);
    impl AdministratorCaUnlock for Administrator {
        fn unlock(&self) -> Result<CaMaterial, CaError> {
            if self.0 {
                Ok(crate::ca::tests::test_material())
            } else {
                Err(CaError)
            }
        }
    }

    #[test]
    fn cold_start_retains_public_trust_and_denied_unlock_leaves_signing_locked() {
        let issuer = crate::ca::tests::test_material().issuer().clone();
        let source = MemoryCaSource::cold_start(issuer.clone());
        assert!(source.load().is_err());
        assert!(source.handoff().is_err());
        assert_eq!(
            source.issuer().unwrap().to_der().unwrap(),
            issuer.to_der().unwrap()
        );
        assert!(*source.subscribe_locked().borrow());
        assert!(source.unlock_from(&Administrator(false)).is_err());
        assert!(source.load().is_err());
        // A different generation must not replace the retained public trust.
        assert!(source.unlock_from(&Administrator(true)).is_err());
        assert!(source.load().is_err());
    }

    struct Unlocked(CaMaterial);
    impl AdministratorCaUnlock for Unlocked {
        fn unlock(&self) -> Result<CaMaterial, CaError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn accepted_unlock_notifies_and_memory_handoff_preserves_signing_without_a_timer() {
        let material = crate::ca::tests::test_material();
        let source = MemoryCaSource::cold_start_with_https(
            material.issuer().clone(),
            material.issuer().clone(),
        );
        let mut locked = source.subscribe_locked();
        source.unlock_from(&Unlocked(material)).unwrap();
        locked.changed().await.unwrap();
        assert!(!*locked.borrow_and_update());
        assert!(CertificateAuthority::from_source(&source).is_ok());
        let replacement = MemoryCaSource::from_handoff(source.handoff().unwrap()).unwrap();
        assert!(!*replacement.subscribe_locked().borrow());
        assert_eq!(
            replacement.https_certificate().unwrap().to_der().unwrap(),
            source.https_certificate().unwrap().to_der().unwrap()
        );
        assert_eq!(
            replacement.issuer().unwrap().to_der().unwrap(),
            source.issuer().unwrap().to_der().unwrap()
        );
        assert!(CertificateAuthority::from_source(&replacement).is_ok());
        assert!(CertificateAuthority::from_source(&source).is_ok());
        // A new cold process gets public trust, never the previous unlocked state.
        let cold = MemoryCaSource::cold_start(replacement.issuer().unwrap());
        assert!(cold.load().is_err());
    }
}
