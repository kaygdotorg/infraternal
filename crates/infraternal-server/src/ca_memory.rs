//! Holds the D168 cold-start lock and process-only update handoff; authentication adapters authorize administrator passkey unlocks, #78.

use crate::ca::{CaError, CaKeySource, CaMaterial, CertificateAuthority};
use openssl::x509::X509;
use std::sync::RwLock;
use tokio::sync::watch;

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
/// has no Debug, serialization or disk constructor; update IPC is a later slice.
pub struct CaHandoff(CaMaterial);

/// One issuer's public trust survives cold starts independently of its signing key.
/// Notifications are changes, not a timer; callers add administrator delivery.
pub struct MemoryCaSource {
    issuer: X509,
    material: RwLock<Option<CaMaterial>>,
    locked: watch::Sender<bool>,
}

impl MemoryCaSource {
    /// Start with public trust only; never infer an unlock from encrypted state.
    #[must_use]
    pub fn cold_start(issuer: X509) -> Self {
        let (locked, _) = watch::channel(true);
        Self {
            issuer,
            material: RwLock::new(None),
            locked,
        }
    }

    /// Public certificate verification never requires a signing unlock [168].
    #[must_use]
    pub fn issuer(&self) -> &X509 {
        &self.issuer
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
        self.load().map(CaHandoff)
    }

    /// Accept only a validated process-only automatic-update/rollback handoff.
    /// # Errors
    /// Refuses inconsistent issuer/key material; caller falls back to cold start.
    pub fn from_handoff(handoff: CaHandoff) -> Result<Self, CaError> {
        let source = Self::cold_start(handoff.0.issuer().clone());
        source.install(handoff.0)?;
        Ok(source)
    }

    fn install(&self, material: CaMaterial) -> Result<(), CaError> {
        CertificateAuthority::from_material(material.clone())?;
        if material.issuer().to_der().map_err(|_| CaError)?
            != self.issuer.to_der().map_err(|_| CaError)?
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
        assert_eq!(source.issuer().to_der().unwrap(), issuer.to_der().unwrap());
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
        let source = MemoryCaSource::cold_start(material.issuer().clone());
        let mut locked = source.subscribe_locked();
        source.unlock_from(&Unlocked(material)).unwrap();
        locked.changed().await.unwrap();
        assert!(!*locked.borrow_and_update());
        assert!(CertificateAuthority::from_source(&source).is_ok());
        let replacement = MemoryCaSource::from_handoff(source.handoff().unwrap()).unwrap();
        assert!(!*replacement.subscribe_locked().borrow());
        assert_eq!(
            replacement.issuer().to_der().unwrap(),
            source.issuer().to_der().unwrap()
        );
        assert!(CertificateAuthority::from_source(&replacement).is_ok());
        assert!(CertificateAuthority::from_source(&source).is_ok());
        // A new cold process gets public trust, never the previous unlocked state.
        let cold = MemoryCaSource::cold_start(replacement.issuer().clone());
        assert!(cold.load().is_err());
    }
}
