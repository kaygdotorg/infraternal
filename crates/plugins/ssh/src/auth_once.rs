//! Scopes browser-unwrapped key/password inputs to one target attempt and consumes each secret at most once.
//!
//! A person can paste a private key, its passphrase or a password in the
//! browser for a single connection attempt. [`OneUseAuth`] carries those bytes
//! from the request to [`OneUseAuth::layer`], which wraps the normal
//! [`AuthProvider`] chain. The wrapper offers each secret to the SSH
//! transport exactly once, then erases it. It never stores the secret on disk,
//! never serializes it and has no `Debug` output. Unused secrets expire after
//! 60 seconds. If a one-use secret was supplied but already spent or expired,
//! the wrapper answers "no credential" instead of falling back to the stored
//! one of the same kind, so a typed secret never silently switches to another.

use crate::{
    auth_order::{AuthProvider, NetworkProvider},
    model::Failure,
    transport::{Credentials, Operation, Secret},
};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

/// Start and retry accept these transient bytes. No serialization or Debug implementation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OneUseAuth {
    /// Private key bytes (at most 24576, no NUL).
    #[serde(default)]
    pub key: Option<Secret>,
    /// Passphrase for `key`; only valid together with a key.
    #[serde(default)]
    pub passphrase: Option<Secret>,
    /// Account password (single line, at most 16384 bytes).
    #[serde(default)]
    pub password: Option<Secret>,
    /// When the bytes arrived; set at deserialization, starts the 60 second expiry.
    #[serde(skip, default = "std::time::Instant::now")]
    received: std::time::Instant,
}

/// A start request binds private inputs to one existing target id before any work.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetAuth {
    /// Id of the existing target the secrets are for.
    pub target: String,
    /// The transient secrets for that target.
    pub auth: OneUseAuth,
}

impl OneUseAuth {
    /// Validate the complete input before admission or credential helper creation.
    /// # Errors
    /// Refuses empty/oversized material, invalid prompts and a passphrase without a key.
    pub fn validate(&self) -> Result<(), Failure> {
        if self.key.is_none() && self.password.is_none()
            || self.passphrase.is_some() && self.key.is_none()
            || self.key.as_ref().is_some_and(|key| {
                key.expose().is_empty() || key.expose().len() > 24576 || key.expose().contains(&0)
            })
            || [&self.passphrase, &self.password]
                .into_iter()
                .flatten()
                .any(|secret| {
                    secret.expose().is_empty()
                        || secret.expose().len() > 16384
                        || secret.expose().contains(&0)
                        || secret.expose().contains(&b'\n')
                        || secret.expose().contains(&b'\r')
                })
        {
            return Err(Failure::unsupported(
                "The one-use SSH credential is invalid.",
            ));
        }
        Ok(())
    }

    /// Time left before the plaintext expires (60 seconds after arrival, zero once past).
    ///
    /// Plaintext waiting for a scheduler slot expires without entering a helper.
    #[must_use]
    pub fn remaining(&self) -> std::time::Duration {
        std::time::Duration::from_secs(60).saturating_sub(self.received.elapsed())
    }

    /// The automatic transport drops this wrapper after selecting a method, erasing
    /// any unused browser secret. The selected session retains only its authenticated connection.
    #[must_use]
    pub fn layer(self, base: Arc<dyn AuthProvider>) -> Arc<dyn AuthProvider> {
        Arc::new(Once {
            expires: self.received + std::time::Duration::from_secs(60),
            has_key: self.key.is_some(),
            has_password: self.password.is_some(),
            base,
            key: Mutex::new(self.key.map(|key| (key, self.passphrase))),
            password: Mutex::new(self.password),
        })
    }
}

/// The one-use layer over a base provider. Network and server-key questions go
/// straight to `base`; user key and password are answered from the secrets here.
struct Once {
    /// Deadline after which both secrets are erased.
    expires: std::time::Instant,
    /// A key was supplied, so the base provider's key is never consulted, even after it is spent.
    has_key: bool,
    /// Same for the password.
    has_password: bool,
    /// Fallback provider for everything not supplied as a one-use secret.
    base: Arc<dyn AuthProvider>,
    /// Key and optional passphrase; `take`n on first use.
    key: Mutex<Option<(Secret, Option<Secret>)>>,
    /// Password; `take`n on first use.
    password: Mutex<Option<Secret>>,
}
impl Once {
    /// True once the deadline passed; on that first observation both secrets are erased.
    fn expired(&self) -> bool {
        if std::time::Instant::now() < self.expires {
            return false;
        }
        // Both branches are erased together; a later fallback cannot revive them.
        let _ = self
            .key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let _ = self
            .password
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        true
    }
}
impl AuthProvider for Once {
    fn network(&self) -> Option<NetworkProvider> {
        self.base.network()
    }
    fn server_key(&self) -> Operation<'_, Option<Credentials>> {
        self.base.server_key()
    }
    fn user_key(&self) -> Operation<'_, Option<Credentials>> {
        if self.expired() {
            return Box::pin(async { Ok(None) });
        }
        let key = self
            .key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((key, passphrase)) = key {
            Box::pin(async move { Ok(Some(Credentials::PrivateKey { key, passphrase })) })
        } else if self.has_key {
            Box::pin(async { Ok(None) })
        } else {
            self.base.user_key()
        }
    }
    fn password(&self) -> Operation<'_, Option<Credentials>> {
        if self.expired() {
            return Box::pin(async { Ok(None) });
        }
        let password = self
            .password
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(password) = password {
            Box::pin(async move { Ok(Some(Credentials::Password(password))) })
        } else if self.has_password {
            Box::pin(async { Ok(None) })
        } else {
            self.base.password()
        }
    }
}

#[cfg(test)]
#[path = "auth_once_tests.rs"]
mod tests;
