//! Scopes browser-unwrapped key/password inputs to one target attempt and consumes each secret at most once.

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
    #[serde(default)]
    pub key: Option<Secret>,
    #[serde(default)]
    pub passphrase: Option<Secret>,
    #[serde(default)]
    pub password: Option<Secret>,
    #[serde(skip, default = "std::time::Instant::now")]
    received: std::time::Instant,
}

/// A start request binds private inputs to one existing target id before any work.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetAuth {
    pub target: String,
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

struct Once {
    expires: std::time::Instant,
    has_key: bool,
    has_password: bool,
    base: Arc<dyn AuthProvider>,
    key: Mutex<Option<(Secret, Option<Secret>)>>,
    password: Mutex<Option<Secret>>,
}
impl Once {
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
