//! Passkey identity and single-use capabilities [23–29,53]. PRF/DEK plaintext stays in the browser.
//!
//! `WebAuthn` state is process-local, expires after five minutes, and is consumed before validation.
//! Restarting invalidates pending ceremonies, never credentials. SQLite transactions serialize
//! owner creation, recovery replacement, passkey limits and capability redemption.

mod crypto;
mod devices;
mod http;
mod recovery;
mod sessions;
mod setup;
mod webauthn;
mod wraps;

use crypto::{hash, prf_salt, random, recovery_hash, verify_recovery};
pub use sessions::Session;
use sessions::{insert_session, require_session_tx};
pub use wraps::Wrap;
use wraps::put_wrap;
#[cfg(test)]
pub(crate) mod tests;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub use http::router;
const DAY: i64 = 86_400;
const SESSION: i64 = 30 * DAY;
const CEREMONY: i64 = 300;
const FRESH: i64 = 300;

/// Errors deliberately expose no credential, capability or database contents.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authorization failed")]
    Denied,
    #[error("invalid request")]
    Invalid,
    #[error("username already exists")]
    Conflict,
    #[error("storage unavailable")]
    Storage(#[from] sqlx::Error),
    #[error("migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("ceremony failed")]
    Webauthn,
    #[error("serialization failed")]
    Json,
    #[error("too many requests")]
    Throttled,
}
// JSON diagnostics can echo attacker-supplied strings; never retain them in auth errors.
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::Json
    }
}
type Result<T> = std::result::Result<T, Error>;

struct Registration {
    state: PasskeyRegistration,
    user: String,
    username: String,
    display_name: String,
    authority: Authority,
    recovery_hash: Option<String>,
    expires: i64,
}
enum Authority {
    Setup(String),
    Add(String),
    Recovery(String),
}
enum LoginState {
    Identified(PasskeyAuthentication, String),
    Discoverable(DiscoverableAuthentication),
}
struct Login {
    state: LoginState,
    expires: i64,
}
#[derive(Default)]
struct Pending {
    registrations: HashMap<String, Registration>,
    logins: HashMap<String, Login>,
}

/// Shared auth library state. Configure the public HTTPS origin explicitly; proxy headers cannot change it.
#[derive(Clone)]
pub struct Auth {
    pool: SqlitePool,
    webauthn: Arc<Webauthn>,
    origin: String,
    pending: Arc<Mutex<Pending>>,
    ingress: Arc<Mutex<http::Ingress>>,
    #[cfg(test)]
    recovery_pause: Arc<Mutex<Option<Arc<RecoveryPause>>>>,
}

// Public entry points share one error contract, documented here instead of repeating it:
// any invalid/expired capability returns Denied; database failures return Storage.
#[allow(clippy::missing_errors_doc)]
impl Auth {
    /// Return the pinned public origin; HTTP proxy headers cannot override it.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Migrate storage and pin `WebAuthn` to an HTTPS RP origin without wildcard ports/subdomains.
    pub async fn new(pool: SqlitePool, rp_id: &str, origin: &str) -> Result<Self> {
        let url = url::Url::parse(origin).map_err(|_| Error::Invalid)?;
        if url.scheme() != "https"
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Error::Invalid);
        }
        let webauthn = WebauthnBuilder::new(rp_id, &url)
            .map_err(|_| Error::Invalid)?
            .rp_name("infraternal")
            .build()
            .map_err(|_| Error::Invalid)?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self {
            pool,
            webauthn: Arc::new(webauthn),
            origin: url.origin().ascii_serialization(),
            pending: Arc::default(),
            ingress: Arc::default(),
            #[cfg(test)]
            recovery_pause: Arc::default(),
        })
    }
}

// Tests pause at the actual verification/write boundary without timing assumptions.
#[cfg(test)]
#[derive(Default)]
struct RecoveryPause {
    verified: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
