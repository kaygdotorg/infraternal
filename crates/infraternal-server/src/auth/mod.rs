//! Passkey identity and single-use capabilities [23–29,53]. PRF/DEK plaintext stays in the browser.
//!
//! `WebAuthn` state is process-local, expires after five minutes, and is consumed before validation.
//! Restarting invalidates pending ceremonies, never credentials. SQLite transactions serialize
//! owner creation, recovery replacement, passkey limits and capability redemption.

mod account_events;
pub(crate) use account_events::AccountSubscription;
mod binding;
#[path = "../bootstrap_authorization.rs"]
mod bootstrap_authorization;
mod committed;
pub(crate) mod cookies;
mod crypto;
mod devices;
mod http;
mod recovery;
mod recovery_rotation;
mod sessions;
mod setup;
mod webauthn;
mod wraps;

use crypto::{constant_prf_input, prf_salt, random, recovery_hash};
pub(crate) use crypto::{hash, session_incarnation};
#[cfg(feature = "remote")]
pub(crate) use http::cookie as session_cookie_from_headers;
pub use sessions::Session;
use sessions::insert_session;
pub(crate) use sessions::require_session_tx;
pub use wraps::Wrap;
use wraps::put_wrap;
mod migration_compat;
#[cfg(test)]
mod migration_compat_tests;
#[cfg(test)]
mod migration_data_tests;
#[cfg(test)]
pub(crate) mod tests;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Row, SqlitePool};
#[cfg(test)]
use std::sync::atomic::AtomicI64;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, watch};
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub use http::router;
const DAY: i64 = 86_400;
const SESSION: i64 = 30 * DAY;
const CEREMONY: i64 = 300;
const FRESH: i64 = infraternal_plugin_api::FRESH_SECONDS;

/// Fresh real passkey verification without a browser session or implied role.
/// Construction stays inside the verifier; identifiers alone cannot forge it.
pub struct VerifiedPasskey {
    user: String,
    credential: String,
    verified_at: i64,
    expires: i64,
}
impl VerifiedPasskey {
    /// Identity authenticated by the registered credential's signature.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }
    /// Exact registered credential rechecked by the consuming operation.
    #[must_use]
    pub fn credential(&self) -> &str {
        &self.credential
    }
    /// Server time when this fresh proof completed verification.
    #[must_use]
    pub fn verified_at(&self) -> i64 {
        self.verified_at
    }
    /// Original challenge deadline, retained for the final operation check.
    #[must_use]
    pub fn expires(&self) -> i64 {
        self.expires
    }
}

/// Errors deliberately expose no credential, capability or database contents.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authorization failed")]
    Denied,
    #[error("invalid request")]
    Invalid,
    #[error("username already exists")]
    Conflict,
    #[error("owner setup is no longer available")]
    SetupClosed,
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
    rotate_recovery: bool,
    expires: i64,
    binding: Option<String>,
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
    binding: Option<String>,
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
    system_service: bool,
    pending: Arc<Mutex<Pending>>,
    ingress: Arc<Mutex<http::Ingress>>,
    recovery_changes: Arc<account_events::AccountEvents>,
    revocations: Arc<account_events::AccountEvents>,
    setup_consumed: Arc<watch::Sender<()>>,
    #[cfg(test)]
    recovery_pause: Arc<Mutex<Option<Arc<RecoveryPause>>>>,
    #[cfg(test)]
    authority_reads: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    // i64::MIN leaves HTTP on wall time; tests opt into a shared, advanceable clock.
    #[cfg(test)]
    test_http_time: Arc<AtomicI64>,
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

    /// Mark the server's public setup instructions for its installed service scope.
    pub(crate) fn with_system_service(mut self, system_service: bool) -> Self {
        self.system_service = system_service;
        self
    }

    /// Command shown beside the first-run token, derived from the action definition.
    fn setup_token_command(&self) -> String {
        #[cfg(feature = "cli-plugin")]
        {
            crate::cli::setup_token_command(self.system_service)
        }
        #[cfg(not(feature = "cli-plugin"))]
        {
            if self.system_service {
                "sudo infraternal server setup-token".to_owned()
            } else {
                "infraternal server setup-token".to_owned()
            }
        }
    }

    /// Subscribe to the successful owner-enrollment event used to retire its CLI socket.
    pub(crate) fn subscribe_setup_consumed(&self) -> watch::Receiver<()> {
        self.setup_consumed.subscribe()
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
        migration_compat::normalize_production_index(&pool).await?;
        migration_compat::MIGRATIONS.run(&pool).await?;
        let (setup_consumed, _) = watch::channel(());
        Ok(Self {
            pool,
            webauthn: Arc::new(webauthn),
            origin: url.origin().ascii_serialization(),
            system_service: false,
            pending: Arc::default(),
            ingress: Arc::default(),
            recovery_changes: Arc::default(),
            revocations: Arc::default(),
            setup_consumed: Arc::new(setup_consumed),
            #[cfg(test)]
            recovery_pause: Arc::default(),
            #[cfg(test)]
            authority_reads: Arc::default(),
            #[cfg(test)]
            test_http_time: Arc::new(AtomicI64::new(i64::MIN)),
        })
    }

    #[cfg(test)]
    pub(crate) fn authority_reads(&self, user: &str) -> usize {
        self.authority_reads
            .lock()
            .unwrap()
            .get(user)
            .copied()
            .unwrap_or(0)
    }

    /// Set the HTTP time shared by cloned test routers.
    #[cfg(test)]
    pub(crate) fn set_test_http_time(&self, now: i64) {
        self.test_http_time
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }

    /// Return the opted-in test time, if a test has installed one.
    #[cfg(test)]
    pub(super) fn test_http_time(&self) -> Option<i64> {
        let now = self
            .test_http_time
            .load(std::sync::atomic::Ordering::Relaxed);
        (now != i64::MIN).then_some(now)
    }
}

// Tests pause at the actual verification/write boundary without timing assumptions.
#[cfg(test)]
#[derive(Default)]
struct RecoveryPause {
    verified: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
