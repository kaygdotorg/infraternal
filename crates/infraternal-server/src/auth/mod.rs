//! Passkey identity and single-use capabilities [23–29,53]. PRF/DEK plaintext stays in the browser.
//!
//! `WebAuthn` state is process-local, expires after five minutes, and is consumed before validation.
//! Restarting invalidates pending ceremonies, never credentials. SQLite transactions serialize
//! owner creation, recovery replacement, passkey limits and capability redemption.

mod account_events;
pub(crate) use account_events::AccountSubscription;
mod action_tap;
mod binding;
#[path = "../bootstrap_authorization.rs"]
mod bootstrap_authorization;
mod committed;
pub(crate) mod cookies;
mod crypto;
mod devices;
#[cfg(feature = "remote")]
pub(crate) use devices::ApprovedMachineJoin;
#[cfg(all(feature = "remote", any(test, feature = "parser-checks")))]
pub(crate) use devices::check_join_machine_sample;
mod http;
pub(crate) use http::{AdmittedBrowserSession, refresh_api_cookie};
mod recovery;
mod recovery_rotation;
mod security_settings;
mod sessions;
mod setup;
mod webauthn;
mod wraps;

pub(crate) use action_tap::{TapAction, require_tap_tx};
/// 32 random bytes, base64url: an unguessable single-use capability id.
pub(crate) use crypto::random as random_capability;
use crypto::{constant_prf_input, prf_salt, random, recovery_hash};
pub(crate) use crypto::{hash, session_incarnation};
#[cfg(feature = "remote")]
pub(crate) use http::cookie as session_cookie_from_headers;
pub use sessions::Session;
use sessions::{insert_session, require_live_session_tx};
pub use wraps::Wrap;
use wraps::put_wrap;
mod migration_compat;
#[cfg(test)]
mod migration_compat_tests;
#[cfg(test)]
mod migration_data_tests;
/// Timestamp ordering and strict upgrade-history regression tests [D347].
#[cfg(test)]
mod migration_timestamp_tests;
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
#[cfg(feature = "remote")]
pub(crate) use http::router_with_invitation_issuer;
const DAY: i64 = 86_400;
const SESSION: i64 = 30 * DAY;
const CEREMONY: i64 = 300;

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
    /// The caller is a signed-in account, but its 15-minute admin window (D333) has closed.
    /// Every route that needs the window answers this the same way: HTTP 428, so the page can
    /// offer the quick passkey renewal (#498, #563). It is not an authorization failure.
    #[error("confirm with your passkey again")]
    FreshRequired,
    #[error("invalid request")]
    Invalid,
    #[error("username already exists")]
    Conflict,
    #[error("owner setup is no longer available")]
    SetupClosed,
    #[error("storage unavailable")]
    Storage(#[from] sqlx::Error),
    /// A statement on the D379 pool failed (see [`Auth::new`]). Same meaning
    /// and same message as `Storage`; only the driver differs during the port.
    #[error("storage unavailable")]
    Database(#[from] infraternal_db::Error),
    #[error("migration failed")]
    Migration(#[from] sqlx::migrate::MigrateError),
    /// The database file was named by a relative path (see
    /// `open_session_database`). Start the server with an absolute `--data`.
    #[error("the database path must be absolute")]
    RelativeDatabase,
    #[error("ceremony failed")]
    Webauthn,
    #[error("serialization failed")]
    Json,
    #[error("too many requests")]
    Throttled,
    #[error("enrollment unavailable")]
    RemoteUnavailable,
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
    /// Start order (see [`Pending::started`]); eviction drops the lowest.
    order: u64,
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
    /// Digest of the one action this tap is for (`action_tap`); `None` for a plain sign-in.
    action: Option<String>,
    /// For an anonymous (discoverable) ceremony started over HTTP, the
    /// caller's enclosing network; it bounds that network's share.
    network: Option<std::net::IpAddr>,
    /// Start order (see [`Pending::started`]); eviction drops the lowest.
    order: u64,
}
#[derive(Default)]
struct Pending {
    registrations: HashMap<String, Registration>,
    logins: HashMap<String, Login>,
    /// Ceremonies started so far. Expiry has one-second resolution, so a
    /// burst in one second would make "oldest" arbitrary; this counter orders
    /// starts exactly for the pool evictions (#263).
    started: u64,
}
impl Pending {
    /// The next start order.
    fn start(&mut self) -> u64 {
        self.started += 1;
        self.started
    }
}

/// Shared auth library state. Configure the public HTTPS origin explicitly; proxy headers cannot change it.
#[derive(Clone)]
pub struct Auth {
    pool: SqlitePool,
    /// The D379 rusqlite pool on the same file, when the database is a file
    /// on disk (#473, slice 2). The session statements run here; everything
    /// else still runs on `pool`. `None` for in-memory test databases, which
    /// the pool cannot open (it needs WAL); the session code then falls back
    /// to `pool`. See [`open_session_database`].
    db: Option<infraternal_db::Database>,
    webauthn: Arc<Webauthn>,
    origin: String,
    system_service: bool,
    pending: Arc<Mutex<Pending>>,
    ingress: Arc<Mutex<http::Ingress>>,
    device_sources: Arc<Mutex<devices::PendingSources>>,
    approval_ceremonies: Arc<Mutex<devices::ApprovalCeremonies>>,
    /// Approval commits wake only waiters that hold the matching poll capability.
    join_approval_changes: Arc<account_events::AccountEvents>,
    /// Cap long requests even when clients reuse a valid capability.
    join_approval_waiters: Arc<tokio::sync::Semaphore>,
    recovery_changes: Arc<account_events::AccountEvents>,
    recovery_clock: Arc<recovery::Clock>,
    revocations: Arc<account_events::AccountEvents>,
    setup_consumed: Arc<watch::Sender<()>>,
    #[cfg(test)]
    recovery_pause: Arc<Mutex<Option<Arc<RecoveryPause>>>>,
    #[cfg(test)]
    authority_reads: Arc<std::sync::Mutex<HashMap<String, usize>>>,
    /// How many times a session read took the writer (a slide or the
    /// expired-pending cleanup), so tests can prove a read that needs no
    /// slide writes nothing (#559).
    #[cfg(test)]
    session_writes: Arc<std::sync::atomic::AtomicUsize>,
    // i64::MIN leaves HTTP on wall time; tests opt into a shared, advanceable clock.
    #[cfg(test)]
    test_http_time: Arc<AtomicI64>,
    // MIN retains explicit legacy fixture clocks; otherwise independent elapsed nanoseconds.
    #[cfg(test)]
    test_recovery_elapsed: Arc<AtomicI64>,
}

// Public entry points share one error contract, documented here instead of repeating it:
// any invalid/expired capability returns Denied; database failures return Storage.
#[allow(clippy::missing_errors_doc)]
impl Auth {
    /// Let sibling server adapters share the pool used by auth transactions.
    #[must_use]
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

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
        // After the migrations, so the pool opens a file whose schema is current.
        let db = open_session_database(&pool).await?;
        let recovery_clock = Arc::new(recovery::Clock::load(&pool).await?);
        recovery_clock.start_checkpointing(pool.clone());
        #[cfg(test)]
        let test_recovery_elapsed = recovery_clock.test_elapsed.clone();
        let (setup_consumed, _) = watch::channel(());
        Ok(Self {
            pool,
            db,
            webauthn: Arc::new(webauthn),
            origin: url.origin().ascii_serialization(),
            system_service: false,
            pending: Arc::default(),
            ingress: Arc::default(),
            device_sources: Arc::default(),
            approval_ceremonies: Arc::default(),
            join_approval_changes: Arc::default(),
            join_approval_waiters: Arc::new(tokio::sync::Semaphore::new(128)),
            recovery_changes: Arc::default(),
            recovery_clock,
            revocations: Arc::default(),
            setup_consumed: Arc::new(setup_consumed),
            #[cfg(test)]
            recovery_pause: Arc::default(),
            #[cfg(test)]
            authority_reads: Arc::default(),
            #[cfg(test)]
            session_writes: Arc::default(),
            #[cfg(test)]
            test_http_time: Arc::new(AtomicI64::new(i64::MIN)),
            #[cfg(test)]
            test_recovery_elapsed,
        })
    }

    /// Shut the D379 pool down at server exit: finish queued session writes,
    /// then copy the WAL into the main file (`infraternal_db::Database::close`).
    /// Does nothing when there is no pool. Every clone shares the pool, so call
    /// it once, after the listener has stopped.
    pub async fn close_database(&self) {
        if let Some(db) = &self.db {
            db.close().await;
        }
    }

    /// The D379 pool (`infraternal-db`) shared with the session statements, for
    /// other hot writes that move off sqlx (#473, #562). `None` for in-memory
    /// test databases; callers then run the same SQL on sqlx.
    pub(crate) fn database(&self) -> Option<&infraternal_db::Database> {
        self.db.as_ref()
    }

    /// Whether the session statements run on the D379 pool (tests only).
    #[cfg(test)]
    pub(crate) fn sessions_on_pool(&self) -> bool {
        self.db.is_some()
    }

    /// How many socket authority reads ran for `user` so far (tests only).
    #[cfg(test)]
    pub(crate) fn authority_reads(&self, user: &str) -> usize {
        self.authority_reads
            .lock()
            .unwrap()
            .get(user)
            .copied()
            .unwrap_or(0)
    }

    /// How many session reads have taken the writer so far (tests only).
    #[cfg(test)]
    pub(crate) fn session_writes(&self) -> usize {
        self.session_writes
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Count one session read that takes the writer (tests only).
    #[cfg(test)]
    pub(super) fn count_session_write(&self) {
        self.session_writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

/// The file name prefix sqlx gives an in-memory database (`sqlite::memory:`):
/// `file:sqlx-in-memory-N`. See [`open_session_database`].
const SQLX_IN_MEMORY: &str = "file:sqlx-in-memory-";

/// Open the D379 rusqlite pool (`infraternal-db`) on the same file as `pool`,
/// or `None` when `pool` is not a database file on disk (#473, slice 2).
///
/// The port moves call sites one slice at a time, so both drivers share the
/// file for a while. sqlx still owns the schema: its migrations ran before
/// this is called, and the pool only opens the existing file
/// (`create_if_missing: false`). The pool gets two readers, not the default
/// seven, because only the session reads use them so far; the eight sqlx
/// connections still serve everything else, and each reader costs a thread
/// and its page cache.
///
/// Which databases get the pool:
/// - **In-memory** (sqlx names it `file:sqlx-in-memory-N`): no pool, quietly.
///   SQLite would read that name as a relative file and create it in the
///   working directory, and an in-memory database cannot run in WAL mode
///   anyway. These are test databases.
/// - **A relative path: refused** with [`Error::RelativeDatabase`]. The pool reopens
///   the path on each of its threads, so a relative name would follow any
///   later change of directory, and falling back to sqlx would silently bring
///   back the unbounded-WAL slide (J696 P3). The server opens its database by
///   an absolute path (`runtime::open_database`), so only a caller that
///   skips that reaches this.
/// - **An absolute path to a regular file in WAL mode**: the pool.
/// - **Anything else stays on sqlx, with a warning.** The pool switches every
///   file it opens to WAL, and that setting is stored in the file. The
///   server's own database is WAL from `open_database`; a file the caller
///   keeps in another journal mode (some tests use a rollback journal on
///   purpose, to make a read wait on a lock) must stay as it is.
async fn open_session_database(pool: &SqlitePool) -> Result<Option<infraternal_db::Database>> {
    let options = pool.connect_options();
    let path = options.get_filename();
    if path
        .to_str()
        .is_some_and(|name| name.starts_with(SQLX_IN_MEMORY))
    {
        return Ok(None);
    }
    if !path.is_absolute() {
        tracing::error!(
            path = %path.display(),
            "the server database path must be absolute; start the server with an absolute --data folder"
        );
        return Err(Error::RelativeDatabase);
    }
    if !std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file()) {
        tracing::warn!(
            path = %path.display(),
            "the database is not a regular file; session statements stay on sqlx"
        );
        return Ok(None);
    }
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(pool)
        .await?;
    if !mode.eq_ignore_ascii_case("wal") {
        tracing::warn!(
            path = %path.display(),
            journal_mode = %mode,
            "the database is not in WAL mode; session statements stay on sqlx"
        );
        return Ok(None);
    }
    let db = infraternal_db::Database::open(
        path,
        infraternal_db::Options {
            readers: 2,
            create_if_missing: false,
            ..infraternal_db::Options::default()
        },
    )
    .await?;
    Ok(Some(db))
}

// Tests pause at the actual verification/write boundary without timing assumptions.
#[cfg(test)]
#[derive(Default)]
struct RecoveryPause {
    verified: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
