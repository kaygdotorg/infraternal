//! Sliding sessions, the admin window, provider diagnostics and transaction authority rechecks
//! [28]. Per-action taps are bound to one action in `action_tap` (D336).
//!
//! # The D379 pool (#473, slice 2)
//!
//! The session slide is a write on every authenticated request, the server's
//! hottest SQLite path. It is the first to move from sqlx to the rusqlite pool
//! (`infraternal-db`): the slide, its denial cleanup, the socket renewal, and
//! the two indexed session reads (`cookie_state`, `live_expiry`). On the pool:
//!
//! - The slide and its cleanup run as **one** closure on the pool's single
//!   writer thread: one hop instead of sqlx's two pool checkouts, and the
//!   `UPDATE … RETURNING` no longer races sqlx's other writers for SQLite's
//!   write lock with busy sleeps inside this process's pool.
//! - Every write commits through `COMMIT`, so the pool's WAL hook always runs
//!   and the WAL stays bounded. sqlx's `fetch_optional` on
//!   `UPDATE … RETURNING` never reached SQLite's auto-checkpoint, so this path
//!   used to grow the WAL without bound (J619). Background passes copy most
//!   of the log off the request path, but the log only rewinds when a pass
//!   finishes inside one gap between commits, which needs a gap longer than a
//!   checkpoint's fsync. So a steady stream of slides, paced or not, still
//!   reaches the pool's 8,000-page backstop: J696 measured that at 462 and
//!   737 slides/s on backup01, where about one slide in 4,000 checkpoints
//!   inline and takes 19–23 ms (sqlx defers a 180 ms checkpoint instead, and
//!   keeps a 100 MB log).
//! - The two reads run on the pool's read-only reader threads.
//!
//! When `Auth` has no pool (in-memory test databases, see
//! `open_session_database`), the same statements run on sqlx.
//!
//! # Read first, slide only when due (#559, J1151)
//!
//! Every authenticated HTTP route calls [`Auth::session`]. It used to run the
//! slide on every call, so each request queued on the pool's single writer
//! even when the deadline had moved a moment ago, and an unknown cookie cost
//! a write too (the slide that matched nothing, then the pending cleanup).
//! Now the session is first read on a reader thread, with the same columns
//! and the same liveness rule; the writer is taken only when
//!
//! - the session is live and unlocked and its slide is due: its deadline is
//!   more than a minute behind `now + SESSION` (the same rule a socket's
//!   renewal uses, [`Auth::renewal_due`]), or ahead of it after the clock
//!   stepped back. The slide is the same `UPDATE … RETURNING`, which checks
//!   liveness again under the writer, so a session revoked or expired between
//!   the read and the write is refused and never revived; or
//! - the token's pending login has expired, which is still deleted.
//!
//! What stays the same: a row past its deadline, a deleted (revoked) row and
//! a pending login on a full-session route are refused; the read starts a
//! fresh snapshot per call, so a revocation committed before the request is
//! seen at once; `fresh` (the admin window) is never written here. The only
//! change is that the idle deadline can be up to a minute earlier than with a
//! write per request, never later.
//! Everything else in this file, and every transaction that takes a sqlx
//! `Transaction` (`require_live_session_tx`, `insert_session`), stays on sqlx
//! until its callers move.
use super::{Auth, Error, Result, Row, SESSION, Serialize, hash};
use infraternal_db::rusqlite::{OptionalExtension, Transaction, params};

/// The columns a `Session` is built from, shared by the read and the slide so
/// both return exactly the same row. A macro, so `concat!` can splice it into
/// each statement at compile time.
macro_rules! session_columns {
    () => {
        "user_id,device,fresh,expires,unlocked,(SELECT username FROM users WHERE id=sessions.user_id) AS username,(SELECT display_name FROM users WHERE id=sessions.user_id) AS display_name,(SELECT aaguid FROM passkeys WHERE id=sessions.passkey_id AND user_id=sessions.user_id) AS aaguid,(SELECT ready FROM recovery WHERE user_id=sessions.user_id) AS recovery_ready,(SELECT recovery_version=1 OR recovery_wrap_version=1 FROM users WHERE id=sessions.user_id) AS recovery_words_need_replacing,(SELECT owner FROM users WHERE id=sessions.user_id) AS owner"
    };
}
/// The read that comes first: the token's row, live or not, with its
/// deadline and lock state so `next_step` can judge it. Binds: token hash.
const SQL_READ: &str = concat!(
    "SELECT ",
    session_columns!(),
    " FROM sessions WHERE token_hash=?"
);
/// The session slide: extend a live, unlocked session by `SESSION` (or only
/// confirm a pending one) and return what the `Session` needs, in one
/// statement. Binds: new expiry, token hash, now, whether pending is allowed.
const SQL_SLIDE: &str = concat!(
    "UPDATE sessions SET expires=CASE WHEN unlocked=1 THEN ? ELSE expires END WHERE token_hash=? AND expires>? AND (unlocked=1 OR ?) RETURNING ",
    session_columns!()
);
/// Cleanup after a refused slide: drop the token's expired pending login.
/// Binds: token hash, now.
const SQL_DROP_EXPIRED_PENDING: &str =
    "DELETE FROM sessions WHERE token_hash=? AND unlocked=0 AND expires<=?";
/// The socket renewal: slide by `SESSION` from SQLite's own clock, only while
/// still live. Binds: `SESSION`, token hash, user.
const SQL_RENEW: &str = "UPDATE sessions SET expires=unixepoch()+? WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch()";
/// A live row's cookie ordering and deadline. Binds: token hash, now.
const SQL_COOKIE_STATE: &str =
    "SELECT login_sequence,expires FROM sessions WHERE token_hash=? AND expires>?";
/// The indexed admission check requires a live, fully unlocked browser session.
const SQL_ADMISSION_SESSION: &str =
    "SELECT 1 FROM sessions WHERE token_hash=? AND unlocked=1 AND expires>?";
/// A socket's live deadline. Binds: token hash, user, now.
const SQL_LIVE_EXPIRY: &str =
    "SELECT expires FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>?";

/// The row `SQL_READ` and `SQL_SLIDE` return, read the same way from either
/// driver.
struct Slid {
    user_id: String,
    device: String,
    fresh: i64,
    /// The committed deadline, in Unix seconds.
    expires: i64,
    /// `false` for a login still waiting for the browser's local unlock.
    unlocked: bool,
    username: String,
    display_name: String,
    aaguid: Option<String>,
    recovery_ready: Option<i64>,
    recovery_words_need_replacing: bool,
    owner: bool,
}

/// Slide the session on the pool's writer: the `UPDATE … RETURNING`, and when
/// it matched nothing, the expired-pending cleanup, in one transaction.
///
/// The token hash is unique, so the `RETURNING` yields at most one row, and
/// inside the pool's `BEGIN IMMEDIATE` the update is fully applied on the
/// first step. The cleanup only runs on denial, as before: a successful slide
/// stays one statement.
fn slide_on_pool(
    tx: &Transaction<'_>,
    token_hash: &str,
    now: i64,
    pending: bool,
) -> std::result::Result<Option<Slid>, infraternal_db::Error> {
    let row = tx
        .prepare_cached(SQL_SLIDE)?
        .query_row(params![now + SESSION, token_hash, now, pending], slid_row)
        .optional()?;
    if row.is_none() {
        tx.prepare_cached(SQL_DROP_EXPIRED_PENDING)?
            .execute(params![token_hash, now])?;
    }
    Ok(row)
}

/// Map one `session_columns!` row from the pool into a `Slid`.
fn slid_row(row: &infraternal_db::rusqlite::Row<'_>) -> infraternal_db::rusqlite::Result<Slid> {
    Ok(Slid {
        user_id: row.get("user_id")?,
        device: row.get("device")?,
        fresh: row.get("fresh")?,
        expires: row.get("expires")?,
        unlocked: row.get("unlocked")?,
        username: row.get("username")?,
        display_name: row.get("display_name")?,
        aaguid: row.get("aaguid")?,
        recovery_ready: row.get("recovery_ready")?,
        recovery_words_need_replacing: row.get("recovery_words_need_replacing")?,
        owner: row.get("owner")?,
    })
}

/// Map one `session_columns!` row from sqlx into a `Slid`.
fn slid_sqlx(row: &sqlx::sqlite::SqliteRow) -> Slid {
    Slid {
        user_id: row.get("user_id"),
        device: row.get("device"),
        fresh: row.get("fresh"),
        expires: row.get("expires"),
        unlocked: row.get("unlocked"),
        username: row.get("username"),
        display_name: row.get("display_name"),
        aaguid: row.get("aaguid"),
        recovery_ready: row.get("recovery_ready"),
        recovery_words_need_replacing: row.get("recovery_words_need_replacing"),
        owner: row.get("owner"),
    }
}

/// What `read_session` does after its first read of a token's row.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NextStep {
    /// The row read is live and needs no write: answer from it.
    Answer,
    /// Live and unlocked, with the slide due: run the slide on the writer,
    /// which checks liveness again and answers from its own row.
    Slide,
    /// The token's pending login has expired: delete it, then refuse.
    DropExpiredPending,
    /// Nothing to answer and nothing to clean up (no such row, an expired
    /// unlocked row, or a pending login on a full-session route): refuse.
    Refuse,
}

/// Judge a session row read at `now` (`expires`, `unlocked`), for a route
/// that accepts a pending login when `pending` is set.
///
/// The liveness rule is the slide's own `WHERE` clause (`expires>now AND
/// (unlocked=1 OR pending)`), and the cleanup rule is
/// `SQL_DROP_EXPIRED_PENDING`'s, so the read refuses and cleans up exactly
/// what the write-always path did. A pending login is never extended, so it
/// never needs the writer while it is live.
pub(super) fn next_step(expires: i64, unlocked: bool, now: i64, pending: bool) -> NextStep {
    if expires > now && (unlocked || pending) {
        if unlocked && slide_due(expires, now) {
            NextStep::Slide
        } else {
            NextStep::Answer
        }
    } else if !unlocked && expires <= now {
        NextStep::DropExpiredPending
    } else {
        NextStep::Refuse
    }
}

/// Whether a live, unlocked session's deadline needs the slide at `now`.
///
/// Due when the deadline is more than a minute behind a full session from
/// now (the socket renewal's rule, [`Auth::renewal_due`]), so a busy session
/// writes at most about once a minute instead of on every request. Also due
/// when it is ahead of a full session from now, which only happens after the
/// clock stepped back: the slide then pulls it back, as the write on every
/// request did, so a session read never leaves a deadline later than
/// `now + SESSION`.
fn slide_due(expires: i64, now: i64) -> bool {
    Auth::renewal_due(expires, now) || expires > now + SESSION
}

/// Authenticated browser device, including the last successful passkey verification.
#[derive(Serialize)]
pub struct Session {
    /// Public lifetime label; never grants authority and never enters browser storage.
    pub session_incarnation: String,
    pub recovery_words_need_replacing: bool,
    pub recovery_pending: Option<RecoveryPending>,
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub device: String,
    pub fresh: i64,
    pub passkey_provider: Option<&'static str>,
    /// Current owner authority, kept server-side and omitted from session JSON.
    #[serde(skip)]
    pub(crate) owner: bool,
}
/// Publicly safe absolute cookie deadline and ordering value for one live session row.
pub(super) struct CookieState {
    pub login_sequence: i64,
    pub expires: i64,
}
/// Pending recovery discloses only its original deadline, including after bearer expiry.
#[derive(Serialize)]
pub struct RecoveryPending {
    pub ready_at: i64,
}
impl Session {
    /// The session is inside the browser's 15-minute admin window that its tap started (D333).
    /// The one check every fresh-session route uses; a closed window is `Error::FreshRequired`
    /// (HTTP 428), never a plain denial, so the page can offer renewal (#563).
    pub(crate) fn require_admin_window(&self, now: i64) -> Result<()> {
        if self.fresh > now || now - self.fresh >= infraternal_plugin_api::ADMIN_WINDOW_SECONDS {
            return Err(Error::FreshRequired);
        }
        Ok(())
    }
}

#[allow(clippy::missing_errors_doc)]
impl Auth {
    /// Read only setup facts, with authority and account scoping in the same statement.
    /// No credential, recovery verifier or ciphertext is selected. Presence is not proof
    /// that the person still holds their recovery key; verification history is unavailable.
    pub(super) async fn account_summary(&self, token: &str, now: i64) -> Result<serde_json::Value> {
        let row = sqlx::query("SELECT users.id AS user_id,(SELECT COUNT(*) FROM passkeys WHERE user_id=users.id) AS passkeys,(users.recovery_hash<>'' AND EXISTS(SELECT 1 FROM wraps WHERE user_id=users.id AND kind='recovery')) AS recovery_set_up FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.unlocked=1 AND sessions.expires>?")
            .bind(hash(token)).bind(now).fetch_optional(&self.pool).await?.ok_or(Error::Denied)?;
        Ok(serde_json::json!({
            "user_id": row.get::<String, _>("user_id"),
            "session_incarnation": super::session_incarnation(token),
            "passkeys": row.get::<i64, _>("passkeys"),
            "recovery_set_up": row.get::<bool, _>("recovery_set_up"),
        }))
    }

    /// Authenticate a live, unlocked session and keep it sliding: its deadline
    /// moves to 30 days from now when the slide is due (at most about once a
    /// minute, see the module docs), never resurrecting an expired or revoked
    /// record. A request that needs no slide takes no write.
    pub async fn session(&self, token: &str, now: i64) -> Result<Session> {
        self.read_session(token, now, false).await
    }

    /// Restricted login cookies can read identity/wraps while awaiting local DEK unwrap.
    /// Reads never extend their five-minute expiry; expired rows are revoked here.
    pub async fn unlock_session(&self, token: &str, now: i64) -> Result<Session> {
        self.read_session(token, now, true).await
    }

    /// The shared body of `session` and `unlock_session`: read the token's
    /// row, then slide it only when the slide is due (or, with `pending`,
    /// also accept a still-live pending login, which is never extended), and
    /// build the `Session`. A refused read deletes the token's expired
    /// pending login and returns `Denied`. Runs on the D379 pool when `Auth`
    /// has one, else on sqlx (see the module docs, "Read first").
    async fn read_session(&self, token: &str, now: i64, pending: bool) -> Result<Session> {
        let token_hash = hash(token);
        let read = self.read_session_row(&token_hash).await?;
        let step = read.as_ref().map_or(NextStep::Refuse, |row| {
            next_step(row.expires, row.unlocked, now, pending)
        });
        let row = match step {
            NextStep::Answer => read,
            // The slide repeats the liveness check under the writer and runs
            // the pending cleanup itself when it matches nothing, so a row
            // revoked since the read is refused here and never revived.
            NextStep::Slide => self.slide(token_hash, now, pending).await?,
            NextStep::DropExpiredPending => {
                self.drop_expired_pending(token_hash, now).await?;
                None
            }
            NextStep::Refuse => None,
        };
        let Some(row) = row else {
            return Err(Error::Denied);
        };
        let recovery_pending = if row.recovery_ready.is_some() {
            self.pending_recovery(&row.user_id, now)
                .await?
                .map(|ready_at| RecoveryPending { ready_at })
        } else {
            None
        };
        Ok(Session {
            session_incarnation: super::session_incarnation(token),
            recovery_words_need_replacing: row.recovery_words_need_replacing,
            recovery_pending,
            user_id: row.user_id,
            username: row.username,
            display_name: row.display_name,
            device: row.device,
            fresh: row.fresh,
            passkey_provider: provider_name(row.aaguid.as_deref()),
            owner: row.owner,
        })
    }

    /// The first, write-free step of `read_session`: the token's row, live
    /// or not, on a pool reader (a fresh snapshot per call) or on sqlx.
    async fn read_session_row(&self, token_hash: &str) -> Result<Option<Slid>> {
        if let Some(db) = &self.db {
            let token_hash = token_hash.to_owned();
            return Ok(db
                .read(move |tx| {
                    tx.prepare_cached(SQL_READ)?
                        .query_row(params![token_hash], slid_row)
                        .optional()
                        .map_err(infraternal_db::Error::from)
                })
                .await?);
        }
        let row = sqlx::query(SQL_READ)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(slid_sqlx))
    }

    /// Run the slide (`SQL_SLIDE`, plus the pending cleanup when it matches
    /// nothing) on the pool's writer, or on sqlx without a pool.
    async fn slide(&self, token_hash: String, now: i64, pending: bool) -> Result<Option<Slid>> {
        #[cfg(test)]
        self.count_session_write();
        match &self.db {
            Some(db) => Ok(db
                .write(move |tx| slide_on_pool(tx, &token_hash, now, pending))
                .await?),
            None => self.slide_on_sqlx(&token_hash, now, pending).await,
        }
    }

    /// Delete the token's expired pending login (`SQL_DROP_EXPIRED_PENDING`,
    /// which checks the expiry again itself) on the writer or on sqlx.
    async fn drop_expired_pending(&self, token_hash: String, now: i64) -> Result<()> {
        #[cfg(test)]
        self.count_session_write();
        if let Some(db) = &self.db {
            return Ok(db
                .write(move |tx| {
                    tx.prepare_cached(SQL_DROP_EXPIRED_PENDING)?
                        .execute(params![token_hash, now])?;
                    Ok::<_, infraternal_db::Error>(())
                })
                .await?);
        }
        sqlx::query(SQL_DROP_EXPIRED_PENDING)
            .bind(token_hash)
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// `slide_on_pool` on sqlx, for an `Auth` without the pool (in-memory
    /// test databases). Two statements on two checkouts, as before the port.
    async fn slide_on_sqlx(
        &self,
        token_hash: &str,
        now: i64,
        pending: bool,
    ) -> Result<Option<Slid>> {
        let row = sqlx::query(SQL_SLIDE)
            .bind(now + SESSION)
            .bind(token_hash)
            .bind(now)
            .bind(pending)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            // Successful sessions keep the original single write; cleanup runs only on denial.
            sqlx::query(SQL_DROP_EXPIRED_PENDING)
                .bind(token_hash)
                .bind(now)
                .execute(&self.pool)
                .await?;
            return Ok(None);
        };
        Ok(Some(slid_sqlx(&row)))
    }

    /// Read the live row's cookie deadline after an authenticated action has succeeded.
    /// The session read remains the only expiry write; this indexed lookup only returns the
    /// committed deadline needed for the persistent cookie's absolute Expires attribute.
    pub(super) async fn cookie_state(&self, token: &str, now: i64) -> Result<Option<CookieState>> {
        let token_hash = hash(token);
        if let Some(db) = &self.db {
            return Ok(db
                .read(move |tx| {
                    tx.prepare_cached(SQL_COOKIE_STATE)?
                        .query_row(params![token_hash, now], |row| {
                            Ok(CookieState {
                                login_sequence: row.get("login_sequence")?,
                                expires: row.get("expires")?,
                            })
                        })
                        .optional()
                        .map_err(infraternal_db::Error::from)
                })
                .await?);
        }
        let row = sqlx::query(SQL_COOKIE_STATE)
            .bind(token_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| CookieState {
            login_sequence: row.get("login_sequence"),
            expires: row.get("expires"),
        }))
    }

    /// Return a session's budget key only while its cookie has live authority.
    /// This indexed read leaves expiry, pending login state and recovery untouched.
    pub(crate) async fn admission_session(
        &self,
        token: &str,
        now: i64,
        hold: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<Option<String>> {
        let token_hash = hash(token);
        let live: Option<i64> = if let Some(db) = &self.db {
            let token_hash = token_hash.clone();
            db.read(move |tx| {
                let _hold = &hold;
                tx.prepare_cached(SQL_ADMISSION_SESSION)?
                    .query_row(params![token_hash, now], |row| row.get(0))
                    .optional()
                    .map_err(infraternal_db::Error::from)
            })
            .await?
        } else {
            let _hold = hold;
            sqlx::query_scalar(SQL_ADMISSION_SESSION)
                .bind(&token_hash)
                .bind(now)
                .fetch_optional(&self.pool)
                .await?
        };
        Ok(live.map(|_| token_hash))
    }

    /// Activate only a still-live pending cookie after the browser confirms successful unwrap.
    /// The server never receives the plaintext DEK; this is a client completion signal.
    pub async fn unlock_finish(&self, token: &str, transaction: &str, now: i64) -> Result<()> {
        require_pending_transaction(token, transaction)?;
        let changed = sqlx::query("UPDATE sessions SET unlocked=1,expires=? WHERE token_hash=? AND unlocked=0 AND expires>?")
            .bind(now + SESSION).bind(hash(token)).bind(now).execute(&self.pool).await?.rows_affected();
        if changed != 1 {
            return Err(Error::Denied);
        }
        Ok(())
    }

    /// Failed local unwrap may revoke only the exact still-pending login from this page.
    pub(super) async fn logout_pending(&self, token: &str, transaction: &str) -> Result<()> {
        require_pending_transaction(token, transaction)?;
        let changed = sqlx::query("DELETE FROM sessions WHERE token_hash=? AND unlocked=0")
            .bind(hash(token))
            .execute(&self.pool)
            .await?
            .rows_affected();
        if changed != 1 {
            return Err(Error::Denied);
        }
        Ok(())
    }

    /// Authenticate a device inside the admin window its last tap started (D333: 15 minutes of
    /// admin actions without taps) [28].
    pub async fn fresh_session(&self, token: &str, now: i64) -> Result<Session> {
        let session = self.session(token, now).await?;
        session.require_admin_window(now)?;
        Ok(session)
    }

    /// Revoke the presented bearers that belong to the signed-in account, and no others (#285).
    ///
    /// The account is the owner of the selected (newest) session cookie. If that bearer no longer
    /// resolves (a replayed logout, or a session revoked meanwhile), the browser is already logged
    /// out and nothing is deleted: the remaining bearers may belong to someone else. Only when no
    /// cookie is selected (an ambiguous ordering) is the account the one that all live presented
    /// bearers share; bearers of more than one account then refuse the logout with nothing deleted.
    /// A browser may hold another account's cookie, and logging out here must never end that session.
    pub async fn logout_presented(&self, selected: Option<&str>, tokens: &[&str]) -> Result<()> {
        let Some(account) = self.logout_account(selected, tokens).await? else {
            return Ok(());
        };
        for token in tokens {
            self.revoke_session(token, Some(&account)).await?;
        }
        Ok(())
    }

    /// The account a logout acts for, or `None` when its selected bearer is already gone; see
    /// `logout_presented`.
    async fn logout_account(
        &self,
        selected: Option<&str>,
        tokens: &[&str],
    ) -> Result<Option<String>> {
        if let Some(selected) = selected {
            // Never infer an account from the other bearers once a cookie was selected (#285).
            return Ok(sqlx::query_scalar::<_, String>(
                "SELECT user_id FROM sessions WHERE token_hash=?",
            )
            .bind(hash(selected))
            .fetch_optional(&self.pool)
            .await?);
        }
        let mut owners = Vec::new();
        for token in tokens {
            if let Some(user) =
                sqlx::query_scalar::<_, String>("SELECT user_id FROM sessions WHERE token_hash=?")
                    .bind(hash(token))
                    .fetch_optional(&self.pool)
                    .await?
                && !owners.contains(&user)
            {
                owners.push(user);
            }
        }
        match owners.as_slice() {
            [only] => Ok(Some(only.clone())),
            _ => Err(Error::Denied),
        }
    }

    /// Revoke the current session immediately.
    pub async fn logout(&self, token: &str) -> Result<()> {
        self.revoke_session(token, None).await
    }

    /// Delete one session by bearer, only within `account` when given, and publish the revocation.
    async fn revoke_session(&self, token: &str, account: Option<&str>) -> Result<()> {
        let session_hash = hash(token);
        let account = account.map(str::to_owned);
        let revocations = self.revocations.clone();
        // Pool waiters remain cancellable. Only work that already owns a connection
        // is detached, so the pool also bounds unfinished logout tasks.
        let mut connection = self.pool.acquire().await?;
        // RETURNING binds the affected account to the committed deletion in one statement.
        // A separate lookup could race recovery or another logout and lose its scope.
        // Drain through statement completion before acknowledging/publishing: a single-row
        // RETURNING read can hide a deferred commit refusal. The unique hash bounds this
        // result to one row, so draining cannot collect an unbounded account list.
        super::committed::run(Box::pin(async move {
            // Keep connection ownership through publication. Returning it to the pool
            // also fences the notification, even after the requesting future is gone.
            let mut users: Vec<String> = sqlx::query_scalar(
                "DELETE FROM sessions WHERE token_hash=? AND (?2 IS NULL OR user_id=?2) RETURNING user_id",
            )
            .bind(&session_hash)
            .bind(&account)
            .fetch_all(&mut *connection)
            .await?;
            if let Some(user) = users.pop() {
                revocations.publish(&user, Some(session_hash));
            }
            Ok(())
        }))
        .await
    }

    /// Wake live sockets on committed revocation without periodic idle database polling.
    pub(crate) fn revocation_events(&self, user: &str) -> super::AccountSubscription {
        self.revocations.subscribe(user)
    }

    /// Whether a live session read at `now` with this `expiry` is due for its
    /// at-most-once-a-minute slide. Only ever asked after a read proved it live.
    /// Sockets (`websocket.rs`) and HTTP session reads (`slide_due`) share it,
    /// so both kinds of activity keep a session alive the same way.
    pub(crate) fn renewal_due(expiry: i64, now: i64) -> bool {
        expiry < now + SESSION - 60
    }

    /// Slide an active socket's session forward by a full session, off the
    /// read path (#240). The future owns everything it needs, so the caller
    /// can run it without holding the socket's frame. It reads the clock
    /// when the UPDATE runs, and `expires>now` keeps it from extending a
    /// session that ended, or reviving one that was revoked (deleted), while
    /// it waited. The write may wait on SQLite's busy timeout behind another
    /// writer; the caller bounds how many of these run at once. Its outcome is
    /// not reported: a failed or skipped renewal is retried on a later frame,
    /// and the socket's own reads still see the old, still-valid expiry.
    /// `hold` is dropped when the renewal ends or is dropped; the caller uses
    /// it to return its bounds. The task is boxed as an `Operation` so spawning
    /// it reuses the task code already compiled for plugin node work (D243).
    pub(crate) fn renewal(
        &self,
        token: &str,
        user: &str,
        hold: impl Send + 'static,
    ) -> infraternal_plugin_api::Operation<'static, ()> {
        let pool = self.pool.clone();
        let db = self.db.clone();
        let token_hash = hash(token);
        let user = user.to_owned();
        Box::pin(async move {
            let _hold = hold;
            // SQLite's own clock, read when the statement runs: a renewal that
            // waited behind a writer judges the session at that moment.
            if let Some(db) = db {
                let _ = db
                    .write(move |tx| {
                        tx.prepare_cached(SQL_RENEW)?
                            .execute(params![SESSION, token_hash, user])?;
                        Ok::<_, infraternal_db::Error>(())
                    })
                    .await;
                return;
            }
            let _ = sqlx::query(SQL_RENEW)
                .bind(SESSION)
                .bind(token_hash)
                .bind(user)
                .execute(&pool)
                .await;
        })
    }

    /// Read a socket's actual deadline without sliding it during idle checks.
    /// `hold` stays with the SELECT future until it completes, even if the
    /// caller's wait expires. Pool return and health checks may finish afterward.
    pub(crate) fn live_expiry(
        &self,
        token: &str,
        user: &str,
        now: i64,
        hold: impl Send + 'static,
    ) -> impl std::future::Future<Output = Result<i64>> + Send + 'static {
        let pool = self.pool.clone();
        let db = self.db.clone();
        let token_hash = hash(token);
        let user = user.to_owned();
        #[cfg(test)]
        let reads = self.authority_reads.clone();
        async move {
            #[cfg(test)]
            {
                *reads.lock().unwrap().entry(user.clone()).or_default() += 1;
            }
            let _hold = hold;
            let expires: Option<i64> = if let Some(db) = db {
                db.read(move |tx| {
                    tx.prepare_cached(SQL_LIVE_EXPIRY)?
                        .query_row(params![token_hash, user, now], |row| row.get(0))
                        .optional()
                        .map_err(infraternal_db::Error::from)
                })
                .await?
            } else {
                sqlx::query_scalar(SQL_LIVE_EXPIRY)
                    .bind(token_hash)
                    .bind(user)
                    .bind(now)
                    .fetch_optional(&pool)
                    .await?
            };
            expires.ok_or(Error::Denied)
        }
    }
}

/// Check, inside the caller's writer transaction, that this session is still live and unlocked
/// by both the caller's clock and SQLite's.
///
/// This grants no per-action authority and checks no tap age. A change that needs a tap verifies
/// its own ceremony, bound to that one action, before calling this (D336). For example, a key
/// approval verifies the passkey ceremony `device_approve_start` bound to its code. This check
/// only makes a logout or expiry that committed first refuse the change.
pub(crate) async fn require_live_session_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token_hash: &str,
    user: &str,
    now: i64,
) -> Result<()> {
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 \
         AND expires>MAX(?,unixepoch()))",
    )
    .bind(token_hash)
    .bind(user)
    .bind(now)
    .fetch_one(&mut **tx)
    .await?;
    if !live {
        return Err(Error::Denied);
    }
    Ok(())
}

/// Insert a session row with its login sequence inside the caller's transaction.
pub(super) async fn insert_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token: &str,
    user: &str,
    device: &str,
    now: i64,
    passkey_id: Option<&str>,
) -> Result<()> {
    let login_sequence: i64 = sqlx::query_scalar(
        "UPDATE session_login_sequence SET value=value+1 WHERE singleton=1 AND value<9223372036854775807 RETURNING value",
    )
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,passkey_id,login_sequence) VALUES (?,?,?,?,?,?,?)")
        .bind(hash(token))
        .bind(user)
        .bind(device)
        .bind(now + SESSION)
        .bind(now)
        .bind(passkey_id)
        .bind(login_sequence)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Domain separation keeps this page-memory id distinct from the `HttpOnly` cookie and its stored hash.
/// The pending flag consumes it atomically; no extra table or per-login heap state is needed.
pub(super) fn pending_transaction(token: &str) -> String {
    hash(&format!("infraternal/unlock/v1|{token}"))
}
fn require_pending_transaction(token: &str, transaction: &str) -> Result<()> {
    let expected = pending_transaction(token);
    if transaction.len() != expected.len()
        || !openssl::memcmp::eq(transaction.as_bytes(), expected.as_bytes())
    {
        return Err(Error::Denied);
    }
    Ok(())
}

/// Best-effort names, not attested provider claims, from the community-maintained list:
/// <https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/aaguid.json>
/// Retrieved 2026-10-07. Unlisted/redacted values stay unlabeled; never guess from the browser.
pub(super) fn provider_name(aaguid: Option<&str>) -> Option<&'static str> {
    match aaguid? {
        "bada5566-a7aa-401f-bd96-45619a55120d" => Some("1Password"),
        "dd4ec289-e01d-41c9-bb89-70fa845d4bf2" => Some("iCloud Keychain"),
        "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4" => Some("Google Password Manager"),
        "d548826e-79b4-db40-a3d8-11116f7e8349" => Some("Bitwarden"),
        "08987058-cadc-4b81-b6e1-30de50dcbe96"
        | "9ddd1817-af5a-4672-a2b9-3e3dd95000a9"
        | "6028b017-b1d4-4c02-b4b3-afcdafc96bb2" => Some("Windows Hello"),
        _ => None,
    }
}
