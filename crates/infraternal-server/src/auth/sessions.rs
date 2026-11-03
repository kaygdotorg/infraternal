//! Sliding sessions, fresh-tap policy, provider diagnostics and transaction authority rechecks [28].
use super::{Auth, Error, FRESH, Result, Row, SESSION, Serialize, hash};

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
/// Pending recovery discloses an estimated deadline, including after bearer expiry.
#[derive(Serialize)]
pub struct RecoveryPending {
    pub ready_at: i64,
}
impl Session {
    pub(super) fn require_fresh(&self, now: i64) -> Result<()> {
        if self.fresh > now || now - self.fresh >= FRESH {
            return Err(Error::Denied);
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

    /// Slide a live session by 30 days, never resurrecting an expired or revoked record.
    pub async fn session(&self, token: &str, now: i64) -> Result<Session> {
        self.read_session(token, now, false).await
    }

    /// Restricted login cookies can read identity/wraps while awaiting local DEK unwrap.
    /// Reads never extend their five-minute expiry; expired rows are revoked here.
    pub async fn unlock_session(&self, token: &str, now: i64) -> Result<Session> {
        self.read_session(token, now, true).await
    }

    async fn read_session(&self, token: &str, now: i64, pending: bool) -> Result<Session> {
        // Keep the diagnostic lookup in the existing write/returning query. The
        // indexed credential ID and user binding identify this session's passkey.
        let row = sqlx::query("UPDATE sessions SET expires=CASE WHEN unlocked=1 THEN ? ELSE expires END WHERE token_hash=? AND expires>? AND (unlocked=1 OR ?) RETURNING user_id,device,fresh,(SELECT username FROM users WHERE id=sessions.user_id) AS username,(SELECT display_name FROM users WHERE id=sessions.user_id) AS display_name,(SELECT aaguid FROM passkeys WHERE id=sessions.passkey_id AND user_id=sessions.user_id) AS aaguid,(SELECT ready FROM recovery WHERE user_id=sessions.user_id) AS recovery_ready,(SELECT recovery_version=1 OR recovery_wrap_version=1 FROM users WHERE id=sessions.user_id) AS recovery_words_need_replacing,(SELECT owner FROM users WHERE id=sessions.user_id) AS owner")
            .bind(now + SESSION).bind(hash(token)).bind(now).bind(pending).fetch_optional(&self.pool).await?;
        let Some(row) = row else {
            // Successful sessions keep the original single write; cleanup runs only on denial.
            sqlx::query("DELETE FROM sessions WHERE token_hash=? AND unlocked=0 AND expires<=?")
                .bind(hash(token))
                .bind(now)
                .execute(&self.pool)
                .await?;
            return Err(Error::Denied);
        };
        let user_id: String = row.get("user_id");
        let recovery_pending = if row.get::<Option<i64>, _>("recovery_ready").is_some() {
            self.pending_recovery(&user_id, now)
                .await?
                .map(|ready_at| RecoveryPending { ready_at })
        } else {
            None
        };
        Ok(Session {
            session_incarnation: super::session_incarnation(token),
            recovery_words_need_replacing: row.get("recovery_words_need_replacing"),
            recovery_pending,
            user_id,
            username: row.get("username"),
            display_name: row.get("display_name"),
            device: row.get("device"),
            fresh: row.get("fresh"),
            passkey_provider: provider_name(row.get::<Option<&str>, _>("aaguid")),
            owner: row.get("owner"),
        })
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

    /// Authenticate a device and require a passkey tap within five minutes for destructive UI actions [28].
    pub async fn fresh_session(&self, token: &str, now: i64) -> Result<Session> {
        let session = self.session(token, now).await?;
        session.require_fresh(now)?;
        Ok(session)
    }

    /// Revoke the current session immediately.
    pub async fn logout(&self, token: &str) -> Result<()> {
        let session_hash = hash(token);
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
            let mut users: Vec<String> =
                sqlx::query_scalar("DELETE FROM sessions WHERE token_hash=? RETURNING user_id")
                    .bind(&session_hash)
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
        let token_hash = hash(token);
        let user = user.to_owned();
        Box::pin(async move {
            let _hold = hold;
            // SQLite's own clock, read when the statement runs: a renewal that
            // waited behind a writer judges the session at that moment.
            let _ = sqlx::query("UPDATE sessions SET expires=unixepoch()+? WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch()")
                .bind(SESSION).bind(token_hash).bind(user).execute(&pool).await;
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
            sqlx::query_scalar("SELECT expires FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>?")
                .bind(token_hash).bind(user).bind(now).fetch_optional(&pool).await?.ok_or(Error::Denied)
        }
    }
}

pub(crate) async fn require_session_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token_hash: &str,
    user: &str,
    now: i64,
) -> Result<()> {
    if !infraternal_plugin_api::fresh_session_tx(tx, token_hash, user, now, FRESH).await? {
        return Err(Error::Denied);
    }
    Ok(())
}
pub(super) async fn insert_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token: &str,
    user: &str,
    device: &str,
    now: i64,
    passkey_id: Option<&str>,
) -> Result<()> {
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,passkey_id) VALUES (?,?,?,?,?,?)")
        .bind(hash(token))
        .bind(user)
        .bind(device)
        .bind(now + SESSION)
        .bind(now)
        .bind(passkey_id)
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
