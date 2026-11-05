//! Sliding sessions, the admin window, provider diagnostics and transaction authority rechecks
//! [28]. Per-action taps are bound to one action in `action_tap` (D336).
use super::{Auth, Error, Result, Row, SESSION, Serialize, hash};

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
    pub(super) fn require_admin_window(&self, now: i64) -> Result<()> {
        if self.fresh > now || now - self.fresh >= infraternal_plugin_api::ADMIN_WINDOW_SECONDS {
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

    /// Read the live row's cookie deadline after an authenticated action has succeeded.
    /// The session read remains the only expiry write; this indexed lookup only returns the
    /// committed deadline needed for the persistent cookie's absolute Expires attribute.
    pub(super) async fn cookie_state(&self, token: &str, now: i64) -> Result<Option<CookieState>> {
        let row = sqlx::query(
            "SELECT login_sequence,expires FROM sessions WHERE token_hash=? AND expires>?",
        )
        .bind(hash(token))
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| CookieState {
            login_sequence: row.get("login_sequence"),
            expires: row.get("expires"),
        }))
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
