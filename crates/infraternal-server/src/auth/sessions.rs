//! Sliding sessions, fresh-tap policy, provider diagnostics and transaction authority rechecks [28].
use super::{Auth, Error, FRESH, Result, Row, SESSION, Serialize, hash};

/// Authenticated browser device, including the last successful passkey verification.
#[derive(Serialize)]
pub struct Session {
    pub recovery_words_need_replacing: bool,
    pub recovery_pending: Option<RecoveryPending>,
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub device: String,
    pub fresh: i64,
    pub passkey_provider: Option<&'static str>,
}
/// Pending recovery discloses only its original deadline, including after bearer expiry.
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
        let row = sqlx::query("UPDATE sessions SET expires=CASE WHEN unlocked=1 THEN ? ELSE expires END WHERE token_hash=? AND expires>? AND (unlocked=1 OR ?) RETURNING user_id,device,fresh,(SELECT username FROM users WHERE id=sessions.user_id) AS username,(SELECT display_name FROM users WHERE id=sessions.user_id) AS display_name,(SELECT aaguid FROM passkeys WHERE id=sessions.passkey_id AND user_id=sessions.user_id) AS aaguid,(SELECT ready FROM recovery WHERE user_id=sessions.user_id) AS recovery_ready,(SELECT recovery_version=1 OR recovery_wrap_version=1 FROM users WHERE id=sessions.user_id) AS recovery_words_need_replacing")
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
        Ok(Session {
            recovery_words_need_replacing: row.get("recovery_words_need_replacing"),
            recovery_pending: row
                .get::<Option<i64>, _>("recovery_ready")
                .map(|ready_at| RecoveryPending { ready_at }),
            user_id: row.get("user_id"),
            username: row.get("username"),
            display_name: row.get("display_name"),
            device: row.get("device"),
            fresh: row.get("fresh"),
            passkey_provider: provider_name(row.get::<Option<&str>, _>("aaguid")),
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
        let changed = sqlx::query("DELETE FROM sessions WHERE token_hash=?")
            .bind(hash(token))
            .execute(&self.pool)
            .await?
            .rows_affected();
        if changed != 0 {
            self.revocations.send_replace(());
        }
        Ok(())
    }

    /// Wake live sockets on committed revocation without periodic idle database polling.
    pub(crate) fn revocation_events(&self) -> tokio::sync::watch::Receiver<()> {
        self.revocations.subscribe()
    }

    /// Recheck every hot-path event with a read, renewing active sessions at most once a minute.
    /// Return the resulting expiry so a watchdog can reuse this exact authority read.
    pub(crate) async fn socket_activity(&self, token: &str, user: &str, now: i64) -> Result<i64> {
        let expiry = self.live_expiry(token, user, now).await?;
        if expiry < now + SESSION - 60 {
            let changed = sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>?")
                .bind(now + SESSION).bind(hash(token)).bind(user).bind(now).execute(&self.pool).await?.rows_affected();
            if changed != 1 {
                return Err(Error::Denied);
            }
            return Ok(now + SESSION);
        }
        Ok(expiry)
    }

    /// Read a socket's actual deadline without sliding it during idle checks.
    pub(crate) async fn live_expiry(&self, token: &str, user: &str, now: i64) -> Result<i64> {
        sqlx::query_scalar("SELECT expires FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>?")
            .bind(hash(token)).bind(user).bind(now).fetch_optional(&self.pool).await?.ok_or(Error::Denied)
    }
}

pub(super) async fn require_session_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token_hash: &str,
    user: &str,
    now: i64,
) -> Result<()> {
    if sqlx::query("SELECT user_id FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>MAX(?,unixepoch()) AND fresh>MAX(?,unixepoch())-? AND fresh<=MAX(?,unixepoch())")
        .bind(token_hash).bind(user).bind(now).bind(now).bind(FRESH).bind(now).fetch_optional(&mut **tx).await?.is_none() { return Err(Error::Denied); }
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
