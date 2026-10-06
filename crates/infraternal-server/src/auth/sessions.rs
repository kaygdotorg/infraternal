//! Sliding sessions, fresh-tap policy and transaction authority rechecks [28].
use super::{Auth, Error, FRESH, Result, Row, SESSION, Serialize, hash};

/// Authenticated browser device, including the last successful passkey verification.
#[derive(Serialize)]
pub struct Session {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub device: String,
    pub fresh: i64,
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
        let row = sqlx::query("UPDATE sessions SET expires=CASE WHEN unlocked=1 THEN ? ELSE expires END WHERE token_hash=? AND expires>? AND (unlocked=1 OR ?) RETURNING user_id,device,fresh,(SELECT username FROM users WHERE id=sessions.user_id) AS username,(SELECT display_name FROM users WHERE id=sessions.user_id) AS display_name")
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
            user_id: row.get("user_id"),
            username: row.get("username"),
            display_name: row.get("display_name"),
            device: row.get("device"),
            fresh: row.get("fresh"),
        })
    }

    /// Activate only a still-live pending cookie after the browser confirms successful unwrap.
    /// The server never receives the plaintext DEK; this is a client completion signal.
    pub async fn unlock_finish(&self, token: &str, now: i64) -> Result<()> {
        let changed = sqlx::query("UPDATE sessions SET unlocked=1,expires=? WHERE token_hash=? AND unlocked=0 AND expires>?")
            .bind(now + SESSION).bind(hash(token)).bind(now).execute(&self.pool).await?.rows_affected();
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
        sqlx::query("DELETE FROM sessions WHERE token_hash=?")
            .bind(hash(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

pub(super) async fn require_session_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token_hash: &str,
    user: &str,
    now: i64,
) -> Result<()> {
    if sqlx::query("SELECT user_id FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>? AND fresh>? AND fresh<=?")
        .bind(token_hash).bind(user).bind(now).bind(now - FRESH).bind(now).fetch_optional(&mut **tx).await?.is_none() { return Err(Error::Denied); }
    Ok(())
}
pub(super) async fn insert_session(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    token: &str,
    user: &str,
    device: &str,
    now: i64,
) -> Result<()> {
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh) VALUES (?,?,?,?,?)")
        .bind(hash(token))
        .bind(user)
        .bind(device)
        .bind(now + SESSION)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
