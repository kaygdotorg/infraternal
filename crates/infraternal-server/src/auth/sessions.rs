//! Sliding sessions, fresh-tap policy and transaction authority rechecks [28].
use super::{Auth, Error, FRESH, Result, Row, SESSION, Serialize, hash};

/// Authenticated browser device, including the last successful passkey verification.
#[derive(Serialize)]
pub struct Session {
    pub user_id: String,
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
        let row = sqlx::query("UPDATE sessions SET expires=? WHERE token_hash=? AND expires>? RETURNING user_id,device,fresh")
            .bind(now + SESSION).bind(hash(token)).bind(now).fetch_optional(&self.pool).await?.ok_or(Error::Denied)?;
        Ok(Session {
            user_id: row.get("user_id"),
            device: row.get("device"),
            fresh: row.get("fresh"),
        })
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
    if sqlx::query("SELECT user_id FROM sessions WHERE token_hash=? AND user_id=? AND expires>? AND fresh>? AND fresh<=?")
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
