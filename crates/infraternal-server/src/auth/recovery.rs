//! Recovery delay, same-account live-session exemption and rotation isolation [25,D113].
use super::{Auth, Authority, DAY, Error, Result, Row, Value, hash, random, verify_recovery};

#[allow(clippy::missing_errors_doc)]
impl Auth {
    /// Start a 24-hour delayed recovery; repeat requests do not reset or accelerate it.
    pub async fn recovery_start(&self, user: &str, words: String, now: i64) -> Result<String> {
        Ok(self
            .recovery_start_with_session(user, words, None, now)
            .await?
            .0)
    }

    /// Only an unlocked, unexpired session for this account may waive the delay [D113].
    /// Returns the recovery capability and its authoritative Unix ready time.
    pub async fn recovery_start_with_session(
        &self,
        user: &str,
        words: String,
        session: Option<&str>,
        now: i64,
    ) -> Result<(String, i64)> {
        let (token, ready, _) = self
            .recovery_start_clock(user, words, session, || Ok(now), false)
            .await?;
        Ok((token, ready))
    }

    /// Reauthenticate after page loss; a pending request always retains its original deadline.
    pub async fn recovery_resume(
        &self,
        user: &str,
        words: String,
        now: i64,
    ) -> Result<(String, i64)> {
        let (token, ready, _) = self
            .recovery_start_clock(user, words, None, || Ok(now), true)
            .await?;
        Ok((token, ready))
    }

    // HTTP supplies a live clock; deterministic library callers supply their own time.
    // Sample it only after the writer lock so every verification/database await is covered.
    pub(super) async fn recovery_start_clock(
        &self,
        user: &str,
        words: String,
        session: Option<&str>,
        clock: impl Fn() -> Result<i64>,
        resume: bool,
    ) -> Result<(String, i64, i64)> {
        let stored: String = sqlx::query_scalar("SELECT recovery_hash FROM users WHERE id=?")
            .bind(user)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::Denied)?;
        verify_recovery(words, stored.clone()).await?;
        #[cfg(test)]
        if let Some(pause) = self.recovery_pause.lock().await.take() {
            pause.verified.notify_one();
            pause.resume.notified().await;
        }
        let mut tx = self.pool.begin().await?;
        // Argon2 runs off-thread without holding a database writer lock. Recheck the
        // exact verified hash under that lock so rotation cannot authorize old words.
        let current: Option<String> =
            sqlx::query_scalar("UPDATE users SET name=name WHERE id=? RETURNING recovery_hash")
                .bind(user)
                .fetch_optional(&mut *tx)
                .await?;
        if current.as_deref() != Some(stored.as_str()) {
            return Err(Error::Denied);
        }
        // Do not slide or check the cookie before Argon2: revocation/expiry can occur
        // during verification. This recheck shares the writer lock with request creation.
        let now = clock()?;
        let live: bool = if let Some(token) = session {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>?)")
                .bind(hash(token)).bind(user).bind(now).fetch_one(&mut *tx).await?
        } else {
            false
        };
        let existed: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM recovery WHERE user_id=?)")
                .bind(user)
                .fetch_one(&mut *tx)
                .await?;
        let now_ready = if live { now } else { now + DAY };
        let token = random();
        let ready: Option<i64> = if resume {
            // Reissue only the bearer capability. Even an expired capability's row
            // retains the original deadline until explicit cancellation or completion.
            // Rotation also invalidates replacement ceremonies in a discarded browser.
            sqlx::query_scalar("INSERT INTO recovery(user_id,token_hash,ready,expires) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,expires=excluded.expires RETURNING ready")
                .bind(user).bind(hash(&token)).bind(now_ready).bind(now + 2 * DAY)
                .fetch_optional(&mut *tx).await?
        } else {
            sqlx::query_scalar("INSERT INTO recovery(user_id,token_hash,ready,expires) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,ready=excluded.ready,expires=excluded.expires WHERE recovery.expires<=? RETURNING ready")
                .bind(user).bind(hash(&token)).bind(now_ready).bind(now + 2 * DAY).bind(now)
                .fetch_optional(&mut *tx).await?
        };
        let ready = ready.ok_or(Error::Denied)?;
        if !existed {
            record(&mut tx, user, "start", now).await?;
        }
        tx.commit().await?;
        self.recovery_changes.send_replace(());
        Ok((token, ready, (ready - now).max(0)))
    }

    /// Any signed-in device may cancel recovery without a fresh tap [25].
    pub async fn recovery_cancel(&self, token: &str, now: i64) -> Result<()> {
        let session = self.session(token, now).await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE users SET name=name WHERE id=?")
            .bind(&session.user_id)
            .execute(&mut *tx)
            .await?;
        if sqlx::query(
            "SELECT user_id FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>?",
        )
        .bind(hash(token))
        .bind(&session.user_id)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?
        .is_none()
        {
            return Err(Error::Denied);
        }
        let deleted = sqlx::query("DELETE FROM recovery WHERE user_id=?")
            .bind(&session.user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if deleted != 0 {
            record(&mut tx, &session.user_id, "cancel", now).await?;
        }
        tx.commit().await?;
        self.recovery_changes.send_replace(());
        Ok(())
    }

    /// Current account-scoped recovery state; callers must already hold session authority.
    pub(crate) async fn pending_recovery(&self, user: &str) -> Result<Option<i64>> {
        Ok(
            sqlx::query_scalar("SELECT ready FROM recovery WHERE user_id=?")
                .bind(user)
                .fetch_optional(&self.pool)
                .await?,
        )
    }

    /// Coalesced changes wake existing authenticated sockets without idle polling.
    pub(crate) fn recovery_events(&self) -> tokio::sync::watch::Receiver<()> {
        self.recovery_changes.subscribe()
    }

    /// Release the old recovery envelope only after the delay, then enroll a replacement passkey.
    pub async fn recovery_ready(&self, token: &str, now: i64) -> Result<Value> {
        let row = sqlx::query("SELECT users.id,users.username,users.display_name,wraps.blob FROM recovery JOIN users ON users.id=recovery.user_id JOIN wraps ON wraps.user_id=users.id AND wraps.kind='recovery' WHERE recovery.token_hash=? AND recovery.ready<=? AND recovery.expires>?")
            .bind(hash(token)).bind(now).bind(now).fetch_optional(&self.pool).await?.ok_or(Error::Denied)?;
        let mut registration = self
            .registration(
                row.get("id"),
                row.get("username"),
                row.get("display_name"),
                Authority::Recovery(hash(token)),
                true,
                now,
            )
            .await?;
        registration["old_recovery_wrap"] = serde_json::from_str(row.get("blob"))?;
        Ok(registration)
    }
}

// Audit writes share the writer transaction; notifications are emitted only after commit.
pub(super) async fn record(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    event: &str,
    now: i64,
) -> Result<()> {
    sqlx::query("INSERT INTO recovery_audit(user_id,event,occurred_at) VALUES (?,?,?)")
        .bind(user)
        .bind(event)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

// Consume recovery authority and replace all capabilities in one writer transaction.
pub(super) async fn complete(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    token: &str,
    verifier_hash: &str,
    version: i64,
    now: i64,
) -> Result<()> {
    if sqlx::query(
        "DELETE FROM recovery WHERE user_id=? AND token_hash=? AND ready<=? AND expires>?",
    )
    .bind(user)
    .bind(token)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        != 1
    {
        return Err(Error::Denied);
    }
    record(tx, user, "complete", now).await?;
    for table in ["sessions", "api_keys", "approvals", "passkeys", "wraps"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id=?"))
            .bind(user)
            .execute(&mut **tx)
            .await?;
    }
    sqlx::query(
        "UPDATE users SET recovery_hash=?,recovery_version=?,recovery_wrap_version=? WHERE id=?",
    )
    .bind(verifier_hash)
    .bind(version)
    .bind(version)
    .bind(user)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
