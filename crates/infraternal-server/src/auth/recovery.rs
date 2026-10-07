//! Recovery delay, same-account live-session exemption and rotation isolation [25,D113].
use super::{Auth, Authority, DAY, Error, Result, Row, Value, hash, random, verify_recovery};

pub(super) enum RecoveryCredential {
    Legacy(String),
    Verifier(String),
    Upgrade { words: String, verifier: String },
}

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
            .recovery_start_clock(
                user,
                RecoveryCredential::Legacy(words),
                session,
                || Ok(now),
                false,
            )
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
            .recovery_start_clock(
                user,
                RecoveryCredential::Legacy(words),
                None,
                || Ok(now),
                true,
            )
            .await?;
        Ok((token, ready))
    }

    // HTTP supplies a live clock; deterministic library callers supply their own time.
    // Sample it only after the writer lock so every verification/database await is covered.
    pub(super) async fn recovery_start_clock(
        &self,
        user: &str,
        credential: RecoveryCredential,
        session: Option<&str>,
        clock: impl Fn() -> Result<i64>,
        resume: bool,
    ) -> Result<(String, i64, i64)> {
        let resume = resume || !matches!(&credential, RecoveryCredential::Legacy(_));
        let (stored, version, upgrade) = verify_credential(self, user, credential).await?;
        #[cfg(test)]
        if let Some(pause) = self.recovery_pause.lock().await.take() {
            pause.verified.notify_one();
            pause.resume.notified().await;
        }
        let mut tx = self.pool.begin().await?;
        // Argon2 runs off-thread without holding a database writer lock. Recheck the
        // exact verified hash under that lock so rotation cannot authorize old words.
        let current: Option<(String, i64)> = sqlx::query_as(
            "UPDATE users SET name=name WHERE id=? RETURNING recovery_hash,recovery_version",
        )
        .bind(user)
        .fetch_optional(&mut *tx)
        .await?;
        if current.as_ref() != Some(&(stored.clone(), version)) {
            return Err(Error::Denied);
        }
        if let Some(upgraded) = upgrade {
            // This same transaction permanently disables phrase authentication and
            // preserves the old wrap version/ciphertext and any original deadline.
            sqlx::query("UPDATE users SET recovery_hash=?,recovery_version=2 WHERE id=?")
                .bind(upgraded)
                .bind(user)
                .execute(&mut *tx)
                .await?;
        }
        // Do not slide or check the cookie before Argon2: revocation/expiry can occur
        // during verification. This recheck shares the writer lock with request creation.
        let now = clock()?;
        let existed: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM recovery WHERE user_id=?)")
                .bind(user)
                .fetch_one(&mut *tx)
                .await?;
        let token = random();
        let conflict = if resume {
            "ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,expires=excluded.expires"
        } else {
            "ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,ready=excluded.ready,expires=excluded.expires WHERE recovery.expires<=MAX(?,unixepoch())"
        };
        // Evaluate session/account/expiry inside the very statement that grants the
        // waiver. SQLite's statement clock covers executor delays after Rust sampled
        // time; MAX also respects the explicit future clock used by library callers.
        // Resumption changes only bearer lifetime, never the stored ready deadline.
        let sql = format!(
            "WITH clock(now) AS (SELECT MAX(?,unixepoch())) INSERT INTO recovery(user_id,token_hash,ready,expires) SELECT ?,?,CASE WHEN EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>clock.now) THEN clock.now ELSE clock.now+? END,clock.now+? FROM clock WHERE 1 {conflict} RETURNING ready,MAX(ready-MAX(?,unixepoch()),0),MAX(?,unixepoch())"
        );
        let mut query = sqlx::query_as::<_, (i64, i64, i64)>(&sql)
            .bind(now)
            .bind(user)
            .bind(hash(&token))
            .bind(session.map(hash).unwrap_or_default())
            .bind(user)
            .bind(DAY)
            .bind(2 * DAY);
        if !resume {
            query = query.bind(now);
        }
        let (ready, delay, authority_now) = query
            .bind(now)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::Denied)?;
        if !existed {
            record(&mut tx, user, "start", authority_now).await?;
        }
        tx.commit().await?;
        self.recovery_changes.send_replace(());
        Ok((token, ready, delay))
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
        let row = sqlx::query("SELECT users.id,users.username,users.display_name,users.recovery_wrap_version,wraps.blob FROM recovery JOIN users ON users.id=recovery.user_id JOIN wraps ON wraps.user_id=users.id AND wraps.kind='recovery' WHERE recovery.token_hash=? AND recovery.ready<=? AND recovery.expires>?")
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
        registration["old_recovery_wrap_version"] =
            serde_json::json!(row.get::<i64, _>("recovery_wrap_version"));
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

// Consume recovery and ceremony authority at statement time inside the writer
// transaction. MAX preserves explicit future clocks in deterministic library tests.
pub(super) async fn complete(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    token: &str,
    verifier_hash: &str,
    version: i64,
    now: i64,
    ceremony_expires: i64,
) -> Result<()> {
    if sqlx::query(
        "DELETE FROM recovery WHERE user_id=? AND token_hash=? AND ready<=MAX(?,unixepoch()) AND expires>MAX(?,unixepoch()) AND ?>MAX(?,unixepoch())",
    )
    .bind(user)
    .bind(token)
    .bind(now)
    .bind(now)
    .bind(ceremony_expires)
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

// Expensive verifier work stays outside the writer lock. The returned hash/version
// snapshot must be rechecked together under that lock before granting any authority.
async fn verify_credential(
    auth: &Auth,
    user: &str,
    credential: RecoveryCredential,
) -> Result<(String, i64, Option<String>)> {
    // Both identities use one indexed owner/candidate lookup and the same Argon2
    // work. A conditional second query would expose a different denial path,
    // especially when global KDF admission is exhausted. No metadata is published.
    let (known, stored, version): (bool, String, i64) = sqlx::query_as(
        "SELECT candidate.id IS NOT NULL,COALESCE(candidate.recovery_hash,owner.recovery_hash),COALESCE(candidate.recovery_version,owner.recovery_version) FROM users AS owner LEFT JOIN users AS candidate ON candidate.id=? WHERE owner.owner=1",
    ).bind(user).fetch_optional(&auth.pool).await?.ok_or(Error::Denied)?;
    let upgrade = match credential {
        RecoveryCredential::Legacy(words) => {
            verify_recovery(words, stored.clone()).await?;
            if version != 1 {
                return Err(Error::Denied);
            }
            None
        }
        RecoveryCredential::Verifier(secret) => {
            super::crypto::verify_secret(secret, stored.clone()).await?;
            if version != 2 {
                return Err(Error::Denied);
            }
            None
        }
        RecoveryCredential::Upgrade { words, verifier } => {
            super::crypto::valid_secret(&verifier)?;
            verify_recovery(words, stored.clone()).await?;
            if version != 1 {
                return Err(Error::Denied);
            }
            Some(super::recovery_hash(verifier).await?)
        }
    };
    if !known {
        return Err(Error::Denied);
    }
    Ok((stored, version, upgrade))
}
