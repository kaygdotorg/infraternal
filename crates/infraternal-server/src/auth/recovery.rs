//! Recovery delay, same-account live-session exemption and rotation isolation [25,D113].
use super::{Auth, Authority, DAY, Error, Result, Row, Value, hash, random};

/// Nanoseconds in a second; the recovery clock counts nanoseconds.
const SECOND: i64 = 1_000_000_000;

// The persisted epoch plus this process's uptime is a conservative elapsed clock.
// Restart loads only committed progress: downtime and unrecorded uptime earn no
// credit. MAX under the writer lock also supports overlapping Auth instances.
/// Conservative recovery-delay clock. Elapsed time is the committed value plus this
/// process's uptime, never moves backwards, and earns no credit for downtime.
pub(super) struct Clock {
    /// Elapsed nanoseconds already committed when this process started.
    epoch: i64,
    /// When this process loaded the clock; uptime is measured from here.
    started: std::time::Instant,
    /// Wakes the checkpoint task when a recovery starts.
    wake: std::sync::Arc<tokio::sync::Notify>,
    /// Handle used to stop and join the checkpoint task during database teardown.
    worker: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    pub(super) test_elapsed: std::sync::Arc<std::sync::atomic::AtomicI64>,
}
impl Clock {
    /// Loads the committed elapsed time from the database. Fails if the clock row is missing.
    pub(super) async fn load(pool: &sqlx::SqlitePool) -> Result<Self> {
        let epoch = sqlx::query_scalar("SELECT elapsed FROM recovery_clock WHERE singleton=1")
            .fetch_one(pool)
            .await?;
        Ok(Self {
            epoch,
            started: std::time::Instant::now(),
            wake: std::sync::Arc::default(),
            worker: std::sync::Mutex::default(),
            #[cfg(test)]
            test_elapsed: std::sync::Arc::new(std::sync::atomic::AtomicI64::new(i64::MIN)),
        })
    }

    /// Current elapsed nanoseconds: committed value plus uptime. Errors on overflow.
    fn sample(&self) -> Result<i64> {
        #[cfg(test)]
        {
            let elapsed = self.test_elapsed.load(std::sync::atomic::Ordering::Relaxed);
            if elapsed != i64::MIN {
                return self.epoch.checked_add(elapsed.max(0)).ok_or(Error::Invalid);
            }
        }
        let elapsed =
            i64::try_from(self.started.elapsed().as_nanos()).map_err(|_| Error::Invalid)?;
        self.epoch.checked_add(elapsed).ok_or(Error::Invalid)
    }

    // One writer-serialized measurement serves checkpoints and every authority check.
    /// Writes the current elapsed time inside `tx` (never lowering the stored value) and returns it.
    /// The first write takes the writer lock, so all checks see one serialized reading.
    async fn record(&self, tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<i64> {
        sqlx::query("UPDATE recovery_clock SET elapsed=elapsed WHERE singleton=1")
            .execute(&mut **tx)
            .await?;
        Ok(sqlx::query_scalar(
            "UPDATE recovery_clock SET elapsed=MAX(elapsed,?) WHERE singleton=1 RETURNING elapsed",
        )
        .bind(self.sample()?)
        .fetch_one(&mut **tx)
        .await?)
    }

    /// Commits the current elapsed time so a restart keeps the progress.
    async fn checkpoint(&self, pool: &sqlx::SqlitePool) -> Result<()> {
        let mut tx = pool.begin().await?;
        self.record(&mut tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// True if any recovery is still waiting out its delay.
    async fn active(pool: &sqlx::SqlitePool) -> Result<bool> {
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM recovery WHERE expires>(SELECT elapsed FROM recovery_clock WHERE singleton=1))")
            .fetch_one(pool).await?)
    }

    /// Stop and join the checkpoint worker before its database is closed or removed.
    ///
    /// An explicit join closes the gap between requesting cancellation and the task
    /// dropping its pooled connection. Dropping the clock itself remains a best-effort
    /// abort because `Drop` cannot wait asynchronously.
    ///
    /// # Errors
    /// Returns the worker panic if it failed before cancellation completed.
    #[cfg(test)]
    pub(super) async fn shutdown_checkpointing(
        &self,
    ) -> std::result::Result<(), tokio::task::JoinError> {
        let task = self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let Some(task) = task else {
            return Ok(());
        };
        task.abort();
        match task.await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error),
        }
    }

    // The task owns only a weak clock reference while sleeping. Dropping the last
    // Auth aborts it, so neither the pool nor recovery timers outlive their owner.
    // With no active recovery it waits on notification, without an idle timer.
    /// Starts the background task that saves progress every 60 seconds while a recovery is waiting, and sleeps on a notification otherwise.
    pub(super) fn start_checkpointing(self: &std::sync::Arc<Self>, pool: sqlx::SqlitePool) {
        let weak = std::sync::Arc::downgrade(self);
        let wake = self.wake.clone();
        let mut deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        let task = tokio::spawn(async move {
            loop {
                match Self::active(&pool).await {
                    Ok(false) => wake.notified().await,
                    Ok(true) | Err(_) => {
                        tokio::select! {
                            () = tokio::time::sleep_until(deadline) => {},
                            () = wake.notified() => {},
                        }
                    }
                }
                deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
                let Some(clock) = weak.upgrade() else {
                    return;
                };
                // Recheck after waking: cancellation must not keep an idle writer alive.
                let result = async {
                    if Self::active(&pool).await? {
                        clock.checkpoint(&pool).await?;
                    }
                    Ok::<_, Error>(())
                }
                .await;
                if result.is_err() {
                    tracing::warn!(
                        "could not checkpoint recovery elapsed time; unrecorded progress remains uncredited"
                    );
                }
            }
        });
        *self
            .worker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        if let Some(worker) = self
            .worker
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            worker.abort();
        }
    }
}

// Dates are presentation estimates only; every path derives them from the same
// elapsed-clock remainder. A wall correction can move the date, never authority.
fn estimate(ready: i64, elapsed: i64, wall: i64) -> i64 {
    let ticks = ready.saturating_sub(elapsed);
    wall.saturating_add(ticks.div_euclid(SECOND) + i64::from(ticks.rem_euclid(SECOND) != 0))
}

fn delay(ready: i64, elapsed: i64) -> i64 {
    estimate(ready, elapsed, 0).max(0)
}

pub(super) enum RecoveryCredential {
    #[cfg(test)]
    Legacy(String),
    Verifier(String),
}

#[allow(clippy::missing_errors_doc)]
impl Auth {
    // Obtain the writer lock before sampling uptime, including any database wait.
    // No wall clock is used by production recovery authority.
    async fn recovery_time(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        wall: i64,
    ) -> Result<i64> {
        let elapsed = self.recovery_clock.record(tx).await?;
        // Legacy fixtures explicitly simulate time with their supplied Unix clock.
        // Clock-step regressions inject measured nanoseconds into Clock itself.
        #[cfg(test)]
        if self
            .test_recovery_elapsed
            .load(std::sync::atomic::Ordering::Relaxed)
            == i64::MIN
        {
            let legacy = super::devices::api_key_time(tx, wall)
                .await?
                .checked_mul(SECOND)
                .ok_or(Error::Invalid)?;
            return Ok(sqlx::query_scalar("UPDATE recovery_clock SET elapsed=MAX(elapsed,?) WHERE singleton=1 RETURNING elapsed")
                .bind(legacy).fetch_one(&mut **tx).await?);
        }
        #[cfg(not(test))]
        let _ = wall;
        Ok(elapsed)
    }

    /// Save only measured uptime before the server exits, even before the first minute.
    pub(crate) async fn checkpoint_recovery_clock(&self) -> Result<()> {
        self.recovery_clock.checkpoint(&self.pool).await
    }

    /// Stop and join the recovery checkpoint task before test database cleanup.
    ///
    /// All cloned auth handles share the same clock, so this stops its one writer
    /// before the pool and its temporary directory are torn down.
    ///
    /// # Errors
    /// Returns the worker panic if it failed before cancellation completed.
    #[cfg(test)]
    pub(crate) async fn shutdown_recovery_clock(
        &self,
    ) -> std::result::Result<(), tokio::task::JoinError> {
        self.recovery_clock.shutdown_checkpointing().await
    }

    /// Start a 24-hour delayed recovery; repeat requests do not reset or accelerate it.
    #[cfg(test)]
    pub async fn recovery_start(&self, user: &str, words: String, now: i64) -> Result<String> {
        Ok(self
            .recovery_start_with_session(user, words, None, now)
            .await?
            .0)
    }

    /// Only an unlocked, unexpired session for this account may waive the delay [D113].
    /// Returns the recovery capability and its estimated Unix ready time.
    #[cfg(test)]
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
    #[cfg(test)]
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
        let resume = resume || matches!(&credential, RecoveryCredential::Verifier(_));
        let (stored, version) = verify_credential(self, user, credential).await?;
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
        // Session exemption retains wall-clock expiry; it cannot change an existing
        // request. Recovery readiness and lifetime use only the elapsed clock.
        let wall = clock()?;
        let session_now = super::devices::api_key_time(&mut tx, wall).await?;
        let elapsed = self.recovery_time(&mut tx, wall).await?;
        let previous: Option<(i64, i64)> =
            sqlx::query_as("SELECT ready,expires FROM recovery WHERE user_id=?")
                .bind(user)
                .fetch_optional(&mut *tx)
                .await?;
        let fresh = previous.is_none_or(|(_, expires)| expires <= elapsed);
        if !fresh && !resume {
            return Err(Error::Denied);
        }
        let (ready, expires) = if let Some(deadlines) = previous.filter(|_| !fresh) {
            deadlines
        } else {
            // Verify the exemption only after Argon2 and while holding the writer
            // lock. SQLite's statement clock covers executor delays in this check.
            let waived: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>MAX(?,unixepoch()))")
                .bind(session.map(hash).unwrap_or_default()).bind(user).bind(session_now)
                .fetch_one(&mut *tx).await?;
            (
                elapsed
                    .checked_add(if waived { 0 } else { DAY * SECOND })
                    .ok_or(Error::Invalid)?,
                elapsed
                    .checked_add(2 * DAY * SECOND)
                    .ok_or(Error::Invalid)?,
            )
        };
        let token = random();
        sqlx::query("INSERT INTO recovery(user_id,token_hash,ready,expires) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,ready=excluded.ready,expires=excluded.expires")
            .bind(user).bind(hash(&token)).bind(ready).bind(expires)
            .execute(&mut *tx).await?;
        if fresh {
            record(&mut tx, user, "start", wall).await?;
        }
        self.recovery_changes.commit(tx, user, None).await?;
        self.recovery_clock.wake.notify_one();
        Ok((token, estimate(ready, elapsed, wall), delay(ready, elapsed)))
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
        self.recovery_changes
            .commit(tx, &session.user_id, None)
            .await?;
        self.recovery_clock.wake.notify_one();
        Ok(())
    }

    /// Current account-scoped recovery state; callers must already hold session authority.
    pub(crate) async fn pending_recovery(&self, user: &str, wall: i64) -> Result<Option<i64>> {
        // Keep the usual no-recovery status read free of clock writes.
        let present: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM recovery WHERE user_id=?)")
                .bind(user)
                .fetch_one(&self.pool)
                .await?;
        if !present {
            return Ok(None);
        }
        let mut tx = self.pool.begin().await?;
        let elapsed = self.recovery_time(&mut tx, wall).await?;
        let ready: Option<i64> = sqlx::query_scalar("SELECT ready FROM recovery WHERE user_id=?")
            .bind(user)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(ready.map(|ready| estimate(ready, elapsed, wall)))
    }

    /// Coalesced account changes wake its authenticated sockets without idle polling.
    pub(crate) fn recovery_events(&self, user: &str) -> super::AccountSubscription {
        self.recovery_changes.subscribe(user)
    }

    /// Read an existing capability without rotating it, starting recovery or issuing a ceremony.
    pub async fn recovery_status(&self, token: &str, wall: i64) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        let elapsed = self.recovery_time(&mut tx, wall).await?;
        let ready: Option<i64> =
            sqlx::query_scalar("SELECT ready FROM recovery WHERE token_hash=? AND expires>?")
                .bind(hash(token))
                .bind(elapsed)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        let ready = ready.ok_or(Error::Denied)?;
        Ok(serde_json::json!({
            "ready": ready <= elapsed,
            "delay_seconds": delay(ready, elapsed),
            "ready_at": estimate(ready, elapsed, wall),
        }))
    }

    /// Release the old recovery envelope only after the delay, then enroll a replacement passkey.
    pub async fn recovery_ready(&self, token: &str, now: i64) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        let elapsed = self.recovery_time(&mut tx, now).await?;
        let row = sqlx::query("SELECT users.id,users.username,users.display_name,users.recovery_wrap_version,wraps.blob FROM recovery JOIN users ON users.id=recovery.user_id JOIN wraps ON wraps.user_id=users.id AND wraps.kind='recovery' WHERE recovery.token_hash=? AND recovery.ready<=? AND recovery.expires>?")
            .bind(hash(token)).bind(elapsed).bind(elapsed).fetch_optional(&mut *tx).await?;
        // Denied checks also record progress; a restart never invents elapsed time.
        tx.commit().await?;
        let row = row.ok_or(Error::Denied)?;
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

// Recovery delay/lifetime use the same elapsed clock as admission and status.
// The short, process-local ceremony separately retains its wall expiry policy.
#[allow(clippy::too_many_arguments)] // Keep both capability policies inside the consuming writer transaction.
pub(super) async fn complete(
    auth: &Auth,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    token: &str,
    verifier_hash: &str,
    version: i64,
    now: i64,
    ceremony_expires: i64,
) -> Result<()> {
    let elapsed = auth.recovery_time(tx, now).await?;
    if sqlx::query(
        "DELETE FROM recovery WHERE user_id=? AND token_hash=? AND ready<=? AND expires>? AND ?>MAX(?,unixepoch())",
    )
    .bind(user)
    .bind(token)
    .bind(elapsed)
    .bind(elapsed)
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
) -> Result<(String, i64)> {
    // Both identities use one indexed owner/candidate lookup and the same Argon2
    // work. A conditional second query would expose a different denial path,
    // especially when global KDF admission is exhausted. No metadata is published.
    let (known, stored, version): (bool, String, i64) = sqlx::query_as(
        "SELECT candidate.id IS NOT NULL,COALESCE(candidate.recovery_hash,owner.recovery_hash),COALESCE(candidate.recovery_version,owner.recovery_version) FROM users AS owner LEFT JOIN users AS candidate ON candidate.id=? WHERE owner.owner=1",
    ).bind(user).fetch_optional(&auth.pool).await?.ok_or(Error::Denied)?;
    match credential {
        #[cfg(test)]
        RecoveryCredential::Legacy(words) => {
            super::crypto::verify_recovery(words, stored.clone()).await?;
            if version != 1 {
                return Err(Error::Denied);
            }
        }
        RecoveryCredential::Verifier(secret) => {
            super::crypto::verify_secret(secret, stored.clone()).await?;
            if version != 2 {
                return Err(Error::Denied);
            }
        }
    }
    if !known {
        return Err(Error::Denied);
    }
    Ok((stored, version))
}
