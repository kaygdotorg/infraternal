//! Applies fresh owner-authorized administrator role transitions, advancing wrapping generations and preserving offline recipient grants [151][168], #78.
use super::{
    CaAdministration, CaError, MessageDigest, PendingUnlock, RoleChange, Value, json,
    require_binding, require_live,
};
impl CaAdministration {
    /// Bind a fresh owner passkey proof to an exact administrator role change.
    /// # Errors
    /// Refuses non-owners, absent recipients and oversized identities.
    pub async fn membership_start(
        &self,
        token: &str,
        change: RoleChange,
        now: i64,
    ) -> Result<Value, CaError> {
        if change.user_id.is_empty() || change.user_id.len() > 256 {
            return Err(CaError);
        }
        let mut tx = self.pool.begin().await.map_err(|_| CaError)?;
        let actor = require_live(&mut tx, &crate::auth::hash(token), now).await?;
        let owner = sqlx::query_scalar::<_, bool>("SELECT owner=1 FROM users WHERE id=?")
            .bind(actor.user())
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| CaError)?;
        let recipient =
            sqlx::query_scalar::<_, i64>("SELECT 1 FROM passkeys WHERE user_id=? LIMIT 1")
                .bind(&change.user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| CaError)?;
        if !owner || recipient.is_none() {
            return Err(CaError);
        }
        tx.rollback().await.map_err(|_| CaError)?;
        let mut pending = self.pending.lock().await;
        pending.retain(|_, entry| entry.expires > now);
        if pending.len() >= 1024 {
            return Err(CaError);
        }
        let mut start = self
            .auth
            .login_start(actor.user(), now)
            .await
            .map_err(|_| CaError)?;
        let id = start["ceremony"].as_str().ok_or(CaError)?.to_owned();
        start["ca"] =
            json!({"member":actor.user(),"generation":actor.generation(),"operation":"role"});
        pending.insert(
            id,
            PendingUnlock {
                session_hash: crate::auth::hash(token),
                membership: actor,
                expires: now.checked_add(300).ok_or(CaError)?,
                salt: None,
                role: Some(change),
            },
        );
        Ok(start)
    }
    /// Revoke the exact old-generation copy or leave an offline grant pending.
    /// A recipient rewraps through bootstrap with its own scoped key while the
    /// issuer is unlocked. Other current copies remain usable after a cold start.
    /// # Errors
    /// Refuses stale proofs/roles, last-administrator removal or storage failure.
    pub async fn membership_finish(
        &self,
        token: &str,
        id: &str,
        proof: Value,
        now: i64,
    ) -> Result<(), CaError> {
        let hash = crate::auth::hash(token);
        let entry = {
            let mut pending = self.pending.lock().await;
            if pending.get(id).ok_or(CaError)?.session_hash != hash {
                return Err(CaError);
            }
            pending.remove(id).ok_or(CaError)?
        };
        if entry.role.is_none() {
            return Err(CaError);
        }
        if entry.expires <= now {
            return Err(CaError);
        }
        let verified = self
            .auth
            .verify_passkey(id, proof, now)
            .await
            .map_err(|_| CaError)?;
        let operation = self.operation();
        let permit = self
            .crypto
            .clone()
            .try_acquire_owned()
            .map_err(|_| CaError)?;
        tokio::spawn(async move {
            operation
                .membership_publish(entry, verified, now, permit)
                .await
        })
        .await
        .map_err(|_| CaError)?
    }
    /// Applies the change in one writer transaction: re-checks the owner's session and
    /// membership generation, that the proof was for a registered owner passkey made
    /// within the last 300 seconds, and that the role really changes. A revoke must
    /// leave another active administrator who still holds a copy for the current
    /// issuer. The generation goes up by one, the old encrypted copy file is removed,
    /// and the role row is written. A no-op change commits nothing.
    async fn membership_publish(
        &self,
        entry: PendingUnlock,
        verified: crate::auth::VerifiedPasskey,
        now: i64,
        _permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), CaError> {
        let hash = &entry.session_hash;
        let change = entry.role.as_ref().ok_or(CaError)?;
        let mut tx = self.pool.begin().await.map_err(|_| CaError)?;
        let live_now = now.max(crate::runtime::unix_seconds().map_err(|_| CaError)?);
        let current = require_live(&mut tx, hash, live_now).await?;
        require_binding(&current, &entry.membership)?;
        let registered=sqlx::query_scalar::<_,i64>("SELECT 1 FROM passkeys p JOIN users u ON u.id=p.user_id WHERE p.id=? AND p.user_id=? AND u.owner=1").bind(verified.credential()).bind(verified.user()).fetch_optional(&mut *tx).await.map_err(|_|CaError)?;
        if registered.is_none()
            || verified.user() != current.user()
            || verified.verified_at() > live_now
            || verified.verified_at() <= live_now - 300
            || verified.expires() <= live_now
            || entry.expires <= live_now
        {
            return Err(CaError);
        }
        let old = sqlx::query_as::<_, (i64, bool)>(
            "SELECT generation,active FROM ca_administrators WHERE user_id=?",
        )
        .bind(&change.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| CaError)?;
        if old.is_some_and(|(_, active)| active == change.administrator) {
            return tx.rollback().await.map_err(|_| CaError);
        }
        if !change.administrator {
            let remaining = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM ca_administrators WHERE active=1 AND user_id!=?",
            )
            .bind(&change.user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| CaError)?;
            if remaining == 0 {
                return Err(CaError);
            }
            self.require_other_retained_copy(&mut tx, &change.user_id)
                .await?;
        }
        let generation = old.map_or(Ok(1), |(generation, _)| {
            generation.checked_add(1).ok_or(CaError)
        })?;
        if let Some((old_generation, _)) = old {
            let copies = self.copy_store()?;
            let member = change.user_id.clone();
            let old_generation = u64::try_from(old_generation).map_err(|_| CaError)?;
            tokio::task::spawn_blocking(move || copies.remove(&member, old_generation))
                .await
                .map_err(|_| CaError)??;
        }
        sqlx::query("INSERT INTO ca_administrators(user_id,generation,active) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET generation=excluded.generation,active=excluded.active")
            .bind(&change.user_id).bind(generation).bind(change.administrator).execute(&mut *tx).await.map_err(|_|CaError)?;
        tx.commit().await.map_err(|_| CaError)
    }
    // A pending grant has no cold-start unwrap capability. Check public copy
    // bindings under the writer lock; no other administrator's key is requested.
    /// Used before revoking an administrator: succeeds only if some other active administrator still has an encrypted copy for the current issuer. Compares public bindings only, so no other administrator's key is needed. Passes when no issuer is retained yet.
    async fn require_other_retained_copy(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        excluded: &str,
    ) -> Result<(), CaError> {
        self.recover_published_issuer().await?;
        let Some(issuer) = self.source.retained_issuer()? else {
            return Ok(());
        };
        let fingerprint = issuer
            .digest(MessageDigest::sha256())
            .map_err(|_| CaError)?
            .to_vec();
        let members = sqlx::query_as::<_, (String, i64)>(
            "SELECT user_id,generation FROM ca_administrators WHERE active=1 AND user_id!=?",
        )
        .bind(excluded)
        .fetch_all(&mut **tx)
        .await
        .map_err(|_| CaError)?;
        let copies = self.copy_store()?;
        let retained = tokio::task::spawn_blocking(move || {
            members.into_iter().any(|(member, generation)| {
                u64::try_from(generation)
                    .ok()
                    .and_then(|generation| copies.read(&member, generation).ok())
                    .is_some_and(|copy| copy.issuer_fingerprint == fingerprint)
            })
        })
        .await
        .map_err(|_| CaError)?;
        if retained { Ok(()) } else { Err(CaError) }
    }
}
