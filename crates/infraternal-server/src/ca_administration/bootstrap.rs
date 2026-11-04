//! Binds first CA publication and pending-copy wrapping to fresh passkey proof and a serialized live administrator transaction [151][168], #78.
use super::{
    B64, CaAdministration, CaError, CaKeySource, Engine, PendingUnlock, Value, Zeroizing, json,
    require_binding, require_live,
};
impl CaAdministration {
    /// Start first setup or a pending administrator copy with a purpose-bound fresh tap.
    /// # Errors
    /// Refuses non-administrators, expired sessions or ceremony capacity exhaustion.
    pub async fn bootstrap_start(&self, token: &str, now: i64) -> Result<Value, CaError> {
        self.recover_published_issuer().await?;
        if self.source.issuer().is_ok() && self.source.load().is_err() {
            let mut start = self.start(token, now).await?;
            start["ca"]["operation"] = json!("unlock");
            return Ok(start);
        }
        let session_hash = crate::auth::hash(token);
        let mut tx = self.pool.begin().await.map_err(|_| CaError)?;
        let membership = require_live(&mut tx, &session_hash, now).await?;
        tx.rollback().await.map_err(|_| CaError)?;
        let salt = rand::random::<[u8; 32]>();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, entry| entry.expires > now);
        if pending.len() >= 1024 {
            return Err(CaError);
        }
        let mut start = self
            .auth
            .login_start(membership.user(), now)
            .await
            .map_err(|_| CaError)?;
        let id = start["ceremony"].as_str().ok_or(CaError)?.to_owned();
        start["ca"] = json!({"member":membership.user(), "generation":membership.generation(), "salt":B64.encode(salt),"operation":"setup"});
        pending.insert(
            id,
            PendingUnlock {
                session_hash,
                membership,
                expires: now.checked_add(300).ok_or(CaError)?,
                salt: Some(salt),
                role: None,
            },
        );
        Ok(start)
    }

    /// Generate once under writer serialization, or rewrap the unlocked retained
    /// issuer for a current pending member. No failed proof creates private state.
    /// # Errors
    /// Refuses foreign/stale/replayed proofs, unsafe state or unavailable wrapping authority.
    pub async fn bootstrap_finish(
        &self,
        token: &str,
        id: &str,
        proof: Value,
        scoped_key: Zeroizing<[u8; 32]>,
        now: i64,
    ) -> Result<(), CaError> {
        let unlock = self
            .pending
            .lock()
            .await
            .get(id)
            .is_some_and(|entry| entry.salt.is_none() && entry.role.is_none());
        if unlock {
            self.finish(token, id, proof, scoped_key, now).await?;
            if let Some(runtime) = &self.bootstrap {
                runtime.activate().await?;
            }
            return Ok(());
        }
        let session_hash = crate::auth::hash(token);
        let entry = {
            let mut pending = self.pending.lock().await;
            let entry = pending.get(id).ok_or(CaError)?;
            if entry.session_hash != session_hash {
                return Err(CaError);
            }
            pending.remove(id).ok_or(CaError)?
        };
        if entry.role.is_some() {
            return Err(CaError);
        }
        if entry.salt.is_none() {
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
                .bootstrap_publish(entry, verified, scoped_key, now, permit)
                .await
        })
        .await
        .map_err(|_| CaError)?
    }
    /// Final step of bootstrap or re-wrap for the acting administrator. In one writer
    /// transaction it re-checks the live session, membership generation and passkey
    /// (proof at most 300 seconds old, user matching the session), then seals a copy
    /// of the CA for the member. With no CA yet it creates the first one. If a CA exists
    /// only cold, it refuses rather than mint a replacement. After the file work it
    /// re-checks authority against the clock, installs the signing key and activates
    /// the runtime. The transaction is rolled back at the end: it only holds the lock.
    async fn bootstrap_publish(
        &self,
        entry: PendingUnlock,
        verified: crate::auth::VerifiedPasskey,
        scoped_key: Zeroizing<[u8; 32]>,
        now: i64,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), CaError> {
        let session_hash = &entry.session_hash;
        let salt = entry.salt.ok_or(CaError)?;
        let mut tx = self.pool.begin().await.map_err(|_| CaError)?;
        let current = require_live(&mut tx, session_hash, now).await?;
        require_binding(&current, &entry.membership)?;
        let registered =
            sqlx::query_scalar::<_, i64>("SELECT 1 FROM passkeys WHERE user_id=? AND id=?")
                .bind(verified.user())
                .bind(verified.credential())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| CaError)?;
        let live_now = now.max(crate::runtime::unix_seconds().map_err(|_| CaError)?);
        if registered.is_none()
            || verified.user() != current.user()
            || verified.verified_at() > live_now
            || verified.verified_at() <= live_now - 300
            || verified.expires() <= live_now
            || entry.expires <= live_now
        {
            return Err(CaError);
        }
        let current = require_live(&mut tx, session_hash, live_now).await?;
        require_binding(&current, &entry.membership)?;
        let member = current.user().to_owned();
        let generation = u64::try_from(current.generation()).map_err(|_| CaError)?;
        let runtime = self.bootstrap.as_ref().ok_or(CaError)?;
        let config = runtime.config.clone();
        let existing = self.source.load().ok();
        // A cold retained issuer must be unlocked through its existing copy;
        // bootstrap can never mint a replacement or bypass a cold-start lock.
        if existing.is_none() && self.source.issuer().is_ok() {
            return Err(CaError);
        }
        let copies = if existing.is_some() {
            Some(self.copy_store()?)
        } else {
            None
        };
        let _permit = permit;
        let material = tokio::task::spawn_blocking(move || {
            if let Some(material) = existing {
                copies.ok_or(CaError)?.publish(
                    &member,
                    generation,
                    &crate::ca::wrapping::WrappedCa::seal(
                        &material,
                        &member,
                        generation,
                        &salt,
                        &scoped_key,
                    )?,
                )?;
                Ok(material)
            } else {
                crate::ca_bootstrap::publish_first(
                    &config,
                    &member,
                    generation,
                    &salt,
                    &scoped_key,
                    live_now,
                )
            }
        })
        .await
        .map_err(|_| CaError)??;
        self.source
            .retain_published_issuer(material.issuer().clone())?;
        // The writer lock covers durable publication and install; revocations
        // cannot interleave. Recheck elapsed time after filesystem work.
        let live_now = now.max(crate::runtime::unix_seconds().map_err(|_| CaError)?);
        let current = require_live(&mut tx, session_hash, live_now).await?;
        require_binding(&current, &entry.membership)?;
        if entry.expires <= live_now || verified.expires() <= live_now {
            return Err(CaError);
        }
        crate::ca_bootstrap::install(&self.source, material)?;
        tx.rollback().await.map_err(|_| CaError)?;
        runtime.activate().await
    }
    // Recover only public trust after an interrupted finalization. Keeping the
    // signing lock permits a new fresh proof; retained trust is never replaced.
    /// Restores the public issuer after an interrupted finalization, from the `active`
    /// directory under the CA state. Does nothing if an issuer is already known, there is
    /// no bootstrap configuration, or nothing was published. It restores only public
    /// trust, so the signing key stays locked until a fresh passkey proof.
    pub(super) async fn recover_published_issuer(&self) -> Result<(), CaError> {
        if self.source.retained_issuer()?.is_some() {
            return Ok(());
        }
        let Some(runtime) = &self.bootstrap else {
            return Ok(());
        };
        let active = runtime.config.directory.join("active");
        match active.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(CaError),
            Ok(_) => {}
        }
        let issuer =
            tokio::task::spawn_blocking(move || crate::ca_bootstrap::public_issuer(&active))
                .await
                .map_err(|_| CaError)??;
        self.source.retain_published_issuer(issuer)
    }
}
