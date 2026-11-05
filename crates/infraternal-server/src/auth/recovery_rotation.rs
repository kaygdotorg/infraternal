//! Replace legacy recovery metadata from a signed-in device without receiving wrapping material.
use super::{
    Auth, Error, Result, TapAction, Wrap, action_tap, hash, put_wrap, recovery_hash, require_tap_tx,
};

impl Auth {
    /// Install browser-generated recovery ciphertext and its independent verifier [23,28,#45].
    ///
    /// # Errors
    /// Denies stale/pending/revoked sessions and accounts already using both v2 formats.
    pub async fn recovery_rotate(
        &self,
        token: &str,
        user: &str,
        wrap: Wrap,
        verifier: String,
        now: i64,
    ) -> Result<()> {
        self.recovery_rotate_clock(token, user, wrap, verifier, || Ok(now))
            .await
    }

    // A live HTTP clock covers both KDF work and waiting for the SQLite writer.
    pub(super) async fn recovery_rotate_clock(
        &self,
        token: &str,
        user: &str,
        wrap: Wrap,
        verifier: String,
        clock: impl Fn() -> Result<i64>,
    ) -> Result<()> {
        wrap.validate()?;
        super::crypto::valid_secret(&verifier)?;
        let now = clock()?;
        // Reject unauthenticated callers before spending the bounded KDF capacity.
        // This snapshot locates the account only; commit authority is rechecked below.
        // Pin the account used for local envelope AAD. A shared cookie switching
        // accounts while words are displayed must not retarget this ciphertext.
        // The tap must have been made for this rotation (D336); the transaction below spends it.
        if !action_tap::tap_ready(
            &self.pool,
            &hash(token),
            user,
            &TapAction::RotateRecovery,
            now,
        )
        .await?
        {
            return Err(Error::Denied);
        }
        let verifier_hash = recovery_hash(verifier).await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE users SET name=name WHERE id=?")
            .bind(user)
            .execute(&mut *tx)
            .await?;
        let now = clock()?;
        require_tap_tx(&mut tx, &hash(token), user, &TapAction::RotateRecovery, now).await?;
        // Both metadata versions and the envelope change together. This predicate
        // also makes competing signed-in replacements one-shot for a legacy account.
        if sqlx::query("UPDATE users SET recovery_hash=?,recovery_version=2,recovery_wrap_version=2 WHERE id=? AND (recovery_version=1 OR recovery_wrap_version=1)")
            .bind(verifier_hash).bind(user).execute(&mut *tx).await?.rows_affected()!=1 {
            return Err(Error::Denied);
        }
        // put_wrap deliberately rejects duplicate enrollment envelopes. Remove only
        // the recovery row here, under the same writer transaction, before reuse.
        sqlx::query("DELETE FROM wraps WHERE user_id=? AND kind='recovery'")
            .bind(user)
            .execute(&mut *tx)
            .await?;
        put_wrap(&mut tx, user, "recovery", "recovery", &wrap).await?;
        // Old recovery capabilities and ceremonies must not install another envelope
        // after the signed-in device replaces it. Passkeys and sessions are retained.
        if sqlx::query("DELETE FROM recovery WHERE user_id=?")
            .bind(user)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            != 0
        {
            super::recovery::record(&mut tx, user, "cancel", now).await?;
        }
        self.recovery_changes.commit(tx, user, None).await?;
        Ok(())
    }
}
