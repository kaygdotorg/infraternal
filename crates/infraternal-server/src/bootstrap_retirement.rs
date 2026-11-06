//! Retains exact-host provisioning retirement across cancellation, writer contention and restart (#169).

use crate::enrollment::{EnrollmentError, EnrollmentStore};
use uuid::Uuid;

impl EnrollmentStore {
    /// Persist denial for an exact cancelled attempt; person retirement and
    /// intent removal wait for the durable host receipt. The caller fences
    /// transport first, so waiting for SQLite never preserves remote access.
    /// # Errors
    /// Refuses changed ownership, invalid time or unavailable storage.
    pub(crate) async fn retire_bootstrap(
        &self,
        owner: &str,
        host: Uuid,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        loop {
            match self.retire_bootstrap_once(owner, host, now).await {
                Err(EnrollmentError::Storage(error)) if writer_contention(&error) => {
                    // This obligation is active only during retirement. Retry
                    // a fresh transaction after BUSY/LOCKED, including extended
                    // codes; corruption and closed storage are never retried.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                result => return result,
            }
        }
    }

    /// One serialized intent attempt, followed by a cancellable receipt wait.
    /// Refuses a negative time or a host that exists but is not this
    /// owner's, was created later than `now`, or has no pending retirement intent.
    async fn retire_bootstrap_once(
        &self,
        owner: &str,
        host: Uuid,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        if now < 0 {
            return Err(EnrollmentError::Denied);
        }
        let mut transaction = self.0.begin().await?;
        // The first write serializes behind any invitation COMMIT. An absent
        // host after this barrier means issuance never committed; only the
        // caller's pre-registered random UUID can reach this operation.
        let changed = sqlx::query("UPDATE remote_hosts SET id=id WHERE id=? AND owner_id=? AND created_at<=? AND EXISTS(SELECT 1 FROM remote_bootstrap_retirement_intents WHERE host_id=remote_hosts.id)")
            .bind(host.as_bytes().as_slice()).bind(owner).bind(now)
            .execute(&mut *transaction).await?.rows_affected();
        if changed != 1
            && sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM remote_hosts WHERE id=?)")
                .bind(host.as_bytes().as_slice())
                .fetch_one(&mut *transaction)
                .await?
        {
            return Err(EnrollmentError::Denied);
        }
        sqlx::query("DELETE FROM remote_bootstrap_retirement_intents WHERE host_id=? AND EXISTS(SELECT 1 FROM remote_hosts WHERE id=host_id AND owner_id=? AND revoked_at IS NOT NULL)")
            .bind(host.as_bytes().as_slice()).bind(owner)
            .execute(&mut *transaction).await?;
        self.commit_revocation(transaction, host, now).await
    }

    /// Deny an abandoned setup's host found by a later add of the same address
    /// (#305): the same ownership and open-intent checks as
    /// [`retire_bootstrap`](EnrollmentStore::retire_bootstrap), then the denial is
    /// committed without waiting for a receipt from the host's infraternal agent,
    /// which is gone, exactly as Remove does for an offline host. The durable
    /// login-cleanup outbox finishes the person's retirement if that agent ever
    /// reconnects; until then its certificate is no longer admitted.
    /// # Errors
    /// Refuses a negative time, another owner's host, one created after `now` or
    /// one without an open intent, and unavailable storage.
    pub(crate) async fn deny_abandoned_bootstrap(
        &self,
        owner: &str,
        host: Uuid,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        if now < 0 {
            return Err(EnrollmentError::Denied);
        }
        let mut transaction = self.0.begin().await?;
        let matched = sqlx::query("UPDATE remote_hosts SET id=id WHERE id=? AND owner_id=? AND created_at<=? AND EXISTS(SELECT 1 FROM remote_bootstrap_retirement_intents WHERE host_id=remote_hosts.id)")
            .bind(host.as_bytes().as_slice()).bind(owner).bind(now)
            .execute(&mut *transaction).await?.rows_affected();
        if matched != 1 {
            return Err(EnrollmentError::Denied);
        }
        self.commit_revocation_intent(transaction, host, now).await?;
        Ok(())
    }

    /// Startup owns no surviving provisioning batches. Persist pending denials
    /// before listeners start; person retirement awaits a cleanup-only receipt.
    /// Call only before transport admission starts; no live batches may exist.
    /// # Errors
    /// Returns storage failure without partially retiring the intent journal.
    pub(crate) async fn retire_unfinished_bootstraps(&self) -> Result<(), sqlx::Error> {
        let mut transaction = self.0.begin().await?;
        let unfinished: Vec<(Vec<u8>, String)> = sqlx::query_as("SELECT id,owner_id FROM remote_hosts WHERE id IN (SELECT host_id FROM remote_bootstrap_retirement_intents) AND NOT EXISTS(SELECT 1 FROM terminal_sessions s WHERE s.remote_host_id=remote_hosts.id AND s.user_id=remote_hosts.owner_id AND s.closed_at IS NULL)")
            .fetch_all(&mut *transaction).await?;
        for (host, owner) in unfinished {
            if Uuid::parse_str(&owner).is_ok() {
                // Startup has no live transport to drain. Persist denial before
                // listeners start and let cleanup-only reconnect finalize it.
                sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES(?,?) ON CONFLICT(host_id) DO NOTHING")
                    .bind(&host).bind(owner).execute(&mut *transaction).await?;
            } else {
                // Legacy ledger identities cannot own a daemon person login.
                sqlx::query("UPDATE remote_hosts SET revoked_at=COALESCE(revoked_at,MAX(created_at,unixepoch())) WHERE id=?")
                    .bind(&host).execute(&mut *transaction).await?;
            }
        }
        // A published session belongs to its person across server restart.
        // Keep its setup obligation; never apply unpublished-host retirement.
        sqlx::query("DELETE FROM remote_bootstrap_retirement_intents WHERE host_id IN (SELECT id FROM remote_hosts WHERE revoked_at IS NOT NULL)")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await
    }

    /// Proven installation completion releases the restart retirement obligation.
    /// # Errors
    /// Refuses foreign/revoked hosts, missing intent or unavailable storage.
    pub(crate) async fn complete_bootstrap(
        &self,
        owner: &str,
        host: Uuid,
    ) -> Result<(), EnrollmentError> {
        let removed = sqlx::query("DELETE FROM remote_bootstrap_retirement_intents WHERE host_id=? AND EXISTS(SELECT 1 FROM remote_hosts WHERE id=host_id AND owner_id=? AND revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=remote_hosts.id AND q.confirmed=0))")
            .bind(host.as_bytes().as_slice()).bind(owner).execute(&self.0).await?.rows_affected();
        if removed != 1 {
            return Err(EnrollmentError::Denied);
        }
        Ok(())
    }
}

/// Extended SQLite result codes retain their primary code in the low byte.
fn writer_contention(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::PoolTimedOut => true,
        sqlx::Error::Database(database) => database
            .code()
            .and_then(|code| code.parse::<u32>().ok())
            .is_some_and(|code| matches!(code & 0xff, 5 | 6)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    //! Real SQLite restart and exact ownership keep unfinished hosts separate from proven installations.
    use super::*;
    use crate::enrollment::authority::tests::enrolled;

    async fn intent(store: &EnrollmentStore, host: Uuid) {
        sqlx::query("INSERT INTO remote_bootstrap_retirement_intents(host_id) VALUES(?)")
            .bind(host.as_bytes().as_slice())
            .execute(&store.0)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn startup_retires_only_unfinished_provisioning_and_is_idempotent() {
        let (store, pool, prior) = enrolled().await;
        let pending = Uuid::new_v4();
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootless',1002,100)")
            .bind(pending.as_bytes().as_slice()).execute(&pool).await.unwrap();
        intent(&store, pending).await;
        let restarted = EnrollmentStore::new(pool.clone());
        restarted.retire_unfinished_bootstraps().await.unwrap();
        restarted.retire_unfinished_bootstraps().await.unwrap();
        assert_eq!(restarted.admit(&[1; 32], 100).await.unwrap().host, prior);
        assert!(
            sqlx::query_scalar::<_, bool>(
                "SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?"
            )
            .bind(pending.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM remote_bootstrap_retirement_intents"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn proven_completion_is_owner_bound_and_survives_restart() {
        let (store, pool, host) = enrolled().await;
        intent(&store, host).await;
        assert!(store.complete_bootstrap("foreign", host).await.is_err());
        store.complete_bootstrap("owner", host).await.unwrap();
        EnrollmentStore::new(pool)
            .retire_unfinished_bootstraps()
            .await
            .unwrap();
        assert_eq!(store.admit(&[1; 32], 100).await.unwrap().host, host);
    }

    #[tokio::test]
    async fn retirement_consumes_only_its_owned_intent_with_the_tombstone() {
        let (store, pool, host) = enrolled().await;
        intent(&store, host).await;
        assert!(store.retire_bootstrap("foreign", host, 101).await.is_err());
        assert_eq!(store.admit(&[1; 32], 100).await.unwrap().host, host);
        store.retire_bootstrap("owner", host, 101).await.unwrap();
        assert!(store.admit(&[1; 32], 101).await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM remote_bootstrap_retirement_intents"
            )
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
    }
    #[tokio::test]
    async fn startup_preserves_a_published_live_session_and_its_setup_intent() {
        let (store, pool, host) = enrolled().await;
        intent(&store, host).await;
        let session = Uuid::new_v4();
        sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,remote_host_id) VALUES(?,'owner',100,100,?)")
            .bind(session.as_bytes().as_slice()).bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
        store.retire_unfinished_bootstraps().await.unwrap();
        assert_eq!(store.admit(&[1; 32], 100).await.unwrap().host, host);
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM remote_bootstrap_retirement_intents WHERE host_id=?)",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(pending, "published setup remains recoverable after restart");
    }
}

#[cfg(test)]
mod ownership_regression {
    //! A completed installation without a retirement intent is never a failed attempt.
    use super::*;

    #[tokio::test]
    async fn retirement_requires_an_unfinished_intent() {
        let (store, _, host) = crate::enrollment::authority::tests::enrolled().await;
        assert!(matches!(
            store.retire_bootstrap("owner", host, 101).await,
            Err(EnrollmentError::Denied)
        ));
        assert_eq!(store.admit(&[1; 32], 101).await.unwrap().host, host);
    }
}
