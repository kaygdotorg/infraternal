//! Retains exact-host provisioning retirement across cancellation, writer contention and restart (#169).

use crate::enrollment::{EnrollmentError, EnrollmentStore};
use uuid::Uuid;

impl EnrollmentStore {
    /// Retire an exact cancelled attempt and consume its durable intent in the
    /// same writer transaction. The caller fences transport before spawning
    /// this owned operation, so waiting for SQLite never preserves access.
    /// # Errors
    /// Refuses changed ownership, invalid time or unavailable storage.
    pub async fn retire_bootstrap(
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
        let changed = sqlx::query("UPDATE remote_hosts SET revoked_at=COALESCE(revoked_at, ?) WHERE id=? AND owner_id=? AND created_at<=?")
            .bind(now).bind(host.as_bytes().as_slice()).bind(owner).bind(now)
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
        self.commit_revocation(transaction, host).await
    }

    /// Startup owns no surviving provisioning batches. Complete their durable
    /// retirement obligations before exposing enrollment or remote listeners.
    /// Call only before transport admission starts; no live batches may exist.
    /// # Errors
    /// Returns storage failure without partially retiring the intent journal.
    pub async fn retire_unfinished_bootstraps(&self) -> Result<(), sqlx::Error> {
        let mut transaction = self.0.begin().await?;
        sqlx::query("UPDATE remote_hosts SET revoked_at=COALESCE(revoked_at, MAX(created_at, unixepoch())) WHERE id IN (SELECT host_id FROM remote_bootstrap_retirement_intents)")
            .execute(&mut *transaction).await?;
        sqlx::query("DELETE FROM remote_bootstrap_retirement_intents")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await
    }

    /// Proven installation completion releases the restart retirement obligation.
    /// # Errors
    /// Refuses foreign/revoked hosts, missing intent or unavailable storage.
    pub async fn complete_bootstrap(&self, owner: &str, host: Uuid) -> Result<(), EnrollmentError> {
        let removed = sqlx::query("DELETE FROM remote_bootstrap_retirement_intents WHERE host_id=? AND EXISTS(SELECT 1 FROM remote_hosts WHERE id=host_id AND owner_id=? AND revoked_at IS NULL)")
            .bind(host.as_bytes().as_slice()).bind(owner).execute(&self.0).await?.rows_affected();
        if removed != 1 {
            return Err(EnrollmentError::Denied);
        }
        Ok(())
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
}
