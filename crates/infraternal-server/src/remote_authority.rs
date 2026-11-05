//! Rechecks public host authority and persists overlapping renewals without extending revoked hosts [128][133][134], #78.

use crate::enrollment::{CertificateRecord, EnrollmentError, EnrollmentStore, Mode};
use uuid::Uuid;

/// Trusted enrolled identity; the execution uid never comes from browser input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostAuthority {
    /// Host that owns this certificate and the remote sessions.
    pub host: Uuid,
    /// Immutable enrolled privilege mode.
    pub mode: Mode,
    /// Unix uid selected by the trusted enrollment operation on that host.
    pub execution_uid: u32,
    /// Exact current certificate validity cap, independent of host reconnects.
    pub not_after: i64,
}

impl EnrollmentStore {
    /// Admit an exact certificate fingerprint against live, persisted host authority.
    /// # Errors
    /// Refuses unknown/expired/revoked certificates, invalid time and storage failure.
    pub async fn admit(
        &self,
        fingerprint: &[u8; 32],
        now: i64,
    ) -> Result<HostAuthority, EnrollmentError> {
        if now < 0 {
            return Err(EnrollmentError::Denied);
        }
        let row: Option<(Vec<u8>, String, i64, i64)> = sqlx::query_as(
            "SELECT h.id, h.mode, h.execution_uid, c.not_after FROM remote_hosts h \
             JOIN remote_certificates c ON c.host_id=h.id \
             WHERE c.fingerprint=? AND c.not_before<=? AND c.not_after>? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL \
             AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0)",
        )
        .bind(fingerprint.as_slice())
        .bind(now)
        .bind(now)
        .fetch_optional(&self.0)
        .await?;
        let (host, mode, uid, not_after) = row.ok_or(EnrollmentError::Denied)?;
        let host = Uuid::from_slice(&host).map_err(|_| EnrollmentError::Denied)?;
        let execution_uid = u32::try_from(uid).map_err(|_| EnrollmentError::Denied)?;
        let mode = match mode.as_str() {
            "rootless" if execution_uid != 0 => Mode::Rootless,
            "rootful" if execution_uid == 0 => Mode::Rootful,
            _ => return Err(EnrollmentError::Denied),
        };
        Ok(HostAuthority {
            host,
            mode,
            execution_uid,
            not_after,
        })
    }

    /// Admit a pending or retired host only for retained cleanup, never new work.
    /// The certificate must still be exact, valid and individually unrevoked.
    pub(crate) async fn admit_cleanup(
        &self,
        fingerprint: &[u8; 32],
        now: i64,
    ) -> Result<(HostAuthority, Uuid), EnrollmentError> {
        let row: Option<(Vec<u8>, String, i64, i64, String)> = sqlx::query_as(
            "SELECT h.id,h.mode,h.execution_uid,c.not_after,q.person_id FROM remote_hosts h \
             JOIN remote_certificates c ON c.host_id=h.id \
             JOIN remote_login_cleanup q ON q.host_id=h.id \
             WHERE c.fingerprint=? AND c.not_before<=? AND c.not_after>? \
             AND c.revoked_at IS NULL AND q.confirmed=0",
        )
        .bind(fingerprint.as_slice())
        .bind(now)
        .bind(now)
        .fetch_optional(&self.0)
        .await?;
        let (host, mode, uid, not_after, person) = row.ok_or(EnrollmentError::Denied)?;
        let host = Uuid::from_slice(&host).map_err(|_| EnrollmentError::Denied)?;
        let person = Uuid::parse_str(&person).map_err(|_| EnrollmentError::Denied)?;
        let execution_uid = u32::try_from(uid).map_err(|_| EnrollmentError::Denied)?;
        let mode = match mode.as_str() {
            "rootless" if execution_uid != 0 => Mode::Rootless,
            "rootful" if execution_uid == 0 => Mode::Rootful,
            _ => return Err(EnrollmentError::Denied),
        };
        Ok((
            HostAuthority {
                host,
                mode,
                execution_uid,
                not_after,
            },
            person,
        ))
    }

    /// Finalize retirement only on a durable daemon reply; lost replies stay pending.
    /// A removal keeps bootstrap coordinates for manual cleanup until this receipt.
    pub(crate) async fn confirm_login_cleanup(
        &self,
        host: Uuid,
        person: Uuid,
    ) -> Result<(), EnrollmentError> {
        let mut transaction = self.0.begin().await?;
        // Keep tombstoning and its trigger effects in the same transaction as
        // the durable receipt. A foreign or duplicate receipt changes nothing.
        sqlx::query("UPDATE remote_hosts SET revoked_at=MAX(created_at,unixepoch()) WHERE id=? AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=remote_hosts.id AND q.person_id=? AND q.confirmed=0)")
            .bind(host.as_bytes().as_slice()).bind(person.to_string())
            .execute(&mut *transaction).await?;
        sqlx::query("UPDATE remote_login_cleanup SET confirmed=1 WHERE host_id=? AND person_id=?")
            .bind(host.as_bytes().as_slice())
            .bind(person.to_string())
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM remote_bootstrap_retirement_intents WHERE host_id=? AND EXISTS(SELECT 1 FROM remote_hosts WHERE id=host_id AND revoked_at IS NOT NULL)")
            .bind(host.as_bytes().as_slice()).execute(&mut *transaction).await?;
        // Only removal owns this deletion. Other revocation paths may retain
        // bootstrap coordinates for their existing restoration contract; a
        // foreign receipt cannot erase either kind of installation information.
        sqlx::query("DELETE FROM remote_host_bootstrap WHERE host_id=? AND EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=remote_host_bootstrap.host_id) AND EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=remote_host_bootstrap.host_id AND q.person_id=? AND q.confirmed=1)")
            .bind(host.as_bytes().as_slice()).bind(person.to_string())
            .execute(&mut *transaction).await?;
        transaction.commit().await?;
        self.1.tombstoned(host);
        self.publish_revoked_authority().await;
        self.2.publish();
        Ok(())
    }

    /// Persist a renewed certificate only for the live predecessor's same host key.
    /// # Errors
    /// Refuses expired/revoked predecessors, changed keys, invalid validity or storage failure.
    pub async fn renew(
        &self,
        predecessor: &[u8; 32],
        certificate: &CertificateRecord,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        if now < 0
            || certificate.not_before != now
            || now.checked_add(604_800) != Some(certificate.not_after)
        {
            return Err(EnrollmentError::Denied);
        }
        // INSERT SELECT is one serialized write. Revocation either precedes this
        // statement and refuses it, or follows it and denies both generations.
        let changed = sqlx::query(
            "INSERT INTO remote_certificates (fingerprint, host_id, issuer_fingerprint, public_key, not_before, not_after) \
             SELECT ?, old.host_id, ?, ?, ?, ? FROM remote_certificates old \
             JOIN remote_hosts h ON h.id=old.host_id \
             WHERE old.fingerprint=? AND old.public_key=? AND old.not_before<=? AND old.not_after>? \
             AND old.revoked_at IS NULL AND h.revoked_at IS NULL \
             AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0)",
        ).bind(certificate.fingerprint.as_slice()).bind(certificate.issuer_fingerprint.as_slice())
            .bind(certificate.public_key.as_slice()).bind(certificate.not_before).bind(certificate.not_after)
            .bind(predecessor.as_slice()).bind(certificate.public_key.as_slice()).bind(now).bind(now)
            .execute(&self.0).await?.rows_affected();
        if changed != 1 {
            return Err(EnrollmentError::Denied);
        }
        Ok(())
    }

    /// Persist owner-authorized denial, then wait for durable host acceptance.
    /// # Errors
    /// Refuses wrong owner, unknown host, invalid time and storage failure.
    pub async fn revoke(&self, owner: &str, host: Uuid, now: i64) -> Result<(), EnrollmentError> {
        if now < 0 {
            return Err(EnrollmentError::Denied);
        }
        let mut transaction = self.0.begin().await?;
        let changed = sqlx::query(
            "UPDATE remote_hosts SET id=id \
             WHERE id=? AND owner_id=? AND created_at<=?",
        )
        .bind(host.as_bytes().as_slice())
        .bind(owner)
        .bind(now)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnrollmentError::Denied);
        }
        self.commit_revocation(transaction, host, now).await
    }

    /// HTTP authority is rechecked in the serialized intent write, including logout or
    /// role change racing a request. Cancellation follows authorization, before commit.
    pub(crate) async fn revoke_for_session(
        &self,
        session_hash: &str,
        host: Uuid,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        if now < 0 {
            return Err(EnrollmentError::Denied);
        }
        let mut transaction = self.0.begin().await?;
        let changed = sqlx::query(
            "UPDATE remote_hosts SET id=id \
             WHERE id=? AND created_at<=? AND EXISTS( \
             SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id \
             WHERE s.token_hash=? AND s.user_id=remote_hosts.owner_id \
             AND s.unlocked=1 AND s.expires>unixepoch() AND u.owner=1)",
        )
        .bind(host.as_bytes().as_slice())
        .bind(now)
        .bind(session_hash)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnrollmentError::Denied);
        }
        self.commit_revocation(transaction, host, now).await
    }

    /// Preserve the synchronous revocation contract for callers that require a
    /// durable host receipt. Only this request's watch is retained while offline.
    pub(crate) async fn commit_revocation(
        &self,
        transaction: sqlx::Transaction<'static, sqlx::Sqlite>,
        host: Uuid,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        if self
            .commit_revocation_intent(transaction, host, now)
            .await?
        {
            self.wait_login_cleanup(host).await?;
            self.1.tombstoned(host);
        }
        Ok(())
    }

    /// Commit and publish denial without waiting for an offline host. Removal
    /// admission ends here: the durable outbox owns delivery, not a task or slot.
    /// Returns true when a host receipt is required before retirement completes.
    pub(crate) async fn commit_revocation_intent(
        &self,
        mut transaction: sqlx::Transaction<'static, sqlx::Sqlite>,
        host: Uuid,
        now: i64,
    ) -> Result<bool, EnrollmentError> {
        let owner: Option<String> =
            sqlx::query_scalar("SELECT owner_id FROM remote_hosts WHERE id=?")
                .bind(host.as_bytes().as_slice())
                .fetch_optional(&mut *transaction)
                .await?;
        // Only UUID principals can have daemon person logins. Legacy ledger
        // identities have no login to revoke and retain direct retirement.
        let person = owner
            .as_deref()
            .and_then(|owner| Uuid::parse_str(owner).ok());
        if let Some(person) = person {
            sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES(?,?) ON CONFLICT(host_id) DO NOTHING")
                .bind(host.as_bytes().as_slice()).bind(person.to_string())
                .execute(&mut *transaction).await?;
        } else {
            sqlx::query("UPDATE remote_hosts SET revoked_at=COALESCE(revoked_at,?) WHERE id=?")
                .bind(now)
                .bind(host.as_bytes().as_slice())
                .execute(&mut *transaction)
                .await?;
            sqlx::query("DELETE FROM remote_bootstrap_retirement_intents WHERE host_id=?")
                .bind(host.as_bytes().as_slice())
                .execute(&mut *transaction)
                .await?;
        }
        let store = self.clone();
        // Ownership is detached only through COMMIT/publication, never through
        // an offline host wait. Request cancellation releases its watch promptly.
        tokio::spawn(async move {
            let _fence = store.1.quiesce(host).await.map_err(|_| {
                EnrollmentError::Storage(sqlx::Error::Protocol(
                    "revocation fence unavailable".into(),
                ))
            })?;
            transaction.commit().await?;
            if person.is_none() {
                store.1.tombstoned(host);
            }
            store.2.publish();
            #[cfg(test)]
            store.1.after_commit().await;
            store.publish_revoked_authority().await;
            Ok::<_, EnrollmentError>(())
        })
        .await
        .map_err(|_| {
            EnrollmentError::Storage(sqlx::Error::Protocol("revocation finalizer failed".into()))
        })??;
        Ok(person.is_some())
    }

    /// Subscribe before reading so a concurrent durable receipt cannot be lost.
    /// No background waiter, polling timer or database connection is held idle.
    async fn wait_login_cleanup(&self, host: Uuid) -> Result<(), EnrollmentError> {
        let mut changed = self.2.subscribe();
        loop {
            let confirmed: bool =
                sqlx::query_scalar("SELECT confirmed FROM remote_login_cleanup WHERE host_id=?")
                    .bind(host.as_bytes().as_slice())
                    .fetch_one(&self.0)
                    .await?;
            if confirmed {
                return Ok(());
            }
            changed
                .changed()
                .await
                .map_err(|_| EnrollmentError::Denied)?;
        }
    }

    /// Notify plugin readers after the denial or final retirement commits.
    async fn publish_revoked_authority(&self) {
        let plugins = self
            .1
            .plugins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upgrade();
        if let Some(plugins) = plugins {
            plugins.authority_changed().await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    pub(crate) async fn enrolled() -> (EnrollmentStore, sqlx::SqlitePool, Uuid) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        enrolled_with_pool(pool).await
    }

    pub(crate) async fn enrolled_with_pool(
        pool: sqlx::SqlitePool,
    ) -> (EnrollmentStore, sqlx::SqlitePool, Uuid) {
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query("INSERT INTO users (id, name, owner, recovery_hash, username, display_name) VALUES ('owner', 'owner', 1, 'test', 'owner', 'Owner')").execute(&pool).await.unwrap();
        let host = Uuid::from_u128(42);
        sqlx::query("INSERT INTO remote_hosts (id, owner_id, mode, execution_uid, created_at) VALUES (?, 'owner', 'rootless', 1002, 100)")
            .bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
        let store = EnrollmentStore::new(pool.clone());
        let key_digest = openssl::sha::sha256(&[3u8; 32]);
        let token = store
            .issue("owner", host, Mode::Rootless, 100, &key_digest)
            .await
            .unwrap();
        store
            .redeem(
                token.secret(),
                host,
                Mode::Rootless,
                100,
                &certificate(1, 100),
            )
            .await
            .unwrap();
        (store, pool, host)
    }

    fn certificate(seed: u8, now: i64) -> CertificateRecord {
        CertificateRecord {
            fingerprint: [seed; 32],
            issuer_fingerprint: [9; 32],
            public_key: [3; 32],
            not_before: now,
            not_after: now + 604_800,
        }
    }

    #[tokio::test]
    async fn admission_uses_enrolled_uid_and_exact_public_identity_validity() {
        let (store, _, host) = enrolled().await;
        assert_eq!(
            store.admit(&[1; 32], 100).await.unwrap(),
            HostAuthority {
                host,
                mode: Mode::Rootless,
                execution_uid: 1002,
                not_after: 604_900,
            }
        );
        for time in [-1, 99, 604_900, i64::MAX] {
            assert!(matches!(
                store.admit(&[1; 32], time).await,
                Err(EnrollmentError::Denied)
            ));
        }
        assert!(matches!(
            store.admit(&[2; 32], 101).await,
            Err(EnrollmentError::Denied)
        ));
    }

    #[tokio::test]
    async fn renewal_preserves_overlap_and_refuses_changed_key_or_expired_predecessor() {
        let (store, pool, _) = enrolled().await;
        let mut changed = certificate(2, 200);
        changed.public_key = [4; 32];
        assert!(matches!(
            store.renew(&[1; 32], &changed, 200).await,
            Err(EnrollmentError::Denied)
        ));
        store
            .renew(&[1; 32], &certificate(2, 200), 200)
            .await
            .unwrap();
        assert!(store.admit(&[1; 32], 201).await.is_ok());
        assert!(store.admit(&[2; 32], 201).await.is_ok());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM remote_certificates")
                .fetch_one(&pool)
                .await
                .unwrap(),
            2
        );
        assert!(matches!(
            store
                .renew(&[1; 32], &certificate(3, 604_900), 604_900)
                .await,
            Err(EnrollmentError::Denied)
        ));
        assert!(matches!(
            store.renew(&[2; 32], &certificate(3, 201), 202).await,
            Err(EnrollmentError::Denied)
        ));
    }

    #[tokio::test]
    async fn revocation_is_owner_bound_and_denies_admission_and_renewal_after_commit() {
        let (store, _, host) = enrolled().await;
        assert!(matches!(
            store.revoke("stranger", host, 200).await,
            Err(EnrollmentError::Denied)
        ));
        assert!(store.admit(&[1; 32], 201).await.is_ok());
        store.revoke("owner", host, 200).await.unwrap();
        assert!(matches!(
            store.admit(&[1; 32], 201).await,
            Err(EnrollmentError::Denied)
        ));
        assert!(matches!(
            store.renew(&[1; 32], &certificate(2, 201), 201).await,
            Err(EnrollmentError::Denied)
        ));
        // Repeating removal retains the original tombstone instead of restoring authority.
        store.revoke("owner", host, 202).await.unwrap();
        assert!(matches!(
            store.admit(&[1; 32], 203).await,
            Err(EnrollmentError::Denied)
        ));
    }
}
