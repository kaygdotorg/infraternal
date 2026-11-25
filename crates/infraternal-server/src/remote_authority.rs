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

/// The enrolled identity of a `device` (#580): a phone's certificate, admitted for
/// renewal, rotation and its place in the mesh, and for nothing else.
///
/// It has no `execution_uid` and no [`Mode`] field on purpose: code that needs a
/// uid or a place to run work cannot be handed one by mistake, because this type
/// is not a [`HostAuthority`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceAuthority {
    /// The device's host row.
    pub host: Uuid,
    /// Exact current certificate validity cap.
    pub not_after: i64,
}

impl EnrollmentStore {
    /// Admit an exact certificate fingerprint against a live `device` row (#580).
    ///
    /// The same live checks as [`Self::admit`] (certificate window, no
    /// revocation of the certificate or the host, no unconfirmed cleanup), with
    /// the opposite mode rule: only a `device` host whose certificate carries
    /// no uid and a P-256 key passes. A rootless or rootful certificate never
    /// does, so this cannot be used to reach a host's terminals either way.
    /// # Errors
    /// Refuses unknown/expired/revoked certificates, non-device hosts, invalid time and storage failure.
    pub async fn admit_device(
        &self,
        fingerprint: &[u8; 32],
        now: i64,
    ) -> Result<DeviceAuthority, EnrollmentError> {
        if now < 0 {
            return Err(EnrollmentError::Denied);
        }
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT h.id, c.not_after FROM remote_hosts h \
             JOIN remote_certificates c ON c.host_id=h.id \
             WHERE c.fingerprint=? AND c.not_before<=? AND c.not_after>? \
             AND c.revoked_at IS NULL AND h.revoked_at IS NULL \
             AND h.mode='device' AND h.execution_uid IS NULL \
             AND c.role='active' AND c.execution_uid IS NULL AND c.key_algorithm='p256' \
             AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0)",
        )
        .bind(fingerprint.as_slice())
        .bind(now)
        .bind(now)
        .fetch_optional(&self.0)
        .await?;
        let (host, not_after) = row.ok_or(EnrollmentError::Denied)?;
        Ok(DeviceAuthority {
            host: Uuid::from_slice(&host).map_err(|_| EnrollmentError::Denied)?,
            not_after,
        })
    }

    /// Admit an exact certificate fingerprint against live, persisted host authority.
    ///
    /// Only the host's ordinary identity passes: a certificate with
    /// `role='active'` issued for the host's current uid (J415 R1). A root
    /// upgrade's successor certificate never does; it has its own check,
    /// [`EnrollmentStore::admit_successor`], whose result this guard can't take.
    /// After an upgrade, a leftover rootless certificate (issued for the old
    /// uid) is refused here too, even before the handover revoked it.
    /// A `device` certificate is refused as well (#580): this is the guard of
    /// the link that runs terminals and logins, and a device never does. A
    /// device is admitted by [`EnrollmentStore::admit_device`] for what it may do.
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
             AND h.mode IN ('rootless','rootful') \
             AND c.role='active' AND c.execution_uid=h.execution_uid \
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
             AND c.revoked_at IS NULL AND q.confirmed=0 \
             AND h.mode IN ('rootless','rootful') \
             AND c.role='active' AND c.execution_uid=h.execution_uid",
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
    /// For a confirmation that carries no D356 report (the agent is gone), no
    /// report is kept (D398).
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn confirm_login_cleanup(
        &self,
        host: Uuid,
        person: Uuid,
    ) -> Result<(), EnrollmentError> {
        self.confirm_removal_cleanup(host, person, None, None).await
    }

    /// [`Self::confirm_login_cleanup`] with the host's D356 report of access
    /// files changed since the grant, in the same transaction as the
    /// #409 uninstall answer. Only tests call it
    /// directly; the outbox passes the report to `confirm_removal_cleanup`.
    #[cfg(test)]
    pub(crate) async fn confirm_login_cleanup_with_report(
        &self,
        host: Uuid,
        person: Uuid,
        report: Option<&crate::access_report::AccessReport>,
    ) -> Result<(), EnrollmentError> {
        self.confirm_removal_cleanup(host, person, None, report)
            .await
    }

    /// Wait up to `wait` for this host's removal to be confirmed by its
    /// cleanup receipt, then return how the host answered its uninstall
    /// (`host_cleanup`) and the kernel objects it said it leaves (#409).
    /// `None` when the receipt has not arrived in time; nothing changes then.
    ///
    /// Subscribes before reading, as [`Self::wait_login_cleanup`] does, so a
    /// receipt that commits in between is not missed.
    pub(crate) async fn wait_removal_outcome(
        &self,
        host: Uuid,
        wait: std::time::Duration,
    ) -> Result<Option<(String, Vec<String>)>, EnrollmentError> {
        let mut changed = self.2.subscribe();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let row: Option<(bool, String, Option<String>)> = sqlx::query_as("SELECT q.confirmed=1, r.host_cleanup, r.retained FROM remote_login_cleanup q JOIN remote_host_removals r ON r.host_id=q.host_id WHERE q.host_id=?")
                .bind(host.as_bytes().as_slice())
                .fetch_optional(&self.0)
                .await?;
            match row {
                Some((true, cleanup, retained)) => {
                    // A malformed column reads as "nothing reported", never as text.
                    let retained = retained
                        .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
                        .unwrap_or_default();
                    return Ok(Some((cleanup, retained)));
                }
                None => return Ok(None),
                Some(_) => {}
            }
            match tokio::time::timeout_at(deadline, changed.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => return Ok(None),
            }
        }
    }

    /// Whether `host` is being removed (a removal request exists for it, with
    /// or without an uninstall). Only a revocation that leaves the host in
    /// place asks its agent for an access report, and only it keeps one (D398).
    pub(crate) async fn removal_requested(&self, host: Uuid) -> Result<bool, EnrollmentError> {
        Ok(
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_host_removals WHERE host_id=?)")
                .bind(host.as_bytes().as_slice())
                .fetch_one(&self.0)
                .await?,
        )
    }

    /// Whether this host's removal asked for an uninstall that its infraternal
    /// agent has not accepted yet, so the removal outbox must still ask (#409).
    /// `unreachable` rows come from before the outbox delivered uninstalls,
    /// when the one live attempt failed; they are asked again too.
    pub(crate) async fn pending_uninstall(&self, host: Uuid) -> Result<bool, EnrollmentError> {
        Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_host_removals WHERE host_id=? AND uninstall=1 AND host_cleanup IN ('pending','unreachable'))")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&self.0)
            .await?)
    }

    /// [`Self::confirm_login_cleanup`], also recording how the host answered
    /// its removal's uninstall request (`host_cleanup`) and the server-known
    /// kernel objects it leaves (`retained`, #409), in the same
    /// transaction as the receipt. Once the receipt commits, the host is never
    /// admitted again, so an answer recorded later could be lost (#409).
    pub(crate) async fn confirm_removal_cleanup(
        &self,
        host: Uuid,
        person: Uuid,
        answer: Option<(&'static str, &[&'static str])>,
        report: Option<&crate::access_report::AccessReport>,
    ) -> Result<(), EnrollmentError> {
        let mut transaction = self.0.begin().await?;
        // Like the receipt below, only this person's unconfirmed cleanup may
        // record an answer; a foreign or duplicate one changes nothing.
        if let Some((host_cleanup, retained)) = answer {
            let retained = serde_json::to_string(retained).map_err(|_| EnrollmentError::Denied)?;
            sqlx::query("UPDATE remote_host_removals SET host_cleanup=?,retained=? WHERE host_id=? AND uninstall=1 AND host_cleanup IN ('pending','unreachable') AND EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=remote_host_removals.host_id AND q.person_id=? AND q.confirmed=0)")
                .bind(host_cleanup)
                .bind(retained)
                .bind(host.as_bytes().as_slice())
                .bind(person.to_string())
                .execute(&mut *transaction)
                .await?;
        }
        let pending: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_login_cleanup WHERE host_id=? AND person_id=? AND confirmed=0)")
            .bind(host.as_bytes().as_slice())
            .bind(person.to_string())
            .fetch_one(&mut *transaction)
            .await?;
        if pending {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
                });
            // D398: only revoking a person while the host stays keeps a
            // report (it becomes an Inbox item). A removal never does: it
            // deletes infraternal and its state and nothing else, so no scan
            // was asked for and nothing is stored. Neither does a
            // confirmation without a host reply (the Start fresh proof): no
            // agent answered, so there is nothing to say.
            // The outcome is decided here, by the server's rule, with the
            // host's mode from the server's own record (J334 P1-3).
            let removal: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_host_removals WHERE host_id=?)",
            )
            .bind(host.as_bytes().as_slice())
            .fetch_one(&mut *transaction)
            .await?;
            if let (false, Some(report)) = (removal, report) {
                let mode: Option<String> =
                    sqlx::query_scalar("SELECT mode FROM remote_hosts WHERE id=?")
                        .bind(host.as_bytes().as_slice())
                        .fetch_optional(&mut *transaction)
                        .await?;
                let rootless = mode.as_deref() != Some("rootful");
                let report = report.clone().decided(rootless);
                crate::access_report::store(&mut transaction, host, person, &report, now).await?;
            }
        }
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
    ///
    /// The renewal inherits the predecessor's role and uid in the same
    /// statement, and only an admissible (`active`, current uid) predecessor
    /// renews; a successor never renews (its promotion is shorter than a week).
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
            "INSERT INTO remote_certificates (fingerprint, host_id, issuer_fingerprint, public_key, key_algorithm, not_before, not_after, role, execution_uid) \
             SELECT ?, old.host_id, ?, ?, old.key_algorithm, ?, ?, old.role, old.execution_uid FROM remote_certificates old \
             JOIN remote_hosts h ON h.id=old.host_id \
             WHERE old.fingerprint=? AND old.public_key=? AND old.key_algorithm=? AND old.not_before<=? AND old.not_after>? \
             AND old.revoked_at IS NULL AND h.revoked_at IS NULL \
             AND old.role='active' AND old.execution_uid IS h.execution_uid \
             AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0)",
        ).bind(certificate.fingerprint.as_slice()).bind(certificate.issuer_fingerprint.as_slice())
            .bind(certificate.public_key.as_bytes()).bind(certificate.not_before).bind(certificate.not_after)
            .bind(predecessor.as_slice()).bind(certificate.public_key.as_bytes())
            .bind(certificate.public_key.algorithm().as_str()).bind(now).bind(now)
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
        // A removal ends any root upgrade of the host in the same write, so
        // its handover can never commit afterwards; a successor that had
        // joined is asked to uninstall itself (D376, J415 R5).
        sqlx::query(super::promotion::ABANDON_WHERE_HOST)
            .bind(now)
            .bind(host.as_bytes().as_slice())
            .execute(&mut *transaction)
            .await?;
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

    /// Commit a `device`'s removal and publish its denial (#580). A device has no
    /// agent link to cut and no cleanup receipt to wait for, so this only holds
    /// the revocation fence across the commit, as [`Self::commit_revocation_intent`]
    /// does, and then tombstones the host in memory and tells subscribers.
    pub(crate) async fn commit_device_retirement(
        &self,
        transaction: sqlx::Transaction<'static, sqlx::Sqlite>,
        host: Uuid,
    ) -> Result<(), EnrollmentError> {
        let store = self.clone();
        tokio::spawn(async move {
            let _fence = store.1.quiesce(host).await.map_err(|_| {
                EnrollmentError::Storage(sqlx::Error::Protocol(
                    "revocation fence unavailable".into(),
                ))
            })?;
            transaction.commit().await?;
            store.1.tombstoned(host);
            store.2.publish();
            store.publish_revoked_authority().await;
            Ok::<_, EnrollmentError>(())
        })
        .await
        .map_err(|_| {
            EnrollmentError::Storage(sqlx::Error::Protocol("revocation finalizer failed".into()))
        })?
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
    pub(crate) async fn publish_revoked_authority(&self) {
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
    //! Real SQLite enrollment, retirement, and pending-cleanup authority boundaries.
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

    /// [`enrolled`] on a caller-supplied pool, so a test can keep the pool's options.
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

    /// Turns the fixture's enrolled host into a `device` row (#580) so a test can give
    /// it P-256 certificates. The mode and uid are write-once for hosts, so the guard
    /// trigger is dropped for this fixture only, as the bootstrap tests do. The host's
    /// certificates and invitation are replaced: they were issued for a uid.
    pub(crate) async fn into_device(pool: &sqlx::SqlitePool, host: Uuid) {
        for statement in [
            "DROP TRIGGER remote_hosts_mode_write_once",
            "DELETE FROM remote_certificates WHERE host_id=?",
            "DELETE FROM remote_join_tokens WHERE host_id=?",
            "UPDATE remote_hosts SET mode='device', execution_uid=NULL WHERE id=?",
        ] {
            let mut query = sqlx::query(statement);
            if statement.contains('?') {
                query = query.bind(host.as_bytes().as_slice());
            }
            query.execute(pool).await.unwrap();
        }
    }

    /// The owner session the device fixtures approve with: its cookie hash.
    pub(crate) const DEVICE_SESSION: &str = "device-test-session";

    /// A migrated database holding the owner, a live unlocked owner session, and one
    /// `device` host row (#580): no uid, device-approved, named `phone`, never joined.
    pub(crate) async fn device_host() -> (EnrollmentStore, sqlx::SqlitePool, Uuid) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query("INSERT INTO users (id, name, owner, recovery_hash, username, display_name) VALUES ('owner', 'owner', 1, 'test', 'owner', 'Owner')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,'owner','test',?,0,1)")
            .bind(DEVICE_SESSION)
            .bind(i64::MAX / 2)
            .execute(&pool)
            .await
            .unwrap();
        let host = Uuid::from_u128(77);
        sqlx::query("INSERT INTO remote_hosts (id, owner_id, mode, execution_uid, created_at, device_approved, hostname) VALUES (?, 'owner', 'device', NULL, 100, 1, 'phone')")
            .bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
        (EnrollmentStore::new(pool.clone()), pool, host)
    }

    /// Publishes the receipt an approved join leaves for `host`, bound to `key_digest`,
    /// as the approval does at `now` (ten minutes of life). `mode` and `algorithm` are
    /// the caller's to get wrong, so tests can prove the pairing is refused.
    /// Returns the invitation secret, or the refusal.
    pub(crate) async fn device_receipt(
        store: &EnrollmentStore,
        pool: &sqlx::SqlitePool,
        host: Uuid,
        (mode, algorithm): (Mode, crate::identity_key::KeyAlgorithm),
        key_digest: &[u8; 32],
        now: i64,
    ) -> Result<String, EnrollmentError> {
        use base64::Engine;
        let secret =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let mut connection = pool.acquire().await.unwrap();
        store
            .issue_approved_receipt_in(
                crate::enrollment::ApprovedJoinReceipt {
                    owner: "owner",
                    host,
                    mode,
                    issued_at: now,
                    expires_at: now + 600,
                    now,
                    session_hash: DEVICE_SESSION,
                    invitation_secret: &secret,
                    expected_key_digest: key_digest,
                    key_algorithm: algorithm,
                },
                &mut connection,
            )
            .await
            .map(|_| secret)
    }

    /// A fixture certificate record with fingerprint `seed`, valid for seven days from `now`, over a fixed Ed25519 key.
    fn certificate(seed: u8, now: i64) -> CertificateRecord {
        CertificateRecord {
            fingerprint: [seed; 32],
            issuer_fingerprint: [9; 32],
            public_key: crate::identity_key::IdentityKey::Ed25519([3; 32]),
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

    /// Renewal keeps the predecessor's validity overlap, and refuses a changed key or an expired predecessor.
    #[tokio::test]
    async fn renewal_preserves_overlap_and_refuses_changed_key_or_expired_predecessor() {
        let (store, pool, _) = enrolled().await;
        let mut changed = certificate(2, 200);
        changed.public_key = crate::identity_key::IdentityKey::Ed25519([4; 32]);
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
    /// An undelivered denial refuses fresh join authority even before final retirement.
    #[tokio::test]
    async fn pending_cleanup_refuses_join_token_issuance() {
        let (store, pool, host) = enrolled().await;
        sqlx::query(
            "INSERT INTO remote_login_cleanup(host_id,person_id,confirmed) VALUES(?,'owner',0)",
        )
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
        let digest = openssl::sha::sha256(&[3u8; 32]);
        assert!(matches!(
            store
                .issue_authorized("owner", host, Mode::Rootless, 200, None, Some(&digest))
                .await,
            Err(EnrollmentError::Denied)
        ));
    }

    /// A pre-existing invitation cannot revive a pending-removed identity or be consumed.
    #[tokio::test]
    async fn pending_cleanup_refuses_join_token_redemption() {
        let (store, pool, host) = enrolled().await;
        let digest = openssl::sha::sha256(&[3u8; 32]);
        let token = store
            .issue("owner", host, Mode::Rootless, 200, &digest)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO remote_login_cleanup(host_id,person_id,confirmed) VALUES(?,'owner',0)",
        )
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            store
                .redeem(
                    token.secret(),
                    host,
                    Mode::Rootless,
                    200,
                    &certificate(2, 200)
                )
                .await,
            Err(EnrollmentError::Denied)
        ));
        let consumed: Option<i64> =
            sqlx::query_scalar("SELECT consumed_at FROM remote_join_tokens WHERE host_id=?")
                .bind(host.as_bytes().as_slice())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(consumed, None);
    }
}
