//! Records host removal denial, retains pending cleanup details and forgets owned SSH pins [16][168][198], #87.
//!
//! A removal is a dry run, then the removal. In the browser both run inside the 15-minute
//! admin window that a sign-in tap opens (D333, D339): the dry run returns a single-use review
//! bound to the session, the host and the uninstall choice for `REVIEW_SECONDS`. With an API
//! key, the action route issues its own review token (D28, D333).
//! D369 Forget archives an unreachable retirement and cancels its pending cleanup without touching the machine.
//! Forget deletes the removal row; its details survive only in `mesh_audit.detail_json`.
use crate::{auth::Auth, enrollment::EnrollmentStore, remote_runtime::RemoteHosts};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

/// How long a browser dry run's review stays usable, as for a key's review token.
const REVIEW_SECONDS: i64 = 120;

/// How long a removal waits, after its commit, for a connected host's answer to
/// arrive through the outbox (#409). A connected host reconnects and answers
/// within about a second of the cut; the root and rootless end-to-end runs
/// measured whole uninstalls of 0.4–3.7 s. Past this the person gets the
/// pending answer, which stays true: the cleanup still completes.
const REMOVAL_ANSWER_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

struct Pending {
    hash: String,
    user: String,
    host: Uuid,
    uninstall: bool,
    expires: i64,
}

/// What authorizes one removal. Both are rechecked inside the publish transaction.
enum RemovalAuthority {
    /// D339: a browser session inside its admin window, with this session's live review.
    AdminWindow,
    /// D333: a `hosts:write` API key inside its scope, with no further tap. Its audit row is
    /// completed in the same transaction as the removal.
    ApiKey { key_hash: String, audit_id: i64 },
}
/// Shared host-removal authority, bounded reviews and session-bound renewal challenges.
#[derive(Clone)]
pub(crate) struct Removal {
    auth: Auth,
    pool: SqlitePool,
    store: EnrollmentStore,
    hosts: RemoteHosts,
    trust: PathBuf,
    pending: Arc<Mutex<HashMap<String, Pending>>>,
    /// Renewal ceremonies belong to one session and host, separate from removal reviews (#498).
    taps: Arc<Mutex<HashMap<String, Pending>>>,
    admission: Arc<Semaphore>,
}
impl Removal {
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }
    /// Share the server identity, enrollment and host-delivery state across removal requests.
    pub(crate) fn new(
        auth: Auth,
        pool: SqlitePool,
        store: EnrollmentStore,
        hosts: RemoteHosts,
        trust: PathBuf,
    ) -> Self {
        Self {
            auth,
            pool,
            store,
            hosts,
            trust,
            pending: Arc::default(),
            taps: Arc::default(),
            admission: Arc::new(Semaphore::new(8)),
        }
    }
    /// Ask this host's owner for a passkey to renew the browser admin window (#498).
    pub(crate) async fn reauth_start(
        &self,
        token: &str,
        host: Uuid,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let user = self.auth.bootstrap_owner(token, now).await?;
        if !self.auth.bootstrap_host(&user, host).await {
            return Err(crate::auth::Error::Denied);
        }
        let mut taps = self.taps.lock().await;
        taps.retain(|_, entry| entry.expires > now);
        if taps.len() >= 1024 {
            return Err(crate::auth::Error::Denied);
        }
        let mut start = self.auth.login_start(&user, now).await?;
        // Identity verification needs no account-key secret or PRF extension in mobile browsers.
        start["options"]["publicKey"]
            .as_object_mut()
            .ok_or(crate::auth::Error::Invalid)?
            .remove("extensions");
        let id = start["ceremony"]
            .as_str()
            .ok_or(crate::auth::Error::Invalid)?
            .to_owned();
        taps.insert(
            id,
            Pending {
                hash: crate::auth::hash(token),
                user,
                host,
                uninstall: true,
                expires: now
                    .checked_add(REVIEW_SECONDS)
                    .ok_or(crate::auth::Error::Denied)?,
            },
        );
        Ok(start)
    }

    /// Spend only the selected host's ceremony and renew the same live owner session.
    /// This grants ordinary admin authority, never a per-action tap or a new login.
    pub(crate) async fn reauth_finish(
        &self,
        token: &str,
        host: Uuid,
        ceremony: &str,
        proof: Value,
        now: i64,
    ) -> Result<(), crate::auth::Error> {
        let hash = crate::auth::hash(token);
        let entry = {
            let mut taps = self.taps.lock().await;
            let entry = taps.get(ceremony).ok_or(crate::auth::Error::Denied)?;
            if entry.hash != hash || entry.host != host {
                return Err(crate::auth::Error::Denied);
            }
            taps.remove(ceremony).ok_or(crate::auth::Error::Denied)?
        };
        let verified = self.auth.verify_passkey(ceremony, proof, now).await?;
        let live_now = verified.verified_at().max(now);
        if entry.expires <= live_now
            || verified.expires() <= live_now
            || verified.user() != entry.user
        {
            return Err(crate::auth::Error::Denied);
        }
        // Recheck registration, host and owner authority in the write. Clear any older
        // per-action grant: renewing `fresh` must never make that grant usable again.
        let changed = sqlx::query("UPDATE sessions SET fresh=MAX(?,unixepoch()),tap_action=NULL,tap_spent=1 WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>MAX(?,unixepoch()) AND ?>MAX(?,unixepoch()) AND EXISTS(SELECT 1 FROM users WHERE id=sessions.user_id AND owner=1) AND EXISTS(SELECT 1 FROM passkeys WHERE user_id=sessions.user_id AND id=?) AND EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=sessions.user_id AND revoked_at IS NULL)")
            .bind(live_now).bind(hash).bind(&entry.user).bind(live_now)
            .bind(entry.expires.min(verified.expires()))
            .bind(live_now)
            .bind(verified.credential()).bind(host.as_bytes().as_slice())
            .execute(&self.pool).await?.rows_affected();
        if changed != 1 {
            return Err(crate::auth::Error::Denied);
        }
        Ok(())
    }
    /// Dry run of a host removal: names the host (a device by its name) and hands back a single-use review.
    pub(crate) async fn start(
        &self,
        token: &str,
        host: Uuid,
        uninstall: bool,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        // D339: the dry run runs inside the admin window; the removal rechecks it.
        let session = self.auth.fresh_session(token, now).await?;
        let address: Option<String> = sqlx::query_scalar("SELECT COALESCE(b.address,CASE WHEN h.mode='device' THEN h.hostname END,lower(hex(h.id))) FROM remote_hosts h JOIN users u ON u.id=h.owner_id LEFT JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.id=? AND h.owner_id=? AND h.revoked_at IS NULL AND u.owner=1")
            .bind(host.as_bytes().as_slice()).bind(&session.user_id).fetch_optional(&self.pool).await?;
        let address = address.ok_or(crate::auth::Error::Denied)?;
        let mut pending = self.pending.lock().await;
        pending.retain(|_, request| request.expires > now);
        if pending.len() >= 1024 {
            return Err(crate::auth::Error::Denied);
        }
        // The review is a random capability, held only in memory: a restart means a new dry run.
        let review = crate::auth::random_capability();
        let start = json!({
            "review": review,
            "review_expires_in": REVIEW_SECONDS,
            "action": {"id":infraternal_plugin_remote::REMOVE.id,"label":infraternal_plugin_remote::REMOVE.summary,"host_id":host,"host":address,"uninstall":uninstall},
        });
        pending.insert(
            review,
            Pending {
                hash: crate::auth::hash(token),
                user: session.user_id,
                host,
                uninstall,
                expires: now
                    .checked_add(REVIEW_SECONDS)
                    .ok_or(crate::auth::Error::Denied)?,
            },
        );
        Ok(start)
    }
    /// D398: the access reports waiting in the owner's Inbox: what the host
    /// found in the access files of a person whose login was revoked while the
    /// host stayed, as it reported when it revoked them. Read-only. Only the
    /// server owner's session reads it; others are refused. A host removal
    /// never makes one. The text can include a pasted token from a shell
    /// startup file, so it goes to the owner's session and nowhere else, and
    /// is never logged. The admin window is not needed: revoked hosts cannot
    /// start the passkey renewal that window needs (#498), and this reads
    /// nothing a signed-in owner cannot already see in a terminal.
    pub(crate) async fn access_reports(
        &self,
        token: &str,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let session = self.auth.session(token, now).await?;
        if !session.owner {
            return Err(crate::auth::Error::Denied);
        }
        let waiting = crate::access_report::inbox(&self.pool, &session.user_id).await?;
        let mut shown = Vec::with_capacity(waiting.reports.len());
        for item in waiting.reports {
            // The words are built here, once, from the cleaned report (D360,
            // D364, D367): the browser only draws them. The raw report object
            // is not sent, so nothing in the page can reword it.
            let single = json!({"state": "reported", "outcome": item.report.state, "more": 0, "reports": [item.report]});
            let lines: Vec<String> = crate::access_report_text::report_body(&single)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect();
            shown.push(json!({
                "host_id": item.host,
                "host": display_name(&item.host_name),
                "person_id": item.person,
                "person_name": crate::access_report::person_name(&self.pool, item.person).await?,
                "recorded_at": item.recorded_at,
                "outcome": item.report.state,
                "headline": crate::access_report_text::headline(&single),
                "lines": lines,
            }));
        }
        Ok(json!({"reports": shown, "more": waiting.more}))
    }

    /// The owner dismisses one Inbox report. `false` when it is not theirs or
    /// is already dismissed.
    pub(crate) async fn dismiss_access_report(
        &self,
        token: &str,
        host: Uuid,
        person: Uuid,
        now: i64,
    ) -> Result<bool, crate::auth::Error> {
        let session = self.auth.session(token, now).await?;
        if !session.owner {
            return Err(crate::auth::Error::Denied);
        }
        Ok(crate::access_report::dismiss(&self.pool, &session.user_id, host, person, now).await?)
    }

    /// Remove the host a review from this session's dry run named. A review for another host
    /// is refused without spending it.
    pub(crate) async fn finish_host(
        &self,
        token: &str,
        host: Uuid,
        id: &str,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        if self
            .pending
            .lock()
            .await
            .get(id)
            .is_none_or(|entry| entry.host != host)
        {
            return Err(crate::auth::Error::Denied);
        }
        self.finish(token, id, now).await
    }
    /// Complete a reviewed removal for a browser session: look the review up by its token, then publish it under one permit.
    async fn finish(&self, token: &str, id: &str, now: i64) -> Result<Value, crate::auth::Error> {
        let hash = crate::auth::hash(token);
        let entry = {
            let mut pending = self.pending.lock().await;
            if pending.get(id).ok_or(crate::auth::Error::Denied)?.hash != hash {
                return Err(crate::auth::Error::Denied);
            }
            pending.remove(id).ok_or(crate::auth::Error::Denied)?
        };
        if entry.expires <= now {
            return Err(crate::auth::Error::Denied);
        }
        let permit = admit(&self.admission)?;
        let service = self.clone();
        // Once verified, disconnecting HTTP must not abandon an accepted uninstall
        // halfway through revocation. No recurring worker or secret is retained.
        tokio::spawn(async move {
            let _permit = permit;
            service
                .publish(entry, RemovalAuthority::AdminWindow, now)
                .await
        })
        .await
        .map_err(|_| crate::auth::Error::Denied)?
    }

    /// The dry run of a key-driven removal: what would be removed, with no change.
    /// The host must belong to the key's owner account, as for the removal itself.
    pub(crate) async fn review_with_key(
        &self,
        person: &str,
        host: Uuid,
    ) -> Result<Value, crate::auth::Error> {
        let address: Option<String> = sqlx::query_scalar("SELECT COALESCE(b.address,CASE WHEN h.mode='device' THEN h.hostname END,lower(hex(h.id))) FROM remote_hosts h JOIN users u ON u.id=h.owner_id LEFT JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.id=? AND h.owner_id=? AND h.revoked_at IS NULL AND u.owner=1")
            .bind(host.as_bytes().as_slice()).bind(person).fetch_optional(&self.pool).await?;
        let address = address.ok_or(crate::auth::Error::Denied)?;
        let name = display_name(&address);
        Ok(json!({
            "dry_run": true,
            "host_id": host,
            "host": name,
            "label": format!("Remove {name}"),
            "uninstall": true,
            "effect": "The host loses server access, and its infraternal agent, service and data are removed from it.",
        }))
    }

    /// D333: inside its `hosts:write` scope an API key removes a host with no further tap. The
    /// key, its owner and the host are rechecked in the publish transaction, which also
    /// completes the key's audit row. The agent is always uninstalled (D334: no retain).
    pub(crate) async fn remove_with_key(
        &self,
        key_hash: &str,
        person: &str,
        host: Uuid,
        audit_id: i64,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let permit = admit(&self.admission)?;
        let entry = Pending {
            hash: String::new(),
            user: person.to_owned(),
            host,
            uninstall: true,
            expires: now.checked_add(300).ok_or(crate::auth::Error::Denied)?,
        };
        let authority = RemovalAuthority::ApiKey {
            key_hash: key_hash.to_owned(),
            audit_id,
        };
        let service = self.clone();
        // As for the browser path: a dropped request must not abandon an accepted uninstall.
        tokio::spawn(async move {
            let _permit = permit;
            service.publish(entry, authority, now).await
        })
        .await
        .map_err(|_| crate::auth::Error::Denied)?
    }

    /// Forget a revoked host in the browser's existing admin window (D369, #591).
    /// No command is sent to the machine; its denial tombstone remains permanently.
    pub(crate) async fn forget_browser(
        &self,
        token: &str,
        host: Uuid,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let session = self.auth.fresh_session(token, now).await?;
        self.finish_forget(
            Pending {
                hash: crate::auth::hash(token),
                user: session.user_id,
                host,
                uninstall: true,
                expires: now
                    .checked_add(REVIEW_SECONDS)
                    .ok_or(crate::auth::Error::Denied)?,
            },
            RemovalAuthority::AdminWindow,
            now,
        )
        .await
    }

    /// Review an owner's pending removal without changing its audit or delivery state.
    pub(crate) async fn review_forget_with_key(
        &self,
        person: &str,
        host: Uuid,
    ) -> Result<Value, crate::auth::Error> {
        let mut tx = self.pool.begin().await?;
        let (name, _) = Self::forget_record(&mut tx, person, host).await?;
        let name = display_name(&name);
        Ok(
            json!({"dry_run":true,"host_id":host,"host":name,"label":format!("Forget {name}"),"effect":"Forgetting removes this host from the list and stops automatic cleanup. The audit record stays. If anything remains, sign in to the machine and uninstall the infraternal agent the way it was installed. For a manual install, stop and remove its service unit, then delete its agent files and identity key."}),
        )
    }

    /// Apply an API-reviewed Forget, rechecking the live hosts:write key in the writer transaction.
    pub(crate) async fn forget_with_key(
        &self,
        key_hash: &str,
        person: &str,
        host: Uuid,
        audit_id: i64,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        self.finish_forget(
            Pending {
                hash: String::new(),
                user: person.to_owned(),
                host,
                uninstall: true,
                expires: now
                    .checked_add(REVIEW_SECONDS)
                    .ok_or(crate::auth::Error::Denied)?,
            },
            RemovalAuthority::ApiKey {
                key_hash: key_hash.to_owned(),
                audit_id,
            },
            now,
        )
        .await
    }

    /// Snapshot cleanup and any removal details for a revoked host still listed for its owner.
    /// An unconfirmed cleanup already denies normal access. A valid certificate can only
    /// deliver cleanup, so it does not block Forget. Abandoned setups can lack a removal row.
    /// An ineligible selection is Invalid, distinct from a Denied session or key authority check.
    async fn forget_record(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        person: &str,
        host: Uuid,
    ) -> Result<(String, String), crate::auth::Error> {
        sqlx::query_as(
            "SELECT COALESCE(h.hostname,b.address,lower(hex(h.id))),
             json_object('owner_id',h.owner_id,'removal_owner_id',r.owner_id,
                         'cleanup_person_id',q.person_id,'cleanup_confirmed',q.confirmed,
                         'requested_at',r.requested_at,'uninstall',r.uninstall,
                         'host_cleanup',r.host_cleanup,'completed_at',r.completed_at,'retained',r.retained)
             FROM remote_hosts h JOIN users u ON u.id=h.owner_id
             JOIN remote_login_cleanup q ON q.host_id=h.id
             LEFT JOIN remote_host_removals r ON r.host_id=h.id
             LEFT JOIN remote_host_bootstrap b ON b.host_id=h.id
             WHERE h.id=? AND h.owner_id=? AND u.owner=1 AND h.revoked_at IS NULL AND q.confirmed=0
             AND EXISTS(SELECT 1 FROM remote_certificates c WHERE c.host_id=h.id)",
        )
            .bind(host.as_bytes().as_slice()).bind(person)
            .fetch_optional(&mut **tx).await?.ok_or(crate::auth::Error::Invalid)
    }

    /// Keep the shared bounded admission until commit publication, even if the caller disconnects.
    async fn finish_forget(
        &self,
        entry: Pending,
        authority: RemovalAuthority,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let permit = admit(&self.admission)?;
        let service = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            service.forget_publish(entry, authority, now).await
        })
        .await
        .map_err(|_| crate::auth::Error::Denied)?
    }

    /// Archive the removal and stop pending delivery atomically, retaining certificate denial history.
    /// Authority and expiry are checked after the writer lock, so a stale review cannot forget a live host.
    async fn forget_publish(
        &self,
        entry: Pending,
        authority: RemovalAuthority,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE remote_hosts SET revoked_at=revoked_at WHERE id=?")
            .bind(entry.host.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
        let live = now.max(crate::runtime::unix_seconds().map_err(|_| crate::auth::Error::Denied)?);
        if entry.expires <= live {
            return Err(crate::auth::Error::Denied);
        }
        match &authority {
            RemovalAuthority::AdminWindow => {
                if !infraternal_plugin_api::fresh_session_tx(
                    &mut tx,
                    &entry.hash,
                    &entry.user,
                    now,
                    infraternal_plugin_api::ADMIN_WINDOW_SECONDS,
                )
                .await?
                {
                    return Err(crate::auth::Error::FreshRequired);
                }
            }
            RemovalAuthority::ApiKey { key_hash, .. } => {
                let person = self
                    .auth
                    .api_authorize_key_hash_tx(&mut tx, key_hash, "hosts:write", None)
                    .await?;
                if person.as_deref() != Some(entry.user.as_str()) {
                    // Preserve the key clock and any key-expiry tombstone, as removal does.
                    tx.commit().await?;
                    return Err(crate::auth::Error::Denied);
                }
            }
        }
        let (name, detail) = Self::forget_record(&mut tx, &entry.user, entry.host).await?;
        sqlx::query("INSERT INTO mesh_audit(user_id,action,resource,revision,occurred_at,detail_json) VALUES(?,'remote.host.forget',?,0,?,?)")
            .bind(&entry.user).bind(entry.host.to_string()).bind(live).bind(detail).execute(&mut *tx).await?;
        sqlx::query("UPDATE remote_hosts SET revoked_at=MAX(created_at,?) WHERE id=?")
            .bind(live)
            .bind(entry.host.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
        // Retirement's trigger creates a cleanup obligation. Forget deliberately cancels it,
        // along with the uninstall outbox and unfinished-bootstrap intent, after recording history.
        for statement in [
            "DELETE FROM remote_host_removals WHERE host_id=?",
            "DELETE FROM remote_login_cleanup WHERE host_id=?",
            "DELETE FROM remote_host_bootstrap WHERE host_id=?",
            "DELETE FROM remote_bootstrap_retirement_intents WHERE host_id=?",
        ] {
            sqlx::query(statement)
                .bind(entry.host.as_bytes().as_slice())
                .execute(&mut *tx)
                .await?;
        }
        if let RemovalAuthority::ApiKey { key_hash, audit_id } = &authority {
            let updated = sqlx::query("UPDATE api_action_audit SET state='complete',completed_at=?,result='forgotten' WHERE id=? AND key_id=? AND person_id=? AND action_id='remote.host.forget' AND target_id=? AND state='pending'")
                .bind(live).bind(audit_id).bind(key_hash).bind(&entry.user).bind(entry.host.to_string()).execute(&mut *tx).await?;
            if updated.rows_affected() != 1 {
                return Err(crate::auth::Error::Denied);
            }
        }
        let _fence = self
            .store
            .1
            .quiesce(entry.host)
            .await
            .map_err(|_| crate::auth::Error::Denied)?;
        tx.commit().await?;
        self.store.1.tombstoned(entry.host);
        self.store.publish_revoked_authority().await;
        self.store.2.publish();
        Ok(
            json!({"host_id":entry.host,"state":"forgotten","message":format!("{} was forgotten here. The machine itself was not changed.",display_name(&name))}),
        )
    }

    /// Remove a `device` (#580) inside the writer transaction `publish` holds.
    ///
    /// The host row is revoked here. The retirement triggers then remove its mesh
    /// node and grants, and record a login-cleanup obligation that is born confirmed
    /// (migration 20261125055624), so no uninstall or receipt is ever awaited. The
    /// answer is `removed`, never `pending`.
    async fn retire_device(
        &self,
        mut tx: sqlx::Transaction<'static, sqlx::Sqlite>,
        entry: &Pending,
        audit_id: Option<i64>,
        live: i64,
    ) -> Result<Value, crate::auth::Error> {
        let name: String = sqlx::query_scalar(
            "SELECT COALESCE(h.hostname,lower(hex(h.id))) FROM remote_hosts h WHERE h.id=?",
        )
        .bind(entry.host.as_bytes().as_slice())
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("UPDATE remote_hosts SET revoked_at=MAX(created_at,?) WHERE id=? AND revoked_at IS NULL")
            .bind(live)
            .bind(entry.host.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
        if let Some(audit_id) = audit_id {
            let updated = sqlx::query("UPDATE api_action_audit SET state='complete',completed_at=?,result='removed' WHERE id=? AND state='pending'")
                .bind(live)
                .bind(audit_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            if updated != 1 {
                return Err(crate::auth::Error::Denied);
            }
        }
        self.store
            .commit_device_retirement(tx, entry.host)
            .await
            .map_err(|_| crate::auth::Error::Denied)?;
        Ok(json!({
            "host_id": entry.host,
            "state": "removed",
            "host_cleanup": "none",
            "message": format!("{} was removed. It no longer takes part in the mesh.", display_name(&name)),
            "manual": null,
            "left": [],
        }))
    }

    /// Persist verified denial and return pending instead of retaining admission
    /// until an offline host returns. Only its durable receipt completes retirement
    /// and removes bootstrap coordinates needed for manual uninstall.
    async fn publish(
        &self,
        entry: Pending,
        authority: RemovalAuthority,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let mut tx = self.pool.begin().await?;
        // Acquire SQLite's writer lock before authority checks and the bounded
        // node handoff: concurrent logout/revocation cannot invalidate them in between.
        sqlx::query("UPDATE remote_hosts SET revoked_at=revoked_at WHERE id=?")
            .bind(entry.host.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
        let live = now.max(crate::runtime::unix_seconds().map_err(|_| crate::auth::Error::Denied)?);
        let audit_id = match &authority {
            RemovalAuthority::AdminWindow => {
                // Owner, host and session are rechecked under the writer lock, and the admin
                // window by both clocks (`fresh_session_tx`), so a logout, role loss or the
                // window closing after the dry run refuses the removal.
                let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN remote_hosts h ON h.owner_id=u.id WHERE s.token_hash=? AND s.user_id=? AND s.unlocked=1 AND s.expires>? AND u.owner=1 AND h.id=? AND h.revoked_at IS NULL)")
                    .bind(&entry.hash).bind(&entry.user).bind(live).bind(entry.host.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
                if !allowed || entry.expires <= live {
                    return Err(crate::auth::Error::Denied);
                }
                // Same answer as every other closed window (#563): the page renews and retries.
                if !infraternal_plugin_api::fresh_session_tx(
                    &mut tx,
                    &entry.hash,
                    &entry.user,
                    now,
                    infraternal_plugin_api::ADMIN_WINDOW_SECONDS,
                )
                .await?
                {
                    return Err(crate::auth::Error::FreshRequired);
                }
                None
            }
            RemovalAuthority::ApiKey { key_hash, audit_id } => {
                // J90 judges the key with its own clock inside this writer transaction.
                let key_user = self
                    .auth
                    .api_authorize_key_hash_tx(&mut tx, key_hash, "hosts:write", None)
                    .await?;
                if key_user.as_deref() != Some(entry.user.as_str()) {
                    // Commit keeps the J90 tombstone and key clock; nothing else was written.
                    tx.commit().await?;
                    return Err(crate::auth::Error::Denied);
                }
                let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users u JOIN remote_hosts h ON h.owner_id=u.id WHERE u.id=? AND u.owner=1 AND h.id=? AND h.revoked_at IS NULL)")
                    .bind(&entry.user).bind(entry.host.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
                if !allowed || entry.expires <= live {
                    return Err(crate::auth::Error::Denied);
                }
                Some(*audit_id)
            }
        };
        // A device (a phone, #580) has no infraternal agent to uninstall and no
        // logins to revoke, so it is retired at once and there is nothing to wait for.
        let is_device: bool =
            sqlx::query_scalar("SELECT mode='device' FROM remote_hosts WHERE id=?")
                .bind(entry.host.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await?
                .unwrap_or(false);
        if is_device {
            return self.retire_device(tx, &entry, audit_id, live).await;
        }
        // SSH setup records coordinates. A device-approved install instead
        // records its origin on the host row and must have redeemed its join.
        let bootstrap: Option<Option<String>> =
            sqlx::query_scalar("SELECT trust_lookup FROM remote_host_bootstrap WHERE host_id=?")
                .bind(entry.host.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await?;
        let installed_by_setup = bootstrap.is_some();
        let lookup = bootstrap.flatten();
        let (mode, name, mac_recovery): (String, String, bool) = sqlx::query_as(
            "SELECT h.mode,COALESCE(b.address,CASE WHEN h.mode='device' THEN h.hostname END,lower(hex(h.id))),
             h.device_approved=1 AND h.mode='rootful'
                 AND (h.device_os IS NULL OR h.device_os='macOS')
                 AND EXISTS(SELECT 1 FROM remote_certificates c WHERE c.host_id=h.id)
             FROM remote_hosts h LEFT JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.id=?",
        )
        .bind(entry.host.as_bytes().as_slice())
        .fetch_one(&mut *tx)
        .await?;
        let host = entry.host.simple().to_string();
        let installation = if installed_by_setup {
            Some(Installation::Bootstrap(&host))
        } else {
            mac_recovery.then_some(Installation::Mac(&host))
        };
        // A host's id is the durable key for its one removal request. A repeat
        // observes that outbox entry under the writer lock, preserving the
        // original uninstall choice and avoiding another cleanup attempt.
        let existing_cleanup: Option<String> = sqlx::query_scalar(
            "SELECT r.host_cleanup FROM remote_host_removals r
             JOIN remote_login_cleanup q ON q.host_id=r.host_id AND q.person_id=r.owner_id
             WHERE r.host_id=? AND r.owner_id=? AND r.uninstall=1
               AND r.host_cleanup='pending' AND q.confirmed=0",
        )
        .bind(entry.host.as_bytes().as_slice())
        .bind(&entry.user)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(cleanup) = existing_cleanup {
            if let Some(audit_id) = audit_id {
                let updated = sqlx::query("UPDATE api_action_audit SET state='complete',completed_at=?,result=? WHERE id=? AND state='pending'")
                    .bind(live)
                    .bind(if Uuid::parse_str(&entry.user).is_ok() {
                        "revoked, cleanup pending"
                    } else {
                        "removed"
                    })
                    .bind(audit_id)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                if updated != 1 {
                    return Err(crate::auth::Error::Denied);
                }
            }
            tx.commit().await?;
            let (message, manual) = outcome(
                &cleanup,
                &mode,
                display_name(&name),
                &[],
                installation,
                true,
            );
            return Ok(json!({
                "host_id": entry.host,
                "state": "pending",
                "host_cleanup": cleanup,
                "message": message,
                "manual": manual,
                "left": [],
            }));
        }
        // Record the authorized request before the node effect; the same writer
        // transaction publishes its outcome together with the denial tombstone.
        sqlx::query("INSERT INTO remote_host_removals(host_id,owner_id,requested_at,uninstall,host_cleanup) VALUES(?,?,?,?,'pending')")
            .bind(entry.host.as_bytes().as_slice()).bind(&entry.user).bind(live).bind(entry.uninstall).execute(&mut *tx).await?;
        // One delivery path (#409): for a person's host the removal outbox asks
        // for the uninstall on the agent's cleanup-only reconnect, right after
        // its login revocation receipt, and records the answer with that
        // receipt. That reconnect follows this commit's link cut at once for an
        // online host, and the host's return for an offline one. So nothing
        // here waits on the network under the writer lock, and the uninstall
        // can no longer stop the agent before its receipt is in. Legacy owners
        // have no outbox and keep a single immediate attempt.
        let outbox = Uuid::parse_str(&entry.user).is_ok();
        // Read before the commit cuts the link: only a host connected right now
        // can answer within the short wait below.
        let connected = outbox && entry.uninstall && self.hosts.actor(entry.host).await.is_some();
        let (cleanup, left) = match (entry.uninstall, outbox) {
            (false, _) => ("retained", Vec::new()),
            (true, true) => ("pending", Vec::new()),
            (true, false) => request_uninstall(&self.hosts, entry.host).await,
        };
        sqlx::query(
            "UPDATE remote_host_removals SET host_cleanup=?,completed_at=? WHERE host_id=?",
        )
        .bind(cleanup)
        .bind(live)
        .bind(entry.host.as_bytes().as_slice())
        .execute(&mut *tx)
        .await?;
        if let Some(audit_id) = audit_id {
            sqlx::query("UPDATE api_action_audit SET state='complete',completed_at=?,result=? WHERE id=? AND state='pending'")
                .bind(live)
                .bind(if Uuid::parse_str(&entry.user).is_ok() { "revoked, cleanup pending" } else { "removed" })
                .bind(audit_id)
                .execute(&mut *tx)
                .await?;
        }
        // UUID owners need a durable person-cleanup receipt. Keep their install
        // coordinates until that receipt; legacy identities retire immediately.
        if Uuid::parse_str(&entry.user).is_err() {
            sqlx::query("DELETE FROM remote_host_bootstrap WHERE host_id=?")
                .bind(entry.host.as_bytes().as_slice())
                .execute(&mut *tx)
                .await?;
        }
        #[cfg(feature = "ssh")]
        if let Some(lookup) = lookup {
            // Retained pending removal coordinates are history, not another live user
            // of this pin. They must not prevent forgetting the last live pin.
            let shared: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_host_bootstrap b WHERE b.trust_lookup=? AND b.host_id<>? AND NOT EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=b.host_id))",
            )
            .bind(&lookup)
            .bind(entry.host.as_bytes().as_slice())
            .fetch_one(&mut *tx)
            .await?;
            if !shared {
                let root = self.trust.clone();
                tokio::task::spawn_blocking(move || {
                    infraternal_plugin_ssh::trust::forget_pin(&root, &lookup)
                })
                .await
                .map_err(|_| crate::auth::Error::Denied)?
                .map_err(|_| crate::auth::Error::Denied)?;
            }
        }
        #[cfg(not(feature = "ssh"))]
        let _ = (&self.trust, lookup);
        let pending = self
            .store
            .commit_revocation_intent(tx, entry.host, live)
            .await
            .map_err(|_| crate::auth::Error::Denied)?;
        // A connected host answers through the outbox within about a second of
        // the cut (#409). Wait for that, after the commit and so outside the
        // writer lock, so the result can say what happened and which kernel
        // objects stayed, as the live call did (#235). A host that is slower,
        // or offline, gets the pending answer: its cleanup still completes.
        if pending && connected {
            let answered = self
                .store
                .wait_removal_outcome(entry.host, REMOVAL_ANSWER_WAIT)
                .await
                .map_err(|_| crate::auth::Error::Denied)?;
            if let Some((cleanup, retained)) = answered {
                let left = known_left(retained.iter().map(String::as_str));
                let (message, manual) = outcome(
                    &cleanup,
                    &mode,
                    display_name(&name),
                    &left,
                    installation,
                    false,
                );
                return Ok(
                    json!({"host_id":entry.host,"state":"removed","host_cleanup":cleanup,"message":message,"manual":manual,"left":left}),
                );
            }
        }
        let (message, manual) = outcome(
            cleanup,
            &mode,
            display_name(&name),
            &left,
            installation,
            pending,
        );
        Ok(
            json!({"host_id":entry.host,"state":if pending { "pending" } else { "removed" },"host_cleanup":cleanup,"message":message,"manual":manual,"left":left}),
        )
    }
}
/// The local installation whose own executable recognizes the host receipt.
#[derive(Clone, Copy)]
enum Installation<'a> {
    /// SSH bootstrap uses the canonical launcher for its recorded mode.
    Bootstrap(&'a str),
    /// A Mac checks its launchd installation and can recover without its PATH link.
    Mac(&'a str),
}

/// Describe removal once, distinguishing pending cleanup from completed retirement.
/// Pending responses keep the ownership-checked manual command available.
/// A command ends the text verbatim so copying it cannot include sentence punctuation.
///
/// `installation` is the host id for a managed install with a local ownership check.
fn outcome(
    cleanup: &str,
    mode: &str,
    name: &str,
    left: &[&str],
    installation: Option<Installation<'_>>,
    pending: bool,
) -> (String, Option<String>) {
    // Hosts that enrolled before platform facts were retained can be offline
    // today. The command is explicitly for macOS and checks ownership locally.
    let account = match installation {
        Some(Installation::Mac(_)) => "on macOS as root",
        _ if mode == "rootful" => "as root",
        _ => "as the account it was added with",
    };
    if pending {
        let (detail, manual) = match cleanup {
            "requested" => {
                let mut detail = "its infraternal agent is uninstalling itself".to_owned();
                for object in left {
                    detail.push_str("; ");
                    detail.push_str(object);
                    detail.push_str(" stays because this installation did not create it");
                }
                (detail, None)
            }
            "retained" => ("its infraternal agent stays installed on it".to_owned(), None),
            // The outbox asks the host when it next connects (#409). Hand over
            // the manual command too, for a machine that never comes back.
            "pending" if installation.is_some() => {
                let commands = manual_uninstall(mode, installation);
                (format!("its infraternal agent uninstalls itself as soon as it connects. If it never does, remove it there {account} by running: {commands}"), Some(commands))
            }
            _ if installation.is_none() => (
                "infraternal setup didn't install its infraternal agent, so remove it there the way it was installed".to_owned(),
                None,
            ),
            _ => {
                let commands = manual_uninstall(mode, installation);
                (format!("infraternal is still installed on it, so remove it there {account} by running: {commands}"), Some(commands))
            }
        };
        let punctuation = if manual.is_some() { "" } else { "." };
        return (
            format!("{name}: revoked, cleanup pending; {detail}{punctuation}"),
            manual,
        );
    }
    match cleanup {
        "requested" => {
            let mut message =
                format!("{name} was removed. Its infraternal agent is uninstalling itself.");
            // Kernel objects with our name that the host's installation did
            // not create stay; say which, so nobody removes them by hand (#235).
            for object in left {
                message.push(' ');
                message.push_str(&infraternal_plugin_remote::left_line(object));
            }
            (message, None)
        }
        "retained" => (
            format!("{name} was removed here. Its infraternal agent stays installed on it."),
            None,
        ),
        _ if installation.is_none() => (
            format!(
                "{name} was removed here. infraternal setup didn't install its infraternal agent, so remove that agent on {name} the way it was installed."
            ),
            None,
        ),
        // Say plainly that the machine still runs it, and how to remove it
        // there while automatic cleanup remains unconfirmed (#235).
        _ => {
            let commands = manual_uninstall(mode, installation);
            (
                format!(
                    "{name} was removed here, but infraternal is still installed on it. Remove it there {account} by running: {commands}"
                ),
                Some(commands),
            )
        }
    }
}
/// How a host's infraternal agent answered one uninstall request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UninstallReply {
    /// It accepted, and its helper is removing the installation. These are the
    /// kernel objects it leaves because its installation did not create them.
    Accepted(Vec<&'static str>),
    /// It answered, but will not uninstall (for example an installation that
    /// infraternal setup did not make). Asking again gets the same answer.
    Refused,
    /// No answer: the link was gone, ended mid-call, or timed out. The
    /// request may be repeated on the next connection.
    Lost,
}

/// The kernel objects a host may report leaving in place because its
/// installation did not create them (#235). These are the only names a
/// removal message ever shows.
const KNOWN_LEFT: [&str; 3] = [
    "infraternal0",
    "infraternal_mesh",
    "the IFM_* iptables chains",
];

/// Keep only the names in `names` this server knows, in the server's own order
/// and spelling. A host never puts its own text into the owner's message: this
/// applies to its live reply and to the copy the removal outbox stores (#409).
pub(crate) fn known_left<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<&'static str> {
    let names: Vec<&str> = names.into_iter().collect();
    KNOWN_LEFT
        .into_iter()
        .filter(|known| names.contains(known))
        .collect()
}

/// Ask the infraternal agent behind `actor` to uninstall itself (D273, #235).
///
/// The removal outbox calls this on the host's cleanup-only reconnect, after
/// its login revocation receipt (#409); legacy owners and the real-binary
/// removal check reach it through [`request_uninstall`]. Only names this
/// server knows are kept from the reply: a host never puts its own text into
/// the owner's message.
pub(crate) async fn ask_uninstall(
    actor: &crate::embedded::EmbeddedAgent,
    host: Uuid,
) -> UninstallReply {
    let Ok(input) = serde_json::to_vec(&json!({"host":host.simple().to_string(),"dry_run":false}))
    else {
        return UninstallReply::Lost;
    };
    let reply = match actor
        .control_call(infraternal_plugin_remote::UNINSTALL.id, input)
        .await
    {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes).ok(),
        // A `Result` frame with `ok:false` is the host's own refusal.
        Err(crate::embedded::AgentError::Rejected) => None,
        Err(_) => return UninstallReply::Lost,
    };
    match reply {
        Some(reply) if reply["state"] == "accepted" => UninstallReply::Accepted(known_left(
            reply["left"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        )),
        _ => UninstallReply::Refused,
    }
}

/// Ask a connected host's infraternal agent to uninstall itself, once, now.
///
/// `requested` only when the host accepted the exact action; any refusal, error
/// or absent connection is `unreachable`, which the caller reports as a leftover
/// installation. Only removals with no outbox use it (legacy owners), plus the
/// real-binary removal check (#235).
pub(crate) async fn request_uninstall(
    hosts: &RemoteHosts,
    host: Uuid,
) -> (&'static str, Vec<&'static str>) {
    let Some(actor) = hosts.actor(host).await else {
        return ("unreachable", Vec::new());
    };
    match ask_uninstall(&actor, host).await {
        UninstallReply::Accepted(left) => ("requested", left),
        UninstallReply::Refused | UninstallReply::Lost => ("unreachable", Vec::new()),
    }
}
/// Take one of the removal service's bounded work permits, or say the service is busy.
///
/// Running out of permits is "try again in a moment" (`Throttled`, 429), never `Denied`: a 403 tells the browser the
/// person lacks authority and sends them to refresh the host list, which is the wrong advice for a busy server (#519).
fn admit(
    admission: &Arc<Semaphore>,
) -> Result<tokio::sync::OwnedSemaphorePermit, crate::auth::Error> {
    admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| crate::auth::Error::Throttled)
}

/// The machine part of a stored `account@machine` address, as people name the host.
fn display_name(address: &str) -> &str {
    address
        .rsplit_once('@')
        .map_or(address, |(_, machine)| machine)
}
/// The command that removes a leftover installation of `mode` on its machine.
///
/// It runs the installed binary's own uninstall, the same ownership-checked
/// cleanup the host runs when asked (#235): nothing is removed unless that
/// account's `.bootstrap-owner` names `host`; only that installation's shells
/// are retired; the mesh interface and packet filter go only when that
/// installation recorded them, in either packet-filter frontend; the server's
/// CA and a joined node's data stay. It stops at its first failure. No
/// names are deleted directly.
fn manual_uninstall(mode: &str, installation: Option<Installation<'_>>) -> String {
    match installation {
        Some(Installation::Mac(host)) => format!(
            "'/Library/Application Support/infraternal/bin/infraternal' --bootstrap-uninstall {host}"
        ),
        Some(Installation::Bootstrap(host)) if mode == "rootful" => {
            format!("/usr/local/bin/infraternal --bootstrap-uninstall {host}")
        }
        Some(Installation::Bootstrap(host)) => {
            format!("~/.local/bin/infraternal --bootstrap-uninstall {host}")
        }
        None => String::new(),
    }
}
/// The removal service reports a full admission as busy, not as refused (#519).
#[cfg(test)]
#[path = "remote_removal_admission_tests.rs"]
mod admission_tests;
#[cfg(test)]
#[path = "remote_removal_review_tests.rs"]
mod review_tests;
