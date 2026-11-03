//! Removes visible host inventory and owned SSH pins while retaining certificate denial tombstones [16][168][198], #87.
use crate::{auth::Auth, enrollment::EnrollmentStore, remote_runtime::RemoteHosts};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

struct Pending {
    hash: String,
    user: String,
    host: Uuid,
    uninstall: bool,
    expires: i64,
    api_key_hash: Option<String>,
    audit_id: Option<i64>,
}

#[derive(Clone)]
struct ApiPending {
    code_hash: String,
    key_hash: String,
    user: String,
    host: Uuid,
    host_label: String,
    uninstall: bool,
    expires: i64,
    ceremony: Option<String>,
    audit_id: Option<i64>,
    state: &'static str,
    result: Option<Value>,
}

enum RemovalAuthority {
    Passkey(crate::auth::VerifiedPasskey),
}

impl RemovalAuthority {
    fn user(&self) -> &str {
        match self {
            Self::Passkey(proof) => proof.user(),
        }
    }
    fn credential(&self) -> &str {
        match self {
            Self::Passkey(proof) => proof.credential(),
        }
    }
    fn verified_at(&self) -> i64 {
        match self {
            Self::Passkey(proof) => proof.verified_at(),
        }
    }
    fn expires(&self) -> i64 {
        match self {
            Self::Passkey(proof) => proof.expires(),
        }
    }
}
#[derive(Clone)]
pub(crate) struct Removal {
    auth: Auth,
    pool: SqlitePool,
    store: EnrollmentStore,
    hosts: RemoteHosts,
    trust: PathBuf,
    pending: Arc<Mutex<HashMap<String, Pending>>>,
    api_pending: Arc<Mutex<HashMap<String, ApiPending>>>,
    admission: Arc<Semaphore>,
}
impl Removal {
    #[cfg(test)]
    pub(crate) fn hold_api_admission_for_test(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.admission.clone().try_acquire_many_owned(8)
    }

    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }
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
            api_pending: Arc::default(),
            admission: Arc::new(Semaphore::new(8)),
        }
    }
    pub(crate) async fn start(
        &self,
        token: &str,
        host: Uuid,
        uninstall: bool,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let session = self.auth.session(token, now).await?;
        let address: Option<String> = sqlx::query_scalar("SELECT COALESCE(b.address,lower(hex(h.id))) FROM remote_hosts h JOIN users u ON u.id=h.owner_id LEFT JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.id=? AND h.owner_id=? AND h.revoked_at IS NULL AND u.owner=1")
            .bind(host.as_bytes().as_slice()).bind(&session.user_id).fetch_optional(&self.pool).await?;
        let address = address.ok_or(crate::auth::Error::Denied)?;
        let mut pending = self.pending.lock().await;
        pending.retain(|_, request| request.expires > now);
        if pending.len() >= 1024 {
            return Err(crate::auth::Error::Denied);
        }
        let mut start = self.auth.login_start(&session.user_id, now).await?;
        let id = start["ceremony"]
            .as_str()
            .ok_or(crate::auth::Error::Denied)?
            .to_owned();
        start["action"] = json!({"id":infraternal_plugin_remote::REMOVE.id,"label":infraternal_plugin_remote::REMOVE.summary,"host_id":host,"host":address,"uninstall":uninstall});
        pending.insert(
            id,
            Pending {
                hash: crate::auth::hash(token),
                user: session.user_id,
                host,
                uninstall,
                expires: now.checked_add(300).ok_or(crate::auth::Error::Denied)?,
                api_key_hash: None,
                audit_id: None,
            },
        );
        Ok(start)
    }

    /// Start an API-key removal that can only be published after a fresh owner passkey tap.
    #[cfg(test)]
    pub(crate) async fn start_api(
        &self,
        token: &str,
        host: Uuid,
        uninstall: bool,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        self.start_api_audited(token, host, uninstall, now, None)
            .await
    }

    /// The action adapter supplies its already committed audit row for final publication.
    pub(crate) async fn start_api_audited(
        &self,
        token: &str,
        host: Uuid,
        uninstall: bool,
        now: i64,
        audit_id: Option<i64>,
    ) -> Result<Value, crate::auth::Error> {
        let user = self.auth.api_authorize(token, "hosts:write").await?;
        let key_hash = crate::auth::hash(token);
        let address: Option<String> = sqlx::query_scalar("SELECT COALESCE(b.address,lower(hex(h.id))) FROM remote_hosts h JOIN users u ON u.id=h.owner_id LEFT JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.id=? AND h.owner_id=? AND h.revoked_at IS NULL AND u.owner=1")
            .bind(host.as_bytes().as_slice()).bind(&user).fetch_optional(&self.pool).await?;
        let address = address.ok_or(crate::auth::Error::Denied)?;
        let host_label = address
            .rsplit_once('@')
            .map_or(address.as_str(), |(_, host)| host)
            .to_owned();
        let expires = now.checked_add(300).ok_or(crate::auth::Error::Denied)?;
        let request_id = Uuid::new_v4().to_string();
        let user_code = B64.encode(rand::random::<[u8; 12]>());
        let mut pending = self.api_pending.lock().await;
        pending.retain(|_, request| request.expires.saturating_add(600) > now);
        if pending.len() >= 1024 {
            return Err(crate::auth::Error::Denied);
        }
        pending.insert(
            request_id.clone(),
            ApiPending {
                code_hash: crate::auth::hash(&user_code),
                key_hash,
                user,
                host,
                host_label: host_label.clone(),
                uninstall,
                expires,
                ceremony: None,
                audit_id,
                state: "pending",
                result: None,
            },
        );
        Ok(json!({
            "request_id": request_id,
            "user_code": user_code,
            "expires_in": 300,
            "action": {
                "id": infraternal_plugin_remote::REMOVE.id,
                "label": format!("Remove {host_label}"),
                "host_id": host,
                "host": address,
                "uninstall": uninstall,
            }
        }))
    }

    /// Read a code-bound removal review from the existing device-approval page.
    pub(crate) async fn inspect_api_approval(
        &self,
        session_token: &str,
        code: &str,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let session = self.auth.session(session_token, now).await?;
        let is_owner: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)")
                .bind(&session.user_id)
                .fetch_one(&self.pool)
                .await?;
        if !is_owner {
            return Err(crate::auth::Error::Denied);
        }
        let code_hash = crate::auth::hash(code);
        let (request_id, snapshot) = {
            let pending = self.api_pending.lock().await;
            let (request_id, request) = pending
                .iter()
                .find(|(_, request)| request.code_hash == code_hash)
                .ok_or(crate::auth::Error::Denied)?;
            if request.state != "pending"
                || request.expires <= now
                || request.user != session.user_id
            {
                return Err(crate::auth::Error::Denied);
            }
            (request_id.clone(), request.clone())
        };
        // Every inspection gets a challenge that the approval handler records against this
        // exact one-time request. A general fresh session cannot approve the action.
        let start = self.auth.login_start(&session.user_id, now).await?;
        let ceremony = start["ceremony"]
            .as_str()
            .ok_or(crate::auth::Error::Denied)?
            .to_owned();
        let options = start
            .get("options")
            .cloned()
            .ok_or(crate::auth::Error::Denied)?;
        let mut pending = self.api_pending.lock().await;
        let request = pending
            .get_mut(&request_id)
            .filter(|request| {
                request.code_hash == code_hash
                    && request.state == "pending"
                    && request.expires > now
                    && request.user == session.user_id
            })
            .ok_or(crate::auth::Error::Denied)?;
        request.ceremony = Some(ceremony.clone());
        Ok(json!({
            "kind": "action",
            "request_id": request_id,
            "ceremony": ceremony,
            "options": options,
            "action": {
                "id": infraternal_plugin_remote::REMOVE.id,
                "label": format!("Remove {}", snapshot.host_label),
                "host": snapshot.host_label,
                "host_id": snapshot.host,
                "uninstall": snapshot.uninstall,
                "uninstall_effect": if snapshot.uninstall {
                    "The infraternal agent, its service, and its data will be removed from this host."
                } else {
                    "The host will lose server access; its infraternal agent will remain installed."
                },
            },
            "expires_in": snapshot.expires.saturating_sub(now),
        }))
    }

    /// A request-bound fresh browser passkey proof, never the API key, approves this action once.
    pub(crate) async fn approve_api(
        &self,
        session_token: &str,
        code: &str,
        ceremony: &str,
        proof: Value,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        if ceremony.is_empty() || ceremony.len() > 128 {
            return Err(crate::auth::Error::Invalid);
        }
        let session = self.auth.session(session_token, now).await?;
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| crate::auth::Error::Denied)?;
        let code_hash = crate::auth::hash(code);
        {
            let pending = self.api_pending.lock().await;
            let request = pending
                .values()
                .find(|request| request.code_hash == code_hash)
                .ok_or(crate::auth::Error::Denied)?;
            if request.state != "pending"
                || request.expires <= now
                || request.user != session.user_id
                || request.ceremony.as_deref() != Some(ceremony)
            {
                return Err(crate::auth::Error::Denied);
            }
        }
        let verified = self.auth.verify_passkey(ceremony, proof, now).await?;
        if verified.user() != session.user_id {
            return Err(crate::auth::Error::Denied);
        }
        let entry = {
            let mut pending = self.api_pending.lock().await;
            let request = pending
                .values_mut()
                .find(|request| request.code_hash == code_hash)
                .ok_or(crate::auth::Error::Denied)?;
            if request.state != "pending"
                || request.expires <= now
                || request.user != session.user_id
                || request.ceremony.as_deref() != Some(ceremony)
            {
                return Err(crate::auth::Error::Denied);
            }
            request.state = "executing";
            request.clone()
        };
        let service = self.clone();
        let pending = Pending {
            hash: crate::auth::hash(session_token),
            user: entry.user.clone(),
            host: entry.host,
            uninstall: entry.uninstall,
            expires: entry.expires,
            api_key_hash: Some(entry.key_hash.clone()),
            audit_id: entry.audit_id,
        };
        let authority = RemovalAuthority::Passkey(verified);
        let result = tokio::spawn(async move {
            let _permit = permit;
            service.publish(pending, authority, now).await
        })
        .await
        .unwrap_or(Err(crate::auth::Error::Denied));
        let state = if result.is_ok() { "complete" } else { "denied" };
        let result_value = result.as_ref().ok().cloned();
        {
            let mut pending = self.api_pending.lock().await;
            if let Some(request) = pending
                .values_mut()
                .find(|request| request.code_hash == code_hash)
            {
                request.state = state;
                request.result = result_value;
            }
        }
        if state == "denied" {
            self.finish_api_audit(entry.audit_id, "denied", now).await?;
        }
        result
    }

    /// Refusal is a durable D303 denial and never triggers a host mutation.
    pub(crate) async fn decline_api(
        &self,
        session_token: &str,
        code: &str,
        now: i64,
    ) -> Result<(), crate::auth::Error> {
        let session = self.auth.session(session_token, now).await?;
        let code_hash = crate::auth::hash(code);
        let audit_id = {
            let mut pending = self.api_pending.lock().await;
            let request = pending
                .values_mut()
                .find(|request| request.code_hash == code_hash)
                .ok_or(crate::auth::Error::Denied)?;
            if request.state != "pending"
                || request.expires <= now
                || request.user != session.user_id
            {
                return Err(crate::auth::Error::Denied);
            }
            request.state = "denied";
            request.audit_id
        };
        self.finish_api_audit(audit_id, "denied", now).await
    }

    /// Poll only with the same live, scoped API key that initiated removal.
    pub(crate) async fn api_status(
        &self,
        token: &str,
        request_id: &str,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
        let user = self.auth.api_authorize(token, "hosts:write").await?;
        let key_hash = crate::auth::hash(token);
        let (state, result, audit_id) = {
            let mut pending = self.api_pending.lock().await;
            let request = pending
                .get_mut(request_id)
                .ok_or(crate::auth::Error::Denied)?;
            if request.user != user || request.key_hash != key_hash {
                return Err(crate::auth::Error::Denied);
            }
            if request.state == "pending" && request.expires <= now {
                request.state = "expired";
            }
            (request.state, request.result.clone(), request.audit_id)
        };
        if state == "expired" {
            self.finish_api_audit(audit_id, "denied", now).await?;
        }
        Ok(match state {
            "complete" => json!({"state":"complete","result":result}),
            "denied" | "expired" => json!({"state":"denied"}),
            _ => json!({"state":"pending"}),
        })
    }

    async fn finish_api_audit(
        &self,
        audit_id: Option<i64>,
        state: &str,
        now: i64,
    ) -> Result<(), crate::auth::Error> {
        if let Some(id) = audit_id {
            sqlx::query(
                "UPDATE api_action_audit SET state=?,completed_at=? WHERE id=? AND state='pending'",
            )
            .bind(state)
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }
    pub(crate) async fn finish_host(
        &self,
        token: &str,
        host: Uuid,
        id: &str,
        proof: Value,
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
        self.finish(token, id, proof, now).await
    }
    pub(crate) async fn finish(
        &self,
        token: &str,
        id: &str,
        proof: Value,
        now: i64,
    ) -> Result<Value, crate::auth::Error> {
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
        let verified = self.auth.verify_passkey(id, proof, now).await?;
        let permit = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| crate::auth::Error::Denied)?;
        let service = self.clone();
        // Once verified, disconnecting HTTP must not abandon an accepted uninstall
        // halfway through revocation. No recurring worker or secret is retained.
        tokio::spawn(async move {
            let _permit = permit;
            service
                .publish(entry, RemovalAuthority::Passkey(verified), now)
                .await
        })
        .await
        .map_err(|_| crate::auth::Error::Denied)?
    }
    #[allow(clippy::too_many_lines)] // Keep authority recheck, revocation, audit and cleanup inside one transaction.
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
        if let Some(key_hash) = &entry.api_key_hash {
            let key_user = self
                .auth
                .api_authorize_key_hash_tx(&mut tx, key_hash, "hosts:write", Some(live))
                .await?;
            if key_user.as_deref() != Some(&entry.user) {
                tx.commit().await?;
                return Err(crate::auth::Error::Denied);
            }
        }
        let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN passkeys p ON p.user_id=u.id AND p.id=COALESCE(?,s.passkey_id) JOIN remote_hosts h ON h.owner_id=u.id WHERE s.token_hash=? AND s.user_id=? AND s.unlocked=1 AND s.expires>? AND u.owner=1 AND h.id=? AND h.revoked_at IS NULL)")
            .bind(authority.credential()).bind(&entry.hash).bind(&entry.user).bind(live).bind(entry.host.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
        if !allowed
            || authority.user() != entry.user
            || authority.verified_at() > live
            || authority.verified_at() <= live - 300
            || authority.expires() <= live
            || entry.expires <= live
        {
            return Err(crate::auth::Error::Denied);
        }
        // A coordinates row means infraternal setup installed this host; only
        // then does a known installation exist to remove by hand (#235).
        let bootstrap: Option<Option<String>> =
            sqlx::query_scalar("SELECT trust_lookup FROM remote_host_bootstrap WHERE host_id=?")
                .bind(entry.host.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await?;
        let installed_by_setup = bootstrap.is_some();
        let lookup = bootstrap.flatten();
        let (mode, name): (String, String) = sqlx::query_as("SELECT h.mode,COALESCE(b.address,lower(hex(h.id))) FROM remote_hosts h LEFT JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.id=?")
            .bind(entry.host.as_bytes().as_slice())
            .fetch_one(&mut *tx)
            .await?;
        // Record the authorized request before the node effect; the same writer
        // transaction publishes its outcome together with the denial tombstone.
        sqlx::query("INSERT INTO remote_host_removals(host_id,owner_id,requested_at,uninstall,host_cleanup) VALUES(?,?,?,?,'pending')")
            .bind(entry.host.as_bytes().as_slice()).bind(&entry.user).bind(live).bind(entry.uninstall).execute(&mut *tx).await?;
        let (cleanup, left) = if entry.uninstall {
            request_uninstall(&self.hosts, entry.host).await
        } else {
            ("retained", Vec::new())
        };
        sqlx::query(
            "UPDATE remote_host_removals SET host_cleanup=?,completed_at=? WHERE host_id=?",
        )
        .bind(cleanup)
        .bind(live)
        .bind(entry.host.as_bytes().as_slice())
        .execute(&mut *tx)
        .await?;
        if let Some(audit_id) = entry.audit_id {
            sqlx::query("UPDATE api_action_audit SET state='complete',completed_at=?,result='removed' WHERE id=? AND state='pending'")
                .bind(live)
                .bind(audit_id)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("DELETE FROM remote_host_bootstrap WHERE host_id=?")
            .bind(entry.host.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
        #[cfg(feature = "ssh")]
        if let Some(lookup) = lookup {
            let shared: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM remote_host_bootstrap WHERE trust_lookup=?)",
            )
            .bind(&lookup)
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
        sqlx::query("UPDATE remote_hosts SET revoked_at=? WHERE id=?")
            .bind(live)
            .bind(entry.host.as_bytes().as_slice())
            .execute(&mut *tx)
            .await?;
        self.store
            .commit_revocation(tx, entry.host)
            .await
            .map_err(|_| crate::auth::Error::Denied)?;
        let installation = installed_by_setup.then(|| entry.host.simple().to_string());
        let (message, manual) = outcome(
            cleanup,
            &mode,
            display_name(&name),
            &left,
            installation.as_deref(),
        );
        Ok(
            json!({"host_id":entry.host,"state":"removed","host_cleanup":cleanup,"message":message,"manual":manual}),
        )
    }
}
/// What removal tells the person, and the commands for a leftover install.
///
/// `installation` is the host id when infraternal setup installed the host:
/// only then are there commands, because only then is there an installation
/// whose ownership the host can check.
fn outcome(
    cleanup: &str,
    mode: &str,
    name: &str,
    left: &[&str],
    installation: Option<&str>,
) -> (String, Option<String>) {
    match cleanup {
        "requested" => {
            let mut message =
                format!("{name} was removed. Its infraternal agent is uninstalling itself.");
            // Kernel objects with our name that the host's installation did
            // not create stay; say which, so nobody removes them by hand (#235).
            for object in left {
                message.push(' ');
                message.push_str(&infraternal_plugin_remote::uninstall::left_line(object));
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
        // there; the record is gone, so nothing here can retry (#235).
        _ => {
            let commands = manual_uninstall(mode, installation.unwrap_or_default());
            let account = if mode == "rootful" {
                "as root"
            } else {
                "as the account it was added with"
            };
            (
                format!(
                    "{name} was removed here, but infraternal is still installed on it. Remove it there {account} with: {commands}"
                ),
                Some(commands),
            )
        }
    }
}
/// Ask a connected host's infraternal agent to uninstall itself (D273).
///
/// `requested` only when the host accepted the exact action; any refusal, error
/// or absent connection is `unreachable`, which the caller reports as a leftover
/// installation. The real-binary removal check calls this same path (#235).
///
/// With `requested` come the kernel objects the host will leave because its
/// installation did not create them. Only names this server knows are kept:
/// a host never puts its own text into the owner's message.
pub(crate) async fn request_uninstall(
    hosts: &RemoteHosts,
    host: Uuid,
) -> (&'static str, Vec<&'static str>) {
    const KNOWN: [&str; 3] = [
        "infraternal0",
        "infraternal_mesh",
        "the IFM_* iptables chains",
    ];
    let Some(actor) = hosts.actor(host).await else {
        return ("unreachable", Vec::new());
    };
    let Ok(input) = serde_json::to_vec(&json!({"host":host.simple().to_string(),"dry_run":false}))
    else {
        return ("unreachable", Vec::new());
    };
    let reply = actor
        .control_call(infraternal_plugin_remote::UNINSTALL.id, input)
        .await
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    match reply {
        Some(reply) if reply["state"] == "accepted" => {
            let left = reply["left"].as_array().map_or_else(Vec::new, |left| {
                KNOWN
                    .into_iter()
                    .filter(|known| left.iter().any(|name| name == known))
                    .collect()
            });
            ("requested", left)
        }
        _ => ("unreachable", Vec::new()),
    }
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
fn manual_uninstall(mode: &str, host: &str) -> String {
    if mode == "rootful" {
        format!("/usr/local/bin/infraternal --bootstrap-uninstall {host}")
    } else {
        format!("~/.local/bin/infraternal --bootstrap-uninstall {host}")
    }
}
#[cfg(test)]
#[path = "remote_removal_review_tests.rs"]
mod review_tests;
