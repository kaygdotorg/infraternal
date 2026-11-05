//! Removes visible host inventory and owned SSH pins while retaining certificate denial tombstones [16][168][198], #87.
use crate::{auth::Auth, enrollment::EnrollmentStore, remote_runtime::RemoteHosts};
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
}
#[derive(Clone)]
pub(crate) struct Removal {
    auth: Auth,
    pool: SqlitePool,
    store: EnrollmentStore,
    hosts: RemoteHosts,
    trust: PathBuf,
    pending: Arc<Mutex<HashMap<String, Pending>>>,
    admission: Arc<Semaphore>,
}
impl Removal {
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
            },
        );
        Ok(start)
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
            service.publish(entry, verified, now).await
        })
        .await
        .map_err(|_| crate::auth::Error::Denied)?
    }
    /// Persist verified removal intent and wait for durable host refusal before
    /// reporting removal. Cancelling the request cannot erase the intent.
    async fn publish(
        &self,
        entry: Pending,
        verified: crate::auth::VerifiedPasskey,
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
        let allowed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN passkeys p ON p.user_id=u.id JOIN remote_hosts h ON h.owner_id=u.id WHERE s.token_hash=? AND s.user_id=? AND s.unlocked=1 AND s.expires>? AND u.owner=1 AND p.id=? AND h.id=? AND h.revoked_at IS NULL)")
            .bind(&entry.hash).bind(&entry.user).bind(live).bind(verified.credential()).bind(entry.host.as_bytes().as_slice()).fetch_one(&mut *tx).await?;
        if !allowed
            || verified.user() != entry.user
            || verified.verified_at() > live
            || verified.verified_at() <= live - 300
            || verified.expires() <= live
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
        self.store
            .commit_revocation(tx, entry.host, live)
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
