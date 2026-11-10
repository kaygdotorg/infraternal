//! Adapts the existing enrollment ledger and transport registry to the removable admitted-host inventory [198], #194.
use crate::remote_runtime::RemoteHosts;
use infraternal_plugin_api::{
    Operation,
    host_name::{fallback_machine_name, machine_name},
};
use infraternal_plugin_remote::inventory::{Changes, Inventory};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Public host facts and an optional server-owned cleanup status, read together.
type AdmittedHostRow = (
    Vec<u8>,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

#[cfg(test)]
#[path = "remote_inventory_name_tests.rs"]
mod name_tests;

pub(crate) struct Source {
    pub pool: SqlitePool,
    pub hosts: RemoteHosts,
    #[cfg(feature = "mesh")]
    pub mesh: Option<infraternal_plugin_mesh::api::MeshService>,
}
#[derive(Default)]
struct FactChanges {
    hostname: bool,
    any: bool,
}
impl Source {
    /// Retain valid machine facts without allowing an older host to erase a name it cannot report.
    async fn save_facts(&self, id: Uuid, facts: &Value) -> FactChanges {
        let hostname = facts
            .get("hostname")
            .and_then(Value::as_str)
            .and_then(machine_name);
        let os = facts
            .get("os")
            .and_then(Value::as_str)
            .filter(|os| !os.is_empty() && os.len() <= 256);
        let Ok(mut tx) = self.pool.begin().await else {
            return FactChanges::default();
        };
        let mut changed = FactChanges::default();
        if let Some(hostname) = hostname
            && let Ok(result) = sqlx::query("UPDATE remote_hosts SET hostname=? WHERE id=? AND revoked_at IS NULL AND hostname IS NOT ?")
                .bind(&hostname)
                .bind(id.as_bytes().as_slice())
                .bind(&hostname)
                .execute(&mut *tx)
                .await
        {
            changed.hostname = result.rows_affected() > 0;
            changed.any |= changed.hostname;
        }
        if let Some(os) = os
            && let Ok(result) = sqlx::query("UPDATE remote_host_bootstrap SET os=? WHERE host_id=? AND os IS NOT ? AND EXISTS(SELECT 1 FROM remote_hosts WHERE id=host_id AND revoked_at IS NULL)")
                .bind(os)
                .bind(id.as_bytes().as_slice())
                .bind(os)
                .execute(&mut *tx)
                .await
        {
            changed.any |= result.rows_affected() > 0;
        }
        if tx.commit().await.is_err() {
            return FactChanges::default();
        }
        changed
    }

    /// Publish retained facts and reconcile only when a hostname changes; old hosts may omit the field.
    async fn apply_facts(&self, id: Uuid, facts: &Value) -> bool {
        let changed = self.save_facts(id, facts).await;
        if changed.any {
            self.hosts.5.publish();
        }
        #[cfg(feature = "mesh")]
        if changed.hostname
            && let Some(mesh) = &self.mesh
        {
            mesh.refresh_host_name(&id.to_string()).await;
        }
        changed.any
    }
}
impl Inventory for Source {
    fn observe(
        &self,
        channel: std::sync::Arc<dyn infraternal_plugin_api::node_channel::NodeChannel>,
    ) -> Operation<'_, ()> {
        Box::pin(async move {
            let Ok(id) = Uuid::parse_str(channel.id()) else {
                return;
            };
            let Some(actor) = self.hosts.actor(id).await else {
                return;
            };
            let mut inventory = actor.session_inventory();
            let mut available = false;
            loop {
                // Read the latest census under the same mutex as output admission:
                // a newer session cannot be removed by an older parked observation.
                let snapshot = {
                    let mut queries = self
                        .hosts
                        .6
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let snapshot = inventory.borrow_and_update().clone();
                    if let crate::embedded::SessionInventoryState::Available(ids) = &snapshot {
                        queries.reconcile(Some(id), ids);
                    }
                    snapshot
                };
                let current = matches!(
                    snapshot,
                    crate::embedded::SessionInventoryState::Available(_)
                );
                if current != available {
                    available = current;
                    self.hosts.5.publish();
                    if current {
                        let facts = channel
                            .call("host.facts.read", br#"{"includeLive":false}"#.to_vec())
                            .await
                            .ok()
                            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
                        if let Some(facts) = facts {
                            self.apply_facts(id, &facts).await;
                        }
                    }
                }
                if inventory.changed().await.is_err() {
                    break;
                }
            }
        })
    }
    /// Read live facts from the named host's own infraternal agent, never from the server's (#410).
    /// The host must pass the same authority predicate as `list`; a pending retirement is not a host to read.
    fn facts<'a>(
        &'a self,
        account: &'a str,
        host_id: &'a str,
    ) -> Operation<'a, Result<Value, &'static str>> {
        use infraternal_plugin_remote::inventory::{HOST_OFFLINE, HOST_UNAVAILABLE};
        Box::pin(async move {
            let id = Uuid::parse_str(host_id).map_err(|_| HOST_UNAVAILABLE)?;
            let admitted: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM remote_hosts h WHERE h.id=? AND h.owner_id=? AND h.revoked_at IS NULL AND EXISTS(SELECT 1 FROM remote_certificates c WHERE c.host_id=h.id) AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0)")
                .bind(id.as_bytes().as_slice()).bind(account).fetch_optional(&self.pool).await.map_err(|_| HOST_UNAVAILABLE)?;
            if admitted.is_none() {
                return Err(HOST_UNAVAILABLE);
            }
            if !self.hosts.online(id).await {
                return Err(HOST_OFFLINE);
            }
            let actor = self.hosts.actor(id).await.ok_or(HOST_OFFLINE)?;
            let reply = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                actor.call(
                    "host.facts.read".into(),
                    br#"{"includeLive":true}"#.to_vec(),
                ),
            )
            .await
            .map_err(|_| HOST_OFFLINE)?
            .map_err(|_| HOST_OFFLINE)?;
            // The connection observer retains identity facts. A live panel read
            // needs no writer transaction or inventory invalidation every second.
            serde_json::from_slice(&reply).map_err(|_| HOST_UNAVAILABLE)
        })
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<()> {
        self.hosts.5.subscribe()
    }
    /// List account hosts, retaining undelivered denials as offline status rows.
    fn list<'a>(
        &'a self,
        account: &'a str,
        after: Option<&'a str>,
    ) -> Operation<'a, Result<Value, ()>> {
        Box::pin(async move {
            let after = after
                .map(|id| {
                    Uuid::parse_str(id).map_err(|_| ()).and_then(|parsed| {
                        if parsed.to_string() == id {
                            Ok(parsed)
                        } else {
                            Err(())
                        }
                    })
                })
                .transpose()?;
            // Same authority predicate as websocket::terminal_actor. Unredeemed invitations are not admitted hosts.
            let rows: Vec<AdmittedHostRow> = sqlx::query_as(
                "SELECT h.id,COALESCE(b.address,''),b.os,h.hostname,h.mode,CASE WHEN EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0) THEN CASE WHEN EXISTS(SELECT 1 FROM remote_certificates c WHERE c.host_id=h.id AND c.revoked_at IS NULL AND c.not_after>unixepoch()) THEN 'pending' ELSE 'retired-unreachable' END END FROM remote_hosts h LEFT JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.owner_id=? AND h.revoked_at IS NULL AND EXISTS(SELECT 1 FROM remote_certificates c WHERE c.host_id=h.id) AND (? IS NULL OR h.id>?) ORDER BY h.id LIMIT 129")
                .bind(account).bind(after.map(|id| id.as_bytes().to_vec())).bind(after.map(|id| id.as_bytes().to_vec())).fetch_all(&self.pool).await.map_err(|_| ())?;
            let mut next = if rows.len() > 128 {
                Some(Uuid::from_slice(&rows[127].0).map_err(|_| ())?.to_string())
            } else {
                None
            };
            let mut hosts = Vec::with_capacity(rows.len().min(128));
            let mut bytes = 1024;
            for (id, address, os, hostname, mode, cleanup) in rows.into_iter().take(128) {
                let id = Uuid::from_slice(&id).map_err(|_| ())?;
                let user = address.split_once('@').map(|(user, _)| user);
                let name = machine_name(&address)
                    .or_else(|| hostname.as_deref().and_then(machine_name))
                    .unwrap_or_else(|| {
                        fallback_machine_name(os.as_deref(), &id.simple().to_string())
                    });
                // A pending host may still have a draining actor, never usable
                // authority. Expiry is derived from the ledger without a timer
                // or a false durable receipt; renewal already refuses this row.
                let online = cleanup.is_none() && self.hosts.online(id).await;
                let mut value = json!({"id":id,"name":name,"user":if mode == "rootful" {Some("root")} else {user},"os":os,"address":if address.is_empty(){None}else{Some(&address)},"online":online});
                if let Some(cleanup) = cleanup {
                    value["state"] = cleanup.into();
                }
                let size = serde_json::to_vec(&value).map_err(|_| ())?.len();
                if bytes + size > 60 * 1024 {
                    next = hosts
                        .last()
                        .and_then(|value: &Value| value["id"].as_str())
                        .map(str::to_owned);
                    break;
                }
                bytes += size;
                hosts.push(value);
            }
            Ok(json!({"hosts":hosts,"next":next}))
        })
    }
}
/// A pure data notification source is shared with durable admission and revocation writers.
pub(crate) type InventoryChanges = Changes;

/// Tests the admitted-host list and the per-host facts read against the real enrollment store.
#[cfg(test)]
mod tests {
    use super::*;
    /// The list is account-scoped, shows offline hosts, and drops revoked ones.
    #[tokio::test]
    async fn admitted_hosts_are_account_scoped_offline_and_revocation_filtered() {
        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,os) VALUES(?,'operator@worker','Debian GNU/Linux')").bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('other','Other',0,'fixture','other','Other')").execute(&pool).await.unwrap();
        let foreign = Uuid::from_u128(43);
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'other','rootless',1002,100)").bind(foreign.as_bytes().as_slice()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after) VALUES(?,?,?, ?,100,604900)").bind([2u8;32].as_slice()).bind(foreign.as_bytes().as_slice()).bind([3u8;32].as_slice()).bind([4u8;32].as_slice()).execute(&pool).await.unwrap();
        let source = Source {
            pool,
            hosts: RemoteHosts::default(),
            #[cfg(feature = "mesh")]
            mesh: None,
        };
        let owner = source.list("owner", None).await.unwrap();
        assert_eq!(owner["hosts"][0]["id"], host.to_string());
        assert_eq!(owner["hosts"][0]["name"], "worker");
        assert_eq!(owner["hosts"][0]["user"], "operator");
        assert_eq!(owner["hosts"][0]["os"], "Debian GNU/Linux");
        assert_eq!(owner["hosts"][0]["online"], false);
        assert_eq!(
            source.list("other", None).await.unwrap()["hosts"][0]["id"],
            foreign.to_string()
        );
        assert_eq!(owner["hosts"].as_array().unwrap().len(), 1);
        store.revoke("owner", host, 101).await.unwrap();
        assert_eq!(
            source.list("owner", None).await.unwrap()["hosts"],
            json!([])
        );
    }
    /// A window's details name its own host (#410): an unknown or other account's host is `host unavailable`,
    /// and an admitted host whose agent is not connected is `host offline`. Neither answers with the server's facts.
    #[tokio::test]
    async fn host_facts_refuse_foreign_unknown_and_offline_hosts() {
        let (_, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let source = Source {
            pool,
            hosts: RemoteHosts::default(),
            #[cfg(feature = "mesh")]
            mesh: None,
        };
        let own = host.to_string();
        assert_eq!(source.facts("owner", &own).await, Err("host offline"));
        assert_eq!(source.facts("other", &own).await, Err("host unavailable"));
        assert_eq!(
            source.facts("owner", &Uuid::from_u128(9).to_string()).await,
            Err("host unavailable")
        );
        assert_eq!(
            source.facts("owner", "not-a-uuid").await,
            Err("host unavailable")
        );
    }
    #[tokio::test]
    async fn unredeemed_invitations_are_not_admitted_and_cursors_are_canonical() {
        let (_, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        sqlx::query("DELETE FROM remote_certificates")
            .execute(&pool)
            .await
            .unwrap();
        let source = Source {
            pool,
            hosts: RemoteHosts::default(),
            #[cfg(feature = "mesh")]
            mesh: None,
        };
        assert_eq!(
            source.list("owner", None).await.unwrap()["hosts"],
            json!([])
        );
        assert!(source.list("owner", Some("not-a-host")).await.is_err());
        assert!(
            source
                .list("owner", Some(&host.simple().to_string()))
                .await
                .is_err()
        );
    }
}

#[cfg(test)]
mod pagination_tests {
    use super::*;
    #[tokio::test]
    async fn long_destinations_stay_bounded_and_all_pages_are_complete() {
        let (_, pool, _) = crate::enrollment::authority::tests::enrolled().await;
        let mut tx = pool.begin().await.unwrap();
        for serial in 100_u128..1100 {
            let id = Uuid::from_u128(serial);
            let mut fingerprint = vec![0_u8; 32];
            fingerprint[..16].copy_from_slice(id.as_bytes());
            sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootless',1002,100)").bind(id.as_bytes().as_slice()).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after) VALUES(?,?,zeroblob(32),zeroblob(32),100,604900)").bind(fingerprint).bind(id.as_bytes().as_slice()).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address) VALUES(?,?)")
                .bind(id.as_bytes().as_slice())
                .bind(format!("user@{}", "x".repeat(1000)))
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        let source = Source {
            pool,
            hosts: RemoteHosts::default(),
            #[cfg(feature = "mesh")]
            mesh: None,
        };
        let mut cursor = None;
        let mut found = std::collections::HashSet::new();
        loop {
            let page = source.list("owner", cursor.as_deref()).await.unwrap();
            assert!(serde_json::to_vec(&page).unwrap().len() < 64 * 1024);
            let hosts = page["hosts"].as_array().unwrap();
            assert!(hosts.len() <= 128);
            for host in hosts {
                assert!(found.insert(host["id"].as_str().unwrap().to_owned()));
            }
            cursor = page["next"].as_str().map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(found.len(), 1001);
    }
}

/// Pending denial remains visible without presenting a usable host. Certificate
/// expiry makes delivery permanently unreachable, including after store restart.
#[cfg(test)]
mod cleanup_status_tests {
    use super::*;

    /// Inventory distinguishes delivery waiting from exhausted certificate authority.
    #[tokio::test]
    async fn pending_cleanup_exposes_pending_then_retired_unreachable() {
        let (_, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        let now = crate::runtime::unix_seconds().unwrap();
        sqlx::query("UPDATE remote_certificates SET not_before=?,not_after=?")
            .bind(now + 3600 - 604_800)
            .bind(now + 3600)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES(?,?)")
            .bind(host.as_bytes().as_slice())
            .bind(Uuid::new_v4().to_string())
            .execute(&pool)
            .await
            .unwrap();
        let source = Source {
            pool: pool.clone(),
            hosts: RemoteHosts::default(),
            #[cfg(feature = "mesh")]
            mesh: None,
        };
        let inventory = source.list("owner", None).await.unwrap();
        assert_eq!(inventory["hosts"][0]["state"], "pending");
        assert_eq!(inventory["hosts"][0]["online"], false);
        sqlx::query("UPDATE remote_certificates SET not_before=?,not_after=?")
            .bind(now - 604_800)
            .bind(now)
            .execute(&pool)
            .await
            .unwrap();
        let inventory = source.list("owner", None).await.unwrap();
        assert_eq!(inventory["hosts"][0]["state"], "retired-unreachable");
        assert_eq!(inventory["hosts"][0]["online"], false);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT confirmed FROM remote_login_cleanup WHERE host_id=?"
            )
            .bind(host.as_bytes().as_slice())
            .fetch_one(&pool)
            .await
            .unwrap(),
            0
        );
    }
}
