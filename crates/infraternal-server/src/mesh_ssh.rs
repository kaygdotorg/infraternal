//! Pushes mesh SSH access and certificates to nodes, and serves the owner's mesh SSH settings [D235, D319], #221.
//!
//! For each connected node, and again after every change or before a
//! certificate expires, the server:
//! 1. as the client side: certifies the key of the person who added the
//!    machine (owner L1 rule; the server's own host belongs to the owner),
//!    bound to the node's one mesh address, records the certificate's digest
//!    and installs it with the client files (`mesh-ssh-node.person_key`,
//!    `mesh-ssh-node.client`);
//! 2. as the target side: pushes a sequence-numbered [`Snapshot`] (the CA
//!    key, every currently valid person certificate, and every person's
//!    login grant for this host from [`crate::login_access`]) together with
//!    a host certificate for the node's in-memory host key
//!    (`mesh-ssh-node.host_key`, `mesh-ssh-node.configure`).
//!
//! Mesh SSH is off for every node until the owner turns it on (owner
//! question Q4 on #221). A node that is off still receives snapshots, so
//! turning it on needs no other change; its listener and client files stay
//! off. While the CA is locked nothing is issued and nothing is pushed: a
//! node keeps its last snapshot and its certificates expire on time.
//!
//! The owner's settings are socket actions in the same plugin: per-node on
//! and off, the login rules, and the "Names match people here" marker. The
//! CLI words for them wait for remote CLI actions (#303).

use crate::{
    ca::{CaKeySource, CertificateAuthority},
    login_access,
};
use infraternal_plugin_api::{
    ActionDef, Dependency, DryRun, Effect, Operation, Permission, Plugin, PluginDescriptor,
    ReplySender, RoleDef, SchemaRef, SocketHost, SubscriptionRegistry, Target,
    node_channel::NodeChannel,
};
use infraternal_plugin_ssh::{
    mesh_authority::{Issued, Snapshot},
    mesh_issue::{self, Certificate, HostRequest, PersonRequest, PublicKey},
};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

/// A certificate is renewed once less than this much of it remains.
const RENEW_BEFORE: u64 = 12 * 60 * 60;
/// How long to wait before retrying a push that could not complete: a node
/// that refused it (stale or busy) must get the current state soon.
const RETRY: Duration = Duration::from_secs(10);
/// The one refusal text: it never says which check failed.
const REFUSED: &str = "mesh SSH settings unavailable or unauthorized";

/// One owner action of the mesh SSH server plugin.
const fn action(id: &'static str, summary: &'static str, effect: Effect) -> ActionDef {
    ActionDef {
        id,
        summary,
        instructions: &[
            "Sign in as the owner.",
            "Changes reach every connected machine at once.",
        ],
        input: SchemaRef("Object"),
        output: SchemaRef("Object"),
        target: Target::Global,
        effect,
        permission: Permission::One("authenticated"),
        dry_run: DryRun::Unsupported,
        opens: None,
    }
}

/// Owner settings for mesh SSH and login access.
pub static DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "mesh-ssh",
    api: infraternal_plugin_api::API_VERSION,
    topics: &[],
    roles: &[RoleDef {
        id: "server",
        requires: &["server"],
        default_enabled: true,
    }],
    max_frame_len: 4096,
    unavailable: br#"{"error":"Mesh SSH is off"}"#,
    unavailable_event: br#"{"error":"Mesh SSH is off"}"#,
    actions: &[
        action(
            "mesh-ssh.set",
            "Turn mesh SSH on or off for a machine",
            Effect::Write,
        ),
        action(
            "mesh-ssh.login-rules",
            "List the login access rules",
            Effect::Read,
        ),
        action(
            "mesh-ssh.login-rule-add",
            "Add a login access rule",
            Effect::Write,
        ),
        action(
            "mesh-ssh.login-rule-remove",
            "Remove a login access rule",
            Effect::Write,
        ),
        action(
            "mesh-ssh.names-match",
            "Mark whether names match people on a machine",
            Effect::Write,
        ),
    ],
    events: &[],
    streams: &[],
    settings: None,
    defaults: &[],
    dependencies: &[Dependency::ExistingServer],
    can_enable_components: &[],
};

/// The server side of mesh SSH.
#[derive(Clone)]
pub(crate) struct MeshSshPlugin {
    pool: SqlitePool,
    ca: Option<Arc<dyn CaKeySource>>,
    store: infraternal_plugin_mesh::store::Store,
    changes: watch::Sender<u64>,
}

/// Server time in Unix seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs())
}

/// `server` for the server's own host, otherwise the host's ID: the same
/// identity the node channel and the mesh store use.
fn host_ref(host: &str) -> Result<Option<uuid::Uuid>, ()> {
    if host == "server" {
        Ok(None)
    } else {
        uuid::Uuid::parse_str(host).map(Some).map_err(|_| ())
    }
}

/// The stored form of a host for `login_rules` and `login_names_match`.
fn host_blob(host: Option<uuid::Uuid>) -> Vec<u8> {
    host.map_or_else(Vec::new, |host| host.as_bytes().to_vec())
}

impl MeshSshPlugin {
    /// The plugin over the server database, CA source and public origin.
    pub(crate) fn new(
        pool: SqlitePool,
        ca: Option<Arc<dyn CaKeySource>>,
        public_origin: Option<&str>,
    ) -> Self {
        let store = public_origin.map_or_else(
            || infraternal_plugin_mesh::store::Store::new(pool.clone()),
            |origin| {
                infraternal_plugin_mesh::store::Store::with_public_origin(pool.clone(), origin)
            },
        );
        Self {
            pool,
            ca,
            store,
            changes: watch::Sender::new(0),
        }
    }

    /// Every node pushes again: rules, people, certificates or hosts changed.
    fn changed(&self) {
        self.changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    /// Whether the owner turned mesh SSH on for this node.
    async fn enabled(&self, host: &str) -> bool {
        sqlx::query_scalar::<_, bool>("SELECT enabled = 1 FROM mesh_ssh_hosts WHERE host = ?")
            .bind(host)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten()
            .unwrap_or(false)
    }

    /// The person whose ordinary accounts act as them on this machine (owner
    /// L1): whoever added it, from enrollment provenance.
    async fn adder(&self, host: Option<uuid::Uuid>) -> Option<String> {
        match host {
            None => sqlx::query_scalar("SELECT id FROM users WHERE owner = 1")
                .fetch_optional(&self.pool)
                .await
                .ok()?,
            Some(host) => sqlx::query_scalar(
                "SELECT owner_id FROM remote_hosts WHERE id = ? AND revoked_at IS NULL",
            )
            .bind(host.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await
            .ok()?,
        }
    }

    /// The local account this machine was added with (J181 M3): the only
    /// account whose processes act as the person. Rootless hosts run as it;
    /// rootful hosts were added over SSH as the user in their bootstrap
    /// address. Root, a missing user part or the server's own host give
    /// `None`, which leaves the client side off.
    async fn added_with(&self, host: Option<uuid::Uuid>) -> Option<Value> {
        let host = host?;
        let (mode, uid, address): (String, i64, Option<String>) = sqlx::query_as(
            "SELECT h.mode, h.execution_uid, b.address FROM remote_hosts h \
             LEFT JOIN remote_host_bootstrap b ON b.host_id = h.id \
             WHERE h.id = ? AND h.revoked_at IS NULL",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .ok()??;
        if mode == "rootless" {
            return u32::try_from(uid).ok().map(|uid| json!({ "uid": uid }));
        }
        let user = address?.split_once('@')?.0.to_owned();
        (!user.is_empty() && user != "root").then(|| json!({ "name": user }))
    }

    /// The client's mesh peers by name, so plain `ssh <name>.<suffix>` works
    /// with no DNS: each peer's mesh machine name with its mesh IPv4 address
    /// from this node's applied configuration.
    async fn mesh_hosts(&self, config: &infraternal_plugin_mesh::dataplane::Config) -> Vec<Value> {
        let names: Vec<(i64, String)> = sqlx::query_as("SELECT id, name FROM mesh_nodes")
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();
        names
            .into_iter()
            .filter_map(|(id, name)| {
                let peer = config
                    .peers
                    .get(&infraternal_plugin_mesh::policy::model::NodeId(
                        u64::try_from(id).ok()?,
                    ))?;
                Some(json!({ "name": name, "address": peer.peer.addresses.ipv4 }))
            })
            .collect()
    }

    /// Every issued certificate, person and host, is recorded for audit
    /// (J181 M6), by digest and without key material.
    async fn audit(&self, kind: &str, certificate: &Certificate) -> Result<(), ()> {
        let digest =
            infraternal_plugin_ssh::mesh_certificate::digest(certificate).map_err(|_| ())?;
        let principals = serde_json::to_string(certificate.valid_principals()).map_err(|_| ())?;
        sqlx::query(
            "INSERT OR IGNORE INTO mesh_ssh_issued(digest, kind, principals, valid_before, issued_at) \
             VALUES (?, ?, ?, ?, unixepoch())",
        )
        .bind(digest.as_slice())
        .bind(kind)
        .bind(principals)
        .bind(i64::try_from(certificate.valid_before()).map_err(|_| ())?)
        .execute(&self.pool)
        .await
        .map_err(|_| ())?;
        Ok(())
    }

    /// The sequence, the certificates and the grants are read in one write
    /// transaction (J181 M1), so a higher sequence can never carry older
    /// state than a lower one. The sequence is stored and never below the
    /// clock, so it survives a server restart and a restored backup.
    async fn snapshot(
        &self,
        node: u64,
        ca: [u8; 32],
        host: Option<uuid::Uuid>,
    ) -> Result<Snapshot, ()> {
        let millis = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ())?
                .as_millis(),
        )
        .map_err(|_| ())?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| ())?;
        let sequence: i64 = sqlx::query_scalar(
            "UPDATE mesh_ssh_sequence SET value = max(value + 1, ?) WHERE singleton = 1 RETURNING value",
        )
        .bind(millis)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| ())?;
        let rows: Vec<(Vec<u8>, String, i64, String, i64)> = sqlx::query_as(
            "SELECT digest, person, source_node, source_address, valid_before \
             FROM mesh_ssh_certificates WHERE valid_before > ?",
        )
        .bind(i64::try_from(now()).map_err(|_| ())?)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ())?;
        let mut certificates = Vec::with_capacity(rows.len());
        for (digest, person, source_node, source_address, valid_before) in rows {
            certificates.push(Issued {
                digest: digest.try_into().map_err(|_| ())?,
                person,
                source_node: u64::try_from(source_node).map_err(|_| ())?,
                source_address: source_address.parse().map_err(|_| ())?,
                valid_before: u64::try_from(valid_before).map_err(|_| ())?,
            });
        }
        let people: Vec<String> = sqlx::query_scalar("SELECT id FROM users")
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| ())?;
        let mut grants = std::collections::BTreeMap::new();
        for person in people {
            let grant = login_access::grant_in(&mut tx, &person, host)
                .await
                .map_err(|_| ())?;
            if grant != infraternal_plugin_api::login_access::LoginGrant::default() {
                grants.insert(person, grant);
            }
        }
        tx.commit().await.map_err(|_| ())?;
        Ok(Snapshot {
            sequence: u64::try_from(sequence).map_err(|_| ())?,
            node,
            ca,
            certificates,
            grants,
        })
    }

    /// One push to one node. Returns when the next renewal is due.
    #[allow(clippy::too_many_lines)]
    async fn push(&self, channel: &dyn NodeChannel, issue: bool) -> Result<Duration, ()> {
        let host_text = channel.id().to_owned();
        let host = host_ref(&host_text)?;
        let enabled = self.enabled(&host_text).await;
        let node = self.store.node_for_host(&host_text).await.ok_or(())?;
        let config = self.store.config(node).await.map_err(|_| ())?;
        let ca =
            CertificateAuthority::from_source(self.ca.as_deref().ok_or(())?).map_err(|_| ())?;
        let ca_key = ca.ssh_public_key().map_err(|_| ())?;
        let now = now();
        let address = IpAddr::V4(config.addresses.ipv4);
        let mut next = Duration::from_secs(RENEW_BEFORE);

        // The client side: this machine's person certificate.
        let person = self.adder(host).await;
        let added_with = self.added_with(host).await;
        match (enabled, person, added_with) {
            (true, Some(person), Some(added_with)) => {
                let current: Option<i64> = sqlx::query_scalar(
                    "SELECT max(valid_before) FROM mesh_ssh_certificates WHERE person = ? AND host = ?",
                )
                .bind(&person)
                .bind(&host_text)
                .fetch_one(&self.pool)
                .await
                .map_err(|_| ())?;
                let remaining = current
                    .and_then(|end| u64::try_from(end).ok())
                    .map_or(0, |end| end.saturating_sub(now));
                // A fresh connection may be a restarted infraternal agent whose
                // in-memory key is gone, so it always gets a new certificate.
                if issue || remaining < RENEW_BEFORE {
                    let reply = channel
                        .call(
                            "mesh-ssh-node.person_key",
                            serde_json::to_vec(&json!({ "person": person })).map_err(|_| ())?,
                        )
                        .await
                        .map_err(|_| ())?;
                    let reply: Value = serde_json::from_slice(&reply).map_err(|_| ())?;
                    let subject = PublicKey::from_openssh(reply["public_key"].as_str().ok_or(())?)
                        .map_err(|_| ())?;
                    let certificate = ca
                        .issue_ssh_person(&PersonRequest {
                            subject: &subject,
                            person: &person,
                            source_address: address,
                            now,
                            lifetime: mesh_issue::MAX_LIFETIME,
                        })
                        .map_err(|_| ())?;
                    self.audit("person", &certificate).await?;
                    self.record(&certificate, &person, &host_text, node.0, address)
                        .await?;
                    let range = self.store.ipv4_range().await.ok_or(())?;
                    let suffix = config.exposure.as_ref().map_or_else(
                        || "internal".to_owned(),
                        |exposure| exposure.dns_suffix.clone(),
                    );
                    let input = json!({
                        "person": person,
                        "certificate": certificate.to_openssh().map_err(|_| ())?,
                        "ca": ca_key,
                        "suffix": suffix,
                        "network": range.network,
                        "prefix": range.prefix,
                        "added_with": added_with,
                        "hosts": self.mesh_hosts(&config).await,
                    });
                    channel
                        .call(
                            "mesh-ssh-node.client",
                            serde_json::to_vec(&input).map_err(|_| ())?,
                        )
                        .await
                        .map_err(|_| ())?;
                    // Every target must learn the new digest.
                    self.changed();
                } else {
                    next = Duration::from_secs(remaining - RENEW_BEFORE);
                }
            }
            _ => {
                let _ = channel
                    .call("mesh-ssh-node.client", br#"{"person":null}"#.to_vec())
                    .await;
            }
        }

        // The target side: snapshot and host certificate.
        let snapshot = self.snapshot(node.0, ca_key, host).await?;
        let host_certificate = if enabled {
            let reply = channel
                .call("mesh-ssh-node.host_key", b"{}".to_vec())
                .await
                .map_err(|_| ())?;
            let reply: Value = serde_json::from_slice(&reply).map_err(|_| ())?;
            let subject =
                PublicKey::from_openssh(reply["host_key"].as_str().ok_or(())?).map_err(|_| ())?;
            let mut principals = Vec::new();
            if let Some(exposure) = &config.exposure {
                principals.push(exposure.machine_name.clone());
                principals.push(format!("{}.{}", exposure.machine_name, exposure.dns_suffix));
            }
            principals.push(config.addresses.ipv4.to_string());
            principals.push(config.addresses.ipv6.to_string());
            let certificate = ca
                .issue_ssh_host(&HostRequest {
                    subject: &subject,
                    principals: &principals,
                    now,
                    lifetime: mesh_issue::MAX_LIFETIME,
                })
                .map_err(|_| ())?;
            self.audit("host", &certificate).await?;
            Some(certificate.to_openssh().map_err(|_| ())?)
        } else {
            None
        };
        let input = json!({
            "enabled": enabled,
            "snapshot": snapshot,
            "host_certificate": host_certificate,
        });
        channel
            .call(
                "mesh-ssh-node.configure",
                serde_json::to_vec(&input).map_err(|_| ())?,
            )
            .await
            .map_err(|_| ())?;
        Ok(next)
    }

    /// Record an issued person certificate; it replaces this person's earlier
    /// certificate for this machine, which is no longer current anywhere.
    async fn record(
        &self,
        certificate: &Certificate,
        person: &str,
        host: &str,
        node: u64,
        address: IpAddr,
    ) -> Result<(), ()> {
        let digest =
            infraternal_plugin_ssh::mesh_certificate::digest(certificate).map_err(|_| ())?;
        let mut tx = self.pool.begin().await.map_err(|_| ())?;
        sqlx::query("DELETE FROM mesh_ssh_certificates WHERE person = ? AND host = ?")
            .bind(person)
            .bind(host)
            .execute(&mut *tx)
            .await
            .map_err(|_| ())?;
        sqlx::query(
            "INSERT INTO mesh_ssh_certificates(digest, person, host, source_node, source_address, valid_before) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(digest.as_slice())
        .bind(person)
        .bind(host)
        .bind(i64::try_from(node).map_err(|_| ())?)
        .bind(address.to_string())
        .bind(i64::try_from(certificate.valid_before()).map_err(|_| ())?)
        .execute(&mut *tx)
        .await
        .map_err(|_| ())?;
        tx.commit().await.map_err(|_| ())
    }

    /// Push to one node until its connection ends.
    async fn serve_node(self, channel: Arc<dyn NodeChannel>) {
        let mut changes = self.changes.subscribe();
        let mut issue = true;
        loop {
            changes.borrow_and_update();
            let wait = match self.push(channel.as_ref(), issue).await {
                Ok(next) => {
                    issue = false;
                    next
                }
                Err(()) => RETRY,
            };
            tokio::select! {
                result = changes.changed() => if result.is_err() { return },
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// Owner-only actions, checked against the live session in one transaction.
    async fn call(
        &self,
        person: &str,
        token_hash: &str,
        action: &str,
        input: &[u8],
    ) -> Result<Value, &'static str> {
        let input: Value = serde_json::from_slice(input).map_err(|_| "invalid input")?;
        let mut tx = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| REFUSED)?;
        let owner: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.user_id = ? AND s.token_hash = ? AND s.unlocked = 1 AND s.expires > unixepoch() AND u.owner = 1)",
        )
        .bind(person)
        .bind(token_hash)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| REFUSED)?;
        if !owner {
            return Err(REFUSED);
        }
        let host_of = |value: &Value| -> Result<String, &'static str> {
            let host = value.as_str().ok_or("invalid input")?;
            host_ref(host).map_err(|()| "invalid input")?;
            Ok(host.to_owned())
        };
        let reply = match action {
            "mesh-ssh.set" => {
                let host = host_of(&input["host"])?;
                let enabled = input["enabled"].as_bool().ok_or("invalid input")?;
                sqlx::query("INSERT INTO mesh_ssh_hosts(host, enabled) VALUES (?, ?) ON CONFLICT(host) DO UPDATE SET enabled = excluded.enabled")
                    .bind(&host)
                    .bind(enabled)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| REFUSED)?;
                json!({ "host": host, "enabled": enabled })
            }
            "mesh-ssh.login-rules" => list_rules(&mut tx).await?,
            "mesh-ssh.login-rule-add" => {
                let subject = input["subject"].as_str();
                let kind = input["account_kind"].as_str().ok_or("invalid input")?;
                let account = input["account"].as_str();
                let host = match &input["host"] {
                    Value::Null => None,
                    value => Some(host_blob(
                        host_ref(&host_of(value)?).map_err(|()| "invalid input")?,
                    )),
                };
                let id: i64 = sqlx::query_scalar(
                    "INSERT INTO login_rules(subject, account_kind, account, host_id, created_at) VALUES (?, ?, ?, ?, unixepoch()) RETURNING id",
                )
                .bind(subject)
                .bind(kind)
                .bind(account)
                .bind(host)
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| "invalid input")?;
                json!({ "id": id })
            }
            "mesh-ssh.login-rule-remove" => {
                let id = input["id"].as_i64().ok_or("invalid input")?;
                let removed = sqlx::query("DELETE FROM login_rules WHERE id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| REFUSED)?
                    .rows_affected();
                json!({ "removed": removed == 1 })
            }
            "mesh-ssh.names-match" => {
                let host =
                    host_blob(host_ref(&host_of(&input["host"])?).map_err(|()| "invalid input")?);
                let enabled = input["enabled"].as_bool().ok_or("invalid input")?;
                let query = if enabled {
                    "INSERT OR IGNORE INTO login_names_match(host_id) VALUES (?)"
                } else {
                    "DELETE FROM login_names_match WHERE host_id = ?"
                };
                sqlx::query(query)
                    .bind(host)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| REFUSED)?;
                json!({ "enabled": enabled })
            }
            _ => return Err("unknown action"),
        };
        tx.commit().await.map_err(|_| REFUSED)?;
        if action != "mesh-ssh.login-rules" {
            self.changed();
        }
        Ok(reply)
    }
}

/// One stored rule: id, subject (none for everyone), kind, account, host.
type RuleRow = (i64, Option<String>, String, Option<String>, Option<Vec<u8>>);

/// Every login rule, in creation order.
async fn list_rules(tx: &mut sqlx::SqliteConnection) -> Result<Value, &'static str> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, subject, account_kind, account, host_id FROM login_rules ORDER BY id",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| REFUSED)?;
    let rules: Vec<Value> = rows
        .into_iter()
        .map(|(id, subject, kind, account, host)| {
            json!({
                "id": id,
                "subject": subject,
                "account_kind": kind,
                "account": account,
                "host": host.map(|host| uuid::Uuid::from_slice(&host)
                    .map_or_else(|_| "server".to_owned(), |id| id.to_string())),
            })
        })
        .collect();
    Ok(json!({ "rules": rules }))
}

impl Plugin for MeshSshPlugin {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn authority_changed(&self) -> Option<Operation<'_, ()>> {
        // People, hosts or sessions changed: grants and adders may differ.
        self.changed();
        None
    }
    fn node_connected(&self, channel: Arc<dyn NodeChannel>) -> Option<Operation<'static, ()>> {
        Some(Box::pin(self.clone().serve_node(channel)))
    }
    fn run(
        &self,
        host: Arc<dyn SocketHost>,
        mut requests: tokio::sync::mpsc::Receiver<bytes::Bytes>,
        replies: ReplySender,
        _registry: SubscriptionRegistry,
    ) -> Operation<'static, ()> {
        let service = self.clone();
        Box::pin(async move {
            while let Some(wire) = requests.recv().await {
                if host
                    .authorized(Box::pin(async {
                        let decoded =
                            infraternal_protocol::decode_muxed_frame(&wire).map_err(|_| ())?;
                        let infraternal_protocol::Frame::Call {
                            call_id,
                            action_id,
                            input_json,
                        } = decoded.frame
                        else {
                            return Err(());
                        };
                        let (ok, value) = match service
                            .call(host.user_id(), host.token_hash(), action_id, input_json)
                            .await
                        {
                            Ok(value) => (true, value),
                            Err(error) => (false, json!({ "error": error })),
                        };
                        let json = serde_json::to_vec(&value).map_err(|_| ())?;
                        let mut encoded = Vec::new();
                        infraternal_protocol::encode_muxed_frame_into(
                            0,
                            &infraternal_protocol::Frame::Result {
                                call_id,
                                ok,
                                json: &json,
                            },
                            &mut encoded,
                        )
                        .map_err(|_| ())?;
                        replies
                            .send(bytes::Bytes::from(encoded))
                            .await
                            .map_err(|_| ())
                    }))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "mesh_ssh_tests.rs"]
mod tests;
