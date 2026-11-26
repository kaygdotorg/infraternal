//! The relay list the coordinator pushes to every node, and the relay role it gives the server's node (D401 Q2–Q4).
//!
//! Both travel in one action, [`ACTION`] (`mesh.relays`), on the same authenticated
//! coordinator channel as the mesh configuration. It is a separate action rather than new
//! `Config` fields on purpose: `Config` and `Chunk` refuse unknown fields and are persisted in
//! `mesh-public.json`, which the previous release parses strictly, so a field there would
//! break rollback. A node that does not know the action refuses it, and the coordinator
//! stops sending it to that node until the node reconnects or its identity is read again.
//!
//! - Every node gets [`RelayList::relays`]: the relays it may use, in the coordinator's
//!   order. The node keeps the list in its own file ([`save`], [`load`]), so after a restart
//!   with the server down it still knows its relays (D285).
//! - Only the server's own node gets [`RelayList::serve`] (slice 1, D401 Q4): run the relay
//!   role with this relay leaf, on this port, refusing these revoked hosts. The relay is a
//!   role of the one binary, not part of the server process; the same message can name any
//!   node later. The node answers with the port it bound ([`RelaysReply::serving`]), and the
//!   coordinator then lists that relay for everyone else.
//!
//! Invariant: the relay list never needs a relayed path to arrive. It comes over the node's
//! coordinator link, which has its own TCP/TLS 443 fallback (D215, D291).

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// The coordinator-to-node action that carries a [`RelayList`].
pub const ACTION: &str = "mesh.relays";
/// Most relays one list names. D401 Q9 keeps a node on at most four relays at once.
pub const MAX_RELAYS: usize = 8;
/// Most addresses one relay lists.
pub const MAX_ADDRESSES: usize = 4;
/// Most revoked hosts one relay role is told about. A revoked host past this many still
/// reaches nobody, because its peers dropped its mesh key (D166), so its
/// pair tokens no longer match anything; it could only hold a connection slot until its leaf
/// expires (7 days at most).
///
/// 128 keeps the whole message (38 bytes per host, plus about 1.5 KiB of leaf and root) inside
/// one 8 KiB action frame (`MAX_ACTION_BYTES`).
pub const MAX_REVOKED: usize = 128;
/// Largest relay leaf (certificate and key PEM) or CA root PEM accepted.
const MAX_PEM: usize = 3 * 1024;
/// Most CA roots a relay role accepts host leaves from.
const MAX_ROOTS: usize = 2;

/// What `mesh.relays` carries to one node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayList {
    /// The relays this node may use, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<RelayEntry>,
    /// Run the relay role (only in the server node's list in slice 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve: Option<ServeRelay>,
}

/// One relay a node may connect to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayEntry {
    /// The DNS name in the relay's leaf. The node verifies it and binds pair tokens to it.
    pub name: String,
    /// The relay's UDP port.
    pub port: u16,
    /// Addresses to dial, in order. Empty means: resolve `name`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<IpAddr>,
}

/// The relay role a node runs (D401 Q3, Q4). It holds the relay leaf's private key, so it is
/// never written to disk by the node and its `Debug` output hides the key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServeRelay {
    /// The DNS name the leaf certifies; relay clients verify it.
    pub name: String,
    /// The UDP port to bind; when it is taken (or not allowed), the role binds another and
    /// reports it.
    pub port: u16,
    /// The relay leaf certificate PEM followed by its PKCS#8 key PEM.
    pub leaf: String,
    /// The deployment CA roots host leaves must chain to, as PEM.
    pub roots: Vec<String>,
    /// Hosts whose leaves the relay refuses although they still verify (revoked or removed
    /// before their 7-day leaf expired), as canonical UUID text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<String>,
}

impl std::fmt::Debug for ServeRelay {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServeRelay")
            .field("name", &self.name)
            .field("port", &self.port)
            .field("leaf", &"[REDACTED]")
            .field("roots", &self.roots.len())
            .field("revoked", &self.revoked.len())
            .finish()
    }
}

/// A node's answer to `mesh.relays`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaysReply {
    /// The node took the list.
    pub accepted: bool,
    /// The UDP port its relay role listens on, while it serves one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving: Option<u16>,
}

/// Whether `name` is a plain DNS host name: 1–253 bytes of lowercase letters, digits, dots
/// and hyphens, no empty label. Relay names end up in certificates and log lines.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

impl RelayList {
    /// Check every bound and name. A node refuses a list that fails, and keeps its old one.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.relays.len() <= MAX_RELAYS
            && self.relays.iter().all(|relay| {
                valid_name(&relay.name) && relay.port != 0 && relay.addresses.len() <= MAX_ADDRESSES
            })
            && self.serve.as_ref().is_none_or(|serve| {
                valid_name(&serve.name)
                    && serve.leaf.len() <= MAX_PEM
                    && !serve.roots.is_empty()
                    && serve.roots.len() <= MAX_ROOTS
                    && serve.roots.iter().all(|root| root.len() <= MAX_PEM)
                    && serve.revoked.len() <= MAX_REVOKED
                    && serve.revoked.iter().all(|host| valid_host(host))
            })
    }

    /// The same list without the relay role, which is what a node saves and shows.
    #[must_use]
    pub fn public(&self) -> Self {
        Self {
            relays: self.relays.clone(),
            serve: None,
        }
    }
}

/// Whether `host` is a canonical lowercase hyphenated UUID.
fn valid_host(host: &str) -> bool {
    host.len() == 36
        && host.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

/// The node's file for the last relay list it accepted, beside its other mesh state.
pub const FILE: &str = "mesh-relays.json";

/// Save the public part of `list` in `directory`, atomically: a temporary file, fsync, rename.
/// # Errors
/// Storage failures; the previous file stays.
pub fn save(directory: &std::path::Path, list: &RelayList) -> std::io::Result<()> {
    use std::io::Write as _;
    let bytes = serde_json::to_vec(&list.public()).map_err(std::io::Error::other)?;
    let pending = directory.join(format!(".{FILE}.pending"));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&pending, directory.join(FILE))?;
        std::fs::File::open(directory)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&pending);
    }
    result
}

/// The relay list saved in `directory`, or an empty one when there is none or it is unreadable
/// (a node without a saved list simply has no relays until the coordinator sends one).
#[must_use]
pub fn load(directory: &std::path::Path) -> RelayList {
    std::fs::read(directory.join(FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<RelayList>(&bytes).ok())
        .filter(RelayList::valid)
        .map(|list| list.public())
        .unwrap_or_default()
}

/// What one coordinator worker last sent its node, so it sends `mesh.relays` only on a change.
#[cfg(feature = "server")]
#[derive(Default)]
pub(crate) struct Pushed {
    /// The list the node accepted last.
    sent: Option<RelayList>,
    /// The node refused the action (an older node): stop until the worker reads the node's
    /// identity again.
    unsupported: bool,
}

#[cfg(feature = "server")]
impl Pushed {
    /// Forget what was sent, after the node reconnected or changed identity.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Where the server's node gets its relay role from: the relay leaf identity the server keeps
/// (`server_leaf`'s relay rotation) and the port to try. Set once by the server.
#[cfg(feature = "server")]
#[derive(Clone)]
pub struct ServeSource {
    /// The current relay leaf (certificate PEM then key PEM), its DNS name and the CA roots,
    /// or `None` while none was issued yet (a CA locked since first start).
    pub identity: std::sync::Arc<dyn Fn() -> Option<ServeIdentity> + Send + Sync>,
    /// Wakes the server node's worker when the identity changes (a rotation).
    pub changes: tokio::sync::watch::Receiver<u64>,
    /// The UDP port the relay role tries first.
    pub port: u16,
}

/// One relay leaf as the server hands it to its node.
#[cfg(feature = "server")]
#[derive(Clone)]
pub struct ServeIdentity {
    pub name: String,
    pub leaf: String,
    pub roots: Vec<String>,
}

/// The serve source set once by the server; read by its own node's worker.
#[cfg(feature = "server")]
static SERVE_SOURCE: std::sync::OnceLock<ServeSource> = std::sync::OnceLock::new();

/// Tell the coordinator how its own node runs the relay role. Without it no node relays.
#[cfg(feature = "server")]
pub fn set_serve_source(source: ServeSource) {
    let _ = SERVE_SOURCE.set(source);
}

/// The source set by [`set_serve_source`], if any.
#[cfg(feature = "server")]
pub(crate) fn serve_source() -> Option<&'static ServeSource> {
    SERVE_SOURCE.get()
}

/// Send `channel`'s node the list it should have now, if it differs from what it has.
///
/// The server's node gets the relay role (with the revoked hosts read from the store's
/// removal tombstones) and no relays; when it answers with a bound port, that relay is
/// published to every other worker through `service`. Every other node gets the published
/// relays. A node that refuses the action is not asked again until [`Pushed::reset`]; the
/// server's own node is never written off.
#[cfg(feature = "server")]
pub(crate) async fn push(
    store: &crate::store::Store,
    service: &crate::api::MeshService,
    channel: &dyn infraternal_plugin_api::node_channel::NodeChannel,
    pushed: &mut Pushed,
) {
    if pushed.unsupported {
        return;
    }
    let list = if channel.is_server() {
        let Some(source) = serve_source() else {
            return;
        };
        let Some(identity) = (source.identity)() else {
            return;
        };
        let revoked = store.removed_hosts(MAX_REVOKED).await.unwrap_or_default();
        RelayList {
            relays: Vec::new(),
            serve: Some(ServeRelay {
                name: identity.name,
                port: source.port,
                leaf: identity.leaf,
                roots: identity.roots,
                revoked,
            }),
        }
    } else {
        RelayList {
            relays: service.server_relay().into_iter().collect(),
            serve: None,
        }
    };
    if pushed.sent.as_ref() == Some(&list) {
        return;
    }
    let Ok(input) = serde_json::to_vec(&list) else {
        return;
    };
    match channel.call(ACTION, input).await {
        Ok(reply) => {
            let Ok(reply) = serde_json::from_slice::<RelaysReply>(&reply) else {
                return;
            };
            if !reply.accepted {
                return;
            }
            if let Some(serve) = &list.serve {
                service.set_server_relay(reply.serving.map(|port| RelayEntry {
                    name: serve.name.clone(),
                    port,
                    addresses: Vec::new(),
                }));
            }
            pushed.sent = Some(list);
        }
        // Only a node that answered with a refusal does not take the list; a timeout or a
        // lost channel is tried again on the next wake-up. The server's own node runs this
        // same binary, so it is never written off.
        Err(error) if error == infraternal_plugin_api::node_channel::CALL_REFUSED => {
            pushed.unsupported = !channel.is_server();
        }
        Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    //! Bounds, names, redaction and the saved file.
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A valid relay role with a recognisable fake key.
    fn serve() -> ServeRelay {
        ServeRelay {
            name: "relay.example.org".into(),
            port: 443,
            leaf: "-----BEGIN PRIVATE KEY-----secret".into(),
            roots: vec!["root".into()],
            revoked: vec!["0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0".into()],
        }
    }

    /// Names, ports and every bound are checked before a node takes a list.
    #[test]
    fn names_ports_and_bounds_are_checked() {
        for good in ["relay.example.org", "a", "x-1.y"] {
            assert!(valid_name(good), "{good}");
        }
        for bad in [
            "",
            "Relay.example.org",
            "a..b",
            "-a.b",
            "a-.b",
            "a b",
            "a_b",
            "é",
        ] {
            assert!(!valid_name(bad), "{bad}");
        }
        let entry = |port| RelayEntry {
            name: "relay.example.org".into(),
            port,
            addresses: Vec::new(),
        };
        assert!(
            RelayList {
                relays: vec![entry(443)],
                serve: Some(serve())
            }
            .valid()
        );
        assert!(
            !RelayList {
                relays: vec![entry(0)],
                serve: None
            }
            .valid()
        );
        assert!(
            !RelayList {
                relays: vec![entry(443); MAX_RELAYS + 1],
                serve: None
            }
            .valid()
        );
        let mut revoked = serve();
        revoked.revoked = vec!["not-a-uuid".into()];
        assert!(
            !RelayList {
                relays: Vec::new(),
                serve: Some(revoked)
            }
            .valid()
        );
        let mut rootless = serve();
        rootless.roots.clear();
        assert!(
            !RelayList {
                relays: Vec::new(),
                serve: Some(rootless)
            }
            .valid()
        );
    }

    /// The role's key stays out of `Debug` and the saved file; the public list round-trips.
    #[test]
    fn the_relay_key_never_reaches_debug_output_or_the_saved_file() {
        let list = RelayList {
            relays: Vec::new(),
            serve: Some(serve()),
        };
        assert!(!format!("{list:?}").contains("secret"));
        let directory = std::env::temp_dir().join(format!("relay-list-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        save(&directory, &list).unwrap();
        let saved = std::fs::read_to_string(directory.join(FILE)).unwrap();
        assert!(!saved.contains("secret"), "{saved}");
        assert_eq!(load(&directory), RelayList::default());
        let listed = RelayList {
            relays: vec![RelayEntry {
                name: "relay.example.org".into(),
                port: 443,
                addresses: vec!["198.51.100.7".parse().unwrap()],
            }],
            serve: None,
        };
        save(&directory, &listed).unwrap();
        assert_eq!(load(&directory), listed);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A list or entry with an unknown field is refused, like every strict mesh shape.
    #[test]
    fn unknown_fields_are_refused() {
        assert!(serde_json::from_str::<RelayList>(r#"{"relays":[],"extra":1}"#).is_err());
        assert!(serde_json::from_str::<RelayEntry>(r#"{"name":"a","port":1,"via":"b"}"#).is_err());
    }
}

#[cfg(all(test, feature = "server"))]
mod push_tests {
    //! The coordinator side: the server's node gets the role, the others get its relay.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use infraternal_plugin_api::{PluginOperation, node_channel::NodeChannel};
    use std::sync::{Arc, Mutex};

    /// A node channel that records each `mesh.relays` body and answers with `reply`.
    struct Recorder {
        server: bool,
        reply: Result<&'static str, &'static str>,
        sent: Mutex<Vec<serde_json::Value>>,
        changes: tokio::sync::watch::Sender<()>,
    }

    impl Recorder {
        /// A recorder that is the server's own node or not, answering every call with `reply`.
        fn new(server: bool, reply: Result<&'static str, &'static str>) -> Self {
            Self {
                server,
                reply,
                sent: Mutex::new(Vec::new()),
                changes: tokio::sync::watch::Sender::new(()),
            }
        }
        /// Every body sent so far.
        fn sent(&self) -> Vec<serde_json::Value> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl NodeChannel for Recorder {
        fn id(&self) -> &'static str {
            "recorder"
        }
        fn observed_ip(&self) -> std::net::IpAddr {
            std::net::Ipv4Addr::LOCALHOST.into()
        }
        fn is_server(&self) -> bool {
            self.server
        }
        fn changes(&self) -> tokio::sync::watch::Receiver<()> {
            self.changes.subscribe()
        }
        fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>> {
            assert_eq!(action, ACTION);
            self.sent
                .lock()
                .unwrap()
                .push(serde_json::from_slice(&input).unwrap());
            let reply = self.reply.map(|reply| reply.as_bytes().to_vec());
            Box::pin(async move { reply })
        }
    }

    /// The server node gets the role with the revoked hosts, others get its relay, and refusals stop retries.
    #[tokio::test]
    async fn the_server_node_serves_and_every_other_node_lists_its_relay() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("../../infraternal-server/migrations")
            .run(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO mesh_dataplane_removed(host) VALUES(?)")
            .bind("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0")
            .execute(&pool)
            .await
            .unwrap();
        let service = crate::api::MeshService::new(pool);
        let store = service.dataplane();
        let (_changes, receiver) = tokio::sync::watch::channel(0);
        set_serve_source(ServeSource {
            identity: Arc::new(|| {
                Some(ServeIdentity {
                    name: "relay.example.org".into(),
                    leaf: "LEAF".into(),
                    roots: vec!["ROOT".into()],
                })
            }),
            changes: receiver,
            port: 3478,
        });

        let server = Recorder::new(true, Ok(r#"{"accepted":true,"serving":3478}"#));
        let mut pushed = Pushed::default();
        push(&store, &service, &server, &mut pushed).await;
        push(&store, &service, &server, &mut pushed).await;
        let sent = server.sent();
        assert_eq!(sent.len(), 1, "an unchanged list is not sent again");
        assert_eq!(sent[0]["serve"]["port"], 3478);
        assert_eq!(
            sent[0]["serve"]["revoked"],
            serde_json::json!(["0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"])
        );
        assert!(sent[0].get("relays").is_none());
        assert_eq!(
            service.server_relay(),
            Some(RelayEntry {
                name: "relay.example.org".into(),
                port: 3478,
                addresses: Vec::new(),
            })
        );

        let node = Recorder::new(false, Ok(r#"{"accepted":true}"#));
        let mut pushed = Pushed::default();
        push(&store, &service, &node, &mut pushed).await;
        assert_eq!(
            node.sent(),
            vec![serde_json::json!({"relays":[{"name":"relay.example.org","port":3478}]})]
        );

        // An older node refuses the action: it is not asked again until it reconnects.
        let older = Recorder::new(
            false,
            Err(infraternal_plugin_api::node_channel::CALL_REFUSED),
        );
        let mut pushed = Pushed::default();
        push(&store, &service, &older, &mut pushed).await;
        push(&store, &service, &older, &mut pushed).await;
        assert_eq!(older.sent().len(), 1);
        pushed.reset();
        push(&store, &service, &older, &mut pushed).await;
        assert_eq!(older.sent().len(), 2);
    }
}
