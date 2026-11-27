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
use std::sync::atomic::{AtomicU64, Ordering};

/// The coordinator-to-node action that carries a [`RelayList`].
pub const ACTION: &str = "mesh.relays";
/// Most relays one list names. D401 Q9 keeps a node on at most four relays at once.
pub const MAX_RELAYS: usize = 8;
/// Most addresses one relay lists.
pub const MAX_ADDRESSES: usize = 4;
/// Most recent revoked hosts considered for a relay list. A revoked host past this many still
/// reaches nobody, because its peers dropped its mesh key (D166); older entries also age out
/// after the seven-day leaf lifetime. The encoder trims the oldest entries again when the
/// certificates make the action exceed its frame budget.
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
            && serde_json::to_vec(self)
                .is_ok_and(|bytes| bytes.len() <= infraternal_plugin_api::MAX_ACTION_BYTES)
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
/// A saved relay list is an action-shaped record, so loading and saving share its frame bound.
const MAX_FILE_BYTES: u64 = infraternal_plugin_api::MAX_ACTION_BYTES as u64;
/// Unique pending names keep concurrent saves from truncating or following one another's files.
static NEXT_PENDING: AtomicU64 = AtomicU64::new(0);

/// Save the public part of `list` in `directory`, atomically: a temporary file, fsync, rename.
/// # Errors
/// Storage failures; the previous file stays.
pub fn save(directory: &std::path::Path, list: &RelayList) -> std::io::Result<()> {
    use std::io::Write as _;
    let public = list.public();
    let bytes = serde_json::to_vec(&public).map_err(std::io::Error::other)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let (pending, mut file) = create_pending(directory)?;
    let result = (|| {
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

/// Create an owned, private pending file without replacing another writer's file.
/// # Errors
/// Returns the first filesystem error other than a pending-name collision.
fn create_pending(
    directory: &std::path::Path,
) -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    for _ in 0..32 {
        let sequence = NEXT_PENDING.fetch_add(1, Ordering::Relaxed);
        let pending = directory.join(format!(".{FILE}.{}.{sequence}.pending", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&pending)
        {
            Ok(file) => {
                if let Err(error) = file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
                    drop(file);
                    let _ = std::fs::remove_file(&pending);
                    return Err(error);
                }
                return Ok((pending, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::ErrorKind::AlreadyExists.into())
}

/// The relay list saved in `directory`, or an empty one when there is none or it is unreadable
/// (a node without a saved list simply has no relays until the coordinator sends one).
#[must_use]
pub fn load(directory: &std::path::Path) -> RelayList {
    read_saved(directory.join(FILE).as_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<RelayList>(&bytes).ok())
        .filter(RelayList::valid)
        .map(|list| list.public())
        .unwrap_or_default()
}

/// Read one owned regular file without following links, and stop at the action-frame limit.
/// # Errors
/// Refuses links, special files, unowned or multiply-linked files, oversized input and I/O errors.
fn read_saved(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.nlink() != 1
        || metadata.len() > MAX_FILE_BYTES
    {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    // Older releases created this public cache with the process umask. Keep it readable across
    // upgrade, but tighten its mode as soon as we have opened the owned file without following links.
    if metadata.mode() & 0o7777 != 0o600 {
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| std::io::ErrorKind::InvalidData)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
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
    let mut list = if channel.is_server() {
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
    let Some(input) = action_input(&mut list) else {
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

/// Encode one relay list inside the action frame, trimming its oldest revocations as needed.
/// # Errors
/// Returns `None` if the remaining fields are invalid or cannot fit without dropping certificates.
/// Client-only production builds do not send relay-list actions; tests keep this encoder available
/// so the action-size bound remains covered without the server feature.
#[cfg(any(feature = "server", test))]
fn action_input(list: &mut RelayList) -> Option<Vec<u8>> {
    loop {
        let input = serde_json::to_vec(list).ok()?;
        if input.len() <= infraternal_plugin_api::MAX_ACTION_BYTES {
            return list.valid().then_some(input);
        }
        list.serve.as_mut()?.revoked.pop()?;
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

    /// Even individually bounded PEM fields cannot make an action larger than its frame.
    #[test]
    fn a_relay_list_must_fit_the_action_frame() {
        let oversized = RelayList {
            relays: Vec::new(),
            serve: Some(ServeRelay {
                name: "relay.example.org".into(),
                port: 443,
                leaf: "l".repeat(MAX_PEM),
                roots: vec!["r".repeat(MAX_PEM); MAX_ROOTS],
                revoked: Vec::new(),
            }),
        };
        assert!(!oversized.valid(), "a list over 8 KiB must be refused");
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

    /// The relay list file is private even when the process umask is permissive.
    #[test]
    fn saved_relay_list_has_private_mode() {
        use std::os::unix::fs::MetadataExt as _;

        let directory =
            std::env::temp_dir().join(format!("relay-list-mode-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        save(&directory, &RelayList::default()).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(directory.join(FILE))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A pre-existing pending symlink cannot redirect a save or truncate its target.
    #[cfg(unix)]
    #[test]
    fn save_does_not_follow_a_pending_symlink() {
        use std::os::unix::fs::symlink;

        let directory =
            std::env::temp_dir().join(format!("relay-list-pending-{}", std::process::id()));
        let target = std::env::temp_dir().join(format!("relay-list-target-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(&target, b"keep this file").unwrap();
        symlink(&target, directory.join(format!(".{FILE}.pending"))).unwrap();
        let sequence = NEXT_PENDING.load(Ordering::Relaxed);
        symlink(
            &target,
            directory.join(format!(".{FILE}.{}.{sequence}.pending", std::process::id())),
        )
        .unwrap();

        save(&directory, &RelayList::default()).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"keep this file");
        std::fs::remove_dir_all(&directory).unwrap();
        std::fs::remove_file(target).unwrap();
    }

    /// Oversized files and symlinks are ignored instead of being decoded as saved relay state.
    #[cfg(unix)]
    #[test]
    fn load_refuses_oversized_files_and_symlinks() {
        use std::os::unix::fs::symlink;

        let directory =
            std::env::temp_dir().join(format!("relay-list-load-{}", std::process::id()));
        let target =
            std::env::temp_dir().join(format!("relay-list-load-target-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(FILE),
            vec![b' '; usize::try_from(MAX_FILE_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert_eq!(load(&directory), RelayList::default());

        let target_list = RelayList {
            relays: vec![RelayEntry {
                name: "relay.example.org".into(),
                port: 3478,
                addresses: vec!["8.8.8.8".parse().unwrap()],
            }],
            serve: None,
        };
        std::fs::write(&target, serde_json::to_vec(&target_list).unwrap()).unwrap();
        std::fs::remove_file(directory.join(FILE)).unwrap();
        symlink(&target, directory.join(FILE)).unwrap();
        assert_eq!(load(&directory), RelayList::default());

        std::fs::remove_dir_all(&directory).unwrap();
        std::fs::remove_file(target).unwrap();
    }

    /// Loading a legacy umask-created cache preserves it while tightening its file mode.
    #[cfg(unix)]
    #[test]
    fn loading_legacy_relay_list_secures_its_mode() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let directory =
            std::env::temp_dir().join(format!("relay-list-legacy-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let list = RelayList {
            relays: vec![RelayEntry {
                name: "relay.example.org".into(),
                port: 3478,
                addresses: vec!["8.8.8.8".parse().unwrap()],
            }],
            serve: None,
        };
        save(&directory, &list).unwrap();
        std::fs::set_permissions(directory.join(FILE), std::fs::Permissions::from_mode(0o644))
            .unwrap();

        assert_eq!(load(&directory), list);
        assert_eq!(
            std::fs::metadata(directory.join(FILE)).unwrap().mode() & 0o777,
            0o600
        );
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
    #![allow(clippy::expect_used, clippy::unwrap_used)]
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

    /// The server keeps newest revocations while trimming the oldest to fit an 8 KiB action.
    #[test]
    fn large_relay_certificates_trim_old_revocations_to_fit() {
        let revoked = (0..MAX_REVOKED)
            .map(|host| format!("00000000-0000-0000-0000-{host:012x}"))
            .collect::<Vec<_>>();
        let mut list = RelayList {
            relays: Vec::new(),
            serve: Some(ServeRelay {
                name: "relay.example.org".into(),
                port: 443,
                leaf: "l".repeat(1_800),
                roots: vec!["r".repeat(1_800); 2],
                revoked: revoked.clone(),
            }),
        };

        let input =
            action_input(&mut list).expect("the certificate fields fit without all revocations");
        let decoded: RelayList = serde_json::from_slice(&input).unwrap();
        let kept = &decoded.serve.as_ref().unwrap().revoked;
        assert!(input.len() <= infraternal_plugin_api::MAX_ACTION_BYTES);
        assert!(!kept.is_empty() && kept.len() < revoked.len());
        assert_eq!(
            kept,
            &revoked[..kept.len()],
            "the newest entries remain first"
        );
    }
}
