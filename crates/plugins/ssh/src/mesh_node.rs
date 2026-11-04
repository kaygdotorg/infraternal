//! The mesh SSH component inside the infraternal agent: host key, pushed authority and the TCP/22 listener [D235, D289], #221.
//!
//! The server drives it with control actions. As a target:
//! - `mesh-ssh-node.host_key` returns this node's host public key. The key is
//!   created in memory when the infraternal agent starts and is never written
//!   to disk; a restart makes a new one and the server certifies it again.
//! - `mesh-ssh-node.configure` installs the authority snapshot and the host
//!   certificate, and turns the listener on or off (off by default, owner
//!   question Q4 on #221).
//!
//! As a client (the machine a person types `ssh` on):
//! - `mesh-ssh-node.person_key` makes the person's key in memory and returns its
//!   public half; the server certifies it with this node's mesh address.
//! - `mesh-ssh-node.client` installs that certificate, writes the `ssh_config.d`
//!   block and the CA known-hosts line from structured values (never server
//!   text), and serves the key socket ([`crate::mesh_keys`]). A `person` of
//!   null removes all three. The socket admits only ordinary local accounts
//!   ([`crate::mesh_keys::may_ask`], checked from the kernel's peer
//!   credentials on every connection).
//!
//! The listener serves only while it has all three: a snapshot, a host
//! certificate for this exact key, and an applied mesh view. It binds only
//! this node's own mesh addresses on TCP/22 through `mesh_port` (exact bind,
//! or the owned redirect when the host's sshd holds the port), never a
//! wildcard or loopback address. Each accepted connection is served by
//! `mesh_server::serve`, which checks both access rules on authentication
//! and again on every channel open.

use crate::{
    mesh_admission::Refusal,
    mesh_authority::{AccountLookup, Authority, Guard, MeshView, Snapshot},
    mesh_keys::PersonKey,
    mesh_login::LoginAuthority,
    mesh_port::MeshPort,
    mesh_runtime::ShimRuntime,
    mesh_server,
};
use infraternal_plugin_api::{
    ActionDef, AgentPlugin, Dependency, DryRun, Effect, Permission, PluginDescriptor, PluginError,
    SchemaRef, Target,
};
use russh::keys::{Algorithm, Certificate, PrivateKey};
use serde::Deserialize;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{sync::watch, task::JoinHandle};

/// One server-only control action of this component.
const fn control(id: &'static str, summary: &'static str) -> ActionDef {
    ActionDef {
        id,
        summary,
        input: SchemaRef("Object"),
        output: SchemaRef("Object"),
        effect: Effect::Write,
        instructions: &["The authenticated server sends this; people never run it."],
        permission: Permission::One("mesh.node"),
        target: Target::Node,
        dry_run: DryRun::Unsupported,
        opens: None,
    }
}
/// The actions only the authenticated server link may call.
const CONTROL_ACTIONS: &[ActionDef] = &[
    control(
        "mesh-ssh-node.host_key",
        "Read this node's mesh SSH host key",
    ),
    control(
        "mesh-ssh-node.configure",
        "Apply mesh SSH access and the host certificate",
    ),
    control("mesh-ssh-node.person_key", "Make a person's mesh SSH key"),
    control(
        "mesh-ssh-node.client",
        "Install a person's certificate and the client files",
    ),
];
/// The node component's descriptor; it has no public actions.
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "mesh-ssh-node",
    api: infraternal_plugin_api::API_VERSION,
    actions: &[],
    topics: &[],
    settings: None,
    events: &[],
    streams: &[],
    defaults: &[],
    dependencies: &[Dependency::ExistingServer],
    can_enable_components: &[],
    roles: &[],
    max_frame_len: infraternal_plugin_api::MAX_ACTION_BYTES,
    unavailable: br#"{"error":"Mesh SSH is unavailable."}"#,
    unavailable_event: br#"{"type":"error","error":"Mesh SSH is unavailable."}"#,
};

/// Input of `mesh-ssh-node.configure`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configure {
    enabled: bool,
    snapshot: Snapshot,
    /// OpenSSH form of the host certificate for this node's host key;
    /// required to turn the listener on.
    #[serde(default)]
    host_certificate: Option<String>,
}

/// Input of `mesh-ssh-node.person_key`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonKeyRequest {
    person: String,
}

/// Input of `mesh-ssh-node.client`; a `person` of null removes the client side.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Client {
    person: Option<String>,
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    ca: Option<[u8; 32]>,
    #[serde(default)]
    suffix: Option<String>,
    #[serde(default)]
    network: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    prefix: Option<u8>,
    /// The account this machine was added with (J181 M3): the only local
    /// account that acts as the person. The server knows it by uid
    /// (rootless) or by name (the add-host login account).
    #[serde(default)]
    added_with: Option<AddedWith>,
}

/// How the server identifies the account the machine was added with.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum AddedWith {
    Uid(u32),
    Name(String),
}

/// Fixed paths. Each directory on the way must be owned by root and closed
/// to group and other writes ([`trusted_directory`]); otherwise nothing is
/// written or served (J181 M4).
const SOCKET: &str = "/run/infraternal/mesh-ssh-agent.sock";
/// The known-hosts file holding the mesh CA line.
const KNOWN_HOSTS: &str = "/etc/ssh/infraternal-mesh-known_hosts";
/// The uid that must own every trusted directory.
const ROOT: u32 = 0;

/// What the server last asked for: listener on or off, and its host certificate.
#[derive(Clone)]
struct Desired {
    enabled: bool,
    certificate: Option<Certificate>,
}

/// State shared by the component, its listener tasks and the key socket.
struct Shared {
    authority: Authority<ShimRuntime>,
    host_key: PrivateKey,
    /// The person key made by `mesh-ssh-node.person_key`, waiting for its certificate.
    pending: std::sync::Mutex<Option<(String, PrivateKey)>>,
    /// The identity the key socket serves; replaced whole on renewal.
    identity: std::sync::RwLock<Option<Arc<PersonKey>>>,
    /// The only local uid that may ask the key socket.
    allowed: std::sync::RwLock<Option<u32>>,
    accounts: AccountLookup,
    /// Bumped to end every open mesh SSH connection (off, or leaving the mesh).
    brake: watch::Sender<u64>,
}

/// The node component; one per infraternal agent process.
pub struct MeshSshNode {
    shared: Arc<Shared>,
    mesh: watch::Sender<Option<MeshView>>,
    desired: watch::Sender<Desired>,
    supervisor: Option<JoinHandle<()>>,
    socket: Option<JoinHandle<()>>,
    runtime: Option<Runtime>,
}

/// The component's own single-threaded runtime on a dedicated thread.
///
/// The infraternal agent calls node plugins on its `node-plugins` OS thread,
/// which has no Tokio runtime, so the component cannot borrow one. It starts
/// this runtime on first use (nothing runs until mesh SSH is configured) and
/// spawns every listener, connection, key-socket and pump task on it.
/// Dropping it stops the thread and every task on it.
struct Runtime {
    handle: tokio::runtime::Handle,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Runtime {
    /// Start the runtime thread and wait for its handle.
    fn start() -> Result<Self, PluginError> {
        let (ready, handle) = std::sync::mpsc::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("mesh-ssh".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                if ready.send(runtime.handle().clone()).is_ok() {
                    runtime.block_on(async {
                        let _ = stopped.await;
                    });
                }
            })
            .map_err(|_| PluginError::Rejected)?;
        let handle = handle.recv().map_err(|_| PluginError::Rejected)?;
        Ok(Self {
            handle,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl MeshSshNode {
    /// The component's runtime, started on first use.
    fn handle(&mut self) -> Result<tokio::runtime::Handle, PluginError> {
        if self.runtime.is_none() {
            self.runtime = Some(Runtime::start()?);
        }
        self.runtime
            .as_ref()
            .map(|runtime| runtime.handle.clone())
            .ok_or(PluginError::Rejected)
    }

    /// # Errors
    /// Fails only if the system random source cannot make a host key.
    pub fn new(state: PathBuf, accounts: AccountLookup) -> Result<Self, PluginError> {
        let host_key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
            .map_err(|_| PluginError::Rejected)?;
        Ok(Self {
            shared: Arc::new(Shared {
                authority: Authority::new(ShimRuntime::new(state), accounts),
                host_key,
                pending: std::sync::Mutex::new(None),
                identity: std::sync::RwLock::new(None),
                allowed: std::sync::RwLock::new(None),
                accounts,
                brake: watch::Sender::new(0),
            }),
            mesh: watch::Sender::new(None),
            desired: watch::Sender::new(Desired {
                enabled: false,
                certificate: None,
            }),
            supervisor: None,
            socket: None,
            runtime: None,
        })
    }

    /// The observer the mesh plugin calls with each accepted configuration.
    /// It never blocks: the latest view replaces any view not yet applied.
    #[must_use]
    pub fn mesh_observer(&self) -> Arc<dyn Fn(Option<MeshView>) + Send + Sync> {
        let mesh = self.mesh.clone();
        Arc::new(move |view| {
            mesh.send_replace(view);
        })
    }

    /// Install a snapshot and the listener state; report a refused snapshot.
    fn configure(&mut self, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        let input: Configure = serde_json::from_slice(input).map_err(|_| PluginError::Rejected)?;
        let certificate = match input.host_certificate.as_deref() {
            Some(text) => {
                let certificate =
                    Certificate::from_openssh(text).map_err(|_| PluginError::Rejected)?;
                // A certificate for another key would make every client refuse us.
                if certificate.public_key() != self.shared.host_key.public_key().key_data() {
                    return Err(PluginError::Rejected);
                }
                Some(certificate)
            }
            None if input.enabled => return Err(PluginError::Rejected),
            None => None,
        };
        // Narrowing is always safe: "off" applies even when the snapshot
        // that came with it is refused (J181 M1).
        if !input.enabled {
            self.desired.send_replace(Desired {
                enabled: false,
                certificate: None,
            });
        }
        // Installed before replying, so the server learns of a stale or
        // contended push and retries; it is never told "accepted" for state
        // this node does not hold.
        let installed = self.shared.authority.try_install(input.snapshot);
        if installed.is_ok() && input.enabled {
            self.desired.send_replace(Desired {
                enabled: true,
                certificate,
            });
        }
        if self.supervisor.is_none() {
            let runtime = self.handle()?;
            self.supervisor = Some(runtime.spawn(supervise(
                Arc::clone(&self.shared),
                self.mesh.subscribe(),
                self.desired.subscribe(),
            )));
        }
        installed.map_err(|_| PluginError::Rejected)?;
        Ok(br#"{"accepted":true}"#.to_vec())
    }

    /// Make a person's in-memory key and return its public half.
    fn person_key(&self, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        let input: PersonKeyRequest =
            serde_json::from_slice(input).map_err(|_| PluginError::Rejected)?;
        if uuid::Uuid::parse_str(&input.person).is_err() {
            return Err(PluginError::Rejected);
        }
        let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
            .map_err(|_| PluginError::Rejected)?;
        let public = key
            .public_key()
            .to_openssh()
            .map_err(|_| PluginError::Rejected)?;
        *self
            .shared
            .pending
            .lock()
            .map_err(|_| PluginError::Rejected)? = Some((input.person, key));
        serde_json::to_vec(&serde_json::json!({ "public_key": public }))
            .map_err(|_| PluginError::Rejected)
    }

    /// Install or remove the client side: certificate, files and key socket.
    fn client(&mut self, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        let input: Client = serde_json::from_slice(input).map_err(|_| PluginError::Rejected)?;
        let known_hosts = Path::new(KNOWN_HOSTS);
        let Some(person) = input.person else {
            *self
                .shared
                .identity
                .write()
                .map_err(|_| PluginError::Rejected)? = None;
            *self
                .shared
                .allowed
                .write()
                .map_err(|_| PluginError::Rejected)? = None;
            remove_client_files(known_hosts);
            return Ok(br#"{"accepted":true}"#.to_vec());
        };
        let allowed = match input.added_with {
            Some(AddedWith::Uid(uid)) => Some(uid),
            Some(AddedWith::Name(name)) => (self.shared.accounts)(&name),
            None => None,
        }
        .filter(|uid| {
            crate::mesh_keys::may_ask(
                *uid,
                Some(*uid),
                infraternal_plugin_api::login_access::OrdinaryUids::host(),
            )
        })
        .ok_or(PluginError::Rejected)?;
        let (Some(certificate), Some(ca), Some(suffix), Some(network), Some(prefix)) = (
            input.certificate,
            input.ca,
            input.suffix,
            input.network,
            input.prefix,
        ) else {
            return Err(PluginError::Rejected);
        };
        let certificate =
            Certificate::from_openssh(&certificate).map_err(|_| PluginError::Rejected)?;
        // Only the key this node made for this person may be certified here.
        let key = {
            let pending = self
                .shared
                .pending
                .lock()
                .map_err(|_| PluginError::Rejected)?;
            match pending.as_ref() {
                Some((owner, key))
                    if *owner == person
                        && certificate.public_key() == key.public_key().key_data()
                        && certificate.valid_principals() == std::slice::from_ref(&person) =>
                {
                    key.clone()
                }
                _ => return Err(PluginError::Rejected),
            }
        };
        let config = crate::mesh_client_config::client_config(
            &suffix,
            network,
            prefix,
            Path::new(SOCKET),
            known_hosts,
        )
        .ok_or(PluginError::Rejected)?;
        let known = crate::mesh_client_config::known_hosts(&suffix, network, prefix, ca)
            .ok_or(PluginError::Rejected)?;
        write_client_files(known_hosts, &known, &config).map_err(|_| PluginError::Rejected)?;
        *self
            .shared
            .allowed
            .write()
            .map_err(|_| PluginError::Rejected)? = Some(allowed);
        *self
            .shared
            .identity
            .write()
            .map_err(|_| PluginError::Rejected)? = Some(Arc::new(PersonKey { certificate, key }));
        if self.socket.is_none() {
            let runtime = self.handle()?;
            self.socket = Some(runtime.spawn(serve_socket(Arc::clone(&self.shared))));
        }
        Ok(br#"{"accepted":true}"#.to_vec())
    }
}

/// A directory that only `root_uid` can change: owned by it, not a symlink,
/// and closed to group and other writes. Every ancestor must be owned by
/// root (or `root_uid`) and closed to writes, or sticky like `/tmp`, so no
/// other account can swap a directory on the way.
pub(crate) fn trusted_directory(path: &Path, root_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let closed = |mode: u32| mode & 0o022 == 0;
    let itself = std::fs::symlink_metadata(path)
        .is_ok_and(|meta| meta.is_dir() && meta.uid() == root_uid && closed(meta.mode()));
    itself
        && path.ancestors().skip(1).all(|directory| {
            std::fs::symlink_metadata(directory).is_ok_and(|meta| {
                meta.is_dir()
                    && (meta.uid() == root_uid || meta.uid() == 0)
                    && (closed(meta.mode()) || meta.mode() & 0o1000 != 0)
            })
        })
}

/// Refuse a path whose directory is not trusted ([`trusted_directory`]).
fn in_trusted_directory(path: &Path) -> std::io::Result<()> {
    let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    if trusted_directory(parent, ROOT) {
        Ok(())
    } else {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}

/// Write a file atomically with the given mode, through a temporary sibling.
fn write_file(path: &std::path::Path, contents: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    in_trusted_directory(path)?;
    let temporary = path.with_extension("infraternal-tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&temporary)?;
    std::io::Write::write_all(&mut file, contents.as_bytes())?;
    file.sync_all()?;
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&temporary, path)
}

/// Write the known-hosts file and the `ssh_config.d` block.
fn write_client_files(
    known_hosts: &std::path::Path,
    known: &str,
    config: &str,
) -> std::io::Result<()> {
    // Readable by every local account: they hold only public keys and paths.
    write_file(known_hosts, known, 0o644)?;
    write_file(
        std::path::Path::new(crate::mesh_client_config::CONFIG_PATH),
        config,
        0o644,
    )
}

/// Remove both client files; missing files are fine.
fn remove_client_files(known_hosts: &std::path::Path) {
    let _ = std::fs::remove_file(crate::mesh_client_config::CONFIG_PATH);
    let _ = std::fs::remove_file(known_hosts);
}

/// Serve the key socket. Every connection's kernel peer credentials decide
/// whether it may ask ([`crate::mesh_keys::may_ask`]); the identity is read
/// per message, so renewal and removal apply at once.
async fn serve_socket(shared: Arc<Shared>) {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let path = Path::new(SOCKET);
    let Some(parent) = path.parent() else {
        return;
    };
    let _ = std::fs::DirBuilder::new().mode(0o755).create(parent);
    // The socket must be connectable by others, so its directory, not its
    // mode, keeps anyone from replacing it.
    if !trusted_directory(parent, ROOT) {
        return;
    }
    let _ = std::fs::remove_file(path);
    let Ok(listener) = tokio::net::UnixListener::bind(path) else {
        return;
    };
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    let ordinary = infraternal_plugin_api::login_access::OrdinaryUids::host();
    let mut backoff = Duration::from_millis(10);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            // Out of descriptors: wait instead of spinning (J181 M2).
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(1));
            continue;
        };
        backoff = Duration::from_millis(10);
        // Checked on every connection before a byte is read (J181 M4): the
        // kernel's peer credentials must be the account the machine was
        // added with (M3).
        let allowed = shared.allowed.read().ok().and_then(|allowed| *allowed);
        let permitted = stream.peer_cred().is_ok_and(|credentials| {
            crate::mesh_keys::may_ask(credentials.uid(), allowed, ordinary)
        });
        if !permitted {
            continue;
        }
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let _ = crate::mesh_keys::serve(stream, || {
                shared
                    .identity
                    .read()
                    .ok()
                    .and_then(|identity| identity.clone())
            })
            .await;
        });
    }
}

impl Drop for MeshSshNode {
    fn drop(&mut self) {
        if let Some(supervisor) = self.supervisor.take() {
            supervisor.abort();
        }
        if let Some(socket) = self.socket.take() {
            socket.abort();
        }
    }
}

impl AgentPlugin for MeshSshNode {
    fn descriptor(&self) -> &'static PluginDescriptor {
        &DESCRIPTOR
    }
    fn control_actions(&self) -> &'static [ActionDef] {
        CONTROL_ACTIONS
    }
    fn call(&mut self, action_id: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        match action_id {
            "mesh-ssh-node.host_key" => {
                let key = self
                    .shared
                    .host_key
                    .public_key()
                    .to_openssh()
                    .map_err(|_| PluginError::Rejected)?;
                serde_json::to_vec(&serde_json::json!({ "host_key": key }))
                    .map_err(|_| PluginError::Rejected)
            }
            "mesh-ssh-node.configure" => self.configure(input),
            "mesh-ssh-node.person_key" => self.person_key(input),
            "mesh-ssh-node.client" => self.client(input),
            _ => Err(PluginError::UnknownAction),
        }
    }
}

/// What the listeners depend on. Peer and rule changes are not part of it:
/// they reach the authority, and running listeners and sessions continue.
#[derive(PartialEq, Eq)]
struct ListenerKey {
    node: u64,
    addresses: Vec<IpAddr>,
    interface: String,
    certificate: Vec<u8>,
}

/// The listener inputs, or `None` when the listener must be off.
fn listener_key(view: Option<&MeshView>, want: &Desired) -> Option<ListenerKey> {
    let view = view?;
    let certificate = want.certificate.as_ref()?;
    want.enabled.then(|| ListenerKey {
        node: view.node,
        addresses: view.addresses.clone(),
        interface: view.interface.clone(),
        certificate: certificate.to_bytes().unwrap_or_default(),
    })
}

/// Whether a listener change must end open connections: turning off, or the
/// node's identity or addresses changing. A new host certificate alone does not.
fn ends_sessions(previous: Option<&ListenerKey>, next: Option<&ListenerKey>) -> bool {
    match (previous, next) {
        (Some(_), None) => true,
        (Some(previous), Some(next)) => {
            previous.node != next.node
                || previous.addresses != next.addresses
                || previous.interface != next.interface
        }
        (None, _) => false,
    }
}

/// Run one connection until it ends or the brake is pulled.
async fn until_braked<F: std::future::Future<Output = ()>>(
    work: F,
    mut brake: watch::Receiver<u64>,
) {
    tokio::select! {
        () = work => {}
        _ = brake.changed() => {}
    }
}

/// Keep the authority's mesh view current and the listeners matching it.
async fn supervise(
    shared: Arc<Shared>,
    mut mesh: watch::Receiver<Option<MeshView>>,
    mut desired: watch::Receiver<Desired>,
) {
    let mut running: Vec<(MeshPort, JoinHandle<()>)> = Vec::new();
    let mut current: Option<ListenerKey> = None;
    loop {
        let view = mesh.borrow_and_update().clone();
        let want = desired.borrow_and_update().clone();
        shared.authority.set_mesh(view.clone()).await;
        let next = listener_key(view.as_ref(), &want);
        if next != current {
            if ends_sessions(current.as_ref(), next.as_ref()) {
                // Off, or this node left or moved: end every open connection
                // (J181 M7). A renewed host certificate keeps them.
                shared
                    .brake
                    .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
            }
            stop(&mut running).await;
            if next.is_some()
                && let (Some(view), Some(certificate)) = (view, want.certificate)
            {
                let mut config = mesh_server::config(shared.host_key.clone());
                config.certificates = vec![certificate];
                let config = Arc::new(config);
                for address in view.addresses.iter().copied() {
                    if let Some(port) = bind(address, view.interface.clone()).await
                        && let Some(task) = accept(&shared, &port, view.node, &config)
                    {
                        running.push((port, task));
                    }
                }
            }
            current = next;
        }
        tokio::select! {
            changed = mesh.changed() => if changed.is_err() { break },
            changed = desired.changed() => if changed.is_err() { break },
        }
    }
    stop(&mut running).await;
}

/// Bind one mesh address on TCP/22 (exact bind or owned redirect).
async fn bind(address: IpAddr, interface: String) -> Option<MeshPort> {
    // Binding may install an nft redirect: blocking work, off the reactor.
    tokio::task::spawn_blocking(move || MeshPort::bind(address, &interface).ok())
        .await
        .ok()
        .flatten()
}

/// Serve one bound listener until it is stopped.
fn accept(
    shared: &Arc<Shared>,
    port: &MeshPort,
    target_node: u64,
    config: &Arc<russh::server::Config>,
) -> Option<JoinHandle<()>> {
    let listener = port.listener()?.try_clone().ok()?;
    listener.set_nonblocking(true).ok()?;
    let listener = tokio::net::TcpListener::from_std(listener).ok()?;
    let shared = Arc::clone(shared);
    let config = Arc::clone(config);
    let pending = Pending::default();
    Some(tokio::spawn(async move {
        let mut backoff = Duration::from_millis(10);
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                // Out of descriptors: wait instead of spinning (J181 M2).
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(1));
                continue;
            };
            backoff = Duration::from_millis(10);
            // Over the bound: close at once, before any protocol work.
            let Some(slot) = pending.admit(peer.ip()) else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let authority = Arc::new(SharedAuthority(Arc::clone(&shared)));
            let config = Arc::clone(&config);
            let brake = shared.brake.subscribe();
            // Not owned by this accept task, so a listener restart for a new
            // host certificate keeps running sessions; the brake ends them
            // when the node turns off or leaves the mesh (J181 M7).
            tokio::spawn(until_braked(
                async move {
                    let _ = mesh_server::serve_admitted(
                        authority,
                        peer.ip(),
                        target_node,
                        config,
                        stream,
                        mesh_server::LOGIN_GRACE,
                        slot,
                    )
                    .await;
                },
                brake,
            ));
        }
    }))
}

/// Unauthenticated connections per source node and in total (J181 M2).
/// A security bound on peers that have not proven who they are, not a limit
/// on sessions: a slot is released as soon as the peer authenticates.
const PENDING_PER_SOURCE: usize = 8;
/// Unauthenticated connections across all sources.
const PENDING_TOTAL: usize = 64;

/// Counts of unauthenticated connections, in total and per source.
#[derive(Clone, Default)]
struct Pending(Arc<std::sync::Mutex<(usize, std::collections::HashMap<IpAddr, usize>)>>);

/// One held unauthenticated slot; dropping it gives the slot back.
struct PendingSlot {
    pending: Pending,
    source: IpAddr,
}

impl Pending {
    /// Take a slot for a new connection from `source`, or `None` over a bound.
    fn admit(&self, source: IpAddr) -> Option<PendingSlot> {
        let mut counts = self.0.lock().ok()?;
        let (total, by_source) = &mut *counts;
        let for_source = by_source.entry(source).or_insert(0);
        if *total >= PENDING_TOTAL || *for_source >= PENDING_PER_SOURCE {
            return None;
        }
        *for_source += 1;
        *total += 1;
        Some(PendingSlot {
            pending: self.clone(),
            source,
        })
    }
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        if let Ok(mut counts) = self.pending.0.lock() {
            let (total, by_source) = &mut *counts;
            *total = total.saturating_sub(1);
            if let Some(count) = by_source.get_mut(&self.source) {
                *count -= 1;
                if *count == 0 {
                    by_source.remove(&self.source);
                }
            }
        }
    }
}

/// Stop the listeners; open connections end only through the brake.
async fn stop(running: &mut Vec<(MeshPort, JoinHandle<()>)>) {
    for (mut port, task) in running.drain(..) {
        // Stops new connections; open ones end only through the brake.
        task.abort();
        let _ = tokio::task::spawn_blocking(move || port.stop()).await;
    }
}

/// Lets each connection share the node's one authority.
struct SharedAuthority(Arc<Shared>);
impl LoginAuthority for SharedAuthority {
    type Guard<'a> = Guard<'a, ShimRuntime>;
    async fn current(&self) -> Result<Guard<'_, ShimRuntime>, Refusal> {
        self.0.authority.current().await
    }
}

#[cfg(test)]
#[path = "mesh_node_tests.rs"]
mod tests;
