//! The mesh SSH component inside the infraternal agent: host key, pushed authority and the TCP/22 listener [D235, D289], #221.
//!
//! The server drives it with two control actions:
//! - `mesh.ssh.host_key` returns this node's host public key. The key is
//!   created in memory when the infraternal agent starts and is never written
//!   to disk; a restart makes a new one and the server certifies it again.
//! - `mesh.ssh.configure` installs the authority snapshot and the host
//!   certificate, and turns the listener on or off (off by default, owner
//!   question Q4 on #221).
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
    mesh_login::LoginAuthority,
    mesh_port::MeshPort,
    mesh_runtime::ShimRuntime,
    mesh_server,
};
use infraternal_plugin_api::{
    ActionDef, AgentPlugin, Dependency, PluginDescriptor, PluginError, SchemaRef,
    action::{DryRun, Effect, Permission, Target},
};
use russh::keys::{Algorithm, Certificate, PrivateKey};
use serde::Deserialize;
use std::{net::IpAddr, path::PathBuf, sync::Arc};
use tokio::{sync::watch, task::JoinHandle};

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
const CONTROL_ACTIONS: &[ActionDef] = &[
    control("mesh.ssh.host_key", "Read this node's mesh SSH host key"),
    control(
        "mesh.ssh.configure",
        "Apply mesh SSH access and the host certificate",
    ),
];
pub const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
    id: "mesh-ssh",
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configure {
    enabled: bool,
    snapshot: Snapshot,
    /// OpenSSH form of the host certificate for this node's host key.
    host_certificate: String,
}

#[derive(Clone)]
struct Desired {
    enabled: bool,
    certificate: Option<Certificate>,
}

struct Shared {
    authority: Authority<ShimRuntime>,
    host_key: PrivateKey,
}

/// The node component; one per infraternal agent process.
pub struct MeshSshNode {
    shared: Arc<Shared>,
    mesh: watch::Sender<Option<MeshView>>,
    desired: watch::Sender<Desired>,
    supervisor: Option<JoinHandle<()>>,
}

impl MeshSshNode {
    /// # Errors
    /// Fails only if the system random source cannot make a host key.
    pub fn new(state: PathBuf, accounts: AccountLookup) -> Result<Self, PluginError> {
        let host_key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
            .map_err(|_| PluginError::Rejected)?;
        Ok(Self {
            shared: Arc::new(Shared {
                authority: Authority::new(ShimRuntime::new(state), accounts),
                host_key,
            }),
            mesh: watch::Sender::new(None),
            desired: watch::Sender::new(Desired {
                enabled: false,
                certificate: None,
            }),
            supervisor: None,
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

    fn configure(&mut self, input: &[u8]) -> Result<Vec<u8>, PluginError> {
        let input: Configure = serde_json::from_slice(input).map_err(|_| PluginError::Rejected)?;
        let certificate = Certificate::from_openssh(&input.host_certificate)
            .map_err(|_| PluginError::Rejected)?;
        // A certificate for another key would make every client refuse us.
        if certificate.public_key() != self.shared.host_key.public_key().key_data() {
            return Err(PluginError::Rejected);
        }
        let shared = Arc::clone(&self.shared);
        let desired = self.desired.clone();
        let snapshot = input.snapshot;
        let enabled = input.enabled;
        // The snapshot is installed before the listener may start, and an
        // older snapshot is refused by its sequence however tasks interleave.
        tokio::spawn(async move {
            if shared.authority.install(snapshot).await.is_ok() {
                desired.send_replace(Desired {
                    enabled,
                    certificate: Some(certificate),
                });
            }
        });
        if self.supervisor.is_none() {
            self.supervisor = Some(tokio::spawn(supervise(
                Arc::clone(&self.shared),
                self.mesh.subscribe(),
                self.desired.subscribe(),
            )));
        }
        Ok(br#"{"accepted":true}"#.to_vec())
    }
}

impl Drop for MeshSshNode {
    fn drop(&mut self) {
        if let Some(supervisor) = self.supervisor.take() {
            supervisor.abort();
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
            "mesh.ssh.host_key" => {
                let key = self
                    .shared
                    .host_key
                    .public_key()
                    .to_openssh()
                    .map_err(|_| PluginError::Rejected)?;
                serde_json::to_vec(&serde_json::json!({ "host_key": key }))
                    .map_err(|_| PluginError::Rejected)
            }
            "mesh.ssh.configure" => self.configure(input),
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

async fn bind(address: IpAddr, interface: String) -> Option<MeshPort> {
    // Binding may install an nft redirect: blocking work, off the reactor.
    tokio::task::spawn_blocking(move || MeshPort::bind(address, &interface).ok())
        .await
        .ok()
        .flatten()
}

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
    Some(tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let authority = Arc::new(SharedAuthority(Arc::clone(&shared)));
            let config = Arc::clone(&config);
            // Detached on purpose: a listener restart (new address or host
            // certificate) must not end running sessions. Every channel open
            // still rechecks the current authority. Ending running sessions
            // on revocation is left out of slice 1 (#221 plan).
            tokio::spawn(async move {
                let _ = mesh_server::serve(authority, peer.ip(), target_node, config, stream).await;
            });
        }
    }))
}

async fn stop(running: &mut Vec<(MeshPort, JoinHandle<()>)>) {
    for (mut port, task) in running.drain(..) {
        // Stops new connections only; running sessions are separate tasks.
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
