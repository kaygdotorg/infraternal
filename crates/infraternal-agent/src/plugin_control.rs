//! Runs bounded node plugin work off terminal dispatch and exposes it to same-uid local CLI callers [9,16,198,202].
use infraternal_plugin_api::{MAX_ACTION_BYTES, PluginError, PluginRegistry};
use infraternal_protocol::{DecodeError, Frame, decode_muxed_frame, encode_muxed_frame_into};
use std::{
    io,
    path::{Path, PathBuf},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::mpsc,
    task::JoinHandle,
};
/// One dedicated sleeping worker owns synchronous plugin calls; terminal dispatch never enters kernel work.
#[derive(Clone)]
pub(crate) struct Registry {
    // Dynamic fixture identity is explicit, never inferred from worker failure.
    #[cfg(test)]
    empty: bool,
    #[cfg(feature = "remote")]
    lifetime: Option<std::sync::Arc<std::fs::File>>,
    sender: mpsc::Sender<Job>,
    #[cfg(any(test, feature = "native-streams"))]
    capabilities: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(any(test, feature = "native-streams"))]
    wire_caps: std::sync::Arc<std::sync::atomic::AtomicU64>,
    #[cfg(any(test, feature = "native-streams"))]
    shared: std::sync::Arc<std::sync::OnceLock<crate::plugins::SharedRegistry>>,
    events: tokio::sync::broadcast::Sender<Vec<u8>>,
    pending: std::sync::Arc<std::sync::Mutex<Option<PendingWorker>>>,
    paths: tokio::sync::watch::Sender<Option<std::net::IpAddr>>,
    link: std::sync::Arc<std::sync::Mutex<infraternal_plugin_api::server_path::ServerLink>>,
}
#[cfg(any(test, feature = "native-streams"))]
type Factory = Box<dyn FnOnce() -> Result<crate::plugins::SharedRegistry, PluginError> + Send>;
#[cfg(not(any(test, feature = "native-streams")))]
type Factory = Box<dyn FnOnce() -> Result<PluginRegistry, PluginError> + Send>;
#[cfg(test)]
tokio::task_local! {
    /// Scope fault injection to one reconnect task; unrelated tests use real plugins.
    pub(crate) static TEST_FACTORY: std::sync::Arc<dyn Fn() -> Result<PluginRegistry, PluginError> + Send + Sync>;
}
struct PendingWorker {
    factory: Factory,
    incoming: mpsc::Receiver<Job>,
}
#[cfg(any(test, feature = "native-streams"))]
type PreparedReply = infraternal_plugin_api::Operation<
    'static,
    Result<infraternal_plugin_api::ActionReply, PluginError>,
>;
#[cfg(not(any(test, feature = "native-streams")))]
type PreparedReply = infraternal_plugin_api::ActionReply;
enum Job {
    #[cfg(any(test, feature = "native-streams"))]
    Capabilities,
    #[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
    Providers {
        result: tokio::sync::oneshot::Sender<
            Result<Vec<infraternal_plugin_api::streams::WireProviderEntry>, PluginError>,
        >,
    },
    Call {
        public: bool,
        action: String,
        input: Vec<u8>,
        context: Option<infraternal_plugin_api::admission::NodeContext>,
        result: tokio::sync::oneshot::Sender<Result<PreparedReply, PluginError>>,
    },
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    Admit {
        action: String,
        context: infraternal_plugin_api::admission::NodeContext,
        result: tokio::sync::oneshot::Sender<
            Result<(), infraternal_plugin_api::admission::OpenRefusal>,
        >,
    },
    #[cfg(any(test, feature = "remote"))]
    Paths {
        result: tokio::sync::oneshot::Sender<()>,
    },
}
/// Publish intent before releasing a caller; contradictory proposals erase stale paths.
fn publish_paths(
    registry: &PluginRegistry,
    paths: &tokio::sync::watch::Sender<Option<std::net::IpAddr>>,
) {
    let preferred = registry.preferred_server().unwrap_or_default();
    paths.send_if_modified(|current| {
        if *current == preferred {
            return false;
        }
        *current = preferred;
        true
    });
}

// Only the opted-in native build transfers an owned future out of registry admission.
// Terminal builds preserve the synchronous reply and deferred-after-write contract.
fn prepare_call(
    registry: &mut PluginRegistry,
    public: bool,
    action: &str,
    input: &[u8],
) -> Result<PreparedReply, PluginError> {
    #[cfg(any(test, feature = "native-streams"))]
    let response = if public {
        registry.call_public(action, input).map(|json| {
            let reply = infraternal_plugin_api::ActionReply {
                json,
                after_write: None,
            };
            Box::pin(async move { Ok(reply) })
                as infraternal_plugin_api::Operation<
                    'static,
                    Result<infraternal_plugin_api::ActionReply, PluginError>,
                >
        })
    } else {
        registry.begin_call(action, input)
    };
    #[cfg(not(any(test, feature = "native-streams")))]
    let response = if public {
        registry
            .call_public(action, input)
            .map(|json| infraternal_plugin_api::ActionReply {
                json,
                after_write: None,
            })
    } else {
        registry.call_with_reply(action, input)
    };
    response
}

impl Registry {
    #[cfg(not(any(test, feature = "native-streams")))]
    #[allow(clippy::unused_self)]
    pub(crate) fn capabilities(&self, _: u64) {}
    #[cfg(any(test, feature = "native-streams"))]
    pub(crate) fn capabilities(&self, caps: u64) {
        self.capabilities
            .store(caps, std::sync::atomic::Ordering::Release);
        // Withdrawal cannot wait on an in-flight kernel transaction. If that
        // owner holds the map, its bounded queue applies the latest atomic value.
        if let Some(shared) = self.shared.get() {
            if let Ok(mut registry) = shared.try_lock() {
                registry.transport_capabilities(caps);
            } else {
                let _ = self.sender.try_send(Job::Capabilities);
            }
        }
    }
    #[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
    pub(crate) async fn wire_providers(
        &self,
    ) -> Result<Vec<infraternal_plugin_api::streams::WireProviderEntry>, PluginError> {
        self.start()?;
        let (result, receive) = tokio::sync::oneshot::channel();
        self.sender
            .try_send(Job::Providers { result })
            .map_err(|_| PluginError::Rejected)?;
        let entries = receive.await.map_err(|_| PluginError::Rejected)??;
        self.wire_caps.store(
            entries
                .iter()
                .fold(0, |caps, entry| caps | entry.definition.capability),
            std::sync::atomic::Ordering::Release,
        );
        Ok(entries)
    }
    #[cfg(not(any(test, feature = "native-streams")))]
    #[allow(clippy::unused_self)] // This build has no provider projection to inspect.
    pub(crate) fn wire_capabilities(&self, _: &impl crate::channel::Channel) -> u64 {
        0
    }
    #[cfg(any(test, feature = "native-streams"))]
    pub(crate) fn wire_capabilities(&self, channel: &impl crate::channel::Channel) -> u64 {
        // Provider discovery is process-owned; availability belongs to this
        // connection. A TCP replacement cannot inherit native QUIC admission.
        if channel.native_stream_id().is_some() {
            self.wire_caps.load(std::sync::atomic::Ordering::Acquire)
        } else {
            0
        }
    }
    #[cfg(test)]
    pub(crate) fn new(registry: PluginRegistry) -> Self {
        Self::from_factory(Some(Box::new(move || Ok(registry))))
    }
    /// Exercise startup failure through the real lazy worker/channel lifecycle.
    #[cfg(all(test, feature = "remote"))]
    pub(crate) fn unavailable() -> Self {
        Self::from_factory(Some(Box::new(|| Err(PluginError::Rejected))))
    }
    fn for_mode(
        state: PathBuf,
        mode: crate::plugins::ExecutionMode,
        installation: Option<crate::plugins::Installation>,
    ) -> Self {
        #[cfg(test)]
        if let Ok(factory) = TEST_FACTORY.try_with(std::sync::Arc::clone) {
            return Self::from_factory(Some(Box::new(move || factory())));
        }
        // The compiled catalog is constant. An absent provider needs no erased
        // factory or retained state; dynamic test fixtures still supply a factory.
        let registry = Self::from_factory(if crate::plugins::descriptors().is_empty() {
            None
        } else {
            Some(Box::new(move || {
                crate::plugins::registry_at(mode, Some(&state), installation.as_ref())
            }))
        });
        if matches!(mode, crate::plugins::ExecutionMode::Embedded) {
            registry.set_server_link(infraternal_plugin_api::server_path::ServerLink {
                kind: infraternal_plugin_api::server_path::ServerLinkKind::Local,
                endpoint: None,
                source_port: None,
                reason: infraternal_plugin_api::server_path::ServerLinkReason::Local,
            });
        }
        registry
    }
    fn from_factory(
        factory: Option<Box<dyn FnOnce() -> Result<PluginRegistry, PluginError> + Send>>,
    ) -> Self {
        #[cfg(any(test, feature = "native-streams"))]
        let factory: Option<Factory> = factory.map(|factory| {
            Box::new(move || {
                factory().map(|registry| std::sync::Arc::new(std::sync::Mutex::new(registry)))
            }) as Factory
        });
        // Terminal builds keep sole ownership in the sleeping worker. A shared
        // mutable registry is needed only for native provider injection.
        Self::from_shared_factory(factory)
    }
    #[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
    pub(crate) fn from_shared(registry: crate::plugins::SharedRegistry) -> Self {
        #[cfg(any(test, feature = "native-streams"))]
        let shared = registry.clone();
        let instance = Self::from_shared_factory(Some(Box::new(move || Ok(registry))));
        #[cfg(any(test, feature = "native-streams"))]
        let _ = instance.shared.set(shared);
        instance
    }
    fn from_shared_factory(factory: Option<Factory>) -> Self {
        #[cfg(test)]
        let empty = factory.is_none();
        let (sender, incoming) = mpsc::channel::<Job>(8);
        let (events, _) = tokio::sync::broadcast::channel(8);
        Self {
            #[cfg(test)]
            empty,
            #[cfg(feature = "remote")]
            lifetime: None,
            sender,
            #[cfg(any(test, feature = "native-streams"))]
            capabilities: std::sync::Arc::default(),
            #[cfg(any(test, feature = "native-streams"))]
            wire_caps: std::sync::Arc::default(),
            #[cfg(any(test, feature = "native-streams"))]
            shared: std::sync::Arc::default(),
            events,
            paths: tokio::sync::watch::channel(None).0,
            link: std::sync::Arc::default(),
            pending: std::sync::Arc::new(std::sync::Mutex::new(
                factory.map(|factory| PendingWorker { factory, incoming }),
            )),
        }
    }
    // Production identity is the compiled catalog constant. Test registries
    // may contain dynamic providers even when that catalog is empty.
    #[cfg_attr(not(test), allow(clippy::unused_self))]
    const fn is_empty(&self) -> bool {
        #[cfg(test)]
        {
            self.empty
        }
        #[cfg(not(test))]
        {
            crate::plugins::descriptors().is_empty()
        }
    }
    /// Receiver closure fences replacement: no old callback can still execute.
    #[cfg(feature = "remote")]
    pub(crate) fn ended(&self) -> bool {
        self.sender.is_closed()
    }
    fn start(&self) -> Result<(), PluginError> {
        if self.is_empty() {
            return Ok(());
        }
        // An inactive control surface needs no thread or its resident startup
        // code. Serialize the first call so concurrent local/server callers
        // share exactly one sleeping worker for the process lifetime.
        let mut pending = self.pending.lock().map_err(|_| PluginError::Rejected)?;
        if let Some(PendingWorker {
            factory,
            mut incoming,
        }) = pending.take()
        {
            let notifications = self.events.clone();
            let paths = self.paths.clone();
            let link = self.link.clone();
            #[cfg(any(test, feature = "native-streams"))]
            let capabilities = self.capabilities.clone();
            #[cfg(any(test, feature = "native-streams"))]
            let shared = self.shared.clone();
            #[cfg(feature = "remote")]
            let lifetime = self.lifetime.clone();
            std::thread::Builder::new()
                .name("node-plugins".into())
                .spawn(move || {
                    #[cfg(feature = "remote")]
                    let _lifetime = lifetime;
                    let Ok(owner) = factory() else {
                        return;
                    };
                    // Drop the registry before the captured receiver. Never
                    // close it early: ended() uses that as its replacement fence.
                    #[cfg(any(test, feature = "native-streams"))]
                    let _ = shared.set(owner.clone());
                    #[cfg(not(any(test, feature = "native-streams")))]
                    let mut registry = owner;
                    while let Some(job) = incoming.blocking_recv() {
                        #[cfg(any(test, feature = "native-streams"))]
                        let Ok(mut registry) = owner.lock() else {
                            return;
                        };
                        if let Ok(link) = link.lock() {
                            registry.set_server_link(&link);
                        }
                        #[cfg(any(test, feature = "native-streams"))]
                        registry.transport_capabilities(
                            capabilities.load(std::sync::atomic::Ordering::Acquire),
                        );
                        match job {
                            #[cfg(any(test, feature = "native-streams"))]
                            Job::Capabilities => {}
                            #[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
                            Job::Providers { result } => {
                                let _ = result.send(registry.wire_providers());
                            }
                            #[cfg(any(test, feature = "remote"))]
                            Job::Paths { result } => {
                                publish_paths(&registry, &paths);
                                let _ = result.send(());
                            }
                            #[cfg(any(test, target_os = "linux", target_os = "macos"))]
                            Job::Admit {
                                action,
                                context,
                                result,
                            } => {
                                let _ = result.send(registry.admit(&action, context));
                            }
                            Job::Call {
                                public,
                                action,
                                input,
                                context,
                                result,
                            } => {
                                if let Some(context) = context {
                                    registry.update_context(context);
                                }
                                let response = prepare_call(&mut registry, public, &action, &input);
                                if response.is_ok()
                                    && let Ok(events) = registry.events()
                                {
                                    for event in events {
                                        let _ = notifications.send(event);
                                    }
                                }
                                publish_paths(&registry, &paths);
                                let _ = result.send(response);
                            }
                        }
                    }
                })
                .map_err(|_| PluginError::Rejected)?;
        }
        Ok(())
    }
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    pub(crate) async fn admit(
        &self,
        action: &str,
        context: infraternal_plugin_api::admission::NodeContext,
    ) -> Result<(), infraternal_plugin_api::admission::OpenRefusal> {
        use infraternal_plugin_api::admission::OpenRefusal;
        if self.is_empty() {
            // Equivalent to admission through an empty PluginRegistry.
            return Ok(());
        }
        self.start().map_err(|_| OpenRefusal::ResourceUnavailable)?;
        let (result, receive) = tokio::sync::oneshot::channel();
        self.sender
            .try_send(Job::Admit {
                action: action.to_owned(),
                context,
                result,
            })
            .map_err(|_| OpenRefusal::ResourceUnavailable)?;
        receive
            .await
            .map_err(|_| OpenRefusal::ResourceUnavailable)?
    }

    /// Resolve retained component intent before dialing, without inventing a plugin action.
    #[cfg(any(test, feature = "remote"))]
    pub(crate) async fn initialize_paths(&self) -> Result<(), PluginError> {
        if self.is_empty() {
            return Ok(());
        }
        self.start()?;
        let (result, receive) = tokio::sync::oneshot::channel();
        self.sender
            .try_send(Job::Paths { result })
            .map_err(|_| PluginError::Rejected)?;
        receive.await.map_err(|_| PluginError::Rejected)?;
        Ok(())
    }
    /// Transport updates neither start the lazy worker nor enter kernel code.
    pub(crate) fn set_server_link(&self, value: infraternal_plugin_api::server_path::ServerLink) {
        if let Ok(mut link) = self.link.lock() {
            *link = value;
        }
    }
    #[cfg(any(test, feature = "remote"))]
    pub(crate) fn server_paths(&self) -> tokio::sync::watch::Receiver<Option<std::net::IpAddr>> {
        self.paths.subscribe()
    }
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Vec<u8>> {
        self.events.subscribe()
    }
    #[cfg(test)]
    pub(crate) async fn call(
        &self,
        action: String,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, PluginError> {
        let reply = self.execute(false, action, input, None).await?;
        if reply.after_write.is_some() {
            return Err(PluginError::Rejected);
        }
        Ok(reply.json)
    }
    async fn call_public(&self, action: String, input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
        Ok(self.execute(true, action, input, None).await?.json)
    }
    async fn execute(
        &self,
        public: bool,
        action: String,
        input: Vec<u8>,
        context: Option<infraternal_plugin_api::admission::NodeContext>,
    ) -> Result<infraternal_plugin_api::ActionReply, PluginError> {
        if input.len() > MAX_ACTION_BYTES || action.len() > 128 {
            return Err(PluginError::MessageTooLarge);
        }
        if self.is_empty() {
            return Err(PluginError::UnknownAction);
        }
        self.start()?;
        let (result, receive) = tokio::sync::oneshot::channel();
        self.sender
            .try_send(Job::Call {
                public,
                context,
                action,
                input,
                result,
            })
            .map_err(|_| PluginError::Rejected)?;
        let reply = receive.await.map_err(|_| PluginError::Rejected)?;
        #[cfg(any(test, feature = "native-streams"))]
        {
            reply?.await
        }
        #[cfg(not(any(test, feature = "native-streams")))]
        {
            reply
        }
    }
}
/// A process-owned control surface survives remote channel replacement and outages.
pub(crate) struct Service {
    pub registry: Registry,
    _local: Local,
}
impl Service {
    pub(crate) async fn start(
        state: &Path,
        mode: crate::plugins::ExecutionMode,
        installation: Option<&crate::plugins::Installation>,
    ) -> io::Result<Self> {
        Self::start_inner(
            state,
            mode,
            installation,
            #[cfg(all(feature = "remote", target_os = "linux"))]
            None,
            #[cfg(any(test, feature = "native-streams"))]
            None,
        )
        .await
    }
    #[cfg(all(feature = "remote", target_os = "linux"))]
    pub(crate) async fn start_retained(
        state: &Path,
        installation: Option<&crate::plugins::Installation>,
        lifetime: &mut Option<std::sync::Arc<std::fs::File>>,
    ) -> io::Result<Self> {
        let service = Self::start_inner(
            state,
            crate::plugins::ExecutionMode::Remote,
            installation,
            lifetime.clone(),
            #[cfg(any(test, feature = "native-streams"))]
            None,
        )
        .await?;
        lifetime.clone_from(&service.registry.lifetime);
        Ok(service)
    }
    fn start_inner<'a>(
        state: &'a Path,
        mode: crate::plugins::ExecutionMode,
        installation: Option<&'a crate::plugins::Installation>,
        #[cfg(all(feature = "remote", target_os = "linux"))] lifetime: Option<
            std::sync::Arc<std::fs::File>,
        >,
        #[cfg(any(test, feature = "native-streams"))] supplied: Option<Registry>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Self>> + Send + 'a>> {
        // Startup has one temporary allocation rather than repeating its state
        // machine in embedded and remote dispatch. It is released after startup [243].
        Box::pin(async move {
            #[cfg(all(feature = "remote", target_os = "linux"))]
            let lifetime = if matches!(mode, crate::plugins::ExecutionMode::Remote) {
                let guard = if let Some(guard) = lifetime {
                    infraternal_plugin_remote::runtime_lock::validate(&guard, state)?;
                    guard
                } else {
                    std::sync::Arc::new(if let Some(context) = installation {
                        infraternal_plugin_remote::runtime_lock::acquire_owned(
                            state,
                            &context.host,
                        )?
                    } else {
                        infraternal_plugin_remote::runtime_lock::acquire(state)?
                    })
                };
                crate::sessions::state(Some(state.to_owned()))?;
                Some(guard)
            } else {
                None
            };
            #[cfg(all(feature = "remote", target_os = "macos"))]
            if matches!(mode, crate::plugins::ExecutionMode::Remote) {
                // launchd is the sole supported daemon owner on macOS and serializes starts.
                crate::sessions::state(Some(state.to_owned()))?;
            }
            // Compiled metadata is validated by registry tests; construct its
            // process-owned instances only when a caller needs an action.
            #[cfg(any(
                all(feature = "remote", target_os = "linux"),
                all(feature = "mesh", target_os = "macos")
            ))]
            let installation = installation.cloned();
            #[cfg(not(any(
                all(feature = "remote", target_os = "linux"),
                all(feature = "mesh", target_os = "macos")
            )))]
            let installation = installation.copied();
            #[cfg(any(test, feature = "native-streams"))]
            let registry = supplied
                .unwrap_or_else(|| Registry::for_mode(state.to_owned(), mode, installation));
            #[cfg(not(any(test, feature = "native-streams")))]
            let registry = Registry::for_mode(state.to_owned(), mode, installation);
            // Listener tasks and synchronous workers retain the same ownership even
            // when cancellation has been requested but their work has not stopped.
            #[cfg(all(feature = "remote", target_os = "linux"))]
            let registry = Registry {
                lifetime,
                ..registry
            };
            #[cfg(all(feature = "remote", feature = "mesh", target_os = "macos"))]
            {
                // Restore the local utun and root-only identity before dialing, so startup
                // remains independent of coordinator availability.
                registry
                    .initialize_paths()
                    .await
                    .map_err(|_| io::Error::other("local Mesh registry initialization failed"))?;
            }
            let local = Local::bind(state, registry.clone()).await?;
            Ok(Self {
                registry,
                _local: local,
            })
        })
    }
    #[cfg(any(test, feature = "native-streams"))]
    pub(crate) async fn with_registry(state: &Path, registry: Registry) -> io::Result<Self> {
        Self::start_inner(
            state,
            crate::plugins::ExecutionMode::Remote,
            None,
            #[cfg(all(feature = "remote", target_os = "linux"))]
            None,
            Some(registry),
        )
        .await
    }
}

/// The dispatcher queues a byte-bound action, never waits for kernel work or the CLI.
#[cfg(any(test, not(feature = "native-streams")))]
pub(crate) struct Request {
    pub call_id: u32,
    pub action: String,
    pub input: Vec<u8>,
    pub context: infraternal_plugin_api::admission::NodeContext,
}
/// Aborting the owner stops accepting work; an already-entered bounded kernel transaction may finish.
#[cfg(any(test, not(feature = "native-streams")))]
pub(crate) struct Worker {
    pub sender: mpsc::Sender<Request>,
    task: JoinHandle<()>,
}
#[cfg(any(test, not(feature = "native-streams")))]
impl Worker {
    pub(crate) fn start(
        registry: Registry,
        replies: mpsc::Sender<(
            u32,
            Result<infraternal_plugin_api::ActionReply, PluginError>,
        )>,
    ) -> Self {
        // Each queue entry is at most MAX_ACTION_BYTES; eight entries cost at most 64 KiB.
        let (sender, mut incoming) = mpsc::channel::<Request>(8);
        let task = tokio::spawn(async move {
            while let Some(request) = incoming.recv().await {
                let result = registry
                    .execute(false, request.action, request.input, Some(request.context))
                    .await;
                if replies.send((request.call_id, result)).await.is_err() {
                    break;
                }
            }
        });
        Self { sender, task }
    }
}
#[cfg(any(test, not(feature = "native-streams")))]
impl Drop for Worker {
    fn drop(&mut self) {
        self.task.abort();
    }
}
/// One listener belongs to this daemon connection, never to an individual feature.
pub(crate) struct Local {
    task: JoinHandle<()>,
    path: PathBuf,
    identity: (u64, u64),
}
impl Local {
    pub(crate) async fn bind(path: &Path, registry: Registry) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let uid = nix::unistd::Uid::effective().as_raw();
        let path = path.join("plugins.sock");
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() || meta.uid() != uid {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            match UnixStream::connect(&path).await {
                Ok(_) => return Err(io::ErrorKind::AddrInUse.into()),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) => {}
                Err(error) => return Err(error),
            }
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        let identity = {
            let meta = std::fs::symlink_metadata(&path)?;
            (meta.dev(), meta.ino())
        };
        let state = path.parent().ok_or(io::ErrorKind::InvalidInput)?.to_owned();
        let task = tokio::spawn(async move {
            // Sequential connections bound resources and preserve operator action order.
            while let Ok((mut socket, _)) = listener.accept().await {
                if socket.peer_cred().is_ok_and(|peer| peer.uid() == uid) {
                    // Request framing and reply writes have deadlines in serve.
                    // An accepted transaction owns its completion: kernel RCU
                    // cleanup at scale may outlive a transport framing deadline.
                    let _ = serve(&mut socket, &registry, &state).await;
                }
            }
        });
        Ok(Self {
            task,
            path,
            identity,
        })
    }
}
impl Drop for Local {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        self.task.abort();
        // The pathname may have been replaced while this listener was alive.
        // Retire only its own filesystem inode, never an unrelated replacement.
        if std::fs::symlink_metadata(&self.path).is_ok_and(|meta| {
            meta.file_type().is_socket() && (meta.dev(), meta.ino()) == self.identity
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
// Reuse the frozen mux/action codec rather than introducing a local framing
// parser. Action payload + bounded id + two wire prefixes fit this resource bound.
const LOCAL_WIRE_BYTES: usize = MAX_ACTION_BYTES + 256;
async fn read_one(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut wire = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        match decode_muxed_frame(&wire) {
            Ok(decoded) if decoded.stream_id == 0 && decoded.wire_len == wire.len() => {
                return Ok(wire);
            }
            Err(DecodeError::Incomplete) => {}
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
        let read = socket.read(&mut buffer).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if wire.len() + read > LOCAL_WIRE_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        wire.extend_from_slice(&buffer[..read]);
    }
}
async fn serve(socket: &mut UnixStream, registry: &Registry, state: &Path) -> io::Result<()> {
    // A wholly idle listener has no timer. Once accepted, bound a stalled local request.
    let wire = tokio::time::timeout(std::time::Duration::from_secs(5), read_one(socket))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    let decoded = decode_muxed_frame(&wire).map_err(|_| io::ErrorKind::InvalidData)?;
    let Frame::Call {
        call_id,
        action_id,
        input_json,
    } = decoded.frame
    else {
        return Err(io::ErrorKind::InvalidData.into());
    };
    if action_id.is_empty() || action_id.len() > 128 || input_json.len() > MAX_ACTION_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    #[cfg(target_os = "linux")]
    if let Some(verb) = action_id.strip_prefix("sessions.") {
        let peer = socket.peer_cred()?;
        let pid = peer
            .pid()
            .and_then(|pid| u32::try_from(pid).ok())
            .ok_or(io::ErrorKind::PermissionDenied)?;
        let reply = crate::automation::execute(state, peer.uid(), pid, verb, input_json).await;
        let reply = serde_json::to_vec(&reply)?;
        let mut wire = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Result {
                call_id,
                ok: true,
                json: &reply,
            },
            &mut wire,
        )
        .map_err(|_| io::ErrorKind::InvalidData)?;
        return tokio::time::timeout(std::time::Duration::from_secs(5), socket.write_all(&wire))
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = state;
    let (ok, reply) = match registry
        .call_public(action_id.to_owned(), input_json.to_vec())
        .await
    {
        Ok(reply) => (true, reply),
        Err(_) => (false, b"{\"error\":\"Plugin action refused.\"}".to_vec()),
    };
    let mut reply_wire = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Result {
            call_id,
            ok,
            json: &reply,
        },
        &mut reply_wire,
    )
    .map_err(|_| io::ErrorKind::InvalidData)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.write_all(&reply_wire),
    )
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}

/// Call the running infraternal agent's local public control surface.
/// # Errors
/// Refuses invalid/private-directory ownership, a different peer uid, oversized
/// framing, unavailable daemon or a rejected plugin action. No credentials are read.
pub async fn call(state: &Path, action: &str, input: &[u8]) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    if action.is_empty() || action.len() > 128 || input.len() > MAX_ACTION_BYTES {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let uid = nix::unistd::Uid::effective().as_raw();
    let meta = std::fs::symlink_metadata(state)?;
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut socket = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let mut socket = UnixStream::connect(state.join("plugins.sock")).await?;
        if socket.peer_cred()?.uid() != uid {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut wire = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Call {
                call_id: 1,
                action_id: action,
                input_json: input,
            },
            &mut wire,
        )
        .map_err(|_| io::ErrorKind::InvalidData)?;
        socket.write_all(&wire).await?;
        Ok::<_, io::Error>(socket)
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)??;
    // Waiting for an accepted transaction is event-driven and owns no timer.
    // Once a reply begins, retain the whole-frame deadline against partial input.
    socket.readable().await?;
    let reply = tokio::time::timeout(std::time::Duration::from_secs(5), read_one(&mut socket))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    let decoded = decode_muxed_frame(&reply).map_err(|_| io::ErrorKind::InvalidData)?;
    match decoded.frame {
        Frame::Result {
            call_id: 1,
            ok: true,
            json,
        } if json.len() <= MAX_ACTION_BYTES => Ok(json.to_vec()),
        Frame::Result {
            call_id: 1,
            ok: false,
            ..
        } => Err(io::ErrorKind::PermissionDenied.into()),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

const MAX_PENDING: usize = 32;
#[cfg(any(test, feature = "native-streams"))]
pub(crate) struct Control {
    registry: Registry,
    jobs: tokio::task::JoinSet<(
        u32,
        Result<infraternal_plugin_api::ActionReply, PluginError>,
    )>,
}
#[cfg(any(test, feature = "native-streams"))]
impl Control {
    pub(crate) fn new(registry: Registry) -> Self {
        Self {
            registry,
            jobs: tokio::task::JoinSet::new(),
        }
    }
    #[cfg(not(any(test, feature = "native-streams")))]
    #[allow(clippy::unused_self)]
    pub(crate) fn capabilities(&self, _: u64) {}
    #[cfg(any(test, feature = "native-streams"))]
    pub(crate) fn capabilities(&self, caps: u64) {
        self.registry.capabilities(caps);
    }
    pub(crate) fn pending(&self) -> bool {
        !self.jobs.is_empty()
    }
    pub(crate) fn start(
        &mut self,
        id: u32,
        action: &str,
        input: &[u8],
        context: infraternal_plugin_api::admission::NodeContext,
    ) -> Result<Option<infraternal_plugin_api::ActionReply>, PluginError> {
        // Validate borrowed framing before copying into the bounded task queue.
        if action.len() > 128 || input.len() > MAX_ACTION_BYTES {
            return Err(PluginError::MessageTooLarge);
        }
        if self.jobs.len() >= MAX_PENDING {
            return Err(PluginError::Rejected);
        }
        let registry = self.registry.clone();
        let action = action.to_owned();
        let input = input.to_owned();
        // Kernel work stays with the process worker; owned native I/O runs off dispatch.
        self.jobs.spawn(async move {
            (
                id,
                registry.execute(false, action, input, Some(context)).await,
            )
        });
        Ok(None)
    }
    pub(crate) async fn completed(
        &mut self,
    ) -> io::Result<(
        u32,
        Result<infraternal_plugin_api::ActionReply, PluginError>,
    )> {
        self.jobs
            .join_next()
            .await
            .ok_or_else(|| io::Error::other("Plugin control work is unavailable."))?
            .map_err(io::Error::other)
    }
}

#[cfg(not(any(test, feature = "native-streams")))]
pub(crate) type Control = TerminalControl;

/// Terminal-only dispatch retains the original bounded sleeping worker and reply channel.
#[cfg(any(test, not(feature = "native-streams")))]
pub(crate) struct TerminalControl {
    worker: Worker,
    replies: mpsc::Receiver<(
        u32,
        Result<infraternal_plugin_api::ActionReply, PluginError>,
    )>,
    pending: usize,
}
#[cfg(any(test, not(feature = "native-streams")))]
impl TerminalControl {
    pub(crate) fn new(registry: Registry) -> Self {
        let (send, replies) = mpsc::channel(8);
        Self {
            worker: Worker::start(registry, send),
            replies,
            pending: 0,
        }
    }
    // No native provider exists in this build, so capability changes carry no work.
    #[allow(clippy::unused_self)]
    pub(crate) fn capabilities(&self, _: u64) {}
    pub(crate) fn pending(&self) -> bool {
        self.pending != 0
    }
    pub(crate) fn start(
        &mut self,
        call_id: u32,
        action: &str,
        input: &[u8],
        context: infraternal_plugin_api::admission::NodeContext,
    ) -> Result<Option<infraternal_plugin_api::ActionReply>, PluginError> {
        if action.len() > 128 || input.len() > MAX_ACTION_BYTES {
            return Err(PluginError::MessageTooLarge);
        }
        if self.pending >= MAX_PENDING {
            return Err(PluginError::Rejected);
        }
        self.worker
            .sender
            .try_send(Request {
                call_id,
                action: action.to_owned(),
                input: input.to_owned(),
                context,
            })
            .map_err(|_| PluginError::Rejected)?;
        self.pending += 1;
        Ok(None)
    }
    pub(crate) async fn completed(
        &mut self,
    ) -> io::Result<(
        u32,
        Result<infraternal_plugin_api::ActionReply, PluginError>,
    )> {
        let reply = self
            .replies
            .recv()
            .await
            .ok_or_else(|| io::Error::other("Plugin control work is unavailable."))?;
        self.pending -= 1;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    //! Exercises worker isolation, public call bounds and reply-owned effects.
    use super::*;
    use infraternal_plugin_api::{ActionDef, AgentPlugin, Effect, PluginDescriptor, SchemaRef};
    const READ: &[ActionDef] = &[ActionDef {
        id: "fixture.read",
        summary: "Read fixture state",
        input: SchemaRef("Empty"),
        output: SchemaRef("Empty"),
        effect: Effect::Read,
        instructions: &["Read fixture state."],
        permission: infraternal_plugin_api::Permission::One("fixture.read"),
        target: infraternal_plugin_api::Target::Node,
        dry_run: infraternal_plugin_api::DryRun::Unsupported,
        opens: None,
        api_scope: None,
        fresh_passkey: false,
    }];
    const CONTROL: &[ActionDef] = &[ActionDef {
        id: "fixture.control",
        ..READ[0]
    }];
    const DESCRIPTOR: PluginDescriptor = PluginDescriptor {
        id: "fixture",
        api: infraternal_plugin_api::API_VERSION,
        actions: READ,
        topics: &[],
        settings: None,
        events: &[],
        streams: &[],
        defaults: &[],
        dependencies: &[],
        can_enable_components: &[],
        roles: &[],
        max_frame_len: MAX_ACTION_BYTES,
        unavailable: b"{}",
        unavailable_event: b"{}",
    };
    #[tokio::test]
    async fn control_rejects_oversized_calls_before_starting_jobs() {
        let (registry, _, _) = registry();
        let mut control = Control::new(registry);
        let context = infraternal_plugin_api::admission::NodeContext::default();
        for (action, input) in [
            ("x".repeat(129), b"{}".to_vec()),
            ("fixture.read".to_owned(), vec![b' '; MAX_ACTION_BYTES + 1]),
        ] {
            assert!(matches!(
                control.start(1, &action, &input, context),
                Err(PluginError::MessageTooLarge)
            ));
            assert!(
                !control.pending(),
                "invalid framing must not retain task-owned input"
            );
        }
    }
    #[tokio::test]
    async fn terminal_control_bounds_work_and_drains_fifo_without_native_tasks() {
        let (registry, started, release) = registry();
        let mut control = TerminalControl::new(registry);
        control.capabilities(0);
        let context = infraternal_plugin_api::admission::NodeContext::default();
        assert!(
            control
                .start(1, "fixture.control", br#"{"hold":true}"#, context)
                .unwrap()
                .is_none()
        );
        tokio::time::timeout(std::time::Duration::from_secs(3), started.notified())
            .await
            .unwrap();
        for id in 2..=9 {
            assert!(
                control
                    .start(id, "fixture.control", b"{}", context)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(matches!(
            control.start(10, "fixture.control", b"{}", context),
            Err(PluginError::Rejected)
        ));
        assert!(matches!(
            control.start(11, &"x".repeat(129), b"{}", context),
            Err(PluginError::MessageTooLarge)
        ));
        release.send(()).unwrap();
        for id in 1..=9 {
            assert!(control.pending());
            let (received, reply) =
                tokio::time::timeout(std::time::Duration::from_secs(3), control.completed())
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(received, id);
            assert!(reply.is_ok());
        }
        assert!(!control.pending());
    }
    struct Echo {
        started: std::sync::Arc<tokio::sync::Notify>,
        release: std::sync::mpsc::Receiver<()>,
    }
    impl AgentPlugin for Echo {
        fn descriptor(&self) -> &'static PluginDescriptor {
            &DESCRIPTOR
        }
        fn control_actions(&self) -> &'static [ActionDef] {
            CONTROL
        }
        fn call(&mut self, _: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
            if input == b"{\"hold\":true}" {
                self.started.notify_one();
                self.release
                    .recv_timeout(std::time::Duration::from_secs(30))
                    .map_err(|_| PluginError::Rejected)?;
            }
            Ok(input.to_vec())
        }
    }
    fn registry() -> (
        Registry,
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::mpsc::Sender<()>,
    ) {
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let (release, receive) = std::sync::mpsc::channel();
        let mut registry = PluginRegistry::default();
        registry
            .register(Box::new(Echo {
                started: started.clone(),
                release: receive,
            }))
            .unwrap();
        (Registry::new(registry), started, release)
    }
    struct Deferred {
        completed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        context: infraternal_plugin_api::admission::NodeContext,
    }
    impl AgentPlugin for Deferred {
        fn descriptor(&self) -> &'static PluginDescriptor {
            &DESCRIPTOR
        }
        fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
            Err(PluginError::Rejected)
        }
        fn update_context(&mut self, context: infraternal_plugin_api::admission::NodeContext) {
            self.context = context;
        }
        fn call_with_reply(
            &mut self,
            _: &str,
            _: &[u8],
        ) -> Result<infraternal_plugin_api::ActionReply, PluginError> {
            let completed = self.completed.clone();
            Ok(infraternal_plugin_api::ActionReply {
                json: format!("{{\"sessions\":{}}}", self.context.session_count).into_bytes(),
                after_write: Some(Box::new(move || {
                    completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                })),
            })
        }
    }
    #[tokio::test]
    async fn worker_preserves_trusted_context_and_writer_owned_effect() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let completed = Arc::new(AtomicUsize::new(0));
        let mut plugins = PluginRegistry::default();
        plugins
            .register(Box::new(Deferred {
                completed: completed.clone(),
                context: infraternal_plugin_api::admission::NodeContext::default(),
            }))
            .unwrap();
        let registry = Registry::new(plugins);
        let (replies, mut receive) = mpsc::channel(1);
        let worker = Worker::start(registry, replies);
        for attempt in 0..2 {
            worker
                .sender
                .send(Request {
                    call_id: attempt,
                    action: "fixture.read".into(),
                    input: b"{}".to_vec(),
                    context: infraternal_plugin_api::admission::NodeContext {
                        session_count: 200,
                        background_session_count: 199,
                    },
                })
                .await
                .unwrap();
            let (_, result) = receive.recv().await.unwrap();
            let mut reply = result.unwrap();
            assert_eq!(reply.json, b"{\"sessions\":200}");
            assert_eq!(completed.load(Ordering::SeqCst), 0);
            if attempt == 1 {
                reply.after_write.take().unwrap()();
            }
            // Dropping the first unwritten response cancels its effect.
        }
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }
    struct Admission(bool);
    impl AgentPlugin for Admission {
        fn descriptor(&self) -> &'static PluginDescriptor {
            &DESCRIPTOR
        }
        fn call(&mut self, _: &str, _: &[u8]) -> Result<Vec<u8>, PluginError> {
            self.0 = true;
            Ok(b"{}".to_vec())
        }
        fn admit(
            &self,
            _: &str,
            context: infraternal_plugin_api::admission::NodeContext,
        ) -> Result<(), infraternal_plugin_api::admission::OpenRefusal> {
            if self.0 {
                Err(
                    infraternal_plugin_api::admission::OpenRefusal::HostMemoryLow {
                        available_mib: 0,
                        session_count: context.session_count,
                    },
                )
            } else {
                Ok(())
            }
        }
    }
    #[tokio::test]
    async fn admission_observes_the_same_plugin_settings_as_actions() {
        use infraternal_plugin_api::admission::{NodeContext, OpenRefusal};
        let mut plugins = PluginRegistry::default();
        plugins.register(Box::new(Admission(false))).unwrap();
        let registry = Registry::new(plugins);
        let context = NodeContext {
            session_count: 200,
            background_session_count: 199,
        };
        assert_eq!(registry.admit("terminal.open", context).await, Ok(()));
        registry
            .call_public("fixture.read".into(), b"{}".to_vec())
            .await
            .unwrap();
        assert_eq!(
            registry.admit("terminal.open", context).await,
            Err(OpenRefusal::HostMemoryLow {
                available_mib: 0,
                session_count: 200
            })
        );
    }

    struct ProposedPath {
        destination: Option<std::net::IpAddr>,
        link: infraternal_plugin_api::server_path::ServerLink,
    }
    impl AgentPlugin for ProposedPath {
        fn descriptor(&self) -> &'static PluginDescriptor {
            &DESCRIPTOR
        }
        fn preferred_server(&self) -> Option<std::net::IpAddr> {
            self.destination
        }
        fn set_server_link(&mut self, link: &infraternal_plugin_api::server_path::ServerLink) {
            self.link = link.clone();
        }
        fn call(&mut self, _: &str, input: &[u8]) -> Result<Vec<u8>, PluginError> {
            if input == b"null" {
                self.destination = None;
            }
            serde_json::to_vec(&self.link).map_err(|_| PluginError::Rejected)
        }
    }
    #[tokio::test]
    async fn retained_path_and_observed_transport_cross_the_lazy_worker() {
        use infraternal_plugin_api::server_path::{ServerLink, ServerLinkKind, ServerLinkReason};
        let mut plugins = PluginRegistry::default();
        plugins
            .register(Box::new(ProposedPath {
                destination: Some("10.254.0.1".parse().unwrap()),
                link: ServerLink::default(),
            }))
            .unwrap();
        let registry = Registry::new(plugins);
        let mut paths = registry.server_paths();
        let observed = ServerLink {
            kind: ServerLinkKind::Fallback,
            endpoint: Some("127.0.0.1:7443".parse().unwrap()),
            source_port: None,
            reason: ServerLinkReason::MeshRefused,
        };
        registry.set_server_link(observed.clone());
        assert!(
            registry.pending.lock().unwrap().is_some(),
            "transport observation cannot start kernel work"
        );
        registry.initialize_paths().await.unwrap();
        assert_eq!(
            *paths.borrow_and_update(),
            Some("10.254.0.1".parse().unwrap())
        );
        let output = registry
            .call("fixture.read".into(), b"{}".to_vec())
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<ServerLink>(&output).unwrap(),
            observed
        );
        assert!(
            !paths.has_changed().unwrap(),
            "an unchanged path cannot cause a replacement loop"
        );
        registry
            .call("fixture.read".into(), b"null".to_vec())
            .await
            .unwrap();
        paths.changed().await.unwrap();
        assert!(paths.borrow_and_update().is_none());
    }
    /// Compile-out builds admit terminals without creating a worker for an empty catalog.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn empty_catalog_preserves_control_contract_without_an_os_worker() {
        // This case belongs to the no-default-features build; populated catalogs
        // retain the generic policy worker and its independent fixture coverage.
        if !crate::plugins::descriptors().is_empty() {
            return;
        }
        let worker_threads = || {
            std::fs::read_dir("/proc/self/task")
                .unwrap()
                .filter_map(|entry| {
                    let entry = entry.unwrap();
                    match std::fs::read_to_string(entry.path().join("comm")) {
                        Ok(name) if name.trim() == "node-plugins" => Some(entry.file_name()),
                        Ok(_) => None,
                        // A previously dropped fixture worker may finish while
                        // enumerating. Its disappearance cannot create a new id.
                        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                        Err(error) => panic!("could not observe plugin worker ownership: {error}"),
                    }
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        let before = worker_threads();
        let registry = Registry::for_mode(
            PathBuf::from("unused-empty-catalog-state"),
            crate::plugins::ExecutionMode::Remote,
            None,
        );
        let mut events = registry.subscribe();
        assert_eq!(
            registry
                .admit(
                    "terminal.open",
                    infraternal_plugin_api::admission::NodeContext::default(),
                )
                .await,
            Ok(())
        );
        for public in [false, true] {
            assert!(matches!(
                registry
                    .execute(public, "unknown.read".into(), b"{}".to_vec(), None)
                    .await,
                Err(PluginError::UnknownAction)
            ));
        }
        assert!(matches!(
            registry
                .execute(
                    false,
                    "unknown.read".into(),
                    vec![0; MAX_ACTION_BYTES + 1],
                    None
                )
                .await,
            Err(PluginError::MessageTooLarge)
        ));
        assert!(matches!(
            registry
                .execute(false, "x".repeat(129), b"{}".to_vec(), None)
                .await,
            Err(PluginError::MessageTooLarge)
        ));
        registry.initialize_paths().await.unwrap();
        assert!(registry.server_paths().borrow().is_none());
        assert!(
            matches!(
                events.try_recv(),
                Err(tokio::sync::broadcast::error::TryRecvError::Empty)
            ),
            "an empty catalog retains an open, silent event channel"
        );
        let after = worker_threads();
        assert!(
            after.is_subset(&before),
            "an empty catalog started a node-plugins OS worker: {:?}",
            after.difference(&before).collect::<Vec<_>>()
        );
    }

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            let parent = PathBuf::from(
                std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()),
            )
            .join("ipc");
            std::fs::create_dir_all(&parent).unwrap();
            // UUID hex is ASCII; a short suffix leaves room for the kernel Unix-socket path bound.
            let id = uuid::Uuid::new_v4().simple().to_string();
            let path = parent.join(&id[..12]);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[cfg(all(feature = "remote", feature = "mesh", target_os = "macos"))]
    #[tokio::test]
    async fn macos_remote_service_constructs_mesh_registry_before_returning() {
        let directory = Directory::new();
        let constructed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = std::sync::Arc::clone(&constructed);
        let factory: std::sync::Arc<dyn Fn() -> Result<PluginRegistry, PluginError> + Send + Sync> =
            std::sync::Arc::new(move || {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(PluginRegistry::default())
            });

        TEST_FACTORY
            .scope(factory, async {
                let service =
                    Service::start(&directory.0, crate::plugins::ExecutionMode::Remote, None)
                        .await
                        .expect("start the macOS remote service");
                assert!(
                    constructed.load(std::sync::atomic::Ordering::SeqCst),
                    "the mesh registry must restore the local node before remote dialing"
                );
                drop(service);
            })
            .await;
    }
    #[cfg(all(feature = "remote", feature = "mesh", target_os = "macos"))]
    #[test]
    fn macos_remote_registry_contains_the_mesh_node_descriptor() {
        assert!(
            crate::plugins::descriptors()
                .iter()
                .any(|descriptor| descriptor.id == "mesh")
        );
    }
    #[cfg(all(feature = "remote", target_os = "linux"))]
    #[tokio::test]
    #[allow(
        clippy::used_underscore_binding,
        reason = "Await the endpoint owner's actual cancellation in this lifecycle test."
    )]
    async fn retained_runtime_registry_keeps_lifetime_ownership_after_listener_abort() {
        let directory = Directory::new();
        let service = Service::start(&directory.0, crate::plugins::ExecutionMode::Remote, None)
            .await
            .unwrap();
        let retained = service.registry.clone();
        let stopped = service._local.task.abort_handle();
        let probe = std::fs::File::open(
            directory
                .0
                .join(infraternal_plugin_remote::runtime_lock::LOCK),
        )
        .unwrap();
        drop(service);
        tokio::task::yield_now().await;
        assert!(
            probe.try_lock().is_err(),
            "retained runtime work lost its lifetime lock"
        );
        drop(retained);
        // Listener completion alone does not observe the lock's release. Keep
        // the existing bound around the externally visible cleanup condition.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !stopped.is_finished() || probe.try_lock().is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        // Listener cancellation joins only its async owner. The synchronous
        // worker also retains ownership until its receiver and registry retire.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while probe.try_lock().is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn synchronous_plugin_work_does_not_park_the_current_thread_reactor() {
        let (registry, started, release) = registry();
        let call = tokio::spawn(async move {
            registry
                .call("fixture.read".into(), b"{\"hold\":true}".to_vec())
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        release.send(()).unwrap();
        assert!(call.await.unwrap().is_ok());
    }
    #[tokio::test]
    async fn accepted_public_transaction_outlives_the_framing_deadline() {
        let directory = Directory::new();
        let (registry, started, release) = registry();
        let _local = Local::bind(&directory.0, registry).await.unwrap();
        let path = directory.0.clone();
        let pending =
            tokio::spawn(async move { call(&path, "fixture.read", b"{\"hold\":true}").await });
        tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
            .await
            .unwrap();
        // A valid accepted operation may wait for kernel cleanup. Its framing
        // deadline cannot turn successful completion into an apparent refusal.
        tokio::time::sleep(std::time::Duration::from_secs(11)).await;
        let remained_pending = !pending.is_finished();
        release.send(()).unwrap();
        let result = pending.await.unwrap();
        assert!(
            remained_pending,
            "accepted transaction timed out before completion"
        );
        assert_eq!(result.unwrap(), b"{\"hold\":true}");
    }
    #[tokio::test]
    async fn local_public_actions_refuse_controls_and_active_socket_replacement() {
        let directory = Directory::new();
        let (registry, _, _) = registry();
        let local = Local::bind(&directory.0, registry.clone()).await.unwrap();
        assert!(Local::bind(&directory.0, registry).await.is_err());
        assert_eq!(
            call(&directory.0, "fixture.read", b"{}").await.unwrap(),
            b"{}"
        );
        assert_eq!(
            call(&directory.0, "fixture.control", b"{}")
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            call(
                &directory.0,
                "fixture.read",
                &vec![b' '; MAX_ACTION_BYTES + 1]
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
        drop(local);
        assert!(!directory.0.join("plugins.sock").exists());
    }
    #[tokio::test]
    async fn local_frame_reader_retains_fragmentation_and_refuses_trailing_frames() {
        let (mut send, mut receive) = UnixStream::pair().unwrap();
        let mut wire = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Call {
                call_id: 1,
                action_id: "fixture.read",
                input_json: &vec![b' '; 2048],
            },
            &mut wire,
        )
        .unwrap();
        let expected = wire.clone();
        let receiver = tokio::spawn(async move { read_one(&mut receive).await });
        for part in wire.chunks(7) {
            send.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
        assert_eq!(receiver.await.unwrap().unwrap(), expected);
        let (mut send, mut receive) = UnixStream::pair().unwrap();
        let mut two = Vec::new();
        encode_muxed_frame_into(
            0,
            &Frame::Call {
                call_id: 1,
                action_id: "fixture.read",
                input_json: b"{}",
            },
            &mut two,
        )
        .unwrap();
        let other = two.clone();
        two.extend_from_slice(&other);
        send.write_all(&two).await.unwrap();
        assert!(read_one(&mut receive).await.is_err());
    }
    #[tokio::test]
    async fn dropping_a_listener_does_not_unlink_a_replacement_file() {
        let directory = Directory::new();
        let (registry, _, _) = registry();
        let local = Local::bind(&directory.0, registry).await.unwrap();
        let path = directory.0.join("plugins.sock");
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"unrelated").unwrap();
        drop(local);
        assert_eq!(std::fs::read(&path).unwrap(), b"unrelated");
    }
}
