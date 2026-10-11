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
    sender: mpsc::Sender<Job>,
    events: tokio::sync::broadcast::Sender<Vec<u8>>,
    pending: std::sync::Arc<std::sync::Mutex<Option<PendingWorker>>>,
}
type Factory = Box<dyn FnOnce() -> Result<PluginRegistry, PluginError> + Send>;
struct PendingWorker {
    factory: Factory,
    incoming: mpsc::Receiver<Job>,
}
struct Job {
    public: bool,
    action: String,
    input: Vec<u8>,
    result: tokio::sync::oneshot::Sender<Result<Vec<u8>, PluginError>>,
}
impl Registry {
    #[cfg(test)]
    pub(crate) fn new(registry: PluginRegistry) -> Self {
        Self::from_factory(Box::new(move || Ok(registry)))
    }
    fn for_mode(state: PathBuf, mode: crate::plugins::ExecutionMode) -> Self {
        Self::from_factory(Box::new(move || {
            crate::plugins::registry_at(mode, Some(&state))
        }))
    }
    fn from_factory(factory: Factory) -> Self {
        let (sender, incoming) = mpsc::channel::<Job>(8);
        let (events, _) = tokio::sync::broadcast::channel(8);
        Self {
            sender,
            events,
            pending: std::sync::Arc::new(std::sync::Mutex::new(Some(PendingWorker {
                factory,
                incoming,
            }))),
        }
    }
    fn start(&self) -> Result<(), PluginError> {
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
            std::thread::Builder::new()
                .name("node-plugins".into())
                .spawn(move || {
                    let Ok(mut registry) = factory() else {
                        return;
                    };
                    while let Some(job) = incoming.blocking_recv() {
                        let result = if job.public {
                            registry.call_public(&job.action, &job.input)
                        } else {
                            registry.call(&job.action, &job.input)
                        };
                        if result.is_ok()
                            && let Ok(events) = registry.events()
                        {
                            for event in events {
                                let _ = notifications.send(event);
                            }
                        }
                        let _ = job.result.send(result);
                    }
                })
                .map_err(|_| PluginError::Rejected)?;
        }
        Ok(())
    }
    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Vec<u8>> {
        self.events.subscribe()
    }
    pub(crate) async fn call(
        &self,
        action: String,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, PluginError> {
        self.execute(false, action, input).await
    }
    async fn call_public(&self, action: String, input: Vec<u8>) -> Result<Vec<u8>, PluginError> {
        self.execute(true, action, input).await
    }
    async fn execute(
        &self,
        public: bool,
        action: String,
        input: Vec<u8>,
    ) -> Result<Vec<u8>, PluginError> {
        if input.len() > MAX_ACTION_BYTES || action.len() > 128 {
            return Err(PluginError::MessageTooLarge);
        }
        self.start()?;
        let (result, receive) = tokio::sync::oneshot::channel();
        self.sender
            .try_send(Job {
                public,
                action,
                input,
                result,
            })
            .map_err(|_| PluginError::Rejected)?;
        receive.await.map_err(|_| PluginError::Rejected)?
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
    ) -> io::Result<Self> {
        // Compiled metadata is validated by registry tests; construct its
        // process-owned instances only when a caller needs an action.
        let registry = Registry::for_mode(state.to_owned(), mode);
        let local = Local::bind(state, registry.clone()).await?;
        Ok(Self {
            registry,
            _local: local,
        })
    }
}
/// The dispatcher queues a byte-bound action, never waits for kernel work or the CLI.
pub(crate) struct Request {
    pub call_id: u32,
    pub action: String,
    pub input: Vec<u8>,
}
/// Aborting the owner stops accepting work; an already-entered bounded kernel transaction may finish.
pub(crate) struct Worker {
    pub sender: mpsc::Sender<Request>,
    task: JoinHandle<()>,
}
impl Worker {
    pub(crate) fn start(
        registry: Registry,
        replies: mpsc::Sender<(u32, Result<Vec<u8>, PluginError>)>,
    ) -> Self {
        // Each queue entry is at most MAX_ACTION_BYTES; eight entries cost at most 64 KiB.
        let (sender, mut incoming) = mpsc::channel::<Request>(8);
        let task = tokio::spawn(async move {
            while let Some(request) = incoming.recv().await {
                let result = registry.call(request.action, request.input).await;
                if replies.send((request.call_id, result)).await.is_err() {
                    break;
                }
            }
        });
        Self { sender, task }
    }
}
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
        let task = tokio::spawn(async move {
            // Sequential connections bound resources and preserve operator action order.
            while let Ok((mut socket, _)) = listener.accept().await {
                if socket.peer_cred().is_ok_and(|peer| peer.uid() == uid) {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        serve(&mut socket, &registry),
                    )
                    .await;
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
async fn serve(socket: &mut UnixStream, registry: &Registry) -> io::Result<()> {
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
    socket.write_all(&reply_wire).await
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
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
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
        let reply = read_one(&mut socket).await?;
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
    })
    .await
    .map_err(|_| io::ErrorKind::TimedOut)?
}

#[cfg(test)]
mod tests {
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
                    .recv_timeout(std::time::Duration::from_secs(5))
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
