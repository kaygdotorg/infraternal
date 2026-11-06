//! Secure rendezvous discovery and init-independent shim launch [9][13][18].
//!
//! Discovery recovers every live socket with bounded concurrent handshakes, each
//! with a two-second handshake deadline; a nonresponsive shim cannot serialize
//! recovery of healthy sessions. Only refused sockets are removed as stale.
//! Launching a shim is process creation, not a handshake: it fails when the
//! launcher exits first, and only a hung start meets the longer launch bound.

use infraternal_shim::frame::{
    APPROXIMATE_SNAPSHOT, Frame, FrameRef, MAX_FRAME, MULTI_WRITER, SEQUENCED_INPUT, SHARED_WRITER,
};
use infraternal_shim::readiness::Registration;
#[cfg(target_os = "linux")]
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify};
use nix::unistd::Uid;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    process::Command,
    task::JoinSet,
    time::timeout,
};

// A malformed shim can require MAX_FRAME receive bytes. Limit recovery work
// to 32 MiB while allowing any number of live sessions (D214).
const DISCOVERY_HANDSHAKES: usize = 32 * 1024 * 1024 / MAX_FRAME;
const HANDSHAKE: Duration = Duration::from_secs(2);
// Starting a process through the init manager is not a handshake. On a loaded
// host the scope, exec and shim startup took 3.5-5.1 s before a shim could
// bind (#324); HANDSHAKE refused launches that were still progressing, and
// their shells kept running. Process exit is the progress signal; this bound
// only detects a hang, well inside the server's 60 s connect budget (#29).
// The same bound applies to macOS shims (#328).
const LAUNCH: Duration = Duration::from_secs(30);
/// How long a failed launch keeps trying to reach the detached shim it started. A shim that missed its
/// Hello is slow rather than gone, and one that binds late has no socket yet, so cleanup waits for it
/// here, on its own bound, after the caller has stopped waiting.
#[cfg(target_os = "linux")]
const CLEANUP: Duration = Duration::from_secs(10);
/// The cleanup budget when the runtime is already shutting down: the process is stopping, so wait less.
#[cfg(target_os = "linux")]
const SHUTDOWN_CLEANUP: Duration = Duration::from_secs(2);
/// What one cleanup may spend. `retry` bounds waiting for a shim to bind or to answer; `total` bounds the
/// whole cleanup, every inner wait included, so no nesting of handshakes can outlast it.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct Budget {
    /// How long to keep asking a shim to close while it binds or answers.
    retry: Duration,
    /// The hard bound on the whole cleanup.
    total: Duration,
}
/// A cleanup on a running runtime: the retry window, then the close and the exit observation.
#[cfg(target_os = "linux")]
const NORMAL: Budget = Budget {
    retry: CLEANUP,
    total: Duration::from_secs(14),
};
/// A cleanup run by `Abandoned::drop` while the process is stopping.
#[cfg(target_os = "linux")]
const SHUTDOWN: Budget = Budget {
    retry: SHUTDOWN_CLEANUP,
    total: SHUTDOWN_CLEANUP,
};
/// How long a stopping infraternal agent waits for launch cleanups still running.
#[cfg(target_os = "linux")]
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(4);

/// The hang bound for one launch, on every platform. Linux tests shorten it per thread to reach the failure path.
fn launch_bound() -> Duration {
    #[cfg(all(test, target_os = "linux"))]
    if let Some(bound) = tests::LAUNCH_BOUND.with(std::cell::Cell::get) {
        return bound;
    }
    LAUNCH
}

/// How long manager detection may wait for `systemctl show-environment`.
///
/// Release builds always use [`HANDSHAKE`] (2 s). Debug builds let an
/// integration oracle widen it with `INFRATERNAL_TEST_MANAGER_PROBE_BUDGET_MS`,
/// because the lazy-manager oracle holds the probe on purpose until it has seen
/// the daemon answer Hello and Pong. On a contended build host a debug daemon
/// can take longer than 2 s to get there, and the deadline then killed the held
/// probe before the oracle could check it (#355). This is the same seam as the
/// status crate's `INFRATERNAL_TEST_MANAGER_QUERY_BUDGET_MS` (#334).
#[cfg(target_os = "linux")]
fn manager_probe_budget() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(milliseconds) = std::env::var("INFRATERNAL_TEST_MANAGER_PROBE_BUDGET_MS")
        .ok()
        .and_then(|value| value.parse().ok())
    {
        return Duration::from_millis(milliseconds);
    }
    HANDSHAKE
}

/// Init manager selected once for session work, never periodically re-probed.
#[derive(Clone, Copy, Debug)]
pub enum Manager {
    System,
    User,
    Detached,
}

impl Manager {
    /// A shim needs direct exec for a live login or the kernel self-image;
    /// choosing its launcher must not replace the host login backend.
    pub(crate) fn for_shim(self, exe: &Path, login: bool) -> Self {
        if login || exe == Path::new("/proc/self/exe") {
            Self::Detached
        } else {
            self
        }
    }

    /// The manager for this launch. `cell` keeps only a probe that answered;
    /// a probe that timed out stands for this launch alone.
    pub async fn resolve(cell: &tokio::sync::OnceCell<Self>) -> Self {
        Self::resolve_with(cell, Self::probe).await
    }

    /// `resolve` with the probe supplied, so a test can stall or answer it without a service manager.
    pub(crate) async fn resolve_with<F, Fut>(cell: &tokio::sync::OnceCell<Self>, probe: F) -> Self
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<Self>>,
    {
        // `get_or_try_init` serializes concurrent first launches and leaves the
        // cell empty on `Err`, so the next launch probes again.
        cell.get_or_try_init(|| async { probe().await.ok_or(()) })
            .await
            .copied()
            .unwrap_or(Self::Detached)
    }

    /// Probe the applicable manager without trusting environment hints alone.
    /// `None` means no answer within the probe budget; a refusal is an answer.
    // launchd has no transient scopes: macOS shims always detach themselves.
    #[cfg_attr(
        target_os = "macos",
        allow(clippy::unused_async, clippy::unused_async_trait_impl)
    )]
    pub async fn probe() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            Some(Self::Detached)
        }
        #[cfg(target_os = "linux")]
        {
            let root = Uid::effective().is_root();
            let mut command = isolated(Path::new("systemctl"));
            if !root {
                command.arg("--user");
            }
            let available = timeout(
                manager_probe_budget(),
                command
                    .arg("show-environment")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .kill_on_drop(true)
                    .status(),
            )
            .await;
            match available {
                Err(_) => None,
                Ok(Ok(status)) if status.success() => {
                    Some(if root { Self::System } else { Self::User })
                }
                Ok(_) => Some(Self::Detached),
            }
        }
    }
}

/// The session identity and its sole authenticated local shim connection.
/// The caller must issue `ReadFrom` and drain frames, or disconnect: an attached
/// shim intentionally backpressures the PTY until its reader makes progress.
pub struct Session {
    pub id: [u8; 16],
    pub path: PathBuf,
    pub peer: UnixStream,
    pub head: u64,
    /// Authoritative screen geometry at the Hello capture, before this peer resizes.
    pub size: (u16, u16),
    pub pid: u32,
    /// Selected capabilities, never inferred from the binary version.
    pub caps: u64,
    /// Advertised ownership support; data Attach never selects this bit.
    pub supports_owner: bool,
}

/// Reusable receive storage, bounded by the frozen shim frame limit.
#[derive(Default)]
pub struct Reader {
    bytes: Vec<u8>,
    prefix: [u8; 4],
    prefix_read: usize,
    received: usize,
}
impl Reader {
    /// Receive one frame using the shim's codec; no framing is duplicated.
    /// # Errors
    /// Returns truncated, oversized or malformed frame errors.
    pub async fn read(&mut self, peer: &mut UnixStream) -> io::Result<Frame> {
        Ok(self.read_ref(peer).await?.into_owned())
    }

    /// Receive a borrowed payload valid until the next read. Frame-scoped
    /// consumers avoid an allocation; writer queues still require ownership.
    /// # Errors
    /// Returns the same framing and IO failures as `read`.
    pub async fn read_ref(&mut self, peer: &mut UnixStream) -> io::Result<FrameRef<'_>> {
        // read() is cancellation safe; counters live in Reader so selecting a
        // control request while a fragmented shim frame arrives loses no bytes.
        while self.prefix_read < self.prefix.len() {
            let n = peer.read(&mut self.prefix[self.prefix_read..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.prefix_read += n;
        }
        let size = u32::from_le_bytes(self.prefix) as usize;
        if size == 0 || size > MAX_FRAME {
            return Err(invalid("invalid shim length"));
        }
        self.bytes.resize(size, 0);
        while self.received < size {
            let n = peer.read(&mut self.bytes[self.received..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.received += n;
        }
        let frame = FrameRef::decode(&self.bytes)?;
        self.prefix_read = 0;
        self.received = 0;
        Ok(frame)
    }
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Send through the frozen shim codec.
/// # Errors
/// Returns codec or socket errors; callers bound outstanding sends to one frame.
pub async fn send(peer: &mut UnixStream, frame: &Frame) -> io::Result<()> {
    peer.write_all(&frame.encode()?).await
}

fn private(path: &Path) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != Uid::effective().as_raw() || meta.mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "infraternal session directory must be owned by the current uid with mode 0700",
        ));
    }
    Ok(())
}

/// Resolve the existing runtime location without creating directories for read-only CLI calls.
/// # Errors
/// Rejects absent/unsafe rootless runtime directories and insecure state paths.
pub fn state_path(path: Option<PathBuf>) -> io::Result<PathBuf> {
    let path = if let Some(path) = path {
        path
    } else if Uid::effective().is_root() {
        // Root runtime state that the OS clears at boot: /run on Linux,
        // /var/run (/private/var/run) on macOS, which has no /run.
        PathBuf::from(if cfg!(target_os = "macos") {
            "/var/run/infraternal"
        } else {
            "/run/infraternal"
        })
    } else {
        let runtime = PathBuf::from(
            std::env::var_os("XDG_RUNTIME_DIR")
                .ok_or_else(|| invalid("rootless infraternal agent requires XDG_RUNTIME_DIR"))?,
        );
        let meta = fs::symlink_metadata(&runtime)?;
        if !meta.is_dir() || meta.uid() != Uid::effective().as_raw() || meta.mode() & 0o777 != 0o700
        {
            return Err(invalid("invalid runtime directory"));
        }
        runtime.join("infraternal")
    };
    Ok(path)
}

/// Validate/create the runtime and session directories for a running infraternal agent.
/// # Errors
/// Rejects absent or unsafe runtime locations and unowned/exposed state directories.
pub fn state(path: Option<PathBuf>) -> io::Result<PathBuf> {
    let path = state_path(path)?;
    private(&path)?;
    private(&path.join("sessions"))?;
    Ok(path)
}

/// Connect, authenticate the rendezvous identity and attach to frozen v1.
/// # Errors
/// Rejects a mismatched identity, unsupported version, or malformed Hello.
pub async fn connect(path: PathBuf, id: [u8; 16]) -> io::Result<Session> {
    connect_with(path, id, 0).await
}

/// Read authenticated process identity without attaching or selecting a terminal writer.
pub(crate) async fn observe(path: PathBuf, id: [u8; 16]) -> io::Result<Session> {
    handshake(path, id, None).await
}

/// Select restart-safe input and approximate recovery when advertised.
/// # Errors
/// Returns the same authentication and framing failures as `connect`.
pub async fn connect_sequenced(path: PathBuf, id: [u8; 16]) -> io::Result<Session> {
    connect_with(
        path,
        id,
        SEQUENCED_INPUT | APPROXIMATE_SNAPSHOT | infraternal_shim::frame::CLOSE_SESSION,
    )
    .await
}

/// Select a stable leg-B writer and advertised queue deferral before querying cursors.
/// # Errors
/// Refuses old shims without writer isolation instead of borrowing another device's Ack.
pub async fn connect_writer(path: PathBuf, id: [u8; 16], writer: u32) -> io::Result<Session> {
    let mut session = connect_with(
        path,
        id,
        SEQUENCED_INPUT
            | MULTI_WRITER
            | APPROXIMATE_SNAPSHOT
            | SHARED_WRITER
            | infraternal_shim::frame::QUERY_REPLIES,
    )
    .await?;
    if session.caps & MULTI_WRITER == 0 || writer == 0 {
        return Err(invalid("shim lacks independent writer capability"));
    }
    send(&mut session.peer, &Frame::SelectWriter(writer)).await?;
    Ok(session)
}

/// Keep ownership independent of the replaceable, credit-funded data link.
/// # Errors
/// Returns authentication/handshake failures. Old shims select no owner capability.
pub async fn own(path: PathBuf, id: [u8; 16]) -> io::Result<Option<Session>> {
    timeout(HANDSHAKE, async {
        let mut owner = connect_with(path, id, infraternal_shim::frame::SESSION_OWNER).await?;
        if owner.caps == 0 {
            return Ok(None);
        }
        send(&mut owner.peer, &Frame::InputStateRequest).await?;
        if Reader::default().read(&mut owner.peer).await? != Frame::InputState(0, 0) {
            return Err(invalid("invalid shim ownership confirmation"));
        }
        Ok(Some(owner))
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Share an existing durable writer without replacing its ordinary local peer.
/// The caller owns this connection and must leave output parked until promotion.
/// # Errors
/// Refuses old shims before sending the additive selector, or a reserved writer.
pub async fn connect_shared_writer(
    path: PathBuf,
    id: [u8; 16],
    writer: u32,
) -> io::Result<Session> {
    if writer == 0 {
        return Err(invalid("shared shim writer must be nonzero"));
    }
    let mut session = connect_with(
        path,
        id,
        SEQUENCED_INPUT
            | MULTI_WRITER
            | APPROXIMATE_SNAPSHOT
            | SHARED_WRITER
            | infraternal_shim::frame::QUERY_REPLIES,
    )
    .await?;
    let required = SEQUENCED_INPUT | MULTI_WRITER | SHARED_WRITER;
    if session.caps & required != required {
        return Err(invalid("shim lacks shared writer capability"));
    }
    send(&mut session.peer, &Frame::SelectSharedWriter(writer)).await?;
    Ok(session)
}

pub(crate) async fn connect_with(
    path: PathBuf,
    id: [u8; 16],
    requested: u64,
) -> io::Result<Session> {
    handshake(path, id, Some(requested)).await
}

/// Read fresh replay metadata without attaching, selecting a writer or changing geometry.
#[cfg(feature = "remote")]
pub(crate) async fn replay_size(path: PathBuf, id: [u8; 16]) -> io::Result<(u16, u16)> {
    let hello = handshake(path, id, None).await?;
    Ok(hello.size)
}

async fn handshake(path: PathBuf, id: [u8; 16], requested: Option<u64>) -> io::Result<Session> {
    timeout(HANDSHAKE, async {
        let mut peer = UnixStream::connect(&path).await?;
        let uid = peer.peer_cred()?.uid();
        if uid != 0 && uid != Uid::effective().as_raw() {
            return Err(invalid("unexpected shim peer uid"));
        }
        let hello = Reader::default().read(&mut peer).await?;
        let Frame::Hello {
            version: 1,
            session,
            head,
            start,
            pid,
            caps,
            cols,
            rows,
            ..
        } = hello
        else {
            return Err(invalid("invalid shim Hello"));
        };
        if session != id
            || start > head
            || cols == 0
            || rows == 0
            || usize::from(cols) * usize::from(rows) > 200_000
        {
            return Err(invalid("shim identity or ring range mismatch"));
        }
        let supports_owner = caps & infraternal_shim::frame::SESSION_OWNER != 0;
        let caps = caps & requested.unwrap_or(0);
        if requested.is_some() {
            send(&mut peer, &Frame::Attach(caps)).await?;
        }
        Ok(Session {
            id,
            path,
            peer,
            head,
            size: (cols, rows),
            pid,
            caps,
            supports_owner,
        })
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shim handshake timed out"))?
}

/// The rendezvous socket a session's shim listens on, derived from its id alone.
#[must_use]
pub fn rendezvous(state: &Path, id: [u8; 16]) -> PathBuf {
    state
        .join("sessions")
        .join(format!("{}.sock", uuid::Uuid::from_bytes(id).simple()))
}

/// True when a connect to a rendezvous proves that no shim is there: the
/// socket file is missing, or it is a stale file nothing listens on. Every
/// other failure (a timeout, a wrong identity) may be transient.
#[must_use]
pub fn gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

/// Discover every socket identity with bounded parallel handshakes.
/// # Errors
/// Returns directory errors or a live shim handshake failure.
#[inline(never)]
pub fn discover(
    state: &Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Vec<Session>>> + Send + '_>> {
    // Discovery runs at recovery and automation boundaries, never per keystroke.
    // Share one state machine across consumers rather than inlining its socket
    // scans and bounded concurrent handshakes into each caller's poll/drop paths.
    Box::pin(discover_inner(state))
}
async fn discover_inner(state: &Path) -> io::Result<Vec<Session>> {
    let mut tasks = JoinSet::new();
    let mut sessions = Vec::new();
    for entry in fs::read_dir(state.join("sessions"))? {
        let entry = entry?;
        let path = entry.path();
        // Markers are published only after bind. If their socket is absent,
        // interruption between the retirement unlinks left no live probe.
        if path.extension().is_some_and(|ext| ext == "readiness")
            && !path.with_extension("sock").try_exists()?
        {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        if path.extension().is_none_or(|ext| ext != "sock") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|name| name.to_str()) else {
            return Err(invalid("invalid shim socket name"));
        };
        let id = uuid::Uuid::parse_str(name)
            .map_err(|_| invalid("invalid shim socket identity"))?
            .into_bytes();
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type())
            || meta.uid() != Uid::effective().as_raw()
            || meta.mode() & 0o777 != 0o600
        {
            return Err(invalid("invalid shim socket permissions"));
        }
        if tasks.len() == DISCOVERY_HANDSHAKES
            && let Some(result) = tasks.join_next().await
            && let Some(session) = result.map_err(io::Error::other)??
        {
            sessions.push(session);
        }
        tasks.spawn(async move {
            match connect(path.clone(), id).await {
                Ok(session) => Ok(Some(session)),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    // An interrupted fixed probe can leave its role marker.
                    // Unlink the refused socket first, preserving classification
                    // for any concurrent revocation while it remains visible.
                    let marker = path.with_extension("readiness");
                    for stale in [path, marker] {
                        match fs::remove_file(stale) {
                            Ok(()) => {}
                            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Ok(None)
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => {
                    // The sealed exit can precede listener teardown. A known
                    // ended session cannot make restart fail on its last EOF;
                    // unknown or insecure records retain the strict error path.
                    if infraternal_shim::ended::read(&path)?.is_some() {
                        Ok(None)
                    } else {
                        Err(error)
                    }
                }
            }
        });
    }
    while let Some(result) = tasks.join_next().await {
        if let Some(session) = result.map_err(io::Error::other)?? {
            sessions.push(session);
        }
    }
    Ok(sessions)
}

/// Extract the live process birth tick from a bounded kernel stat record.
/// The command field can contain spaces, parentheses or non-UTF8 bytes; field
/// 22 is counted from its final delimiter. Dead states never supply an identity.
#[must_use]
pub fn process_birth_ticks(record: &[u8]) -> Option<u64> {
    if record.len() > 4096 {
        return None;
    }
    let open = record.windows(2).position(|pair| pair == b" (")?;
    let end = record.windows(2).rposition(|pair| pair == b") ")?;
    if open + 2 > end {
        return None;
    }
    let pid = std::str::from_utf8(&record[..open]).ok()?;
    if !pid.as_bytes().iter().all(u8::is_ascii_digit) || pid.parse::<u32>().ok()? == 0 {
        return None;
    }
    let mut fields = std::str::from_utf8(&record[end + 2..])
        .ok()?
        .split_ascii_whitespace();
    let state = fields.next()?;
    if state.len() != 1
        || !state.as_bytes()[0].is_ascii_alphabetic()
        || matches!(state, "Z" | "X" | "x")
    {
        return None;
    }
    let birth = fields.nth(18)?;
    if !birth.as_bytes().iter().all(u8::is_ascii_digit) {
        return None;
    }
    birth.parse().ok()
}

/// Directory retirement events keep the registry fresh without idle timers.
#[cfg(target_os = "linux")]
pub(crate) struct SessionEvents(Registration<Inotify>);
#[cfg(target_os = "linux")]
impl SessionEvents {
    pub(crate) fn new(state: &Path) -> io::Result<Self> {
        let watch = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)
            .map_err(io::Error::from)?;
        watch
            .add_watch(state.join("sessions").as_path(), AddWatchFlags::IN_DELETE)
            .map_err(io::Error::from)?;
        Ok(Self(Registration::new(watch)?))
    }
    pub(crate) async fn changed(&self) -> io::Result<()> {
        loop {
            let mut ready = self.0.readable().await?;
            if let Ok(result) = ready.try_io(|fd| fd.read_events().map_err(io::Error::from)) {
                result?;
                return Ok(());
            }
        }
    }
}
/// Directory retirement events through a kqueue vnode filter: an entry
/// added to or removed from `sessions/` is a `NOTE_WRITE` on the directory.
#[cfg(target_os = "macos")]
pub(crate) struct SessionEvents(DirectoryEvents);
#[cfg(target_os = "macos")]
impl SessionEvents {
    /// Watch `state/sessions` for entries being added or removed.
    pub(crate) fn new(state: &Path) -> io::Result<Self> {
        DirectoryEvents::new(&state.join("sessions")).map(Self)
    }

    pub(crate) async fn changed(&self) -> io::Result<()> {
        self.0.changed().await
    }
}

/// One `EVFILT_VNODE` watch on a directory, opened event-only, plus an
/// optional one-shot timer used only to bridge the bind/listen gap below.
#[cfg(target_os = "macos")]
pub(crate) struct DirectoryEvents {
    queue: Registration<nix::sys::event::Kqueue>,
    // Keeps the watched vnode's descriptor open for the filter's lifetime.
    _directory: fs::File,
}
#[cfg(target_os = "macos")]
impl DirectoryEvents {
    /// The kqueue identifier of the one-shot bind/listen bridge timer.
    const TIMER: usize = 1;

    /// Open `directory` event-only and watch it for `NOTE_WRITE` (an entry added or removed).
    pub(crate) fn new(directory: &Path) -> io::Result<Self> {
        use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
        use std::os::{fd::AsRawFd as _, unix::fs::OpenOptionsExt as _};
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_EVTONLY | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
            .open(directory)?;
        let queue = Kqueue::new()?;
        nix::fcntl::fcntl(
            &queue,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )?;
        let watch = KEvent::new(
            usize::try_from(directory.as_raw_fd()).map_err(io::Error::other)?,
            EventFilter::EVFILT_VNODE,
            EvFlags::EV_ADD | EvFlags::EV_CLEAR,
            FilterFlag::NOTE_WRITE,
            0,
            0,
        );
        infraternal_shim::readiness::kevent_now(&queue, &[watch], &mut [])?;
        Ok(Self {
            queue: Registration::new(queue)?,
            _directory: directory,
        })
    }

    /// Wake once after `millis` even without a directory change.
    fn wake_after(&self, millis: isize) -> io::Result<()> {
        use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};
        let timer = KEvent::new(
            Self::TIMER,
            EventFilter::EVFILT_TIMER,
            EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
            FilterFlag::empty(),
            millis,
            0,
        );
        infraternal_shim::readiness::kevent_now(self.queue.get_ref(), &[timer], &mut [])?;
        Ok(())
    }

    /// Wait until the directory changed or the bridge timer fired, then drain the queue.
    pub(crate) async fn changed(&self) -> io::Result<()> {
        use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent};
        loop {
            let mut ready = self.queue.readable().await?;
            match ready.try_io(|queue| {
                let mut events = [KEvent::new(
                    0,
                    EventFilter::EVFILT_VNODE,
                    EvFlags::empty(),
                    FilterFlag::empty(),
                    0,
                    0,
                ); 8];
                match infraternal_shim::readiness::kevent_now(queue, &[], &mut events)? {
                    0 => Err(io::ErrorKind::WouldBlock.into()),
                    _ => Ok(()),
                }
            }) {
                // Signals outlasted the bounded retries: yield to the runtime
                // and retry with readiness kept, never spin or fail (#328).
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    tokio::task::yield_now().await;
                }
                Ok(result) => return result,
                Err(_would_block) => {}
            }
        }
    }
}

/// The variables a shim may inherit from the infraternal agent, from `vars`.
///
/// A root shim must not run with whatever its agent was started with: a
/// planted `DYLD_LIBRARY_PATH`, `BASH_ENV`, `ENV` or `PATH` would follow it into
/// a root process (#328 J215 P3-1). Allowed: locale (`LANG`, `LC_*`) and, on
/// Linux, what `systemd-run --user` needs to reach the person's manager
/// (`XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`), plus `ZDOTDIR`, which the
/// shim forwards to a shell only after checking its directory
/// (`shell_startup::zsh_directory`).
fn shim_environment(
    vars: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    vars.into_iter()
        .filter(|(name, _)| shim_variable(name))
        .collect()
}

/// Whether one variable is on the shim's allow-list (see `shim_environment`).
fn shim_variable(name: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let name = name.as_bytes();
    name == b"LANG"
        || name.starts_with(b"LC_")
        || (cfg!(target_os = "linux")
            && matches!(
                name,
                b"XDG_RUNTIME_DIR" | b"DBUS_SESSION_BUS_ADDRESS" | b"ZDOTDIR"
            ))
}

/// Resolve a launcher by name through the agent's own `PATH`, so the shim it
/// starts needs no `PATH` of its own. An unresolved name is returned as is.
fn on_path(name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join(name))
        .find(|candidate| {
            fs::metadata(candidate)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
        .unwrap_or_else(|| PathBuf::from(name))
}

#[cfg(test)]
mod shim_environment_tests {
    //! The shim's environment allow-list (#328, J215 P3-1).
    use super::*;
    use std::ffi::OsString;

    /// Hostile variables planted in the agent's environment never reach a
    /// shim; locale does, and on Linux the user-manager variables do.
    #[test]
    fn only_allow_listed_variables_reach_the_shim() {
        let planted = [
            "DYLD_LIBRARY_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "BASH_ENV",
            "ENV",
            "PATH",
            "HOME",
            "J146_PLANTED",
        ];
        let kept = ["LANG", "LC_ALL", "LC_CTYPE"];
        let linux_only = ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "ZDOTDIR"];
        let vars = planted
            .iter()
            .chain(&kept)
            .chain(&linux_only)
            .map(|name| (OsString::from(name), OsString::from("x")));
        let passed: Vec<String> = shim_environment(vars)
            .into_iter()
            .map(|(name, _)| name.into_string().unwrap())
            .collect();
        for name in planted {
            assert!(!passed.iter().any(|p| p == name), "{name} reached the shim");
        }
        for name in kept {
            assert!(passed.iter().any(|p| p == name), "{name} was dropped");
        }
        for name in linux_only {
            assert_eq!(
                passed.iter().any(|p| p == name),
                cfg!(target_os = "linux"),
                "{name}"
            );
        }
    }

    /// A launcher found on the agent's `PATH` resolves to its absolute path.
    #[test]
    fn launchers_resolve_through_the_agents_path() {
        assert!(
            on_path("sh").is_absolute(),
            "sh is on every test host's PATH"
        );
        assert_eq!(
            on_path("no-such-launcher-j146"),
            PathBuf::from("no-such-launcher-j146")
        );
    }
}

// Exclude the trusted leg-B descriptor at direct exec. Anonymous images need
// /proc/self/exe to resolve before any intermediate program replaces the image.
// CLOEXEC also preserves Command's private exec-error pipe if it occupies fd3.
pub(crate) fn isolated(program: &Path) -> Command {
    // Exclude borrowed leg-B at fresh exec without an extra shell process.
    // The audited helper preserves Command's error pipe and signal policy.
    let mut command = Command::new(program);
    infraternal_shim::prepare_isolated_child(command.as_std_mut());
    command.stdin(Stdio::null());
    command
}

// bind emits IN_CREATE before listen, so a refused early connection must
// also wake on chmod. The shim chmods to 0600 only after listen succeeds.
#[cfg(target_os = "linux")]
/// Wakes a shim launch when its rendezvous socket may have become connectable (inotify on `sessions/`, Linux).
struct SocketReadiness(Registration<Inotify>);
#[cfg(target_os = "linux")]
impl SocketReadiness {
    /// Watch `state/sessions` for socket creation and the post-listen chmod.
    fn new(state: &Path) -> io::Result<Self> {
        let watch = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)
            .map_err(io::Error::from)?;
        watch
            .add_watch(
                state.join("sessions").as_path(),
                AddWatchFlags::IN_CREATE | AddWatchFlags::IN_ATTRIB,
            )
            .map_err(io::Error::from)?;
        Registration::new(watch).map(Self)
    }
    /// Wait for the next directory event. `_refused` is unused: Linux also wakes on the chmod after listen.
    async fn changed(&self, _refused: bool) -> io::Result<()> {
        let mut readiness = self.0.readable().await?;
        if let Ok(result) = readiness.try_io(|fd| fd.read_events().map_err(io::Error::from)) {
            result?;
        }
        Ok(())
    }
}

// The directory filter fires when bind creates the socket's entry. Rust's
// bind also listens, but a connect between those two syscalls is refused and
// no further directory change follows, and a socket file cannot be opened
// for its own vnode filter. Only after such a refusal, arm one 1 ms timer;
// the launch's two-second deadline still bounds the whole wait.
#[cfg(target_os = "macos")]
/// Wakes a shim launch when its rendezvous socket may have become connectable (kqueue on `sessions/`, macOS).
struct SocketReadiness(DirectoryEvents);
#[cfg(target_os = "macos")]
impl SocketReadiness {
    /// Watch `state/sessions` for socket creation.
    fn new(state: &Path) -> io::Result<Self> {
        DirectoryEvents::new(&state.join("sessions")).map(Self)
    }
    /// Wait for the next directory change; after a refused connect, also wake once 1 ms later (see above).
    async fn changed(&self, refused: bool) -> io::Result<()> {
        if refused {
            self.0.wake_after(1)?;
        }
        self.0.changed().await
    }
}

/// Launch the same binary in an independent scope, or the shim's double fork.
/// Socket readiness is signaled by inotify, never by periodic connect retries.
/// # Errors
/// Returns spawn, readiness timeout, account/dimension or shim handshake errors.
pub async fn launch(
    exe: &Path,
    state: &Path,
    manager: Manager,
    uid: u32,
    cols: u16,
    rows: u16,
) -> io::Result<Session> {
    launch_with_readiness(exe, state, manager, uid, cols, rows, false).await
}

/// Fixed private readiness command retains the enrolled account and normal scope.
/// # Errors
/// Returns the same validation and launch errors as `launch`.
pub async fn launch_with_readiness(
    exe: &Path,
    state: &Path,
    manager: Manager,
    uid: u32,
    cols: u16,
    rows: u16,
    readiness: bool,
) -> io::Result<Session> {
    launch_with_command(exe, state, manager, uid, cols, rows, readiness, false, &[]).await
}

/// Launch a literal program through a bounded private stdin pipe, never a shell string or argv secret.
/// # Errors
/// Returns invalid program arguments, startup or shim handshake failures.
pub async fn launch_with_command(
    exe: &Path,
    state: &Path,
    manager: Manager,
    uid: u32,
    cols: u16,
    rows: u16,
    readiness: bool,
    retain_output: bool,
    program: &[String],
) -> io::Result<Session> {
    launch_configured(
        exe,
        state,
        manager,
        uid,
        cols,
        rows,
        None,
        None,
        None,
        None,
        None,
        readiness,
        None,
        retain_output,
        program,
    )
    .await
}

/// Launch a shim whose shell belongs to an authenticated host login worker.
/// # Errors
/// Returns the same validation/launch errors as `launch`.
pub async fn launch_with_login(
    exe: &Path,
    state: &Path,
    manager: Manager,
    uid: u32,
    cols: u16,
    rows: u16,
    login: Option<&Path>,
    login_cgroup: Option<&Path>,
    login_worker_pid: Option<i32>,
    login_worker_parent: Option<i32>,
    login_worker_proc: Option<&std::fs::File>,
) -> io::Result<Session> {
    launch_configured(
        exe,
        state,
        manager,
        uid,
        cols,
        rows,
        login,
        login_cgroup,
        login_worker_pid,
        login_worker_parent,
        login_worker_proc,
        false,
        None,
        false,
        &[],
    )
    .await
}

/// Launch an attributed shell, transferring its person fence to the durable reservation.
pub(crate) async fn launch_rootless_person(
    exe: &Path,
    state: &Path,
    manager: Manager,
    uid: u32,
    cols: u16,
    rows: u16,
    person: uuid::Uuid,
    person_guard: crate::logins::PersonGuard,
) -> io::Result<Session> {
    launch_configured(
        exe,
        state,
        manager,
        uid,
        cols,
        rows,
        None,
        None,
        None,
        None,
        None,
        false,
        Some((person, person_guard)),
        false,
        &[],
    )
    .await
}

/// Launch one shim and return its first authenticated session. The ordered authentication, launch and
/// handshake setup stays together; on Linux a failure or cancellation after the spawn hands the launch to
/// its own cleanup (`Launch`).
/// A rootless reservation retains its person fence through the readiness attempt.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn launch_configured(
    exe: &Path,
    state: &Path,
    manager: Manager,
    uid: u32,
    cols: u16,
    rows: u16,
    login: Option<&Path>,
    login_cgroup: Option<&Path>,
    login_worker_pid: Option<i32>,
    login_worker_parent: Option<i32>,
    login_worker_proc: Option<&std::fs::File>,
    readiness: bool,
    person: Option<(uuid::Uuid, crate::logins::PersonGuard)>,
    retain_output: bool,
    program: &[String],
) -> io::Result<Session> {
    let manager = manager.for_shim(exe, login.is_some());
    let program_bytes = command_input(program, readiness)?;
    if login.is_some() && !program.is_empty() {
        return Err(invalid("login worker command startup is unavailable"));
    }
    if cols == 0 || rows == 0 || usize::from(cols) * usize::from(rows) > 200_000 {
        return Err(invalid("invalid terminal dimensions"));
    }
    if !Uid::effective().is_root() && uid != Uid::effective().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "rootless infraternal agent can only open its own sessions",
        ));
    }
    let id = uuid::Uuid::new_v4();
    let name = id.simple().to_string();
    let path = state.join("sessions").join(format!("{name}.sock"));
    #[cfg(target_os = "linux")]
    let mut reservation = match person {
        Some((person, guard)) => {
            Some(crate::rootless_sessions::reserve(state, person, id, guard).await?)
        }
        None => None,
    };
    // Durable rootless person records belong to inherited host logins, which
    // are Linux-only (D247); a macOS person shell comes from the root agent.
    #[cfg(target_os = "macos")]
    if person.is_some() {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let watch = SocketReadiness::new(state)?;
    let mut command = if matches!(manager, Manager::Detached) {
        isolated(exe)
    } else {
        let mut command = isolated(&on_path("systemd-run"));
        if matches!(manager, Manager::User) {
            command.arg("--user");
        }
        command
            .args(["--quiet", "--scope", "--unit"])
            .arg(format!("infraternal-session-{name}"))
            .arg(exe);
        command
    };
    // The shim (and its launcher) inherit only the standard handles plus what
    // the login handoff below admits by name; never a stray agent descriptor,
    // such as a shim or plugin connection authenticated as root (#328 P1).
    infraternal_shim::inherit_only_standard_descriptors(command.as_std_mut());
    // ...and only the allow-listed environment: never the agent's DYLD_*,
    // LD_*, BASH_ENV, ENV, PATH or other inherited variables (#328 J215 P3-1).
    // Locale values are added again below from the host's locale files.
    command
        .env_clear()
        .envs(shim_environment(std::env::vars_os()));
    command
        .args([
            "__shim",
            "--session",
            &name,
            "--uid",
            &uid.to_string(),
            "--cols",
            &cols.to_string(),
            "--rows",
            &rows.to_string(),
            "--state",
        ])
        .arg(state);
    if readiness {
        command.arg("--readiness");
    }
    if retain_output {
        command.arg("--retain-output");
    }
    if !program.is_empty() {
        command.arg("--command-stdin");
    }
    let detached = matches!(manager, Manager::Detached) && login.is_none();
    if detached {
        command.arg("--detach");
    }
    if login.is_some() {
        // The controller reaps this fresh exec asynchronously. Separate its
        // session before exec; authenticated placement still precedes Hello
        // and moves established shims outside the controller service's cgroup.
        infraternal_shim::prepare_independent_session(command.as_std_mut());
    }
    if let Some(endpoint) = login {
        command.arg("--login-socket").arg(endpoint);
    }
    if let Some(path) = login_cgroup {
        command.arg("--login-cgroup").arg(path);
    }
    if let Some(pid) = login_worker_pid {
        command.arg("--login-worker-pid").arg(pid.to_string());
    }
    if let Some(pid) = login_worker_parent {
        command.arg("--login-worker-parent").arg(pid.to_string());
    }
    #[cfg(target_os = "linux")]
    if let Some(process) = login_worker_proc {
        let pin = infraternal_shim::inherit_login_process(command.as_std_mut(), process)?;
        command.arg("--login-worker-proc").arg(pin);
    }
    // Host-login workers are Linux-only (D247); macOS shells are placed by the
    // shim's session-shell entry instead (D335).
    #[cfg(target_os = "macos")]
    if login.is_some() || login_worker_proc.is_some() {
        return Err(io::ErrorKind::Unsupported.into());
    }
    // Start the shell on the original authenticated connection before the
    // privileged shim exec. Cancellation/spawn failure drops every parent copy;
    // the worker observes lease EOF and cleans up only this terminal request.
    #[cfg(target_os = "linux")]
    let prestarted = if let (Some(endpoint), Some(pid), Some(process)) =
        (login, login_worker_pid, login_worker_proc)
    {
        let prepared = infraternal_shim::login_handoff::Prepared::new(uid, cols, rows)?;
        let peer = timeout(HANDSHAKE, UnixStream::connect(endpoint))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "login connection timed out"))??;
        let peer = Registration::new(peer.into_std()?)?;
        let pin = PathBuf::from(format!("/proc/self/fd/{}", process.as_raw_fd()));
        timeout(HANDSHAKE, async {
            loop {
                let mut ready = peer.writable().await?;
                if let Ok(result) = ready.try_io(|connection| {
                    prepared.request(connection, id.as_bytes(), pid, &pin, login_worker_parent)
                }) {
                    return result;
                }
            }
        })
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "login terminal transfer timed out")
        })??;
        let (master, lease) = prepared.inherit(command.as_std_mut(), peer.get_ref())?;
        command
            .arg("--login-master-fd")
            .arg(master.to_string())
            .arg("--login-lease-fd")
            .arg(lease.to_string());
        Some((prepared, peer))
    } else {
        None
    };
    // Resolve host locale in the long-lived launcher and pass only locale
    // variables through the isolated shim start, avoiding per-PTY probing.
    for (name, value) in infraternal_shim::session_locale_environment() {
        command.env(name, value);
    }
    // A detaching launch gets a lifeline: the write end of a pipe that the launcher and every process it
    // forks inherit, and that the shim holds for its whole life. End-of-file on the read end, which stays
    // here, therefore proves that no process of this launch is left (contracts/shim.md §2).
    #[cfg(target_os = "linux")]
    let lifeline = if detached {
        Some(new_lifeline(&mut command)?)
    } else {
        None
    };
    let child = command
        .stdin(if program.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    #[cfg(target_os = "macos")]
    {
        // macOS keeps the plain launch: the cleanup guard below is Linux-only (#324).
        let mut child = child;
        if !program.is_empty() {
            child
                .stdin
                .take()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .write_all(&program_bytes)
                .await?;
        }
        drop(command);
        let session = await_launch(&path, id, &watch, &mut child, detached).await;
        // Scope launchers and directly owned login shims live until terminal exit.
        // Reap independently; waiting here would hold terminal.open until close.
        tokio::spawn(async move {
            let _ = child.wait().await;
        });
        return session;
    }
    #[cfg(target_os = "linux")]
    {
        // From here the launch owns a running process, and the guard stops exactly
        // that launch on EVERY way out other than success: an error, or the caller
        // dropping this future (automation's 4 s deadline does). The cleanup runs on
        // its own task and bound, so a cancelled caller cannot cancel it.
        let record = reservation
            .as_mut()
            .and_then(crate::rootless_sessions::Reservation::spawned);
        let mut launch = Launch {
            child: Some(child),
            watch: Some(watch),
            state: state.to_path_buf(),
            path,
            id,
            manager,
            name,
            detached,
            record,
            lifeline,
        };
        let written = if program.is_empty() {
            Ok(())
        } else {
            match launch.child.as_mut().and_then(|child| child.stdin.take()) {
                Some(mut stdin) => stdin.write_all(&program_bytes).await,
                None => Err(io::ErrorKind::BrokenPipe.into()),
            }
        };
        // Command's callbacks retain descriptor duplicates even after spawn. These
        // must close before awaiting Hello; only the privileged shim owns the lease.
        drop(command);
        drop(prestarted);
        written?;
        let (Some(child), Some(watch)) = (launch.child.as_mut(), launch.watch.as_ref()) else {
            return Err(io::Error::other("launch state was released early"));
        };
        let session = await_launch(&launch.path, id, watch, child, detached).await?;
        // Scope launchers and directly owned login shims live until terminal exit.
        // Reap independently; waiting here would hold terminal.open until close.
        if let Some(mut child) = launch.child.take() {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
        }
        Ok(session)
    }
}

/// A launch whose process has started and whose Hello has not yet been accepted.
/// Dropping it, on failure or cancellation, hands the launch to `abandon_launch`.
#[cfg(target_os = "linux")]
struct Launch {
    /// The launcher this call spawned; `None` once it has been handed to its reaper (success).
    child: Option<tokio::process::Child>,
    /// Rendezvous directory watch for this launch's own Hello wait.
    watch: Option<SocketReadiness>,
    /// The state directory, so cleanup can watch the rendezvous directory itself.
    state: PathBuf,
    /// This launch's own rendezvous socket.
    path: PathBuf,
    /// This launch's own session id, the only identity cleanup may address.
    id: uuid::Uuid,
    /// The manager that placed the shim, naming the scope to stop.
    manager: Manager,
    /// The simple-form session id used in the scope name.
    name: String,
    /// Whether the shim detaches, so its launcher is not the shim and exits before it binds.
    detached: bool,
    /// The person-terminal record this launch wrote, retired only once the terminal is proven dead.
    record: Option<PathBuf>,
    /// The read end of this launch's lifeline: end-of-file proves no process of the launch remains.
    lifeline: Option<std::os::fd::OwnedFd>,
}

#[cfg(target_os = "linux")]
impl Drop for Launch {
    /// Hand everything to a tracked cleanup task. With no runtime to run it on, finish it here.
    fn drop(&mut self) {
        let Some(child) = self.child.take() else {
            return;
        };
        let parts = Parts {
            child,
            state: std::mem::take(&mut self.state),
            path: std::mem::take(&mut self.path),
            id: self.id,
            manager: self.manager,
            name: std::mem::take(&mut self.name),
            detached: self.detached,
            record: self.record.take(),
            lifeline: self.lifeline.take(),
        };
        let job = Abandoned {
            parts: Some(parts),
            _pending: Pending::new(),
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(abandon_launch(job));
            }
            Err(_) => drop(job),
        }
    }
}

/// Everything cleanup addresses, all of it this launch's own.
#[cfg(target_os = "linux")]
struct Parts {
    /// The launcher this launch spawned, unreaped, so its pid cannot be reused.
    child: tokio::process::Child,
    /// The state directory holding the rendezvous directory.
    state: PathBuf,
    /// This launch's own rendezvous socket.
    path: PathBuf,
    /// This launch's own session id.
    id: uuid::Uuid,
    /// The manager that placed the shim.
    manager: Manager,
    /// The simple-form session id used in the scope name.
    name: String,
    /// Whether the shim detaches, so its launcher is not the shim.
    detached: bool,
    /// The person-terminal record to retire once the terminal is proven dead.
    record: Option<PathBuf>,
    /// The read end of the launch's lifeline, if it detaches; kept as a plain descriptor so it can move to
    /// the shutdown thread's own runtime.
    lifeline: Option<std::os::fd::OwnedFd>,
}

/// A cleanup owned apart from the caller's future. If it is dropped before it finished (the runtime shut
/// down with it queued or suspended), `Drop` runs the same cleanup to completion on a dedicated thread.
#[cfg(target_os = "linux")]
struct Abandoned {
    /// What is left to clean up; `None` once cleanup has run to its end.
    parts: Option<Parts>,
    /// Counts this cleanup in the process-wide tracker until it is dropped.
    _pending: Pending,
}

#[cfg(target_os = "linux")]
impl Drop for Abandoned {
    /// The shutdown path: finish a cleanup that never completed, on its own thread and runtime, within
    /// `SHUTDOWN` in total. No part of it depends on the runtime that was just dropped. The launch's parts
    /// are shared with the thread rather than moved into it, so if the thread cannot start, they are still
    /// here to be stopped synchronously.
    fn drop(&mut self) {
        let Some(parts) = self.parts.take() else {
            return;
        };
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Some(parts)));
        let worker = {
            let shared = shared.clone();
            spawn_cleanup_thread(move || {
                let Some(mut parts) = shared.lock().ok().and_then(|mut parts| parts.take()) else {
                    return;
                };
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(cleanup(&mut parts, SHUTDOWN)),
                    // No reactor to wait on: still stop the launcher this launch owns.
                    Err(_) => stop_now(&mut parts),
                }
            })
        };
        match worker {
            Ok(worker) => {
                let _ = worker.join();
            }
            Err(_) => {
                if let Some(mut parts) = shared.lock().ok().and_then(|mut parts| parts.take()) {
                    stop_now(&mut parts);
                }
            }
        }
    }
}

/// Start the shutdown cleanup thread. A test can make this fail, to prove the launcher is still stopped.
#[cfg(target_os = "linux")]
fn spawn_cleanup_thread(
    work: impl FnOnce() + Send + 'static,
) -> io::Result<std::thread::JoinHandle<()>> {
    #[cfg(test)]
    if tests::FAIL_CLEANUP_THREAD.with(std::cell::Cell::get) {
        return Err(io::Error::other("injected cleanup thread failure"));
    }
    std::thread::Builder::new()
        .name("launch-cleanup".into())
        .spawn(work)
}

/// Kill the launcher this launch owns and reap it, blocking for at most about 100 ms. Used where no
/// runtime is available to wait on. It signals only this unreaped child, so it can never reach another
/// process, and it leaves the socket and the person record alone.
#[cfg(target_os = "linux")]
fn stop_now(parts: &mut Parts) {
    let _ = parts.child.start_kill();
    for _ in 0..50 {
        if !matches!(parts.child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Cleanups queued or running, so a stopping agent can wait for them.
#[cfg(target_os = "linux")]
struct Cleanups {
    /// Cleanups not yet dropped.
    pending: std::sync::atomic::AtomicUsize,
    /// Woken when the last pending cleanup is dropped.
    idle: tokio::sync::Notify,
}

/// The process-wide count of launch cleanups, so a stopping agent can wait for them.
#[cfg(target_os = "linux")]
static CLEANUPS: Cleanups = Cleanups {
    pending: std::sync::atomic::AtomicUsize::new(0),
    idle: tokio::sync::Notify::const_new(),
};

/// One cleanup in the tracker; dropping it ends the count.
#[cfg(target_os = "linux")]
struct Pending;

#[cfg(target_os = "linux")]
impl Pending {
    /// Count a new cleanup.
    fn new() -> Self {
        CLEANUPS
            .pending
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self
    }
}

#[cfg(target_os = "linux")]
impl Drop for Pending {
    /// End the count and wake a draining agent when it was the last one.
    fn drop(&mut self) {
        if CLEANUPS
            .pending
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            CLEANUPS.idle.notify_waiters();
        }
    }
}

/// Whether any launch cleanup is still queued or running. A stopping agent asks this first, so the common
/// case (none) adds no future, and no allocation, to its channel loop.
pub(crate) fn cleanups_pending() -> bool {
    #[cfg(target_os = "linux")]
    {
        CLEANUPS.pending.load(std::sync::atomic::Ordering::SeqCst) != 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Wait, bounded, for launch cleanups still running. A stopping infraternal agent calls this so a
/// runtime that outlives it finishes what it queued; a runtime that does not is covered by
/// `Abandoned::drop`.
#[cold]
#[inline(never)]
pub(crate) async fn drain_cleanups() {
    #[cfg(target_os = "linux")]
    {
        let deadline = tokio::time::Instant::now() + SHUTDOWN_DRAIN;
        loop {
            let mut idle = std::pin::pin!(CLEANUPS.idle.notified());
            idle.as_mut().enable();
            if CLEANUPS.pending.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                return;
            }
            if tokio::time::timeout_at(deadline, idle).await.is_err() {
                return;
            }
        }
    }
}

/// Run one abandoned launch's cleanup on its own task. See `cleanup` for what it may do.
#[cfg(target_os = "linux")]
async fn abandon_launch(mut job: Abandoned) {
    if let Some(parts) = job.parts.as_mut() {
        cleanup(parts, NORMAL).await;
    }
    job.parts = None;
}

/// Stop what a failed or cancelled launch started, by identity and never by name: the launcher child
/// this launch spawned and has not reaped, its own scope, and the shim on its own rendezvous, authenticated
/// by the session id in Hello. The shim's exit hangs up its PTY, which ends the shell.
///
/// A terminal counts as dead only on proof, and the launcher's exit is not proof when the shim detaches:
/// the launcher is then the first of three processes and the shim a grandchild with no handle here.
/// - A non-detaching launcher IS the shim: killed and reaped through its own child.
/// - A detached launch carries a lifeline (a pipe whose write end every process of the launch holds):
///   end-of-file on it proves no process of the launch is left (`prove_detached_dead`).
/// - Otherwise only the shim's own authenticated exit counts (`close_detached`).
///
/// Without proof the rendezvous and the person record are left alone: a live terminal keeps its discovery
/// and its revocation attribution. A detached shim's socket is unlinked only on lifeline proof, once no
/// process of the launch is left to own it (`prove_detached_dead`). The launcher this
/// launch owns is stopped and reaped either way, because killing it cannot touch the shim, and the whole
/// cleanup, every inner wait and the final stop of the owned launcher included, ends within `budget.total`.
#[cfg(target_os = "linux")]
async fn cleanup(parts: &mut Parts, budget: Budget) {
    // Everything, the final stop of the owned launcher included, sits under the one deadline.
    let proven = timeout(budget.total, async {
        let proven = stop_launch(parts, budget.retry).await;
        // Whatever the outcome, the owned launcher does not outlive its cleanup.
        let _ = parts.child.start_kill();
        let _ = reaped(&mut parts.child, HANDSHAKE).await;
        proven
    })
    .await
    .unwrap_or(false);
    // Past the deadline only a signal can still be sent: waiting would spend time the budget no longer
    // has. The signal is not a wait, and a killed launcher is reaped when its handle drops.
    let _ = parts.child.start_kill();
    if proven && let Some(record) = parts.record.take() {
        let _ = fs::remove_file(record);
    }
}

/// Stop one launch; whether its terminal is proven dead.
#[cfg(target_os = "linux")]
async fn stop_launch(parts: &mut Parts, retry: Duration) -> bool {
    let cap = HANDSHAKE.min(retry);
    if !parts.detached {
        let _ = timeout(cap, stop_scope(parts.manager, &parts.name)).await;
        let _ = parts.child.start_kill();
        let reaped = reaped(&mut parts.child, cap).await;
        if reaped {
            // The process that owned them is reaped; these are its own leftovers.
            let _ = fs::remove_file(&parts.path);
            let _ = fs::remove_file(parts.path.with_extension("stop"));
        }
        return reaped;
    }
    if matches!(parts.child.try_wait(), Ok(None)) {
        // Killing the original launcher cannot touch a shim: its only remaining work is to exit. Do it
        // first so it cannot outlive this cleanup; it proves nothing about the shim.
        let _ = parts.child.start_kill();
        let _ = reaped(&mut parts.child, cap).await;
    }
    prove_detached_dead(parts, retry).await
}

/// How a detached launch's death was shown.
#[cfg(target_os = "linux")]
enum Proof {
    /// End-of-file on the lifeline: no process of the launch holds it any more.
    Lifeline,
    /// The shim answered an authenticated close and then showed its exit.
    Close,
}

/// Wait up to `retry` for proof that no shim of this launch is alive. Two things can give it: end-of-file
/// on the lifeline (every process that inherited the write end, the shim included, is gone, whether
/// it exited, was killed or never started), or the shim's own authenticated exit after a close request.
/// Nothing else counts, not the launcher's exit and not a missing socket (the shim may bind late). On
/// lifeline proof the dead shim's own leftover socket files are removed, because nothing else will.
#[cfg(target_os = "linux")]
async fn prove_detached_dead(parts: &Parts, retry: Duration) -> bool {
    let lifeline = async {
        match &parts.lifeline {
            Some(descriptor) => lifeline_eof(descriptor).await,
            None => std::future::pending().await,
        }
    };
    let closing = close_detached(&parts.state, &parts.path, parts.id, retry);
    let waiting = async {
        tokio::pin!(lifeline, closing);
        let mut closing_ended = false;
        loop {
            tokio::select! {
                () = &mut lifeline => return Proof::Lifeline,
                observed = &mut closing, if !closing_ended => {
                    if observed {
                        return Proof::Close;
                    }
                    closing_ended = true;
                }
            }
        }
    };
    match timeout(retry, waiting).await {
        Ok(Proof::Lifeline) => {
            let _ = fs::remove_file(&parts.path);
            let _ = fs::remove_file(parts.path.with_extension("stop"));
            true
        }
        Ok(Proof::Close) => true,
        Err(_) => false,
    }
}

/// A fresh lifeline for `command`'s child: returns the read end to keep here. The write end reaches the
/// child by number (`--lifeline-fd`) and is not held by this process once the command is dropped.
#[cfg(target_os = "linux")]
fn new_lifeline(command: &mut Command) -> io::Result<std::os::fd::OwnedFd> {
    let (read, write) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
    let number = infraternal_shim::inherit_lifeline(command.as_std_mut(), &write)?;
    command.arg("--lifeline-fd").arg(number.to_string());
    Ok(read)
}

/// Resolve when the lifeline's read end reaches end-of-file; never on any other outcome. The read end is
/// duplicated and registered on the current runtime, so this works on a shutdown thread's own runtime.
#[cfg(target_os = "linux")]
async fn lifeline_eof(descriptor: &std::os::fd::OwnedFd) {
    let Ok(copy) = descriptor.try_clone() else {
        return std::future::pending().await;
    };
    let Ok(receiver) = tokio::net::unix::pipe::Receiver::from_owned_fd(copy) else {
        return std::future::pending().await;
    };
    let mut buffer = [0_u8; 16];
    loop {
        if receiver.readable().await.is_err() {
            return std::future::pending().await;
        }
        match receiver.try_read(&mut buffer) {
            Ok(0) => return,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return std::future::pending().await,
        }
    }
}

/// Reap an owned child within `bound`, by polling its status: this does not depend on the child
/// reaper of whichever runtime spawned it, which may already be gone at shutdown.
#[cfg(target_os = "linux")]
async fn reaped(child: &mut tokio::process::Child, bound: Duration) -> bool {
    // A test can make the reap stall for its whole bound, as a launcher stuck in uninterruptible sleep would.
    #[cfg(test)]
    if tests::REAP_STALLS.with(std::cell::Cell::get) {
        // sleep: the test hook simulates a reap that cannot finish; this sleep is its whole bound
        tokio::time::sleep(bound).await;
        return false;
    }
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(_) => return false,
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Stop this launch's own scope; the name holds only the fresh session id. A missing manager is a no-op.
#[cfg(target_os = "linux")]
async fn stop_scope(manager: Manager, name: &str) {
    if matches!(manager, Manager::Detached) {
        return;
    }
    let mut stop = isolated(Path::new("systemctl"));
    if matches!(manager, Manager::User) {
        stop.arg("--user");
    }
    let _ = timeout(
        HANDSHAKE,
        stop.args(["stop", &format!("infraternal-session-{name}.scope")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await;
}

/// Ask a detached shim to close its session, however late it binds or answers, within `budget`. The
/// directory watch is made before the first connect, so a bind cannot slip between the two. Returns
/// whether the shim's own exit was observed: its rendezvous gone or sealed by an exit record, after an
/// authenticated close.
#[cfg(target_os = "linux")]
async fn close_detached(state: &Path, path: &Path, id: uuid::Uuid, budget: Duration) -> bool {
    let Ok(watch) = SocketReadiness::new(state) else {
        return false;
    };
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        match connect_sequenced(path.to_path_buf(), id.into_bytes()).await {
            Ok(mut session) => {
                let closed = session.caps & infraternal_shim::frame::CLOSE_SESSION != 0
                    && timeout(HANDSHAKE, send(&mut session.peer, &Frame::CloseSession))
                        .await
                        .is_ok_and(|sent| sent.is_ok());
                return closed && exit_observed(path).await;
            }
            // Slow, not gone: ask again.
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
            // Not bound yet: sleep on the directory watch, never poll.
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.kind() == io::ErrorKind::ConnectionRefused =>
            {
                let refused = error.kind() == io::ErrorKind::ConnectionRefused;
                if !matches!(
                    tokio::time::timeout_at(deadline, watch.changed(refused)).await,
                    Ok(Ok(()))
                ) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    false
}

/// Whether the shim's exit shows within `HANDSHAKE` after a close request: the rendezvous is gone or
/// carries a sealed exit record.
#[cfg(target_os = "linux")]
async fn exit_observed(path: &Path) -> bool {
    let until = tokio::time::Instant::now() + HANDSHAKE;
    loop {
        if !path.exists() || matches!(infraternal_shim::ended::read(path), Ok(Some(_))) {
            return true;
        }
        if tokio::time::Instant::now() >= until {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Wait for a launched shim's Hello. Progress, not a short clock, decides failure: the launcher's exit before the
/// rendezvous refuses the open at once, and `LAUNCH` only detects a hung start (#324).
async fn await_launch(
    path: &Path,
    id: uuid::Uuid,
    watch: &SocketReadiness,
    launcher: &mut tokio::process::Child,
    detached: bool,
) -> io::Result<Session> {
    let hello = wait_for_hello(path, id, watch, launcher, detached);
    #[cfg(all(test, target_os = "linux"))]
    let hello = {
        let mut hello = Box::pin(hello);
        if let Some(armed) = tests::LAUNCH_ARMED.with(std::cell::Cell::take) {
            // Test-only: start the bound once `armed` exists, unless the launch finishes first.
            let ready = async {
                while !armed.exists() {
                    // sleep: poll interval for the test's arming file; the loop ends on that condition.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            };
            tokio::select! {
                result = &mut hello => return result,
                // `LAUNCH` (the real hang bound) also bounds the arming wait.
                _ = timeout(LAUNCH, ready) => {}
            }
        }
        hello
    };
    timeout(launch_bound(), hello)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shim socket readiness timed out"))?
}

/// Connect once per readiness event until the shim says Hello, or its
/// launcher fails first. The directory watch is inotify on Linux and a kqueue
/// vnode filter on macOS (`SocketReadiness`).
async fn wait_for_hello(
    path: &Path,
    id: uuid::Uuid,
    watch: &SocketReadiness,
    launcher: &mut tokio::process::Child,
    detached: bool,
) -> io::Result<Session> {
    let mut launcher_running = true;
    loop {
        // Retry only after directory readiness; healthy handshakes are async.
        // There is no periodic connect loop while startup is pending. Once the
        // socket exists, `connect` bounds the shim's Hello by `HANDSHAKE`.
        let refused = match connect(path.to_path_buf(), id.into_bytes()).await {
            Ok(session) => return Ok(session),
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => true,
            Err(error) => return Err(error),
        };
        tokio::select! {
            readiness = watch.changed(refused) => readiness?,
            status = launcher.wait(), if launcher_running => {
                let status = status?;
                // A detaching shim's first process exits once the session process is forked; that is progress.
                // Every other launcher is the shim itself (systemd-run execs it), so its exit is the shim's.
                if !(detached && status.success()) {
                    return Err(io::Error::other(format!(
                        "shim exited before its rendezvous: {status}"
                    )));
                }
                launcher_running = false;
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/unit/sessions.rs"]
mod tests;

/// The startup pipe carries only bounded literal arguments; no shell or secret argv.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn command_input(program: &[String], readiness: bool) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for argument in program {
        if argument.contains('\0') {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        bytes.extend_from_slice(argument.as_bytes());
        bytes.push(0);
    }
    if bytes.len() > 8192
        || program.first().is_some_and(String::is_empty)
        || (readiness && !program.is_empty())
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(bytes)
}
