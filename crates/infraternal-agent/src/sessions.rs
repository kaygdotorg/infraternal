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
use nix::{
    sys::inotify::{AddWatchFlags, InitFlags, Inotify},
    unistd::Uid,
};
use std::{
    fs::{self, DirBuilder},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt},
    },
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
const LAUNCH: Duration = Duration::from_secs(30);

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
    /// `None` means no answer within `HANDSHAKE`; a refusal is an answer.
    pub async fn probe() -> Option<Self> {
        let root = Uid::effective().is_root();
        let mut command = isolated(Path::new("systemctl"));
        if !root {
            command.arg("--user");
        }
        let available = timeout(
            HANDSHAKE,
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
        PathBuf::from("/run/infraternal")
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
pub(crate) struct SessionEvents(Registration<Inotify>);
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
fn socket_readiness(state: &Path) -> io::Result<Registration<Inotify>> {
    let watch =
        Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).map_err(io::Error::from)?;
    watch
        .add_watch(
            state.join("sessions").as_path(),
            AddWatchFlags::IN_CREATE | AddWatchFlags::IN_ATTRIB,
        )
        .map_err(io::Error::from)?;
    Registration::new(watch)
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
#[allow(clippy::too_many_arguments)]
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
#[allow(clippy::too_many_arguments)]
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
#[allow(clippy::too_many_arguments)]
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn launch_rootless_person(
    exe: &Path,
    state: &Path,
    manager: Manager,
    uid: u32,
    cols: u16,
    rows: u16,
    person: uuid::Uuid,
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
        Some(person),
        false,
        &[],
    )
    .await
}

// Keep the ordered authentication/launch/handshake setup together.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
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
    person: Option<uuid::Uuid>,
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
    let mut reservation = person
        .map(|person| crate::rootless_sessions::reserve(state, person, id))
        .transpose()?;
    let watch = socket_readiness(state)?;
    let mut command = if matches!(manager, Manager::Detached) {
        isolated(exe)
    } else {
        let mut command = isolated(Path::new("systemd-run"));
        if matches!(manager, Manager::User) {
            command.arg("--user");
        }
        command
            .args(["--quiet", "--scope", "--unit"])
            .arg(format!("infraternal-session-{name}"))
            .arg(exe);
        command
    };
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
    if let Some(process) = login_worker_proc {
        let pin = infraternal_shim::inherit_login_process(command.as_std_mut(), process)?;
        command.arg("--login-worker-proc").arg(pin);
    }
    // Start the shell on the original authenticated connection before the
    // privileged shim exec. Cancellation/spawn failure drops every parent copy;
    // the worker observes lease EOF and cleans up only this terminal request.
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
    let mut child = command
        .stdin(if program.is_empty() {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if !program.is_empty() {
        child
            .stdin
            .take()
            .ok_or(io::ErrorKind::BrokenPipe)?
            .write_all(&program_bytes)
            .await?;
    }
    if let Some(reservation) = &mut reservation {
        reservation.spawned();
    }
    // Command's callbacks retain descriptor duplicates even after spawn. These
    // must close before awaiting Hello; only the privileged shim owns the lease.
    drop(command);
    drop(prestarted);
    let session = await_launch(&path, id, &watch, &mut child, detached).await;
    // Scope launchers and directly owned login shims live until terminal exit.
    // Reap independently; waiting here would hold terminal.open until close.
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    session
}

/// Wait for a launched shim's Hello. Progress, not a short clock, decides failure: the launcher's exit before the
/// rendezvous refuses the open at once, and `LAUNCH` only detects a hung start (#324).
async fn await_launch(
    path: &Path,
    id: uuid::Uuid,
    watch: &Registration<Inotify>,
    launcher: &mut tokio::process::Child,
    detached: bool,
) -> io::Result<Session> {
    timeout(LAUNCH, wait_for_hello(path, id, watch, launcher, detached))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shim socket readiness timed out"))?
}

async fn wait_for_hello(
    path: &Path,
    id: uuid::Uuid,
    watch: &Registration<Inotify>,
    launcher: &mut tokio::process::Child,
    detached: bool,
) -> io::Result<Session> {
    let mut launcher_running = true;
    loop {
        // Retry only after directory readiness; healthy handshakes are async.
        // There is no periodic connect loop while startup is pending. Once the
        // socket exists, `connect` bounds the shim's Hello by `HANDSHAKE`.
        match connect(path.to_path_buf(), id.into_bytes()).await {
            Ok(session) => return Ok(session),
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.kind() == io::ErrorKind::ConnectionRefused => {}
            Err(error) => return Err(error),
        }
        tokio::select! {
            readiness = watch.readable() => {
                let mut readiness = readiness?;
                if let Ok(result) =
                    readiness.try_io(|fd| fd.read_events().map_err(io::Error::from))
                {
                    result?;
                }
            }
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

#[cfg(test)]
#[path = "../tests/unit/sessions.rs"]
mod tests;

/// The startup pipe carries only bounded literal arguments; no shell or secret argv.
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
