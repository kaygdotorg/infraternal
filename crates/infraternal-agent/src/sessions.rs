//! Secure rendezvous discovery and init-independent shim launch [9][13][18].
//!
//! Discovery admits at most 128 sockets and connects concurrently, each
//! with a two-second handshake deadline; a nonresponsive shim cannot serialize
//! recovery of healthy sessions. Only refused sockets are removed as stale.

use infraternal_shim::frame::{Frame, FrameRef, MAX_FRAME, MULTI_WRITER, SEQUENCED_INPUT};
use nix::{
    sys::inotify::{AddWatchFlags, InitFlags, Inotify},
    unistd::Uid,
};
use std::{
    fs::{self, DirBuilder},
    io,
    os::{
        fd::{AsFd, AsRawFd, RawFd},
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

/// Session admission bound, also bounding startup concurrency and process tasks.
pub const MAX_SESSIONS: usize = 128;
const HANDSHAKE: Duration = Duration::from_secs(2);

struct Watch(Inotify);
impl AsRawFd for Watch {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_fd().as_raw_fd()
    }
}

/// Init manager detected once at startup, never periodically probed.
#[derive(Clone, Copy, Debug)]
pub enum Manager {
    System,
    User,
    Detached,
}

impl Manager {
    /// Probe the applicable manager without trusting environment hints alone.
    pub async fn detect() -> Self {
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
        if available.is_ok_and(|result| result.is_ok_and(|status| status.success())) {
            if root { Self::System } else { Self::User }
        } else {
            Self::Detached
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
    pub pid: u32,
    /// Selected capabilities, never inferred from the binary version.
    pub caps: u64,
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

/// Resolve and validate the runtime-only state directory and session directory.
/// # Errors
/// Rejects absent/unsafe rootless runtime directories and insecure state paths.
pub fn state(path: Option<PathBuf>) -> io::Result<PathBuf> {
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

/// Select restart-safe input when advertised; expose caps-zero limitations.
/// # Errors
/// Returns the same authentication and framing failures as `connect`.
pub async fn connect_sequenced(path: PathBuf, id: [u8; 16]) -> io::Result<Session> {
    connect_with(path, id, SEQUENCED_INPUT).await
}

/// Select a stable leg-B writer in the surviving shim before querying cursors.
/// # Errors
/// Refuses old shims without writer isolation instead of borrowing another device's Ack.
pub async fn connect_writer(path: PathBuf, id: [u8; 16], writer: u32) -> io::Result<Session> {
    let mut session = connect_with(path, id, SEQUENCED_INPUT | MULTI_WRITER).await?;
    if session.caps & MULTI_WRITER == 0 || writer == 0 {
        return Err(invalid("shim lacks independent writer capability"));
    }
    send(&mut session.peer, &Frame::SelectWriter(writer)).await?;
    Ok(session)
}

async fn connect_with(path: PathBuf, id: [u8; 16], requested: u64) -> io::Result<Session> {
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
            ..
        } = hello
        else {
            return Err(invalid("invalid shim Hello"));
        };
        if session != id || start > head {
            return Err(invalid("shim identity or ring range mismatch"));
        }
        let caps = caps & requested;
        send(&mut peer, &Frame::Attach(caps)).await?;
        Ok(Session {
            id,
            path,
            peer,
            head,
            pid,
            caps,
        })
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shim handshake timed out"))?
}

/// Discover socket identities with bounded parallel handshakes; refuse excess.
/// # Errors
/// Returns directory errors, resource overflow or a live shim handshake failure.
pub async fn discover(state: &Path) -> io::Result<Vec<Session>> {
    let mut tasks = JoinSet::new();
    for entry in fs::read_dir(state.join("sessions"))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "sock") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|name| name.to_str()) else {
            return Err(invalid("invalid shim socket name"));
        };
        let id = uuid::Uuid::parse_str(name)
            .map_err(|_| invalid("invalid shim socket identity"))?
            .into_bytes();
        let meta = fs::symlink_metadata(&path)?;
        if !std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type())
            || meta.uid() != Uid::effective().as_raw()
            || meta.mode() & 0o777 != 0o600
        {
            return Err(invalid("invalid shim socket permissions"));
        }
        if tasks.len() == MAX_SESSIONS {
            return Err(io::Error::other("infraternal session limit reached"));
        }
        tasks.spawn(async move {
            match connect(path.clone(), id).await {
                Ok(session) => Ok(Some(session)),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(path)?;
                    Ok(None)
                }
                Err(error) => Err(error),
            }
        });
    }
    let mut sessions = Vec::with_capacity(tasks.len());
    while let Some(result) = tasks.join_next().await {
        if let Some(session) = result.map_err(io::Error::other)?? {
            sessions.push(session);
        }
    }
    Ok(sessions)
}

// std::process pre_exec would require unsafe code to mark an inherited raw fd
// CLOEXEC. The POSIX shell closes the job's leg-B fd 3 before executing any init
// helper or shim. The target user's shell must never inherit the trusted channel.
fn isolated(program: &Path) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "exec 3<&-; exec \"$@\"", "infraternal-shim-launch"])
        .arg(program);
    command
}

// bind emits IN_CREATE before listen, so a refused early connection must
// also wake on chmod. The shim chmods to 0600 only after listen succeeds.
fn socket_readiness(state: &Path) -> io::Result<tokio::io::unix::AsyncFd<Watch>> {
    let watch =
        Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC).map_err(io::Error::from)?;
    watch
        .add_watch(
            state.join("sessions").as_path(),
            AddWatchFlags::IN_CREATE | AddWatchFlags::IN_ATTRIB,
        )
        .map_err(io::Error::from)?;
    tokio::io::unix::AsyncFd::new(Watch(watch))
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
    if matches!(manager, Manager::Detached) {
        command.arg("--detach");
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // The scope launcher lives until its shim exits. Reap independently; waiting
    // here would hold terminal.open until the user closed the terminal.
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    timeout(HANDSHAKE, async {
        loop {
            // Retry only after directory readiness; healthy handshakes are async.
            // There is no periodic connect loop while startup is pending.
            match connect(path.clone(), id.into_bytes()).await {
                Ok(session) => return Ok(session),
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        || error.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(error) => return Err(error),
            }
            let mut readiness = watch.readable().await?;
            if let Ok(result) =
                readiness.try_io(|fd| fd.get_ref().0.read_events().map_err(io::Error::from))
            {
                result?;
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shim socket readiness timed out"))?
}

#[cfg(test)]
#[path = "../tests/unit/sessions.rs"]
mod tests;
