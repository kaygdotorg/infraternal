//! Coordinates runtime lifetime and safely retires owned session shims for bootstrap cleanup [17], #230.
//! Filesystem setup stays outside CLI and supervisor pollers to bound release size [243].

use infraternal_shim::frame::{Frame, MAX_FRAME};
use nix::sys::socket::{
    AddressFamily, SockFlag, SockType, UnixAddr, connect, getsockopt, socket,
    sockopt::PeerCredentials,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// One fixed file in the private runtime state; never replace it while the runtime is live.
pub const LOCK: &str = ".lifetime-lock";

/// Capability level printed by `--bootstrap-runtime-version`; raise it with every new mode.
/// The cleanup script compares it with the level it needs, so a cached helper that predates
/// a mode asks for a refresh (76) instead of refusing the mode. Helpers before levels print
/// nothing and read as 0. Level 1: `inspect`/`retire`; level 2: `sessions`; level 3: `sessions-stop`;
/// level 4: `sessions-count`; level 5: `enrolled`; level 6: `stage-processes`;
/// level 7: root's `infraternal up` base may be 0711 ([`traversable_base`]).
pub const LEVEL: &[u8] = b"7\n";

fn refused() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
#[cold]
#[inline(never)]
fn directory(path: &Path) -> io::Result<File> {
    private_directory(path, false)
}

/// Root's `/var/lib/infraternal`, which `infraternal up` lays out as 0711.
const UP_ROOT_BASE: &str = "/var/lib/infraternal";

/// Whether an installation base with `mode` may be 0711 rather than 0700.
/// Only root's `/var/lib/infraternal`: `infraternal up` makes it 0711 so every
/// user can reach its 0755 `bin/` through `/usr/local/bin/infraternal`, while
/// only root can list it (#263). The SSH installer's preamble accepts the
/// same and nothing else (J145 P3-4), so recovery of a stuck root install
/// must too. Every directory under it stays exactly 0700.
#[must_use]
pub fn traversable_base(path: &Path, euid: u32, mode: u32) -> bool {
    match mode & 0o777 {
        0o700 => true,
        0o711 => euid == 0 && path == Path::new(UP_ROOT_BASE),
        _ => false,
    }
}

/// Open an owned private directory: 0700, or for an installation base, any
/// mode [`traversable_base`] accepts.
fn private_directory(path: &Path, base: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(path)?;
    let metadata = file.metadata()?;
    let euid = nix::unistd::Uid::effective().as_raw();
    let private = if base {
        traversable_base(path, euid, metadata.mode())
    } else {
        metadata.mode() & 0o777 == 0o700
    };
    if metadata.uid() != euid || !private {
        return Err(refused());
    }
    Ok(file)
}
#[cold]
#[inline(never)]
fn at(file: &File, name: &str) -> PathBuf {
    let mut path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    if !name.is_empty() {
        path.push(name);
    }
    path
}
fn same(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}
#[cold]
#[inline(never)]
fn checked_lock(file: &File, path: &Path) -> io::Result<()> {
    let actual = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if !actual.is_file()
        || actual.uid() != nix::unistd::Uid::effective().as_raw()
        || actual.mode() & 0o777 != 0o600
        || actual.nlink() != 1
        || !same(&actual, &named)
        || named.file_type().is_symlink()
    {
        return Err(refused());
    }
    Ok(())
}
/// Acquire before any socket bind and retain until all runtime work has stopped.
/// # Errors
/// Refuses unsafe paths or a second running infraternal agent/cleanup.
pub fn acquire(state: &Path) -> io::Result<File> {
    acquire_bound(state, None)
}
/// Bind a managed runtime to its loaded host identity while admitting startup.
/// # Errors
/// Refuses outstanding rollback receipts or another host's installation marker.
pub fn acquire_owned(state: &Path, host: &str) -> io::Result<File> {
    acquire_bound(state, Some(host))
}
/// Test support: holds the next acquisition for one runtime state, on the
/// thread doing it, until the paired sender sends or drops (or 10 s pass).
/// `active` reads true while that acquisition is held. Async callers use this
/// to prove the acquisition, including its blocking socket dump, runs off
/// their event loop.
#[cfg(feature = "test-support")]
pub struct AcquireHold {
    /// The state directory whose next acquisition is held.
    pub state: std::path::PathBuf,
    /// Released when the sender sends or is dropped.
    pub release: std::sync::mpsc::Receiver<()>,
    /// True while the acquisition is held.
    pub active: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// The pending [`AcquireHold`], if any (test support).
#[cfg(feature = "test-support")]
pub static ACQUIRE_HOLD: std::sync::Mutex<Option<AcquireHold>> = std::sync::Mutex::new(None);

/// Takes the runtime lifetime lock for `state`, bound to `host` when given,
/// under the parent directory's shared admission guard. It may block: on
/// filesystem work, and on the kernel socket dump under its hang-only bound.
/// So async callers run it off their event loop. With `test-support`, a
/// pending [`AcquireHold`] for `state` first holds the call until it is
/// released (at most 10 s).
#[cold]
#[inline(never)]
fn acquire_bound(state: &Path, host: Option<&str>) -> io::Result<File> {
    #[cfg(feature = "test-support")]
    {
        let mut pending = ACQUIRE_HOLD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pending.as_ref().is_some_and(|hold| hold.state == state) {
            let hold = pending.take().unwrap_or_else(|| unreachable!());
            drop(pending);
            hold.active.store(true, std::sync::atomic::Ordering::SeqCst);
            // Bounded, so a caller that blocks its own loop on this hold fails
            // its test instead of hanging forever.
            let _ = hold
                .release
                .recv_timeout(std::time::Duration::from_secs(10));
            hold.active
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    // Cleanup holds the exclusive parent-directory setup guard. This shared
    // admission guard prevents starting between lock-file unlink and root retirement.
    let parent = File::open(state.parent().and_then(Path::parent).ok_or_else(refused)?)?;
    parent.lock_shared()?;
    if let Some(host) = host {
        let base = state.parent().ok_or_else(refused)?;
        let _root = directory(base)?;
        if super::uninstall::public_file(
            &base.join(".bootstrap-owner"),
            nix::unistd::Uid::effective().as_raw(),
            33,
        )? != format!("{host}\n")
        {
            return Err(refused());
        }
        let prefix = format!(
            "{}.bootstrap-rollback-",
            base.file_name().ok_or_else(refused)?.to_string_lossy()
        );
        for entry in fs::read_dir(base.parent().ok_or_else(refused)?)? {
            if entry?.file_name().to_string_lossy().starts_with(&prefix) {
                return Err(refused());
            }
        }
    }
    match fs::DirBuilder::new().mode(0o700).create(state) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let directory = directory(state)?;
    let path = at(&directory, LOCK);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Never publish a new-protocol lock beside a live legacy runtime:
            // a later cleanup would otherwise treat that unheld file as authority.
            control(&directory, false, true)
                .map_err(|_| io::Error::from(io::ErrorKind::AddrInUse))?;
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)?;
    checked_lock(&file, &path)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => io::ErrorKind::WouldBlock.into(),
        std::fs::TryLockError::Error(error) => error,
    })?;
    checked_lock(&file, &path)?;
    Ok(file)
}

/// Recheck a retained runtime description before restarting its local service.
/// # Errors
/// Refuses replacement or redirected state while the process still owns its original lock.
#[cold]
#[inline(never)]
pub fn validate(file: &File, state: &Path) -> io::Result<()> {
    let directory = directory(state)?;
    checked_lock(file, &at(&directory, LOCK))
}

// Linux unix_diag.h dump ABI with UID and VFS identity requested. Records are
// identified only by numbers the kernel reports; socket names are never read,
// so spaces, newlines or an aliased home cannot hide or impersonate an endpoint.
#[derive(Debug, PartialEq, Eq)]
struct SocketOwner {
    uid: u32,
    inode: u32,
    /// Superblock device in the kernel's internal encoding (major << 20 | minor).
    device: u32,
    /// The socket's own inode, the `N` in a holder's `socket:[N]` descriptor link.
    socket: u32,
}
#[derive(Debug, PartialEq, Eq)]
enum DumpRecord {
    /// A socket without a filesystem binding (unnamed or abstract).
    Unbound,
    Bound(SocketOwner),
    /// The kernel finished the dump without error.
    Done,
}
fn dump_request() -> [u8; 40] {
    let mut request = [0_u8; 40];
    request[0..4].copy_from_slice(&40_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20_u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    request[6..8].copy_from_slice(&0x301_u16.to_ne_bytes()); // NLM_F_REQUEST | NLM_F_DUMP
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    request[16] = 1; // AF_UNIX
    request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // Every socket state.
    request[28..32].copy_from_slice(&0x42_u32.to_ne_bytes()); // UDIAG_SHOW_UID | UDIAG_SHOW_VFS
    request
}
// Accept exactly the three record shapes this request can produce. Anything
// else, including a kernel error, proves nothing and makes inspection unsure.
fn dump_record(data: &[u8]) -> Option<DumpRecord> {
    let (kind, vfs) = match data.len() {
        20 => (3_u16, 0), // NLMSG_DONE
        48 => (20, 0),
        60 => (20, 12),
        _ => return None,
    };
    if data[0..4] != u32::try_from(data.len()).ok()?.to_ne_bytes()
        || data[4..6] != kind.to_ne_bytes()
        || data[6..8] != 2_u16.to_ne_bytes() // NLM_F_MULTI
        || data[8..12] != 1_u32.to_ne_bytes()
    {
        return None;
    }
    if kind == 3 {
        return (data[16..20] == [0; 4]).then_some(DumpRecord::Done);
    }
    let tail = 32 + vfs;
    if data[16] != 1
        || data[tail..tail + 2] != 5_u16.to_ne_bytes()
        || data[tail + 2..tail + 4] != 6_u16.to_ne_bytes()
        || data[tail + 8..tail + 10] != 8_u16.to_ne_bytes()
        || data[tail + 10..tail + 12] != 7_u16.to_ne_bytes()
    {
        return None;
    }
    if vfs == 0 {
        return Some(DumpRecord::Unbound);
    }
    if data[32..34] != 12_u16.to_ne_bytes() || data[34..36] != 1_u16.to_ne_bytes() {
        return None;
    }
    Some(DumpRecord::Bound(SocketOwner {
        uid: u32::from_ne_bytes([data[56], data[57], data[58], data[59]]),
        inode: u32::from_ne_bytes([data[36], data[37], data[38], data[39]]),
        device: u32::from_ne_bytes([data[40], data[41], data[42], data[43]]),
        socket: u32::from_ne_bytes([data[20], data[21], data[22], data[23]]),
    }))
}
// Split one kernel datagram into records. Every record this request yields is
// a multiple of four bytes, so netlink alignment never adds padding.
fn dump_datagram(mut data: &[u8], mut visit: impl FnMut(DumpRecord)) -> Option<()> {
    while !data.is_empty() {
        let length = usize::try_from(u32::from_ne_bytes(data.get(0..4)?.try_into().ok()?)).ok()?;
        if length < 16 || length % 4 != 0 || length > data.len() {
            return None;
        }
        visit(dump_record(&data[..length])?);
        data = &data[length..];
    }
    Some(())
}
/// Internal property-test entry; never inspects the host.
#[cfg(feature = "test-support")]
#[doc(hidden)]
#[must_use]
pub fn check_diagnostic_datagram(data: &[u8]) -> Option<Vec<Option<u32>>> {
    let mut owners = Vec::new();
    dump_datagram(data, |record| {
        owners.push(match record {
            DumpRecord::Bound(owner) => Some(owner.uid),
            DumpRecord::Unbound | DumpRecord::Done => None,
        });
    })?;
    Some(owners)
}

// Superblock device (kernel encoding) of the mount each file lives on, or
// `None` where the mount id or the mount table cannot be read. The mount id
// comes from an O_PATH descriptor's fdinfo, which needs no unsafe call and
// works on kernels older than statx's mount id.
#[cold]
#[inline(never)]
fn mount_devices(files: &[(PathBuf, fs::Metadata)]) -> Vec<Option<u32>> {
    let table = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let device = |path: &Path| -> Option<u32> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_PATH | nix::libc::O_NOFOLLOW)
            .open(path)
            .ok()?;
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).ok()?;
        let id = info
            .lines()
            .find_map(|line| line.strip_prefix("mnt_id:"))?
            .trim();
        let mut fields = table
            .lines()
            .map(|line| line.split(' '))
            .find_map(|mut fields| (fields.next() == Some(id)).then_some(fields))?;
        let (major, minor) = fields.nth(1)?.split_once(':')?;
        let (major, minor) = (major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?);
        (major < 1 << 12 && minor < 1 << 20).then_some(major << 20 | minor)
    };
    files.iter().map(|(path, _)| device(path)).collect()
}

// Ask the kernel whether any socket is bound to one of the given files,
// instead of inspecting private process descriptors (absent for non-dumpable
// holders) or bound names (distorted by newlines and aliases). `None` means
// the dump proved nothing, and callers retain state.
//
// Files match on owner, inode and superblock device. The kernel reports the
// superblock device, while stat reports the filesystem's own device; they
// differ on btrfs and on overlays with layers on different filesystems (#230
// R09). So the device compared is that of the mount the file lives on, from
// its mount id and the mount table, which is the same superblock device. An
// inode alone also matches unrelated sockets on other filesystems and holds a
// dead endpoint live forever (#230 R12). When the mount device is unavailable
// (old kernels, no /proc), an inode match still counts: a false match only
// preserves state.
#[cold]
#[inline(never)]
fn kernel_bound(files: &[(PathBuf, fs::Metadata)]) -> Option<bool> {
    dump_bound(files, |_| true)
}

/// The socket inodes of every socket bound to one of the given files.
#[cold]
#[inline(never)]
fn bound_sockets(files: &[(PathBuf, fs::Metadata)]) -> Option<Vec<u32>> {
    let mut sockets = Vec::new();
    dump_bound(files, |socket| {
        sockets.push(socket);
        false
    })?;
    Some(sockets)
}

/// Hang guard, in seconds, for each datagram of the kernel's socket dump.
const SOCK_DIAG_HANG_SECONDS: i64 = 30;

/// Walk the kernel's socket dump. `found` sees the socket inode of each socket
/// bound to one of `files` and returns true to stop early. The result says
/// whether any socket matched.
fn dump_bound(
    files: &[(PathBuf, fs::Metadata)],
    mut found: impl FnMut(u32) -> bool,
) -> Option<bool> {
    use nix::sys::socket::{
        MsgFlags, NetlinkAddr, SockProtocol, recvfrom, sendto, setsockopt, sockopt,
    };
    let query = socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkSockDiag,
    )
    .ok()?;
    // The kernel always answers a sock_diag dump; this bound only detects a
    // hang. A 100 ms budget made a loaded host's dump "prove nothing", so a
    // check refused (77) or kept state for a reason unrelated to the sockets
    // it asked about (#355).
    setsockopt(
        &query,
        sockopt::ReceiveTimeout,
        &nix::sys::time::TimeVal::new(SOCK_DIAG_HANG_SECONDS, 0),
    )
    .ok()?;
    let devices = mount_devices(files);
    let request = dump_request();
    if sendto(
        query.as_raw_fd(),
        &request,
        &NetlinkAddr::new(0, 0),
        MsgFlags::MSG_DONTWAIT,
    )
    .ok()?
        != request.len()
    {
        return None;
    }
    // Kernel dump datagrams stay below 32 KiB; a full buffer may be truncated.
    let mut response = vec![0_u8; 64 * 1024];
    let mut any = false;
    loop {
        let (count, source) = recvfrom::<NetlinkAddr>(query.as_raw_fd(), &mut response).ok()?;
        if count == response.len()
            || !source.is_some_and(|source| source.pid() == 0 && source.groups() == 0)
        {
            return None;
        }
        let (mut stop, mut done) = (false, false);
        dump_datagram(&response[..count], |record| match record {
            DumpRecord::Bound(owner) => {
                if files.iter().zip(&devices).any(|((_, file), device)| {
                    owner.uid == file.uid()
                        && u64::from(owner.inode) == file.ino() & 0xffff_ffff
                        && device.is_none_or(|device| device == owner.device)
                }) {
                    any = true;
                    stop |= found(owner.socket);
                }
            }
            DumpRecord::Unbound => {}
            DumpRecord::Done => done = true,
        })?;
        if stop {
            return Some(true);
        }
        if done {
            return Some(any);
        }
    }
}

/// Refuse (73) while a process of this user runs the staged payload
/// (`.bootstrap-lock/payload`) without holding a socket bound to one of this
/// install's session endpoints. A shim serves such an endpoint, and a
/// replacement stops it through that endpoint. Any other payload process (a
/// crashed attempt's agent or key preparation) has no endpoint to stop it
/// through, and it is never signalled. So a replacement checks this before
/// it stops anything, and the service and sessions stay as they are (#305
/// P2-3). Read-only. A process whose `exe` the caller cannot see is skipped:
/// it cannot be inspected or signalled by this user either.
#[cold]
#[inline(never)]
fn stage_processes(root: &File) -> Result<(), u8> {
    let payload = match fs::symlink_metadata(at(root, ".bootstrap-lock/payload")) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Err(71),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(77),
    };
    let endpoints = match directory(&at(root, "sessions")) {
        Ok(runtime) => session_sockets(&runtime)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err(71),
    };
    let endpoint_sockets = if endpoints.is_empty() {
        Vec::new()
    } else {
        bound_sockets(&endpoints).ok_or(77)?
    };
    let uid = nix::unistd::Uid::effective().as_raw();
    let me = std::process::id();
    let mut processes = 0_u32;
    for entry in fs::read_dir("/proc").map_err(|_| 77)? {
        let entry = entry.map_err(|_| 77)?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        processes += 1;
        if processes > 65_536 {
            return Err(77);
        }
        let process = entry.path();
        if pid == me || !fs::metadata(&process).is_ok_and(|owner| owner.uid() == uid) {
            continue;
        }
        let Ok(exe) = fs::metadata(process.join("exe")) else {
            continue;
        };
        if !same(&exe, &payload) {
            continue;
        }
        let serves = match fs::read_dir(process.join("fd")) {
            Ok(descriptors) => descriptors.filter_map(Result::ok).any(|descriptor| {
                fs::read_link(descriptor.path()).is_ok_and(|link| {
                    link.to_str()
                        .and_then(|link| link.strip_prefix("socket:["))
                        .and_then(|link| link.strip_suffix(']'))
                        .and_then(|inode| inode.parse::<u32>().ok())
                        .is_some_and(|inode| endpoint_sockets.contains(&inode))
                })
            }),
            // It exited during the scan: nothing runs the payload any more.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => false,
        };
        if !serves && process.join("exe").exists() {
            return Err(73);
        }
    }
    Ok(())
}
#[cold]
#[inline(never)]
fn control(runtime: &File, retire: bool, legacy: bool) -> Result<(), u8> {
    let path = at(runtime, "plugins.sock");
    let before = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(77),
    };
    if !before.file_type().is_socket()
        || before.uid() != nix::unistd::Uid::effective().as_raw()
        || before.nlink() != 1
    {
        return Err(71);
    }
    if legacy {
        let peer = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|_| 77)?;
        let address = UnixAddr::new(&path).map_err(|_| 77)?;
        match connect(peer.as_raw_fd(), &address) {
            Ok(()) => return Err(73),
            Err(nix::errno::Errno::ECONNREFUSED) => {}
            Err(_) => return Err(77),
        }
        // Legacy runtimes did not hold the lifetime lock, and a refused
        // connect alone is insufficient before listen.
        if kernel_bound(&[(path.clone(), before.clone())]).ok_or(77)? {
            return Err(73);
        }
    }
    let after = fs::symlink_metadata(&path).map_err(|_| 77)?;
    if !same(&before, &after)
        || !after.file_type().is_socket()
        || after.uid() != before.uid()
        || after.nlink() != 1
    {
        return Err(77);
    }
    if retire {
        fs::remove_file(path).map_err(|_| 77)?;
    }
    Ok(())
}
// Session endpoints belong to shims, which are non-dumpable while live, so the
// kernel table is the only sign of a holder. Any owned endpoint still bound
// means the runtime is live (73); an unreadable directory or dump is unsure.
#[cold]
#[inline(never)]
fn sessions(runtime: &File) -> Result<(), u8> {
    let files = session_sockets(runtime)?;
    if files.is_empty() {
        return Ok(());
    }
    if kernel_bound(&files).ok_or(77)? {
        return Err(73);
    }
    Ok(())
}

/// Print how many session endpoints a live shim still serves. A socket file
/// left by an exited shim is not a session: only a kernel-bound one counts.
/// A stuck-install replacement names this number before it ends them (#305).
#[cold]
#[inline(never)]
fn open_sessions(runtime: &File) -> Result<u16, u8> {
    let mut open = 0_u16;
    for file in session_sockets(runtime)? {
        if kernel_bound(std::slice::from_ref(&file)).ok_or(77)? {
            open += 1;
        }
    }
    Ok(open)
}

/// The enrolled identity in `state/identity.json`, as `<digest> <server>`:
/// the SHA-256 of its raw Ed25519 public key (the value join-key preparation
/// binds to an invitation) and the server name it was issued for. The server
/// matches both before a stuck install is replaced or re-enrolled, so this
/// runs before anything on the host changes (#305, D335). A missing or
/// unreadable identity reads as `- -`; the private key never leaves memory.
#[cold]
#[inline(never)]
fn enrolled(root: &File) -> String {
    enrolled_record(root).unwrap_or_else(|| "- -".to_owned())
}
fn enrolled_record(root: &File) -> Option<String> {
    let state = directory(&at(root, "state")).ok()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(at(&state, "identity.json"))
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 8192
    {
        return None;
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(8192));
    (&mut file).take(8193).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 8192 {
        return None;
    }
    let stored: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let server = stored.get("server_name")?.as_str()?;
    if server.is_empty()
        || server.len() > 253
        || server.starts_with(['-', '.'])
        || !server
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return None;
    }
    // Identities store DER as unpadded URL-safe base64; OpenSSL decodes the
    // standard alphabet with padding.
    let mut key = zeroize::Zeroizing::new(
        stored
            .get("key_der")?
            .as_str()?
            .replace('-', "+")
            .replace('_', "/"),
    );
    while key.len() % 4 != 0 {
        key.push('=');
    }
    let der = zeroize::Zeroizing::new(openssl::base64::decode_block(&key).ok()?);
    let public = openssl::pkey::PKey::private_key_from_pkcs8(&der)
        .ok()?
        .raw_public_key()
        .ok()?;
    let digest = openssl::sha::sha256(&public);
    let mut record = String::with_capacity(65 + server.len());
    for byte in digest {
        record.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        record.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    record.push(' ');
    record.push_str(server);
    Some(record)
}

/// The user's own `*.sock` files in the runtime and its nested sessions
/// directory, except the control socket; at most 1024 of them.
fn session_sockets(runtime: &File) -> Result<Vec<(PathBuf, fs::Metadata)>, u8> {
    let nested = match directory(&at(runtime, "sessions")) {
        Ok(nested) => Some(nested),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(71),
    };
    let mut files = Vec::new();
    for (directory, top) in [(Some(runtime), true), (nested.as_ref(), false)] {
        let Some(directory) = directory else { continue };
        for entry in fs::read_dir(at(directory, "")).map_err(|_| 77)? {
            let entry = entry.map_err(|_| 77)?;
            let name = entry.file_name();
            let name = name.as_encoded_bytes();
            if !name.ends_with(b".sock") || (top && name == b"plugins.sock") {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| 77)?;
            if metadata.file_type().is_socket()
                && metadata.uid() == nix::unistd::Uid::effective().as_raw()
            {
                files.push((entry.path(), metadata));
                if files.len() > 1024 {
                    return Err(77);
                }
            }
        }
    }
    Ok(files)
}

/// Read the start tick and state for a PID, keeping the command's closing parenthesis intact.
fn process_identity(pid: i32) -> io::Result<(u64, u8)> {
    let record = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, suffix) = record
        .rsplit_once(')')
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let mut fields = suffix.split_ascii_whitespace();
    let state = fields
        .next()
        .and_then(|value| value.as_bytes().first().copied())
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
    let start = fields
        .nth(18)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?
        .parse()
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok((start, state))
}

fn write_session_frame(stream: &mut UnixStream, frame: &Frame) -> io::Result<()> {
    stream.write_all(&frame.encode()?)
}

fn read_session_frame(stream: &mut UnixStream) -> io::Result<Frame> {
    let mut prefix = [0_u8; 4];
    stream.read_exact(&mut prefix)?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body)?;
    Frame::decode(&body)
}

fn session_id(path: &Path) -> Result<[u8; 16], u8> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".sock"))
        .ok_or(77)?;
    let id = uuid::Uuid::parse_str(name).map_err(|_| 77)?;
    if id.simple().to_string() != name {
        return Err(77);
    }
    Ok(*id.as_bytes())
}

/// Remove one unchanged endpoint only after the kernel confirms it is unbound.
fn retire_session_socket(path: &Path, before: &fs::Metadata) -> Result<(), u8> {
    let after = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(77),
    };
    if !same(before, &after)
        || !after.file_type().is_socket()
        || after.uid() != nix::unistd::Uid::effective().as_raw()
        || after.mode() & 0o777 != 0o600
        || after.nlink() != 1
    {
        return Err(77);
    }
    if kernel_bound(&[(path.to_path_buf(), after.clone())]).ok_or(77)? {
        return Err(73);
    }
    let named = fs::symlink_metadata(path).map_err(|_| 77)?;
    if !same(&after, &named) || !named.file_type().is_socket() {
        return Err(77);
    }
    fs::remove_file(path).map_err(|_| 77)
}

/// Shut down only the process authenticated by both the session socket and its Hello.
#[cold]
#[inline(never)]
fn stop_session(path: &Path, before: &fs::Metadata) -> Result<(), u8> {
    let id = session_id(path)?;
    let Ok(mut stream) = UnixStream::connect(path) else {
        if kernel_bound(&[(path.to_path_buf(), before.clone())]).ok_or(77)? {
            return Err(73);
        }
        return retire_session_socket(path, before);
    };
    let timeout = Some(Duration::from_secs(2));
    stream.set_read_timeout(timeout).map_err(|_| 77)?;
    stream.set_write_timeout(timeout).map_err(|_| 77)?;
    let credentials = getsockopt(&stream, PeerCredentials).map_err(|_| 77)?;
    let pid = credentials.pid();
    if pid <= 0 || credentials.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(77);
    }
    let (birth, state) = process_identity(pid).map_err(|_| 77)?;
    if matches!(state, b'Z' | b'X' | b'x') {
        return Err(77);
    }
    let pidfd = infraternal_shim::process_exit_descriptor(u32::try_from(pid).map_err(|_| 77)?)
        .map_err(|_| 77)?;
    if process_identity(pid).map_err(|_| 77)?.0 != birth {
        return Err(77);
    }
    let Frame::Hello {
        version,
        session,
        pid: hello_pid,
        head,
        ..
    } = read_session_frame(&mut stream).map_err(|_| 77)?
    else {
        return Err(77);
    };
    if version != 1 || session != id || i32::try_from(hello_pid).ok() != Some(pid) {
        return Err(77);
    }
    let (current_birth, current_state) = process_identity(pid).map_err(|_| 77)?;
    if current_birth != birth || matches!(current_state, b'Z' | b'X' | b'x') {
        return Err(77);
    }

    write_session_frame(&mut stream, &Frame::Attach(0)).map_err(|_| 77)?;
    write_session_frame(&mut stream, &Frame::ReadFrom(head)).map_err(|_| 77)?;
    write_session_frame(
        &mut stream,
        &Frame::Signal(nix::sys::signal::Signal::SIGHUP as u8),
    )
    .map_err(|_| 77)?;

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut frames = 0_u16;
    loop {
        if Instant::now() >= deadline || frames == 1024 {
            return Err(77);
        }
        stream
            .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
            .map_err(|_| 77)?;
        frames += 1;
        match read_session_frame(&mut stream).map_err(|_| 77)? {
            Frame::Exited(_, _) => break,
            Frame::Output(_, _)
            | Frame::Snapshot(_, _)
            | Frame::SnapshotWithFlags(_, _, _)
            | Frame::InputAck(_)
            | Frame::InputState(_, _)
            | Frame::Error(_, _) => {}
            _ => return Err(77),
        }
    }
    acknowledge_exit(&mut stream)?;
    drop(stream);
    // ExitAck proves that the shim has reaped its shell. The pidfd pins only the
    // same verified shim if it has not already retired itself.
    if process_identity(pid).is_ok_and(|(current, state)| current == birth && state != b'Z')
        && let Err(error) = infraternal_shim::signal_process_descriptor(
            std::os::fd::AsFd::as_fd(&pidfd),
            nix::sys::signal::Signal::SIGTERM,
        )
        && error.raw_os_error() != Some(nix::libc::ESRCH)
    {
        return Err(77);
    }
    wait_for_session_exit(path, before, pid, birth)
}

/// Acknowledge the shim's Exited frame. A shim from an older release (the
/// b-0.1.0 one on the #305 field host) closes its socket right after sending
/// Exited, without waiting for the ack, so the write fails with EPIPE. A
/// closed peer here already means the session is over. The caller still
/// proves that the process exited and that the endpoint is unbound.
fn acknowledge_exit(stream: &mut UnixStream) -> Result<(), u8> {
    match write_session_frame(stream, &Frame::ExitAck) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(())
        }
        Err(_) => Err(77),
    }
}

/// Wait for the verified shim to exit, then retire its unbound endpoint.
fn wait_for_session_exit(
    path: &Path,
    before: &fs::Metadata,
    pid: i32,
    birth: u64,
) -> Result<(), u8> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match process_identity(pid) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Ok((current, state)) if current != birth || matches!(state, b'Z' | b'X' | b'x') => {
                break;
            }
            Ok(_) => {}
            Err(_) => return Err(77),
        }
        if Instant::now() >= deadline {
            return Err(73);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match kernel_bound(&[(path.to_path_buf(), before.clone())]).ok_or(77)? {
            false => return retire_session_socket(path, before),
            true if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            true => return Err(73),
        }
    }
}

/// Retire all session rendezvous after the old service has stopped.
#[cold]
#[inline(never)]
fn stop_sessions(runtime: &File) -> Result<(), u8> {
    let nested = match directory(&at(runtime, "sessions")) {
        Ok(nested) => Some(nested),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(71),
    };
    let mut files = Vec::new();
    for (directory, top) in [(Some(runtime), true), (nested.as_ref(), false)] {
        let Some(directory) = directory else { continue };
        for entry in fs::read_dir(at(directory, "")).map_err(|_| 77)? {
            let entry = entry.map_err(|_| 77)?;
            let name = entry.file_name();
            if !name.as_encoded_bytes().ends_with(b".sock") || (top && name == "plugins.sock") {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| 77)?;
            if !metadata.file_type().is_socket()
                || metadata.uid() != nix::unistd::Uid::effective().as_raw()
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
            {
                return Err(71);
            }
            session_id(&path)?;
            files.push((path, metadata));
            if files.len() > 1024 {
                return Err(77);
            }
        }
    }
    for (path, metadata) in files {
        if kernel_bound(&[(path.clone(), metadata.clone())]).ok_or(77)? {
            stop_session(&path, &metadata)?;
        } else {
            retire_session_socket(&path, &metadata)?;
        }
    }
    Ok(())
}

/// Take the legacy runtime lock when present so a replacement cannot race a managed runtime.
#[cold]
#[inline(never)]
fn stop_sessions_locked(runtime: &File) -> Result<(), u8> {
    let path = at(runtime, LOCK);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&path)
                .map_err(|_| 71)?;
            checked_lock(&file, &path).map_err(|_| 71)?;
            file.try_lock().map_err(|error| lock_status(&error))?;
            checked_lock(&file, &path).map_err(|_| 71)?;
            stop_sessions(runtime)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => stop_sessions(runtime),
        Err(_) => Err(71),
    }
}
// Only a conflicting holder is live; other lock failures are uncertain.
fn lock_status(error: &std::fs::TryLockError) -> u8 {
    match error {
        std::fs::TryLockError::WouldBlock => 73,
        std::fs::TryLockError::Error(_) => 77,
    }
}

/// Internal installer entry: stdin duplicates the cleanup shell's lock descriptor.
/// Taking flock on that open description keeps it held by the shell after we exit.
/// Returns a fixed status; never emits host filesystem content.
#[must_use]
#[cold]
#[inline(never)]
pub fn command(arguments: &mut dyn Iterator<Item = std::ffi::OsString>) -> Option<u8> {
    let first = arguments.next()?;
    if first == "--bootstrap-runtime-version" {
        if arguments.next().is_some() {
            return None;
        }
        // An unwritable stdout leaves the level unread, and the script then refreshes.
        return Some(u8::from(
            io::Write::write_all(&mut io::stdout(), LEVEL).is_err(),
        ));
    }
    if first != "--bootstrap-runtime" {
        return None;
    }
    let mut execute = || -> Result<(), u8> {
        let base = arguments.next().ok_or(71)?;
        let identity = arguments.next().ok_or(71)?;
        let mode = arguments.next().ok_or(71)?;
        if arguments.next().is_some() {
            return Err(71);
        }
        let base = Path::new(&base);
        let root = private_directory(base, true).map_err(|_| 71)?;
        let metadata = root.metadata().map_err(|_| 71)?;
        if identity != format!("{}:{}", metadata.dev(), metadata.ino()).as_str() {
            return Err(71);
        }
        // The identity report needs no runtime directory and changes nothing.
        if mode == "enrolled" {
            return writeln!(io::stdout(), "{}", enrolled(&root)).map_err(|_| 77);
        }
        if mode == "stage-processes" {
            return stage_processes(&root);
        }
        let runtime = directory(&at(&root, "sessions")).map_err(|_| 71)?;
        // Session inspection takes no lock and never removes anything.
        if mode == "sessions" {
            return sessions(&runtime);
        }
        if mode == "sessions-count" {
            let open = open_sessions(&runtime)?;
            return writeln!(io::stdout(), "{open}").map_err(|_| 77);
        }
        if mode == "sessions-stop" {
            return stop_sessions_locked(&runtime);
        }
        let lock_path = at(&runtime, LOCK);
        let legacy = match fs::symlink_metadata(&lock_path) {
            Ok(_) => {
                let file: File = nix::unistd::dup(std::io::stdin()).map_err(|_| 71)?.into();
                checked_lock(&file, &lock_path).map_err(|_| 71)?;
                file.try_lock().map_err(|error| lock_status(&error))?;
                checked_lock(&file, &lock_path).map_err(|_| 71)?;
                false
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(_) => return Err(71),
        };
        let mode = mode.to_str().ok_or(71)?;
        if !matches!(mode, "inspect" | "retire") {
            return Err(71);
        }
        control(&runtime, mode == "retire", legacy)
    };
    Some(execute().err().unwrap_or(0))
}

#[cfg(test)]
#[path = "runtime_lock_tests.rs"]
mod tests;
