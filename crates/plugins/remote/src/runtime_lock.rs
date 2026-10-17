//! Coordinates remote runtime lifetime with transaction cleanup without host interpreters [17], #230.
//! Filesystem setup stays outside CLI and supervisor pollers to bound release size [243].

use nix::sys::socket::{AddressFamily, SockFlag, SockType, UnixAddr, connect, socket};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

/// One fixed file in the private runtime state; never replace it while the runtime is live.
pub const LOCK: &str = ".lifetime-lock";

fn refused() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}
#[cold]
#[inline(never)]
fn directory(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() || metadata.mode() & 0o777 != 0o700
    {
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
#[cold]
#[inline(never)]
fn acquire_bound(state: &Path, host: Option<&str>) -> io::Result<File> {
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

// Legacy runtimes did not hold the lifetime lock. A refused connect alone is
// insufficient before listen. Ask the kernel whether any socket is bound to
// this file (UID, inode), instead of inspecting private process
// descriptors, which cannot establish absence. Unknown inspection retains state.
#[cold]
#[inline(never)]
fn legacy_bound(expected: &fs::Metadata) -> Option<bool> {
    use nix::sys::socket::{
        MsgFlags, NetlinkAddr, SockProtocol, recvfrom, sendto, setsockopt, sockopt,
    };
    // Match on owner and inode only. The kernel reports the superblock device,
    // and stat reports the filesystem's own device; they differ on btrfs and on
    // overlays with layers on different filesystems, so comparing them would
    // miss a bound endpoint there (#230 R09). A match only preserves state, so
    // a false match (same inode on another filesystem, 32-bit projection) is
    // safe. New runtimes use the lifetime lock instead of this legacy fallback.
    let inode = expected.ino() & u64::from(u32::MAX);
    let query = socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkSockDiag,
    )
    .ok()?;
    setsockopt(
        &query,
        sockopt::ReceiveTimeout,
        &nix::sys::time::TimeVal::new(0, 100_000),
    )
    .ok()?;
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
    loop {
        let (count, source) = recvfrom::<NetlinkAddr>(query.as_raw_fd(), &mut response).ok()?;
        if count == response.len()
            || !source.is_some_and(|source| source.pid() == 0 && source.groups() == 0)
        {
            return None;
        }
        let (mut bound, mut done) = (false, false);
        dump_datagram(&response[..count], |record| match record {
            DumpRecord::Bound(owner) => {
                bound |= owner.uid == expected.uid() && u64::from(owner.inode) == inode;
            }
            DumpRecord::Unbound => {}
            DumpRecord::Done => done = true,
        })?;
        if bound {
            return Some(true);
        }
        if done {
            return Some(false);
        }
    }
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
        if legacy_bound(&before).ok_or(77)? {
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
        return arguments.next().is_none().then_some(0);
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
        let root = directory(base).map_err(|_| 71)?;
        let metadata = root.metadata().map_err(|_| 71)?;
        if identity != format!("{}:{}", metadata.dev(), metadata.ino()).as_str() {
            return Err(71);
        }
        let runtime = directory(&at(&root, "sessions")).map_err(|_| 71)?;
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
