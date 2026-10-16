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
    PathBuf::from(format!("/proc/self/fd/{}/{name}", file.as_raw_fd()))
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
            control(&directory, false, true).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Runtime ownership is not available",
                )
            })?;
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
    file.try_lock().map_err(io::Error::other)?;
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

// Legacy runtimes did not hold the lifetime lock. A refused connect alone is
// insufficient before listen. Ask the kernel for candidate ownership instead
// of inspecting private process descriptors, which cannot establish absence.
#[cold]
#[inline(never)]
fn legacy_bound(runtime: &Path) -> io::Result<bool> {
    let rows = fs::read_to_string("/proc/net/unix")?;
    for row in rows.lines().skip(1) {
        let mut fields = row.split_whitespace();
        let Some(inode) = fields.nth(6) else { continue };
        let Some(name) = fields.next() else { continue };
        let saved = Path::new(name);
        if !(saved.starts_with(runtime)
            || (!saved.is_absolute()
                && saved
                    .extension()
                    .is_some_and(|extension| extension == "sock")))
        {
            continue;
        }
        let inode = inode.parse::<u32>().map_err(|_| refused())?;
        if socket_uid(inode)? == nix::unistd::Uid::effective().as_raw() {
            return Ok(true);
        }
    }
    Ok(false)
}

// Linux unix_diag.h fixed exact-query ABI: only UID is requested. A response
// outside this known layout is uncertain, never permission to remove a socket.
fn diagnostic_uid(data: &[u8], inode: u32) -> io::Result<u32> {
    if data.len() != 48
        || data[0..4] != 48_u32.to_ne_bytes()
        || data[4..6] != 20_u16.to_ne_bytes()
        || data[6..8] != 0_u16.to_ne_bytes()
        || data[8..12] != 1_u32.to_ne_bytes()
        || data[16] != 1
        || data[20..24] != inode.to_ne_bytes()
        || data[32..34] != 5_u16.to_ne_bytes()
        || data[34..36] != 6_u16.to_ne_bytes()
        || data[40..42] != 8_u16.to_ne_bytes()
        || data[42..44] != 7_u16.to_ne_bytes()
    {
        return Err(refused());
    }
    Ok(u32::from_ne_bytes([data[44], data[45], data[46], data[47]]))
}
/// Internal property-test entry; never inspects the host.
#[cfg(feature = "test-support")]
#[doc(hidden)]
#[must_use]
pub fn check_diagnostic_record(data: &[u8], inode: u32) -> Option<u32> {
    diagnostic_uid(data, inode).ok()
}
#[cold]
#[inline(never)]
fn socket_uid(inode: u32) -> io::Result<u32> {
    use nix::sys::socket::{
        MsgFlags, NetlinkAddr, SockProtocol, recvfrom, sendto, setsockopt, sockopt,
    };
    let query = socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkSockDiag,
    )?;
    setsockopt(
        &query,
        sockopt::ReceiveTimeout,
        &nix::sys::time::TimeVal::new(0, 100_000),
    )?;
    let mut request = [0_u8; 40];
    request[0..4].copy_from_slice(&40_u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20_u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    request[6..8].copy_from_slice(&1_u16.to_ne_bytes()); // NLM_F_REQUEST
    request[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    request[16] = 1; // AF_UNIX
    request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
    request[24..28].copy_from_slice(&inode.to_ne_bytes());
    request[28..32].copy_from_slice(&0x40_u32.to_ne_bytes()); // UDIAG_SHOW_UID
    request[32..40].fill(0xff); // No prior socket cookie.
    if sendto(
        query.as_raw_fd(),
        &request,
        &NetlinkAddr::new(0, 0),
        MsgFlags::MSG_DONTWAIT,
    )? != request.len()
    {
        return Err(refused());
    }
    let mut response = [0_u8; 64];
    let (count, source) = recvfrom::<NetlinkAddr>(query.as_raw_fd(), &mut response)?;
    if !source.is_some_and(|source| source.pid() == 0 && source.groups() == 0) {
        return Err(refused());
    }
    diagnostic_uid(&response[..count], inode)
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
        let resolved =
            fs::read_link(format!("/proc/self/fd/{}", runtime.as_raw_fd())).map_err(|_| 77)?;
        if legacy_bound(&resolved).map_err(|_| 77)? {
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
pub fn command(arguments: &[std::ffi::OsString]) -> Option<u8> {
    if arguments.len() == 1 && arguments[0] == "--bootstrap-runtime-version" {
        return Some(0);
    }
    if arguments
        .first()
        .is_none_or(|arg| arg != "--bootstrap-runtime")
    {
        return None;
    }
    let execute = || -> Result<(), u8> {
        if arguments.len() != 4 {
            return Err(71);
        }
        let base = Path::new(&arguments[1]);
        let root = directory(base).map_err(|_| 71)?;
        let metadata = root.metadata().map_err(|_| 71)?;
        if arguments[2] != format!("{}:{}", metadata.dev(), metadata.ino()).as_str() {
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
        let mode = arguments[3].to_str().ok_or(71)?;
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
