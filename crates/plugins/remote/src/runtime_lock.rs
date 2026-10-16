//! Coordinates remote runtime lifetime with transaction cleanup without host interpreters [17], #230.

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
fn at(file: &File, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{name}", file.as_raw_fd()))
}
fn same(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}
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
    // Cleanup holds the exclusive parent-directory setup guard. This shared
    // admission guard prevents starting between lock-file unlink and root retirement.
    let parent = File::open(state.parent().and_then(Path::parent).ok_or_else(refused)?)?;
    parent.lock_shared()?;
    match fs::DirBuilder::new().mode(0o700).create(state) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let directory = directory(state)?;
    let path = at(&directory, LOCK);
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

// Legacy runtimes did not hold the lifetime lock. A refused connect alone is
// insufficient during bind-before-listen: retain a same-user bound endpoint too.
fn base_root(name: &Path) -> &Path {
    name.parent().and_then(Path::parent).unwrap_or(name)
}
fn legacy_bound(name: &Path) -> io::Result<bool> {
    let rows = fs::read_to_string("/proc/net/unix")?;
    for row in rows.lines().skip(1) {
        let fields = row.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 8 {
            continue;
        }
        let saved = Path::new(fields[7]);
        if !(saved.starts_with(base_root(name))
            || (!saved.is_absolute()
                && saved
                    .extension()
                    .is_some_and(|extension| extension == "sock")))
        {
            continue;
        }
        let expected = format!("socket:[{}]", fields[6]);
        for process in fs::read_dir("/proc")? {
            let process = process?;
            if !process
                .file_name()
                .as_encoded_bytes()
                .iter()
                .all(u8::is_ascii_digit)
                || !process
                    .metadata()
                    .is_ok_and(|metadata| metadata.uid() == nix::unistd::Uid::effective().as_raw())
            {
                continue;
            }
            let Ok(descriptors) = fs::read_dir(process.path().join("fd")) else {
                continue;
            };
            for descriptor in descriptors.flatten() {
                if fs::read_link(descriptor.path())
                    .is_ok_and(|target| target.as_os_str() == expected.as_str())
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
fn control(runtime: &File, base: &Path, retire: bool, legacy: bool) -> Result<(), u8> {
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
        if legacy_bound(&base.join("sessions/plugins.sock")).map_err(|_| 77)? {
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
/// Internal installer entry: stdin duplicates the cleanup shell's lock descriptor.
/// Taking flock on that open description keeps it held by the shell after we exit.
/// Returns a fixed status; never emits host filesystem content.
#[must_use]
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
                file.try_lock().map_err(|_| 73)?;
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
        control(&runtime, base, mode == "retire", legacy)
    };
    Some(execute().err().unwrap_or(0))
}

#[cfg(test)]
#[path = "runtime_lock_tests.rs"]
mod tests;
