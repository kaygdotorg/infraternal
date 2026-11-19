//! Descriptor-relative I/O for the server-data move. Writable ancestors and
//! entries owned by other accounts are rejected before any privileged I/O.

use nix::{
    dir::Dir,
    fcntl::{AtFlags, OFlag, open, openat, readlinkat, renameat},
    sys::stat::{FileStat, Mode, SFlag, fstatat, mkdirat},
    unistd::{Gid, Uid, UnlinkatFlags, fchown, symlinkat, unlinkat},
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, Metadata, Permissions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};

/// The device and inode that a transaction is allowed to replace or remove.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Identity {
    /// Filesystem device.
    dev: u64,
    /// Inode number within the device.
    ino: u64,
}

impl Identity {
    /// Read an object's identity through its open descriptor.
    pub(super) fn of(file: &File) -> io::Result<Self> {
        let m = file.metadata()?;
        Ok(Self {
            dev: m.dev(),
            ino: m.ino(),
        })
    }

    /// Whether both objects are on the same filesystem device.
    pub(super) fn same_device(self, other: Self) -> bool {
        self.dev == other.dev
    }
}

/// Refuse absolute path traversal through symlinks or writable ancestors.
/// A directory's owner must be root or the current user.
pub(super) fn directory(path: &Path, create: bool) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("expected an absolute folder"));
    }
    let mut dir = File::from(open("/", dir_flags(), Mode::empty())?);
    for part in path.components().skip(1) {
        let Component::Normal(name) = part else {
            return Err(invalid("folder contains a parent traversal"));
        };
        dir = match child_dir(&dir, name) {
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                make_dir(&dir, name)?
            }
            result => result?,
        };
        let metadata = dir.metadata()?;
        if (metadata.uid() != 0 && metadata.uid() != Uid::effective().as_raw())
            || metadata.mode() & 0o022 != 0
        {
            return Err(invalid(
                "folder has an untrusted owner or writable ancestor",
            ));
        }
    }
    Ok(dir)
}

/// Split a path into its pinned parent and single-component filename.
pub(super) fn parent(path: &Path, create: bool) -> io::Result<(File, &OsStr)> {
    let dir = path
        .parent()
        .ok_or_else(|| invalid("missing parent folder"))?;
    let leaf = path
        .file_name()
        .ok_or_else(|| invalid("missing file name"))?;
    Ok((directory(dir, create)?, leaf))
}

/// Descriptor flags for opening a directory without following links.
fn dir_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
}

/// Open a child directory relative to a pinned parent.
pub(super) fn child_dir(dir: &File, name: &OsStr) -> io::Result<File> {
    Ok(File::from(openat(dir, name, dir_flags(), Mode::empty())?))
}

/// Create a private child, and make the parent entry durable.
pub(super) fn make_dir(dir: &File, name: &OsStr) -> io::Result<File> {
    mkdirat(dir, name, Mode::from_bits_truncate(0o700))?;
    dir.sync_all()?;
    child_dir(dir, name)
}

/// Read the names contained in this descriptor, independent of the original path.
pub(super) fn names(dir: &File) -> io::Result<Vec<OsString>> {
    let mut entries = Dir::openat(dir, ".", dir_flags(), Mode::empty())?;
    let mut names = Vec::new();
    for entry in entries.iter() {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if !matches!(name, b"." | b"..") {
            names.push(OsStr::from_bytes(name).to_owned());
        }
    }
    Ok(names)
}

/// Open only a regular, same-owner, single-link file, with metadata checked on the fd.
pub(super) fn regular(dir: &File, name: &OsStr) -> io::Result<File> {
    let before = entry(dir, name)?;
    if kind(&before) != SFlag::S_IFREG || before.st_nlink != 1 {
        return Err(invalid("expected a regular file with one link"));
    }
    let flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    let file = File::from(openat(dir, name, flags, Mode::empty())?);
    let after = file.metadata()?;
    checked(&before, &after)?;
    if !after.is_file() || after.nlink() != 1 {
        return Err(invalid("file changed while opening it"));
    }
    Ok(file)
}

/// Open a trusted root of a data tree, rejecting a mounted directory.
pub(super) fn tree(dir: &File, name: &OsStr) -> io::Result<File> {
    let stat = entry(dir, name)?;
    let child = child_dir(dir, name)?;
    checked(&stat, &child.metadata()?)?;
    Ok(child)
}

/// Inspect a leaf without dereferencing it, before opening or unlinking it.
#[allow(
    clippy::unnecessary_cast,
    reason = "stat device and mode widths vary across supported Unix targets"
)]
fn entry(dir: &File, name: &OsStr) -> io::Result<FileStat> {
    let info = fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
    if info.st_uid != Uid::effective().as_raw()
        || info.st_dev as u64 != dir.metadata()?.dev()
        || (kind(&info) != SFlag::S_IFLNK && info.st_mode as u32 & 0o022 != 0)
    {
        return Err(invalid(
            "entry has an unsupported owner, mode, or filesystem",
        ));
    }
    check_mount(dir, name)?;
    Ok(info)
}

/// Reject same-device bind mounts as well as mount points on another device.
#[cfg(target_os = "linux")]
fn check_mount(dir: &File, name: &OsStr) -> io::Result<()> {
    use rustix::fs::{AtFlags, StatxFlags, statx};
    let mask = StatxFlags::MNT_ID;
    let current = statx(dir, ".", AtFlags::empty(), mask)?;
    let child = statx(dir, name, AtFlags::SYMLINK_NOFOLLOW, mask)?;
    if (current.stx_mask & child.stx_mask & mask.bits()) != 0
        && current.stx_mnt_id != child.stx_mnt_id
    {
        return Err(invalid("entry crosses a mount boundary"));
    }
    Ok(())
}

/// On other platforms the caller compares filesystem device identifiers.
#[cfg(not(target_os = "linux"))]
fn check_mount(_dir: &File, _name: &OsStr) -> io::Result<()> {
    Ok(())
}

/// Decode only the type bits of an lstat result across supported Unix targets.
fn kind(stat: &FileStat) -> SFlag {
    SFlag::from_bits_truncate(stat.st_mode)
}

/// Ensure an opened entry is the same safe object inspected before opening.
#[allow(
    clippy::unnecessary_cast,
    reason = "stat device and inode widths vary across supported Unix targets"
)]
fn checked(before: &FileStat, after: &Metadata) -> io::Result<()> {
    if before.st_dev as u64 != after.dev()
        || before.st_ino as u64 != after.ino()
        || after.uid() != Uid::effective().as_raw()
        || after.mode() & 0o022 != 0
    {
        return Err(invalid("entry changed while opening it"));
    }
    Ok(())
}

/// Copy every durable entry into an empty private directory and sync it.
pub(super) fn copy_tree(from: &File, to: &File) -> io::Result<()> {
    for name in names(from)? {
        copy_entry(from, to, &name)?;
    }
    to.sync_all()
}

/// Copy one descriptor-checked file or directory, or reproduce a safe relative link.
/// Sockets belong to the old process and are recreated by the new process.
pub(super) fn copy_entry(from: &File, to: &File, name: &OsStr) -> io::Result<()> {
    let info = entry(from, name)?;
    match kind(&info) {
        SFlag::S_IFDIR => {
            let source = tree(from, name)?;
            let child = make_dir(to, name)?;
            copy_tree(&source, &child)?;
            preserve_copy(&source, &child)?;
        }
        SFlag::S_IFREG => {
            let mut source = regular(from, name)?;
            let mut child = new_file(to, name)?;
            io::copy(&mut source, &mut child)?;
            preserve_copy(&source, &child)?;
            source.rewind_and_compare(child)?;
        }
        SFlag::S_IFLNK => {
            let link = readlinkat(from, name)?;
            if !Path::new(&link)
                .components()
                .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
            {
                return Err(invalid("link leaves the data folder"));
            }
            symlinkat(link.as_os_str(), to, name)?;
            let copied = fstatat(to, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
            if copied.st_gid != info.st_gid {
                nix::unistd::fchownat(
                    to,
                    name,
                    None,
                    Some(Gid::from_raw(info.st_gid)),
                    AtFlags::AT_SYMLINK_NOFOLLOW,
                )?;
            }
        }
        SFlag::S_IFSOCK => {}
        _ => return Err(invalid("unsupported file type in data folder")),
    }
    Ok(())
}

/// Create an exclusive 0600 regular file.
fn new_file(dir: &File, name: &OsStr) -> io::Result<File> {
    let flags =
        OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_CREAT | OFlag::O_EXCL;
    Ok(File::from(openat(
        dir,
        name,
        flags,
        Mode::from_bits_truncate(0o600),
    )?))
}

/// Set owner and mode in that order, then flush both content and metadata.
fn preserve(file: &File, source: &Metadata) -> io::Result<()> {
    if file.metadata()?.gid() != source.gid() {
        fchown(file, None, Some(Gid::from_raw(source.gid())))?;
    }
    let mode = source.mode() & 0o7777;
    file.set_permissions(Permissions::from_mode(mode))?;
    file.sync_all()?;
    let copied = file.metadata()?;
    if (copied.uid(), copied.gid(), copied.mode() & 0o7777) != (source.uid(), source.gid(), mode) {
        return Err(invalid("could not preserve entry ownership and mode"));
    }
    Ok(())
}

/// Finish a copied entry with the source ownership, mode, and Linux attributes.
/// Apply directory ACLs after copying children so inheritance cannot alter them.
pub(super) fn preserve_copy(source: &File, target: &File) -> io::Result<()> {
    let metadata = source.metadata()?;
    // The tree checks require both entries to belong to this effective user.
    // Set the group before the mode, since chown can clear setgid.
    preserve(target, &metadata)?;
    #[cfg(target_os = "linux")]
    copy_attributes(source, target)?;
    if target.metadata()?.mode() & 0o7777 != metadata.mode() & 0o7777 {
        return Err(invalid("copied ACL changed the entry mode"));
    }
    target.sync_all()
}

/// Copy Linux xattrs by descriptor. POSIX access and default ACLs are xattrs.
#[cfg(target_os = "linux")]
fn copy_attributes(source: &File, target: &File) -> io::Result<()> {
    use rustix::fs::{XattrFlags, fgetxattr, fgetxattr_query, fremovexattr, fsetxattr};

    let source_names = attributes(source)?;
    for name in attributes(target)? {
        let is_acl = name.as_bytes().starts_with(b"system.posix_acl_");
        if is_acl && !source_names.contains(&name) {
            // The staging parent may carry a default ACL absent on the source.
            fremovexattr(target, name.as_os_str())?;
        }
    }
    for name in source_names {
        let name = name.as_os_str();
        let mut value = vec![0; fgetxattr_query(source, name)?];
        let size = fgetxattr(source, name, value.as_mut_slice())?;
        fsetxattr(target, name, &value[..size], XattrFlags::empty())?;
    }
    Ok(())
}

/// Read the attribute names the filesystem exposes on a pinned entry.
#[cfg(target_os = "linux")]
fn attributes(dir: &File) -> io::Result<Vec<OsString>> {
    use rustix::fs::{flistxattr, flistxattr_query};

    let size = match flistxattr_query(dir) {
        Ok(size) => size,
        Err(rustix::io::Errno::OPNOTSUPP) => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut names = vec![0; size];
    let size = flistxattr(dir, names.as_mut_slice())?;
    Ok(names[..size]
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| OsStr::from_bytes(name).to_owned())
        .collect())
}

/// Compare two pinned files from byte zero, in bounded chunks.
trait Compare {
    /// Verify the copied bytes using the already-validated descriptors.
    fn rewind_and_compare(self, copy: File) -> io::Result<()>;
}

impl Compare for File {
    fn rewind_and_compare(self, copy: File) -> io::Result<()> {
        use std::io::{BufRead, BufReader, Seek};
        let mut a = BufReader::new(self);
        let mut b = BufReader::new(copy);
        a.rewind()?;
        b.rewind()?;
        loop {
            let a_bytes = a.fill_buf()?;
            let b_bytes = b.fill_buf()?;
            let count = a_bytes.len().min(b_bytes.len());
            if count == 0 {
                return if a_bytes.len() == b_bytes.len() {
                    Ok(())
                } else {
                    Err(invalid("copy length differs"))
                };
            }
            if a_bytes[..count] != b_bytes[..count] {
                return Err(invalid("copy bytes differ"));
            }
            a.consume(count);
            b.consume(count);
        }
    }
}

/// Remove one exact transaction-owned tree or make it recursively read-only.
pub(super) fn retire(
    parent: &File,
    name: &OsStr,
    identity: Identity,
    keep: bool,
) -> io::Result<()> {
    let folder = tree(parent, name)?;
    if Identity::of(&folder)? != identity {
        return Err(invalid("backup or staging folder identity changed"));
    }
    retire_contents(&folder, keep)?;
    if !keep {
        unlinkat(parent, name, UnlinkatFlags::RemoveDir)?;
    }
    parent.sync_all()
}

/// Walk without following a link, validating every entry before changing it.
fn retire_contents(dir: &File, keep: bool) -> io::Result<()> {
    if !keep {
        let mode = dir.metadata()?.mode();
        dir.set_permissions(Permissions::from_mode(mode | 0o700))?;
    }
    for name in names(dir)? {
        let info = entry(dir, &name)?;
        match kind(&info) {
            SFlag::S_IFDIR => {
                retire_contents(&tree(dir, &name)?, keep)?;
                if !keep {
                    unlinkat(dir, name.as_os_str(), UnlinkatFlags::RemoveDir)?;
                }
            }
            SFlag::S_IFREG => {
                let file = regular(dir, &name)?;
                if keep {
                    make_read_only(&file)?;
                } else {
                    unlinkat(dir, name.as_os_str(), UnlinkatFlags::NoRemoveDir)?;
                }
            }
            SFlag::S_IFLNK if keep => {}
            SFlag::S_IFLNK | SFlag::S_IFSOCK => {
                // A stopped service's socket has no data to retain.
                unlinkat(dir, name.as_os_str(), UnlinkatFlags::NoRemoveDir)?;
            }
            _ => return Err(invalid("unsupported entry in backup or staging folder")),
        }
    }
    if keep {
        make_read_only(dir)?;
    }
    dir.sync_all()
}

/// Remove write bits through an already checked descriptor.
fn make_read_only(file: &File) -> io::Result<()> {
    let mode = file.metadata()?.mode();
    file.set_permissions(Permissions::from_mode(mode & !0o222))?;
    file.sync_all()
}

/// Read a small regular file from a pinned parent, with an explicit size bound.
pub(super) fn read(dir: &File, name: &OsStr, private: bool) -> io::Result<Vec<u8>> {
    let file = regular(dir, name)?;
    let metadata = file.metadata()?;
    if private && metadata.mode() & 0o077 != 0 {
        return Err(invalid("journal is not private"));
    }
    let mut output = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut output)?;
    if output.len() > 4 * 1024 * 1024 {
        return Err(invalid("unit or journal is too large"));
    }
    Ok(output)
}

/// Publish a new file without replacing any existing directory entry.
#[cfg(target_os = "linux")]
pub(super) fn write_new(dir: &File, name: &OsStr, data: &[u8]) -> io::Result<()> {
    let scratch = OsString::from(format!(".infraternal-write-{}", uuid::Uuid::new_v4()));
    let mut file = new_file(dir, &scratch)?;
    let result = file
        .write_all(data)
        .and_then(|()| file.sync_all())
        .and_then(|()| rename_new(dir, &scratch, dir, name));
    if result.is_err() {
        let _ = unlinkat(dir, scratch.as_os_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

/// Atomically write a file and sync its directory. Keep existing unit metadata.
pub(super) fn write(
    dir: &File,
    name: &OsStr,
    data: &[u8],
    existing: Option<&File>,
) -> io::Result<()> {
    let scratch = OsString::from(format!(".infraternal-write-{}", uuid::Uuid::new_v4()));
    let mut file = new_file(dir, &scratch)?;
    let result = (|| {
        file.write_all(data)?;
        if let Some(existing) = existing {
            preserve(&file, &existing.metadata()?)?;
        } else {
            file.sync_all()?;
        }
        renameat(dir, scratch.as_os_str(), dir, name)?;
        dir.sync_all()
    })();
    if result.is_err() {
        let _ = unlinkat(dir, scratch.as_os_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

/// Swap two named folders in one durable namespace operation.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn exchange(
    left: &File,
    left_name: &OsStr,
    right: &File,
    right_name: &OsStr,
) -> io::Result<()> {
    rustix::fs::renameat_with(
        left,
        left_name,
        right,
        right_name,
        rustix::fs::RenameFlags::EXCHANGE,
    )?;
    left.sync_all()?;
    right.sync_all()
}

/// Report when the platform has no atomic directory swap.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn exchange(_: &File, _: &OsStr, _: &File, _: &OsStr) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}

/// Publish a folder only while the exact destination name is unused.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn rename_new(from: &File, old: &OsStr, to: &File, new: &OsStr) -> io::Result<()> {
    rustix::fs::renameat_with(from, old, to, new, rustix::fs::RenameFlags::NOREPLACE)?;
    from.sync_all()?;
    to.sync_all()
}

/// Publish into a name checked under its trusted parent on other Unix targets.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn rename_new(from: &File, old: &OsStr, to: &File, new: &OsStr) -> io::Result<()> {
    if fstatat(to, new, AtFlags::AT_SYMLINK_NOFOLLOW).is_ok() {
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    rename(from, old, to, new)
}

/// Rename a journaled object and persist both directory entries.
pub(super) fn rename(from: &File, old: &OsStr, to: &File, new: &OsStr) -> io::Result<()> {
    renameat(from, old, to, new)?;
    from.sync_all()?;
    to.sync_all()
}

/// Find the closest existing folder to estimate the destination's device in a dry run.
pub(super) fn existing_parent(path: &Path) -> io::Result<PathBuf> {
    let mut current = path;
    loop {
        match directory(current, false) {
            Ok(_) => return Ok(current.to_owned()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current = current.parent().ok_or(error)?;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Format a local filesystem-boundary refusal.
pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Remove exactly one validated regular file or empty directory and sync its parent.
pub(super) fn unlink(dir: &File, name: &OsStr, folder: bool) -> io::Result<()> {
    let flags = if folder {
        tree(dir, name)?;
        UnlinkatFlags::RemoveDir
    } else {
        regular(dir, name)?;
        UnlinkatFlags::NoRemoveDir
    };
    unlinkat(dir, name, flags)?;
    dir.sync_all()
}

/// Replace the record atomically, including recovery of a previous incomplete write.
pub(super) fn write_record(dir: &File, name: &OsStr, data: &[u8]) -> io::Result<()> {
    let next = OsStr::new("journal.next");
    match unlink(dir, next, false) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = new_file(dir, next)?;
    file.write_all(data)?;
    file.sync_all()?;
    rename(dir, next, dir, name)
}
