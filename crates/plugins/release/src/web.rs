//! The web app build that ships with a signed release, and where a release finds it (#211 S6).
//!
//! A release image and the browser app it serves belong together: an app from another
//! build asks for script chunks the server does not have, or speaks a protocol it does
//! not know, and the page stays blank (#500). So a release carries its own web build as
//! one more signed payload, [`ARCHIVE`] (`infraternal-web.tar`), listed in the release's
//! `SHA256SUMS` like every image, so the release signer covers it with no change.
//!
//! **Where it ends up.** The updater stages the archive with the image and verifies it
//! with the same signed-release verifier. Installing the release unpacks it into
//! `<data>/updates/releases/<version>/web/` ([`extract`]). An older release without an
//! archive still installs; it just has no `web/`.
//!
//! **Which web build a server serves ([`release_web`]).** When the server's executable
//! (argv\[0\], resolved once at start, so a cold start through the `current` boot pointer
//! lands on the real release folder) sits directly in `<data>/updates/releases/<version>/`
//! and that folder holds `web/`, the server serves that folder, whatever `--web-root`
//! says. The flag is inherited across warm switches (a switch keeps the process's
//! arguments), so after an update it still names the build that ran before, which is
//! never the right one for this image. Anywhere else `--web-root` works as before.
//!
//! **Unpacking is strict.** Only regular files and folders, with plain relative names
//! (no `..`, no absolute paths, no links of any kind, no devices), at most
//! [`MAX_ENTRIES`] entries and [`MAX_ARCHIVE`] bytes, each name at most
//! [`MAX_NAME`] bytes. Everything is created fresh and private (folders 0700, files
//! 0600, never following a link), so even a signed archive cannot write outside its
//! folder or replace a file twice.
use std::{
    fs::File,
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

/// The release payload that holds the web build, as named in `SHA256SUMS`.
pub const ARCHIVE: &str = "infraternal-web.tar";
/// The folder inside `releases/<version>/` that holds the unpacked web build.
pub const FOLDER: &str = "web";
/// The largest web archive accepted (a current build is about 6.5 MB).
pub const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
/// The most entries (files and folders) one archive may hold (a current build has ~720).
pub const MAX_ENTRIES: usize = 8192;
/// The longest relative name inside the archive, in bytes.
pub const MAX_NAME: usize = 512;

/// Whether the signed checksum list `sums` names the web archive.
///
/// It only looks for the name: the caller still verifies the archive against the
/// signature with the release verifier before using it. A list that names it obliges the
/// release to carry it, so a release whose archive was stripped is refused rather than
/// installed without its web build.
#[must_use]
pub fn listed(sums: &[u8]) -> bool {
    sums.split(|byte| *byte == b'\n').any(|line| {
        // `sha256sum` writes "<hex>  <name>" (text) or "<hex> *<name>" (binary).
        line.get(64..).is_some_and(|rest| {
            rest == b"  infraternal-web.tar" || rest == b" *infraternal-web.tar"
        })
    })
}

/// Unpack the verified web `archive` into the new folder `folder`.
///
/// `folder` must not exist; it is created 0700 and holds the archive's files (0600) and
/// folders (0700). The archive is read with positional reads, so the caller's file offset
/// is untouched, and the caller keeps it unchanged (a private, locked folder) between its
/// verification and this call. The contents are flushed before this returns. On any
/// refusal the partly written folder is left for the caller to remove (it lives in a
/// `download-*` folder that the update folder's sweep deletes).
/// # Errors
/// A fixed public reason: the archive is not a well-formed tar, holds anything other
/// than plain files and folders under plain relative names, is over its bounds, or could
/// not be written.
pub fn extract(archive: &File, folder: &Path) -> Result<(), &'static str> {
    let refused = "the release's web build is malformed";
    let saved = "the release's web build could not be unpacked";
    if archive.metadata().map_err(|_| saved)?.len() > MAX_ARCHIVE {
        return Err("the release's web build is oversized");
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(folder)
        .map_err(|_| saved)?;
    let mut entries = 0usize;
    let mut tar = tar::Archive::new(Positional {
        file: archive,
        offset: 0,
    });
    for entry in tar.entries().map_err(|_| refused)? {
        let mut entry = entry.map_err(|_| refused)?;
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err("the release's web build has too many files");
        }
        let kind = entry.header().entry_type();
        // A pax global header carries no file; `tar` reads local pax and long-name
        // headers itself and never yields them.
        if kind == tar::EntryType::XGlobalHeader {
            continue;
        }
        let name = entry.path().map_err(|_| refused)?.into_owned();
        // The archive's own root (`./`, as `tar -C dir .` writes it) is the folder itself.
        if kind == tar::EntryType::Directory && is_root(&name) {
            continue;
        }
        let relative = plain_name(&name).ok_or(refused)?;
        let target = folder.join(&relative);
        match kind {
            tar::EntryType::Directory => {
                match std::fs::DirBuilder::new().mode(0o700).create(&target) {
                    Ok(()) => {}
                    // A folder may appear after files inside it already created it.
                    Err(error)
                        if error.kind() == io::ErrorKind::AlreadyExists && real_folder(&target) => {
                    }
                    Err(_) => return Err(refused),
                }
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                if let Some(parent) = relative.parent().filter(|p| !p.as_os_str().is_empty()) {
                    make_folders(folder, parent).map_err(|()| refused)?;
                }
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(&target)
                    .map_err(|_| refused)?;
                let size = entry.header().size().map_err(|_| refused)?;
                if size > MAX_ARCHIVE {
                    return Err(refused);
                }
                let copied =
                    io::copy(&mut (&mut entry).take(size), &mut file).map_err(|_| saved)?;
                if copied != size {
                    return Err(refused);
                }
            }
            // Links, devices, FIFOs and sparse files are never part of a web build.
            _ => return Err(refused),
        }
    }
    flush(folder).map_err(|()| saved)
}

/// The web folder of the release this executable runs from, if it is one (see the module docs).
///
/// `executable` is the path the process was started as (argv\[0\]); `data` is the server's
/// data folder. Both are resolved now, so a later move of the boot pointer does not change
/// the folder a running server serves. Returns `None` for a relative path, an image that
/// is not directly inside `<data>/updates/releases/<version>/`, or a release without a
/// `web/` folder.
#[must_use]
pub fn release_web(executable: &Path, data: &Path) -> Option<PathBuf> {
    if !executable.is_absolute() {
        return None;
    }
    let releases = std::fs::canonicalize(data.join("updates").join("releases")).ok()?;
    let image = std::fs::canonicalize(executable).ok()?;
    let release = image.parent()?;
    if release.parent()? != releases {
        return None;
    }
    let web = release.join(FOLDER);
    std::fs::symlink_metadata(&web)
        .is_ok_and(|metadata| metadata.is_dir())
        .then_some(web)
}

/// Mirror the web build `from` into the new folder `into` with hard links, so the kept
/// previous release (`updates/previous/`) still has its web build after its release
/// folder is removed (D295's manual roll back starts it again).
///
/// Both folders are inside `updates/`, so they are on one file system. Only regular
/// files and folders are mirrored, never a link.
/// # Errors
/// The folder could not be read or the links could not be made.
pub fn mirror(from: &Path, into: &Path) -> Result<(), &'static str> {
    let saved = "the previous release's web build could not be kept";
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(into)
        .map_err(|_| saved)?;
    for entry in std::fs::read_dir(from).map_err(|_| saved)? {
        let entry = entry.map_err(|_| saved)?;
        let kind = entry.file_type().map_err(|_| saved)?;
        let target = into.join(entry.file_name());
        if kind.is_dir() {
            mirror(&entry.path(), &target)?;
        } else if kind.is_file() {
            std::fs::hard_link(entry.path(), &target).map_err(|_| saved)?;
        }
    }
    Ok(())
}

/// A [`Read`] over a file with positional reads, so the shared file offset never moves.
struct Positional<'a> {
    /// The archive.
    file: &'a File,
    /// The next byte to read.
    offset: u64,
}
impl Read for Positional<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read_at(buffer, self.offset)?;
        self.offset += count as u64;
        Ok(count)
    }
}

/// `name` as a plain relative path (only normal components, each a sane file name), or
/// `None`. A leading `./` (what `tar -C dir .` writes) is dropped.
fn plain_name(name: &Path) -> Option<PathBuf> {
    let mut plain = PathBuf::new();
    for part in name.components() {
        match part {
            Component::CurDir => {}
            Component::Normal(part) => {
                let text = part.to_str()?;
                if text.is_empty()
                    || !text
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-+@~".contains(&byte))
                {
                    return None;
                }
                plain.push(part);
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!plain.as_os_str().is_empty() && plain.as_os_str().len() <= MAX_NAME).then_some(plain)
}

/// Whether `name` names the archive's root folder (`.` or `./`).
fn is_root(name: &Path) -> bool {
    name.components().all(|part| part == Component::CurDir)
}

/// Whether `path` is a real folder (never a link).
fn real_folder(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
}

/// Create each folder of `relative` under `root` (0700) that does not exist yet. An
/// existing entry must be a real folder: nothing here follows a link.
fn make_folders(root: &Path, relative: &Path) -> Result<(), ()> {
    let mut path = root.to_owned();
    for part in relative.components() {
        path.push(part);
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && real_folder(&path) => {}
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// Flush the unpacked files to disk: one `syncfs` on Linux, otherwise each file.
fn flush(folder: &Path) -> Result<(), ()> {
    let handle = File::open(folder).map_err(|_| ())?;
    #[cfg(target_os = "linux")]
    {
        nix::unistd::syncfs(&handle).map_err(|_| ())
    }
    #[cfg(not(target_os = "linux"))]
    {
        fn each(path: &Path) -> Result<(), ()> {
            for entry in std::fs::read_dir(path).map_err(|_| ())? {
                let entry = entry.map_err(|_| ())?;
                if entry.file_type().map_err(|_| ())?.is_dir() {
                    each(&entry.path())?;
                } else {
                    File::open(entry.path())
                        .and_then(|file| file.sync_all())
                        .map_err(|_| ())?;
                }
            }
            Ok(())
        }
        each(folder)?;
        handle.sync_all().map_err(|_| ())
    }
}

/// Unit checks for the checksum lookup, strict unpacking and the release web rule.
#[cfg(test)]
#[path = "web_tests.rs"]
mod tests;
