//! Admits signed immutable replacement bytes and separates root-only CA transfer from self reload [217,224,226], #157.

use std::os::fd::AsRawFd;
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    path::{Component, PathBuf},
};

pub(crate) struct Opened {
    pub image: crate::restart_image::Image,
    pub path: PathBuf,
    pub warm: bool,
}
impl Opened {
    pub(crate) fn open(path: PathBuf) -> io::Result<Self> {
        Self::open_with(path, verify_release_fd)
    }

    /// Retain the current kernel image before shutdown for late-exec recovery.
    pub(crate) fn running() -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::{OsStrExt, OsStringExt};

            let file = File::open("/proc/self/exe")?;
            let invoked = std::env::args_os()
                .next()
                .map(PathBuf::from)
                .ok_or(io::ErrorKind::NotFound)?;
            // Keep an explicit service path verbatim. When PATH supplied a
            // relative argv[0], capture the kernel-resolved executable now so
            // a later memfd recovery does not bind it to a changed cwd.
            let path = if invoked.is_absolute() {
                invoked
            } else {
                let resolved = std::env::current_exe()?;
                if file.metadata()?.nlink() == 0 {
                    // Atomic installation unlinks the running inode. Its kernel
                    // label is not a pathname: retain the live install target
                    // for the next reload after sealed recovery [217,250], #188.
                    // Check the inode first so a literal filename ending in this
                    // suffix stays intact; preserve non-UTF-8 pathname bytes too.
                    let path = resolved
                        .as_os_str()
                        .as_bytes()
                        .strip_suffix(b" (deleted)")
                        .ok_or(io::ErrorKind::NotFound)?;
                    PathBuf::from(std::ffi::OsString::from_vec(path.to_vec()))
                } else {
                    resolved
                }
            };
            let image = crate::restart_image::Image::copy_limit(
                &file,
                Path::new("/"),
                RUNNING_IMAGE_LIMIT,
            )?;
            let warm = nix::unistd::Uid::effective().is_root()
                && infraternal_server::ca_handoff_binary::capable(&image.file).unwrap_or(false);
            Ok(Self { image, path, warm })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::open(std::env::current_exe()?)
        }
    }

    /// Reload may reuse the exact running bytes; a changed install image still needs a signature.
    pub(crate) fn open_reload(path: PathBuf) -> io::Result<Self> {
        Self::open_with(path, |file, path| {
            if same_running_bytes(file)? {
                Ok(())
            } else {
                verify_release_fd(file, path)
            }
        })
    }

    pub(crate) fn open_with(
        path: PathBuf,
        verify: impl FnOnce(&File, &Path) -> io::Result<()>,
    ) -> io::Result<Self> {
        #[cfg(test)]
        TEST_OPENS.with(|count| count.set(count.get() + 1));
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Refuse FIFO/device candidates without waiting for a writer before
        // fstat can validate the inode. Never follow the final symlink, and keep
        // the checked image close-on-exec until fexecve consumes this exact fd.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)?;
        let metadata = file.metadata()?;
        let owner = nix::unistd::Uid::effective().as_raw();
        if !metadata.is_file()
            || metadata.mode() & 0o111 == 0
            || metadata.mode() & 0o6022 != 0
            || (metadata.uid() != owner && metadata.uid() != 0)
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        // Only a regular inode reaches any read/signature/ELF probe. Preserve
        // every other status flag when returning to ordinary blocking reads.
        let flags = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_GETFL)?;
        let flags = nix::fcntl::OFlag::from_bits_retain(flags);
        nix::fcntl::fcntl(
            &file,
            nix::fcntl::FcntlArg::F_SETFL(flags & !nix::fcntl::OFlag::O_NONBLOCK),
        )?;
        // A closed standard descriptor can be reused by open. Keep the checked
        // image above fd2 so stdin redirection cannot overwrite its inode handle.
        // Clones retain this exact inode; the target pathname is still opened once.
        let mut reserved = Vec::new();
        while file.as_raw_fd() < 3 {
            let duplicate = file.try_clone()?;
            reserved.push(file);
            file = duplicate;
        }
        drop(reserved);
        let mut root_protected = metadata.uid() == 0;
        let mut private = false;
        let ancestors: Vec<_> = path
            .parent()
            .ok_or(io::ErrorKind::InvalidInput)?
            .ancestors()
            .collect();
        for parent in ancestors.iter().rev() {
            let metadata = std::fs::symlink_metadata(parent)?;
            if !metadata.is_dir()
                || (metadata.uid() != owner && metadata.uid() != 0)
                || metadata.mode() & 0o002 != 0
                || (metadata.mode() & 0o020 != 0 && !private)
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            root_protected &= metadata.uid() == 0 && metadata.mode() & 0o022 == 0;
            if metadata.uid() == owner && metadata.mode() & 0o777 == 0o700 {
                private = true;
            }
        }
        let running = File::open("/proc/self/exe")
            .and_then(|file| file.metadata())
            .is_ok_and(|running| {
                running.dev() == metadata.dev() && running.ino() == metadata.ino()
            });
        // Running development/test images may carry debug sections. Only the
        // kernel-pinned current image gets this larger bound; replacements stay at 128 MiB.
        let limit = if running {
            RUNNING_IMAGE_LIMIT
        } else {
            crate::restart_image::MAX_IMAGE
        };
        let image = crate::restart_image::Image::copy_limit(
            &file,
            path.parent().ok_or(io::ErrorKind::InvalidInput)?,
            limit,
        )?;
        verify(&image.file, &path)?;
        image.probe()?;
        let warm = owner == 0
            && root_protected
            && infraternal_server::ca_handoff_binary::capable(&image.file).unwrap_or(false);
        Ok(Self { image, path, warm })
    }
}

impl std::ops::Deref for Opened {
    type Target = crate::restart_image::Image;
    fn deref(&self) -> &Self::Target {
        &self.image
    }
}

/// Authenticate metadata and the sealed execution descriptor, never reopen the candidate.
fn verify_release_fd(file: &File, path: &Path) -> io::Result<()> {
    verify_metadata(
        file,
        path,
        infraternal_server::release_manifest::verify_release_manifest,
    )
}

pub(crate) fn artifact_name() -> &'static str {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("x86_64", "linux") => "infraternal-x86_64-musl",
        ("aarch64", "linux") => "infraternal-aarch64-musl",
        ("x86_64", "macos") => "infraternal-x86_64-macos",
        ("aarch64", "macos") => "infraternal-aarch64-macos",
        _ => "unsupported-target",
    }
}

/// Bound for copying the kernel-pinned running image, which in development
/// and test builds carries debug sections. Debug test binaries of the whole
/// CLI reached 540 MB with mesh SSH (#221), past the earlier 512 MiB; release
/// binaries are about 22 MB, and replacements keep the 128 MiB bound.
pub(crate) const RUNNING_IMAGE_LIMIT: u64 = 768 * 1024 * 1024;

fn public_file(path: &Path, limit: u64) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(file)
}
fn public_bytes(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let file = public_file(path, limit)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| io::ErrorKind::InvalidData)? > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}
fn verify_metadata(
    file: &File,
    path: &Path,
    verify: impl Fn(
        &File,
        &str,
        &[u8],
        &[u8],
    ) -> Result<String, infraternal_server::release_verify::ReleaseError>,
) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let manifest = public_bytes(&parent.join("MANIFEST"), 65536)?;
    let signature = public_bytes(&parent.join("MANIFEST.sig"), 1024)?;
    let version = public_file(&parent.join("VERSION"), 128)?;
    let version = crate::restart_image::Image::copy_limit(&version, parent, 128)?;
    let identity = verify(&version.file, "VERSION", &manifest, &signature)
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
    let mut declared = vec![
        0;
        usize::try_from(version.file.metadata()?.len())
            .map_err(|_| io::ErrorKind::InvalidData)?
    ];
    version.file.read_exact_at(&mut declared, 0)?;
    if declared != format!("{identity}\n").as_bytes() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let image_identity = verify(file, artifact_name(), &manifest, &signature)
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
    if image_identity != identity {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

/// The self-reload exception is an exact-byte comparison with the kernel-pinned
/// running image, after the candidate has been sealed. It cannot admit changed code.
#[cfg(target_os = "linux")]
fn same_running_bytes(candidate: &File) -> io::Result<bool> {
    use std::os::unix::fs::FileExt;
    #[cfg(target_os = "linux")]
    let running = File::open("/proc/self/exe")?;
    let size = candidate.metadata()?.len();
    if size != running.metadata()?.len() {
        return Ok(false);
    }
    let mut first = vec![0; 65536];
    let mut second = vec![0; 65536];
    let mut offset = 0;
    while offset < size {
        let count =
            usize::try_from((size - offset).min(65536)).map_err(|_| io::ErrorKind::InvalidData)?;
        candidate.read_exact_at(&mut first[..count], offset)?;
        running.read_exact_at(&mut second[..count], offset)?;
        if first[..count] != second[..count] {
            return Ok(false);
        }
        offset += u64::try_from(count).map_err(|_| io::ErrorKind::InvalidData)?;
    }
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
fn same_running_bytes(_candidate: &File) -> io::Result<bool> {
    Ok(false)
}

#[cfg(test)]
#[path = "restart_fixture.rs"]
pub(crate) mod fixture;

#[cfg(test)]
std::thread_local! { static TEST_OPENS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn reset_test_opens() {
    TEST_OPENS.with(|count| count.set(0));
}
#[cfg(test)]
pub(crate) fn test_opens() -> usize {
    TEST_OPENS.with(std::cell::Cell::get)
}

#[cfg(test)]
#[path = "restart_signature_audit_tests.rs"]
mod audit_tests;
