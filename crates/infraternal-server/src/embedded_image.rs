//! Resolve the on-disk equivalent of a sealed warm server image (#613).

use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Cold servers launch the exact kernel image. After a warm exec, the embedded
/// process needs a trusted on-disk equivalent so it can publish account login
/// images. Keep the exact kernel image as the recovery path for existing shims
/// when the on-disk image is unavailable. The update trial detects that failure.
pub(crate) fn executable(data: &Path) -> PathBuf {
    let kernel = Path::new("/proc/self/exe");
    if !nix::unistd::Uid::effective().is_root()
        || !std::fs::read_link(kernel)
            .is_ok_and(|path| path.as_os_str().as_encoded_bytes().starts_with(b"/memfd:"))
    {
        return kernel.to_owned();
    }
    match disk_image(data, kernel) {
        Ok(path) => path,
        Err(error) => {
            tracing::warn!(error_kind = ?error.kind(), "warm embedded login image unavailable");
            kernel.to_owned()
        }
    }
}

/// The forward switch supplies the exact installed release path as `argv[0]`.
/// An undo or reload may name the boot symlink or an older installation path.
/// The installed and kept release paths cover both forms of update rollback.
fn disk_image(data: &Path, kernel: &Path) -> io::Result<PathBuf> {
    use infraternal_plugin_release::apply::digest;
    let running = digest(&File::open(kernel)?).map_err(io::Error::other)?;
    let invoked = std::env::args_os().next().map(PathBuf::from);
    let installed = infraternal_plugin_release::update::server_image().map(|artifact| {
        let updates = data.join("updates");
        [
            updates
                .join("releases")
                .join(infraternal_plugin_api::VERSION)
                .join(artifact),
            updates.join("previous").join(artifact),
        ]
    });
    invoked
        .into_iter()
        .chain(installed.into_iter().flatten())
        .find_map(|path| {
            let (path, image) = open_trusted(&path, 0).ok()?;
            (digest(&image).ok().as_deref() == Some(running.as_str())).then_some(path)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "no trusted copy of the running image",
            )
        })
}

/// Open an executable under directories controlled by the expected owner.
/// Resolve the boot symlink first and use only the checked canonical path for
/// spawning. Every ancestor must be protected so another account cannot
/// replace the verified path between the digest check and a later spawn.
fn open_trusted(path: &Path, owner: u32) -> io::Result<(PathBuf, File)> {
    if !path.is_absolute() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let path = path.canonicalize()?;
    let parents: Vec<_> = path.ancestors().skip(1).collect();
    for directory in parents.into_iter().rev() {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != owner)
            || metadata.mode() & 0o022 != 0
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let image = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&path)?;
    let metadata = image.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o6022 != 0
        || metadata.mode() & 0o111 == 0
        || nix::sys::statvfs::fstatvfs(&image)?
            .flags()
            .contains(nix::sys::statvfs::FsFlags::ST_NOEXEC)
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok((path, image))
}

/// Checks the file and directory trust rules with private fixture images.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    /// An isolated fixture outside world-writable shared scratch.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A private release is usable. A writable file or parent and a foreign
    /// owner are refused even when all other properties are the same.
    #[test]
    fn release_image_refuses_writable_and_foreign_sources() {
        let base = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT")
            .or_else(|| std::env::var_os("HOME"))
            .unwrap();
        let root = PathBuf::from(base).join(format!("login-image-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        let root = Scratch(root);
        let owner = nix::unistd::geteuid().as_raw();
        let path = root.0.join("infraternal");
        std::fs::write(&path, b"fixture").unwrap();
        let mode = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        mode(&path, 0o700);
        assert!(open_trusted(&path, owner).is_ok());
        assert!(open_trusted(&path, owner + 1).is_err());
        mode(&path, 0o720);
        assert!(open_trusted(&path, owner).is_err());
        mode(&path, 0o700);
        mode(&root.0, 0o720);
        assert!(open_trusted(&path, owner).is_err());
    }
}
