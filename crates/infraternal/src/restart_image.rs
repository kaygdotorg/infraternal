//! Freezes bounded replacement bytes before authentication and probes that exact image [217,224], #157.
use std::{
    fs::File,
    io::{self, Write},
    os::{fd::AsRawFd, unix::fs::FileExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) const MAX_IMAGE: u64 = 128 * 1024 * 1024;

/// One immutable Linux image, or an owner-only macOS copy retained until exec.
pub(crate) struct Image {
    pub file: File,
    #[cfg(not(target_os = "linux"))]
    directory: std::path::PathBuf,
}
impl Image {
    #[cfg(test)]
    pub(crate) fn copy(source: &File, parent: &Path) -> io::Result<Self> {
        Self::copy_limit(source, parent, MAX_IMAGE)
    }
    pub(crate) fn copy_limit(source: &File, parent: &Path, limit: u64) -> io::Result<Self> {
        let size = source.metadata()?.len();
        if size == 0 || size > limit {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut image = Self::empty(parent)?;
        // Cloning shares the source offset. Positional reads preserve the caller's
        // offset and make the verified snapshot independent of pathname changes.
        let mut offset = 0;
        let mut buffer = vec![0; 65536];
        while offset < size {
            let remaining = usize::try_from((size - offset).min(65536))
                .map_err(|_| io::ErrorKind::InvalidData)?;
            let count = source.read_at(&mut buffer[..remaining], offset)?;
            if count == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            image.file.write_all(&buffer[..count])?;
            offset += u64::try_from(count).map_err(|_| io::ErrorKind::InvalidData)?;
        }
        let mut end = [0];
        if source.read_at(&mut end, size)? != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        image.freeze()?;
        Ok(image)
    }

    #[cfg(target_os = "linux")]
    fn empty(_parent: &Path) -> io::Result<Self> {
        let fd = nix::sys::memfd::memfd_create(
            c"infraternal-replacement",
            nix::sys::memfd::MFdFlags::MFD_CLOEXEC | nix::sys::memfd::MFdFlags::MFD_ALLOW_SEALING,
        )?;
        let mut file = File::from(fd);
        // Closed stdio must never let dup2(stdin) overwrite the execution image.
        let mut reserved = Vec::new();
        while file.as_raw_fd() < 3 {
            let duplicate = file.try_clone()?;
            reserved.push(file);
            file = duplicate;
        }
        Ok(Self { file })
    }
    #[cfg(target_os = "linux")]
    fn freeze(&self) -> io::Result<()> {
        use nix::fcntl::{FcntlArg, SealFlag, fcntl};
        fcntl(
            &self.file,
            FcntlArg::F_ADD_SEALS(
                SealFlag::F_SEAL_WRITE
                    | SealFlag::F_SEAL_GROW
                    | SealFlag::F_SEAL_SHRINK
                    | SealFlag::F_SEAL_SEAL,
            ),
        )?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    fn empty(parent: &Path) -> io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        let directory = parent.join(format!("replacement-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("image"))?;
        Ok(Self { file, directory })
    }
    #[cfg(not(target_os = "linux"))]
    fn freeze(&self) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        self.file.sync_all()?;
        self.file
            .set_permissions(std::fs::Permissions::from_mode(0o500))
    }

    /// Execute a bounded, secret-free check before listeners or CA custody change.
    #[allow(dead_code)] // Wired after signature admission in the next logical slice.
    pub(crate) fn probe(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
        #[cfg(not(target_os = "linux"))]
        let path = self.directory.join("image");
        let mut command = Command::new(path);
        command
            .arg(if cfg!(test) { "--list" } else { "--version" })
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        infraternal_shim::prepare_child(&mut command);
        let mut child = command.spawn()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(io::ErrorKind::InvalidData.into())
                };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::ErrorKind::TimedOut.into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
#[cfg(not(target_os = "linux"))]
impl Drop for Image {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    #[test]
    fn snapshot_refuses_every_mutation_and_preserves_source_offset() {
        let root = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
        let path = root.join(format!("image-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"original").unwrap();
        let file = File::open(&path).unwrap();
        let image = Image::copy(&file, &root).unwrap();
        std::fs::write(&path, b"modified").unwrap();
        let mut bytes = [0; 8];
        image.file.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"original");
        #[cfg(target_os = "linux")]
        {
            use nix::fcntl::{FcntlArg, SealFlag, fcntl};
            let seals = fcntl(&image.file, FcntlArg::F_GET_SEALS).unwrap();
            assert_eq!(
                SealFlag::from_bits_retain(seals),
                SealFlag::F_SEAL_WRITE
                    | SealFlag::F_SEAL_GROW
                    | SealFlag::F_SEAL_SHRINK
                    | SealFlag::F_SEAL_SEAL
            );
            assert!(image.file.write_all_at(b"changed!", 0).is_err());
            assert!(image.file.set_len(0).is_err());
            assert!(image.file.set_len(9).is_err());
            assert!(
                fcntl(
                    &image.file,
                    FcntlArg::F_ADD_SEALS(SealFlag::F_SEAL_FUTURE_WRITE)
                )
                .is_err()
            );
        }
        std::fs::remove_file(path).unwrap();
    }
}
