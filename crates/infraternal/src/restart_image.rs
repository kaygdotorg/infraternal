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
        let file = reserve_control(File::from(fd))?;
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
        Ok(Self {
            file: reserve_control(file)?,
            directory,
        })
    }
    #[cfg(not(target_os = "linux"))]
    fn freeze(&mut self) -> io::Result<()> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        self.file.sync_all()?;
        self.file
            .set_permissions(std::fs::Permissions::from_mode(0o500))?;
        // Close the writable descriptor before exec to avoid ETXTBSY. macOS has
        // no seals: the same owner can still chmod/rewrite this private copy.
        self.file = reserve_control(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                .open(self.directory.join("image"))?,
        )?;
        Ok(())
    }

    pub(crate) fn execute(
        &self,
        argv: &[std::ffi::CString],
        environment: &[std::ffi::CString],
    ) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            nix::unistd::fexecve(&self.file, argv, environment)
                .map(|_| ())
                .map_err(Into::into)
        }
        #[cfg(not(target_os = "linux"))]
        {
            use std::os::unix::ffi::OsStrExt;
            let path = std::ffi::CString::new(self.directory.join("image").as_os_str().as_bytes())
                .map_err(|_| io::ErrorKind::InvalidInput)?;
            nix::unistd::execve(&path, argv, environment)
                .map(|_| ())
                .map_err(Into::into)
        }
    }

    /// Execute a bounded, secret-free check before listeners or CA custody change.
    pub(crate) fn probe(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        let path = std::path::PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()));
        #[cfg(not(target_os = "linux"))]
        let path = self.directory.join("image");
        // Reserve null handles above stdio and control fd3. A closed fd0 can otherwise be reused
        // as a CLOEXEC source, and dup2(0,0) would close it at the probe boundary.
        let null = reserve_control(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/null")?,
        )?;
        let mut command = Command::new(path);
        command
            .arg(if cfg!(test) { "--list" } else { "--version" })
            .env_clear()
            .stdin(Stdio::from(null.try_clone()?))
            .stdout(Stdio::from(null.try_clone()?))
            .stderr(Stdio::from(null));
        infraternal_shim::prepare_child_without_control(&mut command);
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
/// Keep image/null descriptors above stdio and the isolated control fd3.
fn reserve_control(mut file: File) -> io::Result<File> {
    let mut reserved = Vec::new();
    while file.as_raw_fd() < 4 {
        let duplicate = file.try_clone()?;
        reserved.push(file);
        file = duplicate;
    }
    Ok(file)
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
    #[cfg(target_os = "linux")]
    #[test]
    fn probe_never_inherits_the_control_descriptor() {
        if let Some(path) = std::env::var_os("INFRATERNAL_PROBE_CONTROL_FIXTURE") {
            let source = File::open(&path).unwrap();
            let image = Image::copy(&source, std::path::Path::new(".")).unwrap();
            assert!(
                image.probe().is_ok(),
                "the secret-free probe must close inherited control fd3"
            );
            return;
        }
        let root = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap());
        let fixture = root.join(format!("probe-{}", uuid::Uuid::new_v4()));
        assert!(
            Command::new("cc")
                .args(["-O2", "-o"])
                .arg(&fixture)
                .arg(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures/probe-control.c")
                )
                .status()
                .unwrap()
                .success()
        );
        let result = Command::new(&fixture)
            .arg("launch")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "restart_image::tests::probe_never_inherits_the_control_descriptor",
                "--nocapture",
            ])
            .env("INFRATERNAL_PROBE_CONTROL_FIXTURE", &fixture)
            .output()
            .unwrap();
        std::fs::remove_file(fixture).unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
    }
}
