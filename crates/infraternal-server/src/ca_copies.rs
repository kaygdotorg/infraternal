//! Persists only authenticated encrypted CA copies in private XDG state outside SQLite; publication is atomic and durable [168], #78.
use crate::{
    ca::{CaError, wrapping::WrappedCa},
    remote_startup::{private_directory, private_file},
};
use std::{
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Private encrypted-copy storage; it never owns a plaintext signing key.
pub struct CaCopies {
    directory: PathBuf,
}
impl CaCopies {
    /// Open or create the private administrator-copy directory under CA state.
    /// # Errors
    /// Refuses unsafe ownership, modes, paths or storage failures.
    pub fn new(ca_directory: &Path) -> Result<Self, CaError> {
        private_directory(ca_directory).map_err(|_| CaError)?;
        let directory = ca_directory.join("administrators");
        match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(CaError),
        }
        private_directory(&directory).map_err(|_| CaError)?;
        Ok(Self { directory })
    }
    /// File name of one member's copy. The member name is hashed, so it never reaches
    /// the file system as a path component. Refuses an empty or over-256-byte member
    /// and generation 0 (generations start at 1).
    fn path(&self, member: &str, generation: u64) -> Result<PathBuf, CaError> {
        if member.is_empty() || member.len() > 256 || generation == 0 {
            return Err(CaError);
        }
        Ok(self.directory.join(format!(
            "administrator-{}.{}.json",
            crate::auth::hash(member),
            generation
        )))
    }
    /// Read a bounded copy for one exact member generation without following symlinks.
    /// # Errors
    /// Refuses absent, unsafe, malformed or differently bound copies.
    pub fn read(&self, member: &str, generation: u64) -> Result<WrappedCa, CaError> {
        private_directory(&self.directory).map_err(|_| CaError)?;
        let bytes = private_file(&self.path(member, generation)?).map_err(|_| CaError)?;
        let copy = WrappedCa::decode(&bytes)?;
        if copy.member != member || copy.epoch != generation {
            return Err(CaError);
        }
        Ok(copy)
    }
    /// Publish encrypted bytes with file and directory durability before returning.
    /// # Errors
    /// Refuses unsafe directories, oversized copies or failed storage operations.
    pub fn publish(&self, member: &str, generation: u64, copy: &WrappedCa) -> Result<(), CaError> {
        private_directory(&self.directory).map_err(|_| CaError)?;
        if copy.member != member || copy.epoch != generation {
            return Err(CaError);
        }
        let destination = self.path(member, generation)?;
        let bytes = serde_json::to_vec(copy).map_err(|_| CaError)?;
        if bytes.len() > 8192 {
            return Err(CaError);
        }
        let temporary = self
            .directory
            .join(format!(".copy-{}", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&temporary)
                .map_err(|_| CaError)?;
            file.write_all(&bytes).map_err(|_| CaError)?;
            file.sync_all().map_err(|_| CaError)?;
            // Rename replaces the directory entry; it never follows a destination
            // symlink. Current role generation is checked by the caller's writer tx.
            std::fs::rename(&temporary, &destination).map_err(|_| CaError)?;
            std::fs::File::open(&self.directory)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| CaError)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
    /// Remove only this generation; repeated removal is harmless.
    /// # Errors
    /// Refuses unsafe directories or failed removal/durability operations.
    pub fn remove(&self, member: &str, generation: u64) -> Result<(), CaError> {
        private_directory(&self.directory).map_err(|_| CaError)?;
        match std::fs::remove_file(self.path(member, generation)?) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CaError),
        }
        std::fs::File::open(&self.directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| CaError)
    }
}

#[cfg(test)]
#[path = "ca_copies_tests.rs"]
mod tests;
