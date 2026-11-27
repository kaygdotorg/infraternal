//! Preserve an enrollment outside its install directory when a person opts in.

use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};

/// Compute the sibling destination for a validated host ID and install base.
#[must_use]
pub fn destination(base: &Path, host: &str) -> PathBuf {
    base.with_file_name(format!("infraternal-state-{host}"))
}

/// Check whether the backup path is free without following a symlink.
///
/// # Errors
/// Refuses a pre-existing file, directory or link, or an unreadable parent.
pub fn check_destination(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::ErrorKind::AlreadyExists.into()),
    }
}

/// Move the private enrollment directory into a fresh, owner-only directory.
///
/// # Errors
/// Refuses shared, foreign or linked source directories and an existing destination.
/// A failed move leaves the source in place.
pub fn preserve(source: &Path, destination: &Path, uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    fs::DirBuilder::new().mode(0o700).create(destination)?;
    let result = fs::rename(source, destination.join("enrollment"));
    if result.is_err() {
        let _ = fs::remove_dir(destination);
    }
    result
}

#[cfg(test)]
mod tests {
    //! An explicit backup preserves the exact private directory and never replaces a sibling.
    use super::*;

    /// Back up a private fixture and refuse any subsequent attempt to overwrite it.
    #[test]
    fn preserve_keeps_the_original_private_enrollment() {
        let root = std::env::temp_dir().join(format!("inf-removal-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let source = root.join("state");
        let backup = destination(&root.join("install"), "00000000000000000000000000000001");
        fs::DirBuilder::new().mode(0o700).create(&source).unwrap();
        let uid = fs::metadata(&source).unwrap().uid();
        fs::write(source.join("fixture"), b"original").unwrap();
        preserve(&source, &backup, uid).unwrap();
        assert!(!source.exists());
        assert_eq!(
            fs::read(backup.join("enrollment/fixture")).unwrap(),
            b"original"
        );
        fs::DirBuilder::new().mode(0o700).create(&source).unwrap();
        assert_eq!(
            preserve(&source, &backup, uid).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(source.is_dir());
        fs::remove_dir_all(root).unwrap();
    }
}
