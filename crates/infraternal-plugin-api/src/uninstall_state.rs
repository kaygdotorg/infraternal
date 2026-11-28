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

/// Check a new or interrupted private backup without following symlinks.
///
/// # Errors
/// Refuses an unrelated destination, duplicate enrollment, or unsafe ownership.
pub fn check_destination(source: &Path, destination: &Path, uid: u32) -> io::Result<()> {
    backup_step(source, destination, uid).map(|_| ())
}

/// The durable states around creating the container and moving the enrollment.
enum BackupStep {
    /// Create an empty private container first.
    Create,
    /// The private empty container is ready for the rename.
    Move,
    /// The only copy is already in the private backup.
    Saved,
}

/// A missing path is distinct from an existing directory with unsafe metadata.
fn private(path: &Path, uid: u32) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o7777 == 0o700 =>
        {
            Ok(true)
        }
        Ok(_) => Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Infer progress from the atomic rename. Both copies or an unrelated entry mean refuse.
fn backup_step(source: &Path, destination: &Path, uid: u32) -> io::Result<BackupStep> {
    let from = private(source, uid)?;
    if !private(destination, uid)? {
        return if from {
            Ok(BackupStep::Create)
        } else {
            Err(io::ErrorKind::NotFound.into())
        };
    }
    let mut entries = fs::read_dir(destination)?;
    let first = entries.next().transpose()?;
    let extra = entries.next().transpose()?;
    match (from, first, extra) {
        (true, None, None) => Ok(BackupStep::Move),
        (false, Some(entry), None)
            if entry.file_name() == "enrollment" && private(&entry.path(), uid)? =>
        {
            Ok(BackupStep::Saved)
        }
        _ => Err(io::ErrorKind::AlreadyExists.into()),
    }
}

/// Move the private enrollment or finish an interrupted move of that enrollment.
///
/// # Errors
/// Refuses shared, foreign or linked directories and never replaces a saved enrollment.
pub fn preserve(source: &Path, destination: &Path, uid: u32) -> io::Result<()> {
    match backup_step(source, destination, uid)? {
        BackupStep::Saved => return Ok(()),
        BackupStep::Create => fs::DirBuilder::new().mode(0o700).create(destination)?,
        BackupStep::Move => {}
    }
    fs::File::open(destination.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()?;
    fs::rename(source, destination.join("enrollment"))?;
    fs::File::open(destination)?.sync_all()?;
    fs::File::open(source.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()
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
        fs::DirBuilder::new().mode(0o700).create(&backup).unwrap();
        preserve(&source, &backup, uid).unwrap();
        assert!(!source.exists());
        assert_eq!(
            fs::read(backup.join("enrollment/fixture")).unwrap(),
            b"original"
        );
        preserve(&source, &backup, uid).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&source).unwrap();
        assert_eq!(
            preserve(&source, &backup, uid).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(source.is_dir());
        fs::remove_dir_all(root).unwrap();
    }
}
