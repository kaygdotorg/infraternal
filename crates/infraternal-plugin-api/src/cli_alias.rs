//! Installs and retires the optional `infra` symlink beside a canonical CLI [349].

use std::{ffi::OsStr, fs, io, os::unix::fs::MetadataExt, path::Path};

/// Add `infra` pointing to the basename of `binary` without replacing an existing path.
///
/// Call after publishing the canonical binary in a directory trusted by `owner`.
/// Returns false for a foreign path; the installer should report that it skipped it.
/// Existing links are ours only when their owner and literal target both match.
/// # Errors
/// Returns filesystem errors other than an occupied alias path.
pub fn install(binary: &Path, owner: u32) -> io::Result<bool> {
    let target = binary
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let alias = binary.with_file_name("infra");
    match std::os::unix::fs::symlink(target, &alias) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => owned(&alias, target, owner),
        Err(error) => Err(error),
    }
}

/// Remove the short link only while its owner and target still identify our CLI.
///
/// Call before removing the canonical launcher. Foreign files, directories and
/// links, including dangling links to other commands, are preserved.
/// # Errors
/// Returns inspection or unlink errors; an absent alias is already retired.
pub fn remove(binary: &Path, owner: u32) -> io::Result<()> {
    let target = binary
        .file_name()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let alias = binary.with_file_name("infra");
    if owned(&alias, target, owner)? {
        fs::remove_file(alias)?;
    }
    Ok(())
}

/// Recognize the exact link we publish without following any foreign target.
fn owned(alias: &Path, target: &OsStr, owner: u32) -> io::Result<bool> {
    match fs::symlink_metadata(alias) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && fs::read_link(alias)? == Path::new(target)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    //! Exercise real links and foreign path preservation without global PATH changes.
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// An isolated install directory, retired even when an assertion fails.
    struct Directory(std::path::PathBuf);

    impl Directory {
        /// Allocate a unique directory for one alias scenario.
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "infra-alias-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        /// Publish a canonical executable fixture and return its owner.
        fn binary(&self) -> (std::path::PathBuf, u32) {
            let binary = self.0.join("infraternal");
            fs::write(&binary, b"first image").unwrap();
            let owner = fs::metadata(&binary).unwrap().uid();
            (binary, owner)
        }
    }

    impl Drop for Directory {
        /// Retire only this test's private files.
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Symlinks must follow atomic image replacement and repeated installs.
    #[test]
    fn alias_follows_replaced_image_and_uninstalls() {
        let directory = Directory::new();
        let (binary, owner) = directory.binary();
        assert!(install(&binary, owner).unwrap());
        assert!(install(&binary, owner).unwrap());
        let replacement = directory.0.join("new-image");
        fs::write(&replacement, b"second image").unwrap();
        fs::rename(replacement, &binary).unwrap();
        let alias = directory.0.join("infra");
        assert_eq!(fs::read(&alias).unwrap(), b"second image");
        remove(&binary, owner).unwrap();
        assert!(alias.symlink_metadata().is_err());
        assert_eq!(fs::read(binary).unwrap(), b"second image");
    }

    /// Occupied regular files, directories and dangling links belong to their owner.
    #[test]
    fn foreign_paths_survive_install_and_uninstall() {
        for kind in 0..3 {
            let directory = Directory::new();
            let (binary, owner) = directory.binary();
            let alias = directory.0.join("infra");
            match kind {
                0 => fs::write(&alias, b"foreign").unwrap(),
                1 => fs::create_dir(&alias).unwrap(),
                _ => std::os::unix::fs::symlink("missing", &alias).unwrap(),
            }
            assert!(!install(&binary, owner).unwrap());
            remove(&binary, owner).unwrap();
            assert!(alias.symlink_metadata().is_ok());
            if kind == 0 {
                assert_eq!(fs::read(&alias).unwrap(), b"foreign");
            }
            if kind == 2 {
                assert_eq!(fs::read_link(&alias).unwrap(), Path::new("missing"));
            }
        }
    }

    /// Uninstall must recheck a link replaced after installation.
    #[test]
    fn replaced_alias_and_foreign_owner_are_preserved() {
        let directory = Directory::new();
        let (binary, owner) = directory.binary();
        assert!(install(&binary, owner).unwrap());
        assert!(!install(&binary, owner.wrapping_add(1)).unwrap());
        remove(&binary, owner.wrapping_add(1)).unwrap();
        let alias = directory.0.join("infra");
        fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink("another-command", &alias).unwrap();
        remove(&binary, owner).unwrap();
        assert_eq!(fs::read_link(alias).unwrap(), Path::new("another-command"));
        remove(&directory.0.join("absent/infraternal"), owner).unwrap();
    }
}
