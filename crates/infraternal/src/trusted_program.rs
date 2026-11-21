//! Finds programs that only root can replace, for code that runs them as root.
//!
//! A program root runs (sudo, systemctl, or the binary a root service starts)
//! is only as safe as the file and every folder above it: whoever can write
//! the file, or rename an entry in any of those folders, can make root run
//! their code. [`trusted_program`] is the one check for that rule. It is used
//! by `infraternal up` for the tools it starts and by `server init` for the
//! binary a root service will run (#146, J1087).
//!
//! The rule: the file is regular, executable, owned by root (or the given
//! owner, which tests set to themselves) and not writable by group or others.
//! Every folder on the way to it, both along the path as given and along its
//! canonical form, is owned by root (or that owner) and not writable by group
//! or others, except a sticky folder (such as `/tmp` or `/nix/store`), where
//! nobody can rename or remove another account's entries.

use std::{
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// Why no trusted program came back.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ToolError {
    /// None of the candidates exists.
    Missing,
    /// The first existing candidate could be replaced by someone other than
    /// root (or the given owner), or could not be inspected.
    Untrusted,
}

/// Resolve the first existing candidate to its canonical file, checking that
/// nobody but root (or `owner`, which tests set to themselves) can replace it.
/// An existing but replaceable candidate is refused, never skipped, so a
/// tampered first choice cannot quietly fall through to another.
pub(crate) fn trusted_program<P: AsRef<Path>>(
    candidates: &[P],
    owner: u32,
) -> Result<PathBuf, ToolError> {
    for candidate in candidates {
        let candidate = candidate.as_ref();
        let canonical = match fs::canonicalize(candidate) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(ToolError::Untrusted),
        };
        // Both chains count: symlinks on the way (merged /usr, NixOS's
        // /run/current-system) live in the candidate's own directories.
        let trusted = regular_executable_of(&canonical, owner)
            && candidate
                .parent()
                .into_iter()
                .flat_map(Path::ancestors)
                .chain(canonical.parent().into_iter().flat_map(Path::ancestors))
                .all(|directory| protected_directory(directory, owner));
        return if trusted {
            Ok(canonical)
        } else {
            Err(ToolError::Untrusted)
        };
    }
    Err(ToolError::Missing)
}

/// A regular, executable file owned by root (or `owner`) that nobody else can write.
fn regular_executable_of(path: &Path, owner: u32) -> bool {
    fs::metadata(path).is_ok_and(|metadata| {
        let mode = metadata.permissions().mode();
        metadata.is_file()
            && (metadata.uid() == 0 || metadata.uid() == owner)
            && mode & 0o022 == 0
            && mode & 0o111 != 0
    })
}

/// A directory only root (or `owner`) can add to or rename in. A sticky
/// directory (such as `/nix/store`) may be group-writable: others can add
/// entries there but cannot replace the root-owned ones checked below it.
fn protected_directory(directory: &Path, owner: u32) -> bool {
    fs::metadata(directory).is_ok_and(|metadata| {
        let mode = metadata.permissions().mode();
        metadata.is_dir()
            && (metadata.uid() == 0 || metadata.uid() == owner)
            && (mode & 0o022 == 0 || mode & 0o1000 != 0)
    })
}

/// The trust rule on real files and folders, as the test user (owner = self).
#[cfg(test)]
mod tests {
    use super::{ToolError, trusted_program};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    /// Numbers each temporary folder so parallel tests never share one.
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    /// A folder under the temporary folder, removed when dropped.
    struct TemporaryDirectory(std::path::PathBuf);

    impl TemporaryDirectory {
        /// Create a fresh, empty folder named after this process and a counter.
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "infraternal-trusted-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The test account, which stands in for root as the trusted owner.
    fn me() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    /// A private directory chain the test user owns, holding one program.
    fn program_in(temporary: &TemporaryDirectory, directory_mode: u32, file_mode: u32) -> String {
        let directory = temporary.0.join("bin");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&temporary.0, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(directory_mode)).unwrap();
        let program = directory.join("tool");
        fs::write(&program, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(file_mode)).unwrap();
        program.to_str().unwrap().to_owned()
    }

    /// A program in folders only its owner can change is trusted, also
    /// under a sticky shared folder, and comes back as its canonical path.
    #[test]
    fn a_program_only_its_owner_can_replace_is_trusted_at_its_canonical_path() {
        let temporary = TemporaryDirectory::new();
        let program = program_in(&temporary, 0o755, 0o755);
        assert_eq!(
            trusted_program(&[program.as_str()], me()),
            Ok(fs::canonicalize(&program).unwrap())
        );
        // A sticky shared directory (like /nix/store) is still protected.
        let sticky = TemporaryDirectory::new();
        let program = program_in(&sticky, 0o1777, 0o755);
        assert!(trusted_program(&[program.as_str()], me()).is_ok());
    }

    /// A group- or world-writable file or folder, or a file another account
    /// owns, is refused.
    #[test]
    fn a_program_others_can_replace_is_refused() {
        for (directory_mode, file_mode) in [
            (0o755, 0o775),
            (0o755, 0o757),
            (0o777, 0o755),
            (0o775, 0o755),
        ] {
            let temporary = TemporaryDirectory::new();
            let program = program_in(&temporary, directory_mode, file_mode);
            assert_eq!(
                trusted_program(&[program.as_str()], me()),
                Err(ToolError::Untrusted),
                "directory {directory_mode:o}, file {file_mode:o}"
            );
        }
        // Owned by someone else entirely: the test user cannot vouch for it.
        let temporary = TemporaryDirectory::new();
        let program = program_in(&temporary, 0o755, 0o755);
        assert_eq!(
            trusted_program(&[program.as_str()], me().wrapping_add(1)),
            if me() == 0 {
                Ok(fs::canonicalize(&program).unwrap())
            } else {
                Err(ToolError::Untrusted)
            }
        );
    }

    /// A tampered first choice stops the search instead of falling through,
    /// while a missing one is skipped.
    #[test]
    fn a_replaceable_first_candidate_is_refused_not_skipped() {
        let bad = TemporaryDirectory::new();
        let good = TemporaryDirectory::new();
        let bad = program_in(&bad, 0o777, 0o755);
        let good = program_in(&good, 0o755, 0o755);
        assert_eq!(
            trusted_program(&[bad.as_str(), good.as_str()], me()),
            Err(ToolError::Untrusted)
        );
        let missing = TemporaryDirectory::new();
        let missing = missing.0.join("absent");
        assert_eq!(
            trusted_program(&[missing.to_str().unwrap(), good.as_str()], me()),
            Ok(fs::canonicalize(&good).unwrap())
        );
        assert_eq!(
            trusted_program(&[missing.to_str().unwrap()], me()),
            Err(ToolError::Missing)
        );
    }

    /// A link that others could swap is refused even when its target is fine.
    #[test]
    fn a_symlink_in_a_writable_directory_is_refused_even_to_a_trusted_file() {
        let target = TemporaryDirectory::new();
        let target = program_in(&target, 0o755, 0o755);
        let open = TemporaryDirectory::new();
        fs::set_permissions(&open.0, fs::Permissions::from_mode(0o777)).unwrap();
        let link = open.0.join("tool");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            trusted_program(&[link.to_str().unwrap()], me()),
            Err(ToolError::Untrusted)
        );
    }
}
