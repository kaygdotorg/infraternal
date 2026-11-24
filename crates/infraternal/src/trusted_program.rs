//! Finds programs that only root can replace, for code that runs them as root.
//!
//! A program root runs (sudo, systemctl, or the binary a root service starts)
//! is only as safe as the file and every folder above it: whoever can write
//! the file, or rename an entry in any of those folders, can make root run
//! their code. [`trusted_program`] is the one check for that rule. It is used
//! by `infraternal up` for the tools it starts and by `server init` for the
//! binary a root service will run (#146, J1087). [`trusted_folder`] applies
//! the same rule to a folder whose files a root service serves, such as the
//! web folder of a `--system` server (#146, J1151).
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

/// Why a folder's tree is not one only root can change. Only `server init`
/// asks, so it exists only in builds that carry the server.
#[cfg(feature = "plugin-server")]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum FolderError {
    /// The folder does not exist (or is not a folder).
    Missing,
    /// This path, the folder itself, a folder above it or an entry inside
    /// it, could be changed by someone other than root (or the given
    /// owner), or could not be inspected.
    Untrusted(PathBuf),
}

/// Check that nobody but root (or `owner`, which tests set to themselves)
/// can change anything a service reads from `folder`, and return the
/// folder's canonical path.
///
/// Every folder above it, along the path as given and along its canonical
/// form, follows [`trusted_program`]'s folder rule, so nobody else can swap
/// the folder; a link along the given path must sit in a folder nobody else
/// can add to. The folder itself and every folder inside it may not be
/// group- or world-writable at all (a sticky bit does not excuse them: any
/// account could add a file that gets served), and every
/// file is owned by root (or `owner`) and not writable by group or others,
/// so nobody else can change what is served. A link inside the tree is
/// refused, whatever it points to: the server would follow it to a file
/// this walk did not check, and a release's web build contains none. Other
/// file types (sockets, pipes, devices) are refused as well.
#[cfg(feature = "plugin-server")]
pub(crate) fn trusted_folder(folder: &Path, owner: u32) -> Result<PathBuf, FolderError> {
    let canonical = match fs::canonicalize(folder) {
        Ok(path) if path.is_dir() => path,
        Ok(_) => return Err(FolderError::Missing),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(FolderError::Missing),
        Err(_) => return Err(FolderError::Untrusted(folder.to_owned())),
    };
    // The folder itself is served from, so it is held to the strict rule;
    // only the folders strictly above it may be sticky (such as `/tmp`).
    if !strict_directory(&canonical, owner) {
        return Err(FolderError::Untrusted(canonical));
    }
    if let Some(above) = folder
        .ancestors()
        .skip(1)
        .chain(canonical.ancestors().skip(1))
        .find(|directory| !protected_directory(directory, owner))
    {
        return Err(FolderError::Untrusted(above.to_owned()));
    }
    // The path as given: every folder along it must be protected, and a link
    // along it must sit in a folder nobody else can add to. In a sticky,
    // writable folder an account could plant its own link and repoint it
    // later, so such a link is refused even though the canonical path is fine.
    let given =
        std::path::absolute(folder).map_err(|_| FolderError::Untrusted(folder.to_owned()))?;
    for prefix in given.ancestors() {
        if !protected_directory(prefix, owner) {
            return Err(FolderError::Untrusted(prefix.to_owned()));
        }
        let is_link = fs::symlink_metadata(prefix).is_ok_and(|m| m.file_type().is_symlink());
        if is_link
            && prefix
                .parent()
                .is_some_and(|parent| !strict_directory(parent, owner))
        {
            return Err(FolderError::Untrusted(prefix.to_owned()));
        }
    }
    let mut pending = vec![canonical.clone()];
    while let Some(directory) = pending.pop() {
        let entries =
            fs::read_dir(&directory).map_err(|_| FolderError::Untrusted(directory.clone()))?;
        for entry in entries {
            let entry = entry.map_err(|_| FolderError::Untrusted(directory.clone()))?;
            let path = entry.path();
            // `symlink_metadata`: judge a link itself, never what it points at.
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| FolderError::Untrusted(path.clone()))?;
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                if !strict_directory(&path, owner) {
                    return Err(FolderError::Untrusted(path));
                }
                pending.push(path);
            } else if !(file_type.is_file()
                && (metadata.uid() == 0 || metadata.uid() == owner)
                && metadata.permissions().mode() & 0o022 == 0)
            {
                return Err(FolderError::Untrusted(path));
            }
        }
    }
    Ok(canonical)
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

/// A directory only root (or `owner`) can add to or rename in, with no
/// sticky exception: for the served folder and everything under it, where
/// even a sticky, group- or world-writable folder lets any account add a file
/// that gets served.
#[cfg(feature = "plugin-server")]
fn strict_directory(directory: &Path, owner: u32) -> bool {
    fs::metadata(directory).is_ok_and(|metadata| {
        metadata.is_dir()
            && (metadata.uid() == 0 || metadata.uid() == owner)
            && metadata.permissions().mode() & 0o022 == 0
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
    #[cfg(feature = "plugin-server")]
    use super::{FolderError, trusted_folder};
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

    #[cfg(feature = "plugin-server")]
    /// A web-like folder the test user owns: `web/index.html` and
    /// `web/assets/app.js`, all 0755/0644 under a 0755 parent. Returns the
    /// folder's canonical path.
    fn folder_in(temporary: &TemporaryDirectory) -> std::path::PathBuf {
        fs::set_permissions(&temporary.0, fs::Permissions::from_mode(0o755)).unwrap();
        let web = temporary.0.join("web");
        fs::create_dir_all(web.join("assets")).unwrap();
        fs::write(web.join("index.html"), "<!doctype html>").unwrap();
        fs::write(web.join("assets/app.js"), "").unwrap();
        for (path, mode) in [
            (web.clone(), 0o755),
            (web.join("assets"), 0o755),
            (web.join("index.html"), 0o644),
            (web.join("assets/app.js"), 0o644),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        // Canonical, so the paths a refusal names compare equal on systems
        // whose temporary folder is reached through a link.
        fs::canonicalize(web).unwrap()
    }

    #[cfg(feature = "plugin-server")]
    /// A folder whose whole tree only its owner can change is trusted, and
    /// comes back as its canonical path, also through a trusted link.
    #[test]
    fn a_folder_only_its_owner_can_change_is_trusted() {
        let temporary = TemporaryDirectory::new();
        let web = folder_in(&temporary);
        assert_eq!(
            trusted_folder(&web, me()),
            Ok(fs::canonicalize(&web).unwrap())
        );
        let link = temporary.0.join("current-web");
        std::os::unix::fs::symlink(&web, &link).unwrap();
        assert_eq!(
            trusted_folder(&link, me()),
            Ok(fs::canonicalize(&web).unwrap())
        );
    }

    #[cfg(feature = "plugin-server")]
    /// Anything inside or above the folder that others could change is
    /// refused, and the refusal names that path.
    #[test]
    fn a_folder_others_can_change_anywhere_is_refused_by_name() {
        for (relative, mode) in [
            ("", 0o775),
            ("assets", 0o777),
            ("index.html", 0o664),
            ("assets/app.js", 0o646),
        ] {
            let temporary = TemporaryDirectory::new();
            let web = folder_in(&temporary);
            let changed = if relative.is_empty() {
                web.clone()
            } else {
                web.join(relative)
            };
            fs::set_permissions(&changed, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                trusted_folder(&web, me()),
                Err(FolderError::Untrusted(changed)),
                "{relative:?} at {mode:o}"
            );
        }
        // A writable folder above it.
        let temporary = TemporaryDirectory::new();
        let web = folder_in(&temporary);
        fs::set_permissions(&temporary.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            trusted_folder(&web, me()),
            Err(FolderError::Untrusted(web.parent().unwrap().to_owned()))
        );
        // Owned by someone else entirely: the test user cannot vouch for it.
        let temporary = TemporaryDirectory::new();
        let web = folder_in(&temporary);
        if me() != 0 {
            assert!(trusted_folder(&web, me().wrapping_add(1)).is_err());
        }
    }

    #[cfg(feature = "plugin-server")]
    /// A sticky bit excuses only the folders above the served folder: the
    /// folder itself and any folder inside it that group or others can add to
    /// is refused even when sticky (J1180, F2), because anyone could add a
    /// file there that gets served.
    #[test]
    fn a_sticky_writable_served_folder_or_subfolder_is_refused() {
        for (relative, mode) in [
            ("", 0o1777),
            ("", 0o1775),
            ("assets", 0o1777),
            ("assets", 0o1775),
        ] {
            let temporary = TemporaryDirectory::new();
            let web = folder_in(&temporary);
            let changed = if relative.is_empty() {
                web.clone()
            } else {
                web.join(relative)
            };
            fs::set_permissions(&changed, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                trusted_folder(&web, me()),
                Err(FolderError::Untrusted(changed)),
                "{relative:?} at {mode:o}"
            );
        }
        // A sticky folder above it is still fine.
        let temporary = TemporaryDirectory::new();
        let web = folder_in(&temporary);
        fs::set_permissions(&temporary.0, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(trusted_folder(&web, me()).is_ok());
    }

    #[cfg(feature = "plugin-server")]
    /// A link along the given path that sits in a sticky, writable folder is
    /// refused (J1180, F3): its owner could repoint it after the check.
    #[test]
    fn a_link_in_a_sticky_writable_folder_is_refused() {
        let target = TemporaryDirectory::new();
        let web = folder_in(&target);
        let open = TemporaryDirectory::new();
        fs::set_permissions(&open.0, fs::Permissions::from_mode(0o1777)).unwrap();
        let link = open.0.join("web");
        std::os::unix::fs::symlink(&web, &link).unwrap();
        assert!(matches!(
            trusted_folder(&link, me()),
            Err(FolderError::Untrusted(_))
        ));
    }

    #[cfg(feature = "plugin-server")]
    /// A link inside the tree is refused even when it points at a trusted
    /// file, and a link to the folder that lives in a writable folder is
    /// refused too; a missing folder is reported as missing.
    #[test]
    fn links_inside_or_through_writable_folders_and_missing_folders_are_refused() {
        let temporary = TemporaryDirectory::new();
        let web = folder_in(&temporary);
        let inner = web.join("linked.html");
        std::os::unix::fs::symlink(web.join("index.html"), &inner).unwrap();
        assert_eq!(
            trusted_folder(&web, me()),
            Err(FolderError::Untrusted(inner))
        );

        let target = TemporaryDirectory::new();
        let web = folder_in(&target);
        let open = TemporaryDirectory::new();
        fs::set_permissions(&open.0, fs::Permissions::from_mode(0o777)).unwrap();
        let link = open.0.join("web");
        std::os::unix::fs::symlink(&web, &link).unwrap();
        assert!(matches!(
            trusted_folder(&link, me()),
            Err(FolderError::Untrusted(_))
        ));

        let missing = TemporaryDirectory::new();
        assert_eq!(
            trusted_folder(&missing.0.join("absent"), me()),
            Err(FolderError::Missing)
        );
    }
}
