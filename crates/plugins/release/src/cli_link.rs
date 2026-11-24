//! World-executable CLI copy and `/usr/local/bin/infraternal` link that follow server updates (#211).
//!
//! A self-updating root server runs from `<data>/updates/current/infraternal`, inside a `0700`
//! root-only data folder that non-root users cannot traverse. Putting `/usr/local/bin/infraternal`
//! on that boot pointer would break non-root CLI invocations (`infraternal --version`, skills,
//! remote commands), while leaving `/usr/local/bin/infraternal` pointed at a static `/opt` release
//! makes the command on `PATH` lag behind every `server update apply`.
//!
//! Whenever a server switch commits (after its health check passes), during `server update adopt`,
//! and on manual rollback, this module maintains a world-executable (`0755`, root-owned) copy of
//! the server image outside `<data>`:
//!
//! ```text
//! /usr/local/lib/infraternal/infraternal           active CLI image (0755, atomic rename)
//! /usr/local/lib/infraternal/infraternal.previous  kept previous CLI image for rollback (0755)
//! /usr/local/bin/infraternal -> /usr/local/lib/infraternal/infraternal
//! ```
//!
//! **Safety invariants (P7, P8):**
//! - Before touching any file, [`check_link`] verifies that `/usr/local/bin/infraternal` is either
//!   missing or a symlink pointing to an infraternal release (the active CLI path, or a file named
//!   `infraternal`, `live`, or `current` under a folder named `infraternal`). A regular file,
//!   directory, or symlink to a foreign target is refused loudly and left untouched.
//! - New copies are streamed into a `create_new` (`O_NOFOLLOW`) temporary file in the target
//!   directory, explicitly `fchmod`ed to `0755` (independent of process umask), passed to the
//!   caller's `SELinux` labeler (`bin_t` on enforcing hosts), `fsync`ed, and published with one
//!   atomic `rename`.
//! - The previous active image is preserved via hard link + atomic rename into `infraternal.previous`
//!   before replacement, and re-publishing identical bytes is a no-op that never clobbers
//!   `infraternal.previous`.
use std::{
    fmt,
    fs::File,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

/// Default directory for the world-executable CLI image and its rollback copy.
pub const SYSTEM_LIB_DIR: &str = "/usr/local/lib/infraternal";
/// Default symlink on `PATH` for system-wide server installs.
pub const SYSTEM_PATH_LINK: &str = "/usr/local/bin/infraternal";
/// File name of the active world-executable CLI image inside [`CliPaths::lib_dir`].
pub const ACTIVE_NAME: &str = "infraternal";
/// File name of the previous CLI image kept for rollback inside [`CliPaths::lib_dir`].
pub const PREVIOUS_NAME: &str = "infraternal.previous";

/// Filesystem locations for the world-executable CLI image and its `PATH` symlink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliPaths {
    /// Directory holding the active and previous CLI images (production: [`SYSTEM_LIB_DIR`]).
    pub lib_dir: PathBuf,
    /// Symlink on `PATH` pointing at the active CLI image (production: [`SYSTEM_PATH_LINK`]).
    pub path_link: PathBuf,
}

impl CliPaths {
    /// The production system-wide paths (`/usr/local/lib/infraternal` and `/usr/local/bin/infraternal`).
    #[must_use]
    pub fn system() -> Self {
        Self {
            lib_dir: PathBuf::from(SYSTEM_LIB_DIR),
            path_link: PathBuf::from(SYSTEM_PATH_LINK),
        }
    }

    /// Path of the active world-executable CLI image (`<lib_dir>/infraternal`).
    #[must_use]
    pub fn active(&self) -> PathBuf {
        self.lib_dir.join(ACTIVE_NAME)
    }

    /// Path of the previous CLI image kept for rollback (`<lib_dir>/infraternal.previous`).
    #[must_use]
    pub fn previous(&self) -> PathBuf {
        self.lib_dir.join(PREVIOUS_NAME)
    }
}

/// What [`check_link`] found at [`CliPaths::path_link`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkStatus {
    /// The symlink does not exist yet and may be created.
    Missing,
    /// The symlink already points at [`CliPaths::active`].
    Current,
    /// The symlink points at another infraternal release (`target`) and may be re-pointed.
    Ours(PathBuf),
}

/// What [`publish`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Replaced the active CLI image with the new release and ensured the `PATH` symlink points to it.
    Updated {
        /// Whether an existing active image was preserved in `infraternal.previous`.
        previous_saved: bool,
    },
    /// The active CLI image already had identical bytes; ensured permissions, label, and symlink
    /// without touching `infraternal.previous`.
    Unchanged,
}

/// What [`restore`] did during a rollback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// Restored `infraternal.previous` atomically over the active CLI image.
    RestoredPrevious,
    /// `infraternal.previous` was absent, so the active CLI image was restored from the fallback
    /// image (for example `<data>/updates/previous/infraternal`).
    RestoredFromFallback,
    /// Neither `infraternal.previous` nor a fallback image existed; nothing changed.
    NoPrevious,
}

/// Why publishing or restoring the world-executable CLI image was refused or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliLinkError {
    /// [`CliPaths::path_link`] already exists and is not an infraternal symlink.
    Foreign {
        /// The offending link path.
        link: PathBuf,
        /// Plain-language explanation of why it was refused.
        reason: String,
    },
    /// [`CliPaths::lib_dir`] is not a safe directory owned by this account.
    UnsafeDir {
        /// The unsafe directory path.
        path: PathBuf,
        /// Plain-language explanation of what is unsafe.
        reason: &'static str,
    },
    /// Labeling the staged executable for `SELinux` (`bin_t`) failed.
    Label(String),
    /// A filesystem operation failed.
    Io {
        /// Which step failed.
        context: &'static str,
        /// Underlying OS error text.
        detail: String,
    },
}

impl fmt::Display for CliLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Foreign { link, reason } => {
                write!(f, "refusing to replace {}: {reason}", link.display())
            }
            Self::UnsafeDir { path, reason } => {
                write!(f, "refusing to use {}: {reason}", path.display())
            }
            Self::Label(detail) => write!(f, "could not label CLI image for SELinux: {detail}"),
            Self::Io { context, detail } => write!(f, "{context}: {detail}"),
        }
    }
}

impl std::error::Error for CliLinkError {}

/// Inspect [`CliPaths::path_link`] without changing anything and refuse foreign entries loudly.
///
/// Only a missing entry, a symlink to [`CliPaths::active`], or a symlink to an infraternal
/// release (`infraternal`, `live`, or `current` under a directory component named `infraternal`)
/// is accepted. Regular files, directories, and symlinks to other programs return
/// [`CliLinkError::Foreign`].
/// # Errors
/// Returns [`CliLinkError::Foreign`] when `path_link` is not ours, or [`CliLinkError::Io`] when
/// its metadata cannot be read.
pub fn check_link(paths: &CliPaths) -> Result<LinkStatus, CliLinkError> {
    let active = paths.active();
    match std::fs::symlink_metadata(&paths.path_link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let Some(target) = resolve_link_target(&paths.path_link) else {
                return Err(CliLinkError::Foreign {
                    link: paths.path_link.clone(),
                    reason: "symlink target could not be read".to_owned(),
                });
            };
            if target == active {
                return Ok(LinkStatus::Current);
            }
            if points_at_ours(&target, &active) {
                return Ok(LinkStatus::Ours(target));
            }
            Err(CliLinkError::Foreign {
                link: paths.path_link.clone(),
                reason: format!(
                    "points to {}, which is not an infraternal release",
                    target.display()
                ),
            })
        }
        Ok(_) => Err(CliLinkError::Foreign {
            link: paths.path_link.clone(),
            reason: "is not a symlink (refusing to overwrite a foreign file or directory)"
                .to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(LinkStatus::Missing),
        Err(error) => Err(io_err("could not inspect CLI PATH link", &error)),
    }
}

/// Publish `source` as a world-executable (`0755`) copy at [`CliPaths::active`], preserve any
/// prior active copy at [`CliPaths::previous`], label it via `label`, and ensure
/// [`CliPaths::path_link`] points to it.
///
/// Checks [`check_link`] first so a foreign `/usr/local/bin/infraternal` aborts loudly before any
/// directory or file is touched. Re-publishing identical bytes leaves `infraternal.previous`
/// untouched.
/// # Errors
/// Returns [`CliLinkError`] if `path_link` is foreign, `lib_dir` is unsafe, labeling fails, or
/// any filesystem step fails.
pub fn publish<F>(source: &Path, paths: &CliPaths, label: F) -> Result<PublishOutcome, CliLinkError>
where
    F: Fn(&File) -> io::Result<()>,
{
    check_link(paths)?;
    ensure_lib_dir(&paths.lib_dir)?;

    let source_file = open_regular_nofollow(source, "could not open release image")?;
    let source_digest = crate::apply::digest(&source_file).map_err(|reason| CliLinkError::Io {
        context: "could not hash release image",
        detail: reason.to_owned(),
    })?;

    let active = paths.active();
    if let Some(existing) = open_owned_regular_if_present(&active)? {
        let existing_digest = crate::apply::digest(&existing).ok();
        if existing_digest.as_deref() == Some(source_digest.as_str()) {
            ensure_mode_and_label(&existing, &label)?;
            install_symlink(&paths.path_link, &active)?;
            return Ok(PublishOutcome::Unchanged);
        }
    }

    let staged = stage_copy(&source_file, &paths.lib_dir, &label)?;
    let previous_saved =
        match preserve_active_as_previous(&paths.lib_dir, &active, &paths.previous()) {
            Ok(saved) => saved,
            Err(error) => {
                let _ = std::fs::remove_file(&staged);
                return Err(error);
            }
        };
    if let Err(error) = std::fs::rename(&staged, &active) {
        let _ = std::fs::remove_file(&staged);
        return Err(io_err("could not replace active CLI image", &error));
    }
    sync_dir(&paths.lib_dir)?;
    install_symlink(&paths.path_link, &active)?;
    Ok(PublishOutcome::Updated { previous_saved })
}

/// Restore the previous CLI image on rollback.
///
/// Checks [`check_link`] first and refuses foreign entries loudly without modifying anything.
/// When [`CliPaths::previous`] exists as a regular file owned by this account, it is atomically
/// installed over [`CliPaths::active`] via hard link + rename. Otherwise, if `fallback_source`
/// is provided (for example `<data>/updates/previous/infraternal`, covering the first rollback
/// after upgrading from a release that predated this feature), that image is copied into
/// [`CliPaths::active`] without overwriting `previous`.
/// # Errors
/// Returns [`CliLinkError`] if `path_link` is foreign, `lib_dir` is unsafe, labeling fails, or
/// any filesystem step fails.
pub fn restore<F>(
    paths: &CliPaths,
    fallback_source: Option<&Path>,
    label: F,
) -> Result<RestoreOutcome, CliLinkError>
where
    F: Fn(&File) -> io::Result<()>,
{
    check_link(paths)?;
    let active = paths.active();
    let previous = paths.previous();

    if let Some(prev_file) = open_owned_regular_if_present(&previous)? {
        ensure_lib_dir(&paths.lib_dir)?;
        ensure_mode_and_label(&prev_file, &label)?;
        let temp = paths.lib_dir.join(format!(
            ".infraternal.restore-{}",
            uuid::Uuid::new_v4().hyphenated()
        ));
        std::fs::hard_link(&previous, &temp)
            .map_err(|error| io_err("could not stage previous CLI image for rollback", &error))?;
        if let Err(error) = std::fs::rename(&temp, &active) {
            let _ = std::fs::remove_file(&temp);
            return Err(io_err("could not restore previous CLI image", &error));
        }
        sync_dir(&paths.lib_dir)?;
        install_symlink(&paths.path_link, &active)?;
        return Ok(RestoreOutcome::RestoredPrevious);
    }

    if let Some(source) = fallback_source
        && std::fs::symlink_metadata(source).is_ok()
    {
        ensure_lib_dir(&paths.lib_dir)?;
        let source_file = open_regular_nofollow(source, "could not open fallback previous image")?;
        let staged = stage_copy(&source_file, &paths.lib_dir, &label)?;
        if let Err(error) = std::fs::rename(&staged, &active) {
            let _ = std::fs::remove_file(&staged);
            return Err(io_err("could not install fallback CLI image", &error));
        }
        sync_dir(&paths.lib_dir)?;
        install_symlink(&paths.path_link, &active)?;
        return Ok(RestoreOutcome::RestoredFromFallback);
    }

    Ok(RestoreOutcome::NoPrevious)
}

/// Resolve symlink `link` lexically to an absolute path, matching `install_paths::link_target`.
fn resolve_link_target(link: &Path) -> Option<PathBuf> {
    let target = std::fs::read_link(link).ok()?;
    let joined = if target.is_absolute() {
        target
    } else {
        link.parent()?.join(target)
    };
    let mut normal = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other),
        }
    }
    Some(normal)
}

/// Whether `target` points at an infraternal release binary (ours to re-point).
fn points_at_ours(target: &Path, active: &Path) -> bool {
    if target == active {
        return true;
    }
    let named = target.file_name().is_some_and(|name| {
        ["infraternal", "live", "current"]
            .iter()
            .any(|ours| name == *ours)
    });
    named
        && target.parent().is_some_and(|dir| {
            dir.components()
                .any(|part| part.as_os_str() == "infraternal")
        })
}

/// Ensure `lib_dir` exists as a real `0755` directory owned by this account and not group/world-writable.
fn ensure_lib_dir(lib_dir: &Path) -> Result<(), CliLinkError> {
    match std::fs::symlink_metadata(lib_dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o755)
                .recursive(true)
                .create(lib_dir)
                .map_err(|err| io_err("could not create CLI image directory", &err))?;
            std::fs::set_permissions(lib_dir, std::fs::Permissions::from_mode(0o755))
                .map_err(|err| io_err("could not set permissions on CLI image directory", &err))?;
        }
        Err(error) => return Err(io_err("could not inspect CLI image directory", &error)),
        Ok(_) => {}
    }
    let meta = std::fs::symlink_metadata(lib_dir)
        .map_err(|err| io_err("could not inspect CLI image directory", &err))?;
    if !meta.is_dir() {
        return Err(CliLinkError::UnsafeDir {
            path: lib_dir.to_owned(),
            reason: "is not a real directory",
        });
    }
    if meta.uid() != nix::unistd::geteuid().as_raw() {
        return Err(CliLinkError::UnsafeDir {
            path: lib_dir.to_owned(),
            reason: "is not owned by this account",
        });
    }
    if meta.mode() & 0o022 != 0 {
        return Err(CliLinkError::UnsafeDir {
            path: lib_dir.to_owned(),
            reason: "is writable by group or others",
        });
    }
    if meta.mode() & 0o777 != 0o755 {
        std::fs::set_permissions(lib_dir, std::fs::Permissions::from_mode(0o755))
            .map_err(|err| io_err("could not set permissions on CLI image directory", &err))?;
    }
    Ok(())
}

/// Open `path` read-only without following a final symlink and verify it is a regular file.
fn open_regular_nofollow(path: &Path, context: &'static str) -> Result<File, CliLinkError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| io_err(context, &error))?;
    let meta = file.metadata().map_err(|error| io_err(context, &error))?;
    if !meta.is_file() {
        return Err(CliLinkError::Io {
            context,
            detail: "source is not a regular file".to_owned(),
        });
    }
    Ok(file)
}

/// Open `path` if it exists as a regular file owned by the effective UID (not a symlink).
fn open_owned_regular_if_present(path: &Path) -> Result<Option<File>, CliLinkError> {
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(nix::libc::ELOOP) => return Ok(None),
        Err(error) => return Err(io_err("could not open existing CLI image", &error)),
    };
    let meta = file
        .metadata()
        .map_err(|error| io_err("could not inspect existing CLI image", &error))?;
    if meta.is_file() && meta.uid() == nix::unistd::geteuid().as_raw() {
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

/// Ensure an open regular file has mode `0755` and its `SELinux` executable label.
fn ensure_mode_and_label<F>(file: &File, label: &F) -> Result<(), CliLinkError>
where
    F: Fn(&File) -> io::Result<()>,
{
    let meta = file
        .metadata()
        .map_err(|error| io_err("could not inspect CLI image permissions", &error))?;
    if meta.mode() & 0o777 != 0o755 {
        file.set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|error| io_err("could not set CLI image permissions", &error))?;
    }
    label(file).map_err(|error| CliLinkError::Label(error.to_string()))
}

/// Stream `source` into a fresh `0755` temporary file in `lib_dir`, label it, and `fsync` it.
fn stage_copy<F>(source: &File, lib_dir: &Path, label: &F) -> Result<PathBuf, CliLinkError>
where
    F: Fn(&File) -> io::Result<()>,
{
    let staged = lib_dir.join(format!(
        ".infraternal.tmp-{}",
        uuid::Uuid::new_v4().hyphenated()
    ));
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&staged)
        .map_err(|error| io_err("could not create staged CLI image", &error))?;

    let copy_result = (|| -> Result<(), CliLinkError> {
        let mut buffer = vec![0u8; 1 << 16];
        let mut offset = 0u64;
        loop {
            let count = source
                .read_at(&mut buffer, offset)
                .map_err(|error| io_err("could not read release image", &error))?;
            if count == 0 {
                break;
            }
            offset = offset.saturating_add(count as u64);
            if offset > crate::update::MAX_IMAGE {
                return Err(CliLinkError::Io {
                    context: "could not stage CLI image",
                    detail: "release image exceeds maximum allowed size".to_owned(),
                });
            }
            target
                .write_all(&buffer[..count])
                .map_err(|error| io_err("could not write staged CLI image", &error))?;
        }
        // Apply 0755 explicitly on the open descriptor so a restrictive umask cannot hide it
        // from non-root users.
        target
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|error| io_err("could not set staged CLI image permissions", &error))?;
        label(&target).map_err(|error| CliLinkError::Label(error.to_string()))?;
        target
            .sync_all()
            .map_err(|error| io_err("could not flush staged CLI image", &error))?;
        Ok(())
    })();

    if let Err(error) = copy_result {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    Ok(staged)
}

/// Hard-link `active` into `previous` atomically when `active` is a regular file owned by us.
fn preserve_active_as_previous(
    lib_dir: &Path,
    active: &Path,
    previous: &Path,
) -> Result<bool, CliLinkError> {
    if open_owned_regular_if_present(active)?.is_none() {
        return Ok(false);
    }
    let temp = lib_dir.join(format!(
        ".infraternal.prev-{}",
        uuid::Uuid::new_v4().hyphenated()
    ));
    std::fs::hard_link(active, &temp)
        .map_err(|error| io_err("could not preserve previous CLI image", &error))?;
    if let Err(error) = std::fs::rename(&temp, previous) {
        let _ = std::fs::remove_file(&temp);
        return Err(io_err("could not save previous CLI image", &error));
    }
    sync_dir(lib_dir)?;
    Ok(true)
}

/// Atomically create or re-point symlink `link` to `target`.
fn install_symlink(link: &Path, target: &Path) -> Result<(), CliLinkError> {
    if std::fs::symlink_metadata(link).is_ok_and(|meta| meta.file_type().is_symlink())
        && resolve_link_target(link).as_deref() == Some(target)
    {
        return Ok(());
    }
    let parent = link.parent().ok_or(CliLinkError::Io {
        context: "could not create CLI PATH link",
        detail: "link path has no parent directory".to_owned(),
    })?;
    if std::fs::symlink_metadata(parent).is_err() {
        std::fs::DirBuilder::new()
            .mode(0o755)
            .recursive(true)
            .create(parent)
            .map_err(|error| io_err("could not create CLI PATH link directory", &error))?;
    }
    let temp = parent.join(format!(
        ".infraternal.link-{}",
        uuid::Uuid::new_v4().hyphenated()
    ));
    std::os::unix::fs::symlink(target, &temp)
        .map_err(|error| io_err("could not stage CLI PATH symlink", &error))?;
    if let Err(error) = std::fs::rename(&temp, link) {
        let _ = std::fs::remove_file(&temp);
        return Err(io_err("could not install CLI PATH symlink", &error));
    }
    sync_dir(parent)
}

/// Flush directory `path` so renames inside it survive a crash.
fn sync_dir(path: &Path) -> Result<(), CliLinkError> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| io_err("could not sync directory", &error))
}

/// Wrap an `io::Error` into [`CliLinkError::Io`].
fn io_err(context: &'static str, error: &io::Error) -> CliLinkError {
    CliLinkError::Io {
        context,
        detail: error.to_string(),
    }
}

/// Unit tests for publishing, foreign-link refusal, labeling, and rollback restore.
#[cfg(test)]
#[path = "cli_link_tests.rs"]
mod tests;
