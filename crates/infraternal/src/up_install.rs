//! Installs a fresh system service without modifying an existing installation (#338).
//!
//! Preflight only reads. The install owns each new inode until activation succeeds;
//! errors and unwinding remove those inodes, leaving pre-existing paths alone.
use super::{
    PATH_BINARY, SERVICE_BINARY, SERVICE_NAME, check_directory, hash_stream, run_systemctl,
    systemd_unit,
};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Explain a local refusal without exposing enrollment input or command arguments.
fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// Inspect an entry itself, including dangling symlinks, without creating anything.
fn existing(path: &Path) -> io::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Read the command of an infraternal process without interpreting later remote command arguments.
fn process_command(arguments: &[u8]) -> Option<&[u8]> {
    host_command(arguments.split(|byte| *byte == 0))
}

/// Recognize both CLI spellings in process argv and parsed systemd commands (D349).
fn host_command<'a>(mut arguments: impl Iterator<Item = &'a [u8]>) -> Option<&'a [u8]> {
    let image = arguments.next()?;
    let name = image.rsplit(|byte| *byte == b'/').next()?;
    if name != b"infra" && !name.starts_with(b"infraternal") {
        return None;
    }
    // JSON output is the only root-level option that can precede a running command.
    arguments.find(|argument| *argument != b"--json")
}

/// Refuse a running server or infraternal agent, including ones using custom state paths.
fn running_install() -> io::Result<()> {
    for process in fs::read_dir("/proc")? {
        let process = process?;
        if !process
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        // Processes may exit while inspected. Read argv only in memory; never print it.
        let Ok(arguments) = fs::read(process.path().join("cmdline")) else {
            continue;
        };
        match process_command(&arguments) {
            Some(b"server") => {
                return Err(refused(
                    "An infraternal server is running on this host. Use its embedded infraternal agent; run infraternal up on a different host.",
                ));
            }
            Some(b"agent") => {
                return Err(refused(
                    "An infraternal agent is already running on this host. Manage the existing service instead of running infraternal up.",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Find installed services even when they use a custom unit name or data directory.
fn installed_services(root: &Path) -> io::Result<()> {
    for directory in [
        "etc/systemd/system",
        "run/systemd/system",
        "usr/lib/systemd/system",
        "lib/systemd/system",
    ] {
        let entries = match fs::read_dir(root.join(directory)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_name() == SERVICE_NAME {
                return Err(refused(
                    "An infraternal agent service is already installed. Manage that service instead of running infraternal up.",
                ));
            }
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "service")
            {
                continue;
            }
            // Unrelated private units need not be readable by the invoking user.
            // Root repeats this inspection before making any installation writes.
            let Ok(unit) = fs::read_to_string(entry.path()) else {
                continue;
            };
            if unit
                .lines()
                .filter_map(|line| line.trim().strip_prefix("ExecStart="))
                .filter_map(infraternal_status::exec_words)
                .any(|words| {
                    host_command(words.iter().map(String::as_bytes)) == Some(b"server".as_slice())
                })
            {
                return Err(refused(
                    "An infraternal server service is installed on this host. Use its embedded infraternal agent; run infraternal up on a different host.",
                ));
            }
        }
    }
    Ok(())
}

/// Check every installation destination and its ancestry before the first write.
/// Existing empty bases must already be 0711: this command never repairs their modes.
pub(super) fn preflight(root: &Path, owner: u32) -> io::Result<()> {
    if root == Path::new("/") {
        running_install()?;
    }
    installed_services(root)?;
    let base = root.join("var/lib/infraternal");
    if let Some(metadata) = existing(&base)? {
        check_directory(&metadata, owner)?;
        let mut entries = fs::read_dir(&base).map_err(|_| refused("An existing protected infraternal data directory was found. Use the existing service; infraternal up requires a fresh host and will not change its permissions."))?;
        if entries.next().transpose()?.is_some() || metadata.mode() & 0o7777 != 0o711 {
            return Err(refused(
                "An existing infraternal data directory was found. Use the server's embedded infraternal agent or the existing machine service; infraternal up will not change this directory.",
            ));
        }
    }

    for relative in [
        "var/lib/infraternal/bin",
        "var/lib/infraternal/agent",
        "etc/systemd/system/infraternal-agent.service",
        "etc/systemd/system/multi-user.target.wants/infraternal-agent.service",
    ] {
        if existing(&root.join(relative))?.is_some() {
            return Err(refused(
                "An infraternal agent installation already exists. Manage the existing service; inspect an obsolete installation before removing it and retrying infraternal up.",
            ));
        }
    }
    let link = root.join(PATH_BINARY.trim_start_matches('/'));
    if let Some(metadata) = existing(&link)?
        && (!metadata.file_type().is_symlink()
            || metadata.uid() != owner
            || fs::read_link(&link)? != Path::new(SERVICE_BINARY))
    {
        return Err(refused(
            "A different /usr/local/bin/infraternal already exists. Keep using it or move it aside yourself before retrying infraternal up.",
        ));
    }
    for relative in [
        "var/lib/infraternal",
        "usr/local/bin",
        "etc/systemd/system/multi-user.target.wants",
    ] {
        check_directory(&fs::symlink_metadata(root)?, owner)?;
        let mut path = root.to_path_buf();
        for component in Path::new(relative).components() {
            path.push(component);
            let Some(metadata) = existing(&path)? else {
                break;
            };
            check_directory(&metadata, owner)?;
        }
    }
    Ok(())
}

/// An inode created by this install; replacements at its pathname are never removed.
struct Created {
    /// The pathname published by this run.
    path: PathBuf,
    /// Filesystem identity protects pre-existing and concurrently replaced entries.
    identity: (u64, u64),
    /// Enrollment owns its newly created private directory and everything written in it.
    enrollment: bool,
}

/// Owns only new install paths until the service is confirmed active.
pub(super) struct Install {
    /// The namespace root, injectable for root tests without touching the host install.
    root: PathBuf,
    /// Ownership expected for both existing ancestors and newly created entries.
    owner: u32,
    /// Reverse creation order removes children before their new parent directories.
    created: Vec<Created>,
    /// A trusted service manager used for activation and rollback.
    systemctl: PathBuf,
    /// Registration may have succeeded even when the activation command returns an error.
    registered: bool,
    /// Successful activation transfers ownership to the installed service.
    committed: bool,
    /// A scoped signal listener requests rollback even during synchronous activation.
    interrupted: Option<Arc<AtomicBool>>,
}

impl Install {
    /// Repeat read-only preflight, then create the private enrollment layout under rollback.
    pub(super) fn begin(root: &Path, owner: u32, systemctl: &Path) -> io::Result<Self> {
        preflight(root, owner)?;
        let mut install = Self {
            root: root.to_owned(),
            owner,
            created: Vec::new(),
            systemctl: systemctl.to_owned(),
            registered: false,
            committed: false,
            interrupted: None,
        };
        install.directory("var/lib/infraternal", 0o711, false)?;
        install.directory("var/lib/infraternal/agent", 0o700, true)?;
        install.directory("var/lib/infraternal/bin", 0o755, true)?;
        Ok(install)
    }

    /// Attach the root helper's signal scope before enrollment can yield or activation can commit.
    #[must_use]
    pub(super) fn interrupt_on(mut self, interrupted: Arc<AtomicBool>) -> Self {
        self.interrupted = Some(interrupted);
        self
    }

    /// Observe cancellation between synchronous writes and manager operations, before commit.
    fn check_interruption(&self) -> io::Result<()> {
        if self
            .interrupted
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(super::termination::interrupted());
        }
        Ok(())
    }

    /// Record ownership immediately after creation, before any fallible write or fsync.
    fn record(&mut self, path: PathBuf, metadata: &fs::Metadata, enrollment: bool) {
        self.created.push(Created {
            path,
            identity: (metadata.dev(), metadata.ino()),
            enrollment,
        });
    }

    /// Make missing directories exclusively; existing ancestors are inspected and never chmodded.
    fn directory(&mut self, relative: &str, mode: u32, exclusive: bool) -> io::Result<PathBuf> {
        let destination = self.root.join(relative);
        let mut current = self.root.clone();
        for component in Path::new(relative).components() {
            current.push(component);
            let final_entry = current == destination;
            match fs::DirBuilder::new()
                .mode(if final_entry { mode } else { 0o755 })
                .create(&current)
            {
                Ok(()) => {
                    let metadata = fs::symlink_metadata(&current)?;
                    self.record(
                        current.clone(),
                        &metadata,
                        relative.ends_with("/agent") && final_entry,
                    );
                    fs::set_permissions(
                        &current,
                        fs::Permissions::from_mode(if final_entry { mode } else { 0o755 }),
                    )?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if final_entry && exclusive {
                        return Err(error);
                    }
                    check_directory(&fs::symlink_metadata(&current)?, self.owner)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(destination)
    }

    /// Open a unique private staging file and retain its inode even if writing later fails.
    fn staging(&mut self, destination: &Path) -> io::Result<(PathBuf, fs::File)> {
        let path = destination.with_extension(format!("{}.pending", uuid::Uuid::new_v4()));
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)?;
        self.record(path.clone(), &file.metadata()?, false);
        Ok((path, file))
    }

    /// Atomically publish completed bytes without overwriting an existing destination.
    fn publish(&mut self, staging: &Path, destination: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(staging)?;
        fs::hard_link(staging, destination)?;
        self.record(destination.to_owned(), &metadata, false);
        fs::remove_file(staging)?;
        fs::File::open(
            destination
                .parent()
                .ok_or_else(|| io::Error::other("missing install parent"))?,
        )?
        .sync_all()
    }

    /// Copy and verify the running image before its public pathname becomes visible.
    fn binary(&mut self, source: &Path) -> io::Result<()> {
        let mut input = fs::File::open(source)?;
        if !input.metadata()?.is_file() {
            return Err(refused(
                "The running image is not a regular file. Retry from an installed infraternal binary.",
            ));
        }
        let destination = self.root.join(SERVICE_BINARY.trim_start_matches('/'));
        let (staging, mut output) = self.staging(&destination)?;
        let read = hash_stream(&mut input, Some(&mut output))?;
        output.set_permissions(fs::Permissions::from_mode(0o755))?;
        output.sync_all()?;
        if hash_stream(&mut fs::File::open(&staging)?, None)? != read {
            return Err(io::Error::other(
                "installed binary differs from the running image",
            ));
        }
        self.publish(&staging, &destination)
    }

    /// Create one symlink exclusively and record its own inode, without following the target.
    fn link(&mut self, target: &Path, destination: &Path) -> io::Result<()> {
        std::os::unix::fs::symlink(target, destination)?;
        self.record(
            destination.to_owned(),
            &fs::symlink_metadata(destination)?,
            false,
        );
        Ok(())
    }

    /// Add the optional CLI alias, retaining every pre-existing path regardless of ownership.
    ///
    /// Alias ownership alone cannot grant rollback permission: an earlier install may
    /// own it. Exclusive creation records our new inode; occupied aliases stay untracked.
    fn alias(&mut self, binary: &Path) -> io::Result<()> {
        let alias = binary.with_file_name("infra");
        match self.link(Path::new("infraternal"), &alias) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(&alias)?;
                if !metadata.file_type().is_symlink()
                    || metadata.uid() != self.owner
                    || fs::read_link(&alias)? != Path::new("infraternal")
                {
                    eprintln!(
                        "infraternal: skipped infra; an existing path belongs to another command."
                    );
                }
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Publish the binary, alias and unit, committing only after the service's active check.
    pub(super) fn activate(mut self, source: &Path) -> io::Result<()> {
        self.check_interruption()?;
        self.binary(source)?;
        self.check_interruption()?;
        let path = self
            .directory("usr/local/bin", 0o755, false)?
            .join("infraternal");
        if existing(&path)?.is_none() {
            self.link(Path::new(SERVICE_BINARY), &path)?;
        } else {
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_symlink()
                || metadata.uid() != self.owner
                || fs::read_link(&path)? != Path::new(SERVICE_BINARY)
            {
                return Err(refused(
                    "The CLI pathname changed during installation. Inspect it before retrying infraternal up.",
                ));
            }
        }
        self.alias(&path)?;
        let unit = self
            .directory("etc/systemd/system", 0o755, false)?
            .join(SERVICE_NAME);
        let (staging, mut output) = self.staging(&unit)?;
        output.write_all(systemd_unit().as_bytes())?;
        output.set_permissions(fs::Permissions::from_mode(0o644))?;
        output.sync_all()?;
        self.publish(&staging, &unit)?;
        // Precreate and own enablement paths so systemctl cannot leave new directories behind.
        let enabled = self
            .directory("etc/systemd/system/multi-user.target.wants", 0o755, false)?
            .join(SERVICE_NAME);
        self.link(
            Path::new("/etc/systemd/system/infraternal-agent.service"),
            &enabled,
        )?;
        self.check_interruption()?;
        self.registered = true;
        run_systemctl(&self.systemctl, &["daemon-reload"], None)?;
        self.check_interruption()?;
        run_systemctl(&self.systemctl, &["enable", "--now", SERVICE_NAME], None)?;
        self.check_interruption()?;
        run_systemctl(
            &self.systemctl,
            &["is-active", SERVICE_NAME],
            Some("active"),
        )?;
        self.check_interruption()?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Install {
    /// Undo activation and remove only this run's unchanged inodes, including partial enrollment.
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        // Stop affects runtime state only. Disable would also delete administrator-owned
        // unit aliases; the inode journal already owns our sole enablement link.
        if self.registered {
            let _ = run_systemctl(&self.systemctl, &["stop", SERVICE_NAME], None);
        }
        for created in self.created.iter().rev() {
            let Ok(metadata) = fs::symlink_metadata(&created.path) else {
                continue;
            };
            if (metadata.dev(), metadata.ino()) != created.identity {
                continue;
            }
            let result = if created.enrollment {
                fs::remove_dir_all(&created.path)
            } else if metadata.is_dir() {
                fs::remove_dir(&created.path)
            } else {
                fs::remove_file(&created.path)
            };
            if result.is_err() {
                eprintln!(
                    "Could not remove a path created by this installation. Inspect the incomplete infraternal agent installation before retrying."
                );
            }
        }
        if self.registered {
            let _ = run_systemctl(&self.systemctl, &["daemon-reload"], None);
        }
    }
}

/// Process inspection accepts the global JSON flag and never mistakes an SSH command for a server.
#[cfg(test)]
mod tests {
    /// Global output selection can precede either long-running host mode.
    #[test]
    fn global_json_does_not_hide_a_running_install() {
        assert_eq!(
            super::process_command(b"/opt/infraternal\0--json\0server\0"),
            Some(b"server".as_slice())
        );
        assert_eq!(
            super::process_command(b"infraternal\0--json\0agent\0run\0"),
            Some(b"agent".as_slice())
        );
        assert_eq!(
            super::process_command(b"infraternal\0ssh\0host\0server\0"),
            Some(b"ssh".as_slice())
        );
        assert_eq!(super::process_command(b"other\0server\0"), None);
    }
}

/// Independent regression probes for host refusal and transactional rollback (#338).
#[cfg(test)]
#[path = "j218_review_tests.rs"]
mod j218_review;
