//! Installs a fresh system service without modifying an existing installation (#338).
//!
//! Preflight only reads, including when it models recovery of an unfinished install.
//! Synced inode records precede publication; errors, signals and the next privileged
//! attempt recover only those entries, leaving pre-existing paths alone.
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

/// Kernel and manager inspection stays separate from filesystem installation writes.
#[path = "up_inspect.rs"]
mod inspect;

/// Durable ownership records permit a later privileged run to recover an interrupted install.
#[path = "up_journal.rs"]
mod journal;

/// Check every installation destination and its ancestry before the first write.
/// Existing empty bases must already be 0711: this command never repairs their modes.
pub(super) fn preflight(root: &Path, owner: u32) -> io::Result<()> {
    let systemctl = if root == Path::new("/") {
        super::trusted_tool(&super::SYSTEMCTL_CANDIDATES, super::Failure::NoSystemd)
            .map_err(|_| refused("Could not resolve the service manager. Restore systemctl before retrying infraternal up."))?
    } else {
        root.join("systemctl")
    };
    preflight_with_manager(root, owner, &systemctl)
}

/// Use the same trusted manager for read-only inspection and later activation.
fn preflight_with_manager(root: &Path, owner: u32, systemctl: &Path) -> io::Result<()> {
    let recovery = journal::inspect(root, owner)?;
    if recovery.needs_root {
        // The ordinary-user stage cannot model private enrollment descendants.
        // It may hand off to root, but this result can never authorize writes.
        return Ok(());
    }
    check_preflight(root, owner, systemctl, &recovery)
}

/// Evaluate the filesystem as it will look after removing only proven pending ownership.
fn check_preflight(
    root: &Path,
    owner: u32,
    systemctl: &Path,
    recovery: &journal::Snapshot,
) -> io::Result<()> {
    if recovery.committed {
        return Err(refused(
            "A completed infraternal installation is recorded on this host. Manage the existing service; inspect /.infraternal-up.journal as root before preparing a fresh host.",
        ));
    }
    validate_recovery(recovery)?;
    // The early user check cannot read other users' executable descriptors. Only
    // the privileged repeat can authorize writes, and it inspects the whole host.
    if root == Path::new("/") && nix::unistd::geteuid().is_root() {
        inspect::running_install(recovery)?;
    }
    inspect::installed_services(root, systemctl, recovery)?;
    let base = root.join("var/lib/infraternal");
    if let Some(metadata) = remaining(&base, recovery)? {
        check_directory(&metadata, owner)?;
        let mut entries = fs::read_dir(&base).map_err(|_| refused("An existing protected infraternal data directory was found. Use the existing service; infraternal up requires a fresh host and will not change its permissions."))?;
        if entries.any(|entry| entry.map_or(true, |entry| !recovery.owns(&entry.path())))
            || metadata.mode() & 0o7777 != 0o711
        {
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
        if remaining(&root.join(relative), recovery)?.is_some() {
            return Err(refused(
                "An infraternal agent installation already exists. Manage the existing service; inspect an obsolete installation before removing it and retrying infraternal up.",
            ));
        }
    }
    let link = root.join(PATH_BINARY.trim_start_matches('/'));
    if let Some(metadata) = remaining(&link, recovery)?
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

/// Hide only an exact pending inode from the hypothetical post-recovery filesystem.
fn remaining(path: &Path, recovery: &journal::Snapshot) -> io::Result<Option<fs::Metadata>> {
    if recovery.owns(path) {
        Ok(None)
    } else {
        existing(path)
    }
}

/// Refuse foreign descendants before recovery writes anything; enrollment alone owns its children.
fn validate_recovery(recovery: &journal::Snapshot) -> io::Result<()> {
    if recovery.committed {
        return Ok(());
    }
    for entry in &recovery.created {
        if entry.enrollment || !recovery.owns(&entry.path) {
            continue;
        }
        if fs::symlink_metadata(&entry.path)?.is_dir() {
            for child in fs::read_dir(&entry.path)? {
                if !recovery.owns(&child?.path()) {
                    return Err(refused(
                        "An unfinished infraternal installation contains a path outside its recovery journal. Inspect it as root before retrying; no installation paths were changed.",
                    ));
                }
            }
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
    /// The exclusive durable journal stays locked until commit or completed rollback.
    journal: journal::Journal,
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
        if nix::unistd::geteuid().as_raw() != owner {
            return Err(refused(
                "This infraternal installation needs its privileged owner. Retry sudo infraternal up to validate and recover it.",
            ));
        }
        preflight_with_manager(root, owner, systemctl)?;
        let (journal, recovery) = journal::Journal::open(root, owner)?;
        // Recheck under the retained lock: a different install may have finished
        // between the read-only preflight and lock acquisition.
        check_preflight(root, owner, systemctl, &recovery)?;
        let mut install = Self {
            root: root.to_owned(),
            owner,
            created: recovery.created,
            journal,
            systemctl: systemctl.to_owned(),
            registered: recovery.registered,
            committed: false,
            interrupted: None,
        };
        install.rollback()?;
        check_preflight(root, owner, systemctl, &journal::Snapshot::default())?;
        install.journal.begin()?;
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

    /// Persist ownership before publication, retaining in-memory cleanup even if persistence fails.
    fn record(
        &mut self,
        path: PathBuf,
        metadata: &fs::Metadata,
        enrollment: bool,
    ) -> io::Result<()> {
        let result = self.journal.record(&path, metadata, enrollment);
        // Failed journal writes still need ordinary in-memory rollback authority.
        // Keep the inode before returning that error to the enclosing transaction.
        self.created.push(Created {
            path,
            identity: (metadata.dev(), metadata.ino()),
            enrollment,
        });
        result
    }

    /// Make missing directories exclusively; existing ancestors are inspected and never chmodded.
    fn directory(&mut self, relative: &str, mode: u32, exclusive: bool) -> io::Result<PathBuf> {
        let destination = self.root.join(relative);
        let mut current = self.root.clone();
        for component in Path::new(relative).components() {
            current.push(component);
            let final_entry = current == destination;
            if let Some(metadata) = existing(&current)? {
                if final_entry && exclusive {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                check_directory(&metadata, self.owner)?;
                continue;
            }
            self.journal.step()?;
            let staging = self.temporary(&current)?;
            fs::DirBuilder::new().mode(0o700).create(&staging)?;
            let metadata = fs::symlink_metadata(&staging)?;
            self.record(staging.clone(), &metadata, false)?;
            fs::set_permissions(
                &staging,
                fs::Permissions::from_mode(if final_entry { mode } else { 0o755 }),
            )?;
            self.record(
                current.clone(),
                &metadata,
                relative.ends_with("/agent") && final_entry,
            )?;
            self.publish_directory(
                &staging,
                &current,
                infraternal_shim::publish_install_directory(&staging, &current),
            )?;
            fs::File::open(
                current
                    .parent()
                    .ok_or_else(|| io::Error::other("missing install parent"))?,
            )?
            .sync_all()?;
        }
        Ok(destination)
    }

    /// Fall back to exclusive mkdir when no-replace rename is unsupported.
    /// Directories cannot be hard-linked. Revoke the unpublished staging inode's
    /// destination claim before mkdir, then journal the new inode immediately.
    /// A stop between mkdir and its record leaves an unproven path: retry refuses
    /// it for manual inspection rather than guessing ownership or deleting it.
    fn publish_directory(
        &mut self,
        staging: &Path,
        destination: &Path,
        publication: io::Result<()>,
    ) -> io::Result<()> {
        match publication {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(nix::libc::ENOSYS | nix::libc::EINVAL | nix::libc::EOPNOTSUPP)
                ) => {}
            Err(error) => return Err(error),
        }
        let metadata = fs::symlink_metadata(staging)?;
        self.journal.unpublish(destination, &metadata)?;
        self.created.retain(|entry| {
            entry.path != destination || entry.identity != (metadata.dev(), metadata.ino())
        });
        self.journal.step()?;
        fs::DirBuilder::new().mode(0o700).create(destination)?;
        let published = fs::symlink_metadata(destination)?;
        self.record(
            destination.to_owned(),
            &published,
            destination == self.root.join("var/lib/infraternal/agent"),
        )?;
        fs::set_permissions(
            destination,
            fs::Permissions::from_mode(metadata.mode() & 0o7777),
        )?;
        fs::File::open(destination)?.sync_all()?;
        fs::remove_dir(staging)
    }

    /// Stage in the first pre-existing ancestor on the destination filesystem.
    ///
    /// Publication waits for a synced inode record. A stop between exclusive staging
    /// creation and that record can leave only an empty unpublished entry, outside
    /// directories recovery must remove. Unknown inodes never gain deletion authority.
    fn temporary(&self, destination: &Path) -> io::Result<PathBuf> {
        let mut parent = destination
            .parent()
            .ok_or_else(|| io::Error::other("missing install parent"))?;
        while parent != self.root
            && self.created.iter().any(|entry| {
                entry.path == parent
                    && existing(parent)
                        .ok()
                        .flatten()
                        .is_some_and(|metadata| entry.identity == (metadata.dev(), metadata.ino()))
            })
        {
            parent = parent
                .parent()
                .ok_or_else(|| io::Error::other("missing install ancestor"))?;
        }
        Ok(parent.join(format!(".infraternal-up-{}.pending", uuid::Uuid::new_v4())))
    }

    /// Open a unique private staging file and retain its inode even if writing later fails.
    fn staging(&mut self, destination: &Path) -> io::Result<(PathBuf, fs::File)> {
        self.journal.step()?;
        let path = self.temporary(destination)?;
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)?;
        self.record(path.clone(), &file.metadata()?, false)?;
        Ok((path, file))
    }

    /// Atomically publish completed bytes without overwriting an existing destination.
    fn publish(&mut self, staging: &Path, destination: &Path) -> io::Result<()> {
        let metadata = fs::symlink_metadata(staging)?;
        self.journal.step()?;
        self.record(destination.to_owned(), &metadata, false)?;
        fs::hard_link(staging, destination)?;
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
        if existing(destination)?.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        self.journal.step()?;
        let staging = self.temporary(destination)?;
        std::os::unix::fs::symlink(target, &staging)?;
        let metadata = fs::symlink_metadata(&staging)?;
        self.record(staging.clone(), &metadata, false)?;
        if let Err(error) = self.publish(&staging, destination) {
            if error.kind() == io::ErrorKind::AlreadyExists
                && existing(&staging)?.is_some_and(|current| {
                    (current.dev(), current.ino()) == (metadata.dev(), metadata.ino())
                })
            {
                fs::remove_file(&staging)?;
            }
            return Err(error);
        }
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
        self.journal.register()?;
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
        self.journal.commit()?;
        self.committed = true;
        Ok(())
    }
}

impl Install {
    /// Recover only unchanged journaled inodes; keep the journal if any cleanup operation fails.
    fn rollback(&mut self) -> io::Result<()> {
        if self.committed {
            return Ok(());
        }
        let mut failure = None;
        let unit = self
            .root
            .join("etc/systemd/system/infraternal-agent.service");
        let own_unit = self.created.iter().any(|entry| {
            entry.path == unit
                && existing(&unit)
                    .ok()
                    .flatten()
                    .is_some_and(|metadata| entry.identity == (metadata.dev(), metadata.ino()))
        });
        // Stop affects runtime state only. Disable would also delete administrator-owned
        // unit aliases; the inode journal already owns our sole enablement link.
        if self.registered && own_unit {
            run_systemctl(&self.systemctl, &["stop", SERVICE_NAME], None)?;
        }
        for created in self.created.iter().rev() {
            let metadata = match fs::symlink_metadata(&created.path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => {
                    failure.get_or_insert(error);
                    continue;
                }
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
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        if self.registered {
            let _ = run_systemctl(&self.systemctl, &["daemon-reload"], None);
        }
        if let Some(error) = failure {
            return Err(error);
        }
        self.journal.clear()?;
        self.created.clear();
        self.registered = false;
        Ok(())
    }
}

impl Drop for Install {
    /// Normal errors and handled signals use the same cleanup as next-run durable recovery.
    fn drop(&mut self) {
        if self.rollback().is_err() {
            eprintln!(
                "Could not finish rollback of this infraternal installation. Retry sudo infraternal up to recover its private journal."
            );
        }
    }
}

/// Process inspection accepts the global JSON flag and never mistakes an SSH command for a server.
#[cfg(test)]
mod tests {
    use super::*;
    /// Unsupported no-replace syscalls must preserve exclusive creation and durable rollback ownership.
    #[test]
    fn directory_publication_fallback_is_exclusive_and_owned() {
        for unsupported in [nix::libc::ENOSYS, nix::libc::EINVAL, nix::libc::EOPNOTSUPP] {
            let fixture = crate::restart_binary::fixture::Directory::new();
            let owner = nix::unistd::geteuid().as_raw();
            let mut install = Install::begin(&fixture.0, owner, Path::new("/bin/false")).unwrap();
            let destination = fixture.0.join("usr");
            let staging = install.temporary(&destination).unwrap();
            fs::DirBuilder::new().mode(0o711).create(&staging).unwrap();
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o711)).unwrap();
            let staged = fs::symlink_metadata(&staging).unwrap();
            install.record(staging.clone(), &staged, false).unwrap();
            install.record(destination.clone(), &staged, false).unwrap();
            install
                .publish_directory(
                    &staging,
                    &destination,
                    Err(io::Error::from_raw_os_error(unsupported)),
                )
                .unwrap();
            assert_eq!(fs::metadata(&destination).unwrap().mode() & 0o777, 0o711);
            assert!(
                journal::inspect(&fixture.0, owner).is_err(),
                "live journal must remain locked"
            );
            assert!(install.created.iter().any(|entry| entry.path == destination
                && entry.identity
                    == (
                        fs::metadata(&destination).unwrap().dev(),
                        fs::metadata(&destination).unwrap().ino()
                    )));
            assert!(!staging.exists());
            let foreign = fixture.0.join("etc");
            fs::create_dir(&foreign).unwrap();
            fs::write(foreign.join("keep"), b"earlier data").unwrap();
            let before = fs::symlink_metadata(&foreign).unwrap();
            let other_stage = install.temporary(&foreign).unwrap();
            fs::create_dir(&other_stage).unwrap();
            install
                .record(
                    other_stage.clone(),
                    &fs::symlink_metadata(&other_stage).unwrap(),
                    false,
                )
                .unwrap();
            let error = install
                .publish_directory(
                    &other_stage,
                    &foreign,
                    Err(io::Error::from_raw_os_error(unsupported)),
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            drop(install);
            assert!(
                !destination.exists(),
                "rollback left fallback-created directory"
            );
            let after = fs::symlink_metadata(&foreign).unwrap();
            assert_eq!(
                (before.dev(), before.ino(), before.mode()),
                (after.dev(), after.ino(), after.mode())
            );
            assert_eq!(fs::read(foreign.join("keep")).unwrap(), b"earlier data");
        }
    }

    /// Global output selection can precede either long-running host mode.
    #[test]
    fn global_json_does_not_hide_a_running_install() {
        assert_eq!(
            super::inspect::command(b"/opt/infraternal\0--json\0server\0"),
            Some(b"server".as_slice())
        );
        assert_eq!(
            super::inspect::command(b"infraternal\0--json\0agent\0run\0"),
            Some(b"agent".as_slice())
        );
        assert_eq!(
            super::inspect::command(b"infraternal\0ssh\0host\0server\0"),
            Some(b"ssh".as_slice())
        );
        assert_eq!(
            super::inspect::command(b"harmless\0--json\0server\0"),
            Some(b"server".as_slice())
        );
    }
}

/// Independent regression probes for host refusal and transactional rollback (#338).
#[cfg(test)]
#[path = "j218_review_tests.rs"]
mod j218_review;
