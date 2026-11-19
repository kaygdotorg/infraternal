//! Crash-recoverable D395 server relocation. The old data stays at its boot
//! path until the final unit and firewall policy are durable and the new
//! service has answered. A private journal pins both trees and the unit set.

/// Pins the data and unit paths used by the recovery transaction.
#[path = "install_move_fs.rs"]
mod disk;

use self::disk::Identity;
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fmt::Write as _,
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

/// The legacy in-tree marker, read only when recovering an earlier installer.
const MARKER: &str = ".infraternal-move";
/// The durable record inside the private destination-side work directory.
const RECORD: &str = "journal.json";
/// The exact directory slot used for a verified copy and its displaced target.
const STAGING: &str = "data";

/// Why relocation could not proceed or finish.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MoveError(String);

impl MoveError {
    /// Include the path and operation in an I/O failure.
    fn io(step: &str, path: &Path, error: &io::Error) -> Self {
        Self(format!("{step} {} failed: {error}", path.display()))
    }
}

/// Manager operations for one service, with a readiness check for the moved data.
pub trait Service {
    /// Whether the service may be running.
    fn active(&self) -> io::Result<bool>;
    /// Stop the service and wait for the manager to finish the stop job.
    fn stop(&self) -> io::Result<()>;
    /// Make the manager read the unit files from disk.
    fn reload(&self) -> io::Result<()>;
    /// Confirm no unrelated server already occupies the expected listener.
    fn listener_is_idle(&self) -> io::Result<()>;
    /// Start the unit the manager has loaded.
    fn start(&self) -> io::Result<()>;
    /// Enable the service after it has started and answered.
    fn enable(&self) -> io::Result<()>;
    /// Wait for the new server to answer against its database.
    fn ready(&self, data: &File) -> io::Result<()>;
}

/// The fixed systemd program and the server endpoint to verify after starting.
pub struct Systemd {
    /// The trusted absolute systemctl program.
    pub program: PathBuf,
    /// Which instance of the service manager to contact.
    pub user: bool,
    /// Full service name, including its suffix.
    pub service: String,
    /// Application listener from the final configuration.
    pub listen: std::net::SocketAddr,
    /// Whether that listener uses TLS.
    pub tls: bool,
}

impl Systemd {
    /// Run systemctl for this service scope.
    fn systemctl(&self, arguments: &[&str]) -> io::Result<std::process::Output> {
        let mut command = Command::new(&self.program);
        infraternal_shim::prepare_child(&mut command);
        command.stdin(Stdio::null());
        if self.user {
            command.arg("--user");
        }
        command.args(arguments).output()
    }

    /// Return a manager failure with its action name.
    fn checked(&self, arguments: &[&str]) -> io::Result<()> {
        let output = self.systemctl(arguments)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "systemctl {} {} failed",
                arguments.first().copied().unwrap_or_default(),
                self.service
            )))
        }
    }

    /// Read manager state, distinguishing an unavailable manager from a stopped service.
    fn state(&self) -> io::Result<String> {
        let output = self.systemctl(&["show", "-p", "ActiveState", "--value", &self.service])?;
        if !output.status.success() {
            return Err(io::Error::other("systemctl show failed"));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Verify the manager started a process that has the new database open.
    #[cfg(target_os = "linux")]
    fn verify_database(&self, data: &File) -> io::Result<()> {
        let output = self.systemctl(&["show", "-p", "MainPID", "--value", &self.service])?;
        let pid = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u32>();
        let pid = pid
            .ok()
            .filter(|pid| output.status.success() && *pid != 0)
            .ok_or_else(|| io::Error::other("could not identify moved service process"))?;
        let database = disk::regular(data, OsStr::new("infraternal.sqlite"))?.metadata()?;
        let descriptors = std::fs::read_dir(format!("/proc/{pid}/fd"))?;
        for descriptor in descriptors {
            if descriptor?
                .path()
                .metadata()
                .is_ok_and(|open| open.dev() == database.dev() && open.ino() == database.ino())
            {
                return Ok(());
            }
        }
        Err(io::Error::other(
            "the running service has not opened the moved database",
        ))
    }

    /// Real installs require Linux systemd and its process descriptor view.
    #[cfg(not(target_os = "linux"))]
    fn verify_database(&self, _data: &File) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// Connect to the configured local listener, substituting loopback for a wildcard.
    fn connect(&self) -> io::Result<std::net::TcpStream> {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpStream};
        let address = match self.listen.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip => ip,
        };
        let address = (address, self.listen.port()).into();
        TcpStream::connect_timeout(&address, std::time::Duration::from_millis(500))
    }

    /// Read the local server's health response, without sending credentials.
    fn probe(&self) -> io::Result<()> {
        let stream = self.connect()?;
        let timeout = std::time::Duration::from_millis(500);
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        if self.tls {
            use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
            let mut connector =
                SslConnector::builder(SslMethod::tls_client()).map_err(io::Error::other)?;
            // The local probe tests readiness, not public DNS or certificate renewal.
            connector.set_verify(SslVerifyMode::NONE);
            let stream = connector
                .build()
                .connect("localhost", stream)
                .map_err(io::Error::other)?;
            health(stream)
        } else {
            health(stream)
        }
    }
}

/// Test the SQLite-backed health route over a plain or TLS connection.
fn health(mut stream: impl io::Read + io::Write) -> io::Result<()> {
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut prefix = [0; 13];
    stream.read_exact(&mut prefix)?;
    if &prefix == b"HTTP/1.1 200 " {
        Ok(())
    } else {
        Err(io::Error::other(
            "server health check did not return HTTP 200",
        ))
    }
}

impl Service for Systemd {
    /// Only a confirmed inactive or failed unit counts as stopped.
    fn active(&self) -> io::Result<bool> {
        Ok(!matches!(self.state()?.as_str(), "inactive" | "failed"))
    }

    fn stop(&self) -> io::Result<()> {
        self.checked(&["stop", &self.service])
    }

    fn reload(&self) -> io::Result<()> {
        self.checked(&["daemon-reload"])
    }

    fn listener_is_idle(&self) -> io::Result<()> {
        match self.connect() {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "server listener still occupied after stop",
            )),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn start(&self) -> io::Result<()> {
        self.checked(&["start", &self.service])
    }

    fn enable(&self) -> io::Result<()> {
        self.checked(&["enable", "--now", &self.service])
    }

    fn ready(&self, data: &File) -> io::Result<()> {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.probe().is_ok() && self.state()? == "active" {
                return self.verify_database(data);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "moved server did not answer /healthz",
                ));
            }
            // Relocation runs synchronously in init, outside the server runtime.
            std::thread::park_timeout(Duration::from_millis(100));
        }
    }
}

/// One unit file, including any shadowed definitions, before and after relocation.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Rewrite {
    /// Exact unit or drop-in path.
    path: PathBuf,
    /// Original contents allowed before replacement.
    before: String,
    /// Contents allowed after replacement.
    after: String,
}

/// What is safe to do with the original tree after a healthy cutover.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum Backup {
    /// Keep a dated read-only tree for a cross-filesystem or legacy move.
    Retain,
    /// Delete the old tree after verifying the new service.
    Remove,
}

/// Persistent recovery data. Before `ready`, the effective `ExecStart` on disk
/// identifies the authoritative tree. Once ready, only the exact backup is retired.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Journal {
    /// Data path recorded by the original server.
    from: PathBuf,
    /// Standard data path for this transaction.
    to: PathBuf,
    /// Base service unit defining the scope and name.
    unit: PathBuf,
    /// The original source object, if it still exists.
    source: Option<Identity>,
    /// The currently published or pre-existing target object.
    target: Option<Identity>,
    /// The exact staging path inside the pinned journal directory.
    staging: PathBuf,
    /// The database inode selected before the moved service could start.
    #[serde(default)]
    database: Option<Identity>,
    /// The staged object, saved before any swap.
    staged: Option<Identity>,
    /// The exact backup path, allocated before the original data is touched.
    backup: PathBuf,
    /// Keep the old tree read-only after EXDEV and ambiguous legacy recovery.
    backup_action: Backup,
    /// An older installer put the only authoritative tree at the destination.
    legacy_target: bool,
    /// Health verified after reloading and starting the final configuration.
    ready: bool,
    /// Was the old service active before it was stopped?
    was_running: bool,
    /// All files the effective service definition depends on, in precedence order.
    units: Vec<Rewrite>,
    /// The index of the file supplying the effective `ExecStart`.
    effective: usize,
}

/// A read-only plan, revalidated under the destination lock before applying it.
#[derive(Debug)]
pub struct Relocation {
    /// The original server folder.
    pub from: PathBuf,
    /// The D395 standard folder.
    pub to: PathBuf,
    /// Whether source and destination are on one filesystem.
    pub same_filesystem: bool,
    /// Whether there is already a transaction to finish.
    pub resuming: bool,
    /// The unit files before and after the move.
    units: Vec<Rewrite>,
    /// The base service unit.
    unit: PathBuf,
    /// The effective unit file index.
    effective: usize,
    /// Validated legacy marker makes the target authoritative even with old unit text.
    legacy_target: bool,
}

/// The result of a healthy move.
pub struct Outcome {
    /// Dated read-only old data retained across filesystems or after legacy recovery.
    pub leftover: Option<PathBuf>,
}

/// Plan a relocation or find its journal, without changing anything.
pub fn plan(from: &Path, to: &Path, unit: &Path) -> Result<Option<Relocation>, MoveError> {
    plan_inner(from, to, unit).map_err(|error| MoveError::io("checking move to", to, &error))
}

/// Refuse explicit reconfiguration while a journal is still responsible for the data.
pub fn pending(to: &Path, unit: &Path) -> Result<bool, MoveError> {
    load(to, unit)
        .map(|journal| journal.is_some())
        .map_err(|error| MoveError::io("reading move journal for", to, &error))
}

/// Check the old and new folder and reconstruct the full effective unit set.
fn plan_inner(from: &Path, to: &Path, unit: &Path) -> io::Result<Option<Relocation>> {
    if let Some(journal) = load(to, unit)? {
        if from != journal.from && from != to {
            return Err(disk::invalid(
                "recorded data path does not match the pending move",
            ));
        }
        let current = read_units(unit)?;
        current_side(&journal, &current)?;
        return Ok(Some(Relocation {
            same_filesystem: same_filesystem(&journal.from, to)?,
            from: journal.from,
            to: journal.to,
            resuming: true,
            units: journal.units,
            effective: journal.effective,
            unit: journal.unit,
            legacy_target: journal.legacy_target,
        }));
    }

    let legacy = legacy_source(to)?;
    if from == to && legacy.is_none() {
        return Ok(None);
    }
    let old = legacy.as_deref().unwrap_or(from);
    if !old.is_absolute() || !to.is_absolute() || old.starts_with(to) || to.starts_with(old) {
        return Err(disk::invalid(
            "data folders must be absolute and outside one another",
        ));
    }
    if legacy.is_some() && from != old && from != to {
        return Err(disk::invalid(
            "legacy marker does not match the installed service",
        ));
    }
    let (old_parent, old_name) = disk::parent(old, false)?;
    let source = optional_tree(&old_parent, old_name)?;
    let old_marker = source
        .as_ref()
        .map(read_legacy_marker)
        .transpose()?
        .flatten();
    if old_marker.as_deref().is_some_and(|path| path != old) {
        return Err(disk::invalid(
            "old data has a marker for a different transaction",
        ));
    }
    let legacy_target = legacy.is_some() && (old_marker.is_none() || from == to);
    if source.is_none() && !legacy_target {
        return Err(disk::invalid(
            "the unit's data folder does not exist; mount it or specify --data",
        ));
    }
    if legacy.is_none() {
        inspect_target(to)?;
    } else {
        let (parent, name) = disk::parent(to, false)?;
        let target = disk::tree(&parent, name)?;
        if target.metadata()?.mode() & 0o077 != 0 {
            return Err(disk::invalid(
                "legacy target is a shared base; preserve both folders",
            ));
        }
        reject_shared(&target)?;
    }
    let (units, effective) = unit_rewrites(unit, old, to)?;
    Ok(Some(Relocation {
        from: old.to_owned(),
        to: to.to_owned(),
        unit: unit.to_owned(),
        resuming: legacy.is_some(),
        same_filesystem: same_filesystem(old, to)?,
        units,
        effective,
        legacy_target,
    }))
}

impl Relocation {
    /// Unit files that change paths during this move.
    pub fn unit_files(&self) -> impl Iterator<Item = &Path> {
        self.units
            .iter()
            .filter(|file| file.before != file.after)
            .map(|file| file.path.as_path())
    }

    /// Carry an explicitly configured path inside the old data tree into the new tree.
    pub fn relocate_path(&self, path: &mut Option<PathBuf>) {
        if let Some(value) = path
            && let Ok(suffix) = value.strip_prefix(&self.from)
        {
            *value = if suffix.as_os_str().is_empty() {
                self.to.clone()
            } else {
                self.to.join(suffix)
            };
        }
    }

    /// Check that the requested init uses the same effective command after relocation.
    /// An explicit force can replace a unit in a separate init after the move.
    pub fn check_command(&self, desired: &str) -> Result<(), MoveError> {
        let command = exec_start(&self.units[self.effective].after);
        let requested = exec_start(desired);
        if command.is_none() || command != requested {
            return Err(MoveError("the requested configuration differs from the installed service; move it with its existing flags first, or pass --data to keep the folder (including with --force)".to_owned()));
        }
        Ok(())
    }

    /// Dry-run and confirmation description.
    pub fn describe(&self) -> String {
        let mut text = format!(
            "{} {} to {} (D395).\nThe old path stays available until the moved service answers.\n",
            if self.resuming {
                "Resume moving"
            } else {
                "Move"
            },
            self.from.display(),
            self.to.display(),
        );
        for path in self.unit_files() {
            let _ = writeln!(text, "Rewrite ExecStart in {}", path.display());
        }
        text
    }
}

impl Outcome {
    /// Report the move and any backup retained for the operator.
    pub fn describe(&self, relocation: &Relocation) -> String {
        let mut text = format!(
            "Moved the data folder from {} to {}.\n",
            relocation.from.display(),
            relocation.to.display()
        );
        if let Some(leftover) = &self.leftover {
            let quoted = shell_quote(&leftover.to_string_lossy());
            let _ = writeln!(
                text,
                "The old folder is kept read-only at {}. To remove it:\n  chmod -R u+w {quoted} && rm -rf {quoted}",
                leftover.display()
            );
        }
        text
    }
}

/// Apply an admitted move. Publish the checked policy before any unit change.
pub fn apply(
    relocation: &Relocation,
    service: &dyn Service,
    now: SystemTime,
    publish: impl FnOnce() -> io::Result<()>,
) -> Result<Outcome, MoveError> {
    use nix::fcntl::{Flock, FlockArg};
    let result = (|| {
        let (parent, target_name) = disk::parent(&relocation.to, true)?;
        let parent = Flock::lock(parent, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| io::Error::from(error))?;
        let (old_parent, old_name) = disk::parent(&relocation.from, false)?;
        let work_name = work_name(target_name);
        let existing = optional_tree(&parent, &work_name)?;
        let work = match existing {
            Some(work) => work,
            None => disk::make_dir(&parent, &work_name)?,
        };
        if work.metadata()?.mode() & 0o077 != 0 {
            return Err(disk::invalid("move journal directory is not private"));
        }
        let mut journal =
            if let Some(journal) = load_record(&work, &relocation.to, &relocation.unit)? {
                journal
            } else {
                if disk::names(&work)?
                    .iter()
                    .any(|name| name != "journal.next")
                {
                    return Err(disk::invalid("unclaimed journal directory is not empty"));
                }
                let current = plan_inner(&relocation.from, &relocation.to, &relocation.unit)?
                    .ok_or_else(|| disk::invalid("move no longer applies"))?;
                if current.from != relocation.from
                    || current
                        .units
                        .iter()
                        .map(|f| &f.after)
                        .ne(relocation.units.iter().map(|f| &f.after))
                {
                    return Err(disk::invalid(
                        "move changed after confirmation; run init again",
                    ));
                }
                let source = optional_tree(&old_parent, old_name)?
                    .as_ref()
                    .map(Identity::of)
                    .transpose()?;
                let target = optional_tree(&parent, target_name)?
                    .as_ref()
                    .map(Identity::of)
                    .transpose()?;
                let backup = backup_path(&current.from, now)?;
                let journal = Journal {
                    from: current.from,
                    to: current.to,
                    unit: current.unit,
                    source,
                    target,
                    database: None,
                    staging: relocation.to.with_file_name(&work_name).join(STAGING),
                    staged: None,
                    backup,
                    backup_action: if current.same_filesystem && !current.legacy_target {
                        Backup::Remove
                    } else {
                        Backup::Retain
                    },
                    legacy_target: current.legacy_target,
                    ready: false,
                    was_running: service.active()?,
                    units: current.units,
                    effective: current.effective,
                };
                save(&work, &journal)?;
                journal
            };
        let switched = current_side(&journal, &read_units(&journal.unit)?)?;
        let result = (|| {
            if journal.ready {
                let target = selected_target(&parent, target_name, &journal)?;
                if !service.active()? {
                    service.reload()?;
                    service.start()?;
                }
                service.ready(&target)?;
                selected_target(&parent, target_name, &journal)?;
                return finish(&parent, &work_name, &work, &old_parent, old_name, &journal);
            }
            if service.active()? {
                service.stop()?;
                if service.active()? {
                    return Err(io::Error::other("the service did not stop"));
                }
            }
            service.listener_is_idle()?;
            reconcile_staging(&parent, target_name, &work, &mut journal)?;
            if !switched && !journal.legacy_target {
                prepare_data(
                    &parent,
                    target_name,
                    &work,
                    &old_parent,
                    old_name,
                    &mut journal,
                )?;
            }
            let target = disk::tree(&parent, target_name)?;
            if journal.target != Some(Identity::of(&target)?) {
                return Err(disk::invalid("destination identity changed"));
            }
            if !switched || journal.database.is_none() {
                if switched {
                    // Older journals did not pin the database before first start.
                    journal.backup_action = Backup::Retain;
                }
                journal.database = Some(database_identity(&target)?);
                save(&work, &journal)?;
            }
            selected_target(&parent, target_name, &journal)?;
            publish()?;
            write_units(&journal)?;
            let startup = service
                .reload()
                .and_then(|()| service.start())
                .and_then(|()| service.ready(&target))
                .and_then(|()| service.enable())
                .and_then(|()| service.ready(&target))
                .and_then(|()| selected_target(&parent, target_name, &journal).map(drop));
            if let Err(error) = startup {
                // A service whose startup cannot be confirmed may have written
                // to either tree. Preserve both for inspection after any retry.
                journal.backup_action = Backup::Retain;
                let recorded = save(&work, &journal);
                let stopped = service.stop();
                recorded.and(stopped).map_err(|recovery| {
                    io::Error::other(format!(
                        "{error}; preserving both trees and stopping the service: {recovery}"
                    ))
                })?;
                return Err(error);
            }
            journal.ready = true;
            save(&work, &journal)?;
            finish(&parent, &work_name, &work, &old_parent, old_name, &journal)
        })();
        if let Err(error) = &result
            && !journal.ready
            && !journal.legacy_target
            && !current_side(&journal, &read_units(&journal.unit)?)?
        {
            if journal.was_running {
                service
                    .reload()
                    .and_then(|()| service.start())
                    .map_err(|restart| {
                        io::Error::other(format!(
                            "{error}; restarting the original service failed: {restart}"
                        ))
                    })?;
            }
            if journal.target.is_none() {
                reconcile_staging(&parent, target_name, &work, &mut journal)?;
                if journal.target.is_none() {
                    remove_journal(&parent, &work_name, &work)?;
                }
            }
        }
        result
    })();
    result.map_err(|error| MoveError::io("moving data to", &relocation.to, &error))
}

/// Resume or discard the exact prepared staging tree by its saved identity.
fn reconcile_staging(
    parent: &File,
    target_name: &OsStr,
    work: &File,
    journal: &mut Journal,
) -> io::Result<()> {
    let stage_name = OsStr::new(STAGING);
    let stage = optional_tree(work, stage_name)?
        .as_ref()
        .map(Identity::of)
        .transpose()?;
    let target = optional_tree(parent, target_name)?
        .as_ref()
        .map(Identity::of)
        .transpose()?;
    if target.is_some() && target == journal.staged {
        if let Some(stage) = stage {
            if Some(stage) != journal.target {
                return Err(disk::invalid(
                    "displaced destination does not match the journal",
                ));
            }
            disk::retire(work, stage_name, stage, false)?;
        }
        journal.target = target;
    } else {
        if target != journal.target {
            return Err(disk::invalid("destination identity changed during move"));
        }
        if let Some(stage) = stage {
            if journal.staged.is_some_and(|expected| expected != stage) {
                return Err(disk::invalid("staging identity changed during move"));
            }
            // No copying takes place until the staging inode is journaled.
            if journal.staged.is_none() && !disk::names(&disk::tree(work, stage_name)?)?.is_empty()
            {
                return Err(disk::invalid("unclaimed staging directory is not empty"));
            }
            disk::retire(work, stage_name, stage, false)?;
        }
    }
    if journal.staged.take().is_some() {
        save(work, journal)?;
    }
    Ok(())
}

/// Copy a fresh snapshot while the old service is stopped. Keep the previous
/// destination until a single rename or exchange publishes the new snapshot.
fn prepare_data(
    parent: &File,
    target_name: &OsStr,
    work: &File,
    old_parent: &File,
    old_name: &OsStr,
    journal: &mut Journal,
) -> io::Result<()> {
    let source = disk::tree(old_parent, old_name)?;
    if journal.source != Some(Identity::of(&source)?) {
        return Err(disk::invalid(
            "original folder identity changed during move",
        ));
    }
    let stage_name = OsStr::new(STAGING);
    let stage = disk::make_dir(work, stage_name)?;
    journal.staged = Some(Identity::of(&stage)?);
    save(work, journal)?;
    for name in disk::names(&source)? {
        if name == MARKER {
            continue;
        }
        if is_firewall(&name) || is_shared(&name) {
            return Err(disk::invalid(
                "original folder contains files reserved for the install base",
            ));
        }
        disk::copy_entry(&source, &stage, &name)?;
    }
    if journal.target.is_some() {
        let previous = disk::tree(parent, target_name)?;
        for name in disk::names(&previous)? {
            if is_firewall(&name) {
                disk::copy_entry(&previous, &stage, &name)?;
            }
        }
    }
    disk::preserve_root(&source, &stage)?;
    if journal.target.is_some() {
        disk::exchange(work, stage_name, parent, target_name)?;
    } else {
        disk::rename_new(work, stage_name, parent, target_name)?;
    }
    reconcile_staging(parent, target_name, work, journal)
}

/// Pin the exact SQLite file that the selected server is expected to open.
fn database_identity(data: &File) -> io::Result<Identity> {
    Identity::of(&disk::regular(data, OsStr::new("infraternal.sqlite"))?)
}

/// Reopen the published directory and verify both identities before retirement.
fn selected_target(parent: &File, name: &OsStr, journal: &Journal) -> io::Result<File> {
    let target = disk::tree(parent, name)?;
    if journal.target != Some(Identity::of(&target)?) {
        return Err(disk::invalid("destination identity changed during cleanup"));
    }
    if journal.database != Some(database_identity(&target)?) {
        return Err(disk::invalid("destination database does not match the move journal"));
    }
    Ok(target)
}

/// Once the new process answers, retire the original by its saved identity.
fn finish(
    parent: &File,
    work_name: &OsStr,
    work: &File,
    old_parent: &File,
    old_name: &OsStr,
    journal: &Journal,
) -> io::Result<Outcome> {
    let target_name = journal
        .to
        .file_name()
        .ok_or_else(|| disk::invalid("target lacks a name"))?;
    let target = selected_target(parent, target_name, journal)?;
    if journal.legacy_target
        && let Some(previous) = read_legacy_marker(&target)?
    {
        if previous != journal.from {
            return Err(disk::invalid("legacy move marker changed"));
        }
    }
    let mut leftover = None;
    if let Some(source) = journal.source {
        let (_, backup) = disk::parent(&journal.backup, false)?;
        let backup_id = optional_tree(old_parent, backup)?
            .as_ref()
            .map(Identity::of)
            .transpose()?;
        let old_id = optional_tree(old_parent, old_name)?
            .as_ref()
            .map(Identity::of)
            .transpose()?;
        if backup_id.is_none() && old_id == Some(source) {
            disk::rename_new(old_parent, old_name, old_parent, backup)?;
        }
        if optional_tree(old_parent, backup)?.is_some() {
            disk::retire(
                old_parent,
                backup,
                source,
                journal.backup_action == Backup::Retain,
            )?;
            if journal.backup_action == Backup::Retain {
                leftover = Some(journal.backup.clone());
            }
        } else if journal.backup_action == Backup::Retain {
            return Err(disk::invalid(
                "original folder and its recorded backup are missing",
            ));
        }
    }
    if journal.legacy_target && read_legacy_marker(&target)?.is_some() {
        disk::unlink(&target, OsStr::new(MARKER), false)?;
    }
    remove_journal(parent, work_name, work)?;
    Ok(Outcome { leftover })
}

/// Remove the known record and private directory, leaving other siblings alone.
fn remove_journal(parent: &File, work_name: &OsStr, work: &File) -> io::Result<()> {
    match disk::unlink(work, OsStr::new("journal.next"), false) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    disk::unlink(work, OsStr::new(RECORD), false)?;
    disk::unlink(parent, work_name, true)
}

/// The fixed name of the dedicated journal directory beside the target.
fn work_name(target: &OsStr) -> OsString {
    let mut name = OsString::from(".infraternal-move-");
    name.push(target);
    name
}

/// Load a journal if the target parent already exists.
fn load(to: &Path, unit: &Path) -> io::Result<Option<Journal>> {
    let (parent, target) = match disk::parent(to, false) {
        Ok(parent) => parent,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    match optional_tree(&parent, &work_name(target))? {
        Some(work) => load_record(&work, to, unit),
        None => Ok(None),
    }
}

/// Decode a private journal and verify its path bindings before using it.
fn load_record(work: &File, to: &Path, unit: &Path) -> io::Result<Option<Journal>> {
    if work.metadata()?.mode() & 0o077 != 0 {
        return Err(disk::invalid("move journal directory is not private"));
    }
    let raw = match disk::read(work, OsStr::new(RECORD), true) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let journal: Journal = serde_json::from_slice(&raw)?;
    let target = to
        .file_name()
        .ok_or_else(|| disk::invalid("target lacks a name"))?;
    let old_name = journal
        .from
        .file_name()
        .ok_or_else(|| disk::invalid("source lacks a name"))?;
    let mut prefix = old_name.to_owned();
    prefix.push(".moved-");
    if journal.to != to
        || journal.unit != unit
        || !journal.from.is_absolute()
        || journal.from.starts_with(to)
        || to.starts_with(&journal.from)
        || journal.staging != to.with_file_name(work_name(target)).join(STAGING)
        || journal.backup.parent() != journal.from.parent()
        || !journal.backup.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .starts_with(prefix.to_string_lossy().as_ref())
        })
        || journal.effective >= journal.units.len()
    {
        return Err(disk::invalid(
            "move journal does not match these data and unit paths",
        ));
    }
    Ok(Some(journal))
}

/// Advance the durable journal before executing the next irreversible step.
fn save(work: &File, journal: &Journal) -> io::Result<()> {
    disk::write_record(work, OsStr::new(RECORD), &serde_json::to_vec(journal)?)
}

/// Read a directory entry only if it exists, propagating all other safety errors.
fn optional_tree(parent: &File, name: &OsStr) -> io::Result<Option<File>> {
    match disk::tree(parent, name) {
        Ok(folder) => Ok(Some(folder)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Read the old-format marker through a trusted target directory.
fn legacy_source(to: &Path) -> io::Result<Option<PathBuf>> {
    let (parent, name) = match disk::parent(to, false) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    optional_tree(&parent, name)?
        .as_ref()
        .map(read_legacy_marker)
        .transpose()
        .map(Option::flatten)
}

/// Legacy markers contain one absolute UTF-8 source path.
fn read_legacy_marker(dir: &File) -> io::Result<Option<PathBuf>> {
    match disk::read(dir, OsStr::new(MARKER), true) {
        Ok(data) => String::from_utf8(data)
            .map(PathBuf::from)
            .map(Some)
            .map_err(io::Error::other),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Determine whether the source and destination parents use the same filesystem.
fn same_filesystem(from: &Path, to: &Path) -> io::Result<bool> {
    let (from_parent, _) = disk::parent(from, false)?;
    let to_parent = to
        .parent()
        .ok_or_else(|| disk::invalid("target lacks a parent"))?;
    let existing = disk::directory(&disk::existing_parent(to_parent)?, false)?;
    Ok(Identity::of(&from_parent)?.same_device(Identity::of(&existing)?))
}

/// Reserve a dated exact backup path without reusing an existing object.
fn backup_path(old: &Path, now: SystemTime) -> io::Result<PathBuf> {
    let (_, leaf) = disk::parent(old, false)?;
    let mut name = leaf.to_owned();
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    name.push(format!(
        ".moved-{}-{}",
        utc_stamp(seconds),
        uuid::Uuid::new_v4()
    ));
    Ok(old.with_file_name(name))
}

/// Inspect a fresh target, allowing only the server's dedicated firewall files.
fn inspect_target(to: &Path) -> io::Result<()> {
    let (parent, name) = match disk::parent(to, false) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let Some(folder) = optional_tree(&parent, name)? else {
        return Ok(());
    };
    reject_shared(&folder)?;
    let mut foreign = Vec::new();
    for name in disk::names(&folder)? {
        if is_firewall(&name) {
            disk::regular(&folder, &name)?;
        } else {
            foreign.push(name);
        }
    }
    if !foreign.is_empty() {
        return Err(io::Error::other(format!(
            "{} already holds {foreign:?}; pass --data to keep the current folder",
            to.display()
        )));
    }
    if folder.metadata()?.mode() & 0o077 != 0 {
        return Err(disk::invalid(
            "the target is a shared base; pass --data to keep the current folder",
        ));
    }
    Ok(())
}

/// Refuse a shared install base without listing or altering its component files.
fn reject_shared(folder: &File) -> io::Result<()> {
    if disk::names(folder)?.iter().any(|name| is_shared(name)) {
        return Err(disk::invalid(
            "the target is a shared install base; pass --data to keep the current folder",
        ));
    }
    Ok(())
}

/// Install-base files maintained for the server firewall independently of the server.
fn is_firewall(name: &OsStr) -> bool {
    name == "host-firewall-server.json"
        || name
            .to_string_lossy()
            .starts_with(".host-firewall-server.json.")
}

/// Files owned by other components in a shared install base.
fn is_shared(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    matches!(
        name.as_ref(),
        "bin"
            | "agent"
            | "state"
            | "sessions"
            | "host-firewall-agent.json"
            | ".promotion-transaction"
            | ".infraternal-incoming"
    ) || name.starts_with(".bootstrap-")
        || name.starts_with(".superseded-")
        || name.starts_with(".host-firewall-agent.json.")
}

/// Read the base unit and its drop-ins through pinned, trusted parents.
fn read_units(unit: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    let (parent, leaf) = disk::parent(unit, false)?;
    let text = String::from_utf8(disk::read(&parent, leaf, false)?).map_err(io::Error::other)?;
    let mut files = vec![(unit.to_owned(), text)];
    let mut drop_name = leaf.to_owned();
    drop_name.push(".d");
    if let Some(dropins) = optional_tree(&parent, &drop_name)? {
        let mut entries = disk::names(&dropins)?;
        entries.sort();
        for name in entries
            .into_iter()
            .filter(|name| Path::new(name).extension().is_some_and(|ext| ext == "conf"))
        {
            let text =
                String::from_utf8(disk::read(&dropins, &name, false)?).map_err(io::Error::other)?;
            files.push((unit.with_file_name(&drop_name).join(name), text));
        }
    }
    Ok(files)
}

/// Parse the final explicit `ExecStart` in a file, including an empty reset.
fn exec_assignment(text: &str) -> Option<&str> {
    text.lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix("ExecStart="))
        .map(str::trim)
}

/// Tokenize the final nonempty command like the status reader does.
fn exec_start(text: &str) -> Option<Vec<String>> {
    exec_assignment(text).and_then(infraternal_status::exec_words)
}

/// Compute every replacement and identify the file whose rename switches the live path.
fn unit_rewrites(unit: &Path, from: &Path, to: &Path) -> io::Result<(Vec<Rewrite>, usize)> {
    let (Some(from_text), Some(to_text)) = (from.to_str(), to.to_str()) else {
        return Err(disk::invalid("data folders must be UTF-8 paths"));
    };
    let mut units = Vec::new();
    let mut effective = None;
    for (path, before) in read_units(unit)? {
        if exec_assignment(&before).is_some() {
            effective = live_data(&before).map(|_| units.len());
        }
        let mut after = String::with_capacity(before.len());
        for (number, line) in before.split_inclusive('\n').enumerate() {
            let body = line.trim_end_matches(['\n', '\r']);
            let ending = &line[body.len()..];
            let trimmed = body.trim_start();
            if trimmed.starts_with('#') || trimmed.starts_with(';') {
                after.push_str(line);
                continue;
            }
            if let Some(value) = trimmed
                .strip_prefix("ExecStart=")
                .filter(|v| !v.trim().is_empty())
            {
                let words = infraternal_status::exec_words(value)
                    .ok_or_else(|| disk::invalid("cannot safely parse ExecStart"))?;
                let mapped: Vec<String> = words
                    .iter()
                    .map(|word| map_word(word, from_text, to_text))
                    .collect();
                if mapped != words {
                    after.push_str("ExecStart=");
                    after.push_str(&render_exec(&mapped, &path).map_err(io::Error::other)?);
                    after.push_str(ending);
                    continue;
                }
            } else if names_path(body, from_text) {
                return Err(io::Error::other(format!(
                    "{}:{} names {} outside ExecStart; pass --data to keep it",
                    path.display(),
                    number + 1,
                    from.display()
                )));
            }
            after.push_str(line);
        }
        units.push(Rewrite {
            path,
            before,
            after,
        });
    }
    let effective = effective
        .ok_or_else(|| disk::invalid("installed unit does not select a usable data folder"))?;
    let old = live_data(&units[effective].before);
    let new = live_data(&units[effective].after);
    if old.as_deref().is_none_or(|old| old != from && old != to) || new.as_deref() != Some(to) {
        return Err(disk::invalid(
            "effective unit does not match the planned data paths",
        ));
    }
    Ok((units, effective))
}

/// Read the explicit data location in a unit command.
fn live_data(text: &str) -> Option<PathBuf> {
    let words = exec_start(text)?;
    words
        .windows(2)
        .find(|pair| pair[0] == "--data")
        .map(|pair| PathBuf::from(&pair[1]))
        .or_else(|| {
            words
                .iter()
                .find_map(|word| word.strip_prefix("--data=").map(PathBuf::from))
        })
}

/// Check the snapshot and determine which data path is live on a fresh boot.
fn current_side(journal: &Journal, current: &[(PathBuf, String)]) -> io::Result<bool> {
    if current.len() != journal.units.len()
        || current
            .iter()
            .zip(&journal.units)
            .any(|((path, text), file)| {
                path != &file.path || (text != &file.before && text != &file.after)
            })
    {
        return Err(disk::invalid(
            "a service unit changed outside the pending migration",
        ));
    }
    let switched = live_data(&current[journal.effective].1).as_deref() == Some(&journal.to);
    if journal.ready && !switched {
        return Err(disk::invalid(
            "the confirmed unit no longer points to the new data",
        ));
    }
    Ok(switched)
}

/// Replace shadowed files first, then atomically switch the effective `ExecStart`.
fn write_units(journal: &Journal) -> io::Result<()> {
    current_side(journal, &read_units(&journal.unit)?)?;
    let effective = &journal.units[journal.effective];
    for file in journal
        .units
        .iter()
        .filter(|file| file.path != effective.path)
        .chain(std::iter::once(effective))
    {
        let (parent, name) = disk::parent(&file.path, false)?;
        let old = disk::regular(&parent, name)?;
        let contents = disk::read(&parent, name, false)?;
        if contents == file.after.as_bytes() {
            // An earlier write can have returned before its directory fsync.
            parent.sync_all()?;
        } else {
            if contents != file.before.as_bytes() {
                return Err(disk::invalid("unit changed before replacement"));
            }
            disk::write(&parent, name, file.after.as_bytes(), Some(&old))?;
        }
    }
    Ok(())
}

/// Replace a word that is `from` or lies under it, also as `--flag=<path>`.
fn map_word(word: &str, from: &str, to: &str) -> String {
    let replace = |path: &str| -> Option<String> {
        if path == from {
            Some(to.to_owned())
        } else {
            path.strip_prefix(from)
                .filter(|rest| rest.starts_with('/'))
                .map(|rest| format!("{to}{rest}"))
        }
    };
    if let Some(mapped) = replace(word) {
        return mapped;
    }
    if let Some((flag, value)) = word
        .split_once('=')
        .filter(|(flag, _)| flag.starts_with("--"))
        && let Some(mapped) = replace(value)
    {
        return format!("{flag}={mapped}");
    }
    word.to_owned()
}

/// Whether `text` names `path` as a whole path (not `/data2` for `/data`).
fn names_path(text: &str, path: &str) -> bool {
    text.match_indices(path).any(|(at, _)| {
        text[at + path.len()..].chars().next().is_none_or(|next| {
            next == '/'
                || next == '"'
                || next == '\''
                || next.is_whitespace()
                || ":;,".contains(next)
        })
    })
}

/// Quote words the way `server init` writes them, so a re-run sees the same unit.
///
/// systemd's `ExecStart` prefixes (`-`, `@`, `:`, `+`, `!`) stay outside the
/// quotes of the first word, where systemd looks for them.
fn render_exec(words: &[String], path: &Path) -> Result<String, MoveError> {
    let invalid = || {
        MoveError(format!(
            "{} has an ExecStart word that cannot be written back",
            path.display()
        ))
    };
    let mut parts = Vec::with_capacity(words.len());
    for (index, word) in words.iter().enumerate() {
        let (prefix, rest) = if index == 0 {
            let start = word
                .find(|c: char| !"-@:+!".contains(c))
                .unwrap_or(word.len());
            word.split_at(start)
        } else {
            ("", word.as_str())
        };
        let quoted =
            super::install::quote_systemd(std::ffi::OsStr::new(rest)).map_err(|_| invalid())?;
        parts.push(format!("{prefix}{quoted}"));
    }
    Ok(parts.join(" "))
}

/// Format a UTC calendar timestamp for the dated backup.
fn utc_stamp(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let rest = seconds % 86_400;
    // Howard Hinnant's days-to-civil algorithm, valid for every date after 1970.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Single-quote a path for a shell command line.
fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Exercises interrupted moves on disposable data trees.
#[cfg(test)]
#[path = "install_move_tests.rs"]
mod tests;
