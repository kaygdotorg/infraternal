//! Crash-recoverable D395 server relocation. The old data stays at its boot
//! path until the final unit and firewall policy are durable and the new
//! service has answered. A private journal pins both trees and the unit set.

/// Pins the data and unit paths used by the recovery transaction.
#[path = "install_move_fs.rs"]
mod disk;
/// Runs recovery and readiness in the server's systemd start transaction.
#[cfg(target_os = "linux")]
#[path = "install_move_manager.rs"]
pub(super) mod manager;

use self::disk::Identity;
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
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
    #[cfg(any(test, not(target_os = "linux")))]
    fn active(&self) -> io::Result<bool>;
    /// Stop the service and wait for the manager to finish the stop job.
    #[cfg(any(test, not(target_os = "linux")))]
    fn stop(&self) -> io::Result<()>;
    /// Stop current work before copying. Managers can also cancel an outstanding start.
    #[cfg(any(test, not(target_os = "linux")))]
    fn quiesce(&self) -> io::Result<()> {
        if self.active()? {
            self.stop()?;
        }
        Ok(())
    }
    /// Make the manager read the unit files from disk.
    #[cfg(any(test, not(target_os = "linux")))]
    fn reload(&self) -> io::Result<()>;
    /// Confirm no unrelated server already occupies the expected listener.
    fn listener_is_idle(&self) -> io::Result<()>;
    /// Start the unit the manager has loaded.
    #[cfg(any(test, not(target_os = "linux")))]
    fn start(&self) -> io::Result<()>;
    /// Enable the service after it has started and answered.
    #[cfg(any(test, not(target_os = "linux")))]
    fn enable(&self) -> io::Result<()>;
    /// Wait for the new server to answer against its database.
    fn ready(&self, path: &Path, data: &File) -> io::Result<()>;
    /// Probe fresh HTTP health for the managed process holding the selected database.
    fn check_live(&self, path: &Path, data: &File) -> io::Result<()>;
}

/// The fixed systemd program and the server endpoint to verify after starting.
#[derive(Deserialize, Serialize)]
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
                "systemctl {} {} failed: {}",
                arguments.first().copied().unwrap_or_default(),
                self.service,
                String::from_utf8_lossy(&output.stderr).trim()
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

    /// Identify the process currently named by the service manager.
    #[cfg(target_os = "linux")]
    fn main_pid(&self) -> io::Result<u32> {
        let output = self.systemctl(&["show", "-p", "MainPID", "--value", &self.service])?;
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u32>()
            .ok()
            .filter(|pid| output.status.success() && *pid != 0)
            .ok_or_else(|| io::Error::other("could not identify moved service process"))
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
    fn probe(&self, challenge: Option<(&str, &str)>) -> io::Result<()> {
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
            health(stream, challenge)
        } else {
            health(stream, challenge)
        }
    }
}

/// Test the SQLite-backed health route over a plain or TLS connection.
fn health(
    mut stream: impl io::Read + io::Write,
    challenge: Option<(&str, &str)>,
) -> io::Result<()> {
    use std::io::{BufRead, BufReader};
    write!(
        stream,
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
    )?;
    #[cfg(target_os = "linux")]
    if let Some((nonce, _)) = challenge {
        write!(
            stream,
            "{}: {nonce}\r\n",
            infraternal_server::move_health::HEADER
        )?;
    }
    stream.write_all(b"\r\n")?;
    let mut response = BufReader::new(stream.take(8 * 1024));
    let mut line = String::new();
    response.read_line(&mut line)?;
    if !line.starts_with("HTTP/1.1 200 ") {
        return Err(io::Error::other(
            "server health check did not return HTTP 200",
        ));
    }
    #[cfg(target_os = "linux")]
    if let Some((_, expected)) = challenge {
        loop {
            line.clear();
            if response.read_line(&mut line)? == 0 || line == "\r\n" {
                return Err(disk::invalid(
                    "HTTP health did not identify the process holding the moved database",
                ));
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case(infraternal_server::move_health::HEADER)
                && value.trim() == expected
            {
                break;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = challenge;
    Ok(())
}

#[cfg(target_os = "linux")]
impl Systemd {
    /// Match the selected file against the credential-checked `MainPID`'s report.
    fn verify_database(path: &Path, data: &File, pid: u32, challenge: &str) -> io::Result<String> {
        use crate::server_control::{DATABASE_NAME, Database, query_database};

        let database = disk::regular(data, OsStr::new(DATABASE_NAME))?;
        let expected = Database::new(
            std::path::absolute(path.join(DATABASE_NAME))?,
            &database.metadata()?,
        );
        let proof = query_database(path, pid, challenge).map_err(|error| {
            io::Error::other(format!(
                "the running service has not opened the moved database: {error}"
            ))
        })?;
        if proof.database != expected {
            return Err(disk::invalid(
                "the running service has not opened the moved database",
            ));
        }
        Ok(proof.health)
    }
}

impl Service for Systemd {
    /// Only a confirmed inactive or failed unit counts as stopped.
    #[cfg(any(test, not(target_os = "linux")))]
    fn active(&self) -> io::Result<bool> {
        Ok(!matches!(self.state()?.as_str(), "inactive" | "failed"))
    }

    #[cfg(any(test, not(target_os = "linux")))]
    fn stop(&self) -> io::Result<()> {
        self.checked(&["stop", &self.service])
    }

    /// Stop any start already queued before this direct move.
    #[cfg(any(test, not(target_os = "linux")))]
    fn quiesce(&self) -> io::Result<()> {
        self.stop()
    }

    #[cfg(any(test, not(target_os = "linux")))]
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

    #[cfg(any(test, not(target_os = "linux")))]
    fn start(&self) -> io::Result<()> {
        self.checked(&["start", &self.service])
    }

    #[cfg(any(test, not(target_os = "linux")))]
    fn enable(&self) -> io::Result<()> {
        self.checked(&["enable", "--now", &self.service])
    }

    fn ready(&self, path: &Path, data: &File) -> io::Result<()> {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if self.probe(None).is_ok() {
                return self.check_live(path, data);
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

    #[cfg(target_os = "linux")]
    fn check_live(&self, path: &Path, data: &File) -> io::Result<()> {
        let pid = self.main_pid()?;
        let mut random = [0; 16];
        openssl::rand::rand_bytes(&mut random).map_err(io::Error::other)?;
        let challenge = format!("{:032x}", u128::from_be_bytes(random));
        let proof = Self::verify_database(path, data, pid, &challenge)?;
        self.probe(Some((&challenge, &proof)))?;
        if !matches!(self.state()?.as_str(), "active" | "activating") || self.main_pid()? != pid {
            return Err(disk::invalid(
                "the moved service stopped or changed during verification",
            ));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn check_live(&self, _path: &Path, _data: &File) -> io::Result<()> {
        Err(io::ErrorKind::Unsupported.into())
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
    /// On a combined host, only these recorded top-level entries may retire.
    #[serde(default)]
    original_entries: Option<BTreeMap<String, Identity>>,
    /// Pinned backup directory for individually collected shared-base entries.
    #[serde(default)]
    backup_identity: Option<Identity>,
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
#[derive(Clone, Debug, Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
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
        let current = read_units(unit, to)?;
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
    let combined = combined_move(old, to) && legacy.is_none();
    if !valid_move_paths(old, to) || (combined_move(old, to) && !combined) {
        return Err(disk::invalid(
            "data folders must be absolute and outside one another, except for the combined-host server directory",
        ));
    }
    if legacy.is_some() && from != old && from != to {
        return Err(disk::invalid(
            "legacy marker does not match the installed service",
        ));
    }
    let (old_parent, old_name) = disk::parent(old, false)?;
    let source = optional_tree(&old_parent, old_name)?;
    if let Some(source) = &source {
        if combined {
            if !disk::names(source)?.iter().any(|name| is_shared(name)) {
                return Err(disk::invalid("nested move requires a shared install base"));
            }
            database_identity(source)?;
        } else {
            reject_shared(source, "source")?;
        }
    }
    let old_marker = source
        .as_ref()
        .map(read_legacy_marker)
        .transpose()?
        .flatten();
    if old_marker
        .as_deref()
        .is_some_and(|path| path != old || combined)
    {
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
        inspect_target(to, needs_private_target(to, combined))?;
    } else {
        let (parent, name) = disk::parent(to, false)?;
        let target = disk::tree(&parent, name)?;
        if target.metadata()?.mode() & 0o077 != 0 {
            return Err(disk::invalid(
                "legacy target is a shared base; preserve both folders",
            ));
        }
        reject_shared(&target, "target")?;
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
            && let Some(mapped) = relocated_path(value, &self.from, &self.to)
        {
            *value = mapped;
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
#[cfg(not(target_os = "linux"))]
pub fn apply(
    relocation: &Relocation,
    service: &dyn Service,
    now: SystemTime,
    publish: impl FnOnce() -> io::Result<()>,
) -> Result<Outcome, MoveError> {
    apply_recorded(relocation, service, now, publish, |_, _| Ok(()))
}

/// Finish the cutover with a durable receipt before erasing the journal.
#[cfg(any(test, not(target_os = "linux")))]
fn apply_recorded(
    relocation: &Relocation,
    service: &dyn Service,
    now: SystemTime,
    publish: impl FnOnce() -> io::Result<()>,
    complete: impl FnOnce(&Journal, &Outcome) -> io::Result<()>,
) -> Result<Outcome, MoveError> {
    let result = with_journal(
        relocation,
        now,
        || service.active(),
        |transaction, journal| {
            let Transaction {
                parent,
                target_name,
                work,
                work_name,
                ..
            } = transaction;
            let switched = current_side(journal, &read_units(&journal.unit, &journal.to)?)?;
            let prepare = (|| {
                if journal.ready {
                    let target = selected_target(parent, target_name, journal)?;
                    if !service.active()? {
                        service.reload()?;
                        service.start()?;
                    }
                    service.ready(&journal.to, &target)?;
                    selected_target(parent, target_name, journal)?;
                    return Ok(());
                }
                service.quiesce()?;
                if service.active()? {
                    return Err(io::Error::other("the service did not stop"));
                }
                stage_start(transaction, journal, switched, service, publish)?;
                let target = selected_target(parent, target_name, journal)?;
                let startup = service
                    .reload()
                    .and_then(|()| service.start())
                    .and_then(|()| service.ready(&journal.to, &target))
                    .and_then(|()| service.enable())
                    .and_then(|()| service.ready(&journal.to, &target))
                    .and_then(|()| selected_target(parent, target_name, journal).map(drop));
                if let Err(error) = startup {
                    // A service whose startup cannot be confirmed may have written
                    // to either tree. Preserve both for inspection after any retry.
                    journal.backup_action = Backup::Retain;
                    let recorded = save(work, journal);
                    let stopped = service.stop();
                    recorded.and(stopped).map_err(|recovery| {
                        io::Error::other(format!(
                            "{error}; preserving both trees and stopping the service: {recovery}"
                        ))
                    })?;
                    return Err(error);
                }
                journal.ready = true;
                save(work, journal)
            })();
            let result = prepare.and_then(|()| {
                let outcome = finish(transaction, journal, service)?;
                complete(journal, &outcome)?;
                remove_journal(parent, work_name, work)?;
                Ok(outcome)
            });
            if let Err(error) = &result
                && !journal.ready
                && !journal.legacy_target
                && !current_side(journal, &read_units(&journal.unit, &journal.to)?)?
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
                    discard_unpublished(transaction, journal)?;
                }
            }
            result
        },
    );
    result.map_err(|error| MoveError::io("moving data to", &relocation.to, &error))
}

/// The pinned filesystem entries held while staging or completing a move.
struct Transaction<'a> {
    /// Parent of the destination and journal, locked by the caller.
    parent: &'a File,
    /// Destination name relative to its pinned parent.
    target_name: &'a OsStr,
    /// Private journal directory.
    work: &'a File,
    /// Journal directory name relative to the destination parent.
    work_name: &'a OsStr,
    /// Pinned parent of the original.
    old_parent: &'a File,
    /// Original name relative to its pinned parent.
    old_name: &'a OsStr,
}

/// Open the existing record, or durably record the snapshot plan before staging.
fn with_journal<T>(
    relocation: &Relocation,
    now: SystemTime,
    was_running: impl FnOnce() -> io::Result<bool>,
    run: impl FnOnce(&Transaction<'_>, &mut Journal) -> io::Result<T>,
) -> io::Result<T> {
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
    let mut journal = if let Some(journal) = load_record(&work, &relocation.to, &relocation.unit)? {
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
        let combined = combined_move(&current.from, &current.to);
        let original_entries = if combined {
            Some(combined_entries(&disk::tree(&old_parent, old_name)?)?)
        } else {
            None
        };
        let backup = backup_path(
            if combined { &current.to } else { &current.from },
            now,
            combined,
        )?;
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
            original_entries,
            backup_identity: None,
            backup_action: if current.same_filesystem && !current.legacy_target {
                Backup::Remove
            } else {
                Backup::Retain
            },
            legacy_target: current.legacy_target,
            ready: false,
            was_running: was_running()?,
            units: current.units,
            effective: current.effective,
        };
        save(&work, &journal)?;
        journal
    };
    run(
        &Transaction {
            parent: &parent,
            target_name,
            work: &work,
            work_name: &work_name,
            old_parent: &old_parent,
            old_name,
        },
        &mut journal,
    )
}

/// Prepare the destination while the listener is idle and commit the unit change.
fn stage_start(
    transaction: &Transaction<'_>,
    journal: &mut Journal,
    switched: bool,
    service: &dyn Service,
    publish: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let Transaction {
        parent,
        target_name,
        work,
        old_parent,
        old_name,
        ..
    } = transaction;
    if switched && journal.backup_action == Backup::Remove {
        // A former worker could have started a process before proving which
        // database it opened. Its writes to either tree must survive.
        journal.backup_action = Backup::Retain;
        save(work, journal)?;
    }
    service.listener_is_idle()?;
    reconcile_staging(parent, target_name, work, journal)?;
    if !switched && !journal.legacy_target {
        prepare_data(parent, target_name, work, old_parent, old_name, journal)?;
    }
    let target = disk::tree(parent, target_name)?;
    if journal.target != Some(Identity::of(&target)?) {
        return Err(disk::invalid("destination identity changed"));
    }
    if !switched || journal.database.is_none() {
        if switched {
            // Older journals did not pin the database before first start.
            journal.backup_action = Backup::Retain;
        }
        journal.database = Some(database_identity(&target)?);
        save(work, journal)?;
    }
    selected_target(parent, target_name, journal)?;
    publish()?;
    write_units(journal)?;
    Ok(())
}

/// Free uncommitted staging while the original is still selected for startup.
fn discard_unpublished(transaction: &Transaction<'_>, journal: &mut Journal) -> io::Result<()> {
    let target = optional_tree(transaction.parent, transaction.target_name)?
        .as_ref()
        .map(Identity::of)
        .transpose()?;
    if target != journal.target && target != journal.staged {
        // A different destination blocks recovery, but it does not own the
        // separately journaled staging inode that this transaction created.
        discard_recorded_staging(transaction.work, journal)?;
    } else {
        reconcile_staging(
            transaction.parent,
            transaction.target_name,
            transaction.work,
            journal,
        )?;
    }
    if journal.target.is_none() {
        remove_journal(transaction.parent, transaction.work_name, transaction.work)?;
    }
    Ok(())
}

/// Remove only the staging directory whose identity the journal recorded.
/// An unrecorded or replaced entry stays untouched so cleanup cannot delete a
/// tree that this move did not create.
fn discard_recorded_staging(work: &File, journal: &mut Journal) -> io::Result<()> {
    let stage_name = OsStr::new(STAGING);
    let stage = optional_tree(work, stage_name)?;
    match (journal.staged, stage) {
        (Some(expected), Some(stage)) => {
            if Identity::of(&stage)? != expected {
                return Err(disk::invalid("staging identity changed during move"));
            }
            disk::retire(work, stage_name, expected, false)?;
            journal.staged = None;
            save(work, journal)?;
        }
        (Some(_), None) => {
            journal.staged = None;
            save(work, journal)?;
        }
        (None, Some(_)) => {
            return Err(disk::invalid(
                "staging directory is not recorded in the move journal",
            ));
        }
        (None, None) => {}
    }
    Ok(())
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
    let names = if let Some(entries) = &journal.original_entries {
        if combined_entries(&source)? != *entries {
            return Err(disk::invalid(
                "original server entries changed before staging",
            ));
        }
        entries.keys().map(OsString::from).collect()
    } else {
        disk::names(&source)?
    };
    for name in names {
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
    if let Some(entries) = &journal.original_entries
        && combined_entries(&source)? != *entries
    {
        return Err(disk::invalid(
            "original server entries changed during staging",
        ));
    }
    if journal.target.is_some() {
        let previous = disk::tree(parent, target_name)?;
        for name in disk::names(&previous)? {
            if is_firewall(&name) {
                disk::copy_entry(&previous, &stage, &name)?;
            }
        }
    }
    // The infraternal agent's traversable base does not describe the private
    // child. For a disjoint source, still preserve its directory metadata.
    if journal.original_entries.is_none() {
        disk::preserve_copy(&source, &stage)?;
    }
    if needs_private_target(&journal.to, journal.original_entries.is_some()) {
        use std::os::unix::fs::PermissionsExt as _;
        stage.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        stage.sync_all()?;
    }
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
    if needs_private_target(&journal.to, journal.original_entries.is_some()) {
        check_combined_mode(&target)?;
    }
    if journal.target != Some(Identity::of(&target)?) {
        return Err(disk::invalid("destination identity changed during cleanup"));
    }
    if journal.database != Some(database_identity(&target)?) {
        return Err(disk::invalid(
            "destination database does not match the move journal",
        ));
    }
    Ok(target)
}

/// Resolve the configured absolute path again, independent of staging handles.
fn live_target(journal: &Journal) -> io::Result<File> {
    let (parent, name) = disk::parent(&journal.to, false)?;
    selected_target(&parent, name, journal)
}

/// Retire the saved source only after the current path and service agree.
fn finish(
    transaction: &Transaction<'_>,
    journal: &mut Journal,
    service: &dyn Service,
) -> io::Result<Outcome> {
    if journal.original_entries.is_some() {
        return finish_combined(transaction, journal, service);
    }
    let (old_parent, old_name) = (transaction.old_parent, transaction.old_name);
    let mut leftover = None;
    // The rename is recoverable: the journal already records the exact backup.
    // Do not change the source while the configured destination is uncertain.
    let target = live_target(journal)?;
    if journal.legacy_target
        && let Some(previous) = read_legacy_marker(&target)?
        && previous != journal.from
    {
        return Err(disk::invalid("legacy move marker changed"));
    }
    let backup = if let Some(source) = journal.source {
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
            Some((backup, source))
        } else if journal.backup_action == Backup::Retain {
            return Err(disk::invalid(
                "original folder and its recorded backup are missing",
            ));
        } else {
            None
        }
    } else {
        None
    };
    if let Some((backup, source)) = backup {
        leftover = retire_original(old_parent, backup, source, journal, service)?;
    }
    let target = live_target(journal)?;
    if journal.legacy_target && read_legacy_marker(&target)?.is_some() {
        disk::unlink(&target, OsStr::new(MARKER), false)?;
    }
    Ok(Outcome { leftover })
}

/// Retire the original server entries individually without renaming or chmodding the base.
fn finish_combined(
    transaction: &Transaction<'_>,
    journal: &mut Journal,
    service: &dyn Service,
) -> io::Result<Outcome> {
    let source = disk::tree(transaction.old_parent, transaction.old_name)?;
    if journal.source != Some(Identity::of(&source)?)
        || Identity::of(transaction.parent)? != Identity::of(&source)?
    {
        return Err(disk::invalid("shared base identity changed during move"));
    }
    let entries = journal
        .original_entries
        .as_ref()
        .ok_or_else(|| disk::invalid("combined move is missing its original entries"))?;
    let name = journal
        .backup
        .file_name()
        .ok_or_else(|| disk::invalid("combined backup lacks a name"))?;
    let backup = optional_tree(&source, name)?;
    let keep = journal.backup_action == Backup::Retain;
    let mut remaining = Vec::new();
    for (entry, identity) in entries {
        let entry = OsStr::new(entry);
        let original = disk::entry_identity(&source, entry)?;
        let saved = backup
            .as_ref()
            .map(|dir| disk::entry_identity(dir, entry))
            .transpose()?
            .flatten();
        if original == Some(*identity) && saved.is_none() {
            remaining.push((entry, *identity));
        } else if !(original.is_none()
            && (saved == Some(*identity)
                || (!keep && saved.is_none() && journal.backup_identity.is_some())))
        {
            return Err(disk::invalid(
                "recorded server entry changed before retirement",
            ));
        }
    }
    if let Some(backup) = &backup {
        let identity = Identity::of(backup)?;
        let entries_in_backup = disk::names(backup)?;
        if backup.metadata()?.mode() & 0o077 != 0
            || journal
                .backup_identity
                .is_some_and(|recorded| recorded != identity)
            || (journal.backup_identity.is_none() && !entries_in_backup.is_empty())
            || entries_in_backup
                .iter()
                .any(|name| name.to_str().is_none_or(|name| !entries.contains_key(name)))
        {
            return Err(disk::invalid(
                "combined backup differs from its recorded entries",
            ));
        }
    } else if journal.backup_identity.is_some() && (keep || !remaining.is_empty()) {
        return Err(disk::invalid("recorded combined backup is missing"));
    }
    if backup.is_none() && remaining.is_empty() && !keep {
        source.sync_all()?;
        return Ok(Outcome { leftover: None });
    }
    check_retirement_health(journal, service)?;
    let backup = match backup {
        Some(backup) => backup,
        None => disk::make_dir(&source, name)?,
    };
    let identity = Identity::of(&backup)?;
    if journal.backup_identity.is_none() {
        journal.backup_identity = Some(identity);
        save(transaction.work, journal)?;
    }
    for (entry, expected) in remaining {
        if disk::entry_identity(&source, entry)? != Some(expected) {
            return Err(disk::invalid(
                "original server entry changed during retirement",
            ));
        }
        disk::rename_new(&source, entry, &backup, entry)?;
    }
    let leftover = retire_original(&source, name, identity, journal, service)?;
    Ok(Outcome { leftover })
}

/// Renew the live proof immediately before retiring the exact recorded original.
fn retire_original(
    parent: &File,
    name: &OsStr,
    source: Identity,
    journal: &Journal,
    service: &dyn Service,
) -> io::Result<Option<PathBuf>> {
    check_retirement_health(journal, service)?;
    let keep = journal.backup_action == Backup::Retain;
    disk::retire(parent, name, source, keep)?;
    Ok(keep.then(|| journal.backup.clone()))
}

/// Bind retirement to a fresh challenge and the configured destination.
fn check_retirement_health(journal: &Journal, service: &dyn Service) -> io::Result<()> {
    let target = live_target(journal)?;
    service.check_live(&journal.to, &target)?;
    // The configured parent may have changed while the manager or server replied.
    live_target(journal).map(drop)
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
    let combined = combined_move(&journal.from, to);
    let backup_base = if combined { to } else { &journal.from };
    let prefix = backup_prefix(backup_base, combined)?;
    if journal.to != to
        || journal.unit != unit
        || !valid_move_paths(&journal.from, to)
        || combined != journal.original_entries.is_some()
        || (combined && (journal.legacy_target || journal.source.is_none()))
        || (journal.backup_identity.is_some() && (!combined || !journal.ready))
        || journal.original_entries.as_ref().is_some_and(|entries| {
            !entries.contains_key("infraternal.sqlite")
                || entries.keys().any(|name| {
                    Path::new(name).file_name() != Some(OsStr::new(name))
                        || shared_base_entry(OsStr::new(name))
                        || name == MARKER
                })
        })
        || journal.staging != to.with_file_name(work_name(target)).join(STAGING)
        || journal.backup.parent() != backup_base.parent()
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
fn backup_path(old: &Path, now: SystemTime, combined: bool) -> io::Result<PathBuf> {
    let mut name = backup_prefix(old, combined)?;
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    name.push(format!("{}-{}", utc_stamp(seconds), uuid::Uuid::new_v4()));
    Ok(old.with_file_name(name))
}

/// A combined backup is private and lives inside the shared base.
fn backup_prefix(path: &Path, combined: bool) -> io::Result<OsString> {
    let leaf = path
        .file_name()
        .ok_or_else(|| disk::invalid("source lacks a name"))?;
    let mut prefix = if combined {
        OsString::from(".")
    } else {
        OsString::new()
    };
    prefix.push(leaf);
    prefix.push(".moved-");
    Ok(prefix)
}

/// Inspect a fresh target, allowing only the server's dedicated firewall files.
fn inspect_target(to: &Path, private: bool) -> io::Result<()> {
    let (parent, name) = match disk::parent(to, false) {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let Some(folder) = optional_tree(&parent, name)? else {
        return Ok(());
    };
    if private {
        check_combined_mode(&folder)?;
    }
    reject_shared(&folder, "target")?;
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
fn reject_shared(folder: &File, side: &str) -> io::Result<()> {
    if disk::names(folder)?.iter().any(|name| is_shared(name)) {
        return Err(io::Error::other(format!(
            "the {side} is a shared install base; pass --data to keep the current folder",
        )));
    }
    Ok(())
}

/// The one supported nested layout is the Linux shared base's private server child.
fn combined_move(from: &Path, to: &Path) -> bool {
    cfg!(target_os = "linux")
        && to.parent() == Some(from)
        && to.file_name() == Some(OsStr::new("server"))
}

/// Accept disjoint data trees and the narrowly defined shared-base split.
fn valid_move_paths(from: &Path, to: &Path) -> bool {
    from.is_absolute()
        && to.is_absolute()
        && (combined_move(from, to) || (!from.starts_with(to) && !to.starts_with(from)))
}

/// Paths whose ownership stays with the install base throughout a combined move.
fn shared_base_entry(name: &OsStr) -> bool {
    is_shared(name)
        || is_firewall(name)
        || matches!(
            name.to_str(),
            Some("server" | ".server.cutover" | ".infraternal-move-server")
        )
        || name.to_string_lossy().starts_with(".server.moved-")
}

/// Pin the durable server entries while leaving the infraternal agent's namespace unopened.
fn combined_entries(source: &File) -> io::Result<BTreeMap<String, Identity>> {
    let mut entries = BTreeMap::new();
    for name in disk::names(source)? {
        if shared_base_entry(&name) || name == MARKER || disk::is_socket(source, &name)? {
            continue;
        }
        let identity = disk::entry_identity(source, &name)?
            .ok_or_else(|| disk::invalid("server entry disappeared while planning"))?;
        let name = name
            .into_string()
            .map_err(|_| disk::invalid("combined server entry is not UTF-8"))?;
        entries.insert(name, identity);
    }
    Ok(entries)
}

/// Map a server-owned path while preserving executables and other shared-base paths.
fn relocated_path(path: &Path, from: &Path, to: &Path) -> Option<PathBuf> {
    let suffix = path.strip_prefix(from).ok()?;
    if combined_move(from, to) && suffix.iter().next().is_some_and(shared_base_entry) {
        return None;
    }
    Some(if suffix.as_os_str().is_empty() {
        to.to_owned()
    } else {
        to.join(suffix)
    })
}

/// A combined host's server directory cannot expose its contents or traversal.
fn check_combined_mode(folder: &File) -> io::Result<()> {
    if folder.metadata()?.mode() & 0o7777 != 0o700 {
        return Err(disk::invalid(
            "combined server data directory must have mode 0700",
        ));
    }
    Ok(())
}

/// The private child also receives servers formerly installed outside the shared base.
fn needs_private_target(to: &Path, nested: bool) -> bool {
    nested
        || (cfg!(target_os = "linux")
            && to == Path::new(super::install_paths::LINUX_COMBINED_SERVER))
}

/// Create or verify the private server child through the trusted shared base.
pub(super) fn create_combined_server_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let (base, name) = disk::parent(path, false)?;
    let folder = if let Some(folder) = optional_tree(&base, name)? {
        folder
    } else {
        let folder = disk::make_dir(&base, name)?;
        folder.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        folder.sync_all()?;
        folder
    };
    check_combined_mode(&folder)
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
fn read_units(unit: &Path, to: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    #[cfg(not(target_os = "linux"))]
    let _ = to;
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
            #[cfg(target_os = "linux")]
            if manager::is_recovery_hook(&name, &text, to)? {
                continue;
            }
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
    let (Some(from_text), Some(_)) = (from.to_str(), to.to_str()) else {
        return Err(disk::invalid("data folders must be UTF-8 paths"));
    };
    let mut units = Vec::new();
    let mut effective = None;
    for (path, before) in read_units(unit, to)? {
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
                let mapped: Vec<String> =
                    words.iter().map(|word| map_word(word, from, to)).collect();
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
    current_side(journal, &read_units(&journal.unit, &journal.to)?)?;
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
fn map_word(word: &str, from: &Path, to: &Path) -> String {
    let replace = |path: &str| {
        relocated_path(Path::new(path), from, to)
            .and_then(|path| path.into_os_string().into_string().ok())
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
