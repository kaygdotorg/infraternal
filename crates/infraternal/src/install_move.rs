//! Moves an existing server install's data folder to its D395 standard location [D395, #516].
//!
//! The owner, on D395 (2026-11-15): "change for existing installs too". A fresh
//! `server init` already uses the standard folder ([`super::install_paths`]);
//! this module moves an install that an older init put somewhere else, such as
//! `./data` resolved against the shell's directory.
//!
//! # When it runs
//!
//! [`plan`] and [`apply`] are the whole interface. `server init` calls them
//! when it re-runs over a unit that records a non-standard `--data` and no
//! explicit `--data` was given (an explicit `--data` keeps any folder). The
//! server's updater (#211) is meant to call the same pair inside its stopped
//! window; a warm `server restart --binary` keeps the service running, so it
//! never moves anything.
//!
//! # What moves
//!
//! The whole folder, as one: the database with its `-wal` and `-shm` files,
//! `identity.json`, `ssh-trust/`, the mesh key folder and anything else that
//! lives there. Moving the folder instead of a list of files means a file added
//! later can never be left behind. Every `ExecStart` path inside the folder
//! (`--data`, and a `--remote-ca-dir` or TLS file kept there) is rewritten.
//!
//! # Steps, and why a crash at any point is safe
//!
//! The unit file is the single pointer to the live folder, so there is never a
//! second live copy: whichever folder the unit names is the install.
//!
//! 1. [`plan`] checks everything and changes nothing. It refuses a target that
//!    holds someone else's files (infraternal's own files in the install base,
//!    such as the host firewall's policy, may be there and stay untouched;
//!    see `is_reserved`), a symlinked or mounted old folder, a folder
//!    owned by another user, and a unit line other than `ExecStart` that names
//!    the old folder (it would break after the move).
//! 2. [`apply`] stops the service and confirms it is down.
//! 3. It writes a marker ([`MARKER`]) naming the old folder into it, then
//!    renames the folder. Across filesystems it copies into a hidden staging
//!    folder instead (files fsynced, modes and owners kept, stale sockets
//!    skipped), compares every file byte for byte, and only then renames the
//!    staging folder into place.
//! 4. It rewrites the unit and its drop-ins, each by an atomic rename. This is
//!    the switch.
//! 5. After a copy, the old folder is renamed to `<old>.moved-<UTC time>` and
//!    made read-only, kept until the operator removes it.
//! 6. It removes the marker, reloads the manager and starts the service again
//!    when it was running or is enabled.
//!
//! Crash before step 4: the unit still names the old folder. After a rename the
//! old folder is gone and the target carries our marker, so the next run only
//! finishes the switch ([`Stage::Switch`]). After a copy the old folder is
//! still there and authoritative (the service may have started on it since),
//! so the next run discards the marked copy and copies again ([`Stage::Redo`]).
//! Crash after step 4: the unit names the target and the marker is still in it,
//! so the next run sets the old folder aside if needed and removes the marker
//! ([`Stage::Cleanup`]). A failure inside [`apply`] before the switch undoes the
//! move and starts the old service again, so the old install keeps working.

use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

/// The marker file a move leaves in the data folder until it has finished.
///
/// Its only content is the old folder's path. It proves that a non-empty
/// target was made by our own interrupted move, never by someone else.
pub const MARKER: &str = ".infraternal-move";

/// Why a folder could not be moved; the text says what to do instead.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MoveError(String);

impl MoveError {
    /// Wrap an I/O failure with the step that failed.
    fn io(step: &str, path: &Path, error: &io::Error) -> Self {
        Self(format!("{step} {} failed: {error}", path.display()))
    }
}

/// The service manager calls a move needs; tests use a fake.
pub trait Service {
    /// Whether the service is running or on its way up or down.
    fn active(&self) -> io::Result<bool>;
    /// Whether the service starts at boot or login.
    fn enabled(&self) -> io::Result<bool>;
    /// Stop the service and wait until it has stopped.
    fn stop(&self) -> io::Result<()>;
    /// Make the manager read the rewritten unit files.
    fn reload(&self) -> io::Result<()>;
    /// Start the service.
    fn start(&self) -> io::Result<()>;
}

/// A systemd service, system-wide or in the caller's user manager.
pub struct Systemd {
    /// The `systemctl` to run, found at a fixed root-owned path the way the
    /// install itself finds it, never through `PATH`: a system move runs as
    /// root, and a writable folder early in `PATH` must not be able to supply
    /// its own `systemctl` (J658, J803).
    pub program: PathBuf,
    /// Talk to the user manager (`systemctl --user`).
    pub user: bool,
    /// The unit name, for example `infraternal-server.service`.
    pub service: String,
}

impl Systemd {
    /// Run `systemctl` with this scope and return its output.
    fn systemctl(&self, arguments: &[&str]) -> io::Result<std::process::Output> {
        let mut command = Command::new(&self.program);
        infraternal_shim::prepare_child(&mut command);
        command.stdin(Stdio::null());
        if self.user {
            command.arg("--user");
        }
        command.args(arguments).output()
    }

    /// Run `systemctl` and turn a non-zero exit into an error naming the action.
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
}

impl Service for Systemd {
    /// Reads `ActiveState`; only `inactive` and `failed` count as stopped.
    ///
    /// `is-active` was rejected: its non-zero exit means both "stopped" and
    /// "could not reach the manager", and only the second must stop a move.
    fn active(&self) -> io::Result<bool> {
        let output = self.systemctl(&["show", "-p", "ActiveState", "--value", &self.service])?;
        if !output.status.success() {
            return Err(io::Error::other("systemctl show failed"));
        }
        let state = String::from_utf8_lossy(&output.stdout);
        Ok(!matches!(state.trim(), "inactive" | "failed"))
    }

    fn enabled(&self) -> io::Result<bool> {
        let output = self.systemctl(&["is-enabled", &self.service])?;
        Ok(String::from_utf8_lossy(&output.stdout).trim() == "enabled")
    }

    fn stop(&self) -> io::Result<()> {
        self.checked(&["stop", &self.service])
    }

    fn reload(&self) -> io::Result<()> {
        self.checked(&["daemon-reload"])
    }

    fn start(&self) -> io::Result<()> {
        self.checked(&["start", &self.service])
    }
}

/// Where an interrupted or new move resumes; see the module's crash notes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Nothing moved yet: move the old folder.
    Move,
    /// A copy finished but the unit was never switched: discard it and copy again.
    Redo,
    /// The folder was renamed but the unit was never switched: switch it.
    Switch,
    /// The unit is switched: set the old folder aside if it is still there, drop the marker.
    Cleanup,
}

/// One unit file and the text it gets.
#[derive(Debug, Clone)]
struct Rewrite {
    /// The unit or drop-in file.
    path: PathBuf,
    /// Its bytes now, restored if a later write fails.
    before: Vec<u8>,
    /// Its text after the move.
    after: String,
}

/// A checked move, ready for [`apply`].
#[derive(Debug, Clone)]
pub struct Relocation {
    /// The folder the unit records now.
    pub from: PathBuf,
    /// The D395 standard folder.
    pub to: PathBuf,
    /// Where this run starts.
    pub stage: Stage,
    /// Whether both folders are on one filesystem, so a rename moves the data.
    pub same_filesystem: bool,
    /// Whether the target already holds infraternal's own files ([`is_reserved`]),
    /// so the data is moved in entry by entry and the folder itself stays.
    pub shared: bool,
    /// The unit files whose `ExecStart` changes, in write order.
    rewrites: Vec<Rewrite>,
}

/// What [`apply`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The read-only copy of the old folder, kept after a copy across filesystems.
    pub leftover: Option<PathBuf>,
    /// Whether the data was copied (true) or renamed (false).
    pub copied: bool,
    /// A step after the switch that did not finish; the next run retries it.
    pub warning: Option<String>,
}

/// Check a move from `from` to `to` for the service whose unit file is `unit`.
///
/// Returns `None` when there is nothing to do: the install is already in its
/// standard folder and no earlier move is unfinished. Nothing is changed.
pub fn plan(from: &Path, to: &Path, unit: &Path) -> Result<Option<Relocation>, MoveError> {
    if same_folder(from, to) {
        return Ok(read_marker(to).map(|previous| Relocation {
            from: previous,
            to: to.to_owned(),
            stage: Stage::Cleanup,
            same_filesystem: true,
            shared: false,
            rewrites: Vec::new(),
        }));
    }
    if !from.is_absolute() || !to.is_absolute() {
        return Err(MoveError(
            "both data folders must be absolute paths".to_owned(),
        ));
    }
    if to.starts_with(from) || from.starts_with(to) {
        return Err(MoveError(format!(
            "cannot move {} to {}: one folder is inside the other; pass --data {} to keep it",
            from.display(),
            to.display(),
            from.display()
        )));
    }
    let target = inspect_target(from, to)?;
    let shared = target_is_shared(to);
    let stage = match (fs::symlink_metadata(from), target) {
        (Err(error), Target::Ours) if error.kind() == io::ErrorKind::NotFound => Stage::Switch,
        (Err(error), _) if error.kind() == io::ErrorKind::NotFound => {
            return Err(MoveError(format!(
                "the unit's data folder {} does not exist, so there is nothing to move; \
                 if it lives on a disk that is not mounted, mount it and run init again, \
                 or pass --data to choose a folder",
                from.display()
            )));
        }
        (Err(error), _) => return Err(MoveError::io("reading", from, &error)),
        (Ok(metadata), target) => {
            check_source(from, &metadata)?;
            if shared {
                check_no_reserved_names(from, to)?;
            }
            match target {
                Target::Missing | Target::Empty => Stage::Move,
                Target::Ours => Stage::Redo,
            }
        }
    };
    let rewrites = unit_rewrites(unit, from, to)?;
    if rewrites.is_empty() {
        return Err(MoveError(format!(
            "{} does not record --data {}; nothing was moved",
            unit.display(),
            from.display()
        )));
    }
    let same_filesystem = match (fs::metadata(from), nearest_existing(to)) {
        (Ok(source), Some(ancestor)) => {
            fs::metadata(ancestor).is_ok_and(|a| a.dev() == source.dev())
        }
        _ => true,
    };
    Ok(Some(Relocation {
        from: from.to_owned(),
        to: to.to_owned(),
        stage,
        same_filesystem,
        shared,
        rewrites,
    }))
}

impl Relocation {
    /// The unit files whose `ExecStart` this move rewrites.
    pub fn unit_files(&self) -> impl Iterator<Item = &Path> {
        self.rewrites.iter().map(|rewrite| rewrite.path.as_path())
    }

    /// The text this move gives the unit file at `path`, or `None` when it leaves that file alone.
    ///
    /// `server init` checks the unit it is about to install against this
    /// text before moving anything, so a re-run the install would refuse
    /// moves nothing (J803).
    pub fn unit_text_after(&self, path: &Path) -> Option<&str> {
        self.rewrites
            .iter()
            .find(|rewrite| rewrite.path == path)
            .map(|rewrite| rewrite.after.as_str())
    }

    /// The plan in plain lines, for `--dry-run` and the confirmation.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut text = match self.stage {
            Stage::Cleanup => format!(
                "Finish the earlier move to {}: set {} aside if it is still there.\n",
                self.to.display(),
                self.from.display()
            ),
            Stage::Switch => format!(
                "Finish the earlier move of {} to {}: point the unit at the moved folder.\n",
                self.from.display(),
                self.to.display()
            ),
            Stage::Move | Stage::Redo => format!(
                "Move the data folder {} to {} (D395).\n{}",
                self.from.display(),
                self.to.display(),
                if self.same_filesystem {
                    "Method: rename on the same filesystem.\n".to_owned()
                } else {
                    format!(
                        "Method: copy, compare every file, then keep {} as a dated read-only leftover.\n",
                        self.from.display()
                    )
                }
            ),
        };
        if self.stage != Stage::Cleanup {
            text.push_str("The service is stopped during the move and started again afterwards.\n");
        }
        for path in self.unit_files() {
            let _ = writeln!(text, "Rewrite ExecStart in {}", path.display());
        }
        text
    }
}

impl Outcome {
    /// What happened, with the command that removes a leftover.
    #[must_use]
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
                "The old folder is kept read-only at {}. Once the server works, remove it with:\n  chmod -R u+w {quoted} && rm -rf {quoted}",
                leftover.display()
            );
        }
        if let Some(warning) = &self.warning {
            let _ = writeln!(text, "Not finished: {warning}. Run init again to finish.");
        }
        text
    }
}

/// Carry out a [`plan`]ned move; on failure before the switch the old install keeps working.
///
/// `now` is the UNIX time used to name a leftover folder.
pub fn apply(
    relocation: &Relocation,
    service: &dyn Service,
    now: SystemTime,
) -> Result<Outcome, MoveError> {
    if relocation.stage == Stage::Cleanup {
        // The unit already names the target; the service may run there.
        return Ok(finish(relocation, now, false));
    }
    let running = service.active().map_err(|error| {
        MoveError(format!(
            "could not read the service state: {error}; nothing was moved"
        ))
    })?;
    let enabled = service.enabled().unwrap_or(false);
    if running {
        service
            .stop()
            .map_err(|error| MoveError(format!("{error}; nothing was moved")))?;
        if service.active().unwrap_or(true) {
            let _ = service.start();
            return Err(MoveError(
                "the service did not stop; nothing was moved".to_owned(),
            ));
        }
    }
    match move_and_switch(relocation, now) {
        Ok(outcome) => {
            let restart = service.reload().and_then(|()| {
                if running || enabled {
                    service.start()
                } else {
                    Ok(())
                }
            });
            Ok(match restart {
                Ok(()) => outcome,
                Err(error) => Outcome {
                    warning: Some(format!("the moved service did not start: {error}")),
                    ..outcome
                },
            })
        }
        Err(error) => {
            if running {
                let _ = service.start();
            }
            Err(error)
        }
    }
}

/// Steps 3–6 of the module docs, undoing everything when the switch fails.
///
/// A target that already holds infraternal's own files (`shared`) cannot be
/// replaced by a rename, and those files must stay where they are. The old
/// folder is then renamed (or copied and verified) into
/// `<target>/.infraternal-incoming` as one unit, and its entries are moved
/// out into the target one rename at a time, the marker last. The incoming
/// folder carries the marker until then, so a crash in between is finished
/// by the next run ([`merge_incoming`]); no entry is ever in two places.
fn move_and_switch(relocation: &Relocation, now: SystemTime) -> Result<Outcome, MoveError> {
    let (from, to) = (&relocation.from, &relocation.to);
    let shared = relocation.shared;
    let incoming = to.join(INCOMING);
    let mut copied = false;
    if relocation.stage == Stage::Redo {
        // Our own verified copy of a folder that may have changed since;
        // infraternal's own files in the target are never part of it.
        discard_ours(to)?;
    }
    if matches!(relocation.stage, Stage::Move | Stage::Redo) {
        if !shared && to.is_dir() {
            fs::remove_dir(to)
                .map_err(|error| MoveError::io("removing the empty folder", to, &error))?;
        }
        let parent = to
            .parent()
            .ok_or_else(|| MoveError("the target has no parent folder".to_owned()))?;
        super::install_paths::create_private_dir(parent)
            .map_err(|error| MoveError::io("creating", parent, &error))?;
        if shared {
            // A crashed copy's staging folder is ours; never let it linger beside the data.
            remove_stale_staging(&incoming, &staging_prefix(INCOMING))?;
        }
        write_marker(from, from).map_err(|error| MoveError::io("marking", from, &error))?;
        let destination = if shared { &incoming } else { to };
        copied = match rename_folder(from, destination) {
            Ok(()) => false,
            Err(error) if error.raw_os_error() == Some(nix::libc::EXDEV) => {
                if let Err(error) = copy_into_place(from, destination) {
                    let _ = fs::remove_file(from.join(MARKER));
                    return Err(error);
                }
                true
            }
            Err(error) => {
                let _ = fs::remove_file(from.join(MARKER));
                return Err(MoveError::io("moving", from, &error));
            }
        };
        sync_parent(from);
        sync_parent(destination);
    }
    let resumed = relocation.stage == Stage::Switch;
    let undo = |copied: bool| {
        if resumed {
            return;
        }
        if shared {
            if copied {
                let _ = discard_ours(to);
            } else if gather_ours(to).is_ok() && fs::rename(&incoming, from).is_ok() {
                sync_parent(from);
            }
        } else if copied {
            let _ = fs::remove_dir_all(to);
        } else if fs::rename(to, from).is_ok() {
            sync_parent(from);
        }
        let _ = fs::remove_file(from.join(MARKER));
    };
    if shared {
        if let Err(error) = merge_incoming(to) {
            undo(copied);
            return Err(error);
        }
    } else if let Err(error) = fs::set_permissions(to, fs::Permissions::from_mode(0o700)) {
        // A shared install base keeps its own mode (`infraternal up` makes it 0711).
        undo(copied);
        return Err(MoveError::io("making private", to, &error));
    }
    if let Err(error) = write_rewrites(&relocation.rewrites) {
        undo(copied);
        return Err(error);
    }
    Ok(Outcome {
        copied,
        ..finish(relocation, now, copied)
    })
}

/// Step 5–6 after the switch: set a remaining old folder aside and drop the marker.
///
/// Failures here never undo the switch; they are reported and the next run
/// (in [`Stage::Cleanup`]) retries them.
fn finish(relocation: &Relocation, now: SystemTime, copied: bool) -> Outcome {
    let mut outcome = Outcome {
        leftover: None,
        copied,
        warning: None,
    };
    if fs::symlink_metadata(&relocation.from).is_ok() {
        // The marker went into the old folder before the copy; a leftover is finished.
        let _ = fs::remove_file(relocation.from.join(MARKER));
        match set_aside(&relocation.from, now) {
            Ok(leftover) => outcome.leftover = Some(leftover),
            Err(error) => {
                outcome.warning = Some(format!(
                    "the old folder {} could not be set aside: {error}",
                    relocation.from.display()
                ));
                return outcome;
            }
        }
    }
    match fs::remove_file(relocation.to.join(MARKER)) {
        Ok(()) => sync_dir(&relocation.to),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            outcome.warning = Some(format!("the move marker could not be removed: {error}"));
        }
    }
    outcome
}

/// Rename a folder; tests can make it fail as if across filesystems.
fn rename_folder(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(test)]
    if tests::FORCE_COPY.with(std::cell::Cell::get) {
        return Err(io::Error::from_raw_os_error(nix::libc::EXDEV));
    }
    fs::rename(from, to)
}

/// What already sits at the target.
enum Target {
    /// Nothing.
    Missing,
    /// An empty folder.
    Empty,
    /// A folder our own move to here left, marked with the same old folder.
    Ours,
}

/// Classify the target, refusing anything that is not ours to replace.
fn inspect_target(from: &Path, to: &Path) -> Result<Target, MoveError> {
    let metadata = match fs::symlink_metadata(to) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Target::Missing),
        Err(error) => return Err(MoveError::io("reading", to, &error)),
    };
    if !metadata.is_dir() {
        return Err(MoveError(format!(
            "{} exists and is not a folder; move it away, or pass --data to keep the current folder",
            to.display()
        )));
    }
    let ours =
        |folder: &Path| read_marker(folder).is_some_and(|previous| same_folder(&previous, from));
    if ours(to) || ours(&to.join(INCOMING)) {
        return Ok(Target::Ours);
    }
    // infraternal's own files may stay; anything else is someone's to keep.
    let mut foreign: Vec<String> = fs::read_dir(to)
        .map_err(|error| MoveError::io("reading", to, &error))?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !is_reserved(name) && !name.starts_with(&staging_prefix(INCOMING)))
        .collect();
    if foreign.is_empty() {
        return Ok(Target::Empty);
    }
    foreign.sort();
    let more = foreign.len().saturating_sub(5);
    foreign.truncate(5);
    Err(MoveError(format!(
        "{} already holds {}{}, which infraternal did not put there, so {} was not moved; \
         move {} away, or pass --data {} to keep the current folder",
        to.display(),
        foreign.join(", "),
        if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        },
        from.display(),
        if foreign.len() + more == 1 {
            "it"
        } else {
            "them"
        },
        from.display()
    )))
}

/// The subfolder of a shared target that a move fills before its entries move out.
const INCOMING: &str = ".infraternal-incoming";

/// Whether `name` is something other parts of infraternal keep in the install
/// base itself, so a move into that folder keeps it, never moves or deletes it,
/// and never asks the operator to move it (J755, #483).
///
/// The list: the host firewall's policies (`host-firewall-server.json`,
/// `host-firewall-agent.json`, any `host-firewall-*.json`) and their atomic
/// writes in progress (`.host-firewall-*.pending`), whose loss would make the
/// boot loader drop the host table; and the root infraternal agent's layout
/// from `infraternal up` and SSH setup (`bin/`, `agent/`, `state/`,
/// `sessions/`), plus the hidden files SSH setup and promotion keep beside
/// them: every `.bootstrap-*` (the setup lock folder, owner, ready and
/// acquiring markers, transaction records and their `.tmp` writes), the
/// `.superseded-*` records of a replaced unit, and `.promotion-transaction`
/// (J803). A new file kept in `/var/lib/infraternal` by another part must be
/// added here.
fn is_reserved(name: &str) -> bool {
    // Case-sensitive names and prefixes: these are written by our own code.
    let extension = |wanted: &str| Path::new(name).extension().is_some_and(|ext| ext == wanted);
    matches!(
        name,
        "bin" | "agent" | "state" | "sessions" | ".promotion-transaction"
    ) || name.starts_with(".bootstrap-")
        || name.starts_with(".superseded-")
        || (name.starts_with("host-firewall-") && extension("json"))
        || (name.starts_with(".host-firewall-") && extension("pending"))
}

/// Whether the target folder exists and holds any of infraternal's own files.
fn target_is_shared(to: &Path) -> bool {
    fs::read_dir(to).is_ok_and(|entries| {
        entries
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_str().is_some_and(is_reserved))
    })
}

/// Refuse an old folder whose entries would take a reserved name in a shared target.
fn check_no_reserved_names(from: &Path, to: &Path) -> Result<(), MoveError> {
    let mut clashes: Vec<String> = fs::read_dir(from)
        .map_err(|error| MoveError::io("reading", from, &error))?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| is_reserved(name) || name == INCOMING)
        .collect();
    if clashes.is_empty() {
        return Ok(());
    }
    clashes.sort();
    Err(MoveError(format!(
        "{} holds {}, a name infraternal keeps in {} for other parts, so it was not moved; \
         pass --data {} to keep the current folder",
        from.display(),
        clashes.join(", "),
        to.display(),
        from.display()
    )))
}

/// Move every entry of `<to>/.infraternal-incoming` into `to`, the marker last.
///
/// Each step is one rename inside one folder, so an entry is always in
/// exactly one place; a crash leaves the rest in the incoming folder, still
/// marked, for the next run. Nothing reserved is ever touched.
fn merge_incoming(to: &Path) -> Result<(), MoveError> {
    let incoming = to.join(INCOMING);
    let entries = match fs::read_dir(&incoming) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(MoveError::io("reading", &incoming, &error)),
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name();
        if name == MARKER {
            continue;
        }
        let target = to.join(&name);
        if fs::symlink_metadata(&target).is_ok() {
            return Err(MoveError(format!(
                "{} already exists, so the moved {} was left in {}",
                target.display(),
                name.to_string_lossy(),
                incoming.display()
            )));
        }
        fs::rename(entry.path(), &target)
            .map_err(|error| MoveError::io("moving into", &target, &error))?;
    }
    if incoming.join(MARKER).exists() {
        fs::rename(incoming.join(MARKER), to.join(MARKER))
            .map_err(|error| MoveError::io("moving the marker into", to, &error))?;
    }
    fs::remove_dir(&incoming).map_err(|error| MoveError::io("removing", &incoming, &error))?;
    sync_dir(to);
    Ok(())
}

/// Put every non-reserved entry of `to` back into `<to>/.infraternal-incoming`.
///
/// The undo of [`merge_incoming`] after a failed switch; the caller then
/// renames the incoming folder back to the old one.
fn gather_ours(to: &Path) -> io::Result<()> {
    let incoming = to.join(INCOMING);
    if !incoming.exists() {
        use std::os::unix::fs::DirBuilderExt;
        // It becomes the old data folder again, so it is private like one.
        fs::DirBuilder::new().mode(0o700).create(&incoming)?;
    }
    for entry in fs::read_dir(to)?.filter_map(Result::ok) {
        let name = entry.file_name();
        if name == INCOMING || name.to_str().is_some_and(is_reserved) {
            continue;
        }
        fs::rename(entry.path(), incoming.join(&name))?;
    }
    sync_dir(to);
    Ok(())
}

/// Remove everything in `to` that is not reserved: our own earlier copy.
///
/// Only called when the marker proves the copy is ours, or to undo a copy
/// this run made. infraternal's own files stay.
fn discard_ours(to: &Path) -> Result<(), MoveError> {
    let entries = fs::read_dir(to).map_err(|error| MoveError::io("reading", to, &error))?;
    for entry in entries.filter_map(Result::ok) {
        if entry.file_name().to_str().is_some_and(is_reserved) {
            continue;
        }
        let path = entry.path();
        let result = if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        result.map_err(|error| MoveError::io("removing the stale copy", &path, &error))?;
    }
    Ok(())
}

/// Refuse an old folder that a rename or copy would not move safely.
fn check_source(from: &Path, metadata: &fs::Metadata) -> Result<(), MoveError> {
    let keep = format!("pass --data {} to keep it", from.display());
    if metadata.file_type().is_symlink() {
        return Err(MoveError(format!(
            "{} is a symbolic link; moving it would move only the link; {keep}",
            from.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(MoveError(format!(
            "{} is not a folder; {keep}",
            from.display()
        )));
    }
    if metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(MoveError(format!(
            "{} belongs to user id {}, not to the user running init; run init as that user, or {keep}",
            from.display(),
            metadata.uid()
        )));
    }
    let parent_device = from
        .parent()
        .and_then(|parent| fs::metadata(parent).ok())
        .map(|parent| parent.dev());
    if parent_device.is_some_and(|device| device != metadata.dev()) {
        return Err(MoveError(format!(
            "{} is a mount point; move its volume yourself, or {keep}",
            from.display()
        )));
    }
    Ok(())
}

/// The new text of the unit and every drop-in whose `ExecStart` names `from`.
///
/// Drop-ins come first and the unit last, matching systemd's order for
/// `ExecStart`. A non-`ExecStart` line naming the old folder (for example
/// `ReadWritePaths=`) is refused: after the move it would point at nothing.
fn unit_rewrites(unit: &Path, from: &Path, to: &Path) -> Result<Vec<Rewrite>, MoveError> {
    let (Some(from_text), Some(to_text)) = (from.to_str(), to.to_str()) else {
        return Err(MoveError("data folders must be UTF-8 paths".to_owned()));
    };
    let mut files = vec![unit.to_owned()];
    let mut dropins: Vec<PathBuf> = fs::read_dir(PathBuf::from(format!("{}.d", unit.display())))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "conf"))
                .collect()
        })
        .unwrap_or_default();
    dropins.sort();
    files.extend(dropins);
    let mut rewrites = Vec::new();
    for path in files {
        let before = fs::read(&path).map_err(|error| MoveError::io("reading", &path, &error))?;
        let text = String::from_utf8(before.clone())
            .map_err(|_| MoveError(format!("{} is not UTF-8 text", path.display())))?;
        let mut after = String::with_capacity(text.len());
        for (number, line) in text.split_inclusive('\n').enumerate() {
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
                let words = infraternal_status::exec_words(value).ok_or_else(|| {
                    MoveError(format!(
                        "{}:{} has an ExecStart that cannot be read safely",
                        path.display(),
                        number + 1
                    ))
                })?;
                let mapped: Vec<String> = words
                    .iter()
                    .map(|word| map_word(word, from_text, to_text))
                    .collect();
                if mapped != words {
                    after.push_str("ExecStart=");
                    after.push_str(&render_exec(&mapped, &path)?);
                    after.push_str(ending);
                    continue;
                }
            } else if names_path(body, from_text) {
                return Err(MoveError(format!(
                    "{}:{} names {} outside ExecStart and would break after the move; \
                     change it yourself, or pass --data {} to keep the folder",
                    path.display(),
                    number + 1,
                    from.display(),
                    from.display()
                )));
            }
            after.push_str(line);
        }
        if after != text {
            rewrites.push(Rewrite {
                path,
                before,
                after,
            });
        }
    }
    // The unit is first in `files`; write it last so drop-ins never lag it.
    if rewrites.first().is_some_and(|rewrite| rewrite.path == unit) {
        let first = rewrites.remove(0);
        rewrites.push(first);
    }
    Ok(rewrites)
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

/// Write every rewrite atomically; restore the earlier ones if one fails.
fn write_rewrites(rewrites: &[Rewrite]) -> Result<(), MoveError> {
    for (index, rewrite) in rewrites.iter().enumerate() {
        if let Err(error) = super::install::write_atomic(&rewrite.path, rewrite.after.as_bytes()) {
            for done in &rewrites[..index] {
                let _ = super::install::write_atomic(&done.path, &done.before);
            }
            return Err(MoveError::io("rewriting", &rewrite.path, &error));
        }
    }
    Ok(())
}

/// Copy `from` into a staging folder beside `to`, verify it, then rename it into place.
fn copy_into_place(from: &Path, to: &Path) -> Result<(), MoveError> {
    let name = to
        .file_name()
        .ok_or_else(|| MoveError("the target has no folder name".to_owned()))?
        .to_string_lossy();
    let prefix = staging_prefix(&name);
    remove_stale_staging(to, &prefix)?;
    let staging = to.with_file_name(format!("{prefix}{}", std::process::id()));
    let result = copy_tree(from, &staging)
        .map_err(|error| {
            MoveError(format!(
                "copying {} failed: {error}; nothing was moved",
                from.display()
            ))
        })
        .and_then(|()| {
            verify_tree(from, &staging).map_err(|error| {
                MoveError(format!(
                    "the copy of {} did not match: {error}; nothing was moved",
                    from.display()
                ))
            })
        })
        .and_then(|()| {
            fs::rename(&staging, to)
                .map_err(|error| MoveError::io("placing the copy at", to, &error))
        });
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

/// The name prefix of the hidden staging folder a copy into a folder called `name` uses.
fn staging_prefix(name: &str) -> String {
    format!(".{name}.partial-")
}

/// Remove staging folders an interrupted copy left beside `to`.
///
/// They hold a copy of the data, the mesh key included, that no unit points
/// at. Only real folders (not links or files) whose name starts with
/// `prefix` are ours; the old folder is never among them because it is not a
/// hidden sibling of the target.
fn remove_stale_staging(to: &Path, prefix: &str) -> Result<(), MoveError> {
    let Some(parent) = to.parent() else {
        return Ok(());
    };
    let entries = fs::read_dir(parent).map_err(|error| MoveError::io("reading", parent, &error))?;
    for entry in entries.filter_map(Result::ok) {
        let ours = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(prefix))
            && entry.file_type().is_ok_and(|kind| kind.is_dir());
        if ours {
            let path = entry.path();
            fs::remove_dir_all(&path).map_err(|error| MoveError::io("removing", &path, &error))?;
        }
    }
    Ok(())
}

/// Copy a folder tree, keeping modes (and owners, as root); sockets are skipped.
///
/// Every file and folder is fsynced, so the copy is on disk before the
/// switch. A socket belongs to the stopped server and is made again at start.
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(from)?;
    fs::create_dir(to)?;
    fs::set_permissions(to, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let (source, target) = (entry.path(), to.join(entry.file_name()));
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_tree(&source, &target)?;
        } else if kind.is_file() {
            copy_file(&source, &target)?;
        } else if kind.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(&source)?, &target)?;
            keep_owner(&fs::symlink_metadata(&source)?, &target)?;
        } else if !kind.is_socket() {
            return Err(io::Error::other(format!(
                "{} is a special file that cannot be copied",
                source.display()
            )));
        }
    }
    fs::set_permissions(to, fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
    keep_owner(&metadata, to)?;
    sync_dir(to);
    Ok(())
}

/// Copy one file's bytes and mode, then fsync it.
fn copy_file(from: &Path, to: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(from)?;
    let mut source = File::open(from)?;
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)?;
    io::copy(&mut source, &mut target)?;
    target.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
    target.sync_all()?;
    keep_owner(&metadata, to)
}

/// As root, give the copy the original's owner; a user's copy is already theirs.
fn keep_owner(metadata: &fs::Metadata, path: &Path) -> io::Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        std::os::unix::fs::lchown(path, Some(metadata.uid()), Some(metadata.gid()))?;
    }
    Ok(())
}

/// Check that `copy` holds exactly what `original` holds, reading every byte back.
fn verify_tree(original: &Path, copy: &Path) -> io::Result<()> {
    let mismatch = |path: &Path, what: &str| io::Error::other(format!("{} {what}", path.display()));
    let mut expected = Vec::new();
    for entry in fs::read_dir(original)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_socket() {
            continue;
        }
        let (source, target) = (entry.path(), copy.join(entry.file_name()));
        let copied = fs::symlink_metadata(&target).map_err(|_| mismatch(&target, "is missing"))?;
        if kind.is_dir() != copied.is_dir() || kind.is_symlink() != copied.file_type().is_symlink()
        {
            return Err(mismatch(&target, "has the wrong type"));
        }
        if kind.is_dir() {
            verify_tree(&source, &target)?;
        } else if kind.is_symlink() {
            if fs::read_link(&source)? != fs::read_link(&target)? {
                return Err(mismatch(&target, "points elsewhere"));
            }
        } else if !same_bytes(&source, &target)? {
            return Err(mismatch(&target, "differs from the original"));
        }
        expected.push(entry.file_name());
    }
    if fs::read_dir(copy)?.count() != expected.len() {
        return Err(mismatch(copy, "has extra entries"));
    }
    Ok(())
}

/// Compare two files byte for byte.
fn same_bytes(left: &Path, right: &Path) -> io::Result<bool> {
    let (mut left, mut right) = (File::open(left)?, File::open(right)?);
    if left.metadata()?.len() != right.metadata()?.len() {
        return Ok(false);
    }
    let (mut a, mut b) = (vec![0_u8; 64 * 1024], vec![0_u8; 64 * 1024]);
    loop {
        let read = left.read(&mut a)?;
        if read == 0 {
            return Ok(true);
        }
        right.read_exact(&mut b[..read])?;
        if a[..read] != b[..read] {
            return Ok(false);
        }
    }
}

/// Rename the old folder to `<name>.moved-<UTC time>` and make it read-only.
fn set_aside(from: &Path, now: SystemTime) -> io::Result<PathBuf> {
    let name = from
        .file_name()
        .ok_or_else(|| io::Error::other("the old folder has no name"))?
        .to_string_lossy()
        .into_owned();
    let stamp = utc_stamp(
        now.duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs()),
    );
    let mut leftover = from.with_file_name(format!("{name}.moved-{stamp}"));
    let mut attempt = 1;
    while fs::symlink_metadata(&leftover).is_ok() {
        attempt += 1;
        leftover = from.with_file_name(format!("{name}.moved-{stamp}-{attempt}"));
    }
    fs::rename(from, &leftover)?;
    sync_parent(&leftover);
    read_only(&leftover)?;
    Ok(leftover)
}

/// Remove every write bit in a tree, without following links.
fn read_only(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            read_only(&entry?.path())?;
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(metadata.mode() & 0o7555))
}

/// Write the marker naming `from` into `folder`, durably.
fn write_marker(folder: &Path, from: &Path) -> io::Result<()> {
    let path = folder.join(MARKER);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(from.as_os_str().as_encoded_bytes())?;
    file.sync_all()?;
    sync_dir(folder);
    Ok(())
}

/// The old folder an unfinished move into `folder` came from, if any.
fn read_marker(folder: &Path) -> Option<PathBuf> {
    let text = fs::read_to_string(folder.join(MARKER)).ok()?;
    let path = PathBuf::from(text.trim_end_matches('\n'));
    path.is_absolute().then_some(path)
}

/// Whether two paths are the same folder: equal, or resolving to the same place.
///
/// Prod's `/var/lib/infraternal` is already standard, and so is a path spelled
/// with a trailing slash or through a link to it.
fn same_folder(left: &Path, right: &Path) -> bool {
    if left.components().eq(right.components()) {
        return true;
    }
    matches!((fs::canonicalize(left), fs::canonicalize(right)), (Ok(a), Ok(b)) if a == b)
}

/// The closest ancestor of `path` (or itself) that exists.
fn nearest_existing(path: &Path) -> Option<&Path> {
    path.ancestors().find(|ancestor| ancestor.exists())
}

/// fsync a folder so a rename or new entry in it survives a crash; best effort.
fn sync_dir(path: &Path) {
    if let Ok(folder) = File::open(path) {
        let _ = folder.sync_all();
    }
}

/// fsync the folder that holds `path`.
fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        sync_dir(parent);
    }
}

/// `YYYYMMDD-HHMMSS` in UTC, from UNIX seconds (civil-from-days, no time crate).
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

/// Behaviour tests on real scratch installs; also holds the copy-path test hook.
#[cfg(test)]
#[path = "install_move_tests.rs"]
mod tests;
