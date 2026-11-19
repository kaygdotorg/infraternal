//! Put recovery and readiness inside the server's systemd start job. A start
//! can finish without the installer client, and no hook submits a second job
//! to stop or start the server it is running for.

use super::{
    MoveError, Outcome, Relocation, Service, Systemd, current_side, database_identity, disk,
    exec_assignment, finish, live_data, optional_tree, pending, read_units, remove_journal, save,
    selected_target, stage_start, with_journal,
};
use crate::install::{self, MoveInstall};
use disk::Identity;
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::ExitCode,
    time::SystemTime,
};

/// The private, durable input to recovery.
const REQUEST: &str = "request.json";
/// The last recovery error or the verified outcome.
const RECEIPT: &str = "receipt.json";
/// The installer-owned drop-in in the server unit's own directory.
const HOOK: &str = "zz-infraternal-d395.conf";
/// Prepare the data and unit before systemd starts the server process.
const PRE: &str = "__server-cutover-pre";
/// Verify readiness and finish retirement before systemd reports success.
const POST: &str = "__server-cutover-post";

/// Enough information to recover without the original CLI or its environment.
#[derive(Deserialize, Serialize)]
struct Request {
    /// The original admission, including the expected effective service.
    relocation: Relocation,
    /// The scope, listener and exact service that must become ready.
    service: Systemd,
    /// The firewall policy checked by the triggering invocation.
    install: MoveInstall,
}

/// The persisted result is read by the client and can survive a manager restart.
#[derive(Deserialize, Serialize)]
enum Receipt {
    /// The result and the exact directory and database it applies to.
    Ready {
        /// The dated backup, if retained.
        outcome: Outcome,
        /// Directory opened by the verified server.
        target: Identity,
        /// SQLite file opened by the verified server.
        database: Identity,
    },
    /// A recoverable transaction error.
    Error(String),
}

/// Install the recovery hook before admitting a move, then join the server start.
pub(crate) fn trigger(
    relocation: &Relocation,
    service: Systemd,
    install: MoveInstall,
) -> Result<Outcome, MoveError> {
    let result = (|| {
        let control = control_path(&relocation.to)?;
        let request = Request {
            relocation: relocation.clone(),
            service,
            install,
        };
        admit(&control, &request)?;
        let started = request
            .service
            .checked(&["start", &request.service.service]);
        let dir = control_dir(&control, false)?;
        match read::<Receipt>(&dir, RECEIPT)? {
            Some(Receipt::Error(error)) => Err(io::Error::other(error)),
            Some(Receipt::Ready {
                outcome,
                target,
                database,
            }) => {
                started?;
                confirm_receipt(&request, target, database)?;
                Ok(outcome)
            }
            None => {
                started?;
                Err(disk::invalid(
                    "server start ended without a cutover receipt",
                ))
            }
        }
    })();
    result.map_err(|error| MoveError::io("moving data to", &relocation.to, &error))
}

/// Keep the request in a directory separate from the snapshot and its journal.
fn control_path(to: &Path) -> io::Result<PathBuf> {
    let target = to
        .file_name()
        .ok_or_else(|| disk::invalid("target lacks a name"))?;
    let mut name = OsString::from(".");
    name.push(target);
    name.push(".cutover");
    Ok(to.with_file_name(name))
}

/// Open a descriptor-owned private control directory, creating it for admission only.
fn control_dir(control: &Path, create: bool) -> io::Result<File> {
    let (parent, name) = disk::parent(control, create)?;
    let dir = match optional_tree(&parent, name)? {
        Some(dir) => dir,
        None if create => match disk::make_dir(&parent, name) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                disk::tree(&parent, name)?
            }
            result => result?,
        },
        None => return Err(io::ErrorKind::NotFound.into()),
    };
    if dir.metadata()?.mode() & 0o077 != 0 {
        return Err(disk::invalid("cutover request directory is not private"));
    }
    Ok(dir)
}

/// Serialize request publication and each hook's view of the request.
fn lock(dir: File) -> io::Result<Flock<File>> {
    Flock::lock(dir, FlockArg::LockExclusive).map_err(|(_, error)| io::Error::from(error))
}

/// Read optional control state without following links or accepting public files.
fn read<T: serde::de::DeserializeOwned>(dir: &File, name: &str) -> io::Result<Option<T>> {
    match disk::read(dir, OsStr::new(name), true) {
        Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Keep the hook beside the base unit whose data paths the journal protects.
fn hook_path(unit: &Path) -> io::Result<PathBuf> {
    let mut folder = unit
        .file_name()
        .ok_or_else(|| disk::invalid("missing service unit name"))?
        .to_owned();
    folder.push(".d");
    Ok(unit.with_file_name(folder).join(HOOK))
}

/// Quote the executable and the private request path as literal systemd arguments.
fn hook_text(control: &Path) -> io::Result<String> {
    let quote = |value: &OsStr| {
        install::quote_systemd(value)
            .map(|quoted| quoted.replace('%', "%%"))
            .map_err(io::Error::other)
    };
    let exe = quote(install::service_program()?.as_os_str())?;
    let control = quote(control.as_os_str())?;
    Ok(format!(
        "[Service]\nExecStartPre=:{exe} {PRE} {control}\nExecStartPost=:{exe} {POST} {control}\n\
         TimeoutStartSec=infinity\n"
    ))
}

/// Exclude only our exact recovery hook from the tracked configuration rewrites.
pub(super) fn is_recovery_hook(name: &OsStr, text: &str, to: &Path) -> io::Result<bool> {
    Ok(name == HOOK && text == hook_text(&control_path(to)?)?)
}

/// Prove the manager loaded both commands before a request can reach disk.
fn install_hook(control: &Path, request: &Request) -> io::Result<()> {
    let hook = hook_path(&request.relocation.unit)?;
    let bytes = hook_text(control)?;
    let (units, name) = disk::parent(&hook, true)?;
    match disk::read(&units, name, false) {
        Ok(existing) if existing == bytes.as_bytes() => units.sync_all()?,
        Ok(_) => return Err(disk::invalid("cutover hook path is already occupied")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            disk::write_new(&units, name, bytes.as_bytes())?;
        }
        Err(error) => return Err(error),
    }
    let service = &request.service;
    service.checked(&["daemon-reload"])?;
    for (property, command) in [("ExecStartPre", PRE), ("ExecStartPost", POST)] {
        let output = service.systemctl(&["show", "-p", property, "--value", &service.service])?;
        if !output.status.success()
            || !String::from_utf8_lossy(&output.stdout).contains(&format!(" {command} "))
        {
            return Err(disk::invalid("systemd did not load the cutover hook"));
        }
    }
    Ok(())
}

/// Compare the immutable inputs while allowing a retry to rediscover journal state.
fn same_request(old: &Request, new: &Request) -> io::Result<bool> {
    Ok(old.relocation.from == new.relocation.from
        && old.relocation.to == new.relocation.to
        && old.relocation.unit == new.relocation.unit
        && serde_json::to_vec(&old.service)? == serde_json::to_vec(&new.service)?
        && serde_json::to_vec(&old.install)? == serde_json::to_vec(&new.install)?)
}

/// A completed receipt can answer a racing client only while its unit still
/// selects that completed move's destination.
fn destination_is_selected(request: &Request) -> io::Result<bool> {
    let plan = &request.relocation;
    let units = read_units(&plan.unit, &plan.to)?;
    Ok(units
        .iter()
        .rev()
        .find(|(_, text)| exec_assignment(text).is_some())
        .and_then(|(_, text)| live_data(text))
        .as_deref()
        == Some(plan.to.as_path()))
}

/// Stop any pre-admission start, then publish while later starts wait at the hook.
fn admit(control: &Path, request: &Request) -> io::Result<()> {
    let dir = lock(control_dir(control, true)?)?;
    let receipt = read::<Receipt>(&dir, RECEIPT)?;
    if let Some(previous) = read::<Request>(&dir, REQUEST)? {
        let completed =
            !journal_pending(&previous)? && matches!(&receipt, Some(Receipt::Ready { .. }));
        if !completed {
            if !same_request(&previous, request)? {
                return Err(disk::invalid(
                    "a different cutover request is already pending",
                ));
            }
            return install_hook(control, request);
        }
        if destination_is_selected(request)? {
            if same_request(&previous, request)? {
                return Ok(());
            }
            return Err(disk::invalid(
                "the service changed after move confirmation; run init again",
            ));
        }
        disk::unlink(&dir, OsStr::new(REQUEST), false)?;
    }
    // A crash may have removed the completed request before its receipt.
    if receipt.is_some() {
        disk::unlink(&dir, OsStr::new(RECEIPT), false)?;
    }
    install_hook(control, request)?;
    request
        .service
        .checked(&["stop", &request.service.service])?;
    disk::write_record(&dir, OsStr::new(REQUEST), &serde_json::to_vec(request)?)
}

/// Check for an unfinished move before allowing explicit reconfiguration.
pub(crate) fn requested(to: &Path) -> Result<bool, MoveError> {
    let result = (|| {
        let control = control_path(to)?;
        let dir = match control_dir(&control, false) {
            Ok(dir) => dir,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        Ok(read::<Request>(&dir, REQUEST)?.is_some()
            && !matches!(read::<Receipt>(&dir, RECEIPT)?, Some(Receipt::Ready { .. })))
    })();
    result.map_err(|error| MoveError::io("checking cutover request for", to, &error))
}

/// Dispatch systemd's pre-start and post-start hooks, with no recursive start.
pub(crate) fn run_if_requested() -> Option<ExitCode> {
    let mut arguments = std::env::args_os().skip(1);
    let command = arguments.next()?;
    let run = match command.to_str()? {
        PRE => prepare_start,
        POST => complete_start,
        _ => return None,
    };
    let result = (|| {
        let control = PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| disk::invalid("missing cutover request path"))?,
        );
        if arguments.next().is_some() {
            return Err(disk::invalid("unexpected cutover argument"));
        }
        run_hook(&control, run)
    })();
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("server cutover: {error}");
            ExitCode::FAILURE
        }
    })
}

/// Run only for an admitted request. An installed hook alone leaves startup alone.
fn run_hook(control: &Path, run: impl FnOnce(&File, &Request) -> io::Result<()>) -> io::Result<()> {
    let dir = lock(control_dir(control, false)?)?;
    let Some(request) = read::<Request>(&dir, REQUEST)? else {
        return Ok(());
    };
    if control != control_path(&request.relocation.to)? {
        return Err(disk::invalid("cutover request path changed"));
    }
    if !journal_pending(&request)?
        && matches!(read::<Receipt>(&dir, RECEIPT)?, Some(Receipt::Ready { .. }))
    {
        return Ok(());
    }
    if let Err(error) = run(&dir, &request) {
        let receipt = Receipt::Error(error.to_string());
        disk::write_record(&dir, OsStr::new(RECEIPT), &serde_json::to_vec(&receipt)?)?;
        return Err(error);
    }
    Ok(())
}

/// The receipt is complete only once the journal has been removed.
fn journal_pending(request: &Request) -> io::Result<bool> {
    pending(&request.relocation.to, &request.relocation.unit).map_err(io::Error::other)
}

/// Commit the effective unit and reload it before systemd advances to `ExecStart`.
fn prepare_start(_dir: &File, request: &Request) -> io::Result<()> {
    with_journal(
        &request.relocation,
        SystemTime::now(),
        || Ok(false),
        |transaction, journal| {
            let switched = current_side(journal, &read_units(&journal.unit, &journal.to)?)?;
            if journal.ready {
                selected_target(transaction.parent, transaction.target_name, journal)?;
            } else {
                stage_start(transaction, journal, switched, &request.service, || {
                    request.install.publish()
                })?;
            }
            request.service.checked(&["daemon-reload"])
        },
    )
}

/// Complete the journal within `ExecStartPost`, before systemd can report success.
fn complete_start(dir: &File, request: &Request) -> io::Result<()> {
    let plan = &request.relocation;
    if !journal_pending(request)? {
        return Err(disk::invalid("server started without a cutover journal"));
    }
    with_journal(
        plan,
        SystemTime::now(),
        || Ok(false),
        |transaction, journal| {
            if !current_side(journal, &read_units(&journal.unit, &journal.to)?)? {
                return Err(disk::invalid(
                    "the unit did not switch to the moved database",
                ));
            }
            let target = selected_target(transaction.parent, transaction.target_name, journal)?;
            request.service.ready(&journal.to, &target)?;
            request
                .service
                .checked(&["enable", "--no-reload", &request.service.service])?;
            journal.ready = true;
            save(transaction.work, journal)?;
            let outcome = finish(
                transaction.old_parent,
                transaction.old_name,
                journal,
                &request.service,
            )?;
            let receipt = Receipt::Ready {
                outcome,
                target: journal
                    .target
                    .ok_or_else(|| disk::invalid("missing destination identity"))?,
                database: journal
                    .database
                    .ok_or_else(|| disk::invalid("missing database identity"))?,
            };
            disk::write_record(dir, OsStr::new(RECEIPT), &serde_json::to_vec(&receipt)?)?;
            remove_journal(transaction.parent, transaction.work_name, transaction.work)?;
            Ok(())
        },
    )?;
    if let Err(error) = unregister(request) {
        eprintln!("server cutover hook cleanup: {error}");
    }
    Ok(())
}

/// Remove the exact drop-in. Any cached hooks are inert after the durable receipt.
fn unregister(request: &Request) -> io::Result<()> {
    let hook = hook_path(&request.relocation.unit)?;
    let (units, name) = disk::parent(&hook, false)?;
    if !is_recovery_hook(
        name,
        &String::from_utf8(disk::read(&units, name, false)?).map_err(io::Error::other)?,
        &request.relocation.to,
    )? {
        return Err(disk::invalid("cutover hook changed"));
    }
    disk::unlink(&units, name, false)
}

/// Verify the successful receipt before telling the installer client it finished.
fn confirm_receipt(request: &Request, target: Identity, database: Identity) -> io::Result<()> {
    let (parent, name) = disk::parent(&request.relocation.to, false)?;
    let data = disk::tree(&parent, name)?;
    if Identity::of(&data)? != target || database_identity(&data)? != database {
        return Err(disk::invalid(
            "cutover receipt no longer matches destination",
        ));
    }
    request.service.ready(&request.relocation.to, &data)
}

/// Both commands belong to the unit's startup and receive the literal control path.
#[cfg(test)]
#[test]
fn d395_recovery_and_readiness_are_in_the_server_start_job() {
    let unit = hook_text(Path::new("/run/D395 move %n $HOME")).unwrap();
    for (property, command) in [("ExecStartPre", PRE), ("ExecStartPost", POST)] {
        assert!(unit.lines().any(|line| {
            line.starts_with(&format!("{property}=:"))
                && line.ends_with(&format!("{command} \"/run/D395 move %%n $HOME\""))
        }));
    }
}
