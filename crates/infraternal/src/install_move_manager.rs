//! Give the service manager the complete cutover, from stopping the original
//! process to publishing a receipt for the checked destination. A client
//! disconnect cannot cancel the accepted manager job.

use super::*;
use crate::install::{self, MoveInstall};
use nix::fcntl::{Flock, FlockArg};
use std::process::ExitCode;

/// The private, durable input to the manager's recovery job.
const REQUEST: &str = "request.json";
/// The worker's last error or its verified outcome.
const RECEIPT: &str = "receipt.json";
/// The internal entry point used in the temporary service unit.
const COMMAND: &str = "__server-cutover";

/// Enough information to recover without the original CLI or its environment.
#[derive(Deserialize, Serialize)]
struct Request {
    /// The original admission, including the expected effective service.
    relocation: Relocation,
    /// The scope, listener and exact service that must become ready.
    service: Systemd,
    /// The firewall policy checked by the triggering invocation.
    install: MoveInstall,
    /// The temporary unit to remove after completion.
    worker: PathBuf,
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
    /// A recoverable transaction error from the worker.
    Error(String),
}

/// Publish the request and ask systemd to start it independently of this process.
pub(crate) fn trigger(
    relocation: &Relocation,
    service: Systemd,
    install: MoveInstall,
    name: &str,
) -> Result<Outcome, MoveError> {
    let result = (|| {
        let control = control_path(&relocation.to)?;
        let dir = Flock::lock(
            control_dir(&control, true)?,
            FlockArg::LockExclusiveNonblock,
        )
        .map_err(|(_, error)| io::Error::from(error))?;
        let worker = install::unit_path(service.user, &format!("infraternal-d395-{name}"))
            .map_err(io::Error::other)?;
        let request = Request {
            relocation: relocation.clone(),
            service,
            install,
            worker,
        };
        prepare(&dir, &control, &request)?;
        let worker = worker_name(&request)?;
        request.service.checked(&["enable", worker])?;
        let started = request.service.checked(&["start", worker]);
        let receipt = read::<Receipt>(&dir, RECEIPT)?;
        match receipt {
            Some(Receipt::Error(error)) => Err(io::Error::other(error)),
            Some(Receipt::Ready {
                outcome,
                target,
                database,
            }) => {
                started?;
                confirm_receipt(&request, target, database)?;
                if !request.worker.exists()
                    && let Err(error) = clear_receipt(&dir, &control)
                {
                    eprintln!("server cutover receipt cleanup: {error}");
                }
                Ok(outcome)
            }
            None => {
                started?;
                Err(disk::invalid("cutover ended without a receipt"))
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
        None if create => disk::make_dir(&parent, name)?,
        None => return Err(io::ErrorKind::NotFound.into()),
    };
    if dir.metadata()?.mode() & 0o077 != 0 {
        return Err(disk::invalid("cutover request directory is not private"));
    }
    Ok(dir)
}

/// Read optional control state without following links or accepting public files.
fn read<T: serde::de::DeserializeOwned>(dir: &File, name: &str) -> io::Result<Option<T>> {
    match disk::read(dir, OsStr::new(name), true) {
        Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The exact manager unit name for this request.
fn worker_name(request: &Request) -> io::Result<&str> {
    request
        .worker
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| disk::invalid("invalid cutover unit name"))
}

/// A server start also pulls in the worker after a manager restart or reboot.
/// They have independent ordering so the worker can synchronously manage the server.
fn unit_text(control: &Path, service: &str) -> io::Result<String> {
    let quote = |value: &OsStr| {
        install::quote_systemd(value)
            .map(|quoted| quoted.replace('%', "%%"))
            .map_err(io::Error::other)
    };
    let exe = quote(install::service_program()?.as_os_str())?;
    let control = quote(control.as_os_str())?;
    Ok(format!(
        "[Unit]\nDescription=infraternal server data cutover\n\
         [Service]\nType=oneshot\nExecStart=:{exe} {COMMAND} {control}\n\
         Restart=on-abnormal\nRestartSec=1s\nTimeoutStartSec=infinity\n\
         [Install]\nWantedBy={}\n",
        service
    ))
}

/// Publish only our own unit, and refuse to replace a different admitted request.
fn prepare(dir: &File, control: &Path, request: &Request) -> io::Result<()> {
    let bytes = unit_text(control, &request.service.service)?;
    let (units, name) = disk::parent(&request.worker, true)?;
    let existing = match disk::read(&units, name, false) {
        Ok(existing) if existing == bytes.as_bytes() => true,
        Ok(_) => return Err(disk::invalid("cutover unit path is already occupied")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    let previous = read::<Request>(dir, REQUEST)?;
    let completed = !existing
        && !pending(&request.relocation.to, &request.relocation.unit).map_err(io::Error::other)?
        && matches!(read::<Receipt>(dir, RECEIPT)?, Some(Receipt::Ready { .. }));
    if let Some(previous) = previous.filter(|_| !completed) {
        if previous.relocation.from != request.relocation.from
            || previous.relocation.to != request.relocation.to
            || previous.relocation.unit != request.relocation.unit
            || previous.worker != request.worker
            || serde_json::to_vec(&previous.service)? != serde_json::to_vec(&request.service)?
            || serde_json::to_vec(&previous.install)? != serde_json::to_vec(&request.install)?
        {
            return Err(disk::invalid(
                "a different cutover request is already pending",
            ));
        }
    } else {
        if completed {
            disk::unlink(dir, OsStr::new(RECEIPT), false)?;
        }
        disk::write_record(dir, OsStr::new(REQUEST), &serde_json::to_vec(request)?)?;
    }
    if !existing {
        disk::write_new(&units, name, bytes.as_bytes())?;
    }
    Ok(())
}

/// Retire a successful client's private control files after unregistering the job.
fn clear_receipt(dir: &File, control: &Path) -> io::Result<()> {
    let (parent, name) = disk::parent(control, false)?;
    if Identity::of(&disk::tree(&parent, name)?)? != Identity::of(dir)? {
        return Err(disk::invalid("cutover directory changed"));
    }
    disk::unlink(dir, OsStr::new(REQUEST), false)?;
    disk::unlink(dir, OsStr::new(RECEIPT), false)?;
    disk::unlink(&parent, name, true)
}

/// Check for a persisted manager request before allowing explicit reconfiguration.
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

/// The worker's only inputs are the private request and the current journal.
pub(crate) fn run_if_requested() -> Option<ExitCode> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next()?.as_os_str() != COMMAND {
        return None;
    }
    let result = (|| {
        let control = PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| disk::invalid("missing cutover request path"))?,
        );
        if arguments.next().is_some() {
            return Err(disk::invalid("unexpected cutover argument"));
        }
        let dir = control_dir(&control, false)?;
        let request = read::<Request>(&dir, REQUEST)?
            .ok_or_else(|| disk::invalid("missing cutover request"))?;
        if control != control_path(&request.relocation.to)? {
            return Err(disk::invalid("cutover request path changed"));
        }
        run(&dir, &control, &request)
    })();
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("server cutover: {error}");
            ExitCode::FAILURE
        }
    })
}

/// Resume from the durable journal, then unregister the completed worker.
fn run(dir: &File, control: &Path, request: &Request) -> io::Result<()> {
    let plan = &request.relocation;
    let result = (|| {
        if !pending(&plan.to, &plan.unit).map_err(io::Error::other)?
            && let Some(Receipt::Ready {
                target, database, ..
            }) = read(dir, RECEIPT)?
        {
            confirm_receipt(request, target, database)?;
            return Ok(());
        }
        apply_recorded(
            plan,
            &request.service,
            SystemTime::now(),
            || request.install.publish(),
            |journal, outcome| {
                let ready = Receipt::Ready {
                    outcome: Outcome {
                        leftover: outcome.leftover.clone(),
                    },
                    target: journal
                        .target
                        .ok_or_else(|| disk::invalid("missing destination identity"))?,
                    database: journal
                        .database
                        .ok_or_else(|| disk::invalid("missing database identity"))?,
                };
                disk::write_record(dir, OsStr::new(RECEIPT), &serde_json::to_vec(&ready)?)
            },
        )
        .map_err(io::Error::other)?;
        Ok::<(), io::Error>(())
    })();
    if let Err(error) = result {
        let receipt = Receipt::Error(error.to_string());
        disk::write_record(dir, OsStr::new(RECEIPT), &serde_json::to_vec(&receipt)?)?;
        return Err(error);
    }

    // A failed unregister leaves a harmless recovery hook. The completed
    // receipt lets it check readiness again without touching either tree.
    if let Err(error) = unregister(control, request) {
        eprintln!("server cutover unit cleanup: {error}");
    }
    Ok(())
}

/// Remove the one owned unit and its server-start link after a successful move.
fn unregister(control: &Path, request: &Request) -> io::Result<()> {
    let (units, name) = disk::parent(&request.worker, false)?;
    if disk::read(&units, name, false)? != unit_text(control, &request.service.service)?.as_bytes()
    {
        return Err(disk::invalid("cutover unit changed"));
    }
    request
        .service
        .checked(&["disable", worker_name(request)?])?;
    disk::unlink(&units, name, false)
}

/// Revalidate a finished receipt before reporting success to a client or boot.
fn confirm_receipt(request: &Request, target: Identity, database: Identity) -> io::Result<()> {
    let (parent, name) = disk::parent(&request.relocation.to, false)?;
    let data = disk::tree(&parent, name)?;
    if Identity::of(&data)? != target || database_identity(&data)? != database {
        return Err(disk::invalid(
            "cutover receipt no longer matches destination",
        ));
    }
    request.service.ready(&data)
}

/// Check the durable link from the server to its independently ordered worker.
#[cfg(test)]
#[test]
#[ignore = "Run in a disposable user namespace"]
fn d395_server_start_pulls_in_cutover_worker() {
    let control = Path::new("/run/D395 move %n $HOME");
    let unit = unit_text(control, "infraternal-server.service").unwrap();
    assert!(unit.contains("Type=oneshot\n"));
    assert!(unit.contains("Restart=on-abnormal\n"));
    assert!(unit.contains("WantedBy=infraternal-server.service\n"));
    assert!(unit.lines().any(|line| {
        line.starts_with("ExecStart=:")
            && line.ends_with("__server-cutover \"/run/D395 move %%n $HOME\"")
    }));
}
