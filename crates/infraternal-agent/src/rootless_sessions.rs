//! Durable person-to-terminal ownership for inherited rootless host logins [D18,D240,D247].
//!
//! Records precede spawn under the person lock. Cleanup authenticates each shim
//! and waits for shell-reaping proof; a missing socket alone never proves exit.
#![forbid(unsafe_code)]

use crate::sessions::{self, Manager, Reader, Session};
use infraternal_shim::frame::{Frame, SHELL_CLEANUP};
#[cfg(target_os = "linux")]
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
use std::{
    fs::{self, File},
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

/// An unsuccessful spawn removes its reservation; after spawn the record must
/// survive cancellation, so a later revocation can find the detached shim.
#[cfg(target_os = "linux")]
pub(crate) struct Reservation {
    /// A failed or cancelled launch removes its unconsumed reservation first.
    path: Option<PathBuf>,
    /// Release the person fence only after the record cleanup above.
    _person: crate::logins::PersonGuard,
}
#[cfg(target_os = "linux")]
impl Reservation {
    /// The shim has started: the record must now survive this reservation. Returns its path so a
    /// launch that later fails can retire it once the terminal is proven stopped.
    pub(crate) fn spawned(&mut self) -> Option<PathBuf> {
        self.path.take()
    }
}
#[cfg(target_os = "linux")]
impl Drop for Reservation {
    /// Remove an unconsumed record before the owned person fence is released.
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

/// Reserve ownership durably before spawn, without occupying the host reactor.
/// The returned reservation owns the launch fence. Cancellation releases an
/// unstarted job's fence; an executing write retains it through record cleanup.
#[cfg(target_os = "linux")]
pub(crate) async fn reserve(
    state: &Path,
    person: uuid::Uuid,
    id: uuid::Uuid,
    person_guard: crate::logins::PersonGuard,
) -> io::Result<Reservation> {
    let admission = crate::durable_io::admit()?;
    let state = state.to_owned();
    admission
        .run(move || {
            let directory = state.join("infraternal-login-locks");
            let path = directory.join(format!("{}-{}.terminal", person.simple(), id.simple()));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(&path)?;
            let reservation = Reservation {
                path: Some(path),
                _person: person_guard,
            };
            #[cfg(test)]
            crate::durable_tests::hold(&state);
            file.sync_all()?;
            File::open(directory)?.sync_all()?;
            Ok(reservation)
        })
        .await?
        .0
}

/// Carry one person's fence through durable reservation, spawn and readiness.
#[cold]
pub(crate) async fn launch(
    exe: &Path,
    state: &Path,
    manager: Manager,
    person: uuid::Uuid,
    uid: u32,
    cols: u16,
    rows: u16,
) -> io::Result<Session> {
    let person_guard = crate::logins::rootless_launch_guard(state, person).await?;
    sessions::launch_rootless_person(exe, state, manager, uid, cols, rows, person, person_guard)
        .await
}

/// Clean up the person's shells (each stop step hang-bounded), then await
/// directory durability.
/// A supplied person fence stays owned until the blocking sync finishes, including
/// when the caller is cancelled; a busy disk delays only this operation's reply.
/// Admission is retained from marker publication so cleanup never needs another
/// queue slot. Once cleanup starts, its bounded task finishes the directory sync.
#[cold]
pub(crate) async fn revoke(
    state: &Path,
    person: uuid::Uuid,
    person_guard: Option<crate::logins::PersonGuard>,
    admission: crate::durable_io::Admission,
) -> io::Result<()> {
    let state = state.to_owned();
    tokio::spawn(async move {
        // No clock covers the whole cleanup: each shell stop bounds its own
        // progress steps (`stop`, `STOP_STEP_HANG`). A whole-cleanup deadline
        // failed revocations on a slow host while the shim was still working
        // (#355). The shim runs as the infraternal agent's own account (D18),
        // so its silence is a hang, not a hostile peer.
        let failure = cleanup(&state, person).await?;
        admission
            .run(move || {
                let _person = person_guard;
                #[cfg(test)]
                crate::durable_tests::hold(&state);
                File::open(state.join("infraternal-login-locks"))?.sync_all()?;
                failure.map_or(Ok(()), Err)
            })
            .await?
            .0
    })
    .await
    .map_err(io::Error::other)?
}

/// Authenticate and reap attributable shells, retaining cleanup failures.
#[cold]
async fn cleanup(state: &Path, person: uuid::Uuid) -> io::Result<Option<io::Error>> {
    let directory = state.join("infraternal-login-locks");
    let prefix = format!("{}-", person.simple());
    // Older inherited-account shims have no person record. Never acknowledge
    // cleanup while an unattributable terminal could belong to this person;
    // account-wide termination would also stop unrelated people.
    let owned = fs::read_dir(&directory)?
        .map(|entry| {
            let name = entry?.file_name();
            Ok(name
                .to_str()
                .and_then(|name| name.strip_suffix(".terminal"))
                .and_then(|name| name.rsplit_once('-'))
                .and_then(|(_, id)| uuid::Uuid::parse_str(id).ok()))
        })
        .collect::<io::Result<Vec<_>>>()?;
    let mut failure = None;
    for entry in fs::read_dir(state.join("sessions"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "sock") {
            let id = path
                .file_stem()
                .and_then(|name| name.to_str())
                .and_then(|name| uuid::Uuid::parse_str(name).ok());
            // A retiring shim releases attribution after sealing descendant
            // cleanup, before its socket guard unlinks the rendezvous.
            if id.is_none()
                || (!owned.contains(&id)
                    && infraternal_shim::ended::read(&path)?.is_none()
                    && !private_readiness(&path)?)
            {
                failure = Some(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "existing host login path has no person ownership record",
                ));
            }
        }
    }
    for entry in fs::read_dir(&directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id) = name
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(".terminal"))
        else {
            continue;
        };
        let id = uuid::Uuid::parse_str(id).map_err(io::Error::other)?;
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe person terminal record",
            ));
        }
        let path = sessions::rendezvous(state, id.into_bytes());
        match stop(path.clone(), id.into_bytes()).await {
            // Keep ownership while a viewer retains the ended shim: retrying
            // revocation must not mistake that same socket for an old terminal.
            Ok(()) if !path.exists() => match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            },
            Ok(()) => {}
            Err(error) => failure = Some(error),
        }
    }
    Ok(failure)
}

#[cold]
fn private_readiness(path: &Path) -> io::Result<bool> {
    // Only a fixed probe publishes this marker. Never infer a person-terminal
    // exemption from a missing ownership record or an unsafe runtime file.
    let metadata = match fs::symlink_metadata(path.with_extension("readiness")) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(metadata.is_file()
        && metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.mode() & 0o7777 == 0o600
        && metadata.len() == 0)
}

/// Hang guard for each step of stopping one person's shell (D352 principle,
/// #355). It only detects a stuck shim, or a shell that cannot die (for
/// example one in uninterruptible sleep), and then this revocation attempt
/// fails. The person stays denied and the revocation owner retries
/// (`logins::revocations`), but the shell keeps running until an attempt
/// succeeds, so a slow but progressing host must not fail one.
const STOP_STEP_HANG: Duration = Duration::from_secs(60);

/// Runs one step of a shell stop under [`STOP_STEP_HANG`]; `what` names the
/// step in the timeout error.
async fn step<T>(
    what: &'static str,
    work: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(STOP_STEP_HANG, work)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, what))?
}

/// Stops the shell of the session whose rendezvous socket is `path`, and
/// returns only after the shim has proved the shell is gone.
///
/// The shim does the work: on the stop request it kills the shell, waits for
/// its exit, reaps it and retires adopted descendants, and only then writes
/// its proof (its Hello followed by `ShellStopped`). This side bounds each step
/// it can observe separately: connecting, delivering the request, and each
/// part of the proof. No clock covers the whole stop. A sealed exit record is
/// already proof; refusal, a missing rendezvous, an unsupported capability or
/// a step that hangs fail honestly.
async fn stop(path: PathBuf, id: [u8; 16]) -> io::Result<()> {
    if infraternal_shim::ended::read(&path)?.is_some() {
        return Ok(());
    }
    match step(
        "connect to the shell stop endpoint",
        tokio::net::UnixStream::connect(path.with_extension("stop")),
    )
    .await
    {
        Ok(mut peer) => {
            // This private endpoint has no ordinary link, decoder quota or
            // owner limit. Authenticate before requesting retirement.
            let credentials = peer.peer_cred()?;
            if credentials.uid() != 0 && credentials.uid() != nix::unistd::Uid::effective().as_raw()
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            step(
                "deliver the shell stop request",
                tokio::io::AsyncWriteExt::write_all(&mut peer, b"!"),
            )
            .await?;
            let mut reader = Reader::default();
            let hello = step("receive the shell stop proof", reader.read(&mut peer)).await?;
            if !matches!(hello, Frame::Hello {
                version: 1, caps: SHELL_CLEANUP, session, pid, ..
            } if session == id && i32::try_from(pid).ok() == credentials.pid())
            {
                return Err(io::Error::other("host login cleanup identity differs"));
            }
            if step("receive shell stop confirmation", reader.read(&mut peer)).await?
                != Frame::ShellStopped
            {
                return Err(io::Error::other(
                    "host login path did not confirm shell cleanup",
                ));
            }
            return Ok(());
        }
        Err(error) if sessions::gone(&error) => {}
        Err(error) => return Err(error),
    }
    // Older surviving shims retain the negotiated cleanup capability path. Failure at
    // their ordinary capacity remains an honest refusal, never exit proof.
    let mut session = step(
        "connect to the older shim",
        sessions::connect_with(path.clone(), id, SHELL_CLEANUP),
    )
    .await?;
    if session.caps != SHELL_CLEANUP {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host login path cannot confirm shell cleanup",
        ));
    }
    step(
        "deliver the shell stop request",
        sessions::send(&mut session.peer, &Frame::StopShell),
    )
    .await?;
    if step(
        "receive shell stop confirmation",
        Reader::default().read(&mut session.peer),
    )
    .await?
        != Frame::ShellStopped
    {
        return Err(io::Error::other(
            "host login path did not confirm shell cleanup",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Cleanup refuses unsupported or unconfirmed peers without inventing exit proof.
    use super::*;

    /// A private state root with one recorded terminal of `person` and a fake
    /// shim stop endpoint for it. Returns the root, the endpoint listener and
    /// the terminal id.
    fn revocation_fixture(person: uuid::Uuid) -> (PathBuf, tokio::net::UnixListener, [u8; 16]) {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/real-logins")
            .join(format!(
                "v{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ));
        for directory in ["sessions", "infraternal-login-locks"] {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(root.join(directory))
                .unwrap();
        }
        let id = uuid::Uuid::new_v4();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("infraternal-login-locks").join(format!(
                "{}-{}.terminal",
                person.simple(),
                id.simple()
            )))
            .unwrap();
        let endpoint = sessions::rendezvous(&root, id.into_bytes()).with_extension("stop");
        let listener = tokio::net::UnixListener::bind(endpoint).unwrap();
        (root, listener, id.into_bytes())
    }

    /// A slow but progressing shell stop still revokes access. The fake shim
    /// sends its stop proof 8 s after the request, as a loaded host can: past
    /// the former 3 s stop deadline and the former 5 s whole-revoke deadline,
    /// both of which refused the revocation and left access in place (#355).
    /// Paused tokio time makes the schedule exact and the test instant.
    #[tokio::test(start_paused = true)]
    async fn slow_but_progressing_shell_stop_still_revokes() {
        if nix::unistd::Uid::effective().is_root() {
            return; // Root uses the login-unit path, not rootless records.
        }
        let person = uuid::Uuid::new_v4();
        let (root, listener, id) = revocation_fixture(person);
        let shim = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut request = [0];
            tokio::io::AsyncReadExt::read_exact(&mut peer, &mut request)
                .await
                .unwrap();
            assert_eq!(&request, b"!");
            // sleep: simulates a slow shim (virtual under paused tokio time).
            tokio::time::sleep(Duration::from_secs(8)).await;
            let hello = Frame::Hello {
                version: 1,
                caps: SHELL_CLEANUP,
                session: id,
                pid: std::process::id(),
                cols: 80,
                rows: 24,
                created: 0,
                head: 0,
                start: 0,
            };
            sessions::send(&mut peer, &hello).await.unwrap();
            sessions::send(&mut peer, &Frame::ShellStopped)
                .await
                .unwrap();
        });
        let revoked = crate::logins::revoke(&root, Manager::Detached, person).await;
        shim.await.unwrap();
        fs::remove_dir_all(&root).unwrap();
        revoked.unwrap();
    }

    /// A shell that never dies still ends in the refusal path: the fake shim
    /// takes the stop request and never proves the shell gone, so revocation
    /// fails at the step's hang bound instead of acknowledging cleanup.
    #[tokio::test(start_paused = true)]
    async fn shell_that_never_stops_still_refuses_revocation() {
        if nix::unistd::Uid::effective().is_root() {
            return;
        }
        let person = uuid::Uuid::new_v4();
        let (root, listener, _) = revocation_fixture(person);
        let shim = tokio::spawn(async move {
            let (peer, _) = listener.accept().await.unwrap();
            let _held = peer;
            std::future::pending::<()>().await;
        });
        let revoked = crate::logins::revoke(&root, Manager::Detached, person).await;
        shim.abort();
        fs::remove_dir_all(&root).unwrap();
        assert_eq!(revoked.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn dedicated_cleanup_requires_bound_identity_and_reaping_proof() {
        for case in 0..5 {
            let root = PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache/codex-scratch/real-logins")
                .join(format!(
                    "s{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..12]
                ));
            fs::create_dir_all(&root).unwrap();
            let path = root.join("shim.sock");
            let id = uuid::Uuid::new_v4().into_bytes();
            let listener = tokio::net::UnixListener::bind(path.with_extension("stop")).unwrap();
            let server = tokio::spawn(async move {
                let (mut peer, _) = listener.accept().await.unwrap();
                let mut request = [0];
                tokio::io::AsyncReadExt::read_exact(&mut peer, &mut request)
                    .await
                    .unwrap();
                assert_eq!(&request, b"!");
                sessions::send(
                    &mut peer,
                    &Frame::Hello {
                        version: 1,
                        caps: if case == 0 { 0 } else { SHELL_CLEANUP },
                        session: if case == 1 { [0; 16] } else { id },
                        pid: std::process::id() + u32::from(case == 2),
                        cols: 80,
                        rows: 24,
                        created: 0,
                        head: 0,
                        start: 0,
                    },
                )
                .await
                .unwrap();
                // Invalid identity can close before the second send. A valid
                // greeting alone must still never stand in for reaping proof.
                let _ = sessions::send(
                    &mut peer,
                    &if case == 3 {
                        Frame::Exited(0, 0)
                    } else {
                        Frame::ShellStopped
                    },
                )
                .await;
            });
            assert_eq!(stop(path, id).await.is_ok(), case == 4);
            server.await.unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn unsupported_or_wrong_reply_never_confirms_cleanup() {
        for caps in [0, SHELL_CLEANUP] {
            let root = PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache/codex-scratch/real-logins")
                .join(format!(
                    "s{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..12]
                ));
            fs::create_dir_all(&root).unwrap();
            let path = root.join("shim.sock");
            let id = uuid::Uuid::new_v4().into_bytes();
            let listener = tokio::net::UnixListener::bind(&path).unwrap();
            let server = tokio::spawn(async move {
                let (mut peer, _) = listener.accept().await.unwrap();
                sessions::send(
                    &mut peer,
                    &Frame::Hello {
                        version: 1,
                        caps,
                        session: id,
                        pid: std::process::id(),
                        cols: 80,
                        rows: 24,
                        created: 0,
                        head: 0,
                        start: 0,
                    },
                )
                .await
                .unwrap();
                let mut reader = Reader::default();
                assert_eq!(reader.read(&mut peer).await.unwrap(), Frame::Attach(caps));
                if caps != 0 {
                    assert_eq!(reader.read(&mut peer).await.unwrap(), Frame::StopShell);
                    sessions::send(&mut peer, &Frame::Exited(0, 0))
                        .await
                        .unwrap();
                }
            });
            assert!(stop(path, id).await.is_err());
            server.await.unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    /// An unattributed terminal must prevent a successful person cleanup reply.
    #[tokio::test]
    async fn unattributed_older_terminal_never_confirms_person_cleanup() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/real-logins")
            .join(format!(
                "s{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ));
        fs::create_dir_all(root.join("sessions")).unwrap();
        fs::create_dir(root.join("infraternal-login-locks")).unwrap();
        let path = sessions::rendezvous(&root, uuid::Uuid::new_v4().into_bytes());
        let _listener = tokio::net::UnixListener::bind(path).unwrap();
        assert_eq!(
            revoke(
                &root,
                uuid::Uuid::new_v4(),
                None,
                crate::durable_io::admit().unwrap()
            )
            .await
            .unwrap_err()
            .kind(),
            io::ErrorKind::Unsupported
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// Only a trusted, private readiness record exempts an otherwise unattributed terminal.
    #[tokio::test]
    async fn only_private_empty_readiness_markers_exempt_unattributed_sockets() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/rl12")
            .join(format!(
                "s{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ));
        fs::create_dir_all(root.join("sessions")).unwrap();
        fs::create_dir(root.join("infraternal-login-locks")).unwrap();
        let path = sessions::rendezvous(&root, uuid::Uuid::new_v4().into_bytes());
        let _listener = tokio::net::UnixListener::bind(&path).unwrap();
        let marker = path.with_extension("readiness");
        let person = uuid::Uuid::new_v4();
        assert!(
            revoke(&root, person, None, crate::durable_io::admit().unwrap())
                .await
                .is_err()
        );
        fs::write(&marker, []).unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            revoke(&root, person, None, crate::durable_io::admit().unwrap())
                .await
                .is_ok()
        );
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            revoke(&root, person, None, crate::durable_io::admit().unwrap())
                .await
                .is_err()
        );
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&marker, b"invalid").unwrap();
        assert!(
            revoke(&root, person, None, crate::durable_io::admit().unwrap())
                .await
                .is_err()
        );
        fs::remove_file(&marker).unwrap();
        fs::create_dir(&marker).unwrap();
        assert!(
            revoke(&root, person, None, crate::durable_io::admit().unwrap())
                .await
                .is_err()
        );
        fs::remove_dir(&marker).unwrap();
        symlink("/dev/null", &marker).unwrap();
        assert!(
            revoke(&root, person, None, crate::durable_io::admit().unwrap())
                .await
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn stale_probe_discovery_removes_its_readiness_marker() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/rl12")
            .join(format!(
                "s{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            ));
        fs::create_dir_all(root.join("sessions")).unwrap();
        let path = sessions::rendezvous(&root, uuid::Uuid::new_v4().into_bytes());
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let marker = path.with_extension("readiness");
        fs::write(&marker, []).unwrap();
        drop(listener);
        assert!(sessions::discover(&root).await.unwrap().is_empty());
        assert!(!path.exists());
        assert!(!marker.exists());
        // An abrupt stop between the two unlinks can leave only the marker.
        fs::write(&marker, []).unwrap();
        assert!(sessions::discover(&root).await.unwrap().is_empty());
        assert!(!marker.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn missing_rendezvous_without_exit_proof_is_not_success() {
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/real-logins")
            .join(format!("{}.sock", uuid::Uuid::new_v4().simple()));
        assert!(stop(path, [0; 16]).await.is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod durable_tests {
    //! Reservations and cleanup remain durable without occupying the reactor.
    use super::*;

    /// A reserved terminal is not reported until the held write has completed.
    #[tokio::test]
    async fn reservation_durable_write_leaves_the_reactor_responsive() {
        let root = crate::durable_tests::directory();
        fs::create_dir(root.join("infraternal-login-locks")).unwrap();
        let person = uuid::Uuid::new_v4();
        let reservation = crate::durable_tests::responsive(root.clone(), {
            let root = root.clone();
            async move {
                fs::set_permissions(
                    root.join("infraternal-login-locks"),
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )?;
                crate::logins::synchronize_at(&root, person)?;
                let guard = crate::logins::rootless_launch_guard(&root, person).await?;
                reserve(&root, person, uuid::Uuid::new_v4(), guard).await
            }
        })
        .await
        .unwrap();
        assert!(reservation.path.as_ref().unwrap().exists());
        drop(reservation);
        fs::remove_dir_all(root).unwrap();
    }

    /// Cleanup cannot report success before its directory write is durable.
    #[tokio::test]
    async fn cleanup_durable_write_leaves_the_reactor_responsive() {
        let root = crate::durable_tests::directory();
        fs::create_dir(root.join("infraternal-login-locks")).unwrap();
        fs::create_dir(root.join("sessions")).unwrap();
        crate::durable_tests::responsive(root.clone(), {
            let root = root.clone();
            async move {
                revoke(
                    &root,
                    uuid::Uuid::new_v4(),
                    None,
                    crate::durable_io::admit().unwrap(),
                )
                .await
            }
        })
        .await
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
