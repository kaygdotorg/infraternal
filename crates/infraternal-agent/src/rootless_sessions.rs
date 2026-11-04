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
pub(crate) struct Reservation(Option<PathBuf>);
#[cfg(target_os = "linux")]
impl Reservation {
    /// The shim has started: the record must now survive this reservation. Returns its path so a
    /// launch that later fails can retire it once the terminal is proven stopped.
    pub(crate) fn spawned(&mut self) -> Option<PathBuf> {
        self.0.take()
    }
}
#[cfg(target_os = "linux")]
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn reserve(state: &Path, person: uuid::Uuid, id: uuid::Uuid) -> io::Result<Reservation> {
    let directory = state.join("infraternal-login-locks");
    let path = directory.join(format!("{}-{}.terminal", person.simple(), id.simple()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)?;
    let reservation = Reservation(Some(path));
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    Ok(reservation)
}

#[cold]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn launch(
    exe: &Path,
    state: &Path,
    manager: Manager,
    person: uuid::Uuid,
    uid: u32,
    cols: u16,
    rows: u16,
) -> io::Result<Session> {
    let _person = crate::logins::rootless_launch_guard(state, person).await?;
    sessions::launch_rootless_person(exe, state, manager, uid, cols, rows, person).await
}

#[cold]
pub(crate) async fn revoke(state: &Path, person: uuid::Uuid) -> io::Result<()> {
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
    File::open(directory)?.sync_all()?;
    failure.map_or(Ok(()), Err)
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

async fn stop(path: PathBuf, id: [u8; 16]) -> io::Result<()> {
    // A sealed exit remains proof after listener retirement. Refusal, missing
    // rendezvous, unsupported capability and timeout otherwise fail honestly.
    if infraternal_shim::ended::read(&path)?.is_some() {
        return Ok(());
    }
    tokio::time::timeout(Duration::from_secs(3), async {
        match tokio::net::UnixStream::connect(path.with_extension("stop")).await {
            Ok(mut peer) => {
                // This private endpoint has no ordinary link, decoder quota
                // or owner limit. Authenticate before requesting retirement.
                let credentials = peer.peer_cred()?;
                if credentials.uid() != 0
                    && credentials.uid() != nix::unistd::Uid::effective().as_raw()
                {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                tokio::io::AsyncWriteExt::write_all(&mut peer, b"!").await?;
                let mut reader = Reader::default();
                if !matches!(reader.read(&mut peer).await?, Frame::Hello {
                    version: 1, caps: SHELL_CLEANUP, session, pid, ..
                } if session == id && i32::try_from(pid).ok() == credentials.pid())
                {
                    return Err(io::Error::other("host login cleanup identity differs"));
                }
                if reader.read(&mut peer).await? != Frame::ShellStopped {
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
        let mut session = sessions::connect_with(path.clone(), id, SHELL_CLEANUP).await?;
        if session.caps != SHELL_CLEANUP {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "host login path cannot confirm shell cleanup",
            ));
        }
        sessions::send(&mut session.peer, &Frame::StopShell).await?;
        if Reader::default().read(&mut session.peer).await? != Frame::ShellStopped {
            return Err(io::Error::other(
                "host login path did not confirm shell cleanup",
            ));
        }
        Ok(())
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

#[cfg(test)]
mod tests {
    //! Cleanup refuses unsupported or unconfirmed peers without inventing exit proof.
    use super::*;

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
            revoke(&root, uuid::Uuid::new_v4())
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        fs::remove_dir_all(root).unwrap();
    }

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
        assert!(revoke(&root, person).await.is_err());
        fs::write(&marker, []).unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(revoke(&root, person).await.is_ok());
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(revoke(&root, person).await.is_err());
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&marker, b"invalid").unwrap();
        assert!(revoke(&root, person).await.is_err());
        fs::remove_file(&marker).unwrap();
        fs::create_dir(&marker).unwrap();
        assert!(revoke(&root, person).await.is_err());
        fs::remove_dir(&marker).unwrap();
        symlink("/dev/null", &marker).unwrap();
        assert!(revoke(&root, person).await.is_err());
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
