//! Pre-exec PTY preparation on the original authenticated login lease [D240,D247].
#![forbid(unsafe_code)]
use nix::unistd::{Uid, User};
use std::{fs::File, io, os::unix::net::UnixStream, path::Path, process::Command, time::Duration};

/// Own both terminal ends until transfer/spawn succeeds. Dropping the associated
/// connection cancels only this request; no extra service, process or timer exists.
pub struct Prepared {
    master: File,
    slave: File,
    uid: u32,
}
impl Prepared {
    /// Prepare the same account-owned, bounded PTY used by ordinary startup.
    /// # Errors
    /// Rejects invalid dimensions, absent accounts and unauthorized uid changes.
    pub fn new(uid: u32, cols: u16, rows: u16) -> io::Result<Self> {
        if cols == 0 || rows == 0 || usize::from(cols) * usize::from(rows) > 200_000 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let user = User::from_uid(Uid::from_raw(uid))
            .map_err(io::Error::from)?
            .ok_or_else(|| io::Error::other("target uid has no login account"))?;
        let (master, slave) = crate::pty::open_terminal(&user, cols, rows)?;
        Ok(Self { master, slave, uid })
    }
    /// Borrow the master for readiness observers; production passes it to its shim.
    #[must_use]
    pub fn master(&self) -> &File {
        &self.master
    }

    /// Authenticate this exact connection, then send the unchanged fixed request.
    /// The caller supplies fd readiness for a nonblocking connection; a failed
    /// or canceled send must drop the connection before retrying another request.
    /// # Errors
    /// Refuses a replacement/dead worker, fallback parent loss or failed transfer.
    pub fn request(
        &self,
        peer: &UnixStream,
        session: &[u8; 16],
        pid: i32,
        pin: &Path,
        parent: Option<i32>,
    ) -> io::Result<()> {
        crate::login::authenticate(peer, self.uid, Some(pid), Some(pin), parent)?;
        crate::pty::send_terminal_from(peer, &self.slave, session)
    }

    /// Reserve occupied child descriptor slots for the master and same lease.
    /// Command captures are parent copies: drop Command and Prepared immediately
    /// after spawn, plus the parent's connection, so they cannot retain a shell.
    /// # Errors
    /// Returns descriptor reservation failures before the child is started.
    pub fn inherit(&self, command: &mut Command, peer: &UnixStream) -> io::Result<(i32, i32)> {
        Ok((
            crate::pty::inherit_descriptor(command, &self.master)?,
            crate::pty::inherit_descriptor(command, peer)?,
        ))
    }
}

pub(crate) fn adopt(
    master: i32,
    lease: i32,
    uid: u32,
    pid: i32,
    pin: &Path,
    parent: Option<i32>,
) -> io::Result<crate::pty::Pty> {
    if master == lease {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let master = crate::pty::duplicate_inherited_descriptor(master)?;
    crate::pty::validate_master(&master)?;
    let mut peer = UnixStream::from(std::os::fd::OwnedFd::from(
        crate::pty::duplicate_inherited_descriptor(lease)?,
    ));
    crate::login::authenticate(&peer, uid, Some(pid), Some(pin), parent)?;
    // The shell starts before this exec, so its ACK is commonly queued already.
    // First force nonblocking even for a blocking inherited descriptor. Only
    // an absent byte needs bounded blocking; both paths consume exactly one
    // byte and preserve any coalesced exit status on the same original lease.
    peer.set_nonblocking(true)?;
    match crate::login::acknowledge(&mut peer) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            peer.set_read_timeout(Some(Duration::from_secs(2)))?;
            peer.set_nonblocking(false)?;
            crate::login::acknowledge(&mut peer)?;
            peer.set_nonblocking(true)?;
        }
        Err(error) => return Err(error),
    }
    Ok(crate::pty::Pty {
        master,
        child: crate::child::OwnedChild::login(peer),
    })
}

#[cfg(test)]
mod tests {
    //! Acknowledgment/status framing and occupied-descriptor errors use real fds.
    use super::*;
    use std::{
        io::{Read, Write},
        os::fd::AsRawFd,
    };
    #[test]
    fn adopted_nonblocking_lease_preserves_coalesced_status() {
        let uid = Uid::effective().as_raw();
        let prepared = Prepared::new(uid, 80, 24).unwrap();
        let (peer, mut source) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        source.write_all(&[b'A', 37, 0, 0, 0]).unwrap();
        let mut command = Command::new("/bin/true");
        let (master, lease) = prepared.inherit(&mut command, &peer).unwrap();
        let mut pty = adopt(
            master,
            lease,
            uid,
            nix::unistd::getpid().as_raw(),
            Path::new("/proc/self"),
            None,
        )
        .unwrap();
        assert_eq!(pty.child.try_wait().unwrap().unwrap().code(), Some(37));
        assert!(pty.child.descriptor().is_none());
        source.set_nonblocking(true).unwrap();
        assert_eq!(
            source.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(pty);
        drop(command);
        drop(peer);
        // Parallel fixtures may fork while these descriptors exist; their
        // inherited CLOEXEC copy lasts until exec. Await EOF with a bound so
        // that interval is not mistaken for a permanently retained lease.
        source
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        source.set_nonblocking(false).unwrap();
        assert_eq!(source.read(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn successful_adoption_survives_actual_exec_and_parent_copy_release() {
        const FIXTURE: &str = "INFRATERNAL_HANDOFF_EXEC_FIXTURE";
        if std::env::var_os(FIXTURE).is_some() {
            let value = |key| std::env::var(key).unwrap().parse::<i32>().unwrap();
            let pin =
                std::path::PathBuf::from(std::env::var_os("INFRATERNAL_HANDOFF_PIN").unwrap());
            crate::protect_login_process_at(&pin).unwrap();
            let mut pty = adopt(
                value("INFRATERNAL_HANDOFF_MASTER"),
                value("INFRATERNAL_HANDOFF_LEASE"),
                Uid::effective().as_raw(),
                value("INFRATERNAL_HANDOFF_PID"),
                &pin,
                None,
            )
            .unwrap();
            assert_eq!(pty.child.try_wait().unwrap().unwrap().code(), Some(37));
            return;
        }
        let prepared = Prepared::new(Uid::effective().as_raw(), 80, 24).unwrap();
        let (peer, mut source) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        source.write_all(&[b'A', 37, 0, 0, 0]).unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact","login_handoff::tests::successful_adoption_survives_actual_exec_and_parent_copy_release","--nocapture"]);
        let process = File::open("/proc/self").unwrap();
        let pin = crate::inherit_login_process(&mut command, &process).unwrap();
        let (master, lease) = prepared.inherit(&mut command, &peer).unwrap();
        command
            .env(FIXTURE, "1")
            .env("INFRATERNAL_HANDOFF_PIN", pin)
            .env("INFRATERNAL_HANDOFF_MASTER", master.to_string())
            .env("INFRATERNAL_HANDOFF_LEASE", lease.to_string())
            .env(
                "INFRATERNAL_HANDOFF_PID",
                nix::unistd::getpid().as_raw().to_string(),
            );
        let mut child = command.spawn().unwrap();
        drop(command);
        drop(prepared);
        drop(peer);
        assert!(child.wait().unwrap().success());
        source
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(
            source.read(&mut [0]).unwrap(),
            0,
            "parent copies retained the lease"
        );
    }

    #[test]
    fn acknowledgment_timeout_releases_adoption_and_parent_copies() {
        let uid = Uid::effective().as_raw();
        let prepared = Prepared::new(uid, 80, 24).unwrap();
        let (peer, mut source) = UnixStream::pair().unwrap();
        let mut command = Command::new("/bin/true");
        let (master, lease) = prepared.inherit(&mut command, &peer).unwrap();
        let Err(error) = adopt(
            master,
            lease,
            uid,
            nix::unistd::getpid().as_raw(),
            Path::new("/proc/self"),
            None,
        ) else {
            panic!("missing acknowledgment accepted");
        };
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        drop(command);
        drop(prepared);
        drop(peer);
        source
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        assert_eq!(source.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn delayed_acknowledgment_preserves_exit_status() {
        let uid = Uid::effective().as_raw();
        let prepared = Prepared::new(uid, 80, 24).unwrap();
        let (peer, mut source) = UnixStream::pair().unwrap();
        let mut command = Command::new("/bin/true");
        let (master, lease) = prepared.inherit(&mut command, &peer).unwrap();
        let writer = std::thread::spawn(move || {
            // Exercise the absent-byte path with a real socket, then coalesce
            // the acknowledgment and status to verify their framing together.
            std::thread::sleep(Duration::from_millis(50));
            source.write_all(&[b'A', 37, 0, 0, 0]).unwrap();
        });
        let mut pty = adopt(
            master,
            lease,
            uid,
            nix::unistd::getpid().as_raw(),
            Path::new("/proc/self"),
            None,
        )
        .unwrap();
        writer.join().unwrap();
        assert_eq!(pty.child.try_wait().unwrap().unwrap().code(), Some(37));
    }

    #[test]
    fn adoption_revalidates_identity_before_reading_acknowledgment() {
        let uid = Uid::effective().as_raw();
        let prepared = Prepared::new(uid, 80, 24).unwrap();
        let (peer, _source) = UnixStream::pair().unwrap();
        let mut command = Command::new("/bin/true");
        let (master, lease) = prepared.inherit(&mut command, &peer).unwrap();
        let pid = nix::unistd::getpid().as_raw();
        // No ACK exists. All mismatches must refuse before attempting to read it.
        for (account, expected, pin, parent) in [
            (uid, pid.saturating_add(1), Path::new("/proc/self"), None),
            (
                uid,
                pid,
                Path::new("/nonexistent/infraternal-dead-pin"),
                None,
            ),
            (uid, pid, Path::new("/proc/self"), Some(1)),
            (uid.wrapping_add(1), pid, Path::new("/proc/self"), None),
        ] {
            assert!(adopt(master, lease, account, expected, pin, parent).is_err());
        }
        let config = crate::Config::new([0; 16], uid);
        assert!(
            crate::run_with_prestarted_login(config, Duration::ZERO, None, master, lease).is_err()
        );
    }

    #[test]
    fn prepared_descriptors_keep_missing_exec_errors_and_parent_cloexec() {
        let prepared = Prepared::new(Uid::effective().as_raw(), 80, 24).unwrap();
        let (peer, _source) = UnixStream::pair().unwrap();
        let mut command = Command::new("/nonexistent/infraternal-handoff-fixture");
        let (master, lease) = prepared.inherit(&mut command, &peer).unwrap();
        assert!(master >= 8 && lease >= 8 && master != lease);
        assert_eq!(command.spawn().unwrap_err().kind(), io::ErrorKind::NotFound);
        for fd in [master, lease] {
            let path = std::path::PathBuf::from(format!("/proc/self/fd/{fd}"));
            assert!(path.exists());
        }
        // A non-master cannot be substituted for the terminal output path.
        assert!(
            adopt(
                lease,
                master,
                Uid::effective().as_raw(),
                nix::unistd::getpid().as_raw(),
                Path::new("/proc/self"),
                None
            )
            .is_err()
        );
        assert!(
            adopt(
                peer.as_raw_fd(),
                peer.as_raw_fd(),
                Uid::effective().as_raw(),
                nix::unistd::getpid().as_raw(),
                Path::new("/proc/self"),
                None
            )
            .is_err()
        );
    }
}
