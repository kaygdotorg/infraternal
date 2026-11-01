//! Owns local child status or a login worker's event-driven terminal lease [D240,D247].
#![forbid(unsafe_code)]
use std::{
    io,
    process::{Child, ExitStatus},
};
#[cfg(feature = "host-login")]
use std::{
    io::Read,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::{net::UnixStream, process::ExitStatusExt},
    },
};

pub(crate) enum OwnedChild {
    Local(Child),
    #[cfg(feature = "host-login")]
    Login {
        peer: UnixStream,
        bytes: [u8; 4],
        consumed: usize,
        status: Option<ExitStatus>,
    },
}
impl OwnedChild {
    #[cfg(feature = "host-login")]
    pub(crate) fn login(peer: UnixStream) -> Self {
        Self::Login {
            peer,
            bytes: [0; 4],
            consumed: 0,
            status: None,
        }
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self {
            Self::Local(child) => child.try_wait(),
            #[cfg(feature = "host-login")]
            Self::Login {
                peer,
                bytes,
                consumed,
                status,
            } => {
                if status.is_some() {
                    return Ok(*status);
                }
                while *consumed < bytes.len() {
                    match peer.read(&mut bytes[*consumed..]) {
                        Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                        Ok(length) => *consumed += length,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => return Err(error),
                    }
                }
                let code = crate::login::decode_status(bytes)?;
                // The worker reports an ordinary exit code or a negative signal.
                // Refuse malformed reports rather than converting them to success.
                let raw = if code >= 0 { code << 8 } else { -code };
                *status = Some(ExitStatus::from_raw(raw));
                Ok(*status)
            }
        }
    }

    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        match self {
            Self::Local(child) => child.wait(),
            #[cfg(feature = "host-login")]
            Self::Login { .. } => loop {
                if let Some(status) = self.try_wait()? {
                    return Ok(status);
                }
                let descriptor = self
                    .descriptor()
                    .ok_or_else(|| io::Error::other("login exit descriptor absent"))?;
                let mut fds = [nix::poll::PollFd::new(
                    descriptor,
                    nix::poll::PollFlags::POLLIN,
                )];
                match nix::poll::poll(&mut fds, nix::poll::PollTimeout::NONE) {
                    Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                    Err(error) => return Err(error.into()),
                }
            },
        }
    }

    pub(crate) fn kill(&mut self) -> io::Result<()> {
        match self {
            Self::Local(child) => child.kill(),
            #[cfg(feature = "host-login")]
            Self::Login { peer, .. } => {
                // HUP cancels only this terminal; the authenticated worker reaps
                // its child. Never signal a numeric PID that can be recycled.
                peer.shutdown(std::net::Shutdown::Both)
            }
        }
    }

    #[cfg(any(test, feature = "host-login"))]
    pub(crate) fn id(&self) -> u32 {
        match self {
            Self::Local(child) => child.id(),
            #[cfg(feature = "host-login")]
            Self::Login { .. } => 0,
        }
    }

    // The peer remains owned after status is consumed, retaining the login
    // through output retention/ExitAck. Only its readiness is then disabled.
    #[cfg(feature = "host-login")]
    pub(crate) fn descriptor(&self) -> Option<BorrowedFd<'_>> {
        match self {
            Self::Local(_)
            | Self::Login {
                status: Some(_), ..
            } => None,
            Self::Login { peer, .. } => Some(peer.as_fd()),
        }
    }
}

#[cfg(all(test, feature = "host-login"))]
mod tests {
    //! Fragmented status and retained leases are tested with real socket readiness.
    use super::*;
    use std::io::Write;

    fn pair() -> (OwnedChild, UnixStream) {
        let (peer, source) = UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        (OwnedChild::login(peer), source)
    }

    #[test]
    fn partial_exit_waits_for_readiness_and_retains_the_lease_after_exit() {
        let (mut child, mut source) = pair();
        assert!(child.try_wait().unwrap().is_none());
        source.write_all(&37_i32.to_le_bytes()[..2]).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        source.write_all(&37_i32.to_le_bytes()[2..]).unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(37));
        assert_eq!(child.try_wait().unwrap().unwrap().code(), Some(37));
        assert!(child.descriptor().is_none());
        source.set_nonblocking(true).unwrap();
        assert_eq!(
            source.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(child);
        assert_eq!(source.read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn signal_exit_and_truncated_or_invalid_status_fail_safely() {
        for bytes in [&[][..], &[0; 3][..], &[0; 5][..]] {
            assert!(crate::login::decode_status(bytes).is_err());
        }
        let (mut child, mut source) = pair();
        source.write_all(&(-15_i32).to_le_bytes()).unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(15));
        for code in [256_i32, -65, i32::MIN] {
            let (mut child, mut source) = pair();
            source.write_all(&code.to_le_bytes()).unwrap();
            assert_eq!(
                child.try_wait().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        let (mut child, mut source) = pair();
        source.write_all(&[0, 0]).unwrap();
        drop(source);
        assert_eq!(
            child.try_wait().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn canceling_one_lease_does_not_shutdown_another_terminal() {
        let (mut first, mut first_source) = pair();
        let (mut second, mut second_source) = pair();
        first.kill().unwrap();
        assert_eq!(first_source.read(&mut [0]).unwrap(), 0);
        second_source.write_all(&0_i32.to_le_bytes()).unwrap();
        assert!(second.wait().unwrap().success());
    }
}
