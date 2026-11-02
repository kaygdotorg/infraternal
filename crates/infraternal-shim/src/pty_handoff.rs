//! Audited descriptor-only handoff primitive; state authority stays with the old host until commit [D128].
#![allow(unsafe_code)]
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use std::{
    fs::File,
    io::{self, IoSlice, IoSliceMut},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::UnixDatagram,
    },
};
/// Bound ancillary storage and descriptors per atomic datagram; larger hosts use numbered batches.
const MAX_BATCH: usize = 64;

/// Only ordinary credentials/timestamps accompany this private channel. A
/// kernel-provided pidfd would require separate ownership, and security labels
/// have a deployment-dependent bound; reject those options before recvmsg can
/// install any descriptors. The host freezes all channel mutation for handoff.
fn validate_channel(socket: &UnixDatagram) -> io::Result<()> {
    for option in [nix::libc::SO_PASSSEC, nix::libc::SO_PASSPIDFD] {
        let mut enabled: nix::libc::c_int = 0;
        let mut length = nix::libc::socklen_t::try_from(std::mem::size_of_val(&enabled))
            .map_err(io::Error::other)?;
        // SAFETY: the live socket and initialized integer/length remain valid
        // through this synchronous query; the kernel retains no pointers.
        let result = unsafe {
            nix::libc::getsockopt(
                socket.as_raw_fd(),
                nix::libc::SOL_SOCKET,
                option,
                (&raw mut enabled).cast(),
                &raw mut length,
            )
        };
        if result == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(nix::libc::ENOPROTOOPT) {
                return Err(error);
            }
        } else if enabled != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
    }
    Ok(())
}

/// Duplicate one bounded batch of PTY masters into a private paired socket.
/// The sender retains ownership until the replacement validates all batches.
/// # Errors
/// Refuses empty or oversized batches and reports socket failures.
pub fn send_masters(socket: &UnixDatagram, masters: &[File]) -> io::Result<()> {
    if masters.is_empty() || masters.len() > MAX_BATCH {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let descriptors: Vec<_> = masters.iter().map(AsRawFd::as_raw_fd).collect();
    let bytes = [u8::try_from(masters.len()).map_err(io::Error::other)?];
    sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(&bytes)],
        &[ControlMessage::ScmRights(&descriptors)],
        MsgFlags::MSG_NOSIGNAL,
        None,
    )
    .map_err(io::Error::from)?;
    Ok(())
}
/// Receive an atomic batch with CLOEXEC already set by the kernel.
/// This transfers lifetime; rings, writer cursors and VT state require a
/// separately validated transaction before the old host may resume or retire.
/// # Errors
/// Refuses truncated messages, wrong descriptor counts and socket failures.
pub fn receive_masters(socket: &UnixDatagram) -> io::Result<Vec<File>> {
    validate_channel(socket)?;
    let mut bytes = [0; 1];
    // Linux limits one SCM_RIGHTS datagram to 253 descriptors. Receive that
    // entire kernel bound before rejecting a batch above our 64-descriptor cap,
    // so a refusal can close every descriptor rather than leak ancillary FDs.
    // Credential metadata may accompany the descriptor array. Without its
    // own space recvmsg installs a truncated descriptor prefix, but the safe
    // iterator refuses CTRUNC before those descriptors can be owned/closed.
    // Reserve other ordinary local-socket metadata too; the pair remains a
    // private inherited channel, never an arbitrary configured listener.
    let mut ancillary = nix::cmsg_space!(
        [std::os::fd::RawFd; 253],
        nix::libc::ucred,
        [u8; 4096],
        [nix::libc::timespec; 3],
        std::os::fd::RawFd
    );
    let mut slices = [IoSliceMut::new(&mut bytes)];
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut slices,
        Some(&mut ancillary),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(io::Error::from)?;
    let mut masters = Vec::new();
    for control in message.cmsgs().map_err(io::Error::from)? {
        if let ControlMessageOwned::ScmRights(descriptors) = control {
            for descriptor in descriptors {
                // SAFETY: successful recvmsg created fresh owned descriptors.
                // Wrapping immediately ensures validation failures close them.
                masters.push(unsafe { File::from_raw_fd(descriptor) });
            }
        }
    }
    let invalid = message.bytes != 1
        || message
            .flags
            .intersects(MsgFlags::MSG_CTRUNC | MsgFlags::MSG_TRUNC);
    if invalid
        || masters.len() != usize::from(bytes[0])
        || masters.is_empty()
        || masters.len() > MAX_BATCH
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(masters)
}
#[cfg(test)]
mod tests {
    //! Real PTY lifetime and complete multi-batch descriptor transfer checks.
    use super::*;
    use std::{
        io::{Read, Write},
        time::{Duration, Instant},
    };
    #[test]
    fn all_masters_survive_original_owner_drop_with_cloexec() {
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        let mut ptys = (0..130)
            .map(|_| {
                super::super::Pty::spawn_with_readiness(
                    nix::unistd::Uid::effective().as_raw(),
                    80,
                    24,
                    true,
                    None,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let originals: Vec<_> = ptys.iter().map(|p| p.master.try_clone().unwrap()).collect();
        let mut inherited = Vec::new();
        for chunk in originals.chunks(MAX_BATCH) {
            send_masters(&sender, chunk).unwrap();
            inherited.extend(receive_masters(&receiver).unwrap());
        }
        assert_eq!(inherited.len(), ptys.len());
        drop(originals);
        for (mut inherited, pty) in inherited.into_iter().zip(&mut ptys) {
            // Swap away the original master before writing through its replacement.
            pty.master = File::open("/dev/null").unwrap();
            let flags = nix::fcntl::fcntl(&inherited, nix::fcntl::FcntlArg::F_GETFD).unwrap();
            assert_ne!(flags & nix::libc::FD_CLOEXEC, 0);
            inherited.write_all(b"continue\n").unwrap();
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut output = Vec::new();
            loop {
                let mut bytes = [0; 128];
                match inherited.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(n) => output.extend_from_slice(&bytes[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => break,
                    other => panic!("{other:?}"),
                }
                assert!(Instant::now() < deadline);
            }
            assert!(output.windows(17).any(|s| s == b"infraternal-ready"));
            assert!(pty.child.wait().unwrap().success());
        }
    }
    #[test]
    fn oversized_ancillary_batch_refusal_closes_every_received_descriptor() {
        const CASE: &str = "pty::handoff::tests::oversized_ancillary_batch_refusal_closes_every_received_descriptor";
        const FLAG: &str = "INFRATERNAL_FD_REFUSAL_FIXTURE";
        if std::env::var_os(FLAG).is_none() {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", CASE, "--test-threads=1"])
                    .env(FLAG, "1")
                    .status()
                    .unwrap()
                    .success()
            );
            return;
        }
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        let file = File::open("/dev/null").unwrap();
        let descriptors = [file.as_raw_fd(); 65];
        let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&[65])],
            &[ControlMessage::ScmRights(&descriptors)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        assert_eq!(
            receive_masters(&receiver).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
    }
    #[test]
    fn credential_ancillary_refusal_closes_a_kernel_maximum_descriptor_batch() {
        const CASE: &str = "pty::handoff::tests::credential_ancillary_refusal_closes_a_kernel_maximum_descriptor_batch";
        const FLAG: &str = "INFRATERNAL_FD_CREDENTIAL_FIXTURE";
        if std::env::var_os(FLAG).is_none() {
            assert!(
                std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", CASE, "--test-threads=1"])
                    .env(FLAG, "1")
                    .status()
                    .unwrap()
                    .success()
            );
            return;
        }
        let (sender, receiver) = UnixDatagram::pair().unwrap();
        nix::sys::socket::setsockopt(&receiver, nix::sys::socket::sockopt::PassCred, &true)
            .unwrap();
        let file = File::open("/dev/null").unwrap();
        let descriptors = [file.as_raw_fd(); 253];
        let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(&[253])],
            &[ControlMessage::ScmRights(&descriptors)],
            MsgFlags::empty(),
            None,
        )
        .unwrap();
        assert!(receive_masters(&receiver).is_err());
        assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
    }
}
