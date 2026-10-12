//! Audit the Linux pidfd wrapper's ownership, CLOEXEC flag and real-child exit readiness [D40,D81], #168.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use nix::{
    fcntl::{FcntlArg, FdFlag, fcntl},
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use std::{
    os::fd::AsFd,
    process::{Command, Stdio},
};

#[test]
fn descriptor_is_cloexec_and_observes_a_real_process_exit() {
    let mut child = Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let fd = infraternal_shim::process_exit_descriptor(child.id()).unwrap();
    let flags = FdFlag::from_bits_truncate(fcntl(&fd, FcntlArg::F_GETFD).unwrap());
    let mut watched = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    let before = poll(&mut watched, PollTimeout::ZERO).unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    let after = poll(&mut watched, 2000_u16).unwrap();
    assert!(flags.contains(FdFlag::FD_CLOEXEC));
    assert_eq!(before, 0);
    assert_eq!(after, 1);
    assert!(watched[0].revents().unwrap().contains(PollFlags::POLLIN));
    assert!(infraternal_shim::process_exit_descriptor(child.id()).is_err());
}

#[test]
fn invalid_pid_never_creates_a_descriptor() {
    assert!(infraternal_shim::process_exit_descriptor(0).is_err());
    assert!(infraternal_shim::process_exit_descriptor(u32::MAX).is_err());
}
