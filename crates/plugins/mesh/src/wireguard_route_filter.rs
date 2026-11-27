//! Discard echoes of our route additions before they make the route listener readable.

use nix::libc;
use nix::sys::socket::{NetlinkAddr, getsockname};
use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
};

/// A duplicate of the listener's socket, plus the binding reserved by its current filter.
#[derive(Debug)]
pub(super) struct RouteQueue {
    /// Queue shared with the listener, also polled when settling the underlay generation.
    pub(super) fd: OwnedFd,
    /// Keeps the selected port ID bound until the filter is replaced or the listener stops.
    writer: Option<OwnedFd>,
}

impl RouteQueue {
    /// Track the listener before any writers register.
    pub(super) fn new(fd: OwnedFd) -> Self {
        Self { fd, writer: None }
    }

    /// Filter echoes from this batch's request socket, without affecting any other writer.
    /// Keep the old binding reserved if any step fails and the previous filter stays installed.
    pub(super) fn ignore_adds_from(&mut self, writer: BorrowedFd<'_>) -> io::Result<()> {
        if netns_cookie(self.fd.as_raw_fd())? != netns_cookie(writer.as_raw_fd())? {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let port = getsockname::<NetlinkAddr>(writer.as_raw_fd())?.pid();
        if port == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let reservation = writer.try_clone_to_owned()?;
        attach(self.fd.as_raw_fd(), port)?;
        self.writer = Some(reservation);
        Ok(())
    }
}

/// Read the socket's network namespace ID. Netlink port IDs are unique only within a namespace.
#[allow(unsafe_code)]
fn netns_cookie(fd: std::os::fd::RawFd) -> io::Result<u64> {
    let mut cookie = 0_u64;
    let mut length = libc::socklen_t::try_from(size_of::<u64>()).map_err(io::Error::other)?;
    // SAFETY: Both out-pointers refer to initialized local storage of the supplied size.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_NETNS_COOKIE,
            (&raw mut cookie).cast(),
            &raw mut length,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(length).ok() != Some(size_of::<u64>()) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(cookie)
}

/// Attach classic BPF that rejects a single protocol-250 `RTM_NEWROUTE` echo from `port`.
///
/// Netlink records the requester's bound port in the multicast message header for both IPv4
/// and IPv6. Every deletion and every notification from another port is passed to userspace.
/// The endian-adjusted length comparison passes larger or multi-message datagrams unchanged.
#[allow(unsafe_code)]
fn attach(fd: std::os::fd::RawFd, port: u32) -> io::Result<()> {
    use libc::{
        BPF_ABS, BPF_ALU, BPF_B, BPF_H, BPF_JEQ, BPF_JGT, BPF_JMP, BPF_K, BPF_LD, BPF_LEN, BPF_LSH,
        BPF_MISC, BPF_RET, BPF_TAX, BPF_W, BPF_X,
    };

    let mut instructions = [
        insn(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0),
        // Check that the rtmsg fits. Limit the length to one byte so converting it to
        // the header's byte order on little-endian hosts needs just one shift.
        insn(BPF_JMP | BPF_JGT | BPF_K, 27, 0, 11),
        insn(BPF_JMP | BPF_JGT | BPF_K, 255, 10, 0),
        insn(
            BPF_ALU | BPF_LSH | BPF_K,
            if cfg!(target_endian = "little") {
                24
            } else {
                0
            },
            0,
            0,
        ),
        insn(BPF_MISC | BPF_TAX, 0, 0, 0),
        insn(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0), // nlmsg_len
        insn(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 6),
        insn(BPF_LD | BPF_H | BPF_ABS, 4, 0, 0), // nlmsg_type
        insn(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::from(libc::RTM_NEWROUTE.to_be()),
            0,
            4,
        ),
        insn(BPF_LD | BPF_W | BPF_ABS, 12, 0, 0), // nlmsg_pid
        insn(BPF_JMP | BPF_JEQ | BPF_K, port.to_be(), 0, 2),
        insn(BPF_LD | BPF_B | BPF_ABS, 21, 0, 0), // rtm_protocol
        insn(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::from(super::RTPROT_INFRATERNAL),
            1,
            0,
        ),
        insn(BPF_RET | BPF_K, u32::MAX, 0, 0), // pass the entire datagram
        insn(BPF_RET | BPF_K, 0, 0, 0),        // discard without queueing
    ];
    let program = libc::sock_fprog {
        len: u16::try_from(instructions.len()).map_err(io::Error::other)?,
        filter: instructions.as_mut_ptr(),
    };
    let size =
        libc::socklen_t::try_from(size_of::<libc::sock_fprog>()).map_err(io::Error::other)?;
    // SAFETY: The kernel copies the program synchronously. Both the descriptor and its
    // instruction array hold valid initialized values for the duration of the call.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw const program).cast(),
            size,
        )
    };
    nix::errno::Errno::result(result)?;
    Ok(())
}

/// Encode one classic BPF instruction, with jump offsets relative to the next instruction.
#[expect(
    clippy::cast_possible_truncation,
    reason = "classic BPF opcodes fit in u16"
)]
const fn insn(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}
