//! Sets a Mac utun's MTU and brings it up with kernel ioctls instead of spawning `ifconfig`.
//!
//! Spawning `/sbin/ifconfig <utun> mtu 1280 up` costs about 3.5 ms on every Mac start (#221,
//! J991). The kernel work behind it is three ioctls on a datagram socket, so this module does
//! those directly: `SIOCSIFMTU`, then `SIOCGIFFLAGS` and `SIOCSIFFLAGS` to add `IFF_UP`.
//!
//! This is the one small audited place in the crate that needs `unsafe`: `libc::ioctl` takes a raw
//! pointer. Everything else stays under the crate's `deny(unsafe_code)`. The request layout and
//! the validation are plain safe code kept apart from the single `unsafe` call, so they are unit
//! tested on every platform and only the kernel call is Mac-only.
//!
//! Addresses are not set here. `ifconfig <utun> inet …` and `inet6 … alias` keep their own
//! spawns, which are a separate change (#221).
#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]
// The kernel call is Mac-only, so the Linux test build sees the pure part unused.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::io;

/// Bytes in an interface name field, including its terminating NUL (`IFNAMSIZ`).
const IFNAMSIZ: usize = 16;

/// `struct ifreq` on macOS: a 16-byte name and a 16-byte union (the largest member is a
/// `sockaddr`). `ifr_mtu` (`int`) and `ifr_flags` (`short`) both sit at the start of the union.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    data: [u8; 16],
}

impl IfReq {
    /// Build a request for `name`, with an all-zero union.
    ///
    /// The kernel reads the name as a C string inside a fixed 16-byte field, so a name must be
    /// 1 to 15 bytes and contain no NUL: the last byte always stays NUL, and an embedded NUL
    /// would silently address a shorter interface than the caller named.
    fn new(name: &str) -> io::Result<Self> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name must be 1 to 15 bytes with no NUL",
            ));
        }
        let mut field = [0; IFNAMSIZ];
        field[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            name: field,
            data: [0; 16],
        })
    }

    /// Store `mtu` in the union's `ifr_mtu` (`int`) slot.
    fn set_mtu(&mut self, mtu: u16) {
        self.data[..4].copy_from_slice(&i32::from(mtu).to_ne_bytes());
    }

    /// Read the union's `ifr_flags` (`short`) slot.
    fn flags(&self) -> i16 {
        i16::from_ne_bytes([self.data[0], self.data[1]])
    }

    /// Store `flags` in the union's `ifr_flags` (`short`) slot.
    fn set_flags(&mut self, flags: i16) {
        self.data[..2].copy_from_slice(&flags.to_ne_bytes());
    }
}

/// `IFF_UP` from `<net/if.h>`: the interface is administratively up.
const IFF_UP: i16 = 0x1;

/// Compose a BSD `_IOC` request number (`<sys/ioccom.h>`): direction bits, the parameter
/// length, a group letter and a command number.
const fn ioc(direction: u32, group: u8, number: u8, length: usize) -> u32 {
    // The encoding allows 13 bits (0x1fff) for the length, so the cast below cannot truncate.
    assert!(length <= 0x1fff);
    #[allow(clippy::cast_possible_truncation)]
    let length = length as u32;
    direction | (length << 16) | ((group as u32) << 8) | number as u32
}

/// The caller passes data to the kernel (`IOC_IN`).
const IOC_IN: u32 = 0x8000_0000;
/// The caller passes data and reads data back (`IOC_IN | IOC_OUT`).
const IOC_INOUT: u32 = 0xc000_0000;
/// `sizeof(struct ifreq)` on macOS; checked against `libc::ifreq` in the Mac build.
const IFREQ_LEN: usize = size_of::<IfReq>();

/// `SIOCSIFMTU`: set the interface MTU (`_IOW('i', 52, struct ifreq)`).
const SIOCSIFMTU: u32 = ioc(IOC_IN, b'i', 52, IFREQ_LEN);
/// `SIOCGIFFLAGS`: read the interface flags (`_IOWR('i', 17, struct ifreq)`).
const SIOCGIFFLAGS: u32 = ioc(IOC_INOUT, b'i', 17, IFREQ_LEN);
/// `SIOCSIFFLAGS`: set the interface flags (`_IOW('i', 16, struct ifreq)`).
const SIOCSIFFLAGS: u32 = ioc(IOC_IN, b'i', 16, IFREQ_LEN);

/// Set `interface`'s MTU to `mtu`, without changing whether it is up.
///
/// # Errors
/// Rejects an unusable name or an MTU of 0 with `InvalidInput`, and reports the kernel's
/// `errno` (for example `EPERM` without root, `ENXIO` for no such interface).
#[cfg(target_os = "macos")]
pub(crate) fn set_mtu(interface: &str, mtu: u16) -> io::Result<()> {
    let request = mtu_request(interface, mtu)?;
    let socket = control_socket()?;
    ioctl(&socket, SIOCSIFMTU, &mut { request })
}

/// Set `interface`'s MTU to `mtu` and bring it up, the same as `ifconfig <interface> mtu <mtu> up`.
///
/// # Errors
/// As [`set_mtu`], plus any failure reading or writing the interface flags.
#[cfg(target_os = "macos")]
pub(crate) fn set_mtu_and_up(interface: &str, mtu: u16) -> io::Result<()> {
    let mut request = mtu_request(interface, mtu)?;
    let socket = control_socket()?;
    ioctl(&socket, SIOCSIFMTU, &mut request)?;
    // Flags are read back, not overwritten, so every other flag (POINTOPOINT, MULTICAST, …)
    // survives. The union is reused, so the name stays as it was.
    ioctl(&socket, SIOCGIFFLAGS, &mut request)?;
    let flags = request.flags();
    request.set_flags(flags | IFF_UP);
    ioctl(&socket, SIOCSIFFLAGS, &mut request)
}

/// A validated request carrying `mtu`, or `InvalidInput` for a bad name or zero MTU.
fn mtu_request(interface: &str, mtu: u16) -> io::Result<IfReq> {
    if mtu == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MTU must not be 0",
        ));
    }
    let mut request = IfReq::new(interface)?;
    request.set_mtu(mtu);
    Ok(request)
}

/// A throwaway datagram socket: interface ioctls need some socket, and this carries no traffic.
#[cfg(target_os = "macos")]
fn control_socket() -> io::Result<std::os::fd::OwnedFd> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
    socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .map_err(io::Error::from)
}

/// Issue one interface ioctl and turn `-1` into the thread's `errno`.
#[cfg(target_os = "macos")]
fn ioctl(socket: &std::os::fd::OwnedFd, request: u32, argument: &mut IfReq) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `socket` is an open descriptor owned by the caller for the whole call.
    // `argument` is a live, exclusively borrowed `IfReq` whose `repr(C)` layout is
    // `struct ifreq` (32 bytes, asserted against `libc::ifreq` in the tests below), and every
    // request here reads or writes at most that many bytes through the pointer. Its name field
    // is NUL-terminated and at most 15 bytes by construction in `IfReq::new`, so the kernel
    // never reads past it. The pointer is not retained after the call returns.
    let result = unsafe {
        nix::libc::ioctl(
            socket.as_raw_fd(),
            nix::libc::c_ulong::from(request),
            std::ptr::from_mut(argument),
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Checks request building and validation on every platform, and the Mac layout and numbers.
    #![allow(clippy::expect_used)]
    use super::*;

    /// A short name is copied in full and the rest of the field stays NUL.
    #[test]
    fn name_is_copied_and_nul_terminated() {
        let request = IfReq::new("utun12").expect("valid name");
        assert_eq!(&request.name[..6], b"utun12");
        assert!(request.name[6..].iter().all(|&byte| byte == 0));
    }

    /// The longest accepted name is 15 bytes, so the last byte of the field is always NUL.
    #[test]
    fn longest_name_keeps_a_final_nul() {
        let name = "a".repeat(IFNAMSIZ - 1);
        let request = IfReq::new(&name).expect("15 bytes fit");
        assert_eq!(request.name[IFNAMSIZ - 1], 0);
        assert_eq!(&request.name[..IFNAMSIZ - 1], name.as_bytes());
    }

    /// A name of 16 bytes or more would lose its terminator, so it is refused.
    #[test]
    fn name_too_long_is_refused() {
        for length in [IFNAMSIZ, IFNAMSIZ + 1, 200] {
            let error = IfReq::new(&"a".repeat(length)).expect_err("too long");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "length {length}");
        }
    }

    /// An empty name or one with a NUL would address a different interface than named.
    #[test]
    fn empty_and_embedded_nul_names_are_refused() {
        for name in ["", "\0", "utun\0", "ut\0un1"] {
            let error = IfReq::new(name).expect_err("unusable");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{name:?}");
        }
    }

    /// The MTU is stored as a native-endian `int` at the start of the union.
    #[test]
    fn mtu_lands_in_the_union_as_an_int() {
        let request = mtu_request("utun3", 1280).expect("valid");
        assert_eq!(&request.data[..4], &1280_i32.to_ne_bytes());
        assert!(request.data[4..].iter().all(|&byte| byte == 0));
    }

    /// Bad input fails with `InvalidInput` before any socket is opened.
    #[test]
    fn zero_mtu_and_bad_names_are_refused_before_any_syscall() {
        assert_eq!(
            mtu_request("utun3", 0).expect_err("zero").kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            mtu_request("", 1280).expect_err("empty").kind(),
            io::ErrorKind::InvalidInput
        );
    }

    /// Setting flags leaves the name alone and `IFF_UP` can be added to what was read.
    #[test]
    fn flags_round_trip_and_keep_the_name() {
        let mut request = IfReq::new("utun3").expect("valid");
        request.set_flags(0x50);
        assert_eq!(request.flags(), 0x50);
        request.set_flags(request.flags() | IFF_UP);
        assert_eq!(request.flags() & IFF_UP, IFF_UP);
        assert_eq!(&request.name[..5], b"utun3");
    }

    /// The numbers must equal the ones in the macOS SDK headers, which cannot be included here.
    #[test]
    fn ioctl_numbers_match_the_macos_headers() {
        assert_eq!(IFREQ_LEN, 32);
        assert_eq!(SIOCSIFMTU, 0x8020_6934);
        assert_eq!(SIOCGIFFLAGS, 0xc020_6911);
        assert_eq!(SIOCSIFFLAGS, 0x8020_6910);
    }

    /// The layout the unsafe call relies on is the kernel's `struct ifreq`.
    #[cfg(target_os = "macos")]
    #[test]
    fn layout_matches_libc_ifreq() {
        assert_eq!(size_of::<IfReq>(), size_of::<nix::libc::ifreq>());
        assert_eq!(align_of::<IfReq>(), 1);
        assert_eq!(nix::libc::IFF_UP, i32::from(IFF_UP));
    }
}
