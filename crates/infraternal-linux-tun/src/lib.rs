//! Opens a Linux TUN queue, negotiates virtio TSO offloads and marks the interface persistent.
//!
//! A TUN is non-persistent when opened: it disappears with the last descriptor. The caller makes
//! it persistent once it has marked it as its own, so the interface, its addresses and routes
//! survive a process restart (D332), and reattaches to it by name after a restart.
//!
//! This crate is the narrow syscall boundary required by Linux TUN. The caller owns the returned
//! file descriptor and handles packet framing; this crate never changes addresses, routes, or
//! interface policy. Permission to create or attach the device requires CAP_NET_ADMIN.
//!
//! Every queue this crate opens restricts its interface to the caller's effective user and group
//! (`TUNSETOWNER`, `TUNSETGROUP`). A persistent TUN with no owner admits any local user's attach
//! once its last queue closes, and that user would read and inject the interface's packets
//! (#260 J213 P1).
//!
//! It also holds the one socket option the userspace mesh engine needs and no safe crate
//! offers on Linux: [`allow_ipv4_fragmentation`] for the encrypted underlay socket (#483).

use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::OpenOptionsExt,
    },
};

const IFNAMSIZ: usize = 16;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_VNET_HDR: libc::c_short = 0x4000;
const TUN_F_CSUM: libc::c_ulong = 0x01;
const TUN_F_TSO4: libc::c_ulong = 0x02;
const TUN_F_TSO6: libc::c_ulong = 0x04;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54d0;
const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;
const TUNSETOWNER: libc::c_ulong = 0x4004_54cc;
const TUNSETGROUP: libc::c_ulong = 0x4004_54ce;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

const _: () = assert!(std::mem::size_of::<IfReq>() == 40);

/// An open TUN queue and the features accepted by the kernel.
pub struct Device {
    file: File,
    name: String,
    vnet_header: bool,
    offloads_enabled: bool,
}

impl Device {
    /// Attach one TUN queue, creating the interface if it does not exist, preferring virtio
    /// metadata and TCP segmentation.
    ///
    /// If the kernel rejects the virtio header, this retries once with ordinary TUN frames. If
    /// the header works but TSO is unavailable, the caller can still segment in software.
    /// # Errors
    /// Reports invalid interface names, device access, TUNSETIFF, or file-open failures.
    pub fn open(name: &str) -> io::Result<Self> {
        match Self::open_mode(name, true) {
            Ok(device) => Ok(device),
            Err(vnet_error) => Self::open_mode(name, false).map_err(|_| vnet_error),
        }
    }

    /// Keep the interface after its last descriptor closes (`on`), or let it go with it.
    ///
    /// Opening a persistent interface by name later attaches to it; the kernel refuses the attach
    /// with `EBUSY` while another descriptor still holds its single queue.
    /// # Errors
    /// Reports a TUNSETPERSIST failure.
    pub fn set_persistent(file: &File, on: bool) -> io::Result<()> {
        // SAFETY: TUNSETPERSIST takes an integer value, not a pointer, on a TUN descriptor that
        // TUNSETIFF attached; the kernel refuses any other descriptor.
        let status = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                TUNSETPERSIST as _,
                libc::c_ulong::from(on),
            )
        };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Consume this owner and return its nonblocking descriptor.
    #[must_use]
    pub fn into_file(self) -> File {
        self.file
    }

    /// Name of the interface requested from TUNSETIFF.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the queue includes a virtio network header on each frame.
    #[must_use]
    pub const fn has_vnet_header(&self) -> bool {
        self.vnet_header
    }

    /// Whether the kernel accepted checksum and TCP segmentation offloads.
    #[must_use]
    pub const fn offloads_enabled(&self) -> bool {
        self.offloads_enabled
    }

    fn open_mode(name: &str, vnet_header: bool) -> io::Result<Self> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= IFNAMSIZ || bytes.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open("/dev/net/tun")?;
        let mut request = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI | if vnet_header { IFF_VNET_HDR } else { 0 },
            padding: [0; 22],
        };
        for (slot, byte) in request.name.iter_mut().zip(bytes) {
            *slot = *byte as libc::c_char;
        }
        // SAFETY: TUNSETIFF expects a Linux ifreq. IfReq has the 16-byte name, 2-byte flags,
        // and 22-byte padding for the 24-byte kernel union; its ABI size is asserted above.
        let status = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &mut request) };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        let vnet_header = vnet_header && request.flags & IFF_VNET_HDR != 0;
        if !vnet_header && request.flags & IFF_VNET_HDR != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        restrict_to_caller(&file)?;
        let offloads_enabled = if vnet_header {
            // SAFETY: TUNSETOFFLOAD takes a value bitmask, not a pointer. The kernel validates
            // the requested checksum and TCP segmentation flags and returns an error if absent.
            unsafe {
                libc::ioctl(
                    file.as_raw_fd(),
                    TUNSETOFFLOAD as _,
                    TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6,
                ) == 0
            }
        } else {
            false
        };
        Ok(Self {
            file,
            name: name.to_owned(),
            vnet_header,
            offloads_enabled,
        })
    }
}

/// Admit only the caller's effective user and group to the attached interface, before the
/// caller can make it persistent. Setting them again on a reattached interface is harmless.
fn restrict_to_caller(file: &File) -> io::Result<()> {
    // SAFETY: geteuid and getegid take no arguments, cannot fail and touch no memory.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    for (request, id) in [(TUNSETOWNER, uid), (TUNSETGROUP, gid)] {
        // SAFETY: TUNSETOWNER and TUNSETGROUP take an integer value, not a pointer, on a TUN
        // descriptor that TUNSETIFF attached; the kernel refuses any other descriptor.
        let status =
            unsafe { libc::ioctl(file.as_raw_fd(), request as _, libc::c_ulong::from(id)) };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Let routers fragment the mesh's encrypted IPv4 packets instead of dropping them.
///
/// Linux UDP sockets set Don't Fragment by default. A router whose next link is smaller than
/// the packet must then drop it and send back "fragmentation needed"; many networks block
/// that ICMP, so large mesh packets vanish while small ones (pings, handshakes) still pass and
/// the path looks healthy (a PMTU black hole, #483 `mtu-576-icmp-blocked`). Kernel WireGuard
/// sends with DF clear for exactly this reason; this gives the userspace engine the same
/// behaviour. IPv6 has no in-network fragmentation, so only the IPv4 option is set. It applies
/// to IPv4 traffic on a dual-stack IPv6 socket too.
///
/// Call it once on the bound underlay socket, before it sends. Linux only: macOS spells the
/// option differently and its engine binds its own socket.
/// # Errors
/// Returns the kernel's error if the descriptor is not an IP socket.
#[cfg(target_os = "linux")]
pub fn allow_ipv4_fragmentation(socket: &impl AsFd) -> io::Result<()> {
    let value: libc::c_int = libc::IP_PMTUDISC_DONT;
    // SAFETY: IP_MTU_DISCOVER reads one c_int from the pointer for the length given; `value`
    // lives on this stack frame for the whole call, and the descriptor is borrowed, so open.
    let status = unsafe {
        libc::setsockopt(
            socket.as_fd().as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            std::ptr::from_ref(&value).cast(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        )
    };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Checks the ioctl structure layout and the underlay socket option against the running kernel.
#[cfg(test)]
mod tests {
    use super::{IFNAMSIZ, IfReq};

    /// Linux-only checks for the underlay socket option.
    #[cfg(target_os = "linux")]
    mod fragmentation {
        use super::super::allow_ipv4_fragmentation;
        use std::os::fd::AsRawFd;

        /// Read back IP_MTU_DISCOVER so the test sees what the kernel stored.
        fn mtu_discover(socket: &std::net::UdpSocket) -> libc::c_int {
            let mut value: libc::c_int = -1;
            let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
            // SAFETY: the kernel writes at most `length` bytes into `value`, which outlives the call.
            let status = unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    std::ptr::from_mut(&mut value).cast(),
                    &raw mut length,
                )
            };
            assert_eq!(status, 0, "{}", std::io::Error::last_os_error());
            value
        }

        /// A fresh UDP socket sets DF; after the call the kernel stores "never set DF", for IPv4
        /// and dual-stack IPv6 sockets alike.
        #[test]
        fn underlay_sockets_stop_setting_dont_fragment() {
            for address in ["127.0.0.1:0", "[::]:0"] {
                let Ok(socket) = std::net::UdpSocket::bind(address) else {
                    continue; // a host without IPv6 still checks the IPv4 socket
                };
                assert_ne!(
                    mtu_discover(&socket),
                    libc::IP_PMTUDISC_DONT,
                    "{address}: default sets DF"
                );
                allow_ipv4_fragmentation(&socket).unwrap();
                assert_eq!(mtu_discover(&socket), libc::IP_PMTUDISC_DONT, "{address}");
            }
        }
    }

    #[test]
    fn ifreq_matches_linux_abi_size() {
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
        assert_eq!(IFNAMSIZ, 16);
    }
}
