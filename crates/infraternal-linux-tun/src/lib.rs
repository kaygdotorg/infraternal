//! Opens a non-persistent Linux TUN queue and negotiates virtio TSO offloads.
//!
//! This crate is the narrow syscall boundary required by Linux TUN. The caller owns the returned
//! file descriptor and handles packet framing; this crate never changes addresses, routes, or
//! interface policy. Permission to create or attach the device requires CAP_NET_ADMIN.

use std::{
    fs::{File, OpenOptions},
    io,
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
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
    /// Attach one non-persistent TUN queue, preferring virtio metadata and TCP segmentation.
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

#[cfg(test)]
mod tests {
    use super::{IFNAMSIZ, IfReq};

    #[test]
    fn ifreq_matches_linux_abi_size() {
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
        assert_eq!(IFNAMSIZ, 16);
    }
}
