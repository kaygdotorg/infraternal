//! Finds which utun interfaces one person's infraternal agent holds, so the macOS mesh helper
//! replaces only its own earlier mesh route (#146, review J1027 F1).
//!
//! A utun exists exactly as long as some process holds its kernel-control socket. When the
//! helper is asked to route the mesh prefix and another utun already carries that exact prefix,
//! that utun is either an earlier mesh utun of the same agent (a restart or a rebuild that
//! overlaps) or another VPN that happens to use the same range. Matching the route alone cannot
//! tell them apart: a caller can name any prefix, and a coordinator can pick one another VPN uses
//! (J1027 F1). So the helper asks the kernel who holds the other utun.
//!
//! **The rule** (owner, 2026-11-21: "recognise our own old utun by the account holding it"):
//! a utun counts as ours only when it is held by a process whose real and effective uid are the
//! registered person's *and* whose executable is that person's installed infraternal binary. The
//! executable check is on top of the uid: a VPN app's network extension runs as the same person
//! and holds its own utun, so the uid alone would still let the mesh take that VPN's route.
//!
//! **How:** root lists every process (`proc_listallpids`), reads each one's credentials
//! (`proc_pidinfo(PROC_PIDTBSDINFO)`), and only for the person's processes running that binary
//! (`proc_pidpath`) lists their descriptors (`PROC_PIDLISTFDS`) and reads each socket's details
//! (`proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`). A utun control socket is a `PF_SYSTEM` /
//! `SYSPROTO_CONTROL` socket connected to `com.apple.net.utun_control`; its `kcsi_unit` is the
//! utun number plus one. The lookup runs only when a same-prefix utun exists, so a normal start
//! pays nothing.
//!
//! This is the second small audited place in the crate that needs `unsafe` (after
//! [`crate::macos_utun_ioctl`]): the four `libproc` calls take raw buffers. The kernel's reply
//! layout is read by [`utun_unit_from_socket_info`], plain safe code with fixed offsets that is
//! unit tested on every platform. Any reply that does not look exactly like a utun control socket
//! is ignored, so a layout mistake can only make the helper refuse a takeover, never allow one.
#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]
// The kernel calls are Mac-only, so the Linux test build sees the pure part unused.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

/// The kernel control every utun is connected to.
const UTUN_CONTROL: &[u8] = b"com.apple.net.utun_control";
/// `AF_SYSTEM` / `PF_SYSTEM` from `<sys/socket.h>`.
const AF_SYSTEM: i32 = 32;
/// `SYSPROTO_CONTROL` from `<sys/sys_domain.h>`: a kernel-control socket.
const SYSPROTO_CONTROL: i32 = 2;
/// `MAX_KCTL_NAME` from `<sys/kern_control.h>`.
const MAX_KCTL_NAME: usize = 96;

// Offsets into `struct socket_fdinfo` (`<sys/proc_info.h>`), which is `struct proc_fileinfo`
// (24 bytes) followed by `struct socket_info`. Inside `socket_info`: `struct vinfo_stat` is
// 136 bytes, then `soi_so` and `soi_pcb` (8 each), then `soi_type`, `soi_protocol` and
// `soi_family` (4 each); after ten more 2- and 4-byte fields and two 24-byte `sockbuf_info`
// come `soi_kind` and `rfu_1`, and the protocol union starts 240 bytes in. For a kernel-control
// socket the union is `struct kern_ctl_info`: five `uint32_t` fields, then `kcsi_unit`, then
// `kcsi_name[96]`.
/// Where `socket_info` starts inside `socket_fdinfo`.
const SOCKET_INFO: usize = 24;
/// `soi_protocol`.
const SOI_PROTOCOL: usize = SOCKET_INFO + 156;
/// `soi_family`.
const SOI_FAMILY: usize = SOCKET_INFO + 160;
/// `soi_proto.pri_kern_ctl.kcsi_unit`.
const KCSI_UNIT: usize = SOCKET_INFO + 240 + 20;
/// `soi_proto.pri_kern_ctl.kcsi_name`.
const KCSI_NAME: usize = KCSI_UNIT + 4;
/// The bytes the parser reads; a shorter reply is ignored.
const PARSED_LENGTH: usize = KCSI_NAME + MAX_KCTL_NAME;

/// Read a native-endian `i32` at `offset`, if the buffer holds it.
fn read_i32(info: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(
        info.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// The utun number a `PROC_PIDFDSOCKETINFO` reply describes, or `None` for any other socket.
///
/// `info` is the `struct socket_fdinfo` the kernel filled in. Only a `PF_SYSTEM` kernel-control
/// socket connected to `com.apple.net.utun_control` with a unit of at least 1 is a utun; the
/// utun number is that unit minus one (`utun_ctl_connect` in the kernel), so unit 5 is `utun4`.
#[must_use]
pub(crate) fn utun_unit_from_socket_info(info: &[u8]) -> Option<u32> {
    if info.len() < PARSED_LENGTH
        || read_i32(info, SOI_FAMILY)? != AF_SYSTEM
        || read_i32(info, SOI_PROTOCOL)? != SYSPROTO_CONTROL
    {
        return None;
    }
    let name = &info[KCSI_NAME..KCSI_NAME + MAX_KCTL_NAME];
    let end = name.iter().position(|&byte| byte == 0)?;
    if &name[..end] != UTUN_CONTROL {
        return None;
    }
    let unit = u32::from_ne_bytes(info[KCSI_UNIT..KCSI_UNIT + 4].try_into().ok()?);
    unit.checked_sub(1)
}

/// The names of every utun held by a process of `uid` that runs `executable`.
///
/// `executable` must be the canonical path of the person's installed binary; processes running
/// anything else, or with a real or effective uid other than `uid`, are skipped without looking
/// at their descriptors. Processes that exit during the walk are skipped.
///
/// # Errors
/// Reports a failure to list processes at all (the caller then refuses the takeover).
#[cfg(target_os = "macos")]
pub(crate) fn utuns_held_by(
    uid: u32,
    executable: &std::path::Path,
) -> std::io::Result<std::collections::BTreeSet<String>> {
    let mut held = std::collections::BTreeSet::new();
    for pid in all_pids()? {
        let Some((real, effective)) = credentials(pid) else {
            continue;
        };
        if real != uid || effective != uid {
            continue;
        }
        if path(pid).as_deref() != Some(executable) {
            continue;
        }
        for fd in socket_descriptors(pid) {
            if let Some(unit) = socket_info(pid, fd)
                .as_deref()
                .and_then(utun_unit_from_socket_info)
            {
                held.insert(format!("utun{unit}"));
            }
        }
    }
    Ok(held)
}

/// `PROC_PIDFDSOCKETINFO` from `<sys/proc_info.h>` (not exported by `libc`).
#[cfg(target_os = "macos")]
const PROC_PIDFDSOCKETINFO: i32 = 3;
/// Room for one `struct socket_fdinfo` (792 bytes on current macOS) with margin; the kernel
/// refuses a smaller buffer and fills in only its own size.
#[cfg(target_os = "macos")]
const SOCKET_INFO_BUFFER: usize = 1024;

/// Every process id on the Mac.
#[cfg(target_os = "macos")]
fn all_pids() -> std::io::Result<Vec<i32>> {
    use nix::libc::{c_int, c_void, proc_listallpids};
    // Processes can start between the size query and the read, so ask with room to spare and
    // retry while the answer fills the buffer.
    // SAFETY: a null buffer with size 0 only asks for the current count; nothing is written.
    let mut capacity = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if capacity <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    loop {
        let slots = usize::try_from(capacity).unwrap_or(0) + 64;
        let mut pids = vec![0 as c_int; slots];
        let bytes = c_int::try_from(slots * size_of::<c_int>())
            .map_err(|_| std::io::ErrorKind::InvalidData)?;
        // SAFETY: `pids` is a live, exclusively borrowed buffer of exactly `bytes` bytes, and
        // the kernel writes at most `bytes` bytes of `pid_t` into it. The pointer is not kept.
        let count = unsafe { proc_listallpids(pids.as_mut_ptr().cast::<c_void>(), bytes) };
        if count < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let count = usize::try_from(count).unwrap_or(0);
        if count < slots {
            pids.truncate(count);
            pids.retain(|&pid| pid > 0);
            return Ok(pids);
        }
        capacity = c_int::try_from(slots * 2).map_err(|_| std::io::ErrorKind::InvalidData)?;
    }
}

/// The real and effective uid of `pid`, or `None` if it exited or cannot be read.
#[cfg(target_os = "macos")]
fn credentials(pid: i32) -> Option<(u32, u32)> {
    use nix::libc::{PROC_PIDTBSDINFO, c_int, c_void, proc_bsdinfo, proc_pidinfo};
    let mut info = std::mem::MaybeUninit::<proc_bsdinfo>::zeroed();
    let size = c_int::try_from(size_of::<proc_bsdinfo>()).ok()?;
    // SAFETY: `info` is a live, zeroed buffer of exactly `size` bytes with the layout of
    // `struct proc_bsdinfo`, which is what `PROC_PIDTBSDINFO` writes, and at most `size` bytes.
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<c_void>(),
            size,
        )
    };
    if written != size {
        return None;
    }
    // SAFETY: the kernel filled in the whole structure (checked above), and every field of
    // `proc_bsdinfo` is a plain integer or byte array, so any bit pattern is valid.
    let info = unsafe { info.assume_init() };
    Some((info.pbi_ruid, info.pbi_uid))
}

/// The executable path of `pid`, or `None` if it exited or cannot be read.
#[cfg(target_os = "macos")]
fn path(pid: i32) -> Option<std::path::PathBuf> {
    use nix::libc::{PROC_PIDPATHINFO_MAXSIZE, c_void, proc_pidpath};
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = vec![0_u8; usize::try_from(PROC_PIDPATHINFO_MAXSIZE).ok()?];
    let size = u32::try_from(buffer.len()).ok()?;
    // SAFETY: `buffer` is a live, exclusively borrowed buffer of `size` bytes; the kernel writes
    // at most that many bytes of path into it and returns how many. The pointer is not kept.
    let written = unsafe { proc_pidpath(pid, buffer.as_mut_ptr().cast::<c_void>(), size) };
    let written = usize::try_from(written).ok().filter(|&n| n > 0)?;
    buffer.truncate(written);
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        &buffer,
    )))
}

/// The socket descriptors `pid` holds; empty if it exited or cannot be read.
#[cfg(target_os = "macos")]
fn socket_descriptors(pid: i32) -> Vec<i32> {
    use nix::libc::{
        PROC_PIDLISTFDS, PROX_FDTYPE_SOCKET, c_int, c_void, proc_fdinfo, proc_pidinfo,
    };
    // A first call with no buffer returns the room the current table needs.
    // SAFETY: a null buffer with size 0 only asks for the size; nothing is written.
    let needed = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let Ok(needed) = usize::try_from(needed) else {
        return Vec::new();
    };
    // Room for descriptors opened between the two calls.
    let slots = needed / size_of::<proc_fdinfo>() + 16;
    let mut entries = vec![
        proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        slots
    ];
    let Ok(bytes) = c_int::try_from(slots * size_of::<proc_fdinfo>()) else {
        return Vec::new();
    };
    // SAFETY: `entries` is a live, exclusively borrowed array of `slots` `proc_fdinfo` values,
    // `bytes` long, and `PROC_PIDLISTFDS` writes at most `bytes` bytes of that type into it.
    let written = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast::<c_void>(),
            bytes,
        )
    };
    let count = usize::try_from(written).unwrap_or(0) / size_of::<proc_fdinfo>();
    entries.truncate(count.min(slots));
    let socket = u32::try_from(PROX_FDTYPE_SOCKET).unwrap_or(u32::MAX);
    entries
        .into_iter()
        .filter(|entry| entry.proc_fdtype == socket)
        .map(|entry| entry.proc_fd)
        .collect()
}

/// The raw `struct socket_fdinfo` for descriptor `fd` of `pid`, or `None` if it is gone.
#[cfg(target_os = "macos")]
fn socket_info(pid: i32, fd: i32) -> Option<Vec<u8>> {
    use nix::libc::{c_int, c_void, proc_pidfdinfo};
    // u64 elements keep the buffer 8-byte aligned, as the structure's 64-bit fields expect.
    let mut buffer = vec![0_u64; SOCKET_INFO_BUFFER / 8];
    let size = c_int::try_from(SOCKET_INFO_BUFFER).ok()?;
    // SAFETY: `buffer` is a live, exclusively borrowed, 8-byte-aligned buffer of `size` bytes;
    // the kernel writes at most `size` bytes of `struct socket_fdinfo` into it and returns how
    // many. The pointer is not kept.
    let written = unsafe {
        proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            buffer.as_mut_ptr().cast::<c_void>(),
            size,
        )
    };
    let written = usize::try_from(written).ok().filter(|&n| n > 0)?;
    let bytes: Vec<u8> = buffer.iter().flat_map(|word| word.to_ne_bytes()).collect();
    Some(bytes[..written.min(bytes.len())].to_vec())
}

#[cfg(test)]
mod tests {
    //! The reply parser on every platform, and a live lookup of this process's own utun on a Mac.
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// A `socket_fdinfo` reply as the kernel writes it for a kernel-control socket.
    fn reply(family: i32, protocol: i32, name: &[u8], unit: u32) -> Vec<u8> {
        let mut info = vec![0_u8; 792];
        info[SOI_FAMILY..SOI_FAMILY + 4].copy_from_slice(&family.to_ne_bytes());
        info[SOI_PROTOCOL..SOI_PROTOCOL + 4].copy_from_slice(&protocol.to_ne_bytes());
        info[KCSI_UNIT..KCSI_UNIT + 4].copy_from_slice(&unit.to_ne_bytes());
        info[KCSI_NAME..KCSI_NAME + name.len()].copy_from_slice(name);
        info
    }

    /// A utun control socket with unit 5 is `utun4`, as `lsof` showed on the Mac VM (J1027).
    #[test]
    fn a_utun_control_socket_names_its_utun() {
        assert_eq!(
            utun_unit_from_socket_info(&reply(AF_SYSTEM, SYSPROTO_CONTROL, UTUN_CONTROL, 5)),
            Some(4)
        );
    }

    /// Any other socket, another kernel control, a name that only starts like ours, unit 0, or
    /// a short reply is not a utun, so it can never make a foreign utun look like ours.
    #[test]
    fn anything_else_is_not_a_utun() {
        for info in [
            reply(2, SYSPROTO_CONTROL, UTUN_CONTROL, 5),
            reply(AF_SYSTEM, 1, UTUN_CONTROL, 5),
            reply(
                AF_SYSTEM,
                SYSPROTO_CONTROL,
                b"com.apple.net.ipsec_control",
                5,
            ),
            reply(
                AF_SYSTEM,
                SYSPROTO_CONTROL,
                b"com.apple.net.utun_controlx",
                5,
            ),
            reply(AF_SYSTEM, SYSPROTO_CONTROL, UTUN_CONTROL, 0),
        ] {
            assert_eq!(utun_unit_from_socket_info(&info), None);
        }
        let short = reply(AF_SYSTEM, SYSPROTO_CONTROL, UTUN_CONTROL, 5);
        assert_eq!(
            utun_unit_from_socket_info(&short[..PARSED_LENGTH - 1]),
            None
        );
        // A name that fills all 96 bytes has no terminator and is refused.
        assert_eq!(
            utun_unit_from_socket_info(&reply(AF_SYSTEM, SYSPROTO_CONTROL, &[b'a'; 96], 5)),
            None
        );
    }

    /// The offsets match the kernel's real layout: a utun this process opens is found among
    /// its own descriptors under the name the kernel gives it. Needs root to open a utun.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "Run on the macOS VM as root: opens a utun."]
    fn this_process_finds_its_own_utun() {
        let open = crate::macos_node::OpenUtun::open_kernel().expect("open a utun (needs root)");
        let pid = i32::try_from(std::process::id()).unwrap();
        let own = path(pid).expect("own path");
        let uid = nix::unistd::Uid::current().as_raw();
        let held = utuns_held_by(uid, &own).expect("walk processes");
        assert!(held.contains(&open.name), "{} not in {held:?}", open.name);
        // Another executable path never matches, even for the same account.
        let other = utuns_held_by(uid, std::path::Path::new("/usr/bin/true")).unwrap();
        assert!(!other.contains(&open.name), "{other:?}");
    }
}
