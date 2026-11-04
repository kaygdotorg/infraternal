//! Original process-pin transport and bounded startup identity [D240,D247].
#![forbid(unsafe_code)]
use std::io;

pub const LENGTH: usize = 12;
const MAGIC: &[u8; 4] = b"ILR1";

/// A record is trusted only on the controller's original launch socket, never
/// when supplied by an account socket, a file or a browser request.
#[derive(Debug, PartialEq, Eq)]
pub struct Ready {
    pub pid: i32,
    pub uid: u32,
}

/// Encode only positive kernel PIDs with their actual effective account.
/// # Errors
/// Refuses a non-process identifier.
pub fn encode(pid: i32, uid: u32) -> io::Result<[u8; LENGTH]> {
    if pid <= 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = [0; LENGTH];
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4..8].copy_from_slice(&pid.to_le_bytes());
    bytes[8..].copy_from_slice(&uid.to_le_bytes());
    Ok(bytes)
}

/// Decode the bounded record without allocation or partially accepted identity.
/// # Errors
/// Refuses wrong magic, length and nonpositive PIDs.
pub fn decode(bytes: &[u8]) -> io::Result<Ready> {
    if bytes.len() != LENGTH || &bytes[..4] != MAGIC {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let pid = i32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?,
    );
    let uid = u32::from_le_bytes(
        bytes[8..]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?,
    );
    if pid <= 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Ready { pid, uid })
}

/// Receive the original worker's process descriptor over the private launch socket.
/// # Errors
/// Refuses missing, truncated or extra descriptors and malformed records.
#[cfg(target_os = "linux")]
pub fn receive(peer: &impl std::os::fd::AsRawFd) -> io::Result<(Ready, std::fs::File)> {
    crate::pty::receive_login_ready(peer)
}
/// Darwin session launch is outside this slice, so it cannot accept worker identity records.
/// # Errors
/// Always reports unsupported while the Darwin session shim is compiled out.
#[cfg(target_os = "macos")]
pub fn receive(_peer: &impl std::os::fd::AsRawFd) -> io::Result<(Ready, std::fs::File)> {
    Err(io::ErrorKind::Unsupported.into())
}

/// Identify child-local process pins without touching descriptors or files.
/// External controller-held paths have no descriptor in this process to protect.
/// # Errors
/// Refuses malformed local paths, overflow and standard/reserved startup slots.
pub fn inherited_pin_descriptor(path: &std::path::Path) -> io::Result<Option<i32>> {
    let Ok(suffix) = path.strip_prefix("/proc/self/fd") else {
        return Ok(None);
    };
    suffix
        .to_str()
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|descriptor| *descriptor >= 5)
        .map(Some)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    //! Wire shape and malformed identity are checked independently of launch policy.
    use super::*;
    #[test]
    fn inherited_pin_paths_reject_reserved_and_non_numeric_slots() {
        use std::path::Path;
        for slot in [5, 8, 4096, i32::MAX] {
            assert_eq!(
                inherited_pin_descriptor(Path::new(&format!("/proc/self/fd/{slot}"))).unwrap(),
                Some(slot)
            );
        }
        for suffix in ["", "3", "4", "-5", "+5", "8/stat", "2147483648", "8\0"] {
            assert!(
                inherited_pin_descriptor(Path::new(&format!("/proc/self/fd/{suffix}"))).is_err()
            );
        }
        assert_eq!(
            inherited_pin_descriptor(Path::new("/proc/123/fd/8")).unwrap(),
            None
        );
    }
    fn send(peer: &std::os::unix::net::UnixStream, bytes: &[u8], descriptors: &[i32]) {
        use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
        use std::os::fd::AsRawFd;
        sendmsg::<()>(
            peer.as_raw_fd(),
            &[std::io::IoSlice::new(bytes)],
            &[ControlMessage::ScmRights(descriptors)],
            MsgFlags::MSG_NOSIGNAL,
            None,
        )
        .unwrap();
    }
    #[test]
    fn original_process_descriptor_is_required_and_owned_with_cloexec() {
        use std::os::fd::AsRawFd;
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let bytes = encode(i32::try_from(std::process::id()).unwrap(), 0).unwrap();
        send(&writer, &bytes, &[]);
        assert!(
            receive(&reader).is_err(),
            "numeric PID alone must never admit a login"
        );
        let process = std::fs::File::open("/proc/self").unwrap();
        send(&writer, &bytes, &[process.as_raw_fd(), process.as_raw_fd()]);
        assert!(receive(&reader).is_err());
        send(&writer, &bytes, &[process.as_raw_fd()]);
        let (record, pin) = receive(&reader).unwrap();
        assert_eq!(record.pid, i32::try_from(std::process::id()).unwrap());
        assert!(
            std::fs::read_to_string(format!("/proc/self/fd/{}/stat", pin.as_raw_fd()))
                .unwrap()
                .starts_with(&format!("{} ", record.pid))
        );
        assert!(
            nix::fcntl::FdFlag::from_bits_retain(
                nix::fcntl::fcntl(&pin, nix::fcntl::FcntlArg::F_GETFD).unwrap()
            )
            .contains(nix::fcntl::FdFlag::FD_CLOEXEC)
        );
    }
    #[test]
    fn descriptor_announced_before_exit_stays_dead_after_receipt() {
        use std::os::fd::AsRawFd;
        let (reader, writer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let pid = child.id();
        let process = std::fs::File::open(format!("/proc/{pid}")).unwrap();
        send(
            &writer,
            &encode(i32::try_from(pid).unwrap(), 0).unwrap(),
            &[process.as_raw_fd()],
        );
        child.kill().unwrap();
        child.wait().unwrap();
        let (_, original) = receive(&reader).unwrap();
        assert!(
            std::fs::read_to_string(format!("/proc/self/fd/{}/stat", original.as_raw_fd()))
                .is_err()
        );
    }
    #[test]
    fn exact_kernel_identity_round_trips_and_invalid_envelopes_are_refused() {
        let bytes = encode(123, 1000).unwrap();
        assert_eq!(bytes, *b"ILR1\x7b\0\0\0\xe8\x03\0\0");
        assert_eq!(
            decode(&bytes).unwrap(),
            Ready {
                pid: 123,
                uid: 1000
            }
        );
        for length in 0..LENGTH {
            assert!(decode(&bytes[..length]).is_err());
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(decode(&extra).is_err());
        for pid in [0_i32, -1, i32::MIN] {
            assert!(encode(pid, 1000).is_err());
            let mut bad = bytes;
            bad[4..8].copy_from_slice(&pid.to_le_bytes());
            assert!(decode(&bad).is_err());
        }
        let mut wrong = bytes;
        wrong[0] ^= 1;
        assert!(decode(&wrong).is_err());
    }
}
