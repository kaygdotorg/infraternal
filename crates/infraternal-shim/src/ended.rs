//! Fixed-size runtime exit records preserve typed status after bounded shim retirement [D13,D218], #151.
#![forbid(unsafe_code)]

use crate::frame::Frame;
use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

/// A one-shot ceiling from child exit, never extended by reconnect or input.
pub const MAX_RETENTION: Duration = Duration::from_secs(600);
/// Exact size of an exit record file: a 4-byte little-endian length (13)
/// followed by the 13-byte encoded `Exited` frame.
const RECORD_SIZE: usize = 17;

/// Save the existing frozen Exited frame before the socket disappears.
/// # Errors
/// Refuses an existing record; session identities must never be reused.
pub fn record(socket: &Path, status: i32, final_seq: u64) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(socket.with_extension("ending"))?;
    file.write_all(&Frame::Exited(status, final_seq).encode()?)?;
    drop(file);
    std::fs::rename(
        socket.with_extension("ending"),
        socket.with_extension("ended"),
    )?;
    // A runtime record needs process-restart consistency, not reboot durability.
    // Close finishes before SocketPath removes the rendezvous; no reader sees a
    // partial record after a failed connect because the live socket still exists.
    Ok(())
}

/// Read only a regular, private, same-UID fixed-size record without following links.
/// # Errors
/// Rejects malformed, insecure or truncated records; absence means unknown status.
pub fn read(socket: &Path) -> io::Result<Option<(i32, u64)>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(socket.with_extension("ended"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != 17
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid exit record",
        ));
    }
    let mut bytes = [0; RECORD_SIZE];
    file.read_exact(&mut bytes)?;
    if bytes[..4] != 13_u32.to_le_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid exit record length",
        ));
    }
    match Frame::decode(&bytes[4..])? {
        Frame::Exited(status, seq) => Ok(Some((status, seq))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid exit record frame",
        )),
    }
}

#[cfg(test)]
mod tests {
    //! Records reuse the fuzzed frozen decoder and reject unsafe runtime files.
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn bounded_record_preserves_status_and_rejects_malformed_or_linked_data() {
        let root = std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
            ".cache/codex-scratch/session-bounds/record-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let socket = root.join("session.sock");
        assert_eq!(read(&socket).unwrap(), None);
        record(&socket, -9, u64::MAX).unwrap();
        assert_eq!(read(&socket).unwrap(), Some((-9, u64::MAX)));
        let path = socket.with_extension("ended");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&socket).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, [0; 18]).unwrap();
        assert!(read(&socket).is_err());
        fs::write(&path, [0; 17]).unwrap();
        assert!(read(&socket).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("/dev/null", &path).unwrap();
        assert!(read(&socket).is_err());
        fs::remove_dir_all(root).unwrap();
        assert_eq!(MAX_RETENTION.as_secs(), 600);
    }
}
