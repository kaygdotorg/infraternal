//! Reads public kernel handshake timestamps from the fixture's node through an inherited socket, without polling during the measured join [243,263].
use infraternal_plugin_mesh::{policy::model::PublicKey, wireguard::Device};
use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The child borrows its inherited descriptor through the existing safe channel
/// adapter. Identity still travels exclusively through the separate private pipe.
pub(super) async fn serve(fd: i32, server_key: PublicKey) -> io::Result<()> {
    let socket = infraternal_agent::transport::Socket::inherited(fd)?;
    loop {
        let mut request = [0; 1];
        if socket.read(&mut request).await? == 0 {
            return Ok(());
        }
        if request != *b"h" {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let counters = Device::counters()?;
        let server = counters.get(&server_key).ok_or(io::ErrorKind::NotFound)?;
        let mut reply = [0; 12];
        reply[..8].copy_from_slice(&server.handshake_secs.to_le_bytes());
        reply[8..].copy_from_slice(&server.handshake_nanos.to_le_bytes());
        socket.write(&reply).await?;
    }
}

/// Query after the first mesh byte has already arrived. A kernel timestamp
/// retains its precision without adding a polling worker to either namespace.
pub(super) async fn handshake(socket: &mut tokio::net::UnixStream) -> io::Result<SystemTime> {
    socket.write_all(b"h").await?;
    let mut reply = [0; 12];
    socket.read_exact(&mut reply).await?;
    decode(&reply)
}

fn decode(reply: &[u8; 12]) -> io::Result<SystemTime> {
    let seconds = u64::from_le_bytes(reply[..8].try_into().map_err(io::Error::other)?);
    let nanos = u32::from_le_bytes(reply[8..].try_into().map_err(io::Error::other)?);
    if nanos >= 1_000_000_000 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    UNIX_EPOCH
        .checked_add(Duration::new(seconds, nanos))
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
mod tests {
    //! The fixed public reply preserves precision and refuses nanosecond normalization.
    use super::*;

    #[test]
    fn timestamp_reply_preserves_nanoseconds() {
        let mut reply = [0; 12];
        reply[..8].copy_from_slice(&42_u64.to_le_bytes());
        reply[8..].copy_from_slice(&987_654_321_u32.to_le_bytes());
        assert_eq!(
            decode(&reply).unwrap(),
            UNIX_EPOCH + Duration::new(42, 987_654_321)
        );
        reply[8..].copy_from_slice(&1_000_000_000_u32.to_le_bytes());
        assert!(decode(&reply).is_err());
    }
}
