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

/// Reads the 12-byte reply: 8 bytes of seconds and 4 bytes of nanoseconds, both little-endian, since the Unix epoch. Nanoseconds of one second or more are rejected.
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

/// Each proof creates a fresh kernel peer. Its first handshake must belong to
/// this enable cycle and precede the authenticated mesh connection. The kernel
/// stores only the latest handshake: reject inconsistent timestamps, long
/// cycles and wall/monotonic disagreement. A second handshake before TLS cannot
/// be distinguished from the first by this API; the short fresh-peer lifecycle
/// avoids scheduled rekeying rather than claiming to recover kernel history.
/// `tls` is absent when the existing connection moved without a new handshake.
pub(super) fn validate_lifecycle(
    enabled: SystemTime,
    joined: SystemTime,
    tls: Option<SystemTime>,
    output: SystemTime,
    elapsed: Duration,
) -> io::Result<()> {
    let wall_elapsed = output.duration_since(enabled).map_err(io::Error::other)?;
    let tls_ordered = tls.is_none_or(|tls| joined <= tls && tls <= output);
    if joined < enabled
        || joined > output
        || !tls_ordered
        || elapsed >= Duration::from_secs(60)
        || wall_elapsed.abs_diff(elapsed) > Duration::from_millis(5)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mesh timing lifecycle or clock comparison is invalid",
        ));
    }
    Ok(())
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

    #[test]
    fn lifecycle_rejects_overwritten_handshakes_and_clock_steps() {
        let start = UNIX_EPOCH + Duration::from_secs(100);
        let joined = start + Duration::from_secs(1);
        let tls = start + Duration::from_secs(2);
        let output = start + Duration::from_secs(3);
        assert!(
            validate_lifecycle(start, joined, Some(tls), output, Duration::from_secs(3)).is_ok()
        );
        assert!(
            validate_lifecycle(
                start,
                start - Duration::from_secs(1),
                Some(tls),
                output,
                Duration::from_secs(3)
            )
            .is_err()
        );
        assert!(
            validate_lifecycle(
                start,
                tls + Duration::from_nanos(1),
                Some(tls),
                output,
                Duration::from_secs(3)
            )
            .is_err()
        );
        assert!(
            validate_lifecycle(start, joined, Some(output), tls, Duration::from_secs(2)).is_err()
        );
        assert!(
            validate_lifecycle(start, joined, Some(tls), output, Duration::from_secs(2)).is_err()
        );
        // A preserved connection has no new handshake but keeps the ordering.
        assert!(validate_lifecycle(start, joined, None, output, Duration::from_secs(3)).is_ok());
        assert!(
            validate_lifecycle(
                start,
                output + Duration::from_nanos(1),
                None,
                output,
                Duration::from_secs(3)
            )
            .is_err()
        );
        assert!(
            validate_lifecycle(
                start,
                joined,
                Some(tls),
                start + Duration::from_secs(60),
                Duration::from_secs(60)
            )
            .is_err()
        );
    }
}
