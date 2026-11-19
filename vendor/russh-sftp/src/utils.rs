//! Converts file timestamps to SFTP seconds and reads bounded protocol packets.

use bytes::Bytes;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::Error;

/// Return whole Unix seconds modulo 2^32, as required by SFTP v3 timestamps.
///
/// Negative fractional seconds round toward the preceding second, preserving
/// the former timestamp conversion before wrapping into the wire's u32 field.
pub(crate) fn unix(time: SystemTime) -> u32 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as u32,
        Err(error) => {
            let duration = error.duration();
            0_u32
                .wrapping_sub(duration.as_secs() as u32)
                .wrapping_sub(u32::from(duration.subsec_nanos() != 0))
        }
    }
}

/// Read one length-prefixed packet, refusing payloads above the caller's limit.
pub(crate) async fn read_packet<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_length: u32,
) -> Result<Bytes, Error> {
    let length = stream.read_u32().await?;
    if length > max_length {
        return Err(Error::BadMessage("packet length limit exceeded".to_owned()));
    }

    let mut buf = vec![0; length as usize];
    stream.read_exact(&mut buf).await?;

    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    //! Pin the floor-and-wrap conversion at the epoch and wire-range boundaries.

    use super::unix;
    use std::time::{Duration, UNIX_EPOCH};

    /// Match the prior Unix-seconds conversion, including negative fractions.
    #[test]
    fn unix_seconds_preserve_epoch_floor_and_wire_wrapping() {
        let cases = [
            (UNIX_EPOCH, 0),
            (UNIX_EPOCH + Duration::from_nanos(999_999_999), 0),
            (UNIX_EPOCH + Duration::from_secs(1), 1),
            (UNIX_EPOCH - Duration::from_nanos(1), u32::MAX),
            (UNIX_EPOCH - Duration::from_secs(1), u32::MAX),
            (UNIX_EPOCH - Duration::new(1, 1), u32::MAX - 1),
            (
                UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX)),
                u32::MAX,
            ),
            (UNIX_EPOCH + Duration::from_secs(1_u64 << 32), 0),
            (UNIX_EPOCH + Duration::new((1_u64 << 32) + 42, 123), 42),
            (
                UNIX_EPOCH - Duration::new((1_u64 << 32) + 42, 123),
                u32::MAX - 42,
            ),
        ];
        for (time, expected) in cases {
            assert_eq!(unix(time), expected, "timestamp {time:?}");
        }
    }
}
