//! Abstracts an already-authenticated leg-B byte channel; inherited socket trust and remote mTLS admission stay with callers [9][64], #78.

use std::{future::Future, io};

/// A full-duplex channel with exactly one reader and one serialized writer.
/// Implementations retain partial-read progress; cancellation of a partial write
/// requires retiring the entire connection to avoid frame interleaving.
pub trait Channel: Send + Sync {
    /// Native QUIC channels carry raw frames for one externally bound writer.
    /// TCP and inherited sockets retain the unchanged mux envelope.
    fn native_stream_id(&self) -> Option<u32> {
        None
    }

    /// Active incomplete-frame budget; inherited trusted channels have none.
    /// Remote adapters supply five seconds. Wholly idle reads arm no timer.
    fn frame_timeout(&self) -> Option<std::time::Duration> {
        None
    }
    /// Retire all directions after partial-frame expiry; remote adapters wake readers/writers.
    fn retire(&self) {}
    /// Read ready bytes; an empty result is EOF.
    fn read(&self, bytes: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
    /// Complete one already-encoded bounded frame.
    fn write(&self, bytes: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}

/// Native writer binding capability; independent of the browser resume bit.
pub const REMOTE_WRITER_BINDING: u64 = 1 << 1;
/// Live certificate renewal capability on the authenticated control channel.
pub const LIVE_RENEWAL: u64 = 1 << 2;
/// Durable candidate-key and reconnect-acknowledgment capability [285].
pub const LIVE_IDENTITY_ROTATION: u64 = 1 << 8;
/// Bound for a single decoded control reply or renewal proof.
pub const MAX_CONTROL_JSON: usize = 32_768;
/// Per-connection relay metadata reserve, independent of host session admission.
/// At 200 idle relay tasks the weighted release measurement was 5,140 private
/// bytes per stream, including paired fixture overhead. A 32 KiB allowance gives
/// over six times that measured cost inside a 4 MiB reserve (D214), #151.
/// Payload storage is separately bounded by frame, queue and QUIC byte limits;
/// this reserve does not claim to include full payload buffers. u32 stream IDs
/// retain their protocol range; this limits concurrent streams on one connection.
pub const MAX_TERMINAL_STREAMS: usize = (4 * 1024 * 1024) / (32 * 1024);
/// The peer accepts additive applied server-path proposals from its node plugins [215].
pub const SERVER_PATH_PROPOSALS: u64 = 1 << 3;

/// The server can park an enrolled fallback without replacing its active host actor [215].
pub const REMOTE_STANDBY: u64 = 1 << 4;

/// Native standby writers can share durable shim cursors before path activation [215].
/// Both peers negotiate this bit before using the bounded per-writer cursor request.
pub const REMOTE_PRIMED_WRITERS: u64 = 1 << 5;

/// Both enrolled peers support bounded encrypted copies over the retained path
/// below the same native QUIC connection [215,263]. This grants no authority.
pub const REMOTE_PATH_BACKUP: u64 = 1 << 6;

/// Both native peers support session-bound authenticated physical path responses
/// independent of encrypted backups. This bit grants no host or writer authority.
pub const REMOTE_PATH_PROOF: u64 = 1 << 7;

/// Native plugin lanes cannot alias the reserved leg-B core capability bits 0–7.
/// A new core bit must stay below this one (`native_lanes_start_above_every_core_leg_b_bit`).
pub const MIN_NATIVE_STREAM_CAPABILITY: u64 = 1 << 8;
