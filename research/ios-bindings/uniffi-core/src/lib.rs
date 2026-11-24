//! The benchmark surface, exported to Swift with UniFFI proc macros.
//!
//! Every binding prototype in `research/ios-bindings` exports the same six
//! calls, so the Swift harness can time them side by side:
//! a no-op, a scalar add, a byte buffer in, a byte buffer out, a fallible
//! parse that maps to a Swift `throws`, and an async call that awaits a timer.
//! UniFFI serialises `Vec<u8>` into a `RustBuffer`, so bytes are copied once
//! in each direction; that copy is what the byte-buffer rows measure.

uniffi::setup_scaffolding!();

/// An error the Swift side receives as a thrown `CoreError`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    /// The input was not a decimal unsigned integer.
    #[error("not a number: {input}")]
    NotANumber {
        /// The text that failed to parse.
        input: String,
    },
}

/// Does nothing: the floor cost of one Swift-to-Rust call.
#[uniffi::export]
pub fn noop() {}

/// Adds two integers: a call with scalar arguments and a scalar result.
#[uniffi::export]
pub fn add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// Reads a whole frame sent from Swift and returns a cheap digest of it,
/// so the call cannot be optimised away but the work stays negligible.
#[uniffi::export]
pub fn frame_in(buf: Vec<u8>) -> u64 {
    digest(&buf)
}

/// Returns a frame of `len` bytes to Swift (Rust allocates, Swift receives
/// `Data`).
#[uniffi::export]
pub fn frame_out(len: u32) -> Vec<u8> {
    vec![0xA5; len as usize]
}

/// Parses a decimal number; text that is not a number becomes a thrown error.
#[uniffi::export]
pub fn parse(input: String) -> Result<u64, CoreError> {
    input.parse().map_err(|_| CoreError::NotANumber { input })
}

/// Runs a task on the core's background runtime and awaits its answer:
/// Swift awaits it as `async`. With `ms == 0` there is no timer, so the
/// async row measures the bridge's await and cross-thread wake, not tokio's
/// 1 ms timer granularity.
#[uniffi::export]
pub async fn delayed_echo(ms: u64, value: u64) -> u64 {
    let (tx, rx) = tokio::sync::oneshot::channel();
    runtime().spawn(async move {
        if ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        let _ = tx.send(value);
    });
    rx.await.unwrap_or(0)
}

/// One background tokio runtime (one worker thread), created on first use.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .build()
            .expect("tokio runtime")
    })
}

/// Length, first and last byte folded together: touches both ends of the
/// buffer without scanning it.
fn digest(buf: &[u8]) -> u64 {
    let first = buf.first().copied().unwrap_or(0) as u64;
    let last = buf.last().copied().unwrap_or(0) as u64;
    (buf.len() as u64) ^ (first << 32) ^ (last << 40)
}
