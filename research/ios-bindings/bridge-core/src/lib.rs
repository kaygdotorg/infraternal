//! The benchmark surface, exported to Swift with swift-bridge.
//!
//! Same six calls as the UniFFI and C ABI prototypes. swift-bridge passes
//! `&[u8]` as a borrowed pointer and length (no copy into Rust) and returns
//! `Vec<u8>` as a `RustVec<UInt8>` that Swift reads in place, so the byte
//! rows here measure the pointer crossing rather than a serialised copy.

/// The declarations swift-bridge turns into Swift functions and C glue.
#[swift_bridge::bridge]
mod ffi {
    extern "Rust" {
        fn noop();
        fn add(a: u64, b: u64) -> u64;
        fn frame_in(buf: &[u8]) -> u64;
        fn frame_out(len: u32) -> Vec<u8>;
        // swift-bridge 0.1.59 cannot bridge Result<u64, _>: its glue naming
        // hits a todo!() for U64 inside a Result. The parse row uses u32.
        // It also emits Swift that does not compile for `&str` in with a
        // Result out (a throwing closure passed as non-throwing), so the
        // input is an owned String, which Swift copies into Rust.
        fn parse(input: String) -> Result<u32, String>;
        async fn delayed_echo(ms: u64, value: u64) -> u64;
    }
}

/// Does nothing: the floor cost of one Swift-to-Rust call.
pub fn noop() {}

/// Adds two integers: scalar arguments and a scalar result.
pub fn add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// Reads a frame Swift lends us (no copy) and returns a cheap digest.
pub fn frame_in(buf: &[u8]) -> u64 {
    let first = buf.first().copied().unwrap_or(0) as u64;
    let last = buf.last().copied().unwrap_or(0) as u64;
    (buf.len() as u64) ^ (first << 32) ^ (last << 40)
}

/// Returns a frame of `len` bytes that Swift reads as a `RustVec<UInt8>`.
pub fn frame_out(len: u32) -> Vec<u8> {
    vec![0xA5; len as usize]
}

/// Parses a decimal number. swift-bridge maps `Result<_, String>` to a
/// Swift `throws` whose error is the `RustString`.
pub fn parse(input: String) -> Result<u32, String> {
    input.parse().map_err(|_| format!("not a number: {input}"))
}

/// Waits `ms` milliseconds and returns `value`. swift-bridge polls the
/// future on its own executor, which has no tokio timer, so the sleep runs
/// on a shared background runtime and the answer comes back over a
/// `oneshot` channel, whose receiver works under any executor.
pub async fn delayed_echo(ms: u64, value: u64) -> u64 {
    let (tx, rx) = tokio::sync::oneshot::channel();
    runtime().spawn(async move {
        // No timer for ms == 0: the row measures the await and wake path.
        if ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        let _ = tx.send(value);
    });
    rx.await.unwrap_or(0)
}

/// One background tokio runtime (one worker thread) for timers, created on
/// first use and kept for the life of the process.
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
