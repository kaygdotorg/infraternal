//! The benchmark surface as a hand-written C ABI; cbindgen writes the header.
//!
//! Same six calls as the UniFFI and swift-bridge prototypes, done the way a
//! hand ABI would do a frame path: bytes in are a borrowed pointer and
//! length, bytes out are written into a buffer the caller owns (no
//! allocation per call), errors are a status code plus an out-parameter, and
//! async is a completion callback that Swift wraps in a continuation. Panics
//! are caught at the boundary and reported as a status code.

use std::ffi::c_void;
use std::panic::catch_unwind;

/// Result codes every fallible call returns.
#[repr(C)]
pub enum CabiStatus {
    /// The call succeeded and its out-parameters are set.
    Ok = 0,
    /// The input text was not a decimal number.
    NotANumber = 1,
    /// Rust panicked; the process state is still sound.
    Panic = 2,
}

/// Does nothing: the floor cost of one Swift-to-Rust call.
#[unsafe(no_mangle)]
pub extern "C" fn cabi_noop() {}

/// Adds two integers: scalar arguments and a scalar result.
#[unsafe(no_mangle)]
pub extern "C" fn cabi_add(a: u64, b: u64) -> u64 {
    a.wrapping_add(b)
}

/// Reads `len` bytes at `ptr`, which Swift lends for the call, and returns a
/// cheap digest.
///
/// # Safety
/// `ptr` must point to `len` readable bytes, or be null with `len == 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_frame_in(ptr: *const u8, len: usize) -> u64 {
    let buf = if ptr.is_null() { &[][..] } else { unsafe { std::slice::from_raw_parts(ptr, len) } };
    let first = buf.first().copied().unwrap_or(0) as u64;
    let last = buf.last().copied().unwrap_or(0) as u64;
    (buf.len() as u64) ^ (first << 32) ^ (last << 40)
}

/// Fills the caller's buffer with a frame of up to `cap` bytes and returns
/// how many bytes it wrote. The caller reuses the buffer every frame.
///
/// # Safety
/// `out` must point to `cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_frame_out(out: *mut u8, cap: usize, len: u32) -> usize {
    let n = (len as usize).min(cap);
    unsafe { std::ptr::write_bytes(out, 0xA5, n) };
    n
}

/// Parses a NUL-free UTF-8 decimal string of `len` bytes into `*value`.
///
/// # Safety
/// `ptr` must point to `len` readable bytes and `value` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_parse(ptr: *const u8, len: usize, value: *mut u64) -> CabiStatus {
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    match catch_unwind(|| std::str::from_utf8(bytes).ok().and_then(|s| s.parse::<u64>().ok())) {
        Ok(Some(v)) => {
            unsafe { *value = v };
            CabiStatus::Ok
        }
        Ok(None) => CabiStatus::NotANumber,
        Err(_) => CabiStatus::Panic,
    }
}

/// The completion Swift passes to [`cabi_delayed_echo`]; called exactly once,
/// on a Rust runtime thread, with the caller's `ctx` and the result.
pub type CabiEchoDone = extern "C" fn(ctx: *mut c_void, value: u64);

/// Waits `ms` milliseconds on a background runtime, then calls `done(ctx,
/// value)` exactly once.
#[unsafe(no_mangle)]
pub extern "C" fn cabi_delayed_echo(ms: u64, value: u64, ctx: *mut c_void, done: CabiEchoDone) {
    // Raw pointers are not Send; the address travels as an integer and the
    // caller guarantees `ctx` stays valid until `done` runs.
    let ctx = ctx as usize;
    runtime().spawn(async move {
        // No timer for ms == 0: the row measures the await and wake path.
        if ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        done(ctx as *mut c_void, value);
    });
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
