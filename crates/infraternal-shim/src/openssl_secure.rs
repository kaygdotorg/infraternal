//! Initializes the existing OpenSSL secure allocator once, before server private keys; syscalls and provider allocation stay behind this audited FFI boundary [40,168], #154.
#![allow(unsafe_code)]

use std::sync::OnceLock;

unsafe extern "C" {
    /// OpenSSL's secure-heap initializer. Returns 1 when the heap is locked and
    /// excluded from core dumps, 2 when it works without that protection, 0 on
    /// failure.
    fn CRYPTO_secure_malloc_init(size: usize, minsize: i32) -> i32;
    /// OpenSSL's count of bytes currently allocated from the secure heap.
    fn CRYPTO_secure_used() -> usize;
    /// OpenSSL's library initializer: `opts` are `OPENSSL_INIT_*` bits, `settings` may be
    /// null. Returns 1 on success.
    fn OPENSSL_init_crypto(opts: u64, settings: *const std::ffi::c_void) -> i32;
}

/// `OPENSSL_INIT_NO_ATEXIT`: never register `OPENSSL_cleanup` with `atexit`.
const OPENSSL_INIT_NO_ATEXIT: u64 = 0x0008_0000;

/// Make sure OpenSSL never frees its global state at process exit (#578). Call it first thing
/// in `main`, before any thread exists; it returns whether OpenSSL accepted it.
///
/// OpenSSL decides once per process, at its first initialization, whether `exit` runs
/// `OPENSSL_cleanup`, and some `openssl` crate calls (X25519 key generation, for one)
/// initialize without opting out. Then an infraternal agent that returned from `main` while
/// its plugin thread was still freeing OpenSSL objects had OpenSSL's tables freed under that
/// thread, and musl's `free` crashed. This asks for nothing but that decision: unlike
/// `openssl::init()` it loads no configuration, error strings or algorithms, which measured
/// 0.57 ms on every command start. Later full initializations keep the decision.
#[must_use]
pub fn disable_exit_cleanup() -> bool {
    // SAFETY: a plain library call with a constant option and the documented null settings;
    // OpenSSL serializes its own initialization and keeps no Rust pointer.
    unsafe { OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, std::ptr::null()) == 1 }
}

/// One process heap, not one per host/session. 32-byte blocks fit Ed25519 and
/// X25519 seeds; one MiB leaves headroom over 10,000 distinct live seed allocations.
pub const HEAP_BYTES: usize = 1 << 20;
/// Result of the one-time initialization, kept for the life of the process.
static PROTECTION: OnceLock<i32> = OnceLock::new();

/// Initialize OpenSSL before key import/generation; retain its result forever.
/// A result of 1 means both locking and dump exclusion succeeded; 2 means
/// allocation works but OS protection failed, and 0 means initialization failed.
/// Callers enforce root fail-closed and explicit non-root development warnings.
#[must_use]
pub fn initialize() -> i32 {
    *PROTECTION.get_or_init(|| {
        openssl::init();
        // SAFETY: process-global initialization is serialized by OnceLock; the
        // size/minimum are powers of two. Never tear down a heap holding keys.
        unsafe { CRYPTO_secure_malloc_init(HEAP_BYTES, 32) }
    })
}

/// Public allocation count for measured sizing, never key bytes or addresses.
#[must_use]
pub fn used_bytes() -> usize {
    if PROTECTION.get().is_none_or(|result| *result == 0) {
        return 0;
    }
    // SAFETY: a successful initialization created OpenSSL's counter lock;
    // OpenSSL synchronizes the read internally, with no Rust pointers.
    unsafe { CRYPTO_secure_used() }
}
