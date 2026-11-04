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
