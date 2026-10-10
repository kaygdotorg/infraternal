//! Role: Small OpenSSL TLS reference used to calculate incremental QUIC binary size.
//! SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;

/// Touches the existing TLS API so all candidate artifacts retain the same base link.
pub fn smoke() -> Result<(), Box<dyn Error>> {
    // SAFETY: The context is created by OpenSSL and freed exactly once below.
    let ctx = unsafe { openssl_sys::SSL_CTX_new(openssl_sys::TLS_method()) };
    if ctx.is_null() {
        return Err("OpenSSL TLS context allocation failed".into());
    }
    // SAFETY: ctx is a live SSL_CTX returned by SSL_CTX_new.
    unsafe { openssl_sys::SSL_CTX_free(ctx) };
    println!("baseline_tls_context=ok openssl_version={}", version_hex());
    Ok(())
}

/// Reports the compile-time OpenSSL version for raw benchmark provenance.
pub fn print_version() -> Result<(), Box<dyn Error>> {
    println!("openssl_version={}", version_hex());
    Ok(())
}

fn version_hex() -> String {
    // This symbol is present in OpenSSL 1.1.0 and newer.
    let version = unsafe { openssl_sys::OpenSSL_version_num() };
    format!("0x{version:08x}")
}
