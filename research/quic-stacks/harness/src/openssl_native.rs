//! Role: Exercises OpenSSL's native QUIC client, server, and stream APIs through a narrow FFI shim.
//! SPDX-License-Identifier: AGPL-3.0-only

use crate::test_identity;
use openssl_sys as ossl;
use std::{
    error::Error,
    ffi::{CStr, CString, c_char, c_int, c_uchar, c_uint, c_ulong, c_void},
    net::UdpSocket,
    os::fd::AsRawFd,
    ptr, thread,
};

pub(crate) const ALPN: &[u8] = b"\x09quicbench";
const VERIFY_PEER_AND_REQUIRE_CERT: c_int = 0x01 | 0x02;
const SSL_ERROR_ZERO_RETURN: c_int = 6;
pub(crate) const SSL_DEFAULT_STREAM_MODE_NONE: u32 = 0;
pub(crate) const SSL_INCOMING_STREAM_POLICY_ACCEPT: c_int = 1;
const SSL_DOMAIN_FLAG_MULTI_THREAD_AND_BLOCKING: u64 = (1 << 1) | (1 << 3);
const SSL_DOMAIN_FLAG_THREAD_ASSISTED_AND_BLOCKING: u64 = (1 << 2) | (1 << 3);
pub(crate) const SSL_ACCEPT_STREAM_NO_BLOCK: u64 = 1;

unsafe extern "C" {
    fn OSSL_QUIC_server_method() -> *const ossl::SSL_METHOD;
    fn OSSL_QUIC_client_method() -> *const ossl::SSL_METHOD;
    fn SSL_new_listener(ctx: *mut ossl::SSL_CTX, flags: u64) -> *mut ossl::SSL;
    fn SSL_listen(ssl: *mut ossl::SSL) -> c_int;
    pub(crate) fn SSL_accept_connection(ssl: *mut ossl::SSL, flags: u64) -> *mut ossl::SSL;
    pub(crate) fn SSL_set_fd(ssl: *mut ossl::SSL, fd: c_int) -> c_int;
    fn SSL_CTX_set_domain_flags(ctx: *mut ossl::SSL_CTX, flags: u64) -> c_int;
    pub(crate) fn SSL_set_incoming_stream_policy(
        ssl: *mut ossl::SSL,
        policy: c_int,
        app_error_code: u64,
    ) -> c_int;
    pub(crate) fn SSL_handle_events(ssl: *mut ossl::SSL) -> c_int;
    fn ERR_error_string_n(error: c_ulong, buffer: *mut c_char, length: usize);
}

pub(crate) struct Context(pub(crate) *mut ossl::SSL_CTX);

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: Context owns the non-null pointer returned by SSL_CTX_new.
        unsafe { ossl::SSL_CTX_free(self.0) };
    }
}

pub(crate) struct Ssl(pub(crate) *mut ossl::SSL);

// SAFETY: This wrapper owns its SSL reference exclusively. The benchmark transfers
// individual stream handles to dedicated workers; OpenSSL's default QUIC server
// concurrency model serializes shared connection state internally.
unsafe impl Send for Ssl {}

impl Drop for Ssl {
    fn drop(&mut self) {
        // SAFETY: Ssl owns one reference to the non-null SSL object.
        unsafe { ossl::SSL_free(self.0) };
    }
}

struct X509(*mut ossl::X509);

impl Drop for X509 {
    fn drop(&mut self) {
        // SAFETY: X509 owns one reference returned by d2i_X509.
        unsafe { ossl::X509_free(self.0) };
    }
}

struct PrivateKey(*mut ossl::EVP_PKEY);

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // SAFETY: PrivateKey owns one reference returned by d2i_AutoPrivateKey.
        unsafe { ossl::EVP_PKEY_free(self.0) };
    }
}

/// Runs a mutually authenticated client/server handshake, opens one bidirectional stream, and echoes it.
pub fn smoke() -> Result<(), Box<dyn Error>> {
    let identity = test_identity::generate()?;
    let server_socket = UdpSocket::bind("127.0.0.1:0")?;
    let server_addr = server_socket.local_addr()?;
    let server_ctx = make_context(true, &identity)?;
    // SSL_set_fd is used here to attach the datagram socket BIO. The Rust socket is
    // retained for the entire SSL object lifetime because SSL_set_fd does not own it.
    let listener = unsafe { SSL_new_listener(server_ctx.0, 0) };
    let listener = nonnull(listener, "SSL_new_listener")?;
    let listener = Ssl(listener);
    check_ssl(
        unsafe { SSL_set_fd(listener.0, server_socket.as_raw_fd()) },
        "SSL_set_fd(listener)",
    )?;
    check_ssl(
        unsafe { ossl::SSL_set_blocking_mode(listener.0, 1) },
        "SSL_set_blocking_mode(listener)",
    )?;
    check_ssl(unsafe { SSL_listen(listener.0) }, "SSL_listen")?;

    let server = thread::spawn(move || server_echo(listener));

    let client_ctx = make_context(false, &identity)?;
    let client_socket = UdpSocket::bind("127.0.0.1:0")?;
    client_socket.connect(server_addr)?;
    let client = nonnull(unsafe { ossl::SSL_new(client_ctx.0) }, "SSL_new(client)")?;
    let client = Ssl(client);
    check_ssl(
        unsafe { SSL_set_fd(client.0, client_socket.as_raw_fd()) },
        "SSL_set_fd(client)",
    )?;
    check_ssl(
        unsafe { ossl::SSL_set_blocking_mode(client.0, 1) },
        "SSL_set_blocking_mode(client)",
    )?;
    check_ssl(
        unsafe { ossl::SSL_set_default_stream_mode(client.0, SSL_DEFAULT_STREAM_MODE_NONE) },
        "SSL_set_default_stream_mode",
    )?;
    set_hostname(client.0, "localhost")?;
    check_zero(
        unsafe { ossl::SSL_set_alpn_protos(client.0, ALPN.as_ptr(), ALPN.len() as c_uint) },
        "SSL_set_alpn_protos",
    )?;
    check_handshake(
        client.0,
        unsafe { ossl::SSL_connect(client.0) },
        "SSL_connect",
    )?;

    let stream = unsafe { ossl::SSL_new_stream(client.0, 0) };
    let stream = nonnull(stream, "SSL_new_stream")?;
    let stream = Ssl(stream);
    let payload = b"quinn-vs-openssl-native";
    write_all(&stream, payload, "SSL_write_ex(client)")?;
    check_ssl(
        unsafe { ossl::SSL_stream_conclude(stream.0, 0) },
        "SSL_stream_conclude(client)",
    )?;
    let response = read_all(&stream, "SSL_read_ex(client)")?;
    if response != payload {
        return Err("native QUIC stream echo differed from its payload".into());
    }
    server
        .join()
        .map_err(|_| "OpenSSL QUIC server thread panicked")?
        .map_err(|error| format!("OpenSSL QUIC server: {error}"))?;
    println!("openssl_native_smoke=ok alpn=quicbench mutual_tls=true bidirectional_stream=true");
    Ok(())
}

#[cfg(feature = "measure")]
pub fn bench_handshake(count: u32) -> Result<(), Box<dyn Error>> {
    use std::time::Instant;

    let identity = test_identity::generate()?;
    let server_socket = UdpSocket::bind("127.0.0.1:0")?;
    let server_addr = server_socket.local_addr()?;
    let server_ctx = make_context(true, &identity)?;
    let listener = make_listener(&server_ctx, &server_socket)?;
    let server = thread::spawn(move || server_handshakes(listener, count));

    let client_ctx = make_context(false, &identity)?;
    let cpu_before = crate::measure::cpu_us()?;
    let mut samples_us = Vec::with_capacity(count as usize);
    for index in 0..count {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.connect(server_addr)?;
        let client = nonnull(unsafe { ossl::SSL_new(client_ctx.0) }, "SSL_new(client)")?;
        let client = Ssl(client);
        check_ssl(
            unsafe { SSL_set_fd(client.0, socket.as_raw_fd()) },
            "SSL_set_fd(client)",
        )?;
        check_ssl(
            unsafe { ossl::SSL_set_blocking_mode(client.0, 1) },
            "SSL_set_blocking_mode(client)",
        )?;
        check_ssl(
            unsafe { ossl::SSL_set_default_stream_mode(client.0, SSL_DEFAULT_STREAM_MODE_NONE) },
            "SSL_set_default_stream_mode",
        )?;
        set_hostname(client.0, &format!("bench-{index}.quicbench.test"))?;
        check_zero(
            unsafe { ossl::SSL_set_alpn_protos(client.0, ALPN.as_ptr(), ALPN.len() as c_uint) },
            "SSL_set_alpn_protos",
        )?;
        let start = Instant::now();
        check_handshake(
            client.0,
            unsafe { ossl::SSL_connect(client.0) },
            "SSL_connect",
        )?;
        samples_us.push(start.elapsed().as_micros().min(u64::MAX as u128) as u64);
    }
    server
        .join()
        .map_err(|_| "OpenSSL QUIC benchmark server panicked")?
        .map_err(|error| format!("OpenSSL QUIC benchmark server: {error}"))?;
    let cpu_us = crate::measure::cpu_us()?.saturating_sub(cpu_before);
    crate::measure::emit(crate::measure::Run {
        stack: "openssl-native-3.6.3",
        workload: "handshake-1rtt",
        scenario: "fresh-mtls",
        units: count as u64,
        samples_us,
        cpu_us,
        bytes: 0,
    });
    Ok(())
}

#[cfg(feature = "measure")]
pub fn bench_throughput(stream_count: usize, bytes_total: u64) -> Result<(), Box<dyn Error>> {
    use std::time::Instant;

    let identity = test_identity::generate()?;
    let server_socket = UdpSocket::bind("127.0.0.1:0")?;
    let server_addr = server_socket.local_addr()?;
    let server_ctx = make_context(true, &identity)?;
    let listener = make_listener(&server_ctx, &server_socket)?;
    let (client_finished, server_wait) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        server_transfer(
            listener,
            stream_count,
            bytes_total / stream_count as u64,
            server_wait,
        )
    });

    let client_ctx = make_context(false, &identity)?;
    let client_socket = UdpSocket::bind("127.0.0.1:0")?;
    client_socket.connect(server_addr)?;
    let client = nonnull(unsafe { ossl::SSL_new(client_ctx.0) }, "SSL_new(client)")?;
    let client = Ssl(client);
    check_ssl(
        unsafe { SSL_set_fd(client.0, client_socket.as_raw_fd()) },
        "SSL_set_fd(client)",
    )?;
    check_ssl(
        unsafe { ossl::SSL_set_blocking_mode(client.0, 1) },
        "SSL_set_blocking_mode(client)",
    )?;
    check_ssl(
        unsafe { ossl::SSL_set_default_stream_mode(client.0, SSL_DEFAULT_STREAM_MODE_NONE) },
        "SSL_set_default_stream_mode",
    )?;
    set_hostname(client.0, "localhost")?;
    check_zero(
        unsafe { ossl::SSL_set_alpn_protos(client.0, ALPN.as_ptr(), ALPN.len() as c_uint) },
        "SSL_set_alpn_protos",
    )?;
    check_handshake(
        client.0,
        unsafe { ossl::SSL_connect(client.0) },
        "SSL_connect",
    )?;

    let bytes_per_stream = bytes_total / stream_count as u64;
    let cpu_before = crate::measure::cpu_us()?;
    let start = Instant::now();
    let mut streams = Vec::with_capacity(stream_count);
    for _ in 0..stream_count {
        let stream = unsafe { ossl::SSL_new_stream(client.0, 0) };
        let stream = Ssl(nonnull(stream, "SSL_new_stream")?);
        streams.push(stream);
    }
    // Send a byte on every stream before the server begins draining, so it can
    // accept the full multiplexed set without a blocked first-stream writer.
    for stream in &streams {
        write_all(stream, b"\x00", "SSL_write_ex(open stream)")?;
    }
    let payload = [0u8; 16 * 1024];
    let remaining_per_stream = bytes_per_stream.saturating_sub(1);
    let chunks = remaining_per_stream.div_ceil(payload.len() as u64);
    if chunks > 0 {
        let final_chunk = (remaining_per_stream - (chunks - 1) * payload.len() as u64) as usize;
        for index in 0..chunks {
            let size = if index + 1 == chunks {
                final_chunk
            } else {
                payload.len()
            };
            for stream in &streams {
                write_all(stream, &payload[..size], "SSL_write_ex(client)")?;
            }
        }
    }
    for stream in &streams {
        read_exact(stream, 1, "SSL_read_ex(client acknowledgment)")?;
    }
    let elapsed_us = start.elapsed().as_micros().min(u64::MAX as u128) as u64;
    client_finished
        .send(())
        .map_err(|_| "server stopped before stream acknowledgment completed")?;
    let received = server
        .join()
        .map_err(|_| "OpenSSL QUIC transfer server panicked")?
        .map_err(|error| format!("OpenSSL QUIC transfer server: {error}"))?;
    if received != bytes_total {
        return Err(format!("received {received} bytes, expected {bytes_total}").into());
    }
    let cpu_us = crate::measure::cpu_us()?.saturating_sub(cpu_before);
    crate::measure::emit(crate::measure::Run {
        stack: "openssl-native-3.6.3",
        workload: "stream-throughput",
        scenario: if stream_count == 1 {
            "1-bidi-stream"
        } else {
            "4-bidi-streams"
        },
        units: bytes_total,
        samples_us: vec![elapsed_us],
        cpu_us,
        bytes: bytes_total,
    });
    Ok(())
}

pub(crate) fn make_context(
    server: bool,
    identity: &test_identity::TestIdentity,
) -> Result<Context, Box<dyn Error>> {
    let method = unsafe {
        if server {
            OSSL_QUIC_server_method()
        } else {
            OSSL_QUIC_client_method()
        }
    };
    let ctx = nonnull(unsafe { ossl::SSL_CTX_new(method) }, "SSL_CTX_new(QUIC)")?;
    let ctx = Context(ctx);
    let domain_flags = if server {
        SSL_DOMAIN_FLAG_THREAD_ASSISTED_AND_BLOCKING
    } else {
        SSL_DOMAIN_FLAG_MULTI_THREAD_AND_BLOCKING
    };
    check_ssl(
        unsafe { SSL_CTX_set_domain_flags(ctx.0, domain_flags) },
        "SSL_CTX_set_domain_flags",
    )?;
    let cert = parse_cert(&identity.cert_der)?;
    let ca = parse_cert(&identity.ca_der)?;
    let key = parse_private_key(&identity.key_der)?;
    check_ssl(
        unsafe { ossl::SSL_CTX_use_certificate(ctx.0, cert.0) },
        "SSL_CTX_use_certificate",
    )?;
    check_ssl(
        unsafe { ossl::SSL_CTX_use_PrivateKey(ctx.0, key.0) },
        "SSL_CTX_use_PrivateKey",
    )?;
    let store = unsafe { ossl::SSL_CTX_get_cert_store(ctx.0) };
    check_ssl(
        unsafe { ossl::X509_STORE_add_cert(store, ca.0) },
        "X509_STORE_add_cert",
    )?;
    unsafe {
        ossl::SSL_CTX_set_verify(ctx.0, VERIFY_PEER_AND_REQUIRE_CERT, None);
        if server {
            ossl::SSL_CTX_set_alpn_select_cb__fixed_rust(ctx.0, Some(select_alpn), ptr::null_mut());
        }
    }
    Ok(ctx)
}

fn server_echo(listener: Ssl) -> Result<(), String> {
    let connection = unsafe { SSL_accept_connection(listener.0, 0) };
    let connection = nonnull(connection, "SSL_accept_connection").map_err(|e| e.to_string())?;
    let connection = Ssl(connection);
    check_ssl(
        unsafe { ossl::SSL_set_blocking_mode(connection.0, 1) },
        "SSL_set_blocking_mode(server)",
    )
    .map_err(|e| e.to_string())?;
    check_handshake(
        connection.0,
        unsafe { ossl::SSL_accept(connection.0) },
        "SSL_accept(server)",
    )
    .map_err(|e| e.to_string())?;
    let stream = unsafe { ossl::SSL_accept_stream(connection.0, 0) };
    let stream = nonnull(stream, "SSL_accept_stream").map_err(|e| e.to_string())?;
    let stream = Ssl(stream);
    let request = read_all(&stream, "SSL_read_ex(server)").map_err(|e| e.to_string())?;
    write_all(&stream, &request, "SSL_write_ex(server)").map_err(|e| e.to_string())?;
    check_ssl(
        unsafe { ossl::SSL_stream_conclude(stream.0, 0) },
        "SSL_stream_conclude(server)",
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(feature = "measure")]
fn server_handshakes(listener: Ssl, count: u32) -> Result<(), String> {
    let mut connections = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let connection = unsafe { SSL_accept_connection(listener.0, 0) };
        let connection = nonnull(connection, "SSL_accept_connection").map_err(|e| e.to_string())?;
        let connection = Ssl(connection);
        check_ssl(
            unsafe { ossl::SSL_set_blocking_mode(connection.0, 1) },
            "SSL_set_blocking_mode(server)",
        )
        .map_err(|e| e.to_string())?;
        check_handshake(
            connection.0,
            unsafe { ossl::SSL_accept(connection.0) },
            "SSL_accept(server)",
        )
        .map_err(|e| e.to_string())?;
        connections.push(connection);
    }
    drop(connections);
    Ok(())
}

#[cfg(feature = "measure")]
fn server_transfer(
    listener: Ssl,
    stream_count: usize,
    bytes_per_stream: u64,
    client_finished: std::sync::mpsc::Receiver<()>,
) -> Result<u64, String> {
    let connection = unsafe { SSL_accept_connection(listener.0, 0) };
    let connection = nonnull(connection, "SSL_accept_connection").map_err(|e| e.to_string())?;
    let connection = Ssl(connection);
    check_ssl(
        unsafe { ossl::SSL_set_blocking_mode(connection.0, 1) },
        "SSL_set_blocking_mode(server)",
    )
    .map_err(|e| e.to_string())?;
    check_handshake(
        connection.0,
        unsafe { ossl::SSL_accept(connection.0) },
        "SSL_accept(server)",
    )
    .map_err(|e| e.to_string())?;
    check_ssl(
        unsafe {
            SSL_set_incoming_stream_policy(connection.0, SSL_INCOMING_STREAM_POLICY_ACCEPT, 0)
        },
        "SSL_set_incoming_stream_policy(server)",
    )
    .map_err(|e| e.to_string())?;
    let mut streams = Vec::with_capacity(stream_count);
    for _ in 0..stream_count {
        let stream = loop {
            let stream =
                unsafe { ossl::SSL_accept_stream(connection.0, SSL_ACCEPT_STREAM_NO_BLOCK) };
            if !stream.is_null() {
                break stream;
            }
            // Drive the event API explicitly while waiting so I/O on one stream
            // cannot hold the blocking accept path for another stream.
            check_ssl(
                unsafe { SSL_handle_events(connection.0) },
                "SSL_handle_events(server)",
            )
            .map_err(|e| e.to_string())?;
            thread::sleep(std::time::Duration::from_millis(1));
        };
        let stream = Ssl(nonnull(stream, "SSL_accept_stream").map_err(|e| e.to_string())?);
        streams.push(stream);
    }
    let mut readers = Vec::with_capacity(stream_count);
    for stream in streams {
        readers.push(thread::spawn(move || -> Result<u64, String> {
            read_exact_count(&stream, bytes_per_stream, "SSL_read_ex(server)")
                .map_err(|e| e.to_string())?;
            write_all(&stream, b"\x01", "SSL_write_ex(server acknowledgment)")
                .map_err(|e| e.to_string())?;
            check_ssl(
                unsafe { ossl::SSL_stream_conclude(stream.0, 0) },
                "SSL_stream_conclude(server acknowledgment)",
            )
            .map_err(|e| e.to_string())?;
            Ok(bytes_per_stream)
        }));
    }
    let mut received = 0u64;
    for reader in readers {
        received += reader
            .join()
            .map_err(|_| "OpenSSL QUIC stream worker panicked")?
            .map_err(|error| format!("OpenSSL QUIC stream worker: {error}"))?;
    }
    // Keep the connection alive until the client has consumed every ACK.
    client_finished
        .recv()
        .map_err(|error| format!("client acknowledgment sync failed: {error}"))?;
    drop(connection);
    Ok(received)
}

#[cfg(feature = "measure")]
pub(crate) fn make_listener(ctx: &Context, socket: &UdpSocket) -> Result<Ssl, Box<dyn Error>> {
    let listener = nonnull(unsafe { SSL_new_listener(ctx.0, 0) }, "SSL_new_listener")?;
    let listener = Ssl(listener);
    check_ssl(
        unsafe { SSL_set_fd(listener.0, socket.as_raw_fd()) },
        "SSL_set_fd(listener)",
    )?;
    check_ssl(
        unsafe { ossl::SSL_set_blocking_mode(listener.0, 1) },
        "SSL_set_blocking_mode(listener)",
    )?;
    check_ssl(unsafe { SSL_listen(listener.0) }, "SSL_listen")?;
    Ok(listener)
}

fn parse_cert(bytes: &[u8]) -> Result<X509, Box<dyn Error>> {
    let mut cursor = bytes.as_ptr();
    let cert = unsafe { ossl::d2i_X509(ptr::null_mut(), &mut cursor, bytes.len() as _) };
    nonnull(cert, "d2i_X509").map(X509)
}

fn parse_private_key(bytes: &[u8]) -> Result<PrivateKey, Box<dyn Error>> {
    let mut cursor = bytes.as_ptr();
    let key = unsafe { ossl::d2i_AutoPrivateKey(ptr::null_mut(), &mut cursor, bytes.len() as _) };
    nonnull(key, "d2i_AutoPrivateKey").map(PrivateKey)
}

pub(crate) fn set_hostname(ssl: *mut ossl::SSL, hostname: &str) -> Result<(), Box<dyn Error>> {
    let hostname = CString::new(hostname)?;
    let verify = unsafe { ossl::SSL_get0_param(ssl) };
    check_ssl(
        unsafe {
            ossl::X509_VERIFY_PARAM_set1_host(verify, hostname.as_ptr(), hostname.as_bytes().len())
        },
        "X509_VERIFY_PARAM_set1_host",
    )?;
    // The QUIC TLS ClientHello still carries SNI; the verification parameter above
    // independently requires the server certificate to match the expected host.
    check_ssl(
        unsafe { ossl::SSL_set_tlsext_host_name(ssl, hostname.as_ptr().cast_mut()) as c_int },
        "SSL_set_tlsext_host_name",
    )?;
    Ok(())
}

unsafe extern "C" fn select_alpn(
    _ssl: *mut ossl::SSL,
    out: *mut *const c_uchar,
    out_len: *mut c_uchar,
    input: *const c_uchar,
    input_len: c_uint,
    _arg: *mut c_void,
) -> c_int {
    // OpenSSL gives this callback a valid length-prefixed ALPN list. The chosen
    // output points into that callback-owned input, whose lifetime covers return.
    let mut offset = 0usize;
    let input_len = input_len as usize;
    while offset < input_len {
        let length = unsafe { *input.add(offset) } as usize;
        offset += 1;
        if length == 0 || offset + length > input_len {
            return 2;
        }
        if unsafe { std::slice::from_raw_parts(input.add(offset), length) } == &ALPN[1..] {
            unsafe {
                *out = input.add(offset);
                *out_len = length as c_uchar;
            }
            return 0;
        }
        offset += length;
    }
    2
}

fn read_all(ssl: &Ssl, action: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let mut count = 0usize;
        let ret =
            unsafe { ossl::SSL_read_ex(ssl.0, chunk.as_mut_ptr().cast(), chunk.len(), &mut count) };
        if ret == 1 {
            bytes.extend_from_slice(&chunk[..count]);
        } else {
            let error = unsafe { ossl::SSL_get_error(ssl.0, ret) };
            if error == SSL_ERROR_ZERO_RETURN {
                return Ok(bytes);
            }
            if error == 2 {
                continue;
            }
            let code = unsafe { ossl::ERR_get_error() };
            return Err(format!("{action} failed: SSL error {error}, {}", error_text(code)).into());
        }
    }
}

#[cfg(feature = "measure")]
fn read_exact_count(ssl: &Ssl, expected: u64, action: &str) -> Result<(), Box<dyn Error>> {
    let mut total = 0u64;
    while total < expected {
        let mut chunk = [0u8; 64 * 1024];
        let mut count = 0usize;
        let len = chunk.len().min((expected - total) as usize);
        let ret = unsafe { ossl::SSL_read_ex(ssl.0, chunk.as_mut_ptr().cast(), len, &mut count) };
        if ret == 1 {
            if count == 0 {
                return Err(format!(
                    "{action} returned an empty successful read before {expected} bytes"
                )
                .into());
            }
            total += count as u64;
        } else {
            let error = unsafe { ossl::SSL_get_error(ssl.0, ret) };
            if error == SSL_ERROR_ZERO_RETURN {
                return Err(
                    format!("{action} ended after {total} bytes, expected {expected}").into(),
                );
            }
            if error == 2 || error == 3 {
                continue;
            }
            let code = unsafe { ossl::ERR_get_error() };
            return Err(format!("{action} failed: SSL error {error}, {}", error_text(code)).into());
        }
    }
    Ok(())
}

pub(crate) fn read_exact(ssl: &Ssl, expected: usize, action: &str) -> Result<(), Box<dyn Error>> {
    read_exact_count(ssl, expected as u64, action)
}

pub(crate) fn write_all(ssl: &Ssl, mut bytes: &[u8], action: &str) -> Result<(), Box<dyn Error>> {
    while !bytes.is_empty() {
        let mut count = 0usize;
        let ret =
            unsafe { ossl::SSL_write_ex(ssl.0, bytes.as_ptr().cast(), bytes.len(), &mut count) };
        if ret == 1 {
            bytes = &bytes[count..];
        } else {
            let error = unsafe { ossl::SSL_get_error(ssl.0, ret) };
            if error == 2 {
                continue;
            }
            let code = unsafe { ossl::ERR_get_error() };
            return Err(format!("{action} failed: SSL error {error}, {}", error_text(code)).into());
        }
    }
    Ok(())
}

pub(crate) fn check_ssl(ret: c_int, action: &str) -> Result<(), Box<dyn Error>> {
    if ret == 1 {
        Ok(())
    } else {
        let code = unsafe { ossl::ERR_get_error() };
        Err(format!("{action} failed: return={ret}, OpenSSL error=0x{code:x}").into())
    }
}

fn error_text(code: c_ulong) -> String {
    let mut buffer = [0 as c_char; 256];
    unsafe { ERR_error_string_n(code, buffer.as_mut_ptr(), buffer.len()) };
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

pub(crate) fn check_zero(ret: c_int, action: &str) -> Result<(), Box<dyn Error>> {
    if ret == 0 {
        Ok(())
    } else {
        let code = unsafe { ossl::ERR_get_error() };
        Err(format!("{action} failed: return={ret}, OpenSSL error=0x{code:x}").into())
    }
}

pub(crate) fn check_handshake(
    ssl: *mut ossl::SSL,
    ret: c_int,
    action: &str,
) -> Result<(), Box<dyn Error>> {
    if ret == 1 {
        return Ok(());
    }
    let verify_code = unsafe { ossl::SSL_get_verify_result(ssl) };
    let verify_text = unsafe {
        let ptr = ossl::X509_verify_cert_error_string(verify_code);
        if ptr.is_null() {
            "unknown verification result"
        } else {
            CStr::from_ptr(ptr)
                .to_str()
                .unwrap_or("invalid verification text")
        }
    };
    let code = unsafe { ossl::ERR_get_error() };
    Err(format!("{action} failed: return={ret}, OpenSSL error=0x{code:x}, verify={verify_code} ({verify_text})").into())
}

pub(crate) fn nonnull<T>(ptr: *mut T, action: &str) -> Result<*mut T, Box<dyn Error>> {
    if ptr.is_null() {
        let code = unsafe { ossl::ERR_get_error() };
        let detail = error_text(code);
        Err(format!("{action} failed: OpenSSL error=0x{code:x}, {detail}").into())
    } else {
        Ok(ptr)
    }
}
