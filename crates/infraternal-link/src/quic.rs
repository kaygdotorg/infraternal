//! Leg B's QUIC settings: the client's mutually authenticated TLS config and
//! the transport parameters both ends share (BBR, path-safe MTU, flow-control
//! bounds) [11][64][130], #78, #580.
//!
//! How to use it: a client calls [`client_config_with_liveness`] with its
//! [`ClientIdentity`] and the pinned server roots. The server side (which
//! stays in `infraternal-plugin-remote`) builds its own TLS config and takes
//! [`transport_with_liveness`] and [`ALPN`] from here, so both ends always
//! agree on the protocol name and limits.

use crate::identity::ClientIdentity;
use rustls::pki_types::CertificateDer;
use std::{io, sync::Arc, time::Duration};

/// Application protocol name offered and required in the TLS handshake. A
/// peer that does not speak it is refused.
pub const ALPN: &[u8] = b"infraternal/1";

/// Largest UDP payload a host connection may discover. The connection can move
/// onto the mesh below QUIC without seeing a path change (`remote_path_socket`),
/// so its discovered size must also fit the mesh interface: 1380-byte interface
/// MTU minus the 20-byte IPv4 and 8-byte UDP headers. A larger datagram would
/// be dropped locally (EMSGSIZE) and stall until black-hole detection.
pub const PATH_SAFE_UDP_PAYLOAD: u16 = 1352;

/// Received QUIC DATAGRAM bytes buffered per connection. This is also the
/// largest DATAGRAM the peer may send. Terminal-only builds receive only
/// one-byte liveness probes while on the mesh and nothing reads them; the bound
/// keeps that buffer at a few entries instead of Quinn's default.
#[cfg(not(feature = "native-streams"))]
const DATAGRAM_BUFFER: usize = 64;
/// Native plugin lanes (desktop video, #146) send 1 KiB fragments over the same
/// connection and read them as they arrive, so builds with them accept a full
/// fragment and a short burst of a keyframe. A cap, not an allocation.
#[cfg(feature = "native-streams")]
const DATAGRAM_BUFFER: usize = 128 * 1024;

/// The one error every refusal in this module returns (`PermissionDenied`).
/// Its text names no peer, certificate or reason, so a caller cannot learn why
/// a connection was refused. It is the same error the server side returns.
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "remote infraternal agent QUIC transport refused",
    )
}

/// Builds the trusted CA store from `certificates`. Accepts one to sixteen
/// certificates; none, more than sixteen, or an unparsable one is refused.
/// # Errors
/// The generic refusal ([`io::ErrorKind::PermissionDenied`]).
pub fn root_store(certificates: &[CertificateDer<'static>]) -> io::Result<rustls::RootCertStore> {
    if certificates.is_empty() || certificates.len() > 16 {
        return Err(denied());
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate.clone()).map_err(|_| denied())?;
    }
    Ok(roots)
}

/// Shared transport settings with explicit `keep_alive` and `idle` times.
/// Limits received datagram bytes, caps the discovered packet size to
/// [`PATH_SAFE_UDP_PAYLOAD`], allows `incoming_streams` peer-initiated streams,
/// and for a client (`client` true) asks the peer to delay acknowledgements by
/// at most 5 ms.
#[must_use]
pub fn transport_with_liveness(
    incoming_streams: u32,
    keep_alive: Duration,
    idle: Duration,
    client: bool,
) -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));
    if client {
        // Enrolled ciphertext copies and ACK delay share the backed path's
        // 30ms response margin. Negotiate 5ms without extending loss detection;
        // preserve the ordinary immediate ACK on the first reordered packet.
        let mut frequency = quinn::AckFrequencyConfig::default();
        frequency.max_ack_delay(Some(Duration::from_millis(5)));
        frequency.reordering_threshold(1u32.into());
        config.ack_frequency_config(Some(frequency));
    }
    // Both directions retain their learned MTU across a socket-level mesh move.
    let mut discovery = quinn::MtuDiscoveryConfig::default();
    discovery.upper_bound(PATH_SAFE_UDP_PAYLOAD);
    config.mtu_discovery_config(Some(discovery));
    config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // Transport probes preserve stateful mappings without database or authority
    // work. The caller chooses its measured liveness profile; acknowledged
    // traffic resets idle expiry, with QUIC retaining its minimum PTO bound.
    config
        .max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            u32::try_from(idle.as_millis()).unwrap_or(60_000),
        ))))
        .keep_alive_interval(Some(keep_alive));
    config.max_concurrent_uni_streams(0u32.into());
    // Quinn preallocates slots up to this limit. Hosts initiate only control0;
    // server-opened terminals use the daemon's existing attachment bound, not
    // the deployment-wide viewer count multiplied across every idle host.
    config.max_concurrent_bidi_streams(incoming_streams.into());
    // Credit bounds outstanding bytes across streams, not just stream count.
    // 1MiB per peer is <=1GiB outstanding at the 1000-host admission target.
    config
        .receive_window(1_048_576u32.into())
        .stream_receive_window(262_144u32.into())
        .send_window(1_048_576);
    Arc::new(config)
}

/// Refuses a keep-alive under 1 ms, one not shorter than `idle`, or an idle
/// time over 60 seconds.
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for any of those.
pub fn check_liveness(keep_alive: Duration, idle: Duration) -> io::Result<()> {
    if keep_alive < Duration::from_millis(1) || keep_alive >= idle || idle > Duration::from_secs(60)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}

/// Configure outgoing mTLS, the pinned server roots and transport-only
/// liveness. The caller measures RTT and picks `keep_alive` and `idle`;
/// credential verification and all stream limits stay identical for every
/// profile. Callers must bound `Connecting` and control-Hello negotiation
/// themselves.
/// # Errors
/// `InvalidInput` for the timer intervals [`check_liveness`] refuses, checked
/// first; otherwise the generic refusal for invalid trust, an identity whose
/// key does not match its leaf, or unavailable crypto configuration.
pub fn client_config_with_liveness(
    identity: &ClientIdentity,
    roots: &[CertificateDer<'static>],
    keep_alive: Duration,
    idle: Duration,
) -> io::Result<quinn::ClientConfig> {
    check_liveness(keep_alive, idle)?;
    let key = identity.certified_key().map_err(|_| denied())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| denied())?
        .with_root_certificates(root_store(roots)?)
        .with_client_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(key)));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    // No replayable 0-RTT: terminal input and enrollment are stateful authority.
    tls.enable_early_data = false;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| denied())?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport_with_liveness(
        u32::try_from(infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS)
            .map_err(|_| denied())?,
        keep_alive,
        idle,
        true,
    ));
    Ok(config)
}

/// Tests for the bounds this module enforces before any handshake.
#[cfg(test)]
mod tests {
    use super::*;

    /// Zero, inverted and over-long timer intervals are refused as invalid input.
    #[test]
    fn liveness_bounds_are_checked() {
        let second = Duration::from_secs(1);
        check_liveness(Duration::from_secs(15), Duration::from_secs(60)).unwrap();
        for (keep_alive, idle) in [
            (Duration::ZERO, second),
            (second, second),
            (second, Duration::from_secs(61)),
        ] {
            assert_eq!(
                check_liveness(keep_alive, idle).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    /// An empty root list and one over sixteen are refused with the generic error.
    #[test]
    fn root_store_needs_one_to_sixteen_roots() {
        assert_eq!(
            root_store(&[]).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let many = vec![CertificateDer::from(vec![0u8; 4]); 17];
        assert_eq!(
            root_store(&many).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
