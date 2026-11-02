//! Relay connection identities and transport settings on quinn + rustls + ring (D176) [131,313].
//!
//! Both ends authenticate with certificates from the deployment CA: a relay
//! presents a server-purpose leaf, a node its enrolled host leaf (client
//! purpose, `urn:infraternal:host:<uuid>` SAN). Name and purpose checks are
//! never relaxed. A relay names a connected node only by the verified leaf.

use crate::wire::HostId;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{io, sync::Arc, time::Duration};

/// Relay connections negotiate only this protocol; leg-B connections use their own.
pub const ALPN: &[u8] = b"infraternal-relay/1";

/// First bytes a client writes on its control stream: protocol version 1.
pub const HELLO: [u8; 4] = *b"IFR1";

/// Keep-alive interval. With [`IDLE`] it bounds how long a silent relay loss
/// goes unnoticed (#220 design: three seconds without authenticated receive).
pub const KEEP_ALIVE: Duration = Duration::from_secs(1);
/// A relay connection with no authenticated packet for this long is gone.
pub const IDLE: Duration = Duration::from_secs(3);

/// Largest UDP payload either end probes for: 1472 is the most a 1500-byte
/// IPv4 path carries, and discovery finds less on smaller paths. quinn keeps
/// 38 bytes of each packet for QUIC (flags, 8-byte connection id, worst-case
/// packet number and frame header, AEAD tag), so a full mesh-MTU `WireGuard`
/// packet (1380 + 32) plus the 4-byte link id needs a discovered payload of
/// at least 1454. A 1500-byte IPv6 path (1452) is two bytes short: such pairs
/// need a lower route MTU, which the low-MTU slice adds.
const MAX_UDP_PAYLOAD: u16 = 1472;
/// Node-side receive buffer. The node's relay reader drains it independently.
const CLIENT_DATAGRAM_RECEIVE: usize = 512 * 1024;
/// Node-side send buffer; callers retain the existing congestion allowance.
const CLIENT_DATAGRAM_SEND: usize = 256 * 1024;
/// Relay-side receive buffer; its reader forwards promptly, so a deep queue
/// would add latency without improving delivery.
const SERVER_DATAGRAM_RECEIVE: usize = 8 * 1024;
/// Relay-side send ceiling. Shared queue budgets bound aggregate retained data.
const SERVER_DATAGRAM_SEND: usize = 128 * 1024;

/// One end's certificate chain and key, plus the deployment CA roots.
pub struct Credentials {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub roots: Vec<CertificateDer<'static>>,
}

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "relay identity refused")
}

fn roots(certificates: &[CertificateDer<'static>]) -> io::Result<Arc<rustls::RootCertStore>> {
    if certificates.is_empty() || certificates.len() > 16 {
        return Err(denied());
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate.clone()).map_err(|_| denied())?;
    }
    Ok(Arc::new(roots))
}

fn transport(
    incoming_streams: u32,
    datagram_receive: usize,
    datagram_send: usize,
) -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config
        .datagram_receive_buffer_size(Some(datagram_receive))
        .datagram_send_buffer_size(datagram_send)
        .keep_alive_interval(Some(KEEP_ALIVE))
        .max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            u32::try_from(IDLE.as_millis()).unwrap_or(3_000),
        ))))
        // One control stream per connection; datagrams carry everything else.
        .max_concurrent_bidi_streams(incoming_streams.into())
        .max_concurrent_uni_streams(0_u32.into())
        .stream_receive_window(4_096_u32.into())
        .receive_window(8_192_u32.into())
        .send_window(65_536);
    let mut discovery = quinn::MtuDiscoveryConfig::default();
    discovery.upper_bound(MAX_UDP_PAYLOAD);
    config.mtu_discovery_config(Some(discovery));
    config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(config)
}

/// Relay side: require a client certificate from the deployment CA.
/// # Errors
/// Refuses invalid roots or identity.
pub fn server_config(credentials: Credentials) -> io::Result<quinn::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        roots(&credentials.roots)?,
        provider.clone(),
    )
    .build()
    .map_err(|_| denied())?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| denied())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(credentials.chain, credentials.key)
        .map_err(|_| denied())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|_| denied())?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport(1, SERVER_DATAGRAM_RECEIVE, SERVER_DATAGRAM_SEND));
    Ok(config)
}

/// Node side: present the host leaf and verify the relay's name and purpose.
/// # Errors
/// Refuses invalid roots or identity.
pub fn client_config(credentials: Credentials) -> io::Result<quinn::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| denied())?
        .with_root_certificates(roots(&credentials.roots)?)
        .with_client_auth_cert(credentials.chain, credentials.key)
        .map_err(|_| denied())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    // Link requests change relay state; never send them as replayable 0-RTT.
    tls.enable_early_data = false;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| denied())?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport(0, CLIENT_DATAGRAM_RECEIVE, CLIENT_DATAGRAM_SEND));
    Ok(config)
}

/// The host named by a connected client's verified leaf. A leaf with no host
/// URI, or with more than one, names nobody.
#[must_use]
pub fn peer_host(connection: &quinn::Connection) -> Option<HostId> {
    let chain = connection
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    let leaf = openssl::x509::X509::from_der(chain.first()?.as_ref()).ok()?;
    let mut hosts = leaf
        .subject_alt_names()?
        .iter()
        .filter_map(|name| name.uri().and_then(HostId::from_uri))
        .collect::<Vec<_>>();
    (hosts.len() == 1).then(|| hosts.pop()).flatten()
}
