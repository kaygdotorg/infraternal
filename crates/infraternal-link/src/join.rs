//! The join client: redeem a join invitation for a certificate, without
//! OpenSSL (#580, plan §8 L3).
//!
//! A join turns an approved invitation into this node's leg-B identity. The
//! node sends a PKCS#10 request for its key (built by [`crate::csr`] through
//! its [`IdentitySigner`]) to the server's `POST /remote/join`, and gets back
//! a certificate. Nothing in the reply is trusted until it is checked: the
//! certificate must be a client certificate issued under the CA the
//! invitation pinned, and it must certify this node's own key.
//!
//! How to use it:
//! - [`join`] does everything: check the invitation, POST over HTTPS with the
//!   invitation's pinned root (hyper over `tokio-rustls`, TLS 1.3 only), and
//!   check the reply.
//! - For servers whose invitation says their HTTPS uses ordinary public roots
//!   (`https_system_roots`), this crate has no root store of its own. The
//!   platform makes that request instead (on the iPhone, `URLSession`), with
//!   the two halves here: [`PreparedJoin::new`] checks the invitation and
//!   builds the body, and [`PreparedJoin::finish`] checks the reply.
//!
//! Every refusal is one of a few [`JoinError`] values that carry no server
//! text, certificate bytes or token, so nothing secret reaches a log line.
//! The invitation's token is a one-time capability: the request body that
//! carries it is zeroed when it is dropped.

use crate::{
    enrollment::{JoinInvitation, JoinRequest, JoinResponse, Mode},
    identity::{ClientIdentity, IdentitySigner, KeyAlgorithm},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::{fmt, io, net::SocketAddr, sync::Arc, time::Duration};
use zeroize::Zeroizing;

/// Largest join reply the client reads, in bytes; a certificate is about 600.
pub const MAX_RESPONSE: usize = 8192;
/// Largest certificate the client accepts from the reply, in DER bytes.
const MAX_CERTIFICATE: usize = 4096;
/// The whole HTTPS join (connect, handshake, request, reply) must finish in this.
pub const JOIN_DEADLINE: Duration = Duration::from_secs(10);

/// Why a join failed. The values name the step, never the server's words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinError {
    /// The invitation is malformed, names a non-HTTPS or non-origin URL, or
    /// does not fit this key (a P-256 key joins only as a `device`, Ed25519
    /// only as a host).
    Invitation,
    /// The invitation's server uses public HTTPS roots, which this crate does
    /// not carry: the platform must POST ([`PreparedJoin`]).
    SystemRoots,
    /// The server could not be reached, or TLS or HTTP failed, or the
    /// deadline passed. The kind is the underlying I/O kind.
    Network(io::ErrorKind),
    /// The server answered with this non-200 status (403: the invitation was
    /// refused, spent or expired).
    Status(u16),
    /// The reply is malformed, or its certificate does not chain to the
    /// invited CA as a client certificate, or does not certify this key.
    Reply,
    /// The identity key could not build or sign the request.
    Key,
}

impl fmt::Display for JoinError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invitation => "the join invitation is not valid for this key",
            Self::SystemRoots => "this server's HTTPS needs the platform's public roots",
            Self::Network(_) => "the server could not be reached over HTTPS",
            Self::Status(_) => "the server refused the join",
            Self::Reply => "the server's join reply could not be verified",
            Self::Key => "the identity key could not sign the join request",
        })
    }
}

impl std::error::Error for JoinError {}

/// The result of a successful join: everything the node needs to dial leg B.
pub struct Joined {
    /// The host or device id the invitation bound.
    pub host_id: uuid::Uuid,
    /// The mode the invitation bound.
    pub mode: Mode,
    /// The new leaf with this node's signer, ready for the QUIC client config.
    pub identity: ClientIdentity,
    /// The CA that issued the leaf, and that the server's leaf chains to: the
    /// only root leg B trusts.
    pub ca: CertificateDer<'static>,
    /// The name the server's leg-B leaf is verified against (D168).
    pub server_name: String,
    /// The server's public HTTPS origin, `https://host[:port]`.
    pub public_origin: String,
    /// The server's direct QUIC listener, when it has one. An unspecified IP
    /// means the public origin's host; [`Joined::quic_address`] resolves it.
    pub endpoint: Option<SocketAddr>,
}

impl fmt::Debug for Joined {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Joined")
            .field("host_id", &self.host_id)
            .field("mode", &self.mode)
            .field("server_name", &self.server_name)
            .field("public_origin", &self.public_origin)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl Joined {
    /// The address to dial QUIC at: the invitation's endpoint, with an
    /// unspecified IP replaced by the public origin's host (resolved here).
    /// # Errors
    /// `Unsupported` when the server has no QUIC listener; name resolution
    /// failures.
    pub async fn quic_address(&self) -> io::Result<SocketAddr> {
        let endpoint = self
            .endpoint
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        if !endpoint.ip().is_unspecified() {
            return Ok(endpoint);
        }
        let (host, _) = origin_host_port(&self.public_origin)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        tokio::net::lookup_host((host.as_str(), endpoint.port()))
            .await?
            .next()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
}

/// How the join's HTTPS server is trusted.
#[derive(Clone)]
pub enum HttpsTrust {
    /// Exactly this certificate as the only root: the invitation's pinned
    /// HTTPS certificate, or its CA when it pinned none.
    Pinned(CertificateDer<'static>),
    /// Ordinary public roots; the platform makes the request.
    SystemRoots,
}

/// A checked invitation and the request body for it, waiting for the reply.
pub struct PreparedJoin {
    url: String,
    body: Zeroizing<Vec<u8>>,
    trust: HttpsTrust,
    ca: CertificateDer<'static>,
    host_id: uuid::Uuid,
    mode: Mode,
    server_name: String,
    public_origin: String,
    endpoint: Option<SocketAddr>,
    signer: Arc<dyn IdentitySigner>,
}

impl PreparedJoin {
    /// Check `invitation` for `signer`'s key and build the join request.
    ///
    /// The invitation's origin must be `https://host[:port]` with nothing
    /// else, its D168 server name present, its CA a certificate, and at most
    /// one HTTPS trust source. The mode must fit the key: P-256 only as a
    /// `device`, Ed25519 only as a host (the server enforces the same; the
    /// client refuses first so a mismatched key never spends an invitation).
    /// # Errors
    /// [`JoinError::Invitation`] for any of those; [`JoinError::Key`] when
    /// the request cannot be signed.
    pub fn new(
        invitation: JoinInvitation,
        signer: Arc<dyn IdentitySigner>,
    ) -> Result<Self, JoinError> {
        let device = invitation.mode == Mode::Device;
        if device != (signer.algorithm() == KeyAlgorithm::EcdsaP256Sha256) {
            return Err(JoinError::Invitation);
        }
        let (public_origin, server_name) = invitation_origin(&invitation)?;
        let decode = |value: &str| {
            B64.decode(value)
                .ok()
                .filter(|der| !der.is_empty() && der.len() <= MAX_CERTIFICATE)
                .map(CertificateDer::from)
                .ok_or(JoinError::Invitation)
        };
        let ca = decode(&invitation.ca_der)?;
        let trust = match (&invitation.https_der, invitation.https_system_roots) {
            (Some(_), true) => return Err(JoinError::Invitation),
            (Some(pinned), false) => HttpsTrust::Pinned(decode(pinned)?),
            (None, false) => HttpsTrust::Pinned(ca.clone()),
            (None, true) => HttpsTrust::SystemRoots,
        };
        let csr = crate::csr::certification_request(signer.as_ref()).map_err(|_| JoinError::Key)?;
        let request = JoinRequest {
            host_id: invitation.host_id,
            mode: invitation.mode,
            token: invitation.token,
            csr_der: B64.encode(csr),
        };
        let body = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| JoinError::Key)?);
        // The token lives on only in `body`, which is zeroed on drop.
        let mut token = request.token;
        zeroize::Zeroize::zeroize(&mut token);
        Ok(Self {
            url: format!("{public_origin}/remote/join"),
            body,
            trust,
            ca,
            host_id: invitation.host_id,
            mode: invitation.mode,
            server_name,
            public_origin,
            endpoint: invitation.endpoint,
            signer,
        })
    }

    /// The URL to POST to: `<public origin>/remote/join`.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The JSON body to POST (`Content-Type: application/json`). It holds the
    /// invitation's one-time token: never log it.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// How the HTTPS server must be trusted for this request.
    #[must_use]
    pub fn trust(&self) -> &HttpsTrust {
        &self.trust
    }

    /// Check the server's 200 reply `body` and return the new identity.
    ///
    /// The certificate must parse, verify as a TLS client certificate issued
    /// directly by the invited CA (rustls's own client verifier, the one the
    /// server's QUIC listener uses, so what passes here is what the server
    /// will admit) and name this signer's public key.
    /// # Errors
    /// [`JoinError::Reply`] for every failed check.
    pub fn finish(self, body: &[u8]) -> Result<Joined, JoinError> {
        if body.len() > MAX_RESPONSE {
            return Err(JoinError::Reply);
        }
        let response: JoinResponse = serde_json::from_slice(body).map_err(|_| JoinError::Reply)?;
        let leaf = B64
            .decode(&response.certificate_der)
            .ok()
            .filter(|der| !der.is_empty() && der.len() <= MAX_CERTIFICATE)
            .map(CertificateDer::from)
            .ok_or(JoinError::Reply)?;
        chains_to(&leaf, &self.ca)?;
        let identity = ClientIdentity {
            chain: vec![leaf],
            signer: self.signer,
        };
        // The key check must be definite: an identity whose key rustls cannot
        // compare with the certificate is refused here, unlike a TLS config.
        rustls::sign::CertifiedKey::new(
            identity.chain.clone(),
            Arc::new(crate::identity::signing_key(&identity.signer)),
        )
        .keys_match()
        .map_err(|_| JoinError::Reply)?;
        Ok(Joined {
            host_id: self.host_id,
            mode: self.mode,
            identity,
            ca: self.ca,
            server_name: self.server_name,
            public_origin: self.public_origin,
            endpoint: self.endpoint,
        })
    }
}

/// Redeem `invitation` with `signer`'s key over HTTPS and return the checked
/// identity, all within [`JOIN_DEADLINE`].
/// # Errors
/// [`JoinError::SystemRoots`] when the platform must make the request; the
/// refusals of [`PreparedJoin::new`] and [`PreparedJoin::finish`]; network
/// failures and non-200 statuses.
pub async fn join(
    invitation: JoinInvitation,
    signer: Arc<dyn IdentitySigner>,
) -> Result<Joined, JoinError> {
    let prepared = PreparedJoin::new(invitation, signer)?;
    let HttpsTrust::Pinned(root) = prepared.trust.clone() else {
        return Err(JoinError::SystemRoots);
    };
    let body = tokio::time::timeout(
        JOIN_DEADLINE,
        post_pinned(&prepared.public_origin, &root, prepared.body()),
    )
    .await
    .map_err(|_| JoinError::Network(io::ErrorKind::TimedOut))??;
    prepared.finish(&body)
}

/// Verify `leaf` as a client certificate issued under `ca` alone, at the
/// current time. The server's leg-B listener admits a client with this same
/// verifier, so the check matches what the server will accept.
fn chains_to(leaf: &CertificateDer<'_>, ca: &CertificateDer<'static>) -> Result<(), JoinError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).map_err(|_| JoinError::Reply)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|_| JoinError::Reply)?;
    verifier
        .verify_client_cert(leaf, &[], UnixTime::now())
        .map(|_| ())
        .map_err(|_| JoinError::Reply)
}

/// POST `body` to `<origin>/remote/join` over TLS 1.3 trusting only `root`,
/// and return the 200 reply's body (at most [`MAX_RESPONSE`] bytes).
async fn post_pinned(
    origin: &str,
    root: &CertificateDer<'static>,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, JoinError> {
    use http_body_util::BodyExt;
    let network = |kind: io::ErrorKind| JoinError::Network(kind);
    let (host, port) = origin_host_port(origin)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedServer::new(root.clone(), provider.clone())?);
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| network(io::ErrorKind::Other))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from(host.clone()).map_err(|_| JoinError::Invitation)?;
    let socket = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|error| network(error.kind()))?;
    socket
        .set_nodelay(true)
        .map_err(|error| network(error.kind()))?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(name, socket)
        .await
        .map_err(|error| network(error.kind()))?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| network(io::ErrorKind::ConnectionAborted))?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let authority = if port == 443 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/remote/join")
        .header(hyper::header::HOST, authority)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::copy_from_slice(
            body,
        )))
        .map_err(|_| JoinError::Invitation)?;
    let result = async {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| network(io::ErrorKind::ConnectionAborted))?;
        let status = response.status();
        if status != hyper::StatusCode::OK {
            return Err(JoinError::Status(status.as_u16()));
        }
        let bytes = http_body_util::Limited::new(response.into_body(), MAX_RESPONSE)
            .collect()
            .await
            .map_err(|_| JoinError::Reply)?
            .to_bytes();
        Ok(Zeroizing::new(bytes.to_vec()))
    }
    .await;
    driver.abort();
    result
}

/// Trusts the join's HTTPS server through one pinned certificate.
///
/// The pin is either an issuer (the invitation's CA, or a self-signed HTTPS
/// certificate), checked as a trust anchor by rustls's own verifier, or the
/// server's exact HTTPS leaf, which may be issued by anyone: the CLI's
/// OpenSSL client accepts that through a partial chain. An exact pin is
/// still held to the server name and its validity dates, and the handshake
/// signature is always verified against the presented certificate's key, so
/// the pin never bypasses anything but the path to a root.
#[derive(Debug)]
struct PinnedServer {
    /// The pinned certificate, as the invitation carried it.
    pinned: CertificateDer<'static>,
    /// rustls's verifier with the pin as its only trust anchor.
    anchored: Arc<rustls::client::WebPkiServerVerifier>,
    /// The signature algorithms for the handshake signature.
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinnedServer {
    /// A verifier that trusts `pinned` only.
    /// # Errors
    /// [`JoinError::Invitation`] when the pin is not a usable certificate.
    fn new(
        pinned: CertificateDer<'static>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<Self, JoinError> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(pinned.clone())
            .map_err(|_| JoinError::Invitation)?;
        let algorithms = provider.signature_verification_algorithms;
        let anchored =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|_| JoinError::Invitation)?;
        Ok(Self {
            pinned,
            anchored,
            algorithms,
        })
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let anchored = self.anchored.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        if anchored.is_ok() || end_entity.as_ref() != self.pinned.as_ref() {
            return anchored;
        }
        // The exact pinned leaf: name and dates still hold.
        let parsed = rustls::server::ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_name(&parsed, server_name)?;
        let (not_before, not_after) =
            crate::server_leaf_floor::validity_seconds(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let now = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
        if now < not_before {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidYet,
            ));
        }
        if now > not_after {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired,
            ));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The invitation's canonical public origin and its D168 server name.
///
/// A legacy invitation has no public origin: its server name is the origin's
/// host and the server name at once. Otherwise both must be present.
fn invitation_origin(invitation: &JoinInvitation) -> Result<(String, String), JoinError> {
    if invitation.public_origin.is_empty() {
        let origin = format!("https://{}", invitation.server_name);
        let (host, _) = origin_host_port(&origin)?;
        return Ok((canonical_origin(&origin)?, host));
    }
    if invitation.server_name.is_empty() {
        return Err(JoinError::Invitation);
    }
    Ok((
        canonical_origin(&invitation.public_origin)?,
        invitation.server_name.clone(),
    ))
}

/// Parse `value` as an `https` origin with no credentials, path, query or
/// fragment, and return it in its canonical serialization.
fn canonical_origin(value: &str) -> Result<String, JoinError> {
    let parsed = url::Url::parse(value).map_err(|_| JoinError::Invitation)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(JoinError::Invitation);
    }
    Ok(parsed.origin().ascii_serialization())
}

/// The host (without IPv6 brackets) and port of a canonical `https` origin.
fn origin_host_port(origin: &str) -> Result<(String, u16), JoinError> {
    let parsed = url::Url::parse(origin).map_err(|_| JoinError::Invitation)?;
    let host = match parsed.host().ok_or(JoinError::Invitation)? {
        url::Host::Ipv6(address) => address.to_string(),
        host => host.to_string(),
    };
    let port = parsed
        .port_or_known_default()
        .ok_or(JoinError::Invitation)?;
    Ok((host, port))
}

/// Tests for the invitation checks, which need no server.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{Ed25519Pkcs8, SoftwareP256};

    /// A device invitation for `origin`, with a placeholder CA.
    fn invitation(origin: &str, mode: Mode) -> JoinInvitation {
        serde_json::from_value(serde_json::json!({
            "host_id": uuid::Uuid::nil(),
            "mode": mode.as_str(),
            "execution_uid": 0,
            "public_origin": origin,
            "token": "t",
            "ca_der": B64.encode([0x30, 0x03, 0x02, 0x01, 0x00]),
            "server_name": "infraternal.example.test",
        }))
        .unwrap()
    }

    /// A P-256 device signer.
    fn device() -> Arc<dyn IdentitySigner> {
        Arc::new(SoftwareP256::generate().unwrap())
    }

    /// A clean origin is accepted and the URL is built from it.
    #[test]
    fn a_device_invitation_builds_the_join_url() {
        let prepared = PreparedJoin::new(
            invitation("https://Example.test:8443", Mode::Device),
            device(),
        )
        .unwrap();
        assert_eq!(prepared.url(), "https://example.test:8443/remote/join");
        let body: serde_json::Value = serde_json::from_slice(prepared.body()).unwrap();
        assert_eq!(body["mode"], "device");
        assert!(matches!(prepared.trust(), HttpsTrust::Pinned(_)));
    }

    /// Non-origin URLs, plain HTTP and credentials are refused.
    #[test]
    fn non_origin_urls_are_refused() {
        for origin in [
            "http://example.test",
            "https://example.test/path",
            "https://user@example.test",
            "https://example.test/?q",
            "https://example.test/#f",
            "not a url",
        ] {
            assert_eq!(
                PreparedJoin::new(invitation(origin, Mode::Device), device()).err(),
                Some(JoinError::Invitation),
                "{origin}"
            );
        }
    }

    /// P-256 joins only as a device, Ed25519 only as a host.
    #[test]
    fn the_key_must_fit_the_mode() {
        assert_eq!(
            PreparedJoin::new(invitation("https://example.test", Mode::Rootless), device()).err(),
            Some(JoinError::Invitation)
        );
        let random = ring::rand::SystemRandom::new();
        let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&random).unwrap();
        let host: Arc<dyn IdentitySigner> =
            Arc::new(Ed25519Pkcs8::from_pkcs8(document.as_ref()).unwrap());
        assert_eq!(
            PreparedJoin::new(invitation("https://example.test", Mode::Device), host).err(),
            Some(JoinError::Invitation)
        );
    }

    /// Public-roots servers need the platform's request; pinning both a
    /// certificate and public roots is refused.
    #[tokio::test]
    async fn system_roots_are_left_to_the_platform() {
        let mut public = invitation("https://example.test", Mode::Device);
        public.https_system_roots = true;
        assert_eq!(
            join(public.clone(), device()).await.err(),
            Some(JoinError::SystemRoots)
        );
        public.https_der = Some(public.ca_der.clone());
        assert_eq!(
            PreparedJoin::new(public, device()).err(),
            Some(JoinError::Invitation)
        );
    }

    /// A reply that is not a certificate from the invited CA is refused.
    #[test]
    fn unverifiable_replies_are_refused() {
        let prepared =
            PreparedJoin::new(invitation("https://example.test", Mode::Device), device()).unwrap();
        let reply = serde_json::json!({
            "certificate_der": B64.encode([0x30, 0x00]),
            "execution_uid": 0,
        });
        assert_eq!(
            prepared.finish(&serde_json::to_vec(&reply).unwrap()).err(),
            Some(JoinError::Reply)
        );
    }
}
