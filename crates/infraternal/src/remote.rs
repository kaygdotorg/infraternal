//! Implements the operator-only private-stdin join adapter and local identity publication; no capability is accepted in argv [132][133], #78.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hyper::{StatusCode, header};
use infraternal_agent::{
    remote_client::{self, RemoteIdentity},
    remote_tls::Identity,
};
use infraternal_plugin_remote::enrollment::{JoinInvitation, JoinRequest, JoinResponse, Mode};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{X509, X509NameBuilder, X509Req, X509StoreContext, store::X509StoreBuilder},
};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentity {
    host_id: uuid::Uuid,
    execution_uid: u32,
    /// Legacy direct endpoint; migrated identities use only `public_origin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    endpoint: Option<std::net::SocketAddr>,
    server_name: String,
    /// Public application origin used for enrollment and the server link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_origin: Option<String>,
    /// Optional independently pinned public HTTPS issuer/leaf.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    https_der: Option<String>,
    /// Public HTTPS uses operating-system trust roots.
    #[serde(default)]
    https_system_roots: bool,
    ca_der: String,
    certificate_der: String,
    key_der: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity_rotation: Option<StoredRotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_identity_rotation:
        Option<infraternal_plugin_remote::identity_rotation::CompletedRotation>,
}

/// A pending host identity rotation as stored on disk: the challenge, the candidate private key and, once issued, its
/// certificate. The key is held in a buffer that is wiped on drop.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRotation {
    challenge: infraternal_plugin_remote::identity_rotation::Challenge,
    candidate_key_der: Zeroizing<String>,
    certificate_der: Option<String>,
}

/// A fixed-capacity serializer target for identity documents containing private material.
struct IdentityJsonWriter(Zeroizing<Vec<u8>>);

impl std::io::Write for IdentityJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(end) = self.0.len().checked_add(bytes.len()) else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        if end > 8192 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serialize identity state into wipe-on-drop storage without an intermediate JSON vector.
fn serialize_identity_document(stored: &StoredIdentity) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut writer = IdentityJsonWriter(Zeroizing::new(Vec::with_capacity(8192)));
    serde_json::to_writer(&mut writer, stored).map_err(|_| refused())?;
    Ok(writer.0)
}

/// Encode directly into the zeroizing base64 string retained in the identity model.
fn encode_candidate_key(key_pkcs8: &[u8]) -> Zeroizing<String> {
    let capacity = key_pkcs8.len().saturating_add(2) / 3 * 4;
    let mut encoded = Zeroizing::new(String::with_capacity(capacity));
    B64.encode_string(key_pkcs8, &mut encoded);
    encoded
}

/// Decode into a zeroizing allocation sized to avoid a secret-bearing reallocation.
fn decode_candidate_key(encoded: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    if encoded.len() > 2048 {
        return Err(refused());
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(encoded.len()));
    B64.decode_vec(encoded, &mut decoded)
        .map_err(|_| refused())?;
    Ok(decoded)
}

const PENDING_JOIN_KEY: &str = "join-key.pk8";

/// Why a join step failed, in the classes a caller acts on.
///
/// The class travels inside the `io::Error` as its source, so the command can pick the exit
/// code (D303) from the type. Matching on message text would silently stop working the day a
/// message is reworded. `Display` is the public sentence: it names no path, address or secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Failure {
    /// The invitation or the answer was not accepted; the reason is deliberately not detailed.
    Refused,
    /// The server's name could not be resolved.
    Dns(&'static str),
    /// The server could not be reached.
    Connect,
    /// The server's certificate did not verify.
    Tls,
    /// The app listener or its proxy did not complete the expected upgrade.
    Upgrade,
    /// The upgraded route did not send a valid app-level challenge.
    Challenge,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Refused => "remote infraternal agent operation refused",
            Self::Dns(sentence) => sentence,
            Self::Connect => "The infraternal agent on this host cannot reach the server over HTTPS. Allow outbound TCP 443 to the server's public origin, then try again.",
            Self::Tls => "The infraternal agent on this host could not verify the server's HTTPS certificate. Check the public certificate chain and server name, then try again.",
            Self::Upgrade => "The infraternal agent on this host reached the server over HTTPS, but the server or proxy did not accept the HTTP/1.1 WebSocket upgrade at /remote/agent. Check that the TLS proxy forwards WebSocket upgrades on this path, then try again.",
            Self::Challenge => "The server opened the WebSocket but did not send a valid infraternal agent challenge. Deploy a compatible server build and try again.",
        })
    }
}

impl std::error::Error for Failure {}

impl Failure {
    /// The class an error carries, if it was built by this module.
    pub(crate) fn of(error: &io::Error) -> Option<Self> {
        error.get_ref()?.downcast_ref::<Self>().copied()
    }

    fn error(self, kind: io::ErrorKind) -> io::Error {
        io::Error::new(kind, self)
    }
}

fn refused() -> io::Error {
    Failure::Refused.error(io::ErrorKind::PermissionDenied)
}

pub(crate) fn default_data() -> io::Result<PathBuf> {
    let root = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or_else(refused)?;
    Ok(root.join("infraternal/agent"))
}

pub(crate) async fn join(url: &str, data: &Path, input: &[u8]) -> io::Result<()> {
    join_with_key_inner(url, data, input, None).await
}

/// Enroll the exact key whose public fingerprint was approved before system elevation.
pub(crate) async fn join_with_key(
    url: &str,
    data: &Path,
    invitation: &[u8],
    key_pkcs8: &[u8],
) -> io::Result<()> {
    join_with_key_inner(url, data, invitation, Some(key_pkcs8)).await
}

async fn join_with_key_inner(
    url: &str,
    data: &Path,
    input: &[u8],
    key_pkcs8: Option<&[u8]>,
) -> io::Result<()> {
    if input.len() > 8192 {
        return Err(refused());
    }
    if key_pkcs8.is_some_and(|bytes| bytes.is_empty() || bytes.len() > 4096) {
        return Err(refused());
    }
    let invitation: JoinInvitation = serde_json::from_slice(input).map_err(|_| refused())?;
    let (public_origin, server_name) = invitation_origin(&invitation)?;
    if !invitation.public_origin.is_empty() && join_origin(url)? != public_origin {
        return Err(refused());
    }
    let uid = nix::unistd::Uid::effective().as_raw();
    if uid != invitation.execution_uid || (invitation.mode == Mode::Rootless) == (uid == 0) {
        return Err(refused());
    }
    // The host key is immutable (#78): SSH setup copies an enrolled identity
    // into its transaction before joining, and a published-setup Retry joins
    // the same host again (#87, #230). Re-enroll that host's own key only when
    // the invitation names the server that enrolled it (host id, uid, server
    // name, and a CA that is the stored one or issued the stored certificate).
    // These are public fields an invitation can copy, so this check alone does
    // not stop the CSR from reaching a server the invitation points at. The
    // real guard is the response check below: the issued certificate must be
    // for this key and chain to the invited root, and the stored identity is
    // replaced only after that.
    let previous = enrolled_key(data, &invitation, uid, &server_name)?;
    let supplied_key = key_pkcs8
        .map(|bytes| PKey::private_key_from_pkcs8(bytes).map_err(|_| refused()))
        .transpose()?;
    let (key, snapshot) = match (previous, supplied_key) {
        (Some((key, snapshot)), Some(supplied)) if key.public_eq(&supplied) => {
            (key, Some(snapshot))
        }
        (Some(_), Some(_)) => return Err(refused()),
        (Some((key, snapshot)), None) => (key, Some(snapshot)),
        (None, Some(key)) => (key, None),
        (None, None) => (prepared_key(data)?, None),
    };
    let request = JoinRequest {
        host_id: invitation.host_id,
        mode: invitation.mode,
        token: invitation.token,
        csr_der: join_csr_der(&key)?,
    };
    let root = X509::from_der(&B64.decode(&invitation.ca_der).map_err(|_| refused())?)
        .map_err(|_| refused())?;
    let https = invitation
        .https_der
        .as_ref()
        .map(|der| {
            B64.decode(der)
                .map_err(|_| refused())
                .and_then(|der| X509::from_der(&der).map_err(|_| refused()))
        })
        .transpose()?;
    if invitation.https_system_roots && https.is_some() {
        return Err(refused());
    }
    let https_root = if invitation.https_system_roots {
        None
    } else {
        Some(https.as_ref().unwrap_or(&root))
    };
    preflight(&public_origin, https_root, invitation.https_system_roots).await?;
    let response = tokio::time::timeout(Duration::from_secs(10), redeem(url, https_root, &request))
        .await
        .map_err(|_| refused())??;
    if response.execution_uid != uid {
        return Err(refused());
    }
    let certificate = X509::from_der(
        &B64.decode(&response.certificate_der)
            .map_err(|_| refused())?,
    )
    .map_err(|_| refused())?;
    if !certificate
        .public_key()
        .map_err(|_| refused())?
        .public_eq(&key)
    {
        return Err(refused());
    }
    if !chains_to(&certificate, root)? {
        return Err(refused());
    }
    let stored = StoredIdentity {
        host_id: invitation.host_id,
        execution_uid: uid,
        endpoint: None,
        server_name,
        public_origin: Some(public_origin),
        https_der: invitation.https_der,
        https_system_roots: invitation.https_system_roots,
        ca_der: invitation.ca_der,
        certificate_der: response.certificate_der,
        key_der: B64.encode(key.private_key_to_pkcs8().map_err(|_| refused())?),
        identity_rotation: None,
        completed_identity_rotation: None,
    };
    let bytes = serialize_identity_document(&stored)?;
    match snapshot {
        Some(snapshot) => replace(data, &bytes, Some(&snapshot))?,
        None => publish(data, &bytes)?,
    }
    retire_pending_key(data)
}

/// Verify the public route before creating the private key the SSH setup session will bind.
pub(crate) async fn prepare_join_key(origin: &str, data: &Path) -> io::Result<[u8; 32]> {
    preflight(origin, None, true).await?;
    prepared_key_digest(data)
}

/// Prepare a new machine key without reusing this user's existing agent identity.
pub(crate) async fn prepare_machine_join_key(origin: &str, data: &Path) -> io::Result<[u8; 32]> {
    preflight(origin, None, true).await?;
    prepare(data).map_err(|error| local_state(error.kind()))?;
    prepared_key_digest(data).map_err(|error| local_state(error.kind()))
}

fn join_csr_der(key: &PKey<openssl::pkey::Private>) -> io::Result<String> {
    let mut csr = X509Req::builder().map_err(|_| refused())?;
    csr.set_subject_name(&X509NameBuilder::new().map_err(|_| refused())?.build())
        .map_err(|_| refused())?;
    csr.set_pubkey(key).map_err(|_| refused())?;
    csr.sign(key, MessageDigest::null())
        .map_err(|_| refused())?;
    Ok(B64.encode(csr.build().to_der().map_err(|_| refused())?))
}

fn local_state(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "local machine state could not be accessed")
}

fn prepared_key_digest(data: &Path) -> io::Result<[u8; 32]> {
    let key = prepared_key(data)?;
    let public = key.raw_public_key().map_err(|_| refused())?;
    Ok(openssl::sha::sha256(&public))
}

/// Read the prepared private key only for a private, bounded handoff to the root helper.
pub(crate) fn prepared_join_key_pkcs8(data: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let key = prepared_key(data)?;
    key.private_key_to_pkcs8()
        .map(Zeroizing::new)
        .map_err(|_| refused())
}

/// Remove the user's pending key after the root-owned identity has been published.
pub(crate) fn retire_prepared_join_key(data: &Path) -> io::Result<()> {
    retire_pending_key(data)
}

/// Derive the approved key's public digest from its private PKCS#8 handoff bytes.
pub(crate) fn key_digest_from_pkcs8(bytes: &[u8]) -> io::Result<[u8; 32]> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(refused());
    }
    let key = PKey::private_key_from_pkcs8(bytes).map_err(|_| refused())?;
    let public = key.raw_public_key().map_err(|_| refused())?;
    Ok(openssl::sha::sha256(&public))
}

/// Reuse a previously enrolled key or persist one private key for the later CSR.
fn prepared_key(data: &Path) -> io::Result<PKey<openssl::pkey::Private>> {
    prepare_directory(data)?;
    match std::fs::symlink_metadata(data.join("identity.json")) {
        Ok(_) => {
            let (stored, _) = load_snapshot(data)?;
            return PKey::private_key_from_pkcs8(
                &B64.decode(&stored.key_der).map_err(|_| refused())?,
            )
            .map_err(|_| refused());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(refused()),
    }
    if let Some(key) = read_pending_key(data)? {
        return Ok(key);
    }
    let key = PKey::generate_ed25519().map_err(|_| refused())?;
    if write_pending_key(data, &key)? {
        Ok(key)
    } else {
        read_pending_key(data)?.ok_or_else(refused)
    }
}

fn read_pending_key(data: &Path) -> io::Result<Option<PKey<openssl::pkey::Private>>> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(data.join(PENDING_JOIN_KEY))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(refused()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() == 0
        || metadata.len() > 4096
    {
        return Err(refused());
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| refused())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(refused());
    }
    PKey::private_key_from_pkcs8(&bytes)
        .map(Some)
        .map_err(|_| refused())
}

fn write_pending_key(data: &Path, key: &PKey<openssl::pkey::Private>) -> io::Result<bool> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let bytes = Zeroizing::new(key.private_key_to_pkcs8().map_err(|_| refused())?);
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(data.join(PENDING_JOIN_KEY))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Ok(false);
        }
        Err(_) => return Err(refused()),
    };
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::File::open(data)?.sync_all()?;
    Ok(true)
}

fn retire_pending_key(data: &Path) -> io::Result<()> {
    match std::fs::remove_file(data.join(PENDING_JOIN_KEY)) {
        Ok(()) => std::fs::File::open(data)?.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(refused()),
    }
}

fn https_origin(value: &str) -> io::Result<(url::Url, String)> {
    let parsed = url::Url::parse(value).map_err(|_| refused())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(refused());
    }
    Ok((parsed.clone(), parsed.origin().ascii_serialization()))
}

/// Use the app origin for HTTPS and preserve the invitation's D168 identity name.
fn invitation_origin(invitation: &JoinInvitation) -> io::Result<(String, String)> {
    let legacy = invitation.public_origin.is_empty();
    let value = if legacy {
        format!("https://{}", invitation.server_name)
    } else {
        invitation.public_origin.clone()
    };
    let (origin, canonical) = https_origin(&value)?;
    let server_name = if legacy {
        origin.host_str().ok_or_else(refused)?.to_owned()
    } else if invitation.server_name.is_empty() {
        return Err(refused());
    } else {
        invitation.server_name.clone()
    };
    Ok((canonical, server_name))
}

/// Enrollment and the steady-state link must name the same public app origin.
fn join_origin(value: &str) -> io::Result<String> {
    let parsed = url::Url::parse(value).map_err(|_| refused())?;
    if parsed.scheme() != "https"
        || parsed.path() != "/remote/join"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(refused());
    }
    Ok(parsed.origin().ascii_serialization())
}

/// Verify `certificate` as a client certificate issued under `root` alone.
fn chains_to(certificate: &X509, root: X509) -> io::Result<bool> {
    let mut trust = X509StoreBuilder::new().map_err(|_| refused())?;
    trust.add_cert(root).map_err(|_| refused())?;
    let mut parameters = openssl::x509::verify::X509VerifyParam::new().map_err(|_| refused())?;
    parameters
        .set_purpose(openssl::x509::X509PurposeId::SSL_CLIENT)
        .map_err(|_| refused())?;
    trust.set_param(&parameters).map_err(|_| refused())?;
    let chain = openssl::stack::Stack::new().map_err(|_| refused())?;
    X509StoreContext::new()
        .map_err(|_| refused())?
        .init(
            &trust.build(),
            certificate,
            &chain,
            openssl::x509::X509StoreContextRef::verify_cert,
        )
        .map_err(|_| refused())
}

/// Return the key of an identity this invitation may re-enroll, and the file
/// it was read from.
///
/// The host id alone does not name a host: a cloned server database or any
/// other server can issue the same id (#230). Only the server that enrolled
/// the identity may re-enroll it: same host id, uid and server name, and the
/// invitation's CA is the stored one or issued the stored certificate. The
/// endpoint may change (a server moved to another address).
fn enrolled_key(
    data: &Path,
    invitation: &JoinInvitation,
    uid: u32,
    server_name: &str,
) -> io::Result<Option<(PKey<openssl::pkey::Private>, Snapshot)>> {
    prepare_directory(data)?;
    match std::fs::symlink_metadata(data.join("identity.json")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(refused()),
        Ok(_) => {}
    }
    let (stored, snapshot) = load_snapshot(data)?;
    if stored.host_id != invitation.host_id
        || stored.execution_uid != uid
        || stored.server_name != server_name
    {
        return Err(refused());
    }
    let der = |value: &str| B64.decode(value).map_err(|_| refused());
    let stored_ca = der(&stored.ca_der)?;
    let invited_ca = der(&invitation.ca_der)?;
    if stored_ca != invited_ca {
        let certificate = X509::from_der(&der(&stored.certificate_der)?).map_err(|_| refused())?;
        let root = X509::from_der(&invited_ca).map_err(|_| refused())?;
        if !chains_to(&certificate, root)? {
            return Err(refused());
        }
    }
    let key = PKey::private_key_from_pkcs8(&der(&stored.key_der)?).map_err(|_| refused())?;
    Ok(Some((key, snapshot)))
}

/// DNS is its own boundary: retain only known public resolver diagnostics.
async fn connect_enrollment(name: &str, port: u16) -> io::Result<tokio::net::TcpStream> {
    let addresses = tokio::net::lookup_host((name, port))
        .await
        .map_err(|error| {
            Failure::Dns(
                "The infraternal agent on this host cannot resolve the server's HTTPS origin. Check DNS for the public origin and allow outbound TCP 443.",
            )
            .error(error.kind())
        })?
        .collect::<Vec<_>>();
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(addresses.as_slice()),
    )
    .await
    .map_err(|_| Failure::Connect.error(io::ErrorKind::TimedOut))?
    .map_err(|error| Failure::Connect.error(error.kind()))
}

/// Verify that the target can reach the enrolled public app listener before installation.
async fn preflight(origin: &str, root: Option<&X509>, system_roots: bool) -> io::Result<()> {
    use infraternal_agent::remote_websocket::PreflightFailure as WebSocketFailure;
    infraternal_agent::remote_websocket::preflight(origin, root, system_roots)
        .await
        .map_err(|failure| match failure {
            WebSocketFailure::InvalidOrigin => refused(),
            WebSocketFailure::Dns => Failure::Dns(
                "The infraternal agent on this host cannot resolve the server's HTTPS origin. Check DNS for the public origin and allow outbound TCP 443.",
            )
            .error(io::ErrorKind::AddrNotAvailable),
            WebSocketFailure::Connect => Failure::Connect.error(io::ErrorKind::NotConnected),
            WebSocketFailure::Tls => Failure::Tls.error(io::ErrorKind::PermissionDenied),
            WebSocketFailure::Upgrade => Failure::Upgrade.error(io::ErrorKind::InvalidData),
            WebSocketFailure::Challenge => {
                Failure::Challenge.error(io::ErrorKind::InvalidData)
            }
        })
}

/// A failure at the shared outbound HTTPS boundary, before application JSON is decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientFailure {
    Dns(&'static str, io::ErrorKind),
    Connect(io::ErrorKind),
    SocketOption(io::ErrorKind),
    TlsConfiguration,
    TlsHandshake,
    HttpHandshake,
    Request,
    ResponseBody,
}

/// Status and the bounded, zeroizable body returned by the shared JSON client.
pub(crate) struct ClientResponse {
    pub(crate) status: StatusCode,
    pub(crate) retry_after: Option<Duration>,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

/// Keeps request bytes zeroizable after Hyper has consumed its reference to the payload.
struct SecretBytes(bytes::Bytes);

impl SecretBytes {
    fn clone_for_request(&self) -> bytes::Bytes {
        self.0.clone()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        let bytes = std::mem::replace(&mut self.0, bytes::Bytes::new());
        if let Ok(mut bytes) = bytes.try_into_mut() {
            bytes.as_mut().zeroize();
        }
    }
}

/// Sends a bounded JSON POST over the same TLS and HTTP path as remote enrollment.
///
/// Callers own timeout policy and JSON interpretation. `root` is only for the join
/// invitation's pinned trust root; ordinary sign-in uses the platform CA store.
pub(crate) async fn post_json(
    url: &url::Url,
    path: &str,
    body: bytes::Bytes,
    root: Option<&X509>,
    max_response_bytes: usize,
    request_started: &mut bool,
) -> Result<ClientResponse, ClientFailure> {
    use http_body_util::BodyExt;

    let name = url.host_str().ok_or(ClientFailure::HttpHandshake)?;
    let port = url
        .port_or_known_default()
        .ok_or(ClientFailure::HttpHandshake)?;
    let tls = outbound_tls_connector(root)?;
    let socket =
        connect_enrollment(name, port)
            .await
            .map_err(|error| match Failure::of(&error) {
                Some(Failure::Dns(message)) => ClientFailure::Dns(message, error.kind()),
                _ => ClientFailure::Connect(error.kind()),
            })?;
    socket
        .set_nodelay(true)
        .map_err(|error| ClientFailure::SocketOption(error.kind()))?;
    let ssl = tls
        .configure()
        .map_err(|_| ClientFailure::TlsConfiguration)?
        .into_ssl(name)
        .map_err(|_| ClientFailure::TlsConfiguration)?;
    let mut stream =
        tokio_openssl::SslStream::new(ssl, socket).map_err(|_| ClientFailure::TlsConfiguration)?;
    std::pin::Pin::new(&mut stream)
        .connect()
        .await
        .map_err(|_| ClientFailure::TlsHandshake)?;

    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|_| ClientFailure::HttpHandshake)?;
    let connection = AbortConnection(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request_body = SecretBytes(body);
    let request = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header(
            header::HOST,
            url[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(request_body.clone_for_request()))
        .map_err(|_| ClientFailure::HttpHandshake)?;
    // Hyper may poll the request body as soon as this send future is polled.
    *request_started = true;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| ClientFailure::Request);
    drop(request_body);
    let response = response?;
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs);
    let body = if status == StatusCode::OK {
        let bytes = http_body_util::Limited::new(response.into_body(), max_response_bytes)
            .collect()
            .await
            .map_err(|_| ClientFailure::ResponseBody)?
            .to_bytes();
        let body = Zeroizing::new(bytes.to_vec());
        if let Ok(mut bytes) = bytes.try_into_mut() {
            bytes.as_mut().zeroize();
        }
        body
    } else {
        // Error bodies are not part of these protocols; status and headers decide the outcome.
        drop(response.into_body());
        Zeroizing::new(Vec::new())
    };
    drop(connection);
    Ok(ClientResponse {
        status,
        retry_after,
        body,
    })
}

/// Builds the shared TLS connector before a request opens its socket.
///
/// Sign-in and the hosted CLI actions use platform trust; join may supply its existing pinned
/// root. All retain TLS 1.3, peer verification, and hostname checks so the shared transport
/// cannot weaken any flow.
pub(crate) fn outbound_tls_connector(root: Option<&X509>) -> Result<SslConnector, ClientFailure> {
    let mut tls = SslConnector::builder(SslMethod::tls_client())
        .map_err(|_| ClientFailure::TlsConfiguration)?;
    tls.set_min_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|_| ClientFailure::TlsConfiguration)?;
    // The enrollment and other requests on this connector use Hyper's HTTP/1 client.
    tls.set_alpn_protos(b"\x08http/1.1")
        .map_err(|_| ClientFailure::TlsConfiguration)?;
    tls.set_verify(SslVerifyMode::PEER);
    if let Some(root) = root {
        let mut trust = X509StoreBuilder::new().map_err(|_| ClientFailure::TlsConfiguration)?;
        trust
            .add_cert(root.clone())
            .map_err(|_| ClientFailure::TlsConfiguration)?;
        // A pinned root may issue the HTTPS leaf, but does not bypass hostname or validity checks.
        trust
            .set_flags(openssl::x509::verify::X509VerifyFlags::PARTIAL_CHAIN)
            .map_err(|_| ClientFailure::TlsConfiguration)?;
        tls.set_cert_store(trust.build());
    } else {
        tls.set_default_verify_paths()
            .map_err(|_| ClientFailure::TlsConfiguration)?;
        // Vendored OpenSSL may have a build-time prefix absent on this host.
        // Use the system's public bundle, never an enrollment TOFU pin.
        for bundle in [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
        ] {
            if Path::new(bundle).is_file() {
                tls.set_ca_file(bundle)
                    .map_err(|_| ClientFailure::TlsConfiguration)?;
                break;
            }
        }
    }
    Ok(tls.build())
}

/// CLI output can carry only these authored public sentences, never arbitrary errors.
pub(crate) fn public_error(error: &io::Error) -> &'static str {
    match Failure::of(error) {
        Some(Failure::Dns(sentence)) => sentence,
        Some(Failure::Connect) => {
            "The infraternal agent on this host cannot reach the server over HTTPS. Allow outbound TCP 443 to the server's public origin, then try again."
        }
        Some(Failure::Tls) => {
            "The infraternal agent on this host could not verify the server's HTTPS certificate. Check the public certificate chain and server name, then try again."
        }
        Some(Failure::Upgrade) => {
            "The infraternal agent on this host reached the server over HTTPS, but the server or proxy did not accept the HTTP/1.1 WebSocket upgrade at /remote/agent. Check that the TLS proxy forwards WebSocket upgrades on this path, then try again."
        }
        Some(Failure::Challenge) => {
            "The server opened the WebSocket but did not send a valid infraternal agent challenge. Deploy a compatible server build and try again."
        }
        Some(Failure::Refused) | None => "Remote infraternal agent operation failed",
    }
}

async fn redeem(url: &str, root: Option<&X509>, request: &JoinRequest) -> io::Result<JoinResponse> {
    let url = url::Url::parse(url).map_err(|_| refused())?;
    if url.scheme() != "https"
        || url.path() != "/remote/join"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(refused());
    }
    let body = serde_json::to_vec(request).map_err(|_| refused())?;
    let mut request_started = false;
    let response = post_json(
        &url,
        url.path(),
        bytes::Bytes::from(body),
        root,
        8192,
        &mut request_started,
    )
    .await
    .map_err(client_failure_to_io)?;
    if response.status != StatusCode::OK {
        return Err(refused());
    }
    serde_json::from_slice(&response.body).map_err(|_| refused())
}

fn client_failure_to_io(failure: ClientFailure) -> io::Error {
    match failure {
        ClientFailure::Dns(message, kind) => Failure::Dns(message).error(kind),
        ClientFailure::Connect(kind) => Failure::Connect.error(kind),
        ClientFailure::SocketOption(kind) => io::Error::from(kind),
        ClientFailure::TlsHandshake => Failure::Tls.error(io::ErrorKind::PermissionDenied),
        ClientFailure::TlsConfiguration
        | ClientFailure::HttpHandshake
        | ClientFailure::Request
        | ClientFailure::ResponseBody => refused(),
    }
}

struct AbortConnection(tokio::task::JoinHandle<()>);
impl Drop for AbortConnection {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn prepare(data: &Path) -> io::Result<()> {
    prepare_directory(data)?;
    match std::fs::symlink_metadata(data.join("identity.json")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(refused()),
    }
}

fn prepare_directory(data: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(data)?;
    let metadata = std::fs::symlink_metadata(data)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(refused());
    }
    Ok(())
}

fn publish(data: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    prepare(data)?;
    let pending = data.join(format!("identity-{}.pending", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // Do not replace an existing installation. hard_link publishes the exact
        // fsynced inode with atomic no-replace semantics on the same filesystem.
        std::fs::hard_link(&pending, data.join("identity.json"))?;
        std::fs::File::open(data)?.sync_all()
    })();
    let _ = std::fs::remove_file(pending);
    result
}

/// Read the private identity, refusing links, shared files and oversized input.
/// The identity file a join or renewal read: its inode and exact bytes.
/// A replace aborts unless identity.json is still this file, so a concurrent
/// enrollment or renewal is never overwritten with a stale identity.
struct Snapshot {
    device: u64,
    inode: u64,
    /// The identity document can include the pending candidate's base64 private key.
    bytes: Zeroizing<Vec<u8>>,
}

fn load_snapshot(data: &Path) -> io::Result<(StoredIdentity, Snapshot)> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(data.join("identity.json"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 8192
    {
        return Err(refused());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(8192));
    file.take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(refused());
    }
    let stored = serde_json::from_slice(&bytes).map_err(|_| refused())?;
    let snapshot = Snapshot {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes,
    };
    Ok((stored, snapshot))
}

/// Move an enrolled identity off its legacy 7443 address before the service retries.
fn migrate_identity(data: &Path) -> io::Result<StoredIdentity> {
    let (mut stored, snapshot) = load_snapshot(data)?;
    let mut changed = false;
    if stored.public_origin.is_none() {
        let legacy_origin = format!("https://{}", stored.server_name);
        let (_, canonical) = https_origin(&legacy_origin)?;
        stored.public_origin = Some(canonical);
        stored.https_der = None;
        stored.https_system_roots = true;
        changed = true;
    }
    if stored.endpoint.take().is_some() {
        changed = true;
    }
    if changed {
        let bytes = serialize_identity_document(&stored)?;
        replace(data, &bytes, Some(&snapshot))?;
    }
    Ok(stored)
}

pub(crate) async fn run(data: &Path, state: Option<PathBuf>) -> io::Result<()> {
    let stored = migrate_identity(data)?;
    let public_origin = stored.public_origin.clone().ok_or_else(refused)?;
    let https_root = if stored.https_system_roots {
        None
    } else if let Some(https) = &stored.https_der {
        Some(X509::from_der(&B64.decode(https).map_err(|_| refused())?).map_err(|_| refused())?)
    } else {
        Some(
            X509::from_der(&B64.decode(&stored.ca_der).map_err(|_| refused())?)
                .map_err(|_| refused())?,
        )
    };
    let identity = RemoteIdentity {
        host_id: stored.host_id,
        identity: Identity {
            certificate: X509::from_der(
                &B64.decode(&stored.certificate_der).map_err(|_| refused())?,
            )
            .map_err(|_| refused())?,
            key: PKey::private_key_from_pkcs8(&B64.decode(&stored.key_der).map_err(|_| refused())?)
                .map_err(|_| refused())?,
        },
        roots: vec![
            X509::from_der(&B64.decode(&stored.ca_der).map_err(|_| refused())?)
                .map_err(|_| refused())?,
        ],
        endpoint: stored.endpoint,
        server_name: stored.server_name.clone(),
        public_origin: Some(public_origin),
        https_root,
        https_system_roots: stored.https_system_roots,
        execution_uid: stored.execution_uid,
    };
    #[cfg(target_os = "linux")]
    let installation =
        state
            .as_ref()
            .map(|sessions| infraternal_plugin_remote::uninstall::Context {
                host: stored.host_id.simple().to_string(),
                uid: stored.execution_uid,
                data: data.to_owned(),
                sessions: sessions.clone(),
            });
    // The Mac node discards saved mesh state that another enrolment issued (#265, #325).
    #[cfg(all(target_os = "macos", feature = "plugin-mesh"))]
    let installation = Some(infraternal_plugin_mesh::node::Enrolment::new(
        &B64.decode(&stored.ca_der).map_err(|_| refused())?,
        &stored.host_id.simple().to_string(),
        &identity
            .identity
            .key
            .public_key_to_der()
            .map_err(|_| refused())?,
    ));
    #[cfg(not(any(target_os = "linux", all(target_os = "macos", feature = "plugin-mesh"))))]
    let installation = None;
    let publisher = std::sync::Arc::new(IdentityPublisher {
        data: data.to_owned(),
    });
    remote_client::run_with_identity_rotation(
        &identity,
        state,
        publisher.clone(),
        publisher,
        installation.as_ref(),
    )
    .await
}

/// The existing installation is the publication boundary; no new key is generated.
struct IdentityPublisher {
    data: PathBuf,
}
impl infraternal_agent::remote_renewal::CertificatePublisher for IdentityPublisher {
    fn publish(&self, certificate: &X509) -> io::Result<()> {
        let (mut stored, snapshot) = load_snapshot(&self.data)?;
        let certificate_der = B64.encode(certificate.to_der().map_err(|_| refused())?);
        if let Some(pending) = &mut stored.identity_rotation {
            let candidate_der = decode_candidate_key(&pending.candidate_key_der)?;
            let candidate = PKey::private_key_from_pkcs8(&candidate_der).map_err(|_| refused())?;
            if certificate
                .public_key()
                .map_err(|_| refused())?
                .public_eq(&candidate)
            {
                pending.certificate_der = Some(certificate_der);
            } else {
                stored.certificate_der = certificate_der;
            }
        } else {
            stored.certificate_der = certificate_der;
        }
        let bytes = serialize_identity_document(&stored)?;
        replace(&self.data, &bytes, Some(&snapshot))
    }
}

impl infraternal_plugin_remote::identity_rotation::RotationPublisher for IdentityPublisher {
    fn load(&self) -> io::Result<infraternal_plugin_remote::identity_rotation::RotationStorage> {
        use infraternal_plugin_remote::identity_rotation::{PendingRotation, RotationStorage};
        let (stored, _) = load_snapshot(&self.data)?;
        let pending = stored
            .identity_rotation
            .map(|pending| -> io::Result<PendingRotation> {
                Ok(PendingRotation {
                    challenge: pending.challenge,
                    candidate_key_pkcs8: decode_candidate_key(&pending.candidate_key_der)?,
                    candidate_certificate_der: pending
                        .certificate_der
                        .map(|certificate| B64.decode(certificate).map_err(|_| refused()))
                        .transpose()?,
                })
            })
            .transpose()?;
        Ok(RotationStorage {
            pending,
            completed: stored.completed_identity_rotation,
        })
    }

    fn store_candidate(
        &self,
        challenge: &infraternal_plugin_remote::identity_rotation::Challenge,
        key_pkcs8: &[u8],
    ) -> io::Result<()> {
        if key_pkcs8.is_empty() || key_pkcs8.len() > 1024 {
            return Err(refused());
        }
        let key = PKey::private_key_from_pkcs8(key_pkcs8).map_err(|_| refused())?;
        if key.id() != openssl::pkey::Id::ED25519 {
            return Err(refused());
        }
        let (mut stored, snapshot) = load_snapshot(&self.data)?;
        let current = X509::from_der(&B64.decode(&stored.certificate_der).map_err(|_| refused())?)
            .map_err(|_| refused())?;
        if stored.identity_rotation.is_some()
            || current
                .digest(MessageDigest::sha256())
                .map_err(|_| refused())?
                .as_ref()
                != challenge.predecessor_fingerprint
        {
            return Err(refused());
        }
        stored.identity_rotation = Some(StoredRotation {
            challenge: challenge.clone(),
            candidate_key_der: encode_candidate_key(key_pkcs8),
            certificate_der: None,
        });
        let bytes = serialize_identity_document(&stored)?;
        replace(&self.data, &bytes, Some(&snapshot))
    }

    fn store_certificate(&self, operation_id: uuid::Uuid, der: &[u8]) -> io::Result<()> {
        if der.is_empty() || der.len() > 8192 {
            return Err(refused());
        }
        let (mut stored, snapshot) = load_snapshot(&self.data)?;
        let pending = stored.identity_rotation.as_mut().ok_or_else(refused)?;
        if pending.challenge.operation_id != operation_id {
            return Err(refused());
        }
        pending.certificate_der = Some(B64.encode(der));
        let bytes = serialize_identity_document(&stored)?;
        replace(&self.data, &bytes, Some(&snapshot))
    }

    fn promote(
        &self,
        completed: &infraternal_plugin_remote::identity_rotation::CompletedRotation,
    ) -> io::Result<()> {
        let (mut stored, snapshot) = load_snapshot(&self.data)?;
        let mut pending = stored.identity_rotation.take().ok_or_else(refused)?;
        if pending.challenge.operation_id != completed.operation_id
            || pending.challenge.sequence != completed.sequence
        {
            return Err(refused());
        }
        let certificate_der = pending.certificate_der.ok_or_else(refused)?;
        let certificate = X509::from_der(&B64.decode(&certificate_der).map_err(|_| refused())?)
            .map_err(|_| refused())?;
        if certificate
            .digest(MessageDigest::sha256())
            .map_err(|_| refused())?
            .as_ref()
            != completed.certificate_fingerprint
        {
            return Err(refused());
        }
        stored.key_der = std::mem::take(&mut *pending.candidate_key_der);
        stored.certificate_der = certificate_der;
        stored.completed_identity_rotation = Some(completed.clone());
        let bytes = serialize_identity_document(&stored)?;
        replace(&self.data, &bytes, Some(&snapshot))
    }
}

/// Atomically replace an existing private identity; never create one or follow a link.
///
/// With `expected`, identity.json must still be that file (same inode and
/// bytes) just before the rename; otherwise nothing is replaced. The window
/// left between this check and the rename is a few syscalls.
fn replace(data: &Path, bytes: &[u8], expected: Option<&Snapshot>) -> io::Result<()> {
    use std::{
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let directory = std::fs::symlink_metadata(data)?;
    let current = std::fs::symlink_metadata(data.join("identity.json"))?;
    let uid = nix::unistd::Uid::effective().as_raw();
    if !directory.is_dir()
        || directory.uid() != uid
        || directory.permissions().mode() & 0o077 != 0
        || !current.is_file()
        || current.uid() != uid
        || current.permissions().mode() & 0o077 != 0
        || bytes.len() > 8192
    {
        return Err(refused());
    }
    let pending = data.join(format!("identity-{}.pending", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if let Some(expected) = expected {
            let (_, now) = load_snapshot(data)?;
            if now.device != expected.device
                || now.inode != expected.inode
                || now.bytes.as_slice() != expected.bytes.as_slice()
            {
                return Err(refused());
            }
        }
        std::fs::rename(&pending, data.join("identity.json"))?;
        std::fs::File::open(data)?.sync_all()
    })();
    let _ = std::fs::remove_file(pending);
    result
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;

/// Host uninstall: the independent helper service, or the owner by hand (#235).
///
/// `--bootstrap-uninstall` alone is the transient service the infraternal
/// agent started: it consumes the private plan that agent left.
/// `--bootstrap-uninstall <host>` is the command the server hands the owner
/// when it could not reach the host. Both run the same cleanup, which
/// removes nothing unless this account's `.bootstrap-owner` names the host,
/// retires only this installation's own shells, and leaves kernel objects and
/// files it did not create.
#[cfg(target_os = "linux")]
pub(crate) fn uninstall_if_requested() -> Option<std::process::ExitCode> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments
        .get(1)
        .is_none_or(|argument| argument != "--bootstrap-uninstall")
    {
        return None;
    }
    let by_hand = arguments.len() == 3;
    let execute = || -> io::Result<Vec<String>> {
        let home = std::env::var_os("HOME").map_or_else(|| "/".into(), PathBuf::from);
        let uid = nix::unistd::Uid::effective().as_raw();
        let plan = match arguments.as_slice() {
            [_, _] => infraternal_plugin_remote::uninstall::take_plan(&home, uid)?,
            [_, _, host] => infraternal_plugin_remote::uninstall::installation(
                host.to_str().ok_or_else(refused)?,
                &home,
                uid,
            ),
            _ => return Err(refused()),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut report = Vec::new();
        infraternal_agent::block_on_io(
            &runtime,
            Box::pin(async {
                report = infraternal_plugin_remote::uninstall::cleanup(
                    &plan,
                    &home,
                    uid,
                    infraternal_agent::plugins::KERNEL,
                )
                .await?;
                Ok(())
            }),
        )?;
        Ok(report)
    };
    // The helper's output goes to its unit's journal, the owner's to the terminal.
    Some(match execute() {
        Ok(report) => {
            for line in report {
                println!("{line}");
            }
            if by_hand {
                println!("infraternal was removed from this machine.");
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            if by_hand {
                eprintln!(
                    "infraternal was not removed: {error}. It removes only the installation infraternal setup made for this host, as the account that installed it."
                );
            }
            std::process::ExitCode::FAILURE
        }
    })
}
