//! Supervises a locally enrolled dial-out identity over QUIC first and verified TCP fallback, preserving rootless shims through connection loss [64][133], #78.

use crate::{
    channel::Channel,
    daemon,
    remote_native::NativeChannel,
    remote_quic,
    remote_tls::{self, Identity},
    transport::Receive,
};
use infraternal_protocol::encode_frame_into;
use openssl::x509::X509;
use std::{future::Future, io, net::SocketAddr, path::PathBuf, pin::Pin, time::Duration};
use tokio::sync::Mutex;

/// Local enrolled host credentials; no private material leaves the host.
pub struct RemoteIdentity {
    /// Enrolled host identifier bound to the D168 leaf and app-level proof.
    pub host_id: uuid::Uuid,
    /// Locally generated host key and committed client certificate.
    pub identity: Identity,
    /// Pinned public issuers, including overlap generations.
    pub roots: Vec<X509>,
    /// Legacy direct transport address, absent for HTTPS WebSocket identities.
    pub endpoint: Option<SocketAddr>,
    /// Server SAN, verified on both transports.
    pub server_name: String,
    /// Public HTTPS origin used for enrollment and the resilient app-listener link.
    pub public_origin: Option<String>,
    /// Optional pinned HTTPS issuer/leaf used when the server does not use system roots.
    pub https_root: Option<X509>,
    /// Verify the HTTPS listener using ordinary operating-system roots.
    pub https_system_roots: bool,
    /// Bound uid, checked against the running rootless infraternal agent.
    pub execution_uid: u32,
}

fn trace_attempt<T>(phase: &'static str, result: io::Result<T>) -> io::Result<T> {
    if std::env::var_os("INFRATERNAL_REMOTE_LINK_TRACE").is_some()
        && let Err(error) = &result
    {
        eprintln!("remote agent attempt phase={phase} kind={:?}", error.kind());
    }
    result
}

/// Run until cancelled. Fallback retries sleep; proven alternative paths own a freshness guard.
/// # Errors
/// Refuses local uid mismatch or invalid credentials before contacting the server.
pub async fn run(identity: &RemoteIdentity, state: Option<PathBuf>) -> io::Result<()> {
    Box::pin(run_inner(
        identity,
        state,
        None,
        None,
        #[cfg(any(test, feature = "native-streams"))]
        None,
        #[cfg(any(test, feature = "native-streams"))]
        None,
    ))
    .await
}

/// Keep atomic publication and reconnect identity in sync throughout live renewal.
/// # Errors
/// Refuses unsafe local identity, expired credentials or failed transport configuration.
pub async fn run_with_publisher(
    identity: &RemoteIdentity,
    state: Option<PathBuf>,
    publisher: std::sync::Arc<dyn crate::remote_renewal::CertificatePublisher>,
) -> io::Result<()> {
    run_with_installation(identity, state, publisher, None).await
}

/// Bind node uninstall to checked local managed-service coordinates.
/// # Errors
/// Refuses the same identity and transport configuration failures.
pub async fn run_with_installation(
    identity: &RemoteIdentity,
    state: Option<PathBuf>,
    publisher: std::sync::Arc<dyn crate::remote_renewal::CertificatePublisher>,
    installation: Option<&crate::plugins::Installation>,
) -> io::Result<()> {
    run_with_publishers(identity, state, publisher, None, installation).await
}

/// Run with durable support for overlapping Ed25519 identity-key rotation.
/// # Errors
/// Refuses unsafe local identity, invalid rotation state or failed transport configuration.
pub async fn run_with_identity_rotation(
    identity: &RemoteIdentity,
    state: Option<PathBuf>,
    publisher: std::sync::Arc<dyn crate::remote_renewal::CertificatePublisher>,
    rotation: std::sync::Arc<dyn infraternal_plugin_remote::identity_rotation::RotationPublisher>,
    installation: Option<&infraternal_plugin_remote::uninstall::Context>,
) -> io::Result<()> {
    run_with_publishers(identity, state, publisher, Some(rotation), installation).await
}

type ClientFuture<'a> = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

/// Keep public callers' stack futures small; this owns the long-lived reconnect state machine.
fn run_with_publishers<'a>(
    identity: &'a RemoteIdentity,
    state: Option<PathBuf>,
    publisher: std::sync::Arc<dyn crate::remote_renewal::CertificatePublisher>,
    rotation: Option<
        std::sync::Arc<dyn infraternal_plugin_remote::identity_rotation::RotationPublisher>,
    >,
    installation: Option<&'a infraternal_plugin_remote::uninstall::Context>,
) -> ClientFuture<'a> {
    Box::pin(async move {
        let mut renewal =
            crate::remote_renewal::RenewalIdentity::new(&identity.identity, &identity.roots, publisher);
        if let Some(rotation) = rotation {
            renewal.enable_identity_rotation(rotation)?;
        }
        run_inner(
            identity,
            state,
            Some(&renewal),
            installation,
            #[cfg(any(test, feature = "native-streams"))]
            None,
            #[cfg(any(test, feature = "native-streams"))]
            None,
        )
        .await
    })
}

/// Run with trusted compiled node providers, retaining prepared identities across reconnect.
/// # Errors
/// Refuses enrolled UID mismatch and invalid registry or transport configuration.
#[cfg(any(test, feature = "native-streams"))]
pub async fn run_with_registry(
    identity: &RemoteIdentity,
    state: Option<PathBuf>,
    registry: crate::plugins::SharedRegistry,
) -> io::Result<()> {
    run_inner(
        identity,
        state,
        None,
        None,
        Some(crate::plugin_control::Registry::from_shared(registry)),
        None,
    )
    .await
}

/// Observe discarded connection failures using fixed stage names and error kinds
/// only. The observer receives no transport payload or credential material and
/// must return promptly; retries and transport selection remain unchanged.
/// # Errors
/// Refuses the same identity, registry and transport configuration as `run_with_registry`.
#[cfg(any(test, feature = "native-streams"))]
pub async fn run_with_registry_observed(
    identity: &RemoteIdentity,
    state: Option<PathBuf>,
    registry: crate::plugins::SharedRegistry,
    observer: impl Fn(&'static str, io::ErrorKind) + Send + Sync,
) -> io::Result<()> {
    run_inner(
        identity,
        state,
        None,
        None,
        Some(crate::plugin_control::Registry::from_shared(registry)),
        Some(&observer),
    )
    .await
}

#[cfg(any(test, feature = "native-streams"))]
type FailureObserver<'a> = dyn Fn(&'static str, io::ErrorKind) + Send + Sync + 'a;

// Inspection stays inside rare failure branches. Ordinary supervisors do not
// allocate a callback, format errors, or invoke diagnostics on control traffic.
#[cfg(any(test, feature = "native-streams"))]
fn observe_failure(observer: Option<&FailureObserver<'_>>, stage: &'static str, error: &io::Error) {
    if let Some(observer) = observer {
        observer(stage, error.kind());
    }
}

async fn ensure_service(
    service: &Mutex<Option<crate::plugin_control::Service>>,
    state: &std::path::Path,
    installation: Option<&crate::plugins::Installation>,
    #[cfg(target_os = "linux")] lifetime: &Mutex<Option<std::sync::Arc<std::fs::File>>>,
    #[cfg(any(test, feature = "native-streams"))] supplied: Option<crate::plugin_control::Registry>,
) -> io::Result<crate::plugin_control::Registry> {
    let mut local = service.lock().await;
    if local.as_ref().is_some_and(|local| local.registry.ended()) {
        local.take();
    }
    if local.is_none() {
        #[cfg(any(test, feature = "native-streams"))]
        let supplied_service = match supplied {
            Some(registry) => {
                Some(crate::plugin_control::Service::with_registry(state, registry).await?)
            }
            None => None,
        };
        #[cfg(not(any(test, feature = "native-streams")))]
        let supplied_service = None;
        *local = Some(if let Some(service) = supplied_service {
            service
        } else {
            #[cfg(target_os = "linux")]
            let service = trace_attempt(
                "plugin-service-start",
                crate::plugin_control::Service::start_retained(
                    state,
                    installation,
                    &mut *lifetime.lock().await,
                )
                .await,
            )?;
            #[cfg(not(target_os = "linux"))]
            let service = trace_attempt(
                "plugin-service-start",
                crate::plugin_control::Service::start(
                    state,
                    crate::plugins::ExecutionMode::Remote,
                    installation,
                )
                .await,
            )?;
            service
        });
    }
    local
        .as_ref()
        .map(|local| local.registry.clone())
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
}

async fn run_inner(
    identity: &RemoteIdentity,
    state: Option<PathBuf>,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    installation: Option<&crate::plugins::Installation>,
    #[cfg(any(test, feature = "native-streams"))] supplied: Option<crate::plugin_control::Registry>,
    #[cfg(any(test, feature = "native-streams"))] observer: Option<&FailureObserver<'_>>,
) -> io::Result<()> {
    if identity.execution_uid != nix::unistd::Uid::effective().as_raw() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    // A link cancellation cannot cancel synchronous plugin/kernel work. Keep
    // its sole owner and local listener across watchdog resets; only a closed
    // receiver proves the worker has ended and can safely be replaced.
    let service = Mutex::new(None::<crate::plugin_control::Service>);
    // Keep lifetime ownership even when a failed worker is being replaced or
    // credentials temporarily prevent another connection attempt.
    #[cfg(target_os = "linux")]
    let lifetime = Mutex::new(None::<std::sync::Arc<std::fs::File>>);
    supervisor::run(|connected| {
        let service = &service;
        #[cfg(target_os = "linux")]
        let lifetime = &lifetime;
        let state = state.clone();
        #[cfg(any(test, feature = "native-streams"))]
        let supplied = supplied.clone();
        async move {
            // Invalid enrollment creates no local state or plugin work. A clock or
            // credential failure still leaves the retry owner alive for recovery.
            if let Some(renewal) = renewal {
                let current = trace_attempt("renewal-current", renewal.current())?;
                trace_attempt(
                    "certificate-valid",
                    crate::remote_renewal::require_current(&current),
                )?;
            } else {
                trace_attempt(
                    "certificate-valid",
                    crate::remote_renewal::require_current(&identity.identity),
                )?;
            }
            #[cfg(target_os = "linux")]
            let state = trace_attempt("state-path", crate::sessions::state_path(state.clone()))?;
            #[cfg(not(target_os = "linux"))]
            let state = trace_attempt("state-path", crate::control::runtime_state(state))?;
            let plugins = ensure_service(
                service,
                &state,
                installation,
                #[cfg(target_os = "linux")]
                lifetime,
                #[cfg(any(test, feature = "native-streams"))]
                supplied,
            )
            .await?;
            #[cfg(any(test, feature = "native-streams"))]
            let _availability = Availability(plugins.clone());
            #[cfg(any(test, feature = "native-streams"))]
            if let Some(observer) = observer {
                return trace_attempt(
                    "server-path",
                    server_path::run_observed(
                        identity,
                        state,
                        renewal,
                        plugins,
                        connected,
                        Some(observer),
                    )
                    .await,
                );
            }
            trace_attempt(
                "server-path",
                server_path::run(identity, state, renewal, plugins, connected).await,
            )
        }
    })
    .await
}

// Keep the race in its own future. Its losing socket is dropped when this
// returns, rather than retained throughout the winning control dispatch.
async fn dial_preferred(
    endpoint: &quinn::Endpoint,
    identity: &RemoteIdentity,
    tls: &openssl::ssl::SslConnector,
) -> io::Result<Connected> {
    let address = identity
        .endpoint
        .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
    let quic = quic_connect(endpoint, identity);
    let fallback = async {
        // Start QUIC first, then race TCP after a short grace period. A
        // silent UDP path cannot add its full handshake timeout to TCP.
        tokio::time::sleep(Duration::from_millis(100)).await;
        remote_tls::dial(address, &identity.server_name, tls).await
    };
    tokio::pin!(quic, fallback);
    tokio::select! {
        biased;
        result = &mut quic => match result {
            Ok(connection) => Ok(Connected::Quic(connection)),
            Err(_) => fallback.await.map(Connected::Tcp),
        },
        result = &mut fallback => match result {
            Ok(connection) => Ok(Connected::Tcp(connection)),
            Err(_) => quic.await.map(Connected::Quic),
        },
    }
}

// Dropping the losing handshake releases its transport before dispatch begins.
enum Connected {
    Quic(quinn::Connection),
    Tcp(remote_tls::Connection),
}

// One concrete remote control adapter shares daemon and relay dispatch. TCP
// stays raw; QUIC retains its negotiated greeting and already-buffered decoder.
enum ControlChannel<'a> {
    Quic(&'a PrefixedControl),
    Tcp(&'a crate::remote_tls::TcpTls),
}
impl Channel for ControlChannel<'_> {
    fn native_stream_id(&self) -> Option<u32> {
        match self {
            Self::Quic(channel) => channel.native_stream_id(),
            Self::Tcp(channel) => channel.native_stream_id(),
        }
    }
    fn frame_timeout(&self) -> Option<Duration> {
        match self {
            Self::Quic(channel) => channel.frame_timeout(),
            Self::Tcp(channel) => channel.frame_timeout(),
        }
    }
    fn retire(&self) {
        match self {
            Self::Quic(channel) => channel.retire(),
            Self::Tcp(channel) => channel.retire(),
        }
    }
    async fn read(&self, target: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Quic(channel) => channel.read(target).await,
            Self::Tcp(channel) => channel.read(target).await,
        }
    }
    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Quic(channel) => channel.write(bytes).await,
            Self::Tcp(channel) => channel.write(bytes).await,
        }
    }
}

// Replay the negotiated Hello into common dispatch while retaining the same
// decoder: its first read may also contain the following control frame.
struct PrefixedControl {
    channel: NativeChannel,
    prefix: Mutex<Vec<u8>>,
    sent_greeting: Mutex<Option<Vec<u8>>>,
    receive: Mutex<Receive>,
}
impl Channel for PrefixedControl {
    fn native_stream_id(&self) -> Option<u32> {
        self.channel.native_stream_id()
    }
    fn frame_timeout(&self) -> Option<Duration> {
        self.channel.frame_timeout()
    }
    fn retire(&self) {
        self.channel.retire();
    }
    async fn read(&self, target: &mut [u8]) -> io::Result<usize> {
        let mut prefix = self.prefix.lock().await;
        if prefix.is_empty() {
            let mut receive = self.receive.lock().await;
            let frame = receive.next(&self.channel).await?;
            encode_frame_into(&frame.frame, &mut prefix).map_err(io::Error::other)?;
        }
        let count = target.len().min(prefix.len());
        target[..count].copy_from_slice(&prefix[..count]);
        prefix.drain(..count);
        Ok(count)
    }

    async fn write(&self, bytes: &[u8]) -> io::Result<()> {
        if let Some(greeting) = self.sent_greeting.lock().await.take() {
            if greeting != bytes {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return Ok(());
        }
        self.channel.write(bytes).await
    }
}

async fn quic_connect(
    endpoint: &quinn::Endpoint,
    identity: &RemoteIdentity,
) -> io::Result<quinn::Connection> {
    let address = identity
        .endpoint
        .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
    tokio::time::timeout(
        Duration::from_secs(5),
        endpoint
            .connect(address, &identity.server_name)
            .map_err(io::Error::other)?,
    )
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
    .map_err(io::Error::other)
}

fn client_greeting(renewal: bool, identity_rotation: bool) -> infraternal_protocol::Frame<'static> {
    infraternal_protocol::Frame::Hello {
        version: 1,
        caps: daemon::hello_capabilities(true, renewal, identity_rotation),
        client_info: "infraternal agent",
    }
}

/// A proved native stream retains the decoder that consumed its nonce reply.
struct ProvedControl {
    control: NativeChannel,
    receive: Receive,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn quic_session_on(
    connection: quinn::Connection,
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    plugins: crate::plugin_control::Registry,
    proof: Option<ProvedControl>,
    publish: impl FnOnce(u64),
) -> io::Result<()> {
    #[cfg(any(test, feature = "native-streams"))]
    let providers = native_routes(&plugins).await?;
    let result = async {
        let ProvedControl {
            control,
            receive: mut rx,
        } = if let Some(proof) = proof {
            proof
        } else {
            let (send, receive) = connection.open_bi().await.map_err(io::Error::other)?;
            ProvedControl {
                control: NativeChannel::control(send, receive)?,
                receive: Receive::default(),
            }
        };
        // Opening a QUIC stream emits no packet until there is data. Send the
        // greeting once, then let common dispatch consume the server's greeting.
        let mut tx = crate::transport::Transmit::default();
        let mut greeting = client_greeting(
            renewal.is_some(),
            renewal.is_some_and(crate::remote_renewal::RenewalIdentity::supports_identity_rotation),
        );
        #[cfg(not(any(test, feature = "native-streams")))]
        let native_caps = 0;
        #[cfg(any(test, feature = "native-streams"))]
        let native_caps = providers.capabilities();
        if let infraternal_protocol::Frame::Hello { caps, .. } = &mut greeting {
            *caps |= native_caps;
        }
        tx.send(&control, 0, &greeting).await?;
        let mut sent_greeting = Vec::new();
        encode_frame_into(&greeting, &mut sent_greeting).map_err(io::Error::other)?;
        let hello = tokio::time::timeout(Duration::from_secs(5), rx.next(&control))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let mut prefix = Vec::new();
        encode_frame_into(&hello.frame, &mut prefix).map_err(io::Error::other)?;
        let hello = infraternal_protocol::decode_frame(&prefix).map_err(io::Error::other)?;
        let binding = remote_quic::negotiate_binding(&connection, &hello.frame)?;
        let infraternal_protocol::Frame::Hello { caps, .. } = hello.frame else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        publish(caps);
        let control = PrefixedControl {
            channel: control,
            prefix: Mutex::new(prefix),
            sent_greeting: Mutex::new(Some(sent_greeting)),
            receive: Mutex::new(rx),
        };
        let control = ControlChannel::Quic(&control);
        let dispatch = daemon::run_authenticated_with_plugins(
            &control,
            state.clone(),
            identity.execution_uid,
            renewal,
            plugins,
        );
        let native = primed_native::serve(
            &binding,
            state,
            caps & infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS != 0,
            #[cfg(any(test, feature = "native-streams"))]
            providers.clone(),
            #[cfg(any(test, feature = "native-streams"))]
            caps,
            #[cfg(any(test, feature = "native-streams"))]
            infraternal_plugin_remote::wire_datagrams::NativeDatagrams::new(connection.clone()),
        );
        tokio::select! {
            result = dispatch => result,
            result = native => result,
            _ = connection.closed() => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
    .await;
    connection.close(0u32.into(), b"");
    result
}

#[cfg(test)]
#[path = "remote_client_tests.rs"]
mod tests;

#[path = "remote_dial_runtime.rs"]
mod dial_runtime;

#[path = "remote_server_path.rs"]
mod server_path;

#[path = "remote_supervisor.rs"]
mod supervisor;

#[path = "remote_primed_native.rs"]
mod primed_native;

#[cfg(any(test, feature = "native-streams"))]
async fn native_routes(
    registry: &crate::plugin_control::Registry,
) -> io::Result<std::sync::Arc<crate::native_dispatch::Routes>> {
    let entries = registry
        .wire_providers()
        .await
        .map_err(|_| io::Error::other("Native providers are invalid."))?;
    Ok(std::sync::Arc::new(crate::native_dispatch::Routes::new(
        entries,
    )?))
}

#[cfg(any(test, feature = "native-streams"))]
struct Availability(crate::plugin_control::Registry);
#[cfg(any(test, feature = "native-streams"))]
impl Drop for Availability {
    fn drop(&mut self) {
        self.0.capabilities(0);
    }
}
