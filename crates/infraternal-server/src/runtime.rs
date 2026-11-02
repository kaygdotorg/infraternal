//! Starts the trusted HTTP control plane with private SQLite storage, pinned passkey origin, and optional TLS [8][19][24][26].

use crate::auth::{self, Auth};
use crate::{
    embedded::EmbeddedAgent,
    websocket::{self, WebSocketState},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::get,
    serve::ListenerExt,
};
use axum_server::tls_openssl::OpenSSLConfig;
use infraternal_plugin_api::PluginDescriptor;
use serde_json::json;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    sync::{Mutex, Semaphore},
};
use tracing_subscriber::EnvFilter;

#[cfg(feature = "remote")]
use crate::{
    remote_http::EnrollmentService,
    remote_runtime::{RemoteListeners, RemoteService},
};
#[cfg(not(feature = "remote"))]
type EnrollmentService = ();
#[cfg(not(feature = "remote"))]
type RemoteService = ();
#[cfg(not(feature = "remote"))]
type RemoteListeners = ();
#[cfg(feature = "ssh")]
type BootstrapFactory = crate::bootstrap_runtime::BootstrapFactory;
#[cfg(not(feature = "ssh"))]
type BootstrapFactory = ();
#[cfg(feature = "ssh")]
type PayloadWarmup = infraternal_plugin_ssh::bootstrap::Bootstrap;
#[cfg(not(feature = "ssh"))]
type PayloadWarmup = ();
#[cfg(feature = "ssh")]
type KeyInitialization = crate::bootstrap_runtime::KeyInitialization;
#[cfg(not(feature = "ssh"))]
type KeyInitialization = ();

/// A CIDR network whose peers are permitted to supply `X-Forwarded-For` [keywrap.md].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyNetwork {
    address: IpAddr,
    prefix: u8,
}

impl ProxyNetwork {
    /// Return whether an address falls within this configured proxy network.
    #[must_use]
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(candidate) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(candidate) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for ProxyNetwork {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let max_prefix = if self.address.is_ipv4() { 32 } else { 128 };
        if self.prefix == max_prefix {
            write!(formatter, "{}", self.address)
        } else {
            write!(formatter, "{}/{}", self.address, self.prefix)
        }
    }
}

impl FromStr for ProxyNetwork {
    type Err = ProxyNetworkError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (
                address.parse::<IpAddr>().map_err(|_| ProxyNetworkError)?,
                Some(prefix.parse::<u8>().map_err(|_| ProxyNetworkError)?),
            ),
            None => (
                value.parse::<IpAddr>().map_err(|_| ProxyNetworkError)?,
                None,
            ),
        };
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max_prefix);
        if prefix > max_prefix {
            return Err(ProxyNetworkError);
        }
        Ok(Self { address, prefix })
    }
}

/// Parse failure for a proxy network, without retaining untrusted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProxyNetworkError;

impl std::fmt::Display for ProxyNetworkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("proxy network must be an IP address or CIDR")
    }
}

impl std::error::Error for ProxyNetworkError {}

/// Certificate and private key files for a standalone HTTPS listener.
#[derive(Clone, Debug)]
pub struct TlsFiles {
    /// PEM certificate chain.
    pub certificate: PathBuf,
    /// PEM private key.
    pub private_key: PathBuf,
}

/// Inputs for the server process. The public origin is always explicit to `WebAuthn`.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Address on which the HTTP service accepts connections.
    pub listen: SocketAddr,
    /// Private directory containing the SQLite database.
    pub data_dir: PathBuf,
    /// Public HTTPS origin used for `WebAuthn` and CSRF checks.
    pub public_origin: String,
    /// Optional static web build directory.
    pub web_root: Option<PathBuf>,
    /// Optional standalone TLS files. Without them, `behind_proxy` must be enabled.
    pub tls: Option<TlsFiles>,
    /// Trust forwarding metadata only from configured proxy peers.
    pub behind_proxy: bool,
    /// Explicit peer networks allowed to provide forwarded client addresses.
    pub trusted_proxies: Vec<ProxyNetwork>,
}

/// Startup errors intentionally avoid printing filesystem paths, keys, or request data.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The command-line options cannot provide a safe serving configuration.
    #[error("invalid server configuration")]
    InvalidConfiguration,
    /// The server could not prepare private storage.
    #[error("server storage initialization failed")]
    Storage(#[source] sqlx::Error),
    /// The server database schema could not be migrated.
    #[error("server database migration failed")]
    Migration(#[source] sqlx::migrate::MigrateError),
    /// Passkey/authentication initialization failed.
    #[error("auth initialization failed")]
    Auth(#[source] auth::Error),
    /// The configured certificate or private key could not be loaded.
    #[error("TLS configuration failed")]
    TlsConfiguration,
    /// The configured web root is missing or is not a directory.
    #[error("web root is unavailable")]
    WebRoot,
    /// The listener could not bind or serve.
    #[error("server listener failed")]
    Listener(#[source] std::io::Error),
    /// The private first-run setup-token control socket could not be created.
    #[error("setup-token control socket failed")]
    SetupTokenSocket(#[source] std::io::Error),
    /// Root startup requires the private-key heap to be locked and dump-excluded.
    #[cfg(feature = "remote")]
    #[error(
        "OpenSSL secure heap could not be locked and excluded from dumps; check the server memlock limit"
    )]
    PrivateKeyMemory,
    /// System time predates the Unix epoch or does not fit the auth API.
    #[error("system clock is invalid")]
    Clock,
}

/// Initialize SQLite, mount auth and health routes, and serve HTTP or HTTPS until shutdown.
///
/// # Errors
///
/// Returns a sanitized startup, storage, migration, TLS, or listener error.
pub async fn serve(config: ServerConfig) -> Result<(), ServerError> {
    serve_inner(config, None, None, None, None, None).await
}

/// Start with the caller's compiled infraternal agent action catalog, preserving the production adapter.
/// # Errors
/// Returns sanitized configuration, storage, authentication, TLS and listener failures.
pub async fn serve_with_plugin_descriptors(
    config: ServerConfig,
    catalog: &'static [&'static PluginDescriptor],
) -> Result<(), ServerError> {
    serve_inner(config, None, None, None, None, Some(catalog)).await
}

/// Mount host enrollment using the trusted runtime's D168 signing source.
/// # Errors
/// Returns sanitized startup, storage, migration, TLS or listener failures.
#[cfg(feature = "remote")]
pub async fn serve_with_enrollment(
    config: ServerConfig,
    enrollment: Option<EnrollmentService>,
) -> Result<(), ServerError> {
    serve_inner(config, enrollment, None, None, None, None).await
}

/// Serve enrollment, host transports and browser routing using trusted D168 sources.
/// # Errors
/// Returns sanitized configuration, storage, TLS or listener failures.
#[cfg(feature = "remote")]
pub async fn serve_with_remote(
    config: ServerConfig,
    remote: crate::remote_runtime::RemoteService,
) -> Result<(), ServerError> {
    serve_inner(
        config,
        Some(remote.enrollment.clone()),
        Some(remote),
        None,
        None,
        None,
    )
    .await
}

/// Preserve one startup path for independent remote and SSH components.
#[cfg(feature = "ssh")]
pub(crate) async fn serve_with_bootstrap(
    config: ServerConfig,
    factory: Option<BootstrapFactory>,
) -> Result<(), ServerError> {
    serve_with_key_setup(config, factory, None).await
}

#[cfg(feature = "ssh")]
pub(crate) async fn serve_with_key_setup(
    config: ServerConfig,
    factory: Option<BootstrapFactory>,
    key_setup: Option<KeyInitialization>,
) -> Result<(), ServerError> {
    serve_inner(config, None, None, factory, key_setup, None).await
}

async fn serve_inner(
    config: ServerConfig,
    enrollment: Option<EnrollmentService>,
    remote: Option<RemoteService>,
    factory: Option<BootstrapFactory>,
    key_setup: Option<KeyInitialization>,
    catalog: Option<&'static [&'static PluginDescriptor]>,
) -> Result<(), ServerError> {
    configure_logging(false);
    #[cfg(feature = "remote")]
    crate::ca_memory::initialize_private_key_memory()?;
    let (app, setup_token, _listeners, warmup, auth) = build_router_core(
        config.clone(),
        None,
        enrollment,
        remote,
        factory,
        key_setup,
        catalog,
    )
    .await?;
    if let Some(token) = setup_token {
        start_setup_token_socket(&config.data_dir, token)?;
    }
    tracing::info!(
        listen = %config.listen,
        public_origin = %config.public_origin,
        behind_proxy = config.behind_proxy,
        "infraternal server started"
    );

    // Flush measured recovery progress on either normal shutdown signal or a
    // listener exit. Never infer elapsed credit from wall time or downtime.
    let server = async {
        if let Some(tls) = config.tls {
            let tls_config = OpenSSLConfig::from_pem_file(tls.certificate, tls.private_key)
                .map_err(|_| ServerError::TlsConfiguration)?;
            let listener =
                std::net::TcpListener::bind(config.listen).map_err(ServerError::Listener)?;
            listener
                .set_nonblocking(true)
                .map_err(ServerError::Listener)?;
            warm_payloads(warmup);
            axum_server::from_tcp(listener)
                .map_err(ServerError::Listener)?
                .acceptor(crate::server_tls::acceptor(tls_config))
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .map_err(ServerError::Listener)
        } else {
            let listener = TcpListener::bind(config.listen)
                .await
                .map_err(ServerError::Listener)?
                .tap_io(|socket| {
                    // Match the TLS acceptor: Ack and PTY Output are separate small
                    // writes. Nagle otherwise couples echo to a delayed TCP Ack,
                    // adding tens of milliseconds on the proxy leg [5][41].
                    if socket.set_nodelay(true).is_err() {
                        tracing::warn!("could not set TCP_NODELAY on accepted server socket");
                    }
                });
            warm_payloads(warmup);
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(ServerError::Listener)
        }
    };
    let result = tokio::select! {
        result = server => result,
        signal = shutdown_signal() => signal.map_err(ServerError::Listener),
    };
    auth.checkpoint_recovery_clock()
        .await
        .map_err(ServerError::Auth)?;
    result
}

// Both service-manager termination and interactive shutdown flush before exit.
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

// Binding the public listener precedes optional codec work. Tests composing a
// router alone deliberately do not launch background payload preparation.
fn warm_payloads(warmup: Option<PayloadWarmup>) {
    #[cfg(feature = "ssh")]
    if let Some(bootstrap) = warmup {
        bootstrap.warm_payloads();
    }
    #[cfg(not(feature = "ssh"))]
    let _ = warmup;
}

#[cfg(test)]
pub(crate) async fn router_with_agent(
    config: ServerConfig,
    agent: EmbeddedAgent,
) -> Result<(Router, String), ServerError> {
    let (router, setup_token) = build_router(config, Some(agent)).await?;
    setup_token
        .map(|token| (router, token))
        .ok_or(ServerError::InvalidConfiguration)
}

#[cfg(test)]
async fn build_router(
    config: ServerConfig,
    supplied_agent: Option<EmbeddedAgent>,
) -> Result<(Router, Option<String>), ServerError> {
    build_router_with_enrollment(config, supplied_agent, None).await
}

#[cfg(test)]
async fn build_router_with_enrollment(
    config: ServerConfig,
    supplied_agent: Option<EmbeddedAgent>,
    enrollment: Option<EnrollmentService>,
) -> Result<(Router, Option<String>), ServerError> {
    let (app, setup, _, _, _) =
        build_router_core(config, supplied_agent, enrollment, None, None, None, None).await?;
    Ok((app, setup))
}

/// Assemble configured CA authority before any listener starts; unsafe copy
/// storage refuses startup, while an absent configuration grants no authority.
#[cfg(feature = "remote")]
fn ca_router(
    remote: Option<&RemoteService>,
    auth: &Auth,
    pool: &SqlitePool,
    hosts: crate::remote_runtime::RemoteHosts,
    store: crate::enrollment::EnrollmentStore,
) -> Result<Router, ServerError> {
    remote
        .and_then(|service| service.ca_administration.as_ref())
        .map(|configuration| {
            configuration
                .with_runtime(auth.clone(), pool.clone(), hosts, store)
                .map(|authority| crate::ca_http::router(auth.clone(), authority))
                .map_err(|_| ServerError::TlsConfiguration)
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

/// Build the optional plugin adapter and retain listener ownership for the serving lifetime.
#[cfg(feature = "remote")]
async fn remote_router(
    auth: Auth,
    pool: SqlitePool,
    mut enrollment: Option<EnrollmentService>,
    remote: Option<RemoteService>,
    trust: std::path::PathBuf,
) -> Result<
    (
        Router,
        Router,
        crate::remote_runtime::RemoteHosts,
        Option<RemoteListeners>,
        Option<crate::remote_http::InvitationIssuer>,
        crate::enrollment::EnrollmentStore,
    ),
    ServerError,
> {
    let hosts = crate::remote_runtime::RemoteHosts::from_source(
        enrollment.as_ref().map(|service| service.source.clone()),
    );
    let mut enrollment_store = crate::enrollment::EnrollmentStore::new(pool.clone());
    enrollment_store.2 = hosts.5.clone();
    // No provisioning batch survives a process restart. Consume its durable
    // retirement intent before any listener can admit the abandoned identity.
    enrollment_store
        .retire_unfinished_bootstraps()
        .await
        .map_err(ServerError::Storage)?;
    let ca_api = ca_router(
        remote.as_ref(),
        &auth,
        &pool,
        hosts.clone(),
        enrollment_store.clone(),
    )?;
    let listeners = if let Some(remote) = remote.filter(|remote| remote.identity.is_some()) {
        Some(
            crate::remote_runtime::RemoteListeners::start(
                remote.enrollment.endpoint.endpoint,
                &remote.identity.ok_or(ServerError::TlsConfiguration)?,
                &remote.roots,
                enrollment_store.clone(),
                hosts.clone(),
            )
            .await
            .map_err(ServerError::Listener)?,
        )
    } else {
        None
    };
    if let (Some(service), Some(listeners)) = (&mut enrollment, &listeners) {
        service.endpoint.endpoint = listeners.local_addr().map_err(ServerError::Listener)?;
    }
    let issuer = enrollment.clone().map(|service| {
        crate::remote_http::InvitationIssuer::new(
            auth.clone(),
            pool.clone(),
            enrollment_store.clone(),
            service,
        )
    });
    let remote_api = enrollment.map(|service| {
        crate::remote_http::router_with_store(
            auth.clone(),
            pool.clone(),
            enrollment_store.clone(),
            service.source,
            service.endpoint,
        )
        .merge(crate::remote_agent_http::router(
            hosts.clone(),
            enrollment_store.clone(),
        ))
    });
    let removal = crate::remote_removal::Removal::new(
        auth.clone(),
        pool.clone(),
        enrollment_store.clone(),
        hosts.clone(),
        trust,
    );
    Ok((
        ca_api,
        remote_api
            .unwrap_or_else(crate::remote_http::unavailable_router)
            .merge(crate::remote_removal_http::router(auth, removal)),
        hosts,
        listeners,
        issuer,
        enrollment_store,
    ))
}

#[cfg(all(test, feature = "ssh"))]
async fn build_router_with_key_setup(
    config: ServerConfig,
    supplied_agent: Option<EmbeddedAgent>,
    factory: Option<BootstrapFactory>,
    key_setup: Option<KeyInitialization>,
) -> Result<(Router, Option<String>), ServerError> {
    let (app, setup, _, _, _) =
        build_router_core(config, supplied_agent, None, None, factory, key_setup, None).await?;
    Ok((app, setup))
}

// Keep startup ordering visible: persisted switches load before node workers
// attach, and admitted transports exist before their dependent server features.
#[allow(clippy::too_many_lines)]
async fn build_router_core(
    config: ServerConfig,
    supplied_agent: Option<EmbeddedAgent>,
    enrollment: Option<EnrollmentService>,
    remote: Option<RemoteService>,
    factory: Option<BootstrapFactory>,
    key_setup: Option<KeyInitialization>,
    catalog: Option<&'static [&'static PluginDescriptor]>,
) -> Result<
    (
        Router,
        Option<String>,
        Option<RemoteListeners>,
        Option<PayloadWarmup>,
        Auth,
    ),
    ServerError,
> {
    #[cfg(not(feature = "remote"))]
    let _ = (enrollment, remote);
    #[cfg(not(feature = "ssh"))]
    let _ = (factory, key_setup);
    validate_config(&config)?;
    if config.web_root.as_ref().is_some_and(|root| !root.is_dir()) {
        return Err(ServerError::WebRoot);
    }

    let pool = open_database(&config.data_dir).await?;
    let origin =
        url::Url::parse(&config.public_origin).map_err(|_| ServerError::InvalidConfiguration)?;
    let rp_id = origin.host_str().ok_or(ServerError::InvalidConfiguration)?;
    let system_service =
        std::env::var_os("INFRATERNAL_SERVER_SERVICE_SCOPE").is_some_and(|scope| scope == "system");
    let auth = Auth::new(pool.clone(), rp_id, &config.public_origin)
        .await
        .map_err(ServerError::Auth)?
        .with_system_service(system_service);
    #[cfg(not(feature = "remote"))]
    let ca_api = Router::new();
    let now = unix_seconds()?;
    websocket::recover_connections(&pool, now)
        .await
        .map_err(ServerError::Storage)?;
    let mut setup_token = None;
    auth.bootstrap(now, |banner| {
        setup_token = banner.lines().nth(1).map(str::to_owned);
    })
    .await
    .map_err(ServerError::Auth)?;

    if setup_token.is_some() {
        let mut setup_consumed = auth.subscribe_setup_consumed();
        let data_dir = config.data_dir.clone();
        tokio::spawn(async move {
            if setup_consumed.changed().await.is_ok() {
                remove_setup_token_socket_or_warn(&data_dir, "owner enrollment");
            }
        });
    } else {
        remove_setup_token_socket_or_warn(&config.data_dir, "owner already exists at startup");
    }

    // An injected actor's caller owns node-worker startup. Production starts
    // the process and binds admitted node workers after persisted switches load.
    let owns_node_workers = supplied_agent.is_none();
    #[cfg(feature = "remote")]
    let observed_server_ip = remote
        .as_ref()
        .map_or(std::net::Ipv4Addr::UNSPECIFIED.into(), |remote| {
            remote.enrollment.endpoint.endpoint.ip()
        });
    #[cfg(not(feature = "remote"))]
    let observed_server_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    let agent = if let Some(agent) = supplied_agent {
        agent
    } else {
        // Resolve the exact running inode in the spawn child, including sealed
        // replacement images whose display name is not an executable pathname.
        #[cfg(target_os = "linux")]
        let executable = std::path::PathBuf::from("/proc/self/exe");
        #[cfg(not(target_os = "linux"))]
        let executable = std::env::current_exe().map_err(|_| ServerError::InvalidConfiguration)?;
        EmbeddedAgent::spawn(executable)
    };
    #[cfg(feature = "remote")]
    let (ca_api, remote_api, hosts, listeners, issuer, enrollment_store) = remote_router(
        auth.clone(),
        pool.clone(),
        enrollment,
        remote,
        config.data_dir.join("ssh-trust"),
    )
    .await?;
    #[cfg(all(feature = "ssh", feature = "remote"))]
    let integration = issuer.map(|issuer| (issuer, hosts.clone()));
    #[cfg(all(feature = "ssh", not(feature = "remote")))]
    let integration = None;
    #[cfg(all(feature = "remote", not(feature = "ssh")))]
    let _ = issuer;
    // Compose SSH only after the shared CA ledger and admitted transport exist.
    #[cfg(feature = "ssh")]
    let (bootstrap, ssh_key) = crate::bootstrap_runtime::initialize(
        &config.data_dir,
        &auth,
        &pool,
        factory,
        key_setup,
        integration,
    )
    .await?;
    let local_node = agent.clone();
    #[cfg(feature = "remote")]
    let ws_state = WebSocketState::new_with_hosts_and_public_origin(
        auth.clone(),
        pool.clone(),
        agent,
        hosts.clone(),
        &config.public_origin,
    )
    .await;
    #[cfg(not(feature = "remote"))]
    let ws_state = WebSocketState::new_with_public_origin(
        auth.clone(),
        pool.clone(),
        agent,
        &config.public_origin,
    )
    .await;
    let ws_state = ws_state
        .map_err(|_| ServerError::InvalidConfiguration)?
        .with_plugin_descriptors(catalog.unwrap_or_else(infraternal_agent::plugins::descriptors));
    #[cfg(feature = "remote")]
    let ws_state = ws_state.with_remote_hosts(hosts.clone());
    #[cfg(feature = "remote")]
    enrollment_store.bind_plugins(&ws_state.plugins);
    #[cfg(feature = "ssh")]
    bootstrap.session_notifications(ws_state.session_notifications());
    #[cfg(not(feature = "remote"))]
    let listeners = None;
    if owns_node_workers {
        ws_state
            .plugins
            .attach_node(std::sync::Arc::new(crate::node_bridge::NodeBridge {
                id: "server".to_owned(),
                ip: observed_server_ip,
                server: true,
                server_paths: true,
                actor: local_node,
                #[cfg(feature = "remote")]
                authority: None,
                #[cfg(feature = "remote")]
                listeners: Some(hosts.clone()),
                #[cfg(feature = "remote")]
                peer_routes: None,
            }))
            .await
            .map_err(|_| ServerError::InvalidConfiguration)?;
        #[cfg(feature = "remote")]
        hosts
            .bind_plugins(&ws_state.plugins)
            .await
            .map_err(ServerError::Listener)?;
    }
    let app = Router::new()
        .route("/healthz", get(health))
        .with_state(pool)
        .merge(auth::router(auth.clone()))
        .merge(websocket::router(ws_state))
        .merge(ca_api);
    #[cfg(feature = "remote")]
    let app = app.merge(remote_api);
    #[cfg(feature = "ssh")]
    let warmup = Some(bootstrap.clone());
    #[cfg(not(feature = "ssh"))]
    let warmup = None;
    #[cfg(feature = "ssh")]
    let app = app.merge(crate::bootstrap_api::router_with_ssh_key(
        auth.clone(),
        bootstrap,
        ssh_key,
    ));
    let app = if let Some(web_root) = config.web_root {
        app.fallback_service(crate::web_assets::router(web_root))
    } else {
        app
    };
    let admission = SourceAdmission {
        behind_proxy: config.behind_proxy,
        trusted_proxies: config.trusted_proxies,
        buckets: Arc::default(),
    };
    Ok((
        app.layer(from_fn_with_state(admission, source_admission)),
        setup_token,
        listeners,
        warmup,
        auth,
    ))
}

// Keep the one-time capability in memory. Only a same-user CLI request over this
// private socket may retrieve it; systemd output and application logs never contain it.
fn start_setup_token_socket(data_dir: &Path, token: String) -> Result<(), ServerError> {
    unlink_setup_token_socket(data_dir).map_err(|error| {
        tracing::warn!("could not safely replace setup-token socket");
        ServerError::SetupTokenSocket(error)
    })?;
    let path = data_dir.join("setup-token.sock");
    let listener = UnixListener::bind(&path).map_err(ServerError::SetupTokenSocket)?;
    if let Err(error) = set_private_file(&path) {
        remove_setup_token_socket_or_warn(data_dir, "socket permission setup");
        return Err(ServerError::SetupTokenSocket(error));
    }
    let clients = Arc::new(Semaphore::new(4));
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let Ok(permit) = clients.clone().try_acquire_owned() else {
                continue;
            };
            let token = token.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let mut request = [0; 4];
                let valid =
                    tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut request))
                        .await
                        .is_ok_and(|result| result.is_ok())
                        && request == *b"GET\n";
                if valid {
                    let mut response = token.into_bytes();
                    response.push(b'\n');
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), socket.write_all(&response))
                            .await;
                }
            });
        }
    });
    Ok(())
}

/// Unlink only the fixed setup-token socket name when lstat identifies a socket.
fn unlink_setup_token_socket(data_dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;

    let path = data_dir.join("setup-token.sock");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "setup-token path is not a socket",
        ));
    }
    // remove_file unlinks the pathname and never follows a replacement symlink.
    std::fs::remove_file(path)
}

/// Report cleanup failures without exposing filesystem errors or setup credentials.
fn remove_setup_token_socket_or_warn(data_dir: &Path, operation: &'static str) {
    if unlink_setup_token_socket(data_dir).is_err() {
        tracing::warn!(
            operation = operation,
            "could not safely remove setup-token socket"
        );
    }
}

async fn open_database(data_dir: &std::path::Path) -> Result<SqlitePool, ServerError> {
    std::fs::create_dir_all(data_dir).map_err(|_| ServerError::InvalidConfiguration)?;
    set_private_directory(data_dir).map_err(|_| ServerError::InvalidConfiguration)?;
    let database = data_dir.join("infraternal.sqlite");
    let options = SqliteConnectOptions::new()
        .filename(database)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        // SQLite's acquire-time ping only queues a worker acknowledgement. An
        // idle connection was already checked on release, and its actual query
        // remains authoritative. Avoid the extra cancellable worker roundtrip:
        // a deadline during that ping discards a healthy idle connection.
        .test_before_acquire(false)
        // Local SQLite has no remote connection lifetime. Keep the bounded
        // eight-connection pool until shutdown instead of waking a reaper
        // every 600s while idle; request failures still surface normally [41].
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(options)
        .await
        .map_err(ServerError::Storage)?;
    set_private_file(&data_dir.join("infraternal.sqlite"))
        .map_err(|_| ServerError::InvalidConfiguration)?;
    Ok(pool)
}

pub(crate) fn validate_config(config: &ServerConfig) -> Result<(), ServerError> {
    if crate::compiled_plugins()
        .iter()
        .any(|descriptor| descriptor.validate().is_err())
    {
        return Err(ServerError::InvalidConfiguration);
    }
    if config.behind_proxy == config.trusted_proxies.is_empty() {
        return Err(ServerError::InvalidConfiguration);
    }
    if config.tls.is_none() && !config.behind_proxy {
        return Err(ServerError::InvalidConfiguration);
    }
    let origin =
        url::Url::parse(&config.public_origin).map_err(|_| ServerError::InvalidConfiguration)?;
    if origin.scheme() != "https"
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.host_str().is_none()
    {
        return Err(ServerError::InvalidConfiguration);
    }
    if let Some(web_root) = &config.web_root
        && !web_root.is_dir()
    {
        return Err(ServerError::WebRoot);
    }
    Ok(())
}

pub(crate) fn unix_seconds() -> Result<i64, ServerError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ServerError::Clock)?
            .as_secs(),
    )
    .map_err(|_| ServerError::Clock)
}

/// Select human diagnostics by default or JSON lines for machine callers.
/// Repeated initialization leaves the process-wide subscriber selected by its caller.
pub fn configure_logging(json: bool) {
    use std::io::IsTerminal;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let formatter = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter);
    if json {
        let _ = formatter.json().with_ansi(false).try_init();
    } else {
        let color = logging_color(
            std::io::stderr().is_terminal(),
            std::env::var_os("NO_COLOR"),
        );
        let _ = formatter.with_ansi(color).try_init();
    }
}

/// Only a non-empty `NO_COLOR` value disables ANSI in terminal logs.
fn logging_color(terminal: bool, no_color: Option<std::ffi::OsString>) -> bool {
    terminal && no_color.is_none_or(|value| value.is_empty())
}

async fn health(State(pool): State<SqlitePool>) -> Response {
    match sqlx::query("SELECT 1").execute(&pool).await {
        Ok(_) => Json(json!({"status":"ok"})).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"unavailable"})),
        )
            .into_response(),
    }
}

/// Canonical client address from the listener and explicitly trusted proxy policy.
/// Plugins may bound work by it; untrusted forwarding headers never set this value.
#[derive(Clone, Copy)]
pub(crate) struct ClientAddress(
    #[cfg_attr(not(feature = "remote"), allow(dead_code))] pub(crate) IpAddr,
);

/// Per-source auth admission trusts forwarding data only from configured peers.
#[derive(Clone)]
struct SourceAdmission {
    behind_proxy: bool,
    trusted_proxies: Vec<ProxyNetwork>,
    buckets: Arc<Mutex<HashMap<(IpAddr, bool), SourceBucket>>>,
}

pub(crate) struct SourceBucket {
    window: i64,
    requests: u8,
}

async fn source_admission(
    State(policy): State<SourceAdmission>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(peer) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|address| address.0.ip())
    else {
        if request.uri().path().starts_with("/auth/") && request.uri().path() != "/auth/logout" {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "request address unavailable",
            )
                .into_response();
        }
        return next.run(request).await;
    };
    let source = if policy.behind_proxy
        && policy
            .trusted_proxies
            .iter()
            .any(|network| network.contains(peer))
    {
        match request.headers().get("x-forwarded-for") {
            Some(value) => match value.to_str().ok().and_then(|value| value.parse().ok()) {
                Some(address) => address,
                None => {
                    return (StatusCode::BAD_REQUEST, "invalid forwarded address").into_response();
                }
            },
            None => peer,
        }
    } else {
        peer
    };
    request.extensions_mut().insert(ClientAddress(source));
    let path = request.uri().path();
    // Resolve trusted client metadata once for every plugin, before auth's own
    // request-rate policy. Plugin-specific admission remains in its router.
    if !path.starts_with("/auth/") || path == "/auth/logout" {
        return next.run(request).await;
    }
    let device = matches!(
        path.trim_start_matches("/auth/"),
        "device-start" | "device-redeem"
    );
    let Ok(now) = unix_seconds() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut buckets = policy.buckets.lock().await;
    if let Err(response) = admit_temporal_request(
        &mut buckets,
        (source, device),
        now,
        if device { 10 } else { 30 },
    ) {
        return response.into_response();
    }
    drop(buckets);
    next.run(request).await
}

/// Bounded refusal reasons share ordinary auth's exact HTTP response without
/// allocating a boxed response for each refused request.
pub(crate) enum TemporalRefusal {
    Capacity,
    Budget,
}
impl IntoResponse for TemporalRefusal {
    fn into_response(self) -> Response {
        match self {
            Self::Capacity => (
                StatusCode::TOO_MANY_REQUESTS,
                "source admission capacity exhausted",
            )
                .into_response(),
            Self::Budget => (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, "60")],
                "too many requests",
            )
                .into_response(),
        }
    }
}

/// Shared fixed-window auth budget. Expired entries are reclaimed without an
/// idle worker; the bounded map refuses new principals when full. Keys must be
/// server-attributed (trusted source address or live authenticated user ID).
pub(crate) fn admit_temporal_request<K: Eq + std::hash::Hash>(
    buckets: &mut HashMap<K, SourceBucket>,
    principal: K,
    now: i64,
    limit: u8,
) -> Result<(), TemporalRefusal> {
    buckets.retain(|_, bucket| now.saturating_sub(bucket.window) < 60);
    if !buckets.contains_key(&principal) && buckets.len() >= 4096 {
        return Err(TemporalRefusal::Capacity);
    }
    let bucket = buckets.entry(principal).or_insert(SourceBucket {
        window: now,
        requests: 0,
    });
    if bucket.requests >= limit {
        return Err(TemporalRefusal::Budget);
    }
    bucket.requests += 1;
    Ok(())
}

#[cfg(unix)]
fn set_private_directory(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Verifies startup storage, setup-token socket lifecycle, and proxy validation with local fixtures.

    use super::{
        ProxyNetwork, ServerConfig, TlsFiles, logging_color, router_with_agent,
        set_private_directory, start_setup_token_socket, validate_config,
    };
    use crate::embedded::EmbeddedAgent;
    use axum::{body::Body, http::Request};
    use std::{ffi::OsString, net::SocketAddr, path::PathBuf, str::FromStr};
    use tower::ServiceExt;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("infraternal-server-{}", uuid::Uuid::new_v4()))
    }

    fn config(data_dir: PathBuf) -> ServerConfig {
        ServerConfig {
            listen: SocketAddr::from(([127, 0, 0, 1], 47361)),
            data_dir,
            public_origin: "https://localhost:47361".to_owned(),
            web_root: None,
            tls: Some(TlsFiles {
                certificate: PathBuf::from("unused.crt"),
                private_key: PathBuf::from("unused.key"),
            }),
            behind_proxy: false,
            trusted_proxies: Vec::new(),
        }
    }

    #[tokio::test]
    async fn idle_sqlite_checkout_does_not_wait_for_a_worker_health_probe() {
        const CHILD: &str = "INFRATERNAL_SQLITE_CHECKOUT_CHILD";
        if let Some(directory) = std::env::var_os(CHILD) {
            let source = super::open_database(std::path::Path::new(&directory))
                .await
                .expect("production pool");
            let connect = source.connect_options();
            let options = source
                .options()
                .clone()
                .max_connections(1)
                .min_connections(1)
                .after_connect(|connection, _| {
                    Box::pin(async move {
                        // Freeze the worker before its new connection enters the
                        // idle queue. This deliberate lock leak is confined to a
                        // child process, whose exit releases every fixture resource.
                        std::mem::forget(connection.lock_handle().await?);
                        Ok(())
                    })
                });
            source.close().await;
            let pool = options.connect_lazy_with((*connect).clone());
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while pool.num_idle() != 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("fixture worker entered the idle queue");
            let mut connection =
                tokio::time::timeout(std::time::Duration::from_millis(100), pool.acquire())
                    .await
                    .expect("idle checkout must not wait for a redundant worker ping")
                    .expect("idle connection");
            // Avoiding the probe never converts an unavailable database into
            // authority. The real query still waits for the worker and times out.
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(&mut *connection),
                )
                .await
                .is_err()
            );
            println!("PASS idle checkout completed; blocked real query refused");
            std::process::exit(0);
        }
        let directory = temp_dir();
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "runtime::tests::idle_sqlite_checkout_does_not_wait_for_a_worker_health_probe",
                "--nocapture",
            ])
            .env(CHILD, &directory)
            .output()
            .expect("isolated worker fixture");
        if directory.exists() {
            std::fs::remove_dir_all(directory).expect("remove child fixture");
        }
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .contains("PASS idle checkout completed; blocked real query refused"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn proxy_networks_match_only_their_address_family_and_prefix() {
        let ipv4 = ProxyNetwork::from_str("10.69.69.9/24").expect("valid IPv4 network");
        assert!(ipv4.contains("10.69.69.125".parse().expect("valid IP")));
        assert!(!ipv4.contains("10.69.70.125".parse().expect("valid IP")));
        assert!(!ipv4.contains("::1".parse().expect("valid IP")));

        let ipv6 = ProxyNetwork::from_str("2001:db8::/32").expect("valid IPv6 network");
        assert!(ipv6.contains("2001:db8:1::1".parse().expect("valid IP")));
        assert!(ProxyNetwork::from_str("10.0.0.1/33").is_err());
    }

    #[test]
    fn empty_no_color_does_not_disable_terminal_logs() {
        assert!(logging_color(true, None));
        assert!(logging_color(true, Some(OsString::new())));
        assert!(!logging_color(true, Some(OsString::from("1"))));
        assert!(!logging_color(false, None));
    }

    /// The ordinary runtime, rather than a standalone plugin router, must expose admission.
    #[cfg(feature = "ssh")]
    #[tokio::test]
    async fn production_router_exposes_bootstrap_owner_admission() {
        use tokio_tungstenite::{connect_async, tungstenite::client::IntoClientRequest};
        let data_dir =
            PathBuf::from("target").join(format!("bootstrap-route-{}", uuid::Uuid::new_v4()));
        let (socket, _peer) = tokio::net::UnixStream::pair().expect("fixture socket");
        let (app, _) = router_with_agent(
            config(data_dir.clone()),
            EmbeddedAgent::from_test_socket(socket),
        )
        .await
        .expect("ordinary runtime router");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture listener");
        let address = listener.local_addr().expect("fixture address");
        let serving = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("fixture serving");
        });
        let mut request = format!("ws://{address}/v1/bootstrap/ws")
            .into_client_request()
            .expect("WebSocket handshake");
        request.headers_mut().insert(
            axum::http::header::ORIGIN,
            "https://localhost:47361".parse().expect("fixture Origin"),
        );
        let result = connect_async(request).await;
        serving.abort();
        let _ = serving.await;
        std::fs::remove_dir_all(data_dir).expect("remove fixture storage");
        let Err(tokio_tungstenite::tungstenite::Error::Http(response)) = result else {
            panic!("unauthenticated bootstrap must be refused");
        };
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn router_migrates_private_storage_and_serves_health() {
        let data_dir = temp_dir();
        let (agent_socket, _agent_peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let (app, _) = router_with_agent(
            config(data_dir.clone()),
            EmbeddedAgent::from_test_socket(agent_socket),
        )
        .await
        .expect("server router startup");
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("health request"),
            )
            .await
            .expect("health response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(data_dir.join("infraternal.sqlite").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&data_dir)
                .expect("data directory metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
            let mode = std::fs::metadata(data_dir.join("infraternal.sqlite"))
                .expect("database metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(data_dir).expect("remove temporary data directory");
    }

    /// Recreate the real runtime/router over one file database and replace its stale control socket.
    #[cfg(unix)]
    #[tokio::test]
    async fn restart_serves_fresh_setup_token_and_completes_owner_enrollment() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::UnixStream,
        };
        // A relative pathname stays in the package worktree and fits Unix SUN_LEN.
        let data_dir = PathBuf::from("target").join(format!("restart-{}", uuid::Uuid::new_v4()));
        let mut configuration = config(data_dir.clone());
        configuration.public_origin = "https://auth.example.test".to_owned();
        let (socket, _peer) = UnixStream::pair().expect("initial infraternal agent socketpair");
        let (app, first) = super::build_router(
            configuration.clone(),
            Some(EmbeddedAgent::from_test_socket(socket)),
        )
        .await
        .expect("initial startup");
        let path = data_dir.join("setup-token.sock");
        start_setup_token_socket(&data_dir, first.expect("initial setup capability"))
            .expect("initial private control socket");
        let mut client = UnixStream::connect(&path)
            .await
            .expect("initial CLI control connection");
        client
            .write_all(b"GET\n")
            .await
            .expect("initial CLI request");
        let mut old = String::new();
        client
            .read_to_string(&mut old)
            .await
            .expect("initial CLI capability response");
        drop(app);
        // A crashed process leaves this pathname behind. Startup must unlink it before binding.
        assert!(path.exists());
        let (socket, _peer) = UnixStream::pair().expect("restart infraternal agent socketpair");
        let (app, next) = super::build_router(
            configuration.clone(),
            Some(EmbeddedAgent::from_test_socket(socket)),
        )
        .await
        .expect("restart against existing database");
        start_setup_token_socket(&data_dir, next.expect("rotated setup capability"))
            .expect("replace stale private socket");
        let mut client = UnixStream::connect(&path)
            .await
            .expect("restart CLI control connection");
        client
            .write_all(b"GET\n")
            .await
            .expect("restart CLI request");
        let mut token = String::new();
        client
            .read_to_string(&mut token)
            .await
            .expect("restart CLI capability response");
        assert!(
            old != token,
            "restart must rotate the capability without logging it"
        );
        let pool = super::open_database(&data_dir)
            .await
            .expect("reopen real SQLite");
        let auth = crate::auth::Auth::new(
            pool.clone(),
            "auth.example.test",
            &configuration.public_origin,
        )
        .await
        .expect("inspection auth");
        let now = super::unix_seconds().expect("current time");
        assert!(auth.setup_start(old.trim(), "owner", now).await.is_err());
        crate::auth::tests::register_over_http(&app, token.trim()).await;
        let socket_removed = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .is_ok();
        assert!(
            socket_removed,
            "successful owner enrollment must unlink its CLI socket"
        );
        assert!(auth.setup_start(token.trim(), "owner", now).await.is_err());
        let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE owner=1")
            .fetch_one(&pool)
            .await
            .expect("owner count");
        assert_eq!(owners, 1);
        let mut announced = false;
        auth.bootstrap(now, |_| announced = true)
            .await
            .expect("post-setup startup");
        assert!(!announced, "completed setup must never mint another token");
        drop(app);
        pool.close().await;
        drop(auth);
        std::fs::remove_dir_all(data_dir).expect("remove restart fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn startup_with_owner_unlinks_stale_setup_token_socket() {
        use std::os::unix::net::UnixListener as StdUnixListener;
        use tokio::net::UnixStream;

        let data_dir =
            PathBuf::from("target").join(format!("owner-startup-{}", uuid::Uuid::new_v4()));
        let mut configuration = config(data_dir.clone());
        configuration.public_origin = "https://auth.example.test".to_owned();
        let (socket, _peer) = UnixStream::pair().expect("initial infraternal agent socketpair");
        let (app, _) = super::build_router(
            configuration.clone(),
            Some(EmbeddedAgent::from_test_socket(socket)),
        )
        .await
        .expect("initial server startup");
        drop(app);

        let pool = super::open_database(&data_dir)
            .await
            .expect("open migrated owner fixture");
        sqlx::query(
            "INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES ('test-owner','owner',1,'fixture-hash','owner','owner')",
        )
        .execute(&pool)
        .await
        .expect("persist existing owner fixture");
        pool.close().await;

        let path = data_dir.join("setup-token.sock");
        drop(StdUnixListener::bind(&path).expect("create crash-left socket fixture"));
        assert!(path.exists());
        let (socket, _peer) = UnixStream::pair().expect("restart infraternal agent socketpair");
        let (app, setup_token) =
            super::build_router(configuration, Some(EmbeddedAgent::from_test_socket(socket)))
                .await
                .expect("startup with existing owner");
        let removed = !path.exists();
        let no_token = setup_token.is_none();
        drop(app);
        std::fs::remove_dir_all(&data_dir).expect("remove owner startup fixture");

        assert!(
            no_token,
            "an existing owner must not receive a setup capability"
        );
        assert!(
            removed,
            "startup with an owner must unlink its stale CLI socket"
        );
    }

    #[cfg(unix)]
    #[test]
    fn setup_socket_cleanup_preserves_symlinks_and_regular_files() {
        use std::os::unix::fs::symlink;

        let data_dir =
            PathBuf::from("target").join(format!("setup-socket-safe-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data_dir).expect("create socket cleanup fixture");
        let path = data_dir.join("setup-token.sock");
        let target = data_dir.join("target-file");
        std::fs::write(&target, "untouched").expect("create symlink target");
        symlink(&target, &path).expect("create socket-path symlink");

        assert!(super::unlink_setup_token_socket(&data_dir).is_err());
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("symlink metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("symlink target"),
            "untouched"
        );

        std::fs::remove_file(&path).expect("remove test symlink");
        std::fs::write(&path, "preserved").expect("create regular-file fixture");
        assert!(super::unlink_setup_token_socket(&data_dir).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).expect("regular socket-path file"),
            "preserved"
        );

        std::fs::remove_dir_all(data_dir).expect("remove socket cleanup fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn setup_token_socket_is_private_and_requires_explicit_request() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::UnixStream,
        };

        let data_dir = temp_dir();
        std::fs::create_dir_all(&data_dir).expect("create private data directory");
        set_private_directory(&data_dir).expect("protect data directory");
        let path = data_dir.join("setup-token.sock");
        start_setup_token_socket(&data_dir, "test-capability".to_owned())
            .expect("start token control socket");
        let mode = std::fs::metadata(&path)
            .expect("control socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let mut client = UnixStream::connect(&path)
            .await
            .expect("connect to private token socket");
        client
            .write_all(b"GET\n")
            .await
            .expect("request setup capability");
        let mut token = Vec::new();
        client
            .read_to_end(&mut token)
            .await
            .expect("read setup capability");
        assert_eq!(token, b"test-capability\n");

        let mut invalid = UnixStream::connect(&path)
            .await
            .expect("connect for invalid request");
        invalid
            .write_all(b"NOPE")
            .await
            .expect("send invalid token request");
        let mut rejected = Vec::new();
        invalid
            .read_to_end(&mut rejected)
            .await
            .expect("read invalid request response");
        assert_eq!(rejected.as_slice(), b"");
        std::fs::remove_dir_all(data_dir).expect("remove temporary data directory");
    }

    #[tokio::test]
    async fn proxy_mode_requires_an_explicit_peer_allowlist() {
        let mut config = config(temp_dir());
        config.tls = None;
        config.behind_proxy = true;
        assert!(validate_config(&config).is_err());
    }
}

#[cfg(test)]
mod reviewer_admission {
    //! Independent production middleware checks for recovery source policy.
    use super::*;
    use tower::ServiceExt;
    async fn request(app: &Router, action: &str, forwarded: &str) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/auth/{action}"))
                    .header("x-forwarded-for", forwarded)
                    .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 5000))))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }
    #[tokio::test]
    async fn reviewer_recovery_source_limit_covers_all_routes_without_forwarding_bypass() {
        let policy = SourceAdmission {
            behind_proxy: false,
            trusted_proxies: Vec::new(),
            buckets: Arc::default(),
        };
        let app = Router::new()
            .route(
                "/auth/{action}",
                axum::routing::post(|| async { StatusCode::NO_CONTENT }),
            )
            .layer(from_fn_with_state(policy, source_admission));
        for _ in 0..30 {
            assert_eq!(
                request(&app, "recovery-resume", "198.51.100.1").await,
                StatusCode::NO_CONTENT
            );
        }
        for action in [
            "recovery-start",
            "recovery-resume",
            "recovery-rotate",
            "recovery-ready",
            "recovery-cancel",
        ] {
            assert_eq!(
                request(&app, action, "198.51.100.2").await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        for _ in 0..10 {
            assert_eq!(
                request(&app, "device-redeem", "198.51.100.2").await,
                StatusCode::NO_CONTENT
            );
        }
        assert_eq!(
            request(&app, "device-start", "198.51.100.3").await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            request(&app, "logout", "198.51.100.3").await,
            StatusCode::NO_CONTENT
        );
        println!(
            "REVIEW production source admission: 30 browser / 10 device, five recovery actions covered, untrusted XFF cannot reset budget, logout exempt"
        );
    }
}

#[cfg(all(test, feature = "remote"))]
#[path = "remote_demo_tests.rs"]
mod remote_demo_tests;

#[cfg(all(test, feature = "ssh"))]
#[path = "key_runtime_tests.rs"]
mod key_runtime_tests;
/// Exercises the reused bounded auth window independently of HTTP clock timing.
#[cfg(test)]
mod temporal_admission_tests {
    use super::*;

    #[test]
    fn windows_principals_and_capacity_remain_bounded() {
        let mut buckets = HashMap::new();
        for _ in 0..30 {
            assert!(admit_temporal_request(&mut buckets, 1, 1, 30).is_ok());
        }
        for now in [0, 1, 60] {
            let response = admit_temporal_request(&mut buckets, 1, now, 30)
                .unwrap_err()
                .into_response();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(response.headers()[header::RETRY_AFTER], "60");
        }
        assert!(admit_temporal_request(&mut buckets, 2, 1, 30).is_ok());
        assert!(admit_temporal_request(&mut buckets, 1, 61, 30).is_ok());
        assert_eq!(buckets.len(), 1);
        buckets.clear();
        for principal in 0..4096 {
            assert!(admit_temporal_request(&mut buckets, principal, 1, 30).is_ok());
        }
        assert_eq!(
            admit_temporal_request(&mut buckets, 4096, 1, 30)
                .unwrap_err()
                .into_response()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert!(admit_temporal_request(&mut buckets, 0, 1, 30).is_ok());
        assert_eq!(buckets.len(), 4096);
        assert!(admit_temporal_request(&mut buckets, 4096, 61, 30).is_ok());
        assert_eq!(buckets.len(), 1);
    }

    #[test]
    #[ignore = "isolated debug admission diagnostic at 4096 principals; run without own build overlap"]
    fn ca_budget_cost_at_capacity() {
        let mut buckets = HashMap::new();
        for principal in 0..4096 {
            assert!(
                admit_temporal_request(&mut buckets, format!("principal-{principal:04}"), 1, 30)
                    .is_ok()
            );
        }
        let mut samples = Vec::with_capacity(1000);
        for principal in 0..1000 {
            let key = format!("principal-{principal:04}");
            let start = std::time::Instant::now();
            assert!(admit_temporal_request(&mut buckets, key, 1, 30).is_ok());
            samples.push(start.elapsed().as_nanos());
        }
        samples.sort_unstable();
        println!(
            "METRIC ca_budget_principals={} requests={} wall_p50_ns={} wall_p99_ns={} max_starts_per_minute={} cores={} load={}",
            buckets.len(),
            samples.len(),
            samples[500],
            samples[990],
            4096 * 30,
            std::thread::available_parallelism().unwrap(),
            std::fs::read_to_string("/proc/loadavg").unwrap().trim()
        );
    }
}

/// Share the live runtime pool with verification so connection replacement keeps authority.
#[cfg(all(test, feature = "remote", feature = "ssh"))]
pub(crate) async fn test_open_database(
    data_dir: &std::path::Path,
) -> Result<SqlitePool, ServerError> {
    // This test-only copy preserves production pool setup while allowing shared-disk startup slack.
    std::fs::create_dir_all(data_dir).map_err(|_| ServerError::InvalidConfiguration)?;
    set_private_directory(data_dir).map_err(|_| ServerError::InvalidConfiguration)?;
    let database = data_dir.join("infraternal.sqlite");
    let options = SqliteConnectOptions::new()
        .filename(database)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(60))
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(options)
        .await
        .map_err(ServerError::Storage)?;
    set_private_file(&data_dir.join("infraternal.sqlite"))
        .map_err(|_| ServerError::InvalidConfiguration)?;
    Ok(pool)
}
