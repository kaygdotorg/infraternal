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
    if let Some(service) = remote {
        service.clock_health.start_monitor();
    }
    let Some(service) = remote else {
        return Ok(Router::new());
    };
    let Some(configuration) = service.ca_administration.as_ref() else {
        return Ok(Router::new());
    };
    let clock_health = service.clock_health.clone();
    configuration
        .with_runtime(auth.clone(), pool.clone(), hosts, store)
        .map(|authority| crate::ca_http::router(auth.clone(), authority, clock_health))
        .map_err(|_| ServerError::TlsConfiguration)
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
        crate::remote_removal::Removal,
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
        let source = remote.enrollment.source.clone();
        let clock_health = remote.clock_health.clone();
        Some(
            crate::remote_runtime::RemoteListeners::start_with_recovery(
                remote.enrollment.endpoint.endpoint,
                &remote.identity.ok_or(ServerError::TlsConfiguration)?,
                &remote.roots,
                enrollment_store.clone(),
                hosts.clone(),
                source,
                clock_health,
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
            .merge(crate::remote_removal_http::router(auth, removal.clone())),
        hosts,
        listeners,
        issuer,
        enrollment_store,
        removal,
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

/// Keep startup ordering visible: persisted switches load before node workers
/// attach, and admitted transports exist before their dependent server features.
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
    let (ca_api, remote_api, hosts, listeners, issuer, enrollment_store, removal) = remote_router(
        auth.clone(),
        pool.clone(),
        enrollment,
        remote,
        config.data_dir.join("ssh-trust"),
    )
    .await?;
    #[cfg(feature = "remote")]
    let auth_api_issuer = issuer.clone();
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
    #[cfg(feature = "remote")]
    let action_guard = crate::api_actions::ActionGuard::new(auth.clone(), pool.clone());
    #[cfg(feature = "remote")]
    let action_api = crate::api_actions::router(
        pool.clone(),
        removal.clone(),
        ws_state.clone(),
        action_guard.clone(),
    );
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
    #[cfg(feature = "remote")]
    let auth_api = auth::router_with_invitation_issuer(auth.clone(), auth_api_issuer);
    #[cfg(not(feature = "remote"))]
    let auth_api = auth::router(auth.clone());
    let app = Router::new()
        .route("/healthz", get(health))
        .with_state(pool)
        .merge(auth_api)
        .merge(websocket::router(ws_state))
        .merge(ca_api);
    #[cfg(feature = "remote")]
    let app = app.merge(remote_api).merge(action_api);
    #[cfg(feature = "ssh")]
    let warmup = Some(bootstrap.clone());
    #[cfg(not(feature = "ssh"))]
    let warmup = None;
    #[cfg(all(feature = "ssh", feature = "remote"))]
    let app = app.merge(crate::bootstrap_api::router_with_ssh_key_and_action_guard(
        auth.clone(),
        bootstrap,
        ssh_key,
        action_guard,
    ));
    #[cfg(all(feature = "ssh", not(feature = "remote")))]
    let app = app.merge(crate::bootstrap_api::router_with_ssh_key(
        &auth, bootstrap, ssh_key,
    ));
    let app = app.layer(from_fn_with_state(auth.clone(), auth::refresh_api_cookie));
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
    if server_healthy(&pool).await {
        Json(json!({"status":"ok"})).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"unavailable"})),
        )
            .into_response()
    }
}

/// Shared health predicate for `/healthz` and the signed API `server.status` action.
pub(crate) async fn server_healthy(pool: &SqlitePool) -> bool {
    sqlx::query("SELECT 1").execute(pool).await.is_ok()
}

/// Canonical client address from the listener and explicitly trusted proxy policy.
/// Plugins may bound work by it; untrusted forwarding headers never set this value.
#[derive(Clone, Copy)]
pub(crate) struct ClientAddress(pub(crate) IpAddr);

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
    // Every auth caller is accounted to its network, never its address: an
    // IPv6 caller rotating hosts inside one /64 must neither reset its budget
    // nor fill the shared map and refuse everyone else (#263, J134 P2-1).
    // Device-code requests have no process-wide ceiling, so this per-network
    // budget is their only request limit.
    let mut buckets = policy.buckets.lock().await;
    if let Err(response) = admit_temporal_request(
        &mut buckets,
        (device_source(source), device),
        now,
        if device { 10 } else { 30 },
    ) {
        return response.into_response();
    }
    drop(buckets);
    next.run(request).await
}

/// The network an auth caller is accounted to: the IPv4 address,
/// or the /64 of an IPv6 address (one interface allocation; hosts inside it
/// rotate freely). IPv4-mapped IPv6 addresses count as their IPv4 address.
pub(crate) fn device_source(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V4(_) => source,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
            || IpAddr::V6((u128::from(v6) & !u128::from(u64::MAX)).into()),
            IpAddr::V4,
        ),
    }
}

/// The enclosing network anonymous browser callers share a budget in: the
/// IPv4 /24, or the IPv6 /48 (a site or tunnel-broker allocation). One such
/// network can spend only its own budget, never everyone's (#263, J145 P2-1).
pub(crate) fn browser_network(source: IpAddr) -> IpAddr {
    match device_source(source) {
        IpAddr::V4(v4) => IpAddr::V4((u32::from(v4) & 0xffff_ff00).into()),
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & !((1_u128 << 80) - 1)).into()),
    }
}

/// A spent window shares ordinary auth's exact HTTP response without
/// allocating a boxed response for each refused request. A full map never
/// refuses: it evicts (see [`admit_temporal_request`]).
pub(crate) enum TemporalRefusal {
    Budget,
}
impl IntoResponse for TemporalRefusal {
    fn into_response(self) -> Response {
        match self {
            Self::Budget => (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, "60")],
                "too many requests",
            )
                .into_response(),
        }
    }
}

/// Most principals one fixed-window budget map holds.
const TEMPORAL_PRINCIPALS: usize = 4096;

/// Shared fixed-window auth budget. Expired entries are reclaimed without an
/// idle worker. When the map is full, the principal with the oldest window is
/// evicted, so a flood of new principals can never refuse a different caller
/// (#263, J134 P2-1). Eviction only hands the evicted principal a fresh
/// window early, so a flood buys at most one extra window per 4096 principals
/// it brings. Keys must be server-attributed (trusted source network or live
/// authenticated user ID).
pub(crate) fn admit_temporal_request<K: Eq + std::hash::Hash + Clone>(
    buckets: &mut HashMap<K, SourceBucket>,
    principal: K,
    now: i64,
    limit: u8,
) -> Result<(), TemporalRefusal> {
    buckets.retain(|_, bucket| now.saturating_sub(bucket.window) < 60);
    if !buckets.contains_key(&principal) && buckets.len() >= TEMPORAL_PRINCIPALS {
        // The same O(n) pass as the retain above, only on a full map.
        if let Some(oldest) = buckets
            .iter()
            .min_by_key(|(_, bucket)| bucket.window)
            .map(|(key, _)| key.clone())
        {
            buckets.remove(&oldest);
        }
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

/// D379 slice 1: the rusqlite runner must accept what this module's sqlx path built.
#[cfg(test)]
#[path = "runtime_rusqlite_compat_tests.rs"]
mod rusqlite_compat_tests;

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

    #[tokio::test]
    async fn loopback_https_port_initializes_auth_with_the_server_database() {
        let data_dir = temp_dir();
        let pool = super::open_database(&data_dir)
            .await
            .expect("open private server database");
        let auth = crate::auth::Auth::new(pool.clone(), "localhost", "https://localhost:443")
            .await
            .expect("initialize auth against the server database");
        let mut setup_announced = false;
        auth.bootstrap(super::unix_seconds().expect("current server time"), |_| {
            setup_announced = true;
        })
        .await
        .expect("bootstrap auth against the server database");
        assert!(setup_announced, "new server database should need setup");
        auth.shutdown_recovery_clock()
            .await
            .expect("stop the recovery checkpoint writer");
        drop(auth);
        pool.close().await;
        std::fs::remove_dir_all(data_dir).expect("remove temporary server database");
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

    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn production_router_mounts_the_bearer_action_endpoint() {
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
                    .method("POST")
                    .uri("/v1/actions/remote.host.list")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("action request"),
            )
            .await
            .expect("action response");
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        std::fs::remove_dir_all(data_dir).expect("remove temporary data directory");
    }

    /// J137 P3-1: a well-formed bearer that is not a key learns nothing about the catalogue.
    /// Unknown, non-key-callable and key-callable ids all get the same 403; only a caller
    /// whose key authenticates can tell an unknown action (404) from an out-of-scope one.
    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn an_unknown_bearer_cannot_probe_action_ids() {
        let data_dir = temp_dir();
        let (agent_socket, _agent_peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let (app, _) = router_with_agent(
            config(data_dir.clone()),
            EmbeddedAgent::from_test_socket(agent_socket),
        )
        .await
        .expect("server router startup");
        let pool = super::open_database(&data_dir)
            .await
            .expect("reopen real SQLite");
        let token = "fixture-probe-read-key-never-print";
        let now = super::unix_seconds().expect("current time");
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES('owner','owner',1,'x')")
            .execute(&pool)
            .await
            .expect("owner");
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,'owner','fixture-cli','[\"status:read\"]',?,?,0)")
            .bind(crate::auth::hash(token))
            .bind(now)
            .bind(now + 3600)
            .execute(&pool)
            .await
            .expect("key");
        let status = |bearer: &'static str, action: &'static str| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/actions/{action}"))
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {bearer}"))
                        .body(Body::from("{}"))
                        .expect("action request"),
                )
                .await
                .expect("action response")
                .status()
            }
        };
        for action in ["no.such.action", "server.status", "remote.ca.bootstrap"] {
            assert_eq!(
                status("not-a-key", action).await,
                axum::http::StatusCode::FORBIDDEN,
                "{action}"
            );
        }
        assert_eq!(
            status(token, "no.such.action").await,
            axum::http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(token, "server.status").await,
            axum::http::StatusCode::OK
        );
        pool.close().await;
        std::fs::remove_dir_all(data_dir).expect("remove temporary data directory");
    }

    /// POST one key action through the real router and return its status and JSON body.
    #[cfg(feature = "remote")]
    async fn post_key_action(
        app: &axum::Router,
        token: &str,
        action: &str,
        body: serde_json::Value,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/actions/{action}"))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body.to_string()))
                    .expect("action request"),
            )
            .await
            .expect("action response");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("action body");
        (
            status,
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// An owner, `hosts:write` keys with the given names and one live host, in the real database.
    #[cfg(feature = "remote")]
    async fn removal_fixture(pool: &sqlx::SqlitePool, tokens: &[&str]) -> uuid::Uuid {
        let now = super::unix_seconds().expect("current time");
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES('owner','owner',1,'x')")
            .execute(pool)
            .await
            .expect("owner");
        for token in tokens {
            sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,'owner','fixture-cli','[\"hosts:write\"]',?,?,0)")
                .bind(crate::auth::hash(token))
                .bind(now)
                .bind(now + 3600)
                .execute(pool)
                .await
                .expect("key");
        }
        let host = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)")
            .bind(host.as_bytes().as_slice())
            .execute(pool)
            .await
            .expect("host");
        host
    }

    #[cfg(feature = "remote")]
    async fn host_is_live(pool: &sqlx::SqlitePool, host: uuid::Uuid) -> bool {
        sqlx::query_scalar("SELECT revoked_at IS NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(pool)
            .await
            .expect("host row")
    }

    /// Forget requires hosts:write and a reviewed dry run; its audit commits with the tombstone.
    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn forget_retired_host_api_enforces_scope_review_and_audit() {
        let data_dir = temp_dir();
        let (agent_socket, _agent_peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let (app, _) = router_with_agent(
            config(data_dir.clone()),
            EmbeddedAgent::from_test_socket(agent_socket),
        )
        .await
        .expect("server router startup");
        let pool = super::open_database(&data_dir).await.expect("real SQLite");
        let token = "fixture-forget-key-never-print";
        let read_token = "fixture-forget-read-key-never-print";
        let host = removal_fixture(&pool, &[token, read_token]).await;
        let now = super::unix_seconds().expect("time");
        sqlx::query("UPDATE api_keys SET scopes='[\"hosts:read\"]' WHERE token_hash=?")
            .bind(crate::auth::hash(read_token))
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO remote_certificates(fingerprint,host_id,issuer_fingerprint,public_key,not_before,not_after) VALUES(zeroblob(32),?,zeroblob(32),zeroblob(32),?,?)")
            .bind(host.as_bytes().as_slice()).bind(now-604_800).bind(now).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES(?,'owner')")
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO remote_host_removals(host_id,owner_id,requested_at,uninstall,host_cleanup) VALUES(?,'owner',1,1,'pending')")
            .bind(host.as_bytes().as_slice()).execute(&pool).await.unwrap();
        let action = "remote.host.forget";
        let (status, _) = post_key_action(
            &app,
            read_token,
            action,
            serde_json::json!({"host_id":host,"dry_run":true}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        let (status, _) = post_key_action(
            &app,
            token,
            action,
            serde_json::json!({"host_id":host,"dry_run":false}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert!(host_is_live(&pool, host).await);
        let (status, review) = post_key_action(
            &app,
            token,
            action,
            serde_json::json!({"host_id":host,"dry_run":true}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert!(host_is_live(&pool, host).await);
        // A reviewed target can change before commit: a new valid certificate makes it pending again.
        sqlx::query("UPDATE remote_certificates SET not_before=?,not_after=? WHERE host_id=?")
            .bind(now - 604_800 + 3600)
            .bind(now + 3600)
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        let (status, _) = post_key_action(&app, token, action, serde_json::json!({"host_id":host,"dry_run":false,"review_token":review["review_token"]})).await;
        assert_eq!(status, axum::http::StatusCode::CONFLICT);
        assert!(host_is_live(&pool, host).await);
        let forgotten: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM mesh_audit WHERE action='remote.host.forget' AND resource=?",
        )
        .bind(host.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            forgotten, 0,
            "a state conflict must not record a successful Forget"
        );
        sqlx::query("UPDATE remote_certificates SET not_before=?,not_after=? WHERE host_id=?")
            .bind(now - 604_800)
            .bind(now)
            .bind(host.as_bytes().as_slice())
            .execute(&pool)
            .await
            .unwrap();
        let (status, review) = post_key_action(
            &app,
            token,
            action,
            serde_json::json!({"host_id":host,"dry_run":true}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let input = serde_json::json!({"host_id":host,"dry_run":false,"review_token":review["review_token"]});
        let (status, result) = post_key_action(&app, token, action, input.clone()).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(result["state"], "forgotten");
        assert!(!host_is_live(&pool, host).await);
        let audit: (String, Option<String>) = sqlx::query_as("SELECT state,result FROM api_action_audit WHERE action_id='remote.host.forget' AND key_id=? ORDER BY id DESC LIMIT 1")
            .bind(crate::auth::hash(token)).fetch_one(&pool).await.unwrap();
        assert_eq!(audit, ("complete".into(), Some("forgotten".into())));
        let (status, _) = post_key_action(&app, token, action, input).await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        pool.close().await;
        std::fs::remove_dir_all(data_dir).expect("remove temporary data directory");
    }

    /// J154 P2-2 / D28: "a destructive MCP action needs a dry run first". A key cannot remove
    /// a host in one call: `dry_run: false` without the dry run's review token is refused.
    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn a_removal_without_a_review_token_is_refused_and_the_host_stays() {
        let data_dir = temp_dir();
        let (agent_socket, _agent_peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let (app, _) = router_with_agent(
            config(data_dir.clone()),
            EmbeddedAgent::from_test_socket(agent_socket),
        )
        .await
        .expect("server router startup");
        let pool = super::open_database(&data_dir)
            .await
            .expect("reopen real SQLite");
        let token = "fixture-one-call-removal-key-never-print";
        let host = removal_fixture(&pool, &[token]).await;
        let (status, _) = post_key_action(
            &app,
            token,
            "remote.host.remove",
            serde_json::json!({"host_id": host, "dry_run": false}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
        assert!(host_is_live(&pool, host).await, "the host stays");
        pool.close().await;
        std::fs::remove_dir_all(data_dir).expect("remove temporary data directory");
    }

    /// Found on the test server (#303, J94e): the dry run of a host the owner does not have
    /// answered 403, which the CLI reads as a dead key ("Signed out"). The key is fine; the
    /// host is missing, so the answer is 404.
    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn a_dry_run_of_an_unknown_host_is_not_found_not_a_dead_key() {
        let data_dir = temp_dir();
        let (agent_socket, _agent_peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let (app, _) = router_with_agent(
            config(data_dir.clone()),
            EmbeddedAgent::from_test_socket(agent_socket),
        )
        .await
        .expect("server router startup");
        let pool = super::open_database(&data_dir)
            .await
            .expect("reopen real SQLite");
        let token = "fixture-unknown-host-key-never-print";
        removal_fixture(&pool, &[token]).await;
        let (status, _) = post_key_action(
            &app,
            token,
            "remote.host.remove",
            serde_json::json!({"host_id": uuid::Uuid::new_v4(), "dry_run": true}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        pool.close().await;
        std::fs::remove_dir_all(data_dir).expect("remove temporary data directory");
    }

    /// D28 through the real router: the dry run's token removes the host once. Another key,
    /// another host, a replay and a token on a dry run are refused, and refusals are audited.
    #[cfg(feature = "remote")]
    #[tokio::test]
    // One real-router sequence: each refusal, then the removal, then the audit.
    async fn a_removal_needs_its_own_dry_run_token_once() {
        use axum::http::StatusCode;
        use serde_json::json;
        let data_dir = temp_dir();
        let (agent_socket, _agent_peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let (app, _) = router_with_agent(
            config(data_dir.clone()),
            EmbeddedAgent::from_test_socket(agent_socket),
        )
        .await
        .expect("server router startup");
        let pool = super::open_database(&data_dir)
            .await
            .expect("reopen real SQLite");
        let token = "fixture-reviewed-removal-key-never-print";
        let other = "fixture-other-removal-key-never-print";
        let host = removal_fixture(&pool, &[token, other]).await;
        let remove = "remote.host.remove";
        let dry_run = |bearer| {
            post_key_action(
                &app,
                bearer,
                remove,
                json!({"host_id": host, "dry_run": true}),
            )
        };

        let (status, review) = dry_run(token).await;
        assert_eq!(status, StatusCode::OK, "{review}");
        assert_eq!(review["dry_run"], true);
        assert_eq!(review["review_expires_in"], 120);
        let review_token = review["review_token"]
            .as_str()
            .expect("review token")
            .to_owned();
        assert!(host_is_live(&pool, host).await, "a dry run changes nothing");

        let (status, refusal) = post_key_action(
            &app,
            other,
            remove,
            json!({"host_id": host, "dry_run": false, "review_token": review_token}),
        )
        .await;
        assert_eq!(
            (status, refusal["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("review_invalid"))
        );
        assert!(
            host_is_live(&pool, host).await,
            "another key's call spent the token, nothing else"
        );

        let (_, review) = dry_run(token).await;
        let review_token = review["review_token"].as_str().unwrap().to_owned();
        let (status, refusal) = post_key_action(
            &app,
            token,
            remove,
            json!({"host_id": uuid::Uuid::new_v4(), "dry_run": false, "review_token": review_token}),
        )
        .await;
        assert_eq!(
            (status, refusal["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("review_invalid"))
        );

        let (status, _) = post_key_action(
            &app,
            token,
            remove,
            json!({"host_id": host, "dry_run": true, "review_token": "x"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a dry run carries no token"
        );

        let (_, review) = dry_run(token).await;
        let review_token = review["review_token"].as_str().unwrap().to_owned();
        let real = json!({"host_id": host, "dry_run": false, "review_token": review_token});
        let (status, removed) = post_key_action(&app, token, remove, real.clone()).await;
        assert_eq!(status, StatusCode::OK, "{removed}");
        assert_eq!(removed["state"], "removed");
        assert!(!host_is_live(&pool, host).await);
        let (status, refusal) = post_key_action(&app, token, remove, real).await;
        assert_eq!(
            (status, refusal["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("review_invalid")),
            "a replay"
        );

        let audit: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT state,result FROM api_action_audit WHERE action_id='remote.host.remove' AND key_id=? ORDER BY id",
        )
        .bind(crate::auth::hash(token))
        .fetch_all(&pool)
        .await
        .expect("audit");
        let audit: Vec<(&str, Option<&str>)> = audit
            .iter()
            .map(|(s, r)| (s.as_str(), r.as_deref()))
            .collect();
        assert_eq!(
            audit,
            [
                ("complete", Some("dry_run")),
                ("complete", Some("dry_run")),
                ("denied", Some("review_invalid")),
                ("failed", None),
                ("complete", Some("dry_run")),
                ("complete", Some("removed")),
                ("denied", Some("review_invalid")),
            ]
        );
        pool.close().await;
        std::fs::remove_dir_all(data_dir).expect("remove temporary data directory");
    }

    /// J154 P2-1: reads by key are one summary row per key, action and minute, never one audit
    /// row per call.
    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn key_reads_are_counted_per_minute_not_written_per_call() {
        let data_dir = temp_dir();
        let (agent_socket, _agent_peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let (app, _) = router_with_agent(
            config(data_dir.clone()),
            EmbeddedAgent::from_test_socket(agent_socket),
        )
        .await
        .expect("server router startup");
        let pool = super::open_database(&data_dir)
            .await
            .expect("reopen real SQLite");
        let token = "fixture-read-count-key-never-print";
        let now = super::unix_seconds().expect("current time");
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES('owner','owner',1,'x')")
            .execute(&pool)
            .await
            .expect("owner");
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,'owner','fixture-cli','[\"status:read\"]',?,?,0)")
            .bind(crate::auth::hash(token))
            .bind(now)
            .bind(now + 3600)
            .execute(&pool)
            .await
            .expect("key");
        for _ in 0..5 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/actions/server.status")
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::from("{}"))
                        .expect("action request"),
                )
                .await
                .expect("action response");
            assert_eq!(response.status(), axum::http::StatusCode::OK);
        }
        let per_call: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_action_audit")
            .fetch_one(&pool)
            .await
            .expect("audit rows");
        assert_eq!(per_call, 0, "reads write no per-call row");
        let (rows, calls, failed): (i64, i64, i64) = sqlx::query_as(
            "SELECT COUNT(*),SUM(calls),SUM(failed) FROM api_read_audit WHERE key_id=? AND action_id='server.status'",
        )
        .bind(crate::auth::hash(token))
        .fetch_one(&pool)
        .await
        .expect("read summary");
        // Five calls can straddle one minute boundary.
        assert!(matches!(rows, 1 | 2), "{rows}");
        assert_eq!((calls, failed), (5, 0));
        pool.close().await;
        std::fs::remove_dir_all(data_dir).expect("remove temporary data directory");
    }

    /// Host inventory is a server-side socket plugin, not an infraternal agent descriptor; the
    /// bearer route must find it in the same runtime the browser socket dispatches to.
    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn live_read_key_reaches_the_server_plugin_host_inventory() {
        let data_dir = temp_dir();
        let (agent_socket, _agent_peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let (app, _) = router_with_agent(
            config(data_dir.clone()),
            EmbeddedAgent::from_test_socket(agent_socket),
        )
        .await
        .expect("server router startup");
        let pool = super::open_database(&data_dir)
            .await
            .expect("reopen real SQLite");
        let token = "fixture-inventory-key-never-print";
        let now = super::unix_seconds().expect("current time");
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES('owner','owner',1,'x')")
            .execute(&pool)
            .await
            .expect("owner");
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,'owner','fixture-cli','[\"hosts:read\"]',?,?,0)")
            .bind(crate::auth::hash(token))
            .bind(now)
            .bind(now + 3600)
            .execute(&pool)
            .await
            .expect("key");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/actions/remote.host.list")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from("{}"))
                    .expect("action request"),
            )
            .await
            .expect("action response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("inventory body");
        let inventory: serde_json::Value = serde_json::from_slice(&body).expect("inventory json");
        assert!(inventory["hosts"].is_array(), "{inventory}");
        pool.close().await;
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

#[cfg(test)]
mod device_code_admission_tests {
    //! Public device-code requests: one caller must not refuse another (#263, J122 P2).
    use super::*;
    use axum::body::Body;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    async fn post(app: &Router, action: &str, source: &str, body: &Value) -> (StatusCode, Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/auth/{action}"))
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", source)
                    .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 5000))))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap()
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn app() -> Router {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let auth = Auth::new(pool, "auth.example.test", "https://auth.example.test")
            .await
            .unwrap();
        let admission = SourceAdmission {
            behind_proxy: true,
            trusted_proxies: vec!["192.0.2.0/24".parse().unwrap()],
            buckets: Arc::default(),
        };
        auth::router(auth).layer(from_fn_with_state(admission, source_admission))
    }

    fn join_start() -> Value {
        json!({
            "kind": "join_machine",
            "device": "workstation",
            "request": {
                "host_id": "00000000-0000-0000-0000-000000000001",
                "hostname": "workstation",
                "mode": "system",
                "execution_uid": 0,
                "key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        })
    }

    #[tokio::test]
    async fn device_floods_from_other_sources_leave_a_new_source_its_whole_budget() {
        let app = app().await;
        // Six sources spend their full per-source device budget on guessed tokens.
        for source in 1..=6 {
            for _ in 0..10 {
                let (status, _) = post(
                    &app,
                    "device-redeem",
                    &format!("198.51.100.{source}"),
                    &json!({"token": "A".repeat(43)}),
                )
                .await;
                assert_eq!(status, StatusCode::UNAUTHORIZED);
            }
        }
        // A seventh caller still starts and polls both sign-in and machine join.
        let fresh = "203.0.113.7";
        let (status, started) = post(&app, "device-start", fresh, &join_start()).await;
        assert_eq!(status, StatusCode::OK, "machine join start was refused");
        let poll = json!({"token": started["poll_token"]});
        assert_eq!(
            post(&app, "device-redeem", fresh, &poll).await.0,
            StatusCode::UNAUTHORIZED,
            "a pending machine join poll must not be throttled by other sources"
        );
        let sign_in = json!({"device": "laptop", "scopes": ["hosts:read"]});
        let (status, started) = post(&app, "device-start", fresh, &sign_in).await;
        assert_eq!(status, StatusCode::OK, "sign-in start was refused");
        assert_eq!(
            post(
                &app,
                "device-redeem",
                fresh,
                &json!({"token": started["poll_token"]})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn one_ipv6_network_shares_one_device_budget() {
        let app = app().await;
        let guess = json!({"token": "A".repeat(43)});
        for host in 1..=10 {
            let (status, _) = post(
                &app,
                "device-redeem",
                &format!("2001:db8:1:2::{host}"),
                &guess,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        // Rotating the interface identifier inside the same /64 does not buy more requests.
        assert_eq!(
            post(&app, "device-redeem", "2001:db8:1:2::ffff", &guess)
                .await
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        // A different /64 keeps its own budget.
        assert_eq!(
            post(&app, "device-redeem", "2001:db8:1:3::1", &guess)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// Fresh IPv4 and IPv6 callers can still start an `up` after a flood.
    async fn assert_fresh_sources_start(app: &Router, flood: &str) {
        for fresh in ["203.0.113.9", "2001:db8:ffff::9"] {
            let (status, _) = post(app, "device-start", fresh, &join_start()).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{flood}: fresh {fresh} device-start"
            );
        }
    }

    #[tokio::test]
    async fn one_ipv6_network_rotating_browser_calls_cannot_refuse_other_callers() {
        // J134 P2-1: 4096 login-starts, one per address inside one /64.
        let app = app().await;
        let mut admitted = 0;
        for host in 0..4096_u32 {
            let source = format!("2001:db8:1:2::{:x}:{:x}", host >> 16, host & 0xffff);
            if post(&app, "login-start", &source, &json!({})).await.0
                != StatusCode::TOO_MANY_REQUESTS
            {
                admitted += 1;
            }
        }
        // The whole /64 shares one 30/minute browser budget.
        assert_eq!(admitted, 30);
        assert_fresh_sources_start(&app, "one /64").await;
    }

    /// A browser call from `source` with the app's own Origin.
    async fn browser(app: &Router, action: &str, source: &str) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/auth/{action}"))
                    .header("content-type", "application/json")
                    .header("origin", "https://auth.example.test")
                    .header("x-forwarded-for", source)
                    .extension(ConnectInfo(SocketAddr::from(([192, 0, 2, 1], 5000))))
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn four_networks_cannot_lock_everyone_out_of_sign_in() {
        // J145 P2-1: four networks at 30/minute each used to spend the one
        // server-wide 120/minute browser budget, and then nobody without a
        // live session could start a passkey sign-in.
        for (label, flood, inside) in [
            (
                "ipv4",
                [
                    "198.51.100.1",
                    "198.51.101.1",
                    "198.51.102.1",
                    "198.51.103.1",
                ],
                None,
            ),
            (
                "ipv6-one-/56",
                [
                    "2001:db8:5:100::1",
                    "2001:db8:5:101::1",
                    "2001:db8:5:102::1",
                    "2001:db8:5:103::1",
                ],
                Some("2001:db8:5:200::1"),
            ),
        ] {
            let app = app().await;
            assert_eq!(
                browser(&app, "login-start", "203.0.113.50").await,
                StatusCode::OK
            );
            let mut admitted = 0;
            for source in flood {
                for _ in 0..40 {
                    if browser(&app, "login-start", source).await == StatusCode::OK {
                        admitted += 1;
                    }
                }
            }
            assert!(
                admitted >= 32,
                "{label}: the flood itself was admitted {admitted}"
            );
            for fresh in ["203.0.113.9", "2001:db8:ffff::9"] {
                assert_eq!(
                    browser(&app, "login-start", fresh).await,
                    StatusCode::OK,
                    "{label}: fresh {fresh} login-start"
                );
            }
            // A new /64 inside the flooded /48 shares that /48's spent budget.
            if let Some(inside) = inside {
                assert_eq!(
                    browser(&app, "login-start", inside).await,
                    StatusCode::TOO_MANY_REQUESTS,
                    "{label}: {inside} is inside the flooded /48"
                );
            }
        }
    }

    #[tokio::test]
    async fn one_network_holds_at_most_its_share_of_anonymous_ceremonies() {
        // Without a server-wide budget, the pending anonymous ceremonies are
        // bounded per enclosing network instead.
        let app = app().await;
        let mut admitted = 0;
        for subnet in 0..8 {
            for _ in 0..30 {
                let source = format!("2001:db8:6:{subnet:x}00::1");
                if browser(&app, "login-start", &source).await == StatusCode::OK {
                    admitted += 1;
                }
            }
        }
        assert_eq!(
            admitted, 32,
            "one /48 holds 32 pending anonymous ceremonies"
        );
        assert_eq!(
            browser(&app, "login-start", "2001:db8:7::1").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_full_admission_map_evicts_instead_of_refusing_new_callers() {
        // 4096 distinct /64s fill the shared map; a newcomer still gets in.
        let app = app().await;
        for network in 0..4096_u32 {
            let source = format!("2001:db8:{:x}:{:x}::1", network >> 8, network & 0xff);
            assert_ne!(
                post(
                    &app,
                    "device-redeem",
                    &source,
                    &json!({"token": "A".repeat(43)})
                )
                .await
                .0,
                StatusCode::TOO_MANY_REQUESTS,
                "{source}"
            );
        }
        assert_fresh_sources_start(&app, "4096 networks").await;
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
        // Principal 0 holds the oldest window; 1..4096 open later in the same minute.
        assert!(admit_temporal_request(&mut buckets, 0, 1, 30).is_ok());
        for principal in 1..4096 {
            assert!(admit_temporal_request(&mut buckets, principal, 2, 30).is_ok());
        }
        // A full map admits a new principal by evicting the oldest window,
        // never by refusing the newcomer (#263, J134 P2-1).
        assert!(admit_temporal_request(&mut buckets, 4096, 2, 30).is_ok());
        assert_eq!(buckets.len(), 4096);
        assert!(!buckets.contains_key(&0));
        assert!(buckets.contains_key(&4096));
        assert!(admit_temporal_request(&mut buckets, 4096, 62, 30).is_ok());
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
