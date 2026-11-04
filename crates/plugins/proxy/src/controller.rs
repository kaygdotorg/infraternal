//! Turns authorized port publications into one supervised Traefik snapshot [#281, D303].

use crate::{
    config::{
        DnsChallenge, EntryPoints, ListenerPorts, PublishedService, StaticConfig,
        detect_mixed_listener_ports, detect_public_listener_pair,
    },
    custody::{DnsTokenCustody, FileDnsTokenCustody},
    download::{ComponentDownloader, CurlTransport},
    identity,
    installer::ComponentInstaller,
    manifest::OpenSshManifestVerifier,
    mesh_context::AcceptedMeshContext,
    names::{CertificateName, NameShape, exposure_names},
    supervisor::{ProxyLog, SupervisorSettings, TraefikSupervisor},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    env, fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use url::Url;

const DEFAULT_COMPONENT_MIRROR: &str = "https://builds.infraternal.com/releases/";
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_PING_TIMEOUT: Duration = Duration::from_secs(10);

/// Public DNS provider selection and credential-variable names; token values remain in custody files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsProviderProfile {
    /// Provider name understood by the pinned Traefik release.
    pub provider: String,
    /// ACME registration contact address.
    pub email: String,
    /// Provider environment variable names whose owner-only files are in `DnsTokenCustody`.
    pub credential_variables: Vec<String>,
}

impl DnsProviderProfile {
    pub(crate) fn from_environment() -> io::Result<Option<Self>> {
        let provider = env::var("INFRATERNAL_DNS_PROVIDER").ok();
        let email = env::var("INFRATERNAL_DNS_EMAIL").ok();
        let variables = env::var("INFRATERNAL_DNS_CREDENTIAL_VARIABLES").ok();
        match (provider, email, variables) {
            (None, None, None) => Ok(None),
            (Some(provider), Some(email), Some(variables)) => {
                let credential_variables: Vec<_> = variables
                    .split(',')
                    .map(str::trim)
                    .map(str::to_owned)
                    .collect();
                if provider.is_empty()
                    || provider.len() > 63
                    || email.trim().is_empty()
                    || email.len() > 254
                    || credential_variables.is_empty()
                    || credential_variables.iter().any(|name| {
                        name.is_empty()
                            || name.len() > 128
                            || name.ends_with("_FILE")
                            || !name.bytes().all(|byte| {
                                byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                            })
                            || !name.as_bytes()[0].is_ascii_uppercase()
                    })
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "DNS provider profile is invalid",
                    ));
                }
                Ok(Some(Self {
                    provider,
                    email,
                    credential_variables,
                }))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS provider profile requires provider, email, and credential variable names",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExposureSpec {
    port: u16,
    public: bool,
    shape: NameShape,
}

struct Exposure {
    spec: ExposureSpec,
    last_route: Option<PublishedService>,
}

struct ControllerState {
    enabled: bool,
    rootful: bool,
    mesh: Option<AcceptedMeshContext>,
    exposures: BTreeMap<u16, Exposure>,
    supervisor: Option<Box<dyn RouteSupervisor>>,
    // Rootless only: the public-only process. It exists exactly while a public route does.
    public_supervisor: Option<Box<dyn RouteSupervisor>>,
    listener_ports: ListenerPorts,
}

/// Callback that synchronizes public listener gating and confirmed Mesh route grants with the
/// packet filter.
pub use crate::ingress::MeshIngressObserver;
use crate::ingress::{IngressPublisher, PublicGate};

/// Small replace-only boundary between desired publications and the process owner.
pub trait RouteSupervisor: Send {
    /// Atomically replace the complete active route snapshot and report its listener ports.
    ///
    /// # Errors
    /// Returns an error when config rendering, child startup, or health readiness fails.
    fn replace(&self, services: Vec<PublishedService>) -> io::Result<Option<ListenerPorts>>;

    /// Report whether Traefik currently answers its private health probe.
    ///
    /// # Errors
    /// Returns an error when the supervisor owner has stopped.
    fn is_running(&self) -> io::Result<bool>;
}

impl RouteSupervisor for TraefikSupervisor {
    fn replace(&self, services: Vec<PublishedService>) -> io::Result<Option<ListenerPorts>> {
        TraefikSupervisor::replace(self, services)
    }

    fn is_running(&self) -> io::Result<bool> {
        TraefikSupervisor::is_running(self)
    }
}

/// Starts the local runtime only when the first authorized exposure exists.
pub trait SupervisorFactory: Send + Sync {
    /// Prepare an idle supervisor and select its stable listener ports for the accepted context.
    ///
    /// # Errors
    /// Returns an error when the component, provider files, or private state cannot be prepared.
    ///
    /// A rootful supervisor receives the public listener gate: it closes the gate before a child
    /// binds the wildcard pair and clears it once that child is reaped.
    /// Without root, `rootless_public` is the public process's pair for the Mesh pair to avoid.
    fn start(
        &self,
        context: &AcceptedMeshContext,
        public_gate: Option<PublicGate>,
        rootless_public: Option<infraternal_mesh::proxy_ports::ListenerPortPair>,
    ) -> io::Result<(Box<dyn RouteSupervisor>, ListenerPorts)>;

    /// Rootless only: prepare a public-only process on a free wildcard pair (D330).
    ///
    /// # Errors
    /// Returns an error when no pair is free or the process state can't be prepared.
    fn start_public(
        &self,
        context: &AcceptedMeshContext,
        mesh_pair: Option<infraternal_mesh::proxy_ports::ListenerPortPair>,
    ) -> io::Result<(
        Box<dyn RouteSupervisor>,
        infraternal_mesh::proxy_ports::ListenerPortPair,
    )>;
}

/// Shares accepted Mesh identity with the action handler and its sibling observer.
#[derive(Clone)]
pub struct ProxyController {
    state: Arc<Mutex<ControllerState>>,
    factory: Option<Arc<dyn SupervisorFactory>>,
    ingress: Arc<IngressPublisher>,
}

impl Default for ProxyController {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(ControllerState {
                enabled: true,
                rootful: identity::rootful(),
                mesh: None,
                exposures: BTreeMap::new(),
                supervisor: None,
                public_supervisor: None,
                listener_ports: ListenerPorts {
                    http: 10_080,
                    https: 10_443,
                    mesh_http: None,
                    mesh_https: None,
                },
            })),
            factory: None,
            ingress: Arc::new(IngressPublisher::default()),
        }
    }
}

impl ProxyController {
    /// Link accepted route application to the Mesh node's firewall owner.
    ///
    /// # Errors
    /// Returns an error if proxy publication state is unavailable.
    pub fn set_mesh_ingress_observer(&self, observer: MeshIngressObserver) -> io::Result<()> {
        self.ingress.set_observer(observer)
    }

    /// Build the production node controller from non-secret provider settings and node state.
    ///
    /// DNS token bytes are loaded only by `DnsTokenCustody` when the first route starts. The
    /// component mirror can be overridden with `INFRATERNAL_COMPONENT_MIRROR`; provider identity,
    /// contact, and credential variable names use the `INFRATERNAL_DNS_*` settings. None of those
    /// settings contains a DNS token.
    ///
    /// # Errors
    /// Returns an error when a configured mirror or non-secret DNS provider profile is malformed.
    pub fn for_agent(state_dir: &Path, log: Arc<ProxyLog>) -> io::Result<Self> {
        let mirror = env::var("INFRATERNAL_COMPONENT_MIRROR")
            .unwrap_or_else(|_| DEFAULT_COMPONENT_MIRROR.to_owned());
        let mirror = Url::parse(&mirror).map_err(io::Error::other)?;
        let release_version = option_env!("INFRATERNAL_RELEASE_VERSION")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_owned();
        let profile = DnsProviderProfile::from_environment()?;
        let custody = FileDnsTokenCustody::open(state_dir)?;
        custody.remove_unconfigured_providers(
            profile
                .as_ref()
                .map(|configured| configured.provider.as_str()),
        )?;
        let factory = Arc::new(DownloadedTraefikFactory {
            state_dir: state_dir.to_owned(),
            mirror,
            release_version,
            profile,
            log,
        });
        Ok(Self::with_factory(factory))
    }

    fn with_factory(factory: Arc<dyn SupervisorFactory>) -> Self {
        Self {
            factory: Some(factory),
            ..Self::default()
        }
    }

    /// Refresh authorization from one accepted Mesh snapshot and revoke stale routes immediately.
    ///
    /// # Errors
    /// Returns an error when a complete new route snapshot cannot be applied.
    pub fn set_mesh_context(&self, context: Option<AcceptedMeshContext>) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("proxy publication state is unavailable"))?;
        if state.mesh == context {
            return Ok(());
        }
        let listener_address_changed = matches!(
            (state.mesh.as_ref(), context.as_ref()),
            (Some(previous), Some(next)) if previous.mesh_address != next.mesh_address
        );
        let mesh_identity_lost = context.is_none();
        if listener_address_changed || mesh_identity_lost {
            // Static entry points bind an IP address, so a dynamic route reload cannot move them.
            // Dropping the old owner closes stale listeners before a changed identity is reused.
            state.supervisor = None;
        }
        if mesh_identity_lost {
            // Retain publication intent, but never retain a route bound to an expired Mesh identity.
            for exposure in state.exposures.values_mut() {
                exposure.last_route = None;
            }
        }
        state.mesh = context;
        self.reconcile(&mut state)
    }

    /// Stop accepting new publications or resume the saved in-memory exposure set.
    ///
    /// # Errors
    /// Returns an error when the complete route snapshot cannot be applied.
    pub fn set_enabled(&self, enabled: bool) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("proxy publication state is unavailable"))?;
        if state.enabled == enabled {
            return Ok(());
        }
        state.enabled = enabled;
        self.reconcile(&mut state)
    }

    /// Report whether the proxy component is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.state.lock().is_ok_and(|state| state.enabled)
    }

    /// Dispatch one public proxy action.
    ///
    /// # Errors
    /// Returns only a declared action or a bounded plugin rejection.
    pub fn call(
        &self,
        action_id: &str,
        input: &[u8],
    ) -> Result<Vec<u8>, infraternal_plugin_api::PluginError> {
        match action_id {
            "proxy.publish" => {
                let request: PublishRequest = serde_json::from_slice(input)
                    .map_err(|_| infraternal_plugin_api::PluginError::Rejected)?;
                self.publish(request)
            }
            "proxy.unpublish" => {
                let request: UnpublishRequest = serde_json::from_slice(input)
                    .map_err(|_| infraternal_plugin_api::PluginError::Rejected)?;
                self.unpublish(request)
            }
            _ => Err(infraternal_plugin_api::PluginError::UnknownAction),
        }
    }

    fn publish(
        &self,
        request: PublishRequest,
    ) -> Result<Vec<u8>, infraternal_plugin_api::PluginError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| infraternal_plugin_api::PluginError::Rejected)?;
        if !state.enabled {
            return error_reply("component_down", "The proxy component is off on this node.");
        }
        let Some(port) = request.port else {
            if request.public || request.confirm_public || request.flat_name {
                return error_reply("usage", "Give a port when using publication options.");
            }
            refresh_routes(&mut state)
                .map_err(|_| infraternal_plugin_api::PluginError::Rejected)?;
            return publication_list(&state);
        };
        if port == 0 || request.confirm_public && !request.public {
            return error_reply(
                "usage",
                "Use a valid local port and confirm only a public publication.",
            );
        }
        let Some(context) = state.mesh.clone() else {
            return error_reply(
                "unreachable",
                "Mesh identity is unavailable; turn Mesh on before publishing.",
            );
        };
        let first_public = request.public
            && !state
                .exposures
                .values()
                .any(|exposure| exposure.spec.public);
        if first_public && !request.confirm_public {
            return error_reply(
                "not_allowed",
                "Confirm the first public publication with --confirm-public.",
            );
        }
        let spec = ExposureSpec {
            port,
            public: request.public,
            shape: if request.flat_name {
                NameShape::FlatService
            } else {
                NameShape::PerMachineWildcard
            },
        };
        let route = route_for(spec, &context, state.listener_ports)
            .map_err(|_| infraternal_plugin_api::PluginError::Rejected)?;
        if !route.public && route.allowed_sources.is_empty() {
            return error_reply(
                "not_allowed",
                &format!("No inbound Mesh TCP grant permits port {port} on this node."),
            );
        }
        state.exposures.insert(
            port,
            Exposure {
                spec,
                last_route: Some(route),
            },
        );
        if self.reconcile(&mut state).is_err() {
            return error_reply(
                "failed",
                "The proxy could not update its routes; check its component and DNS provider configuration.",
            );
        }
        let mut reply = publication_list(&state)?;
        if request.public && !state.rootful {
            reply = with_public_reachability_warning(&reply, state.listener_ports)?;
        }
        Ok(reply)
    }

    fn unpublish(
        &self,
        request: UnpublishRequest,
    ) -> Result<Vec<u8>, infraternal_plugin_api::PluginError> {
        let UnpublishRequest { target } = request;
        if !valid_unpublish_target(&target) {
            return error_reply("usage", "Give a local port or exact published DNS name.");
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| infraternal_plugin_api::PluginError::Rejected)?;
        let port = find_publication(&state, &target);
        let Some(port) = port else {
            let display_target = target
                .parse::<u16>()
                .map_or(target, |port| format!("port {port}"));
            return error_reply(
                "missing",
                &format!("No publication matches {display_target}."),
            );
        };
        let exposure = state
            .exposures
            .remove(&port)
            .ok_or(infraternal_plugin_api::PluginError::Rejected)?;
        let route = exposure.last_route;
        if self.reconcile(&mut state).is_err() {
            return error_reply(
                "failed",
                "The proxy could not remove the route; check its component status.",
            );
        }
        let hostname = route.as_ref().map_or_else(
            || format!("local port {port}"),
            |route| route.hostname.clone(),
        );
        let message = route.as_ref().map_or_else(
            || format!("Stopped publishing local port {port}."),
            |route| {
                let url = https_url(
                    &route.hostname,
                    state
                        .listener_ports
                        .https_for_publication(route.public),
                );
                if route.public && !state.rootful && state.public_supervisor.is_none() {
                    format!(
                        "Stopped publishing {url}. The public listener is closed, and with it every open connection."
                    )
                } else if route.public {
                    format!(
                        "Stopped publishing {url}. New connections are refused; connections already open, such as WebSockets, stay open until they close."
                    )
                } else {
                    format!(
                        "Stopped publishing {url}. New connections are refused, and open connections from Mesh peers are closed."
                    )
                }
            },
        );
        serde_json::to_vec(&json!({
            "message": message,
            "data": {"port": port, "hostname": hostname, "public": exposure.spec.public}
        }))
        .map_err(|_| infraternal_plugin_api::PluginError::Rejected)
    }

    fn reconcile(&self, state: &mut ControllerState) -> io::Result<()> {
        if state.rootful {
            return self.reconcile_main(state, |_| true);
        }
        // Without root there is no firewall gate, so public routes live in their own process.
        // Removing a route updates or stops that process before the Mesh one is touched.
        self.reconcile_public(state)?;
        self.reconcile_main(state, |service| !service.public)
    }

    fn reconcile_main(
        &self,
        state: &mut ControllerState,
        owned: fn(&PublishedService) -> bool,
    ) -> io::Result<()> {
        let routes = |state: &mut ControllerState| -> io::Result<Vec<PublishedService>> {
            Ok(refresh_routes(state)?.into_iter().filter(owned).collect())
        };
        let mut services = routes(state)?;
        if state.supervisor.is_some()
            && self.ingress.current()?.public_route_active
            && !services.iter().any(|service| service.public)
        {
            // Close the wildcard pair before Traefik drops the last public route.
            self.ingress
                .update(false, |ingress| ingress.public_route_active = false)?;
        }
        if let Some(supervisor) = &state.supervisor {
            if let Some(ports) = supervisor.replace(services.clone())? {
                merge_main_ports(state, ports);
            }
            self.update_mesh_ingress(state, &services, true)?;
            return Ok(());
        }
        if services.is_empty() {
            self.update_mesh_ingress(state, &services, false)?;
            return Ok(());
        }
        let factory = self.factory.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "proxy runtime is not configured",
            )
        })?;
        let context = state.mesh.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "accepted Mesh identity is unavailable",
            )
        })?;
        let public_gate = state.rootful.then(|| self.ingress.public_gate());
        let rootless_public =
            (!state.rootful).then_some(infraternal_mesh::proxy_ports::ListenerPortPair {
                http: state.listener_ports.http,
                https: state.listener_ports.https,
            });
        let (supervisor, listener_ports) = factory.start(context, public_gate, rootless_public)?;
        merge_main_ports(state, listener_ports);
        services = routes(state)?;
        let listener_ports = supervisor.replace(services.clone())?;
        if let Some(ports) = listener_ports {
            merge_main_ports(state, ports);
        }
        state.supervisor = Some(supervisor);
        self.update_mesh_ingress(state, &services, true)?;
        Ok(())
    }

    // Rootless public routes (D330). Without a firewall the listener's life is the only control:
    // the process starts with its first public snapshot already applied, and the last removal
    // is reported only after the process has exited and its wildcard listener is closed.
    fn reconcile_public(&self, state: &mut ControllerState) -> io::Result<()> {
        let public = |state: &mut ControllerState| -> io::Result<Vec<PublishedService>> {
            Ok(refresh_routes(state)?
                .into_iter()
                .filter(|service| service.public)
                .collect())
        };
        if public(state)?.is_empty() {
            // Dropping the owner stops and reaps the child before this returns.
            state.public_supervisor = None;
            return Ok(());
        }
        if state.public_supervisor.is_none() {
            let factory = self.factory.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "proxy runtime is not configured",
                )
            })?;
            let context = state.mesh.as_ref().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "accepted Mesh identity is unavailable",
                )
            })?;
            let mesh_pair = state
                .listener_ports
                .mesh_http
                .zip(state.listener_ports.mesh_https)
                .map(
                    |(http, https)| infraternal_mesh::proxy_ports::ListenerPortPair { http, https },
                );
            let (supervisor, pair) = factory.start_public(context, mesh_pair)?;
            state.listener_ports.http = pair.http;
            state.listener_ports.https = pair.https;
            state.public_supervisor = Some(supervisor);
        }
        // Routes are rendered again so redirects and URLs name the selected pair.
        let services = public(state)?;
        let replaced = state
            .public_supervisor
            .as_ref()
            .map_or(Ok(None), |supervisor| supervisor.replace(services));
        if replaced.is_err() {
            // An unconfirmed public snapshot must not leave a wildcard listener running.
            state.public_supervisor = None;
        }
        replaced.map(|_| ())
    }

    // Publish the Mesh routes Traefik has applied. The public gate itself belongs to the
    // supervisor; this only marks a public route live once the gate exists.
    fn update_mesh_ingress(
        &self,
        state: &ControllerState,
        services: &[PublishedService],
        confirmed: bool,
    ) -> io::Result<()> {
        let backend_ports = services
            .iter()
            .filter(|service| !service.public)
            .map(|service| service.backend.port())
            .collect::<std::collections::BTreeSet<_>>();
        let listener_pair = if backend_ports.is_empty() {
            None
        } else {
            state
                .listener_ports
                .mesh_http
                .zip(state.listener_ports.mesh_https)
                .map(
                    |(http, https)| infraternal_mesh::proxy_ports::ListenerPortPair { http, https },
                )
        };
        let public_route = services.iter().any(|service| service.public);
        self.ingress.update(confirmed, |ingress| {
            ingress.listener_pair = listener_pair;
            ingress.backend_ports = backend_ports;
            ingress.public_route_active = public_route && ingress.public_listener_pair.is_some();
        })
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishRequest {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    public: bool,
    #[serde(default)]
    confirm_public: bool,
    #[serde(default)]
    flat_name: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnpublishRequest {
    target: String,
}

struct DownloadedTraefikFactory {
    state_dir: PathBuf,
    mirror: Url,
    release_version: String,
    profile: Option<DnsProviderProfile>,
    log: Arc<ProxyLog>,
}

impl DownloadedTraefikFactory {
    // One Traefik process: its own config directory, ACME file, health port and locks. Two
    // processes never share an ACME file, so neither can overwrite the other's account state.
    fn start_process(
        &self,
        context: &AcceptedMeshContext,
        entry_points: EntryPoints,
        listener_ports: ListenerPorts,
        public_gate: Option<PublicGate>,
    ) -> io::Result<Box<dyn RouteSupervisor>> {
        let profile = self.profile.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "DNS provider profile is not configured",
            )
        })?;
        let custody = FileDnsTokenCustody::open(&self.state_dir)?;
        let provider_files = profile
            .credential_variables
            .iter()
            .map(|name| Ok((name.clone(), custody.get(&profile.provider, name)?)))
            .collect::<io::Result<Vec<_>>>()?;

        let installer = ComponentInstaller::new(&self.state_dir);
        let downloader = ComponentDownloader::new(self.mirror.clone(), CurlTransport)?;
        let (os, arch) = target_platform()?;
        let executable = downloader.install(
            &installer,
            &self.release_version,
            os,
            arch,
            &OpenSshManifestVerifier,
        )?;

        let mut proxy_state = self.state_dir.join("proxy");
        ensure_proxy_directory(&proxy_state)?;
        // The lock stays out of the child-readable directory: its parent must be agent-only.
        let mut private_state = self.state_dir.join("proxy-private");
        ensure_private_directory(&private_state)?;
        if entry_points == EntryPoints::PublicOnly {
            proxy_state = proxy_state.join("public");
            ensure_proxy_directory(&proxy_state)?;
            private_state = private_state.join("public");
            ensure_private_directory(&private_state)?;
        }
        let dynamic_directory = proxy_state.join("dynamic");
        ensure_proxy_directory(&dynamic_directory)?;
        let acme_storage = proxy_state.join("acme.json");
        ensure_private_file(&acme_storage)?;
        let private_ping_port = loopback_port()?;
        let static_config = StaticConfig {
            entry_points,
            mesh_address: context.mesh_address,
            // Go opens one dual-stack socket for the IPv4 wildcard.
            public_bind_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ports: listener_ports,
            private_ping_port,
            dynamic_directory: PathBuf::from("dynamic"),
            dns_challenge: DnsChallenge {
                provider: profile.provider.clone(),
                email: profile.email.clone(),
                storage_path: PathBuf::from("acme.json"),
                ca_server: None,
                resolvers: Vec::new(),
                disable_authoritative_ns_checks: false,
            },
        };
        let supervisor = TraefikSupervisor::start(
            SupervisorSettings {
                executable,
                static_config_path: proxy_state.join("traefik.toml"),
                lock_directory: private_state,
                dynamic_config_path: dynamic_directory.join(crate::config::DYNAMIC_CONFIG_FILENAME),
                static_config,
                provider_files,
                private_ping_address: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    private_ping_port,
                ),
                startup_timeout: PRIVATE_PING_TIMEOUT,
                public_gate,
            },
            Arc::clone(&self.log),
        )?;
        Ok(Box::new(supervisor))
    }
}

impl SupervisorFactory for DownloadedTraefikFactory {
    fn start(
        &self,
        context: &AcceptedMeshContext,
        public_gate: Option<PublicGate>,
        rootless_public: Option<infraternal_mesh::proxy_ports::ListenerPortPair>,
    ) -> io::Result<(Box<dyn RouteSupervisor>, ListenerPorts)> {
        let rootful = identity::rootful();
        let listener_ports =
            detect_mixed_listener_ports(rootful, context.mesh_address, rootless_public)?;
        let (entry_points, public_gate) = if rootful {
            (EntryPoints::Mixed, public_gate)
        } else {
            (EntryPoints::MeshOnly, None)
        };
        let supervisor = self.start_process(context, entry_points, listener_ports, public_gate)?;
        Ok((supervisor, listener_ports))
    }

    fn start_public(
        &self,
        context: &AcceptedMeshContext,
        mesh_pair: Option<infraternal_mesh::proxy_ports::ListenerPortPair>,
    ) -> io::Result<(
        Box<dyn RouteSupervisor>,
        infraternal_mesh::proxy_ports::ListenerPortPair,
    )> {
        let pair = detect_public_listener_pair(mesh_pair)?;
        let ports = ListenerPorts {
            http: pair.http,
            https: pair.https,
            mesh_http: None,
            mesh_https: None,
        };
        let supervisor = self.start_process(context, EntryPoints::PublicOnly, ports, None)?;
        Ok((supervisor, pair))
    }
}

// Rootful, the mixed process owns every pair. Rootless, the Mesh process reports only its
// Mesh pair; the public pair belongs to the public process and is never overwritten here.
fn merge_main_ports(state: &mut ControllerState, ports: ListenerPorts) {
    if state.rootful {
        state.listener_ports = ports;
    } else {
        state.listener_ports.mesh_http = ports.mesh_http;
        state.listener_ports.mesh_https = ports.mesh_https;
    }
}

// D330: without root nothing on this machine filters the public pair for us.
fn with_public_reachability_warning(
    reply: &[u8],
    ports: ListenerPorts,
) -> Result<Vec<u8>, infraternal_plugin_api::PluginError> {
    let mut value: serde_json::Value =
        serde_json::from_slice(reply).map_err(|_| infraternal_plugin_api::PluginError::Rejected)?;
    let warning = format!(
        "Public routes listen on ports {} and {} on every address of this machine. The Mesh firewall does not filter these ports; only this machine's firewall or your router limits who can reach them, and either may still block them.",
        ports.http, ports.https
    );
    let message = value["message"].as_str().unwrap_or_default().to_owned();
    value["message"] = serde_json::Value::String(format!("{message} {warning}"));
    value["warning"] = serde_json::Value::String(warning);
    serde_json::to_vec(&value).map_err(|_| infraternal_plugin_api::PluginError::Rejected)
}

fn target_platform() -> io::Result<(&'static str, &'static str)> {
    let os = match env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "proxy platform is unsupported",
            ));
        }
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "proxy architecture is unsupported",
            ));
        }
    };
    Ok((os, arch))
}

fn loopback_port() -> io::Result<u16> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
        .local_addr()?
        .port())
}

pub(crate) fn ensure_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(PRIVATE_DIRECTORY_MODE);
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o7777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy state directory has unsafe ownership or mode",
        ));
    }
    Ok(())
}

/// Prepare a directory the rootful Traefik child may read: owned by the agent, group of the child.
///
/// A new directory starts agent-private (0700) and is then handed to the child group and opened
/// to 0750 through its descriptor, so the path is never group-readable under another group.
pub(crate) fn ensure_proxy_directory(path: &Path) -> io::Result<()> {
    if !identity::rootful() {
        return ensure_private_directory(path);
    }
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(PRIVATE_DIRECTORY_MODE);
            match builder.create(path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(error) => return Err(error),
    }
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = directory.metadata()?;
    let child_gid = identity::child_group()?;
    if !metadata.file_type().is_dir() || metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy state directory has unsafe ownership or type",
        ));
    }
    if metadata.gid() == nix::unistd::Gid::effective().as_raw()
        && metadata.mode() & 0o7777 == PRIVATE_DIRECTORY_MODE
    {
        nix::unistd::fchown(
            &directory,
            Some(nix::unistd::Uid::effective()),
            Some(nix::unistd::Gid::from_raw(child_gid)),
        )?;
        directory.set_permissions(fs::Permissions::from_mode(0o750))?;
    } else if metadata.gid() != child_gid || metadata.mode() & 0o7777 != 0o750 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy state directory has unsafe group or mode",
        ));
    }
    let metadata = directory.metadata()?;
    if metadata.gid() != child_gid || metadata.mode() & 0o7777 != 0o750 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy state directory has unsafe group or mode",
        ));
    }
    Ok(())
}

pub(crate) fn ensure_private_file(path: &Path) -> io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?,
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    let (owner_user, owner_group) = identity::child_ids()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || !path_metadata.file_type().is_file()
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy ACME state file has unsafe ownership or mode",
        ));
    }
    if metadata.uid() == nix::unistd::Uid::effective().as_raw()
        && metadata.gid() == nix::unistd::Gid::effective().as_raw()
        && metadata.mode() & 0o7777 == PRIVATE_FILE_MODE
        && identity::rootful()
    {
        nix::unistd::fchown(
            &file,
            Some(nix::unistd::Uid::from_raw(owner_user)),
            Some(nix::unistd::Gid::from_raw(owner_group)),
        )?;
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    } else if metadata.uid() != owner_user
        || metadata.gid() != owner_group
        || metadata.mode() & 0o7777 != PRIVATE_FILE_MODE
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy ACME state file has unsafe ownership or mode",
        ));
    }
    if metadata.len() == 0 {
        file.write_all(b"{}")?;
    }
    file.sync_all()?;
    Ok(())
}

fn route_for(
    spec: ExposureSpec,
    context: &AcceptedMeshContext,
    listener_ports: ListenerPorts,
) -> io::Result<PublishedService> {
    let service_label = format!("port-{}", spec.port);
    let names = exposure_names(
        spec.shape,
        &context.machine_name,
        &service_label,
        &context.dns_suffix,
    )?;
    Ok(PublishedService {
        id: service_label,
        hostname: names.hostname,
        backend: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), spec.port),
        allowed_sources: context.allowed_sources(spec.port),
        public: spec.public,
        https_port: listener_ports.https_for_publication(spec.public),
        certificate: names.certificate,
    })
}

fn refresh_routes(state: &mut ControllerState) -> io::Result<Vec<PublishedService>> {
    if !state.enabled {
        return Ok(Vec::new());
    }
    let context = state.mesh.clone();
    let mut routes = Vec::new();
    for exposure in state.exposures.values_mut() {
        if let Some(context) = &context {
            exposure.last_route = Some(route_for(exposure.spec, context, state.listener_ports)?);
        }
        let Some(route) = exposure.last_route.as_ref() else {
            continue;
        };
        if route.public || context.is_some() && !route.allowed_sources.is_empty() {
            routes.push(route.clone());
        }
    }
    Ok(routes)
}

fn publication_list(
    state: &ControllerState,
) -> Result<Vec<u8>, infraternal_plugin_api::PluginError> {
    let running = |supervisor: &Option<Box<dyn RouteSupervisor>>| {
        supervisor
            .as_ref()
            .map_or(Ok(false), |supervisor| supervisor.is_running())
            .map_err(|_| infraternal_plugin_api::PluginError::Rejected)
    };
    let main_running = running(&state.supervisor)?;
    let public_running = if state.rootful {
        main_running
    } else {
        running(&state.public_supervisor)?
    };
    let services: Vec<_> = state
        .exposures
        .values()
        .filter_map(|exposure| {
            let route = exposure.last_route.as_ref()?;
            let process_running = if exposure.spec.public {
                public_running
            } else {
                main_running
            };
            let reachable = state.enabled
                && process_running
                && (exposure.spec.public
                    || state.mesh.is_some() && !route.allowed_sources.is_empty());
            Some(json!({
                "port": exposure.spec.port,
                "hostname": route.hostname,
                "url": https_url(
                    &route.hostname,
                    state.listener_ports.https_for_publication(route.public)
                ),
                "public": exposure.spec.public,
                "reachable": reachable,
                "access": if reachable && exposure.spec.public {"internet"} else if reachable {"mesh grant"} else if !state.enabled {"proxy is off"} else if exposure.spec.public {"proxy is starting"} else {"blocked by Mesh grants"},
                "certificate": match &route.certificate {
                    CertificateName::Wildcard(name) | CertificateName::Exact(name) => name,
                },
            }))
        })
        .collect();
    let message = if services.is_empty() {
        "No services are published.".to_owned()
    } else {
        format!("{} published service(s).", services.len())
    };
    serde_json::to_vec(&json!({"message": message, "services": services}))
        .map_err(|_| infraternal_plugin_api::PluginError::Rejected)
}

fn find_publication(state: &ControllerState, target: &str) -> Option<u16> {
    if target.bytes().all(|byte| byte.is_ascii_digit()) {
        let port = target.parse::<u16>().ok()?;
        return state.exposures.contains_key(&port).then_some(port);
    }
    state.exposures.iter().find_map(|(port, exposure)| {
        exposure
            .last_route
            .as_ref()
            .is_some_and(|route| route.hostname == target)
            .then_some(*port)
    })
}

fn valid_unpublish_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 253 {
        return false;
    }
    if target.bytes().all(|byte| byte.is_ascii_digit()) {
        return target.parse::<u16>().is_ok_and(|port| port > 0);
    }
    target.split('.').all(|label| {
        let bytes = label.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
            && (bytes[bytes.len() - 1].is_ascii_lowercase()
                || bytes[bytes.len() - 1].is_ascii_digit())
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    })
}

fn error_reply(code: &str, message: &str) -> Result<Vec<u8>, infraternal_plugin_api::PluginError> {
    serde_json::to_vec(&json!({"error":{"code":code},"message":message}))
        .map_err(|_| infraternal_plugin_api::PluginError::Rejected)
}

fn https_url(hostname: &str, port: u16) -> String {
    if port == 443 {
        format!("https://{hostname}")
    } else {
        format!("https://{hostname}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::net::{IpAddr, Ipv4Addr};

    type Snapshots = Arc<Mutex<Vec<Vec<PublishedService>>>>;
    type StartedAddresses = Arc<Mutex<Vec<IpAddr>>>;

    #[derive(Clone)]
    struct FakeFactory {
        snapshots: Arc<Mutex<Vec<Vec<PublishedService>>>>,
        started_addresses: Arc<Mutex<Vec<IpAddr>>>,
        listener_ports: ListenerPorts,
        public_snapshots: Snapshots,
        public_events: Arc<Mutex<Vec<&'static str>>>,
    }

    // Emulates the real supervisor's gate ownership: closed before the first child starts,
    // cleared when the owner (and so its child) goes away.
    struct FakeSupervisor {
        snapshots: Arc<Mutex<Vec<Vec<PublishedService>>>>,
        listener_ports: ListenerPorts,
        public_gate: Option<PublicGate>,
        child_started: std::sync::atomic::AtomicBool,
        stopped: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    impl Drop for FakeSupervisor {
        fn drop(&mut self) {
            if let Some(gate) = &self.public_gate {
                let _ = gate(crate::ingress::PublicGateState::Cleared);
            }
            if let Some(events) = &self.stopped
                && let Ok(mut events) = events.lock()
            {
                events.push("public process stopped");
            }
        }
    }

    impl SupervisorFactory for FakeFactory {
        fn start(
            &self,
            context: &AcceptedMeshContext,
            public_gate: Option<PublicGate>,
            _rootless_public: Option<infraternal_mesh::proxy_ports::ListenerPortPair>,
        ) -> io::Result<(Box<dyn RouteSupervisor>, ListenerPorts)> {
            self.started_addresses
                .lock()
                .map_err(|_| io::Error::other("fixture start log is unavailable"))?
                .push(context.mesh_address);
            Ok((
                Box::new(FakeSupervisor {
                    snapshots: Arc::clone(&self.snapshots),
                    listener_ports: self.listener_ports,
                    public_gate,
                    child_started: std::sync::atomic::AtomicBool::new(false),
                    stopped: None,
                }),
                self.listener_ports,
            ))
        }

        fn start_public(
            &self,
            _context: &AcceptedMeshContext,
            mesh_pair: Option<infraternal_mesh::proxy_ports::ListenerPortPair>,
        ) -> io::Result<(
            Box<dyn RouteSupervisor>,
            infraternal_mesh::proxy_ports::ListenerPortPair,
        )> {
            let pair = infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS
                .iter()
                .copied()
                .find(|pair| mesh_pair != Some(*pair))
                .ok_or_else(|| io::Error::other("fixture pair"))?;
            self.public_events
                .lock()
                .map_err(|_| io::Error::other("fixture events"))?
                .push("public process started");
            Ok((
                Box::new(FakeSupervisor {
                    snapshots: Arc::clone(&self.public_snapshots),
                    listener_ports: ListenerPorts {
                        http: pair.http,
                        https: pair.https,
                        mesh_http: None,
                        mesh_https: None,
                    },
                    public_gate: None,
                    child_started: std::sync::atomic::AtomicBool::new(false),
                    stopped: Some(Arc::clone(&self.public_events)),
                }),
                pair,
            ))
        }
    }

    impl RouteSupervisor for FakeSupervisor {
        fn replace(&self, services: Vec<PublishedService>) -> io::Result<Option<ListenerPorts>> {
            if !services.is_empty()
                && !self
                    .child_started
                    .swap(true, std::sync::atomic::Ordering::AcqRel)
                && let Some(gate) = &self.public_gate
            {
                gate(crate::ingress::PublicGateState::Closed(
                    infraternal_mesh::proxy_ports::ListenerPortPair {
                        http: self.listener_ports.http,
                        https: self.listener_ports.https,
                    },
                ))?;
            }
            self.snapshots
                .lock()
                .map_err(|_| io::Error::other("fixture snapshot is unavailable"))?
                .push(services);
            Ok(Some(self.listener_ports))
        }

        fn is_running(&self) -> io::Result<bool> {
            Ok(self
                .snapshots
                .lock()
                .map_err(|_| io::Error::other("fixture snapshot is unavailable"))?
                .last()
                .is_some_and(|snapshot| !snapshot.is_empty()))
        }
    }

    fn context(ports: &[(u16, Ipv4Addr)]) -> AcceptedMeshContext {
        context_at(IpAddr::V4(Ipv4Addr::new(10, 254, 0, 2)), ports)
    }

    fn context_at(mesh_address: IpAddr, ports: &[(u16, Ipv4Addr)]) -> AcceptedMeshContext {
        AcceptedMeshContext::new(
            "web01".to_owned(),
            "ssh.kayg.org".to_owned(),
            mesh_address,
            [],
            ports
                .iter()
                .map(|(port, address)| (*port, IpAddr::V4(*address))),
        )
        .expect("accepted Mesh context")
    }

    fn controller() -> (ProxyController, Arc<Mutex<Vec<Vec<PublishedService>>>>) {
        controller_with_ports(ListenerPorts {
            http: 10_080,
            https: 10_443,
            mesh_http: None,
            mesh_https: None,
        })
    }

    fn controller_with_ports(
        listener_ports: ListenerPorts,
    ) -> (ProxyController, Arc<Mutex<Vec<Vec<PublishedService>>>>) {
        let (controller, snapshots, _) = controller_with_ports_and_starts(listener_ports);
        (controller, snapshots)
    }

    fn controller_with_ports_and_starts(
        listener_ports: ListenerPorts,
    ) -> (ProxyController, Snapshots, StartedAddresses) {
        let snapshots = Arc::new(Mutex::new(Vec::new()));
        let started_addresses = Arc::new(Mutex::new(Vec::new()));
        let factory = Arc::new(FakeFactory {
            snapshots: Arc::clone(&snapshots),
            started_addresses: Arc::clone(&started_addresses),
            listener_ports,
            public_snapshots: Arc::default(),
            public_events: Arc::default(),
        });
        let controller = ProxyController::with_factory(factory);
        controller
            .state
            .lock()
            .expect("controller fixture state")
            .rootful = true;
        controller
            .set_mesh_ingress_observer(Arc::new(|_, _| Ok(())))
            .expect("install fake firewall observer");
        (controller, snapshots, started_addresses)
    }

    #[test]
    fn mesh_firewall_tracks_only_applied_non_public_routes() {
        let selected = infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS[1];
        let (controller, snapshots) = controller_with_ports(ListenerPorts {
            http: 10_080,
            https: 10_443,
            mesh_http: Some(selected.http),
            mesh_https: Some(selected.https),
        });
        let applied = Arc::new(Mutex::new(Vec::new()));
        let observer: MeshIngressObserver = {
            let applied = Arc::clone(&applied);
            let snapshots = Arc::clone(&snapshots);
            Arc::new(move |ingress, _confirmed| {
                let snapshots = snapshots
                    .lock()
                    .map_err(|_| io::Error::other("applied route fixture is unavailable"))?;
                assert_eq!(
                    ingress.backend_ports,
                    snapshots
                        .last()
                        .into_iter()
                        .flatten()
                        .filter(|route| !route.public)
                        .map(|route| route.backend.port())
                        .collect()
                );
                applied
                    .lock()
                    .map_err(|_| io::Error::other("ingress fixture is unavailable"))?
                    .push(ingress);
                Ok(())
            })
        };
        controller
            .set_mesh_ingress_observer(observer)
            .expect("install firewall observer");
        controller
            .set_mesh_context(Some(context(&[
                (3000, Ipv4Addr::new(10, 254, 0, 3)),
                (4000, Ipv4Addr::new(10, 254, 0, 4)),
            ])))
            .expect("apply accepted Mesh grants");

        controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish Mesh route");
        controller
            .call(
                "proxy.publish",
                br#"{"port":4000,"public":true,"confirm_public":true}"#,
            )
            .expect("publish public route");

        let updates = applied.lock().expect("firewall updates");
        assert_eq!(updates.len(), 3);
        assert_eq!(
            updates[0].public_listener_pair,
            Some(infraternal_mesh::proxy_ports::ListenerPortPair {
                http: 10_080,
                https: 10_443,
            })
        );
        assert!(!updates[0].public_route_active);
        assert_eq!(updates[1].listener_pair, Some(selected));
        assert_eq!(updates[1].backend_ports, [3000].into_iter().collect());
        assert!(updates[2].public_route_active);
        assert_eq!(updates[2].backend_ports, [3000].into_iter().collect());
        drop(updates);

        controller
            .call("proxy.unpublish", br#"{"target":"3000"}"#)
            .expect("unpublish Mesh route");
        let updates = applied.lock().expect("firewall updates");
        assert_eq!(updates.len(), 4);
        assert!(updates[3].backend_ports.is_empty());
        assert_eq!(updates[3].listener_pair, None);
        assert!(updates[3].public_route_active);
    }

    #[test]
    fn public_listener_gate_is_installed_before_the_first_route_snapshot() {
        let selected = infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS[1];
        let (controller, snapshots) = controller_with_ports(ListenerPorts {
            http: 10_080,
            https: 10_443,
            mesh_http: Some(selected.http),
            mesh_https: Some(selected.https),
        });
        let snapshot_counts = Arc::new(Mutex::new(Vec::new()));
        let observer: MeshIngressObserver = {
            let snapshot_counts = Arc::clone(&snapshot_counts);
            let snapshots = Arc::clone(&snapshots);
            Arc::new(move |ingress, _confirmed| {
                let count = snapshots
                    .lock()
                    .map_err(|_| io::Error::other("route fixture is unavailable"))?
                    .len();
                snapshot_counts
                    .lock()
                    .map_err(|_| io::Error::other("firewall fixture is unavailable"))?
                    .push((count, ingress.public_route_active));
                Ok(())
            })
        };
        controller
            .set_mesh_ingress_observer(observer)
            .expect("install firewall observer");
        controller
            .set_mesh_context(Some(context(&[(3000, Ipv4Addr::new(10, 254, 0, 3))])))
            .expect("accept Mesh grants");

        controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish one Mesh route");
        controller
            .call(
                "proxy.publish",
                br#"{"port":4000,"public":true,"confirm_public":true}"#,
            )
            .expect("publish first public route");
        controller
            .call("proxy.unpublish", br#"{"target":"4000"}"#)
            .expect("remove last public route");

        assert_eq!(
            *snapshot_counts.lock().expect("firewall updates"),
            [(0, false), (1, false), (2, true), (2, false), (3, false)],
            "close before startup, open after apply, and close before removing the last public route"
        );
    }

    #[test]
    fn the_public_gate_is_removed_once_the_proxy_child_is_gone() {
        let (controller, _) = controller_with_ports(ListenerPorts {
            http: 80,
            https: 443,
            mesh_http: Some(10_080),
            mesh_https: Some(10_443),
        });
        let gates = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&gates);
        controller
            .set_mesh_ingress_observer(Arc::new(move |ingress, _confirmed| {
                recorded
                    .lock()
                    .map_err(|_| io::Error::other("gate fixture"))?
                    .push(ingress.public_listener_pair.map(|pair| pair.https));
                Ok(())
            }))
            .expect("install firewall observer");
        controller
            .set_mesh_context(Some(context(&[(3000, Ipv4Addr::new(10, 254, 0, 3))])))
            .expect("accept Mesh grants");
        controller
            .call(
                "proxy.publish",
                br#"{"port":3000,"public":true,"confirm_public":true}"#,
            )
            .expect("publish a public route");
        // Losing Mesh identity drops the process owner, and with it the child.
        controller
            .set_mesh_context(None)
            .expect("drop the expired Mesh identity");

        let gates = gates.lock().expect("gate updates");
        assert_eq!(gates.first(), Some(&Some(443)));
        assert_eq!(
            gates.last(),
            Some(&None),
            "no gate may outlive its listener"
        );
    }

    struct RootlessFixture {
        controller: ProxyController,
        mesh_snapshots: Snapshots,
        mesh_starts: StartedAddresses,
        public_snapshots: Snapshots,
        public_events: Arc<Mutex<Vec<&'static str>>>,
    }

    fn rootless_controller() -> RootlessFixture {
        let mesh_snapshots: Snapshots = Arc::default();
        let mesh_starts: StartedAddresses = Arc::default();
        let public_snapshots: Snapshots = Arc::default();
        let public_events: Arc<Mutex<Vec<&'static str>>> = Arc::default();
        let selected = infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS[1];
        let controller = ProxyController::with_factory(Arc::new(FakeFactory {
            snapshots: Arc::clone(&mesh_snapshots),
            started_addresses: Arc::clone(&mesh_starts),
            listener_ports: ListenerPorts {
                http: 10_080,
                https: 10_443,
                mesh_http: Some(selected.http),
                mesh_https: Some(selected.https),
            },
            public_snapshots: Arc::clone(&public_snapshots),
            public_events: Arc::clone(&public_events),
        }));
        controller
            .state
            .lock()
            .expect("controller fixture state")
            .rootful = false;
        controller
            .set_mesh_context(Some(context(&[
                (3000, Ipv4Addr::new(10, 254, 0, 3)),
                (4000, Ipv4Addr::new(10, 254, 0, 3)),
            ])))
            .expect("accept Mesh grants");
        RootlessFixture {
            controller,
            mesh_snapshots,
            mesh_starts,
            public_snapshots,
            public_events,
        }
    }

    #[test]
    fn rootless_public_publication_warns_that_only_the_host_firewall_limits_reach() {
        let fixture = rootless_controller();
        let output = fixture
            .controller
            .call(
                "proxy.publish",
                br#"{"port":4000,"public":true,"confirm_public":true}"#,
            )
            .expect("publish a public route without root");
        let value: Value = serde_json::from_slice(&output).expect("publication JSON");

        assert!(
            value["error"].is_null(),
            "rootless --public is allowed: {value}"
        );
        let warning = value["warning"].as_str().expect("reachability warning");
        let pair = infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS[0];
        assert!(warning.contains(&pair.https.to_string()), "{warning}");
        assert!(warning.contains("only this machine's firewall or your router"));
        assert!(warning.contains("Mesh firewall does not filter"));
        assert_eq!(
            value["services"][0]["url"],
            format!("https://port-4000.web01.ssh.kayg.org:{}", pair.https)
        );
        // The public route was applied by the public process before the reply.
        let public = fixture.public_snapshots.lock().expect("public snapshots");
        assert_eq!(public.len(), 1);
        assert!(public[0].iter().all(|route| route.public));
        assert!(
            fixture.mesh_starts.lock().expect("Mesh starts").is_empty(),
            "a public route alone needs no Mesh process"
        );
    }

    #[test]
    fn rootless_public_routes_never_restart_the_mesh_listeners() {
        let fixture = rootless_controller();
        fixture
            .controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish a Mesh route");
        fixture
            .controller
            .call(
                "proxy.publish",
                br#"{"port":4000,"public":true,"confirm_public":true}"#,
            )
            .expect("publish a public route");
        fixture
            .controller
            .call("proxy.unpublish", br#"{"target":"4000"}"#)
            .expect("remove the public route");

        assert_eq!(fixture.mesh_starts.lock().expect("Mesh starts").len(), 1);
        for snapshot in fixture
            .mesh_snapshots
            .lock()
            .expect("Mesh snapshots")
            .iter()
        {
            assert!(
                snapshot.iter().all(|route| !route.public),
                "the Mesh process never carries a public route"
            );
        }
        assert_eq!(
            *fixture.public_events.lock().expect("public events"),
            ["public process started", "public process stopped"],
            "the wildcard listener is closed before the removal is reported"
        );
    }

    #[test]
    fn production_acme_storage_initializes_as_a_private_json_object() {
        use std::os::unix::fs::PermissionsExt;

        let root = env::temp_dir().join(format!("proxy-acme-init-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("create ACME storage root");
        fs::set_permissions(&root, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
            .expect("make ACME storage root private");
        let path = root.join("acme.json");

        ensure_private_file(&path).expect("initialize ACME storage");

        assert_eq!(fs::read(&path).expect("read ACME storage"), b"{}");
        assert_eq!(
            fs::symlink_metadata(&path)
                .expect("inspect ACME storage")
                .mode()
                & 0o7777,
            PRIVATE_FILE_MODE
        );
        fs::remove_dir_all(root).expect("remove ACME storage fixture");
    }

    #[test]
    fn production_acme_storage_repairs_an_existing_empty_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = env::temp_dir().join(format!("proxy-acme-empty-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).expect("create ACME storage root");
        fs::set_permissions(&root, fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))
            .expect("make ACME storage root private");
        let path = root.join("acme.json");
        fs::write(&path, b"").expect("create empty ACME storage");
        fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_FILE_MODE))
            .expect("make empty ACME storage private");

        ensure_private_file(&path).expect("repair empty ACME storage");

        assert_eq!(fs::read(&path).expect("read ACME storage"), b"{}");
        fs::remove_dir_all(root).expect("remove ACME storage fixture");
    }

    #[test]
    fn published_url_includes_the_rootless_https_listener_port() {
        let (controller, _) = controller();
        controller
            .set_mesh_context(Some(context(&[(3000, Ipv4Addr::new(10, 254, 0, 3))])))
            .expect("apply accepted context");

        let output = controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish authorized port");
        let value: Value = serde_json::from_slice(&output).expect("publication result JSON");

        assert_eq!(
            value["services"][0]["url"],
            "https://port-3000.web01.ssh.kayg.org:10443"
        );
    }

    #[test]
    fn published_url_omits_the_default_https_port() {
        let (controller, _) = controller_with_ports(ListenerPorts {
            http: 80,
            https: 443,
            mesh_http: None,
            mesh_https: None,
        });
        controller
            .set_mesh_context(Some(context(&[(3000, Ipv4Addr::new(10, 254, 0, 3))])))
            .expect("apply accepted context");

        let output = controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish authorized port");
        let value: Value = serde_json::from_slice(&output).expect("publication result JSON");

        assert_eq!(
            value["services"][0]["url"],
            "https://port-3000.web01.ssh.kayg.org"
        );
    }

    #[test]
    fn mixed_publication_urls_use_the_listener_for_each_audience() {
        let (controller, _) = controller_with_ports(ListenerPorts {
            http: 80,
            https: 443,
            mesh_http: Some(10080),
            mesh_https: Some(10443),
        });
        controller
            .set_mesh_context(Some(context(&[
                (3000, Ipv4Addr::new(10, 254, 0, 3)),
                (3001, Ipv4Addr::new(10, 254, 0, 3)),
            ])))
            .expect("apply accepted context");
        controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish mesh route");

        let output = controller
            .call(
                "proxy.publish",
                br#"{"port":3001,"public":true,"confirm_public":true}"#,
            )
            .expect("publish public route");
        let value: Value = serde_json::from_slice(&output).expect("publication result JSON");

        assert_eq!(
            value["services"][0]["url"],
            "https://port-3000.web01.ssh.kayg.org:10443"
        );
        assert_eq!(
            value["services"][1]["url"],
            "https://port-3001.web01.ssh.kayg.org"
        );
    }

    #[test]
    fn unpublish_by_port_removes_the_route_and_reports_what_is_unreachable() {
        let (controller, snapshots) = controller();
        controller
            .set_mesh_context(Some(context(&[(3000, Ipv4Addr::new(10, 254, 0, 3))])))
            .expect("apply accepted context");
        controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish authorized port");

        let output = controller
            .call("proxy.unpublish", br#"{"target":"3000"}"#)
            .expect("unpublish existing port");
        let value: Value = serde_json::from_slice(&output).expect("unpublish result JSON");

        assert!(value["message"].as_str().is_some_and(|message| {
            message.contains("https://port-3000.web01.ssh.kayg.org:10443")
                && message.contains("open connections from Mesh peers are closed")
                && !message.contains("10 seconds")
        }));
        assert_eq!(value["data"]["port"], 3000);
        assert!(
            snapshots
                .lock()
                .expect("fixture snapshots")
                .last()
                .is_some_and(Vec::is_empty)
        );
    }

    #[test]
    fn unpublish_by_exact_name_removes_the_same_route() {
        let (controller, snapshots) = controller();
        controller
            .set_mesh_context(Some(context(&[(3000, Ipv4Addr::new(10, 254, 0, 3))])))
            .expect("apply accepted context");
        controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish authorized port");

        let output = controller
            .call(
                "proxy.unpublish",
                br#"{"target":"port-3000.web01.ssh.kayg.org"}"#,
            )
            .expect("unpublish exact published name");
        let value: Value = serde_json::from_slice(&output).expect("unpublish result JSON");

        assert_eq!(value["data"]["hostname"], "port-3000.web01.ssh.kayg.org");
        assert!(
            snapshots
                .lock()
                .expect("fixture snapshots")
                .last()
                .is_some_and(Vec::is_empty)
        );
    }

    #[test]
    fn revoking_the_last_mesh_grant_removes_the_route_snapshot() {
        let (controller, snapshots) = controller();
        controller
            .set_mesh_context(Some(context(&[(3000, Ipv4Addr::new(10, 254, 0, 3))])))
            .expect("apply accepted context");
        controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish authorized port");

        controller
            .set_mesh_context(Some(context(&[])))
            .expect("apply grant revocation");

        assert!(
            snapshots
                .lock()
                .expect("fixture snapshots")
                .last()
                .is_some_and(Vec::is_empty)
        );
    }

    #[test]
    fn an_accepted_mesh_address_change_restarts_the_proxy_listener() {
        let (controller, _, started_addresses) = controller_with_ports_and_starts(ListenerPorts {
            http: 10_080,
            https: 10_443,
            mesh_http: None,
            mesh_https: None,
        });
        controller
            .set_mesh_context(Some(context(&[(3000, Ipv4Addr::new(10, 254, 0, 3))])))
            .expect("apply accepted context");
        controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish authorized port");

        controller
            .set_mesh_context(Some(context_at(
                IpAddr::V4(Ipv4Addr::new(10, 254, 0, 9)),
                &[(3000, Ipv4Addr::new(10, 254, 0, 3))],
            )))
            .expect("replace listener with accepted Mesh address");

        assert_eq!(
            *started_addresses.lock().expect("factory start log"),
            [
                IpAddr::V4(Ipv4Addr::new(10, 254, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 254, 0, 9)),
            ]
        );
    }

    #[test]
    fn losing_mesh_identity_and_rejoining_on_a_new_address_restarts_the_proxy_listener() {
        let (controller, _, started_addresses) = controller_with_ports_and_starts(ListenerPorts {
            http: 10_080,
            https: 10_443,
            mesh_http: None,
            mesh_https: None,
        });
        controller
            .set_mesh_context(Some(context(&[(3000, Ipv4Addr::new(10, 254, 0, 3))])))
            .expect("apply initial accepted context");
        controller
            .call("proxy.publish", br#"{"port":3000}"#)
            .expect("publish authorized port");

        controller
            .set_mesh_context(None)
            .expect("remove missing Mesh identity");
        controller
            .set_mesh_context(Some(context_at(
                IpAddr::V4(Ipv4Addr::new(10, 254, 0, 9)),
                &[(3000, Ipv4Addr::new(10, 254, 0, 3))],
            )))
            .expect("apply new accepted context");

        assert_eq!(
            *started_addresses.lock().expect("factory start log"),
            [
                IpAddr::V4(Ipv4Addr::new(10, 254, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 254, 0, 9)),
            ]
        );
    }
}
