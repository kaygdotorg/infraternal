//! Turns authorized port publications into one supervised Traefik snapshot [#281, D303].

use crate::{
    config::{DnsChallenge, ListenerPorts, PublishedService, StaticConfig},
    custody::{DnsTokenCustody, FileDnsTokenCustody},
    download::{ComponentDownloader, CurlTransport},
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
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
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
    mesh: Option<AcceptedMeshContext>,
    exposures: BTreeMap<u16, Exposure>,
    supervisor: Option<Box<dyn RouteSupervisor>>,
    listener_ports: ListenerPorts,
}

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
    /// Create an idle supervisor for the accepted node context.
    ///
    /// # Errors
    /// Returns an error when the component, provider files, or private state cannot be prepared.
    fn start(&self, context: &AcceptedMeshContext) -> io::Result<Box<dyn RouteSupervisor>>;
}

/// Shares accepted Mesh identity with the action handler and its sibling observer.
#[derive(Clone)]
pub struct ProxyController {
    state: Arc<Mutex<ControllerState>>,
    factory: Option<Arc<dyn SupervisorFactory>>,
}

impl Default for ProxyController {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(ControllerState {
                enabled: true,
                mesh: None,
                exposures: BTreeMap::new(),
                supervisor: None,
                listener_ports: ListenerPorts {
                    http: 10_080,
                    https: 10_443,
                    mesh_http: None,
                    mesh_https: None,
                },
            })),
            factory: None,
        }
    }
}

impl ProxyController {
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
        publication_list(&state)
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
                format!(
                    "Stopped new connections to {}; existing connections may drain for up to 10 seconds.",
                    https_url(
                        &route.hostname,
                        state
                            .listener_ports
                            .https_for_publication(route.public)
                    )
                )
            },
        );
        serde_json::to_vec(&json!({
            "message": message,
            "data": {"port": port, "hostname": hostname, "public": exposure.spec.public}
        }))
        .map_err(|_| infraternal_plugin_api::PluginError::Rejected)
    }

    fn reconcile(&self, state: &mut ControllerState) -> io::Result<()> {
        let services = refresh_routes(state)?;
        if let Some(supervisor) = &state.supervisor {
            if let Some(ports) = supervisor.replace(services)? {
                state.listener_ports = ports;
            }
            return Ok(());
        }
        if services.is_empty() {
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
        let supervisor = factory.start(context)?;
        let listener_ports = supervisor.replace(services)?;
        if let Some(ports) = listener_ports {
            state.listener_ports = ports;
        }
        state.supervisor = Some(supervisor);
        Ok(())
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

impl SupervisorFactory for DownloadedTraefikFactory {
    fn start(&self, context: &AcceptedMeshContext) -> io::Result<Box<dyn RouteSupervisor>> {
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

        let proxy_state = self.state_dir.join("proxy");
        ensure_private_directory(&proxy_state)?;
        let dynamic_directory = proxy_state.join("dynamic");
        ensure_private_directory(&dynamic_directory)?;
        let acme_storage = proxy_state.join("acme.json");
        ensure_private_file(&acme_storage)?;
        let private_ping_port = loopback_port()?;
        let static_config = StaticConfig {
            mesh_address: context.mesh_address,
            ports: ListenerPorts {
                http: 10_080,
                https: 10_443,
                mesh_http: None,
                mesh_https: None,
            },
            public: false,
            private_ping_port,
            dynamic_directory: dynamic_directory.clone(),
            dns_challenge: DnsChallenge {
                provider: profile.provider.clone(),
                email: profile.email.clone(),
                storage_path: acme_storage,
                ca_server: None,
                resolvers: Vec::new(),
                disable_authoritative_ns_checks: false,
            },
        };
        let supervisor = TraefikSupervisor::start(
            SupervisorSettings {
                executable,
                static_config_path: proxy_state.join("traefik.toml"),
                dynamic_config_path: dynamic_directory.join(crate::config::DYNAMIC_CONFIG_FILENAME),
                static_config,
                provider_files,
                private_ping_address: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    private_ping_port,
                ),
                startup_timeout: PRIVATE_PING_TIMEOUT,
            },
            Arc::clone(&self.log),
        )?;
        Ok(Box::new(supervisor))
    }
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

fn ensure_private_directory(path: &Path) -> io::Result<()> {
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

fn ensure_private_file(path: &Path) -> io::Result<()> {
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
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o7777 != PRIVATE_FILE_MODE
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
    let process_running = state
        .supervisor
        .as_ref()
        .map_or(Ok(false), |supervisor| supervisor.is_running())
        .map_err(|_| infraternal_plugin_api::PluginError::Rejected)?;
    let services: Vec<_> = state
        .exposures
        .values()
        .filter_map(|exposure| {
            let route = exposure.last_route.as_ref()?;
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
    }

    struct FakeSupervisor {
        snapshots: Arc<Mutex<Vec<Vec<PublishedService>>>>,
        listener_ports: ListenerPorts,
    }

    impl SupervisorFactory for FakeFactory {
        fn start(&self, context: &AcceptedMeshContext) -> io::Result<Box<dyn RouteSupervisor>> {
            self.started_addresses
                .lock()
                .map_err(|_| io::Error::other("fixture start log is unavailable"))?
                .push(context.mesh_address);
            Ok(Box::new(FakeSupervisor {
                snapshots: Arc::clone(&self.snapshots),
                listener_ports: self.listener_ports,
            }))
        }
    }

    impl RouteSupervisor for FakeSupervisor {
        fn replace(&self, services: Vec<PublishedService>) -> io::Result<Option<ListenerPorts>> {
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
        });
        (
            ProxyController::with_factory(factory),
            snapshots,
            started_addresses,
        )
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
                && message.contains("10 seconds")
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
