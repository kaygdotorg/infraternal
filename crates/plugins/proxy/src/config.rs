//! Renders stable public and mesh listeners plus exact-host dynamic routes atomically [#281].
//! Mesh routes use the same accepted peer addresses as mesh DNS. Rootful public listeners keep a
//! stable wildcard bind behind a firewall gate in the one mixed process. Without root there is no
//! gate, so the Mesh process has no public entrypoints at all, and public routes get their own
//! process whose wildcard listener exists only while a public route is applied (D330).
//! Audience changes only replace dynamic routes and preserve active connections. Certificate state
//! remains node-local.
//! A nonce-gated rawdata route on the loopback-only health entrypoint lets the supervisor acknowledge
//! a dynamic snapshot only after Traefik has loaded that generation.

use crate::identity;
use crate::names::CertificateName;
use serde_json::{Map, json};
use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr, TcpListener},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PROXY_CONFIG_MODE: u32 = 0o640;
const MAX_RENDERED_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// Filename recognized by Traefik's file provider for dynamic snapshots.
pub const DYNAMIC_CONFIG_FILENAME: &str = "services.yaml";

/// Listener ports selected from node privilege and conventional-port availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerPorts {
    /// HTTP port for the stable wildcard public listener.
    pub http: u16,
    /// HTTPS port for the stable wildcard public listener.
    pub https: u16,
    /// HTTP port for the stable mesh-address listener.
    pub mesh_http: Option<u16>,
    /// HTTPS port for the stable mesh-address listener.
    pub mesh_https: Option<u16>,
}

impl ListenerPorts {
    /// Select the HTTPS port for a route's audience.
    #[must_use]
    pub const fn https_for_publication(self, public: bool) -> u16 {
        if public {
            self.https
        } else {
            match self.mesh_https {
                Some(port) => port,
                None => self.https,
            }
        }
    }
}

/// DNS-01 resolver values safe to render into the static configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsChallenge {
    /// Provider identifier understood by the selected Traefik release.
    pub provider: String,
    /// ACME account contact address.
    pub email: String,
    /// Node-local ACME state file path.
    pub storage_path: PathBuf,
    /// Optional staging directory endpoint for tests.
    pub ca_server: Option<String>,
    /// DNS resolvers used for challenge propagation checks; empty uses the system resolvers.
    pub resolvers: Vec<SocketAddr>,
    /// Skip authoritative-name-server checks for synthetic zones while keeping recursive checks.
    pub disable_authoritative_ns_checks: bool,
}

/// Which listeners one Traefik process owns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryPoints {
    /// Rootful: the public pair (behind the firewall gate) and the Mesh pair in one process.
    Mixed,
    /// Rootless Mesh process: only the Mesh pair on the Mesh address.
    MeshOnly,
    /// Rootless public process: only the public pair on every address.
    PublicOnly,
}

impl EntryPoints {
    const fn public(self) -> bool {
        matches!(self, Self::Mixed | Self::PublicOnly)
    }
    const fn mesh(self) -> bool {
        matches!(self, Self::Mixed | Self::MeshOnly)
    }
}

/// Inputs for rendering the static Traefik file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticConfig {
    /// Listeners this process owns.
    pub entry_points: EntryPoints,
    /// Node's mesh address used by mesh listeners.
    pub mesh_address: IpAddr,
    /// Address for the public entrypoints; the wildcard, behind the gate when rootful (D330).
    pub public_bind_address: IpAddr,
    /// Public and mesh HTTP/HTTPS listener ports.
    pub ports: ListenerPorts,
    /// Loopback-only private ping port.
    pub private_ping_port: u16,
    /// Directory watched by the file provider.
    pub dynamic_directory: PathBuf,
    /// DNS-01 resolver settings.
    pub dns_challenge: DnsChallenge,
}

/// One desired exposure rendered as a single exact-host router.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedService {
    /// Stable configuration key, restricted to a DNS label.
    pub id: String,
    /// Exact host accepted by the route.
    pub hostname: String,
    /// Local backend endpoint.
    pub backend: SocketAddr,
    /// Peer addresses permitted by the same service grant as mesh DNS.
    pub allowed_sources: Vec<IpAddr>,
    /// Whether this exposure also accepts traffic from the public internet.
    pub public: bool,
    /// HTTPS listener port used by the redirect from this route's HTTP entry point.
    pub https_port: u16,
    /// Wildcard or exact certificate name requested by the resolver.
    pub certificate: CertificateName,
}

/// Select conventional root ports only when both are available; all other cases use high ports.
#[must_use]
pub const fn select_listener_ports(
    rootful: bool,
    plain_http_port_available: bool,
    tls_port_available: bool,
) -> ListenerPorts {
    let pair = if rootful && plain_http_port_available && tls_port_available {
        infraternal_mesh::proxy_ports::CONVENTIONAL_LISTENER_PAIR
    } else {
        infraternal_mesh::proxy_ports::UNPRIVILEGED_LISTENER_PAIR
    };
    ListenerPorts {
        http: pair.http,
        https: pair.https,
        mesh_http: None,
        mesh_https: None,
    }
}

/// Probe only the address Traefik will bind, then use conventional ports when both are free.
#[must_use]
pub fn detect_listener_ports(rootful: bool, mesh_address: IpAddr, public: bool) -> ListenerPorts {
    if !rootful {
        return select_listener_ports(false, false, false);
    }
    let bind_address = if public {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        mesh_address
    };
    let available = |port| TcpListener::bind(SocketAddr::new(bind_address, port)).is_ok();
    select_listener_ports(rootful, available(80), available(443))
}

/// Select stable public and mesh-address listener pairs for the lifetime of one proxy process.
///
/// The mesh pair stays configured even when no mesh route is active, so adding or removing routes
/// changes only the watched dynamic snapshot and never requires an entrypoint restart. Without
/// root, `rootless_public` is the separate public process's pair, which the Mesh pair avoids.
///
/// # Errors
/// Returns an address-in-use error when no bounded pair of high ports is available.
pub fn detect_mixed_listener_ports(
    rootful: bool,
    mesh_address: IpAddr,
    rootless_public: Option<infraternal_mesh::proxy_ports::ListenerPortPair>,
) -> io::Result<ListenerPorts> {
    let mut ports = detect_listener_ports(rootful, mesh_address, true);
    if let (false, Some(pair)) = (rootful, rootless_public) {
        ports.http = pair.http;
        ports.https = pair.https;
    }
    let available = |port| TcpListener::bind(SocketAddr::new(mesh_address, port)).is_ok();
    for pair in infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS
        .iter()
        .copied()
    {
        let http = pair.http;
        let https = pair.https;
        if [ports.http, ports.https].contains(&http)
            || [ports.http, ports.https].contains(&https)
            || !available(http)
            || !available(https)
        {
            continue;
        }
        ports.mesh_http = Some(http);
        ports.mesh_https = Some(https);
        return Ok(ports);
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "no separate high ports are available for mesh-only proxy routes",
    ))
}

/// Probe the first free public pair for a rootless public process, avoiding the Mesh pair.
///
/// Traefik's wildcard listener is one dual-stack socket, so each port must be free on both
/// `0.0.0.0` and `[::]`. A host without IPv6 only needs the IPv4 wildcard. The probe can still
/// lose a race to another process; Traefik then fails to bind and the start reports it.
///
/// # Errors
/// Returns an address-in-use error when every candidate pair is taken.
pub fn detect_public_listener_pair(
    mesh: Option<infraternal_mesh::proxy_ports::ListenerPortPair>,
) -> io::Result<infraternal_mesh::proxy_ports::ListenerPortPair> {
    let free = |port: u16| {
        let ipv4 = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).is_ok();
        let ipv6 = match TcpListener::bind((std::net::Ipv6Addr::UNSPECIFIED, port)) {
            Ok(_) => true,
            Err(error) => {
                error.raw_os_error() == Some(nix::libc::EAFNOSUPPORT)
                    || error.raw_os_error() == Some(nix::libc::EADDRNOTAVAIL)
            }
        };
        ipv4 && ipv6
    };
    let taken = mesh.map(|pair| [pair.http, pair.https]).unwrap_or_default();
    infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS
        .iter()
        .copied()
        .find(|pair| {
            !taken.contains(&pair.http)
                && !taken.contains(&pair.https)
                && free(pair.http)
                && free(pair.https)
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrInUse,
                "no free port pair is available for public proxy routes",
            )
        })
}

/// Render a complete Traefik static configuration in TOML.
///
/// # Errors
/// Returns an error when a path, provider value, or endpoint cannot be represented safely.
pub fn render_static_config(config: &StaticConfig) -> io::Result<String> {
    validate_static_config(config)?;
    let dynamic_directory = config
        .dynamic_directory
        .to_str()
        .ok_or_else(|| invalid_input("dynamic configuration directory must be UTF-8"))?;
    let storage_path = config
        .dns_challenge
        .storage_path
        .to_str()
        .ok_or_else(|| invalid_input("ACME storage path must be UTF-8"))?;
    let mut rendered = String::with_capacity(1024);
    writeln!(
        rendered,
        "[global]\ncheckNewVersion = false\nsendAnonymousUsage = false"
    )
    .map_err(io::Error::other)?;
    render_entry_points(config, &mut rendered)?;
    writeln!(
        rendered,
        "\n[ping]\nentryPoint = \"health\"\nmanualRouting = false"
    )
    .map_err(io::Error::other)?;
    writeln!(rendered, "\n[api]\ndashboard = false\ninsecure = false").map_err(io::Error::other)?;
    writeln!(
        rendered,
        "\n[providers.file]\ndirectory = {}\nwatch = true",
        toml_string(dynamic_directory)?
    )
    .map_err(io::Error::other)?;
    writeln!(
        rendered,
        "\n[certificatesResolvers.dns.acme]\nemail = {}\nstorage = {}",
        toml_string(&config.dns_challenge.email)?,
        toml_string(storage_path)?
    )
    .map_err(io::Error::other)?;
    if let Some(ca_server) = &config.dns_challenge.ca_server {
        writeln!(rendered, "caServer = {}", toml_string(ca_server)?).map_err(io::Error::other)?;
    }
    writeln!(
        rendered,
        "\n[certificatesResolvers.dns.acme.dnsChallenge]\nprovider = {}",
        toml_string(&config.dns_challenge.provider)?
    )
    .map_err(io::Error::other)?;
    render_dns_resolvers(&config.dns_challenge, &mut rendered)?;
    if config.dns_challenge.disable_authoritative_ns_checks {
        writeln!(
            rendered,
            "\n[certificatesResolvers.dns.acme.dnsChallenge.propagation]\ndisableANSChecks = true"
        )
        .map_err(io::Error::other)?;
    }
    if rendered.len() > MAX_RENDERED_CONFIG_BYTES {
        return Err(invalid_data("static configuration exceeds its byte limit"));
    }
    Ok(rendered)
}

fn render_entry_points(config: &StaticConfig, rendered: &mut String) -> io::Result<()> {
    if config.entry_points.public() {
        let plain_address =
            SocketAddr::new(config.public_bind_address, config.ports.http).to_string();
        let tls_address =
            SocketAddr::new(config.public_bind_address, config.ports.https).to_string();
        writeln!(
            rendered,
            "[entryPoints.http]\naddress = {}",
            toml_string(&plain_address)?
        )
        .map_err(io::Error::other)?;
        writeln!(
            rendered,
            "\n[entryPoints.https]\naddress = {}\n",
            toml_string(&tls_address)?
        )
        .map_err(io::Error::other)?;
    }
    if config.entry_points.mesh() {
        render_mesh_entry_points(config, rendered)?;
    }
    let health_address = toml_string(&format!("127.0.0.1:{}", config.private_ping_port))?;
    writeln!(rendered, "[entryPoints.health]\naddress = {health_address}")
        .map_err(io::Error::other)?;
    Ok(())
}

fn render_mesh_entry_points(config: &StaticConfig, rendered: &mut String) -> io::Result<()> {
    let (Some(mesh_http), Some(mesh_https)) = (config.ports.mesh_http, config.ports.mesh_https)
    else {
        return Err(invalid_input(
            "stable proxy config requires a mesh listener pair",
        ));
    };
    writeln!(
        rendered,
        "[entryPoints.mesh-http]\naddress = {}",
        toml_string(&SocketAddr::new(config.mesh_address, mesh_http).to_string())?
    )
    .map_err(io::Error::other)?;
    writeln!(
        rendered,
        "\n[entryPoints.mesh-https]\naddress = {}\n",
        toml_string(&SocketAddr::new(config.mesh_address, mesh_https).to_string())?
    )
    .map_err(io::Error::other)?;
    Ok(())
}

fn render_dns_resolvers(config: &DnsChallenge, rendered: &mut String) -> io::Result<()> {
    if config.resolvers.is_empty() {
        return Ok(());
    }
    let resolvers = config
        .resolvers
        .iter()
        .map(|resolver| toml_string(&resolver.to_string()))
        .collect::<io::Result<Vec<_>>>()?
        .join(", ");
    writeln!(rendered, "resolvers = [{resolvers}]").map_err(io::Error::other)
}

/// Render one exact-host dynamic snapshot with per-service mesh source filters.
///
/// The compact JSON document is valid YAML and callers write it with
/// [`DYNAMIC_CONFIG_FILENAME`], because the file provider skips `.json` files.
///
/// # Errors
/// Returns permission denied when a mesh route has no accepted sources, or invalid data for an unsafe route.
pub fn render_dynamic_config(services: &[PublishedService]) -> io::Result<Vec<u8>> {
    let generation = uuid::Uuid::new_v4().to_string();
    render_dynamic_config_with_generation(services, &generation)
}

/// Render a complete snapshot with a private probe that is unique to this generation.
pub(crate) fn render_dynamic_config_with_generation(
    services: &[PublishedService],
    generation: &str,
) -> io::Result<Vec<u8>> {
    let generation = uuid::Uuid::parse_str(generation)
        .map_err(|_| invalid_input("dynamic config generation must be a UUID"))?
        .to_string();
    if services.len() > 4096 {
        return Err(invalid_data("published service count exceeds its limit"));
    }
    let mut routers = Map::new();
    let mut middlewares = Map::new();
    let mut proxy_services = Map::new();
    let mut seen_ids = std::collections::BTreeSet::new();
    let mut seen_hosts = std::collections::BTreeSet::new();
    for service in services {
        validate_published_service(service, &mut seen_ids, &mut seen_hosts)?;
        render_published_service(service, &mut routers, &mut middlewares, &mut proxy_services)?;
    }
    // The nonce makes a 200 response an exact generation acknowledgment. This route can only use
    // the private loopback health entrypoint and exposes one API path with the current nonce.
    routers.insert(
        "infraternal-config-generation".to_owned(),
        json!({
            "rule": format!(
                "Method(`GET`) && Path(`/api/rawdata`) && Header(`X-Infraternal-Config-Generation`, `{generation}`)"
            ),
            "entryPoints": ["health"],
            "service": "api@internal",
        }),
    );
    let bytes = serde_json::to_vec(&json!({
        "http": {
            "routers": routers,
            "middlewares": middlewares,
            "services": proxy_services,
        }
    }))
    .map_err(io::Error::other)?;
    if bytes.len() > MAX_RENDERED_CONFIG_BYTES {
        return Err(invalid_data("dynamic configuration exceeds its byte limit"));
    }
    Ok(bytes)
}

fn validate_published_service<'a>(
    service: &'a PublishedService,
    seen_ids: &mut std::collections::BTreeSet<&'a str>,
    seen_hosts: &mut std::collections::BTreeSet<&'a str>,
) -> io::Result<()> {
    validate_label(&service.id)?;
    validate_hostname(&service.hostname)?;
    validate_certificate_name(&service.certificate, &service.hostname)?;
    if !service.backend.ip().is_loopback() || service.backend.port() == 0 || service.https_port == 0
    {
        return Err(invalid_input(
            "published backends must use a loopback TCP address",
        ));
    }
    if !seen_ids.insert(service.id.as_str()) || !seen_hosts.insert(service.hostname.as_str()) {
        return Err(invalid_data(
            "published service identifiers and names must be unique",
        ));
    }
    Ok(())
}

fn render_published_service(
    service: &PublishedService,
    routers: &mut Map<String, serde_json::Value>,
    middlewares: &mut Map<String, serde_json::Value>,
    proxy_services: &mut Map<String, serde_json::Value>,
) -> io::Result<()> {
    let access_middleware = format!("{}-mesh-access", service.id);
    let redirect_middleware = format!("{}-https-redirect", service.id);
    let (plain_entry_point, tls_entry_point) = if service.public {
        ("http", "https")
    } else {
        ("mesh-http", "mesh-https")
    };
    if !service.public {
        if service.allowed_sources.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "mesh exposure has no accepted peer grant",
            ));
        }
        let mut sources = service.allowed_sources.clone();
        sources.sort_unstable();
        sources.dedup();
        let ranges: Vec<_> = sources
            .into_iter()
            .map(|address| {
                if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
                    return Err(invalid_input("mesh source address is not a peer address"));
                }
                Ok(format!(
                    "{address}/{}",
                    if address.is_ipv4() { 32 } else { 128 }
                ))
            })
            .collect::<io::Result<_>>()?;
        middlewares.insert(
            access_middleware.clone(),
            json!({"ipAllowList": {"sourceRange": ranges}}),
        );
    }
    middlewares.insert(
        redirect_middleware.clone(),
        json!({"redirectScheme": {
            "scheme": "https",
            "port": service.https_port.to_string(),
            "permanent": true
        }}),
    );
    let rule = format!("Host(`{}`)", service.hostname);
    let mut plain_middlewares = vec![redirect_middleware];
    let mut tls_middlewares = Vec::new();
    if !service.public {
        plain_middlewares.insert(0, access_middleware.clone());
        tls_middlewares.push(access_middleware);
    }
    routers.insert(
        format!("http.{}", service.id),
        json!({
            "rule": rule,
            "entryPoints": [plain_entry_point],
            "middlewares": plain_middlewares,
            "service": service.id,
        }),
    );
    let certificate_name = match &service.certificate {
        CertificateName::Wildcard(name) | CertificateName::Exact(name) => name,
    };
    routers.insert(
        service.id.clone(),
        json!({
            "rule": rule,
            "entryPoints": [tls_entry_point],
            "middlewares": tls_middlewares,
            "service": service.id,
            "tls": {
                "certResolver": "dns",
                "domains": [{"main": certificate_name}],
            },
        }),
    );
    proxy_services.insert(
        service.id.clone(),
        json!({"loadBalancer": {"servers": [{"url": format!("http://{}", service.backend)}]}}),
    );
    Ok(())
}

/// Atomically replace a private static or dynamic configuration file.
///
/// # Errors
/// Returns an error when the parent directory is unsafe or the staged write cannot be synced and renamed.
pub fn write_config_atomic(destination: &Path, bytes: &[u8]) -> io::Result<()> {
    write_config_atomic_with_owner(
        destination,
        bytes,
        nix::unistd::Uid::effective().as_raw(),
        nix::unistd::Gid::effective().as_raw(),
        PRIVATE_FILE_MODE,
        Some(PRIVATE_DIRECTORY_MODE),
    )
}

/// Atomically publish a config readable by the isolated Traefik group in rootful mode.
///
/// The state directory stays owned by the infraternal agent. A limited group
/// permission lets the child read known config files without listing or changing them.
/// # Errors
/// Returns an ownership or staged-write error without replacing the current generation.
pub(crate) fn write_proxy_config_atomic(destination: &Path, bytes: &[u8]) -> io::Result<()> {
    if identity::rootful() {
        write_config_atomic_with_owner(
            destination,
            bytes,
            nix::unistd::Uid::effective().as_raw(),
            identity::child_group()?,
            PROXY_CONFIG_MODE,
            None,
        )
    } else {
        write_config_atomic(destination, bytes)
    }
}

fn write_config_atomic_with_owner(
    destination: &Path,
    bytes: &[u8],
    owner_user: u32,
    owner_group: u32,
    file_mode: u32,
    private_directory_mode: Option<u32>,
) -> io::Result<()> {
    if bytes.len() > MAX_RENDERED_CONFIG_BYTES {
        return Err(invalid_data("configuration exceeds its byte limit"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid_input("configuration path must have a parent directory"))?;
    if let Some(mode) = private_directory_mode {
        validate_proxy_directory(
            parent,
            nix::unistd::Uid::effective().as_raw(),
            nix::unistd::Gid::effective().as_raw(),
            mode,
        )?;
    } else {
        validate_proxy_directory(parent, owner_user, owner_group, 0o750)?;
    }
    let name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid_input("configuration path must name a file"))?;
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if !valid_proxy_config_file(&metadata, owner_user, owner_group, file_mode) {
                return Err(permission_error(
                    "configuration file has unsafe owner, mode, or links",
                ));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let name = name
        .to_str()
        .ok_or_else(|| invalid_input("configuration filename must be UTF-8"))?;
    let temporary_path = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut temporary = TemporaryConfigFile::create(&temporary_path, file_mode, owner_group)?;
    temporary.file.write_all(bytes)?;
    temporary.file.sync_all()?;
    validate_proxy_file(
        &temporary.file.metadata()?,
        owner_user,
        owner_group,
        file_mode,
    )?;
    fs::rename(&temporary.path, destination)?;
    temporary.disarm();
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_static_config(config: &StaticConfig) -> io::Result<()> {
    let mesh_listener_valid = !config.entry_points.mesh()
        || match (config.ports.mesh_http, config.ports.mesh_https) {
            (Some(http), Some(https)) => {
                http != 0
                    && https != 0
                    && http != https
                    && ![config.ports.http, config.ports.https].contains(&http)
                    && ![config.ports.http, config.ports.https].contains(&https)
                    && config.private_ping_port != http
                    && config.private_ping_port != https
            }
            (None | Some(_), None) | (None, Some(_)) => false,
        };
    if config.mesh_address.is_unspecified()
        || config.mesh_address.is_loopback()
        || config.ports.http == 0
        || config.ports.https == 0
        || config.ports.http == config.ports.https
        || config.private_ping_port == 0
        || config.private_ping_port == config.ports.http
        || config.private_ping_port == config.ports.https
        || !mesh_listener_valid
        || config.dns_challenge.resolvers.len() > 16
        || config
            .dns_challenge
            .resolvers
            .iter()
            .any(|resolver| resolver.port() == 0)
        || !safe_config_path(&config.dynamic_directory)
        || !safe_config_path(&config.dns_challenge.storage_path)
        || !valid_provider(&config.dns_challenge.provider)
        || config.dns_challenge.email.trim().is_empty()
        || config
            .dns_challenge
            .email
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        return Err(invalid_input(
            "static Traefik configuration is outside policy",
        ));
    }
    if let Some(ca_server) = &config.dns_challenge.ca_server {
        let url =
            url::Url::parse(ca_server).map_err(|_| invalid_input("ACME server URL is invalid"))?;
        if url.scheme() != "https" || url.host_str().is_none() {
            return Err(invalid_input("ACME server must use HTTPS"));
        }
    }
    Ok(())
}

fn valid_provider(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 63
        && provider
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && provider.as_bytes()[0].is_ascii_lowercase()
        && provider.as_bytes()[provider.len() - 1].is_ascii_alphanumeric()
}

fn validate_certificate_name(certificate: &CertificateName, hostname: &str) -> io::Result<()> {
    match certificate {
        CertificateName::Wildcard(name) => {
            let Some(suffix) = name.strip_prefix("*.") else {
                return Err(invalid_input(
                    "wildcard certificate must have one leading wildcard",
                ));
            };
            validate_hostname(suffix)?;
            if !hostname.ends_with(&format!(".{suffix}")) {
                return Err(invalid_input(
                    "wildcard certificate does not cover the route host",
                ));
            }
        }
        CertificateName::Exact(name) => {
            validate_hostname(name)?;
            if name != hostname {
                return Err(invalid_input(
                    "exact certificate name must match the route host",
                ));
            }
        }
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> io::Result<()> {
    if hostname.len() > 253 || hostname.is_empty() {
        return Err(invalid_input("published hostname is outside DNS limits"));
    }
    for label in hostname.split('.') {
        validate_label(label)?;
    }
    Ok(())
}

fn validate_label(label: &str) -> io::Result<()> {
    let bytes = label.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 63
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes[bytes.len() - 1].is_ascii_lowercase() && !bytes[bytes.len() - 1].is_ascii_digit()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(invalid_input(
            "published service identifier is not a DNS label",
        ));
    }
    Ok(())
}

fn toml_string(value: &str) -> io::Result<String> {
    serde_json::to_string(value).map_err(io::Error::other)
}

fn validate_proxy_directory(
    path: &Path,
    owner_user: u32,
    owner_group: u32,
    required_mode: u32,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user
        || metadata.gid() != owner_group
        || metadata.mode() & 0o7777 != required_mode
    {
        return Err(permission_error(
            "configuration directory has unsafe owner or mode",
        ));
    }
    Ok(())
}

fn validate_proxy_file(
    metadata: &fs::Metadata,
    owner_user: u32,
    owner_group: u32,
    required_mode: u32,
) -> io::Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user
        || metadata.gid() != owner_group
        || metadata.mode() & 0o7777 != required_mode
        || metadata.nlink() != 1
    {
        return Err(permission_error(
            "configuration file has unsafe owner, mode, or links",
        ));
    }
    Ok(())
}

fn valid_proxy_config_file(
    metadata: &fs::Metadata,
    owner_user: u32,
    owner_group: u32,
    required_mode: u32,
) -> bool {
    let safe_file = metadata.file_type().is_file() && metadata.nlink() == 1;
    if !safe_file {
        return false;
    }
    let mode = metadata.mode() & 0o7777;
    (metadata.uid() == owner_user && metadata.gid() == owner_group && mode == required_mode)
        || (identity::rootful()
            && required_mode == PROXY_CONFIG_MODE
            && metadata.uid() == nix::unistd::Uid::effective().as_raw()
            && metadata.gid() == nix::unistd::Gid::effective().as_raw()
            && mode == PRIVATE_FILE_MODE)
}

fn safe_config_path(path: &Path) -> bool {
    path.is_absolute()
        || (!path.as_os_str().is_empty()
            && path
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))))
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

struct TemporaryConfigFile {
    path: PathBuf,
    file: File,
    armed: bool,
}

impl TemporaryConfigFile {
    fn create(path: &Path, mode: u32, group: u32) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?;
        if nix::unistd::Uid::effective().is_root()
            && group != nix::unistd::Gid::effective().as_raw()
        {
            nix::unistd::fchown(&file, None, Some(nix::unistd::Gid::from_raw(group)))?;
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        Ok(Self {
            path: path.to_owned(),
            file,
            armed: true,
        })
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryConfigFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}
