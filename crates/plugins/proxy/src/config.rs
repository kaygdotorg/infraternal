//! Renders mesh-bound static settings and exact-host dynamic routes atomically [#281].
//! Mesh routes use the same accepted peer addresses as mesh DNS; public listeners appear only
//! after an explicit public exposure. Certificate state remains node-local.

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
const MAX_RENDERED_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// Listener ports selected from node privilege and conventional-port availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerPorts {
    /// HTTP listener port.
    pub http: u16,
    /// HTTPS listener port.
    pub https: u16,
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
}

/// Inputs for rendering the static Traefik file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaticConfig {
    /// Node's mesh address used by mesh-only listeners.
    pub mesh_address: IpAddr,
    /// HTTP and HTTPS listener ports.
    pub ports: ListenerPorts,
    /// Whether any explicitly public exposure needs wildcard interface binding.
    pub public: bool,
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
    /// Wildcard or exact certificate name requested by the resolver.
    pub certificate: CertificateName,
}

/// Select conventional root ports only when both are available; all other cases use high ports.
#[must_use]
pub const fn select_listener_ports(
    rootful: bool,
    http_port_available: bool,
    https_port_available: bool,
) -> ListenerPorts {
    if rootful && http_port_available && https_port_available {
        ListenerPorts {
            http: 80,
            https: 443,
        }
    } else {
        ListenerPorts {
            http: 10080,
            https: 10443,
        }
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

/// Render a complete Traefik static configuration in TOML.
///
/// # Errors
/// Returns an error when a path, provider value, or endpoint cannot be represented safely.
pub fn render_static_config(config: &StaticConfig) -> io::Result<String> {
    validate_static_config(config)?;
    let (plain_address, tls_address) = if config.public {
        (
            SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                config.ports.http,
            )
            .to_string(),
            SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                config.ports.https,
            )
            .to_string(),
        )
    } else {
        (
            SocketAddr::new(config.mesh_address, config.ports.http).to_string(),
            SocketAddr::new(config.mesh_address, config.ports.https).to_string(),
        )
    };
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
    writeln!(
        rendered,
        "\n[api]\ndashboard = false\ninsecure = false\ndebug = false"
    )
    .map_err(io::Error::other)?;
    writeln!(
        rendered,
        "\n[entryPoints.http]\naddress = {}",
        toml_string(&plain_address)?
    )
    .map_err(io::Error::other)?;
    writeln!(
        rendered,
        "\n[entryPoints.https]\naddress = {}",
        toml_string(&tls_address)?
    )
    .map_err(io::Error::other)?;
    let health_address = toml_string(&format!("127.0.0.1:{}", config.private_ping_port))?;
    writeln!(
        rendered,
        "\n[entryPoints.health]\naddress = {health_address}"
    )
    .map_err(io::Error::other)?;
    writeln!(
        rendered,
        "\n[ping]\nentryPoint = \"health\"\nmanualRouting = false"
    )
    .map_err(io::Error::other)?;
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
    if rendered.len() > MAX_RENDERED_CONFIG_BYTES {
        return Err(invalid_data("static configuration exceeds its byte limit"));
    }
    Ok(rendered)
}

/// Render one exact-host dynamic snapshot with per-service mesh source filters.
///
/// # Errors
/// Returns permission denied when a mesh route has no accepted sources, or invalid data for an unsafe route.
pub fn render_dynamic_config(services: &[PublishedService]) -> io::Result<Vec<u8>> {
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
    if !service.backend.ip().is_loopback() || service.backend.port() == 0 {
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
        json!({"redirectScheme": {"scheme": "https", "permanent": true}}),
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
            "entryPoints": ["http"],
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
            "entryPoints": ["https"],
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
    if bytes.len() > MAX_RENDERED_CONFIG_BYTES {
        return Err(invalid_data("configuration exceeds its byte limit"));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| invalid_input("configuration path must have a parent directory"))?;
    validate_private_directory(parent)?;
    let name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid_input("configuration path must name a file"))?;
    match fs::symlink_metadata(destination) {
        Ok(metadata) => validate_private_file(&metadata)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let name = name
        .to_str()
        .ok_or_else(|| invalid_input("configuration filename must be UTF-8"))?;
    let temporary_path = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut temporary = TemporaryConfigFile::create(&temporary_path)?;
    temporary.file.write_all(bytes)?;
    temporary.file.sync_all()?;
    validate_private_file(&temporary.file.metadata()?)?;
    fs::rename(&temporary.path, destination)?;
    temporary.disarm();
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_static_config(config: &StaticConfig) -> io::Result<()> {
    if config.mesh_address.is_unspecified()
        || config.mesh_address.is_loopback()
        || config.ports.http == 0
        || config.ports.https == 0
        || config.ports.http == config.ports.https
        || config.private_ping_port == 0
        || config.private_ping_port == config.ports.http
        || config.private_ping_port == config.ports.https
        || !config.dynamic_directory.is_absolute()
        || !config.dns_challenge.storage_path.is_absolute()
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

fn validate_private_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o7777 != PRIVATE_DIRECTORY_MODE
    {
        return Err(permission_error(
            "configuration directory has unsafe owner or mode",
        ));
    }
    Ok(())
}

fn validate_private_file(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o7777 != PRIVATE_FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(permission_error(
            "configuration file has unsafe owner, mode, or links",
        ));
    }
    Ok(())
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
    fn create(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(PRIVATE_FILE_MODE)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
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
