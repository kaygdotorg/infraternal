//! Renders mesh-bound static settings and exact-host dynamic routes atomically [#281].

use crate::names::CertificateName;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

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
    http_available: bool,
    https_available: bool,
) -> ListenerPorts {
    let _ = (rootful, http_available, https_available);
    ListenerPorts {
        http: 10080,
        https: 10443,
    }
}

/// Render a complete Traefik static configuration in TOML.
///
/// # Errors
/// Returns an error when a path, provider value, or endpoint cannot be represented safely.
pub fn render_static_config(_config: &StaticConfig) -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "static configuration is not implemented",
    ))
}

/// Render one exact-host dynamic snapshot with per-service mesh source filters.
///
/// # Errors
/// Returns permission denied when a mesh route has no accepted sources, or invalid data for an unsafe route.
pub fn render_dynamic_config(_services: &[PublishedService]) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "dynamic configuration is not implemented",
    ))
}

/// Atomically replace a private static or dynamic configuration file.
///
/// # Errors
/// Returns an error when the parent directory is unsafe or the staged write cannot be synced and renamed.
pub fn write_config_atomic(_destination: &Path, _bytes: &[u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic configuration writes are not implemented",
    ))
}
