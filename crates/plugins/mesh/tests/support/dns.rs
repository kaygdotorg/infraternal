//! Gives each DNS test its own sockets without releasing a selected port before use.

use infraternal_plugin_mesh::{dataplane::Config, dns::Resolver};
use std::net::{SocketAddr, TcpListener, UdpSocket};

/// Owns a running resolver and the independently assigned UDP and TCP destinations.
pub struct TestResolver {
    /// Keeps both workers and their sockets alive until the fixture is dropped.
    _resolver: Resolver,
    /// Destination read from the UDP socket while that socket remains bound.
    pub udp_address: SocketAddr,
    /// Destination read from the TCP listener while that listener remains bound.
    pub tcp_address: SocketAddr,
}

impl TestResolver {
    /// Binds both protocols to port zero and transfers the held sockets to the resolver.
    pub fn bind(config: &Config) -> std::io::Result<Self> {
        let socket = UdpSocket::bind((config.addresses.ipv4, 0))?;
        let listener = TcpListener::bind((config.addresses.ipv4, 0))?;
        let udp_address = socket.local_addr()?;
        let tcp_address = listener.local_addr()?;
        let resolver = Resolver::from_sockets(config, socket, listener)?;
        Ok(Self {
            _resolver: resolver,
            udp_address,
            tcp_address,
        })
    }
}
