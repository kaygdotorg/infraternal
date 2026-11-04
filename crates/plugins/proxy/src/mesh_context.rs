//! Carries only identity and inbound source grants from the accepted Mesh snapshot [#266, #281].

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
};

/// Naming and source policy copied from one fully accepted Mesh configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedMeshContext {
    /// Stable machine label used by per-machine wildcard names.
    pub machine_name: String,
    /// Server public-host-derived DNS suffix carried by Mesh.
    pub dns_suffix: String,
    /// Local Mesh address used by the proxy listener.
    pub mesh_address: IpAddr,
    all_tcp_sources: BTreeSet<IpAddr>,
    tcp_sources_by_port: BTreeMap<u16, BTreeSet<IpAddr>>,
}

impl AcceptedMeshContext {
    /// Validate an accepted node identity and bind its inbound TCP policy to source addresses.
    ///
    /// # Errors
    /// Returns invalid input when the DNS labels or any grant port is outside policy.
    pub fn new(
        machine_name: String,
        dns_suffix: String,
        mesh_address: IpAddr,
        all_tcp_sources: impl IntoIterator<Item = IpAddr>,
        tcp_sources_by_port: impl IntoIterator<Item = (u16, IpAddr)>,
    ) -> io::Result<Self> {
        crate::names::exposure_names(
            crate::names::NameShape::FlatService,
            &machine_name,
            "port-1",
            &dns_suffix,
        )?;
        let all_tcp_sources = all_tcp_sources.into_iter().collect();
        let mut sources = BTreeMap::<u16, BTreeSet<IpAddr>>::new();
        for (port, address) in tcp_sources_by_port {
            if port == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Mesh grant has an invalid TCP port",
                ));
            }
            sources.entry(port).or_default().insert(address);
        }
        Ok(Self {
            machine_name,
            dns_suffix,
            mesh_address,
            all_tcp_sources,
            tcp_sources_by_port: sources,
        })
    }

    /// List the accepted Mesh peers allowed to reach one local TCP service.
    #[must_use]
    pub fn allowed_sources(&self, port: u16) -> Vec<IpAddr> {
        self.all_tcp_sources
            .iter()
            .chain(self.tcp_sources_by_port.get(&port).into_iter().flatten())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}
