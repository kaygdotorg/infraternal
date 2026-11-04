//! Builds the static compiled plugin registry shared by embedded and remote infraternal agent runners [D198].

use infraternal_plugin_api::{PluginDescriptor, PluginError, PluginRegistry};

/// One node registry survives authenticated transport replacement; owned
/// asynchronous operations never hold this lock while waiting on native I/O.
pub type SharedRegistry = std::sync::Arc<std::sync::Mutex<PluginRegistry>>;

const DESCRIPTORS: &[&PluginDescriptor] = &[
    #[cfg(feature = "plugin-host-facts")]
    &infraternal_plugin_host_facts::DESCRIPTOR,
    #[cfg(feature = "proxy")]
    &infraternal_plugin_proxy::agent::DESCRIPTOR,
    #[cfg(feature = "remote")]
    &infraternal_plugin_remote::DESCRIPTOR,
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    &infraternal_plugin_mesh::node_actions::DESCRIPTOR,
    #[cfg(all(feature = "desktop", target_os = "macos"))]
    &infraternal_plugin_desktop::source_manifest::DESCRIPTOR,
];
#[cfg(all(feature = "remote", target_os = "linux"))]
pub(crate) type Installation = infraternal_plugin_remote::uninstall::Context;
#[cfg(not(all(feature = "remote", target_os = "linux")))]
pub(crate) type Installation = ();

/// Host role bound to one infraternal agent process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    /// The server's own host.
    Embedded,
    /// A separately managed host.
    Remote,
}

/// Descriptors compiled into this infraternal agent binary, for server-side authorization.
#[must_use]
pub const fn descriptors() -> &'static [&'static PluginDescriptor] {
    DESCRIPTORS
}

/// Creates the enabled-by-default registry for an infraternal agent execution context.
/// # Errors
/// Returns an error if the compiled plugin descriptors conflict with the plugin API.
pub fn registry(mode: ExecutionMode) -> Result<PluginRegistry, PluginError> {
    registry_at(mode, None, None)
}

// Even an empty build keeps the same fallible factory contract as builds with
// registered plugins; feature selection must not change its caller's API.
#[cfg_attr(
    not(any(
        feature = "plugin-host-facts",
        feature = "proxy",
        feature = "remote",
        all(feature = "mesh", target_os = "linux")
    )),
    allow(
        clippy::unnecessary_wraps,
        reason = "Keep the fallible registry API identical when every optional component is compiled out."
    )
)]
pub(crate) fn registry_at(
    mode: ExecutionMode,
    state: Option<&std::path::Path>,
    installation: Option<&Installation>,
) -> Result<PluginRegistry, PluginError> {
    #[cfg(any(
        feature = "plugin-host-facts",
        feature = "proxy",
        feature = "remote",
        all(feature = "mesh", target_os = "linux"),
        all(feature = "desktop", target_os = "macos")
    ))]
    let mut registry = PluginRegistry::default();
    #[cfg(not(any(
        feature = "plugin-host-facts",
        feature = "proxy",
        feature = "remote",
        all(feature = "mesh", target_os = "linux"),
        all(feature = "desktop", target_os = "macos")
    )))]
    let registry = PluginRegistry::default();
    #[cfg(feature = "plugin-host-facts")]
    {
        use infraternal_plugin_host_facts::AgentMode;
        let facts_mode = match mode {
            ExecutionMode::Embedded => AgentMode::Embedded,
            ExecutionMode::Remote => AgentMode::Remote,
        };
        registry.register(Box::new(
            infraternal_plugin_host_facts::HostFactsPlugin::new(facts_mode),
        ))?;
    }
    #[cfg(not(feature = "plugin-host-facts"))]
    let _ = mode;
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    let mesh_plugin = state.map_or_else(
        infraternal_plugin_mesh::node_actions::MeshNodePlugin::default,
        infraternal_plugin_mesh::node_actions::MeshNodePlugin::new,
    );
    #[cfg(feature = "proxy")]
    let proxy_plugin = proxy_plugin_at(state)?;
    #[cfg(all(feature = "proxy", feature = "mesh", target_os = "linux"))]
    let mesh_plugin = connect_proxy_and_mesh(&proxy_plugin, mesh_plugin)?;
    #[cfg(feature = "proxy")]
    registry.register(Box::new(proxy_plugin))?;
    #[cfg(all(feature = "remote", target_os = "linux"))]
    if mode == ExecutionMode::Remote
        && let Some(context) = installation
    {
        let home = std::env::var_os("HOME").map_or_else(|| "/".into(), std::path::PathBuf::from);
        if let Ok(plugin) = infraternal_plugin_remote::uninstall::UninstallPlugin::new(
            context.clone(),
            home,
            nix::unistd::Uid::effective().as_raw(),
            KERNEL,
        ) {
            registry.register(Box::new(plugin))?;
        }
    }
    #[cfg(all(feature = "desktop", target_os = "macos"))]
    {
        let home = std::env::var_os("HOME").ok_or(PluginError::Rejected)?;
        let runtime = std::path::PathBuf::from(home).join(".cache/infraternal/desktop-source");
        let executable = std::env::current_exe().map_err(|_| PluginError::Rejected)?;
        let helper = executable
            .parent()
            .ok_or(PluginError::Rejected)?
            .join("infraternal-desktop-helper");
        // Construction retains trusted metadata only; desktop.up is the explicit
        // per-node component switch, and known Attach is the sole capture opener.
        registry.register(Box::new(
            infraternal_plugin_desktop::source::SourceBridge::new(
                runtime,
                helper,
                infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS,
            ),
        ))?;
    }
    #[cfg(not(all(feature = "remote", target_os = "linux")))]
    let _ = installation;
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    registry.register(Box::new(mesh_plugin))?;
    #[cfg(not(all(feature = "mesh", target_os = "linux")))]
    let _ = state;
    Ok(registry)
}

/// Node-state-backed proxy plugin, or the stateless one used by registry tests.
#[cfg(feature = "proxy")]
fn proxy_plugin_at(
    state: Option<&std::path::Path>,
) -> Result<infraternal_plugin_proxy::agent::ProxyAgentPlugin, PluginError> {
    let Some(state) = state else {
        return Ok(infraternal_plugin_proxy::agent::ProxyAgentPlugin::default());
    };
    let log: std::sync::Arc<infraternal_plugin_proxy::supervisor::ProxyLog> =
        std::sync::Arc::new(|line| tracing::info!(target: "infraternal::proxy", "{line}"));
    infraternal_plugin_proxy::agent::ProxyAgentPlugin::for_agent(state, log)
        .map_err(|_| PluginError::Rejected)
}

/// Wire both directions between the proxy and Mesh plugins [#281].
///
/// Mesh pushes each accepted configuration to the proxy controller, so a
/// revoked grant removes its routes. The proxy controller pushes each applied
/// route snapshot back to the Mesh firewall, so the ingress exception admits
/// only peers granted a published backend port. Both hooks are plain setters
/// that run only inside later plugin actions, so wiring order is irrelevant.
#[cfg(all(feature = "proxy", feature = "mesh", target_os = "linux"))]
fn connect_proxy_and_mesh(
    proxy_plugin: &infraternal_plugin_proxy::agent::ProxyAgentPlugin,
    mesh_plugin: infraternal_plugin_mesh::node_actions::MeshNodePlugin,
) -> Result<infraternal_plugin_mesh::node_actions::MeshNodePlugin, PluginError> {
    let proxy_controller = proxy_plugin.controller();
    proxy_controller
        .set_mesh_ingress_observer(mesh_plugin.proxy_ingress_observer())
        .map_err(|_| PluginError::Rejected)?;
    Ok(mesh_plugin
        .with_configuration_observer(std::sync::Arc::new(move |config| {
            let context = config
                .as_ref()
                .and_then(|config| proxy_mesh_context(config).ok());
            proxy_controller.set_mesh_context(context)
        }))
        .with_proxy_containment(std::sync::Arc::new(|| {
            let containment = infraternal_plugin_proxy::cgroup::containment();
            (containment.kind(), containment.describe())
        })))
}

#[cfg(all(test, feature = "proxy"))]
mod proxy_registry_tests {
    //! Keep the publication command connected to the real node-side plugin registry [#281].
    use super::{ExecutionMode, registry_at};
    use infraternal_plugin_api::PluginError;

    #[test]
    fn proxy_publish_is_registered_as_a_node_action() {
        let mut registry =
            registry_at(ExecutionMode::Embedded, None, None).expect("build plugin registry");
        let result = registry.call_public("proxy.publish", br#"{"port":null}"#);
        assert!(
            !matches!(result, Err(PluginError::UnknownAction)),
            "proxy.publish must be present in the compiled node registry"
        );
    }

    #[test]
    fn publishing_without_an_accepted_mesh_context_fails_closed() {
        let mut registry =
            registry_at(ExecutionMode::Embedded, None, None).expect("build plugin registry");
        let reply = registry
            .call_public("proxy.publish", br#"{"port":3000}"#)
            .expect("missing mesh context is a typed action result");
        let reply: serde_json::Value = serde_json::from_slice(&reply).expect("JSON error result");
        assert_eq!(reply["error"]["code"], "unreachable");
    }

    #[test]
    fn proxy_internal_context_update_is_not_a_public_action() {
        let mut registry =
            registry_at(ExecutionMode::Embedded, None, None).expect("build plugin registry");
        assert!(matches!(
            registry.call_public("proxy.mesh-context", b"{}"),
            Err(PluginError::UnknownAction)
        ));
    }
}

#[cfg(all(feature = "proxy", feature = "mesh", target_os = "linux"))]
fn proxy_mesh_context(
    config: &infraternal_plugin_mesh::dataplane::Config,
) -> std::io::Result<infraternal_plugin_proxy::mesh_context::AcceptedMeshContext> {
    use infraternal_plugin_mesh::policy::rules::{Protocol, TrafficPolicy};
    use std::net::IpAddr;

    let exposure = config.exposure.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "Mesh DNS identity is unavailable",
        )
    })?;
    let mut all_tcp_sources = std::collections::BTreeSet::new();
    let mut tcp_sources_by_port = Vec::new();
    for peer in config.peers.values() {
        let address = IpAddr::V4(peer.peer.addresses.ipv4);
        match &peer.inbound {
            TrafficPolicy::None => {}
            TrafficPolicy::All => {
                all_tcp_sources.insert(address);
            }
            TrafficPolicy::Ports(ports) => {
                for port in ports.iter().filter(|port| port.protocol == Protocol::Tcp) {
                    tcp_sources_by_port.push((port.number, address));
                }
            }
        }
    }
    infraternal_plugin_proxy::mesh_context::AcceptedMeshContext::new(
        exposure.machine_name.clone(),
        exposure.dns_suffix.clone(),
        IpAddr::V4(config.addresses.ipv4),
        all_tcp_sources,
        tcp_sources_by_port,
    )
}

#[cfg(all(test, feature = "proxy", feature = "mesh", target_os = "linux"))]
mod proxy_mesh_context_tests {
    //! The proxy reads only the applied Mesh direction and TCP grants [#266, #281].
    use super::proxy_mesh_context;
    use infraternal_plugin_mesh::dataplane::{
        Config, DefaultPolicy, ExposureIdentity, Peer, PeerPolicy,
    };
    use infraternal_plugin_mesh::policy::{
        model::{Addresses, NodeId, PublicKey},
        rules::{Port, Protocol, TrafficPolicy},
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        net::Ipv4Addr,
    };

    fn peer(id: u8, ipv4: Ipv4Addr, inbound: TrafficPolicy, outbound: TrafficPolicy) -> PeerPolicy {
        PeerPolicy {
            peer: Peer {
                key: PublicKey([id; 32]),
                addresses: Addresses {
                    ipv4,
                    ipv6: format!("fd00::{id:x}").parse().expect("IPv6 mesh address"),
                },
                endpoint: None,
            },
            inbound,
            outbound,
        }
    }

    #[test]
    fn accepted_config_exports_only_inbound_tcp_sources_for_the_published_port() {
        let tcp_3000 = Port {
            protocol: Protocol::Tcp,
            number: 3000,
        };
        let udp_3000 = Port {
            protocol: Protocol::Udp,
            number: 3000,
        };
        let config = Config {
            local_key: None,
            server: Some(NodeId(1)),
            node: NodeId(2),
            version: 9,
            addresses: Addresses {
                ipv4: "10.254.0.2".parse().expect("local mesh address"),
                ipv6: "fd00::2".parse().expect("local IPv6 mesh address"),
            },
            default_policy: DefaultPolicy::Deny,
            exposure: Some(ExposureIdentity {
                machine_name: "host-2".to_owned(),
                dns_suffix: "internal".to_owned(),
            }),
            peers: BTreeMap::from([
                (
                    NodeId(3),
                    peer(
                        3,
                        "10.254.0.3".parse().expect("granted peer"),
                        TrafficPolicy::Ports(BTreeSet::from([tcp_3000])),
                        TrafficPolicy::None,
                    ),
                ),
                (
                    NodeId(4),
                    peer(
                        4,
                        "10.254.0.4".parse().expect("UDP-only peer"),
                        TrafficPolicy::Ports(BTreeSet::from([udp_3000])),
                        TrafficPolicy::Ports(BTreeSet::from([tcp_3000])),
                    ),
                ),
                (
                    NodeId(5),
                    peer(
                        5,
                        "10.254.0.5".parse().expect("open inbound peer"),
                        TrafficPolicy::All,
                        TrafficPolicy::None,
                    ),
                ),
            ]),
        };
        let context = proxy_mesh_context(&config).expect("trusted exposure identity");

        assert_eq!(context.machine_name, "host-2");
        assert_eq!(context.dns_suffix, "internal");
        assert_eq!(context.mesh_address.to_string(), "10.254.0.2");
        assert_eq!(
            context.allowed_sources(3000),
            [
                "10.254.0.3"
                    .parse::<std::net::IpAddr>()
                    .expect("source address"),
                "10.254.0.5"
                    .parse::<std::net::IpAddr>()
                    .expect("all inbound source"),
            ]
        );
        assert_eq!(
            context.allowed_sources(8080),
            ["10.254.0.5"
                .parse::<std::net::IpAddr>()
                .expect("all inbound source")]
        );
    }
}

/// Kernel objects an installation leaves outside its files, for host uninstall (D273, #235).
///
/// The mesh interface and its packet filter belong to the kernel, not to the
/// daemon process, so stopping the service keeps them (by design across
/// restarts). Only the root infraternal agent can create them; a rootless
/// installation has none. Ownership is this installation's mesh state record,
/// never the shared name or marker: see `Node::plan_retirement`.
#[cfg(all(feature = "remote", target_os = "linux"))]
pub const KERNEL: infraternal_plugin_remote::uninstall::Kernel =
    infraternal_plugin_remote::uninstall::Kernel {
        inspect: inspect_kernel_state,
        retire: retire_kernel_state,
    };
// The uninstall callback keeps its fallible signature even without kernel roles.
#[cfg(all(feature = "remote", target_os = "linux"))]
#[cfg_attr(not(feature = "mesh"), allow(clippy::unnecessary_wraps))]
fn inspect_kernel_state(state: &std::path::Path) -> std::io::Result<Vec<&'static str>> {
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    if nix::unistd::Uid::effective().is_root() {
        return infraternal_plugin_mesh::node::Node::plan_retirement(state)
            .map(|plan| plan.left().to_vec());
    }
    let _ = state;
    Ok(Vec::new())
}
#[cfg(all(feature = "remote", target_os = "linux"))]
#[cfg_attr(not(feature = "mesh"), allow(clippy::unnecessary_wraps))]
fn retire_kernel_state(state: &std::path::Path) -> std::io::Result<Vec<&'static str>> {
    #[cfg(all(feature = "mesh", target_os = "linux"))]
    if nix::unistd::Uid::effective().is_root() {
        return infraternal_plugin_mesh::node::Node::retire(state);
    }
    let _ = state;
    Ok(Vec::new())
}

/// Exact private handoff decoder shared with parser fuzzing; parsing grants no authority.
#[cfg(all(feature = "remote", target_os = "linux"))]
pub use infraternal_plugin_remote::uninstall::decode_request as decode_uninstall_request;
