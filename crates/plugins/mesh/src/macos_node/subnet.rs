//! The Mac's subnet routes on its utun (D197 M3, #580): the worker's reconcile after every applied
//! snapshot, in root mode through `route` and in user mode through the helper.
//!
//! The plan itself is pure and lives in [`crate::macos_subnet_routes`]. This module reads what
//! the plan needs (routing table, interface networks, peer endpoints), carries it out, and
//! publishes what happened to each network for `mesh routes`. Nothing here fails a snapshot: a
//! network that cannot be routed is reported and the rest of the mesh keeps working, as on Linux.
//!
//! The worker's exclusive `&mut self` is the route lock, as for the peer host routes, and the
//! host tools run on the blocking pool so the packet reactor keeps moving (D351). The routes live
//! on the utun, so the kernel removes them with it on stop, down or a crash; no journal is needed.
use super::{Config, MacUtun, RuntimeState, installed_peers};
use crate::{
    macos_subnet_routes::{Skip, plan_networks, table_network},
    policy::networks::Network,
    subnet_routes::RouteState,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::IpAddr,
    sync::{Arc, Mutex},
};

/// What happened to each network the applied snapshot lets this Mac reach, shared by the worker
/// (which writes it after every reconcile) and the node (which reads it for `mesh routes`).
#[derive(Clone, Debug, Default)]
pub(crate) struct NetworkStatus(Arc<Mutex<BTreeMap<Network, RouteState>>>);

impl NetworkStatus {
    /// The status of one network as `mesh routes` shows it; `pending` before the first reconcile.
    #[must_use]
    pub(crate) fn route_json(&self, network: Network) -> serde_json::Value {
        let states = self.0.lock();
        crate::subnet_routes::route_json(
            states.as_ref().ok().and_then(|states| states.get(&network)),
        )
    }

    /// Replace the published states.
    fn publish(&self, states: BTreeMap<Network, RouteState>) {
        if let Ok(mut published) = self.0.lock() {
            *published = states;
        }
    }

    /// Forget every state: the utun, and with it every route, is gone.
    pub(crate) fn clear(&self) {
        self.publish(BTreeMap::new());
    }
}

/// One wanted network and, in root mode, the path MTU of the router peer that carries it.
type Wanted = Vec<(Network, Option<u16>)>;

impl RuntimeState {
    /// Bring the utun's subnet routes in line with the applied snapshot and publish the outcome.
    ///
    /// Runs after every applied snapshot and when the worker starts. A Mac without wanted or
    /// installed networks does nothing at all, so a mesh without subnet routes never asks the
    /// helper (an older helper would not know the request).
    pub(super) async fn sync_networks(&mut self) {
        let Some(config) = self.config.as_ref() else {
            return;
        };
        let wanted = self.wanted_networks(config);
        if wanted.is_empty() && self.networks.is_empty() {
            self.network_status.clear();
            return;
        }
        let Some(utun) = self.utun.clone() else {
            return;
        };
        let own = config.addresses.ipv4;
        let endpoints = self.underlay_endpoints(config).await;
        let installed = self.networks.clone();
        let user_mode = crate::macos_helper::user_mode();
        let outcome = tokio::task::spawn_blocking(move || {
            if user_mode {
                sync_through_helper(&utun, &wanted, &installed, &endpoints)
            } else {
                sync_as_root(utun.name(), own, &wanted, &installed, &endpoints)
            }
        })
        .await;
        let Ok((installed, states)) = outcome else {
            tracing::warn!("mesh subnet route update could not finish");
            return;
        };
        self.networks = installed;
        self.network_status.publish(states);
    }

    /// The networks of the applied snapshot, each with its router peer's path MTU (root mode
    /// gives every route its own MTU, as for the peer host routes).
    fn wanted_networks(&self, config: &Config) -> Wanted {
        let reachable: BTreeSet<Network> = crate::subnet_routes::reachable_networks(config)
            .into_iter()
            .collect();
        let mut wanted = Vec::new();
        for policy in config.peers.values() {
            let mtu = self
                .route_mtus
                .get(&IpAddr::V4(policy.peer.addresses.ipv4))
                .copied();
            for through in &policy.networks.through {
                if reachable.contains(&through.network) {
                    wanted.push((through.network, mtu));
                }
            }
        }
        wanted.sort_unstable();
        wanted.dedup_by_key(|(network, _)| *network);
        wanted
    }

    /// Every underlay address the mesh sends to: the configured endpoints and the addresses the
    /// engine uses now (it may have roamed to a candidate). A network holding one of them is
    /// never routed into the utun.
    async fn underlay_endpoints(&self, config: &Config) -> Vec<IpAddr> {
        let mut endpoints: Vec<IpAddr> = installed_peers(config)
            .filter_map(|policy| policy.peer.endpoint.map(|endpoint| endpoint.ip()))
            .collect();
        if let Some(device) = self.device.as_ref() {
            endpoints.extend(
                device
                    .read(async |read| read.peers().await)
                    .await
                    .into_iter()
                    .filter_map(|peer| peer.peer.endpoint.map(|endpoint| endpoint.ip())),
            );
        }
        endpoints.sort_unstable();
        endpoints.dedup();
        endpoints
    }

    /// Take every subnet route off the utun before it closes (root mode runs `route` itself;
    /// in user mode the routes go with the utun) and clear the published status.
    pub(super) fn remove_networks(&mut self) {
        let networks = std::mem::take(&mut self.networks);
        if !crate::macos_helper::user_mode()
            && let Some(utun) = self.utun.as_ref()
        {
            for network in networks.keys() {
                if let Err(error) = network_route(utun.name(), *network, "delete", None) {
                    tracing::warn!(%network, error = %error, "mesh subnet route could not be removed");
                }
            }
        }
        self.network_status.clear();
    }

    /// The networks routed into the utun now, for the candidate walks.
    pub(super) fn installed_networks(&self) -> BTreeSet<Network> {
        self.networks.keys().copied().collect()
    }
}

/// Root mode: read the table, plan, and run `route` for each change. Returns the networks now on
/// the utun (with the MTU each was given) and every wanted network's state.
fn sync_as_root(
    interface: &str,
    own: std::net::Ipv4Addr,
    wanted: &Wanted,
    installed: &BTreeMap<Network, Option<u16>>,
    endpoints: &[IpAddr],
) -> (
    BTreeMap<Network, Option<u16>>,
    BTreeMap<Network, RouteState>,
) {
    let networks: Vec<Network> = wanted.iter().map(|(network, _)| *network).collect();
    let mtus: BTreeMap<Network, Option<u16>> = wanted.iter().copied().collect();
    let read = crate::macos_helper::routing_table(true)
        .and_then(|table| Ok((table, crate::macos_helper::local_networks(true)?)));
    let (table, local) = match read {
        Ok(read) => read,
        Err(error) => {
            let failed = networks
                .iter()
                .map(|network| (*network, RouteState::Failed(error.to_string())))
                .collect();
            return (installed.clone(), failed);
        }
    };
    let previous: Vec<Network> = installed.keys().copied().collect();
    let plan = plan_networks(
        &networks,
        interface,
        Some(own),
        &previous,
        &table,
        &local,
        &[],
        endpoints,
        false,
    );
    let mut now = installed.clone();
    let mut states = BTreeMap::new();
    for network in &plan.remove {
        match network_route(interface, *network, "delete", None) {
            Ok(()) => {
                now.remove(network);
            }
            Err(error) => {
                tracing::warn!(%network, error = %error, "mesh subnet route could not be removed");
            }
        }
    }
    for (network, skip) in &plan.skipped {
        states.insert(*network, RouteState::Skipped(skip.sentence()));
    }
    for network in &plan.keep {
        let mtu = mtus.get(network).copied().flatten();
        let state = if now.get(network).copied().flatten() == mtu {
            RouteState::Installed
        } else {
            match network_route(interface, *network, "change", mtu) {
                Ok(()) => {
                    now.insert(*network, mtu);
                    RouteState::Installed
                }
                Err(error) => RouteState::Failed(error.to_string()),
            }
        };
        states.insert(*network, state);
    }
    for network in &plan.add {
        let mtu = mtus.get(network).copied().flatten();
        let state = match network_route(interface, *network, "add", mtu) {
            Ok(()) => {
                now.insert(*network, mtu);
                RouteState::Installed
            }
            Err(error) => RouteState::Failed(error.to_string()),
        };
        states.insert(*network, state);
    }
    (now, states)
}

/// User mode: leave out what only the agent can judge (a peer's underlay address, public space
/// the helper would refuse), then ask the helper to make the utun's networks exactly the rest.
fn sync_through_helper(
    utun: &MacUtun,
    wanted: &Wanted,
    installed: &BTreeMap<Network, Option<u16>>,
    endpoints: &[IpAddr],
) -> (
    BTreeMap<Network, Option<u16>>,
    BTreeMap<Network, RouteState>,
) {
    use std::os::fd::AsFd;
    let mut states = BTreeMap::new();
    let mut asked = Vec::new();
    for (network, _) in wanted {
        if let Some(address) = endpoints.iter().find(|address| network.contains(**address)) {
            states.insert(
                *network,
                RouteState::Skipped(Skip::HoldsEndpoint(*address).sentence()),
            );
        } else if !crate::macos_subnet_routes::is_private(*network) {
            states.insert(*network, RouteState::Skipped(Skip::NotPrivate.sentence()));
        } else {
            asked.push(*network);
        }
    }
    if asked.is_empty() && installed.is_empty() {
        return (BTreeMap::new(), states);
    }
    let request = crate::macos_user_mode::Request::Networks { networks: asked };
    match crate::macos_helper::request(&request, Some(utun.fd.get_ref().as_fd())) {
        Ok((reply, _)) => {
            let mut now = BTreeMap::new();
            for outcome in reply.networks {
                let state = if outcome.installed {
                    now.insert(outcome.network, None);
                    RouteState::Installed
                } else {
                    RouteState::Skipped(outcome.reason.unwrap_or_default())
                };
                states.insert(outcome.network, state);
            }
            (now, states)
        }
        Err(error) => {
            let reason = format!(
                "the mesh helper did not route it ({error}); if the helper predates this agent, \
                 run infraternal up again to update it"
            );
            for (network, _) in wanted {
                states
                    .entry(*network)
                    .or_insert_with(|| RouteState::Failed(reason.clone()));
            }
            // Nothing is known to have changed on the utun.
            (installed.clone(), states)
        }
    }
}

/// Add, change or delete one subnet route through the utun `interface` in root mode. `mtu` is the
/// router peer's path budget; without one the route takes the interface MTU.
/// # Errors
/// Refuses a malformed utun name; reports a failed `route` run (a delete of a route that is
/// already gone succeeds).
fn network_route(
    interface: &str,
    network: Network,
    operation: &str,
    mtu: Option<u16>,
) -> io::Result<()> {
    if !super::valid_utun_name(interface) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let destination = table_network(network).to_string();
    let mut command = std::process::Command::new("/sbin/route");
    command
        .args([
            "-n",
            operation,
            "-inet",
            "-net",
            &destination,
            "-interface",
            interface,
        ])
        .env_clear()
        .stdin(std::process::Stdio::null());
    let mtu_argument = mtu
        .filter(|_| operation != "delete")
        .map(|mtu| mtu.to_string());
    if let Some(mtu) = mtu_argument.as_deref() {
        command.args(["-mtu", mtu]);
    }
    let output = command.output()?;
    if output.status.success()
        || (operation == "delete"
            && String::from_utf8_lossy(&output.stderr)
                .to_ascii_lowercase()
                .contains("not in table"))
    {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "route {operation} {destination} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}
