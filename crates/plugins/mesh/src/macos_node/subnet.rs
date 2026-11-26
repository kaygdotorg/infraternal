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
    macos_subnet_routes::{MAX_NETWORKS, plan_networks, table_network},
    policy::{model::PublicKey, networks::Network},
    subnet_routes::{
        EXTRA_ROUTE_LIMIT, RouteState, holds_endpoint_sentence, matching_endpoints, route_targets,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, SocketAddr},
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
    /// Apply subnet routes after a snapshot, reusing authenticated endpoints for peers that
    /// kept their sessions.
    pub(super) async fn sync_networks(&mut self) {
        self.reconcile_networks(None).await;
    }

    /// Reconcile the utun's routes only when a snapshot or a matching endpoint IP changed.
    /// Root mode and the helper both see only prefixes the tunnel is allowed to carry. A
    /// withdrawn prefix is removed first, so even a partial add leaves the endpoint outside it.
    /// Snapshots pass `None` and read the engine only if there are routes to reconcile.
    pub(super) async fn reconcile_networks(
        &mut self,
        confirmed: Option<&[(PublicKey, SocketAddr)]>,
    ) -> bool {
        let Some(config) = self.config.as_ref() else {
            return false;
        };
        let wanted = self.wanted_networks(config);
        if wanted.is_empty() && self.networks.is_empty() {
            self.admitted_networks.clear();
            self.subnet_exceptions.clear();
            self.network_status.clear();
            return false;
        }
        let Some(utun) = self.utun.clone() else {
            return false;
        };
        let snapshot = confirmed.is_none();
        let fresh;
        let confirmed = if let Some(endpoints) = confirmed {
            endpoints
        } else {
            fresh = self.confirmed_peer_endpoints().await;
            &fresh
        };
        let confirmed: BTreeMap<_, _> = confirmed.iter().copied().collect();
        let own = config.addresses.ipv4;
        let effective: Vec<_> = installed_peers(config)
            .filter_map(|policy| {
                let peer = &policy.peer;
                confirmed
                    .get(&crate::candidate_walks::active_peer_key(peer))
                    .copied()
                    .or(peer.endpoint)
                    .map(|endpoint| endpoint.ip().to_canonical())
            })
            .collect();
        let matched = matching_endpoints(&wanted.iter().map(|(network, _)| *network), effective);
        if !snapshot && matched == self.subnet_exceptions {
            return false;
        }
        let configured = installed_peers(config).filter_map(|policy| {
            policy
                .peer
                .endpoint
                .map(|endpoint| endpoint.ip().to_canonical())
        });
        let wanted_mtus: BTreeMap<_, _> = wanted.into_iter().collect();
        self.admitted_networks
            .retain(|network| wanted_mtus.contains_key(network));
        let user_mode = crate::macos_helper::user_mode();
        let mut states = BTreeMap::new();
        let mut eligible = Vec::new();
        let guarded: Vec<_> = configured.chain(matched.iter().copied()).collect();
        for &network in wanted_mtus.keys() {
            if !self.admitted_networks.contains(&network)
                && let Some(endpoint) = crate::subnet_routes::holds_endpoint(network, &guarded)
            {
                states.insert(
                    network,
                    RouteState::Skipped(holds_endpoint_sentence(endpoint, "this Mac")),
                );
            } else if user_mode && !crate::macos_subnet_routes::is_private(network) {
                states.insert(
                    network,
                    RouteState::Skipped(crate::macos_subnet_routes::Skip::NotPrivate.sentence()),
                );
            } else {
                eligible.push(network);
            }
        }
        let limit = if user_mode {
            MAX_NETWORKS
        } else {
            eligible.len() + EXTRA_ROUTE_LIMIT
        };
        let (targets, skipped) = route_targets(&eligible, &matched, limit);
        states.extend(skipped);
        let parts: Wanted = targets
            .iter()
            .flat_map(|(network, parts)| {
                parts
                    .iter()
                    .map(|part| (*part, wanted_mtus.get(network).copied().flatten()))
            })
            .collect();
        let installed = self.networks.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            if user_mode {
                sync_through_helper(&utun, &parts, &installed)
            } else {
                sync_as_root(utun.name(), own, &parts, &installed)
            }
        })
        .await;
        let Ok((installed, outcomes)) = outcome else {
            tracing::warn!("mesh subnet route update could not finish");
            return true;
        };
        if self.networks != installed && self.subnet_exceptions != matched {
            // The connected socket pool can cache the source it selected before the hole.
            self.udp.underlay_changed();
        }
        self.networks = installed;
        for (network, parts) in targets {
            let state = parts
                .iter()
                .find_map(|part| match outcomes.get(part) {
                    Some(RouteState::Installed) => None,
                    Some(state) => Some(state.clone()),
                    None => Some(RouteState::Failed(format!("no route result for {part}"))),
                })
                .unwrap_or(RouteState::Installed);
            if matches!(state, RouteState::Installed) {
                self.admitted_networks.insert(network);
            }
            states.insert(network, state);
        }
        // A failed removal can leave an old broader prefix in place, even when there
        // were no replacement prefixes (an excluded /32). Keep it visible and retry on
        // the next endpoint scan.
        for part in self.networks.keys() {
            if let Some(endpoint) = matched.range(part.address()..).next()
                && part.contains(*endpoint)
            {
                for network in wanted_mtus
                    .keys()
                    .filter(|network| network.contains(*endpoint))
                {
                    states.insert(
                        *network,
                        RouteState::Failed(format!(
                            "could not exclude underlay endpoint {endpoint}"
                        )),
                    );
                }
            }
        }
        if states
            .values()
            .all(|state| !matches!(state, RouteState::Failed(_)))
        {
            self.subnet_exceptions = matched;
        }
        self.network_status.publish(states);
        true
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

    /// Take every subnet route off the utun before it closes (root mode runs `route` itself;
    /// in user mode the routes go with the utun) and clear the published status.
    pub(super) fn remove_networks(&mut self) {
        self.subnet_exceptions.clear();
        self.admitted_networks.clear();
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
        &[],
        false,
    );
    let mut now = installed.clone();
    let mut states = BTreeMap::new();
    for network in &plan.remove {
        if let Err(error) = network_route(interface, *network, "delete", None) {
            tracing::warn!(%network, %error, "mesh subnet route could not be removed");
            let failed = networks
                .iter()
                .map(|network| (*network, RouteState::Failed(error.to_string())))
                .collect();
            return (now, failed);
        }
        now.remove(network);
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

/// User mode: ask the helper to put the already checked prefixes on this utun.
fn sync_through_helper(
    utun: &MacUtun,
    wanted: &Wanted,
    installed: &BTreeMap<Network, Option<u16>>,
) -> (
    BTreeMap<Network, Option<u16>>,
    BTreeMap<Network, RouteState>,
) {
    use std::os::fd::AsFd;
    let mut states = BTreeMap::new();
    let asked: Vec<_> = wanted.iter().map(|(network, _)| *network).collect();
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
