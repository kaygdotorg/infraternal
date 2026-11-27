//! The peer host-route writers outside the route-repair worker (#260 J1240, #489 J552):
//! [`write_snapshot_routes`] for a snapshot apply, [`update_live_peer_endpoints`] for budgets
//! learned from live endpoints, and [`WrittenRoute`], the record of written routes both share
//! through [`PeerRouteState::written`].
//!
//! It lives in its own file only to keep `node.rs` under the repository's size limit; it is part
//! of the node module and uses its route state directly.

use super::{
    BTreeSet, Device, Mutex, PeerRouteState, io, is_direct_learned_endpoint, lock_route_state,
};

/// One peer's two host routes as this process last wrote them (see [`PeerRouteState::written`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WrittenRoute {
    /// The link index both routes were written on.
    pub(super) ifindex: u32,
    /// The peer's mesh addresses: the destinations of its routes.
    pub(super) addresses: crate::policy::model::Addresses,
    /// Whether the IPv6 host route exists as well as the IPv4 one. It is false for an IPv4-only
    /// peer and while the link carries no IPv6 (#578).
    pub(super) ipv6: bool,
    /// The MTU metric both routes carry.
    pub(super) mtu: u16,
    /// What `mtu` was derived from, when a later snapshot may reuse it without another underlay
    /// lookup: the route endpoint, and the underlay watch's generation read before the lookup.
    /// `None` for a relay budget, a failed lookup, a derivation while no watch ran, and every
    /// write of the live-endpoint refresh.
    pub(super) derived: Option<(Option<std::net::SocketAddr>, u64)>,
}

impl WrittenRoute {
    /// Whether the kernel holds the same two routes for `other` as for `self`: everything but
    /// the derivation note matches.
    pub(super) fn same_routes(&self, other: &Self) -> bool {
        self.ifindex == other.ifindex
            && self.addresses == other.addresses
            && self.ipv6 == other.ipv6
            && self.mtu == other.mtu
    }
}

/// Make the host routes of `peers`, the complete installed set, what this state says they
/// should be, writing only the peers whose routes differ from [`PeerRouteState::written`]
/// (#260 J1240).
///
/// A peer's wanted routes are its two mesh addresses on the marked mesh link, with the active
/// relay budget, or else the direct-path budget of its route endpoint (the learned live
/// endpoint where one is valid, otherwise the configured one). A direct budget written by an
/// earlier snapshot is reused without an underlay lookup while the route endpoint is the same
/// and the underlay watch still reads the generation it was derived at: the watch moves on
/// every link, route, rule or nexthop change that could change the path (#489 J552 P2-2), and
/// [`crate::wireguard::UnderlayWatch::settled_generation`] answers only once the watch has
/// counted every change announced so far. Without such an answer (no watch, or one still
/// reading) every budget is looked up again, as before. All lookups of one call
/// share one probe, so peers behind one endpoint address cost one lookup.
///
/// A snapshot that changes one peer therefore writes two routes, and an identical snapshot
/// writes none, where every apply used to rewrite every peer's routes. Records of peers that
/// are not in `peers` are dropped; their routes are the inventory's to remove.
///
/// Returns the underlay generation at which every peer's direct budget is now known for its
/// route endpoint, if there is one. The caller hands it to [`PeerRouteState::mark_current`]
/// once `peers` is the installed set, so the next live-endpoint refresh looks up only peers that
/// changed since, instead of every peer again.
/// # Errors
/// Returns a missing mesh link or a route-netlink error. Peers written before the error are
/// recorded; the failing peer is not.
pub(super) fn write_snapshot_routes(
    state: &mut PeerRouteState,
    peers: &[crate::dataplane::Peer],
) -> io::Result<Option<u64>> {
    if peers.is_empty() {
        state.written.clear();
        return Ok(None);
    }
    let mut writer = Device::peer_route_writer(state.underlay.clone())?;
    let ifindex = writer.ifindex();
    // Only a generation that already counts every announced change may vouch for an old
    // budget: a caller that changes the underlay and applies a snapshot right after must see
    // the new path, as when every apply looked every peer up.
    let generation = state
        .underlay
        .as_ref()
        .and_then(|underlay| underlay.settled_generation());
    let mut probe = crate::mesh_mtu::EndpointProbe::default();
    let mut all_derived = generation.is_some();
    for peer in peers {
        let route_peer = state.route_peer(peer);
        let previous = state.written.get(&peer.key).copied();
        let (mtu, derived) = if let Some(mtu) = state.overrides.get(&peer.key) {
            (*mtu, None)
        } else if let (Some(previous), Some(generation)) = (previous, generation)
            && previous.ifindex == ifindex
            && previous.derived == Some((route_peer.endpoint, generation))
        {
            (previous.mtu, previous.derived)
        } else {
            let budget = probe.route_budget(route_peer.endpoint);
            let derived = generation
                .filter(|_| !budget.lookup_failed)
                .map(|generation| (route_peer.endpoint, generation));
            all_derived &= derived.is_some();
            (budget.mtu, derived)
        };
        let wanted = WrittenRoute {
            ifindex,
            addresses: peer.addresses,
            // An IPv6-off link holds no IPv6 route, whatever was written before (#578).
            ipv6: writer.writes_ipv6_for(peer),
            mtu,
            derived,
        };
        if previous.is_some_and(|previous| previous.same_routes(&wanted)) {
            state.written.insert(peer.key, wanted);
            continue;
        }
        // Forget first: if the write fails part-way, this peer's routes are unknown.
        state.written.remove(&peer.key);
        writer.replace(&route_peer, mtu)?;
        state.written.insert(
            peer.key,
            WrittenRoute {
                ipv6: writer.writes_ipv6_for(peer),
                ..wanted
            },
        );
    }
    if !writer.ipv6() {
        // IPv6 went off during the batch, and the kernel dropped every IPv6 route of the link.
        for written in state.written.values_mut() {
            if written.ifindex == ifindex {
                written.ipv6 = false;
            }
        }
    }
    let installed: BTreeSet<_> = peers.iter().map(|peer| peer.key).collect();
    state.written.retain(|key, _| installed.contains(key));
    Ok(generation.filter(|_| all_derived))
}

/// Remember learned endpoints and refresh the direct routes whose budget may have changed,
/// without displacing relay MTU overrides.
///
/// A `None` live endpoint returns to the accepted coordinator endpoint. Endpoints for peers that
/// are no longer installed are ignored, so a late packet cannot restore a retired host route.
/// Peers a relay carries record nothing (#489 J552 P2-1).
///
/// Cost (#489 J552 P2-2): a budget is re-derived only for peers whose route endpoint changed or
/// whose written budget was forgotten, and for every peer once after the underlay watch reports
/// a link or route change (or while no watch runs). A refresh with nothing to re-derive takes
/// the lock once and sends no netlink request. Derivation runs in three steps, so the route-state
/// lock is never held across underlay lookups:
/// 1. under the lock, record endpoints and claim the peers to re-derive;
/// 2. without the lock, look their underlay routes up on one shared netlink socket;
/// 3. under the lock again, write the budgets that changed, for peers whose route endpoint and
///    relay state are still the ones that were looked up. Any other peer stays claimed for the
///    next refresh.
///
/// Writes go only to the link the route-repair worker proved (`state.link`), re-verified right
/// before the batch. A callback that outlives that link, even when a replacement link carries our
/// marker under the shared name, therefore writes nothing (#489 J549 P2).
///
/// The result is the number of peers written, two routes each.
/// # Errors
/// Returns route-netlink errors and a missing or changed proven link. The peers of a failed
/// batch are re-derived on the next refresh.
pub(super) fn update_live_peer_endpoints(
    state: &Mutex<PeerRouteState>,
    endpoints: &[(
        crate::policy::model::PublicKey,
        Option<std::net::SocketAddr>,
    )],
) -> io::Result<usize> {
    let candidates = {
        let mut state = lock_route_state(state);
        let candidates = claim_live_route_rechecks(&mut state, endpoints);
        state.sync_client_routes(false);
        candidates
    };
    if candidates.is_empty() {
        return Ok(0);
    }
    // Underlay route lookups are reads; one probe per batch shares its socket and its answers.
    let mut probe = crate::mesh_mtu::EndpointProbe::default();
    let derived: Vec<_> = candidates
        .into_iter()
        .map(|(key, endpoint)| (key, endpoint, probe.route_budget(endpoint)))
        .collect();
    drop(probe);
    write_live_route_budgets(&mut lock_route_state(state), &derived)
}

/// Step 1 of [`update_live_peer_endpoints`]: record endpoints and claim the peers to re-derive,
/// each with the route endpoint its budget must be derived from.
fn claim_live_route_rechecks(
    state: &mut PeerRouteState,
    endpoints: &[(
        crate::policy::model::PublicKey,
        Option<std::net::SocketAddr>,
    )],
) -> Vec<(
    crate::policy::model::PublicKey,
    Option<std::net::SocketAddr>,
)> {
    for (key, endpoint) in endpoints {
        let Some(configured) = state.peers.get(key).map(|peer| peer.endpoint) else {
            continue;
        };
        if state.overrides.contains_key(key) {
            // A relay owns this peer: its confirmed endpoint is the relay shim (#489 J552 P2-1).
            continue;
        }
        let desired = (*endpoint).filter(|endpoint| {
            Some(*endpoint) != configured && is_direct_learned_endpoint(*endpoint)
        });
        let previous = state.live_endpoints.get(key).copied();
        if previous == desired {
            continue;
        }
        let before = previous
            .or(configured)
            .map(|endpoint| endpoint.ip().to_canonical());
        let after = desired
            .or(configured)
            .map(|endpoint| endpoint.ip().to_canonical());
        if before != after
            && state.client_routes.wanted.iter().any(|network| {
                before.is_some_and(|ip| network.contains(ip))
                    || after.is_some_and(|ip| network.contains(ip))
            })
        {
            state.client_routes.dirty = true;
        }
        match desired {
            Some(endpoint) => state.live_endpoints.insert(*key, endpoint),
            None => state.live_endpoints.remove(key),
        };
        state.recheck.insert(*key);
    }
    let generation = state
        .underlay
        .as_ref()
        .and_then(|underlay| underlay.generation());
    let keys: Vec<_> =
        if !state.all_current || generation.is_none() || generation != state.checked_generation {
            // Claim everything at this generation; a change announced from now on moves it again.
            state.all_current = true;
            state.checked_generation = generation;
            state.recheck.clear();
            state.failed_lookups.clear();
            state.peers.keys().copied().collect()
        } else {
            std::mem::take(&mut state.recheck).into_iter().collect()
        };
    keys.into_iter()
        .filter(|key| !state.overrides.contains_key(key))
        .filter_map(|key| state.peers.get(&key))
        .map(|peer| (peer.key, state.route_peer(peer).endpoint))
        .collect()
}

/// Step 3 of [`update_live_peer_endpoints`]: write the derived budgets that changed.
///
/// A peer whose route endpoint or relay state moved while its underlay was looked up is not
/// written: whoever moved it scheduled it again, or owns its route now. A peer whose lookup
/// failed gets the fallback written and is queued again, within its bounded retries.
fn write_live_route_budgets(
    state: &mut PeerRouteState,
    derived: &[(
        crate::policy::model::PublicKey,
        Option<std::net::SocketAddr>,
        crate::mesh_mtu::RouteBudget,
    )],
) -> io::Result<usize> {
    let mut route_peers = Vec::new();
    for (key, endpoint, budget) in derived {
        if state.overrides.contains_key(key) {
            continue;
        }
        let Some(peer) = state.peers.get(key) else {
            continue;
        };
        let route_peer = state.route_peer(peer);
        if route_peer.endpoint != *endpoint {
            state.recheck.insert(*key);
            continue;
        }
        state.note_lookup(*key, budget.lookup_failed);
        let unchanged = state.written.get(key).is_some_and(|written| {
            state
                .link
                .is_some_and(|link| link.ifindex == written.ifindex)
                && written.addresses == route_peer.addresses
                && written.mtu == budget.mtu
        });
        if !unchanged {
            route_peers.push((route_peer, budget.mtu));
        }
    }
    if route_peers.is_empty() {
        return Ok(0);
    }
    let Some(link) = state.link else {
        for (peer, _) in &route_peers {
            state.forget_written_for(peer.key);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "mesh route refresh skipped: no proven mesh link",
        ));
    };
    let routes: Vec<_> = route_peers.iter().map(|(peer, mtu)| (peer, *mtu)).collect();
    let ipv6 = match Device::replace_peer_routes_on(&link, &routes, state.underlay.clone()) {
        Ok(ipv6) => ipv6,
        Err(error) => {
            // A partial batch leaves unknown kernel budgets: rewrite these peers next time.
            for (peer, _) in &route_peers {
                state.forget_written_for(peer.key);
            }
            return Err(error);
        }
    };
    for (peer, mtu) in &route_peers {
        // No derivation note: the claim's generation may have moved during the lookups, so the
        // next snapshot looks this peer up again instead of trusting it.
        state.written.insert(
            peer.key,
            WrittenRoute {
                ifindex: link.ifindex,
                addresses: peer.addresses,
                ipv6: ipv6 && !peer.ipv4_only,
                mtu: *mtu,
                derived: None,
            },
        );
    }
    Ok(route_peers.len())
}

impl PeerRouteState {
    /// Apply subnet exceptions before resolving the new endpoint's route budget. Snapshot and
    /// live callers share this lock, so a late endpoint scan cannot restore a withdrawn route.
    pub(super) fn sync_client_routes(&mut self, snapshot: bool) {
        use crate::subnet_routes::{
            EXTRA_ROUTE_LIMIT, RouteState, matching_endpoints, route_targets,
        };
        let client = &self.client_routes;
        let Some(source) = client.source else {
            return;
        };
        if !snapshot && (!client.dirty || self.link.is_none()) {
            return;
        }
        let endpoints = matching_endpoints(
            &client.wanted.iter().copied(),
            self.peers
                .values()
                .filter(|peer| !self.overrides.contains_key(&peer.key))
                .filter_map(|peer| {
                    self.live_endpoints
                        .get(&peer.key)
                        .copied()
                        .or(peer.endpoint)
                        .map(|endpoint| endpoint.ip().to_canonical())
                }),
        );
        if !snapshot
            && endpoints == client.exceptions
            && client
                .states
                .values()
                .all(|state| !matches!(state, RouteState::Failed(_)))
        {
            self.client_routes.dirty = false;
            return;
        }
        let (targets, mut states) = route_targets(
            &client.wanted,
            &endpoints,
            client.wanted.len() + EXTRA_ROUTE_LIMIT,
        );
        states.extend(client.refused.clone());
        let proven = if snapshot { None } else { self.link };
        let client = &mut self.client_routes;
        client.dirty = true;
        match Device::sync_network_routes(&targets, source, proven, self.underlay.as_deref()) {
            Ok(result) => {
                if result
                    .values()
                    .all(|state| !matches!(state, RouteState::Failed(_)))
                {
                    client.exceptions = endpoints;
                    client.dirty = false;
                }
                client
                    .admitted
                    .extend(result.iter().filter_map(|(network, state)| {
                        matches!(state, RouteState::Installed).then_some(*network)
                    }));
                states.extend(result);
            }
            Err(error) => {
                tracing::warn!(%error, "mesh subnet routes could not be reconciled");
                states.extend(
                    client
                        .wanted
                        .iter()
                        .map(|network| (*network, RouteState::Failed(error.to_string()))),
                );
            }
        }
        client.states = states;
    }
}
