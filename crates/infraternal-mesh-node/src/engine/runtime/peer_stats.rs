//! Reads the live Mac device's per-peer statistics on the worker: the counters the node
//! reports to the coordinator, and the endpoints `GotaTun` confirmed, which the worker hands to
//! the handshake admission guard when they change (J736, J1253).
//!
//! These run on the worker's current-thread runtime, which also carries the packet path, so each
//! is one `peers()` read of the device and no blocking work.

use super::{CounterMap, HostNet, RuntimeState};
use crate::peer_stats;
use crate::policy::model::PublicKey;
use std::{io, net::SocketAddr};

impl<H: HostNet> RuntimeState<H> {
    /// Give the admission guard the endpoints `GotaTun` confirmed for active installed peers.
    ///
    /// A peer that roamed (a NAT rebinding, a new network) is confirmed at its new address by
    /// its first authenticated packet there, before the coordinator publishes that address.
    /// Feeding it in lets the peer keep the guard's reserved budget under a flood (J717, J736).
    /// Only keys with allowed IPs count, like the Linux scan: an overlap key that no longer
    /// routes has no path to vouch for. With no device the list is emptied. The shared feed
    /// takes the guard's write lock only on a change. The worker calls it when the engine reports
    /// a changed confirmed endpoint and after commands that change the peers.
    pub async fn admit_confirmed_endpoints(&mut self) -> Vec<(PublicKey, SocketAddr)> {
        let endpoints = self.confirmed_peer_endpoints().await;
        self.confirmed_feed
            .offer(
                &self.admission,
                endpoints.iter().map(|(_, endpoint)| *endpoint),
            )
            .await;
        endpoints
    }

    /// One authenticated address per active installed key, shared by admission and subnet routing.
    pub async fn confirmed_peer_endpoints(&self) -> Vec<(PublicKey, SocketAddr)> {
        let Some(device) = self.device.as_ref() else {
            return Vec::new();
        };
        peer_stats::confirmed_endpoints(device.read(async |read| read.peers().await).await)
    }

    /// Read every installed peer's handshake time, byte counts and endpoint.
    /// # Errors
    /// Reports a stopped device.
    pub async fn counters(&self) -> io::Result<CounterMap> {
        let device = self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let peers = device.read(async |read| read.peers().await).await;
        Ok(peer_stats::counters(peers))
    }
}
