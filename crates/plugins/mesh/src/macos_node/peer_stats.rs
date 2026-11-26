//! Reads the live Mac device's per-peer statistics on the worker: the counters the node
//! reports to the coordinator, and the endpoints `GotaTun` confirmed, which the worker hands to
//! the handshake admission guard when they change (J736, J1253).
//!
//! These run on the worker's current-thread runtime, which also carries the packet path, so each
//! is one `peers()` read of the device and no blocking work.

use super::{CounterMap, Counters, RuntimeState};
use crate::policy::model::PublicKey;
use std::{
    io,
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

impl RuntimeState {
    /// Give the admission guard the endpoints `GotaTun` confirmed for active installed peers.
    ///
    /// A peer that roamed (a NAT rebinding, a new network) is confirmed at its new address by
    /// its first authenticated packet there, before the coordinator publishes that address.
    /// Feeding it in lets the peer keep the guard's reserved budget under a flood (J717, J736).
    /// Only keys with allowed IPs count, like the Linux scan: an overlap key that no longer
    /// routes has no path to vouch for. With no device the list is emptied. The shared feed
    /// takes the guard's write lock only on a change. The worker calls it when the engine reports
    /// a changed confirmed endpoint and after commands that change the peers.
    pub(super) async fn admit_confirmed_endpoints(&mut self) -> Vec<(PublicKey, SocketAddr)> {
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
    pub(super) async fn confirmed_peer_endpoints(&self) -> Vec<(PublicKey, SocketAddr)> {
        let Some(device) = self.device.as_ref() else {
            return Vec::new();
        };
        device
            .read(async |read| read.peers().await)
            .await
            .into_iter()
            .filter(|peer| !peer.peer.allowed_ips.is_empty())
            .filter_map(|peer| {
                let key = PublicKey(*peer.peer.public_key.as_bytes());
                peer.stats
                    .confirmed_endpoint
                    .map(|endpoint| (key, endpoint))
            })
            .collect()
    }

    /// Read every installed peer's handshake time, byte counts and endpoint.
    /// # Errors
    /// Reports a stopped device.
    pub(super) async fn counters(&self) -> io::Result<CounterMap> {
        let device = self.device.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        let peers = device.read(async |read| read.peers().await).await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut counters = CounterMap::new();
        for peer in peers {
            let age = peer.stats.last_handshake.unwrap_or_default();
            let timestamp = if peer.stats.last_handshake.is_some() {
                now.checked_sub(age).unwrap_or_default()
            } else {
                Duration::ZERO
            };
            let key = crate::policy::model::PublicKey(*peer.peer.public_key.as_bytes());
            counters.insert(
                key,
                Counters {
                    persistent_keepalive_secs: peer.peer.keepalive.unwrap_or(0),
                    handshake_secs: timestamp.as_secs(),
                    #[cfg(feature = "relay")]
                    handshake_nanos: timestamp.subsec_nanos(),
                    received_bytes: u64::try_from(peer.stats.rx_bytes).unwrap_or(u64::MAX),
                    sent_bytes: u64::try_from(peer.stats.tx_bytes).unwrap_or(u64::MAX),
                    endpoint: peer.peer.endpoint,
                },
            );
        }
        Ok(counters)
    }
}
