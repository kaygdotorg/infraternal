//! Converts GotaTun peer snapshots into mesh counters and confirmed paths.

use crate::policy::model::PublicKey;
#[cfg(all(unix, feature = "engine"))]
use gotatun::device::configure::PeerStats;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(all(unix, feature = "engine"))]
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Peer statistics use the same public shape as the Linux kernel adapter.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    /// Configured keepalive interval in seconds, or zero when disabled.
    #[serde(default)]
    pub persistent_keepalive_secs: u16,
    /// Last handshake time as Unix seconds, or zero before the first handshake.
    pub handshake_secs: u64,
    /// Subsecond part of the handshake time used by relay decisions.
    #[cfg(feature = "relay")]
    #[serde(skip)]
    pub handshake_nanos: u32,
    /// Bytes received from this peer.
    pub received_bytes: u64,
    /// Bytes sent to this peer.
    pub sent_bytes: u64,
    /// Last endpoint reported by the device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<std::net::SocketAddr>,
}

/// Peer counters indexed by device key.
pub type CounterMap = BTreeMap<PublicKey, Counters>;

/// Return one authenticated address per active installed key.
#[cfg(all(unix, feature = "engine"))]
#[must_use]
pub fn confirmed_endpoints(peers: Vec<PeerStats>) -> Vec<(PublicKey, SocketAddr)> {
    peers
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

/// Convert the engine's relative handshake times and byte counts to public counters.
#[cfg(all(unix, feature = "engine"))]
#[must_use]
pub fn counters(peers: Vec<PeerStats>) -> CounterMap {
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
    counters
}
