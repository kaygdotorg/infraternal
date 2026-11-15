//! Reads the live Mac device's per-peer statistics on the worker: the counters the node
//! reports to the coordinator.
//!
//! These run on the worker's current-thread runtime, which also carries the packet path, so each
//! is one `peers()` read of the device and no blocking work.

use super::{CounterMap, Counters, RuntimeState};
use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

impl RuntimeState {
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
