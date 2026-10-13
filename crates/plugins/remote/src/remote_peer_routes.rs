//! Leases trusted alternative peer tuples and bounded encrypted replay below the existing QUIC endpoint [198,215,263], #201.
use quinn::udp::{EcnCodepoint, Transmit};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
};

const MAX_BYTES: usize = 64 * 1024;
const MAX_DATAGRAMS: usize = 64;

#[derive(Clone)]
pub(super) struct Datagram {
    pub contents: Vec<u8>,
    pub segment_size: Option<usize>,
    pub ecn: Option<EcnCodepoint>,
}

#[derive(Default)]
pub(super) struct Recent {
    datagrams: VecDeque<Datagram>,
    bytes: usize,
}
impl Recent {
    pub fn keep(&mut self, transmit: &Transmit<'_>) {
        if transmit.contents.len() > MAX_BYTES {
            return;
        }
        while self.datagrams.len() >= MAX_DATAGRAMS
            || self.bytes + transmit.contents.len() > MAX_BYTES
        {
            let Some(old) = self.datagrams.pop_front() else {
                break;
            };
            self.bytes -= old.contents.len();
        }
        self.bytes += transmit.contents.len();
        self.datagrams.push_back(Datagram {
            contents: transmit.contents.to_vec(),
            segment_size: transmit.segment_size,
            ecn: transmit.ecn,
        });
    }
    pub fn clear(&mut self) {
        self.bytes = 0;
        self.datagrams.clear();
    }
    pub fn take(&mut self) -> VecDeque<Datagram> {
        self.bytes = 0;
        std::mem::take(&mut self.datagrams)
    }
}

pub(super) struct Peer {
    pub id: u64,
    pub logical: SocketAddr,
    pub alternate: SocketAddr,
    pub physical: SocketAddr,
    pub binding: Option<u64>,
    pub local: Option<IpAddr>,
    pub recent: Recent,
}
/// Both trusted tuple keys share one bounded slot. Use the same address/u64
/// map representation as reply routing rather than monomorphising separate
/// maps for full peer state and alternative addresses. Slot reuse never
/// reuses a lease identity, so a stale drop cannot retire a replacement.
#[derive(Default)]
pub(super) struct Peers {
    keys: HashMap<SocketAddr, u64>,
    slots: Vec<Option<Peer>>,
    free: Vec<usize>,
    count: usize,
}
impl Peers {
    pub fn len(&self) -> usize {
        self.count
    }
    fn index(&self, address: SocketAddr) -> Option<usize> {
        usize::try_from(*self.keys.get(&address)?).ok()
    }
    #[cfg(test)]
    pub fn logical_for(&self, physical: SocketAddr) -> SocketAddr {
        self.index(physical)
            .and_then(|index| self.slots.get(index)?.as_ref())
            .map_or(physical, |peer| peer.logical)
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn get(&self, logical: SocketAddr) -> Option<&Peer> {
        self.slots
            .get(self.index(logical)?)?
            .as_ref()
            .filter(|peer| peer.logical == logical)
    }
    /// Resolve either leased tuple once, before updating its physical hint.
    pub fn by_physical(&mut self, physical: SocketAddr) -> Option<&mut Peer> {
        let index = self.index(physical)?;
        self.slots.get_mut(index)?.as_mut()
    }
    pub fn get_mut(&mut self, logical: SocketAddr) -> Option<&mut Peer> {
        let index = self.index(logical)?;
        self.slots
            .get_mut(index)?
            .as_mut()
            .filter(|peer| peer.logical == logical)
    }
    pub fn insert(&mut self, id: u64, logical: SocketAddr, alternate: SocketAddr) -> bool {
        if self.count >= 10_000
            || logical == alternate
            || self.keys.contains_key(&logical)
            || self.keys.contains_key(&alternate)
        {
            return false;
        }
        let index = self.free.last().copied().unwrap_or(self.slots.len());
        let Ok(key) = u64::try_from(index) else {
            return false;
        };
        let peer = Some(Peer {
            id,
            logical,
            alternate,
            physical: logical,
            binding: None,
            local: None,
            recent: Recent::default(),
        });
        if self.free.pop().is_some() {
            self.slots[index] = peer;
        } else {
            self.slots.push(peer);
        }
        self.keys.insert(logical, key);
        self.keys.insert(alternate, key);
        self.count += 1;
        true
    }
    pub fn remove(&mut self, logical: SocketAddr, id: u64) {
        let Some(index) = self.index(logical) else {
            return;
        };
        let slot = &mut self.slots[index];
        if !slot
            .as_ref()
            .is_some_and(|peer| peer.logical == logical && peer.id == id)
        {
            return;
        }
        if let Some(peer) = slot.take() {
            self.keys.remove(&logical);
            self.keys.remove(&peer.alternate);
            self.free.push(index);
            self.count -= 1;
        }
        // A mesh role that retires its final alias leaves no replay or slot
        // allocation behind in the otherwise still-running remote endpoint.
        if self.count == 0 {
            *self = Self::default();
        }
    }
}

#[cfg(test)]
mod tests {
    //! GSO batches remain within both replay bounds even when many old packets must retire.
    use super::*;
    #[test]
    fn retiring_an_old_lease_cannot_remove_a_reused_tuple() {
        let logical = "127.0.0.1:40001".parse().unwrap();
        let alternate = "127.0.0.2:40002".parse().unwrap();
        let mut peers = Peers::default();
        assert!(peers.insert(1, logical, alternate));
        assert_eq!(peers.logical_for(alternate), logical);
        peers.remove(logical, 1);
        assert_eq!(peers.logical_for(alternate), alternate);
        assert!(peers.insert(2, logical, alternate));
        peers.remove(logical, 1);
        assert_eq!(peers.get(logical).unwrap().id, 2);
        assert_eq!(peers.len(), 1);
        peers.remove(logical, 2);
        assert_eq!(peers.len(), 0);
        assert_eq!(peers.logical_for(alternate), alternate);
    }

    #[test]
    fn replay_is_bounded_for_large_segmented_transmits() {
        let destination = "127.0.0.1:7443".parse().unwrap();
        let mut recent = Recent::default();
        for length in [1024, 1024, 1024, 63 * 1024, 64 * 1024, 64 * 1024 + 1] {
            let bytes = vec![7; length];
            recent.keep(&Transmit {
                destination,
                contents: &bytes,
                segment_size: Some(1024),
                ecn: None,
                src_ip: None,
            });
            assert!(recent.bytes <= MAX_BYTES);
            assert!(recent.datagrams.len() <= MAX_DATAGRAMS);
        }
        let pending = recent.take();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].contents.len(), MAX_BYTES);
        assert_eq!(recent.bytes, 0);
    }
}

#[cfg(test)]
#[path = "remote_peer_routes_bench.rs"]
mod bench;
