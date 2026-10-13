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
    pub fn take(&mut self) -> VecDeque<Datagram> {
        self.bytes = 0;
        std::mem::take(&mut self.datagrams)
    }
}

pub(super) struct Peer {
    pub id: u64,
    pub alternate: SocketAddr,
    pub physical: SocketAddr,
    pub binding: Option<u64>,
    pub local: Option<IpAddr>,
    pub recent: Recent,
}
#[derive(Default)]
pub(super) struct Peers {
    pub logical: HashMap<SocketAddr, Peer>,
    pub alternate: HashMap<SocketAddr, SocketAddr>,
}
impl Peers {
    pub fn insert(&mut self, id: u64, logical: SocketAddr, alternate: SocketAddr) -> bool {
        if self.logical.len() >= 10_000
            || self.logical.contains_key(&logical)
            || self.alternate.contains_key(&alternate)
            || self.logical.contains_key(&alternate)
            || self.alternate.contains_key(&logical)
        {
            return false;
        }
        self.alternate.insert(alternate, logical);
        self.logical.insert(
            logical,
            Peer {
                id,
                alternate,
                physical: logical,
                binding: None,
                local: None,
                recent: Recent::default(),
            },
        );
        true
    }
    pub fn remove(&mut self, logical: SocketAddr, id: u64) {
        if self.logical.get(&logical).is_some_and(|peer| peer.id == id)
            && let Some(peer) = self.logical.remove(&logical)
        {
            self.alternate.remove(&peer.alternate);
        }
    }
}

#[cfg(test)]
mod tests {
    //! GSO batches remain within both replay bounds even when many old packets must retire.
    use super::*;
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
