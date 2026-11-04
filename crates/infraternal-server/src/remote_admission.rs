//! Bounds simultaneous anonymous work by canonical source address; weak buckets release capacity without a cleanup task [40][168], #78.
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
/// Buckets retain only weak references between requests; the map itself is bounded.
pub(crate) struct SourceSlots {
    limit: usize,
    buckets: Mutex<HashMap<IpAddr, Weak<Semaphore>>>,
}
impl SourceSlots {
    /// Creates a limiter that allows at most `limit` simultaneous holders per source address.
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            buckets: Mutex::default(),
        }
    }
    /// Takes one slot for `address`, or returns `None` when that source is at its
    /// limit or the table of tracked sources (4096) is full of live ones. Drop the permit
    /// to give the slot back. IPv4-mapped IPv6 addresses count as their IPv4 address, and
    /// ports are not part of the key, so one host cannot multiply its quota. Finished
    /// sources are pruned only when the table fills up.
    pub(crate) fn reserve(&self, address: IpAddr) -> Option<OwnedSemaphorePermit> {
        let address = match address {
            IpAddr::V6(v) => v.to_ipv4_mapped().map_or(IpAddr::V6(v), IpAddr::V4),
            v @ IpAddr::V4(_) => v,
        };
        let mut buckets = self.buckets.lock().ok()?;
        let semaphore = if let Some(semaphore) = buckets.get(&address).and_then(Weak::upgrade) {
            semaphore
        } else {
            if buckets.len() >= 4096 {
                buckets.retain(|_, bucket| bucket.strong_count() > 0);
            }
            if buckets.len() >= 4096 {
                return None;
            }
            let semaphore = Arc::new(Semaphore::new(self.limit));
            buckets.insert(address, Arc::downgrade(&semaphore));
            semaphore
        };
        semaphore.try_acquire_owned().ok()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ports_do_not_change_source_capacity_and_mapped_addresses_share_it() {
        let slots = SourceSlots::new(1);
        let permit = slots.reserve("127.0.0.1".parse().unwrap()).unwrap();
        assert!(slots.reserve("::ffff:127.0.0.1".parse().unwrap()).is_none());
        assert!(slots.reserve("127.0.0.2".parse().unwrap()).is_some());
        drop(permit);
        assert!(slots.reserve("127.0.0.1".parse().unwrap()).is_some());
        for address in 1..10000u32 {
            drop(slots.reserve(IpAddr::V4(address.into())));
        }
        assert!(slots.buckets.lock().unwrap().len() <= 4096);
    }
    /// Measures hot-path admission with 1000 concurrently represented sources.
    #[test]
    #[ignore = "optimized source admission diagnostic; no own build overlap"]
    fn source_admission_cost_at_1000_sources() {
        let slots = SourceSlots::new(2);
        let permits: Vec<_> = (1..=1000u32)
            .map(|address| slots.reserve(IpAddr::V4(address.into())).unwrap())
            .collect();
        let address = IpAddr::V4(1u32.into());
        let start = std::time::Instant::now();
        for _ in 0..100_000 {
            drop(slots.reserve(address).unwrap());
        }
        let ns = start.elapsed().as_nanos() / 100_000;
        let buckets = slots.buckets.lock().unwrap();
        let payload = buckets.capacity() * std::mem::size_of::<(IpAddr, Weak<Semaphore>)>()
            + 1000 * (std::mem::size_of::<Semaphore>() + 2 * std::mem::size_of::<usize>());
        println!(
            "source_admission sources={} samples=100000 mean_ns={ns} map_capacity={} payload_bytes_excluding_allocator_and_hash_control={payload} machine={} cores={} load={}",
            permits.len(),
            buckets.capacity(),
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            std::thread::available_parallelism().unwrap(),
            std::fs::read_to_string("/proc/loadavg").unwrap().trim()
        );
    }
}
