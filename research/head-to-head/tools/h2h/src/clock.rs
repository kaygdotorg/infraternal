//! CLOCK_MONOTONIC in nanoseconds. Network namespaces share this clock, so a
//! timestamp taken in one namespace is comparable with one taken in another on
//! the same machine: that is what makes one-way latency measurable here.
/// Read the shared monotonic clock in nanoseconds for same-host probes.
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes into the provided timespec only.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Return elapsed milliseconds from a timestamp produced by `now_ns`.
pub fn ms_since(start_ns: u64) -> f64 {
    (now_ns().saturating_sub(start_ns)) as f64 / 1e6
}
