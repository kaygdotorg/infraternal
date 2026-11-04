//! Opt-in timing of the stages of a policy cutoff, for benchmarks on locked VMs [242,256].
//!
//! Set `INFRATERNAL_CUTOFF_MEASURE=1` to turn it on. Otherwise nothing is
//! timed and nothing is printed, so shipping builds carry no timer or logger.
//! Output goes to standard error, one line per stage, and contains only public
//! values: node number, policy version, a fixed stage name and microseconds.
use crate::policy::model::NodeId;
use std::{io::Write as _, time::Instant};

/// Times one stage of applying a policy version to one node.
///
/// Create it when the stage starts and let it drop when the stage ends. If
/// measuring is enabled, dropping it prints
/// `CUTOFF_STAGE node=<n> version=<v> phase=<name> us=<microseconds>` to
/// standard error. It records only the node number, version and a static
/// stage label, never any data.
pub(crate) struct Stage {
    node: NodeId,
    version: u64,
    phase: &'static str,
    started: Option<Instant>,
}
impl Stage {
    /// Starts timing `phase` for `node` at policy `version`. Does nothing
    /// unless `INFRATERNAL_CUTOFF_MEASURE` is exactly `1`.
    pub(crate) fn new(node: NodeId, version: u64, phase: &'static str) -> Self {
        Self {
            node,
            version,
            phase,
            started: (std::env::var_os("INFRATERNAL_CUTOFF_MEASURE").as_deref()
                == Some(std::ffi::OsStr::new("1")))
            .then(Instant::now),
        }
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let Some(started) = self.started else {
            return;
        };
        let line = format!(
            "CUTOFF_STAGE node={} version={} phase={} us={}\n",
            self.node.0,
            self.version,
            self.phase,
            started.elapsed().as_micros()
        );
        // One short write keeps concurrent node records from interleaving.
        let _ = std::io::stderr().write_all(line.as_bytes());
    }
}

/// The current `CLOCK_MONOTONIC` time in nanoseconds, so stage timings can be
/// compared with packet timestamps taken by other processes.
///
/// Returns `None` when measuring is off or the clock cannot be read. A failure
/// here only loses a diagnostic; it never changes what is enforced.
#[cfg(feature = "agent")]
pub(crate) fn monotonic_ns() -> Option<u64> {
    if std::env::var_os("INFRATERNAL_CUTOFF_MEASURE").as_deref() != Some(std::ffi::OsStr::new("1"))
    {
        return None;
    }
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).ok()?;
    u64::try_from(now.tv_sec())
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(now.tv_nsec()).ok()?)
}
