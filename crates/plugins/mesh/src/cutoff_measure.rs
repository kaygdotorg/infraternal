//! Opt-in cutoff stage diagnostics for locked-VM benchmarks (`INFRATERNAL_CUTOFF_MEASURE=1`); shipping builds retain no timer or logger [242,256].
use crate::policy::model::NodeId;
use std::{io::Write as _, time::Instant};

/// A scoped measurement records only public node/revision coordinates and a static stage label.
pub(crate) struct Stage {
    node: NodeId,
    version: u64,
    phase: &'static str,
    started: Option<Instant>,
}
impl Stage {
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
