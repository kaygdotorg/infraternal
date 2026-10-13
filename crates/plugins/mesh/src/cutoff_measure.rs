//! Opt-in cutoff stage diagnostics for locked-VM benchmarks; shipping builds retain no timer or logger [242,256].
use crate::policy::model::NodeId;
use std::{io::Write as _, time::Instant};

/// A scoped measurement records only public node/revision coordinates and a static stage label.
pub(crate) struct Stage {
    node: NodeId,
    version: u64,
    phase: &'static str,
    started: Instant,
}
impl Stage {
    pub(crate) fn new(node: NodeId, version: u64, phase: &'static str) -> Self {
        Self {
            node,
            version,
            phase,
            started: Instant::now(),
        }
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = writeln!(
            std::io::stderr(),
            "CUTOFF_STAGE node={} version={} phase={} us={}",
            self.node.0,
            self.version,
            self.phase,
            self.started.elapsed().as_micros()
        );
    }
}
