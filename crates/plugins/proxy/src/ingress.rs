//! Serializes every writer of the Mesh firewall's proxy ingress state [#281].
//!
//! Two owners write different fields of one [`MeshProxyIngress`]. The controller writes the
//! confirmed Mesh routes and whether a public route is live. The supervisor writes the public
//! listener gate around each child's life: closed before a child can bind the wildcard pair,
//! opened once that child confirms a snapshot with a public route (so a crash restart serves
//! again on its own), and cleared once the child is reaped, so no stale gate drops a later
//! service on those ports.
//! Each update applies the whole merged value under one lock, so neither writer can undo
//! the other's field. Lock order is controller → publisher → Mesh node; the supervisor
//! thread takes only publisher → Mesh node, so the controller may wait on it safely.

use infraternal_mesh::proxy_ports::{ListenerPortPair, MeshProxyIngress};
use std::{
    io,
    sync::{Arc, Mutex},
};

/// Callback that applies one complete proxy ingress state to the Mesh packet filter.
pub type MeshIngressObserver = Arc<dyn Fn(MeshProxyIngress) -> io::Result<()> + Send + Sync>;

/// The supervisor's view of its child's wildcard public listener pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicGateState {
    /// A child is about to bind the pair: public traffic to it is dropped.
    Closed(ListenerPortPair),
    /// The child confirmed a snapshot with a public route: public traffic is admitted.
    Open(ListenerPortPair),
    /// No child holds the pair.
    Cleared,
}

/// Applies the supervisor's gate state to the Mesh packet filter.
pub type PublicGate = Arc<dyn Fn(PublicGateState) -> io::Result<()> + Send + Sync>;

#[derive(Default)]
struct Applied {
    ingress: MeshProxyIngress,
    observer: Option<MeshIngressObserver>,
}

/// The single path from the proxy to the Mesh firewall.
#[derive(Default)]
pub(crate) struct IngressPublisher {
    applied: Mutex<Applied>,
}

impl IngressPublisher {
    pub(crate) fn set_observer(&self, observer: MeshIngressObserver) -> io::Result<()> {
        self.lock()?.observer = Some(observer);
        Ok(())
    }

    pub(crate) fn current(&self) -> io::Result<MeshProxyIngress> {
        Ok(self.lock()?.ingress.clone())
    }

    /// Apply one change. A `confirmed` update reaches the firewall even when unchanged,
    /// because the firewall retires flows of sources that lost a route since its last one.
    pub(crate) fn update(
        &self,
        confirmed: bool,
        change: impl FnOnce(&mut MeshProxyIngress),
    ) -> io::Result<()> {
        let mut applied = self.lock()?;
        let mut next = applied.ingress.clone();
        change(&mut next);
        if !confirmed && next == applied.ingress {
            return Ok(());
        }
        match &applied.observer {
            Some(observer) => observer(next.clone())?,
            None if next.public_listener_pair.is_some() => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "public listener firewall gate is unavailable",
                ));
            }
            None => {}
        }
        applied.ingress = next;
        Ok(())
    }

    /// The gate callback handed to a rootful supervisor.
    ///
    /// `Open` lets a child restarted after a crash serve the public routes it already
    /// confirmed, without waiting for the next publish to mark them live again.
    pub(crate) fn public_gate(self: &Arc<Self>) -> PublicGate {
        let publisher = Arc::clone(self);
        Arc::new(move |state| {
            publisher.update(false, |ingress| {
                let (pair, live) = match state {
                    PublicGateState::Closed(pair) => (Some(pair), false),
                    PublicGateState::Open(pair) => (Some(pair), true),
                    PublicGateState::Cleared => (None, false),
                };
                ingress.public_listener_pair = pair;
                ingress.public_route_active = live;
            })
        })
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Applied>> {
        self.applied
            .lock()
            .map_err(|_| io::Error::other("proxy ingress state is unavailable"))
    }
}
