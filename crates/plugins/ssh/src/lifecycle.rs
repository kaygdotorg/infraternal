//! Owns admission and cancellation for one node's SSH component without idle work [198].
//!
//! The SSH component can be switched on and off. While on, each piece of work
//! takes an [`Activity`] lease; while off, no new lease or batch is admitted.
//! Turning it off cancels registered batches and then waits until every lease is
//! dropped, so "off" really means no SSH work is still running. No background
//! task polls; waiting is done on watch channels.

use crate::bootstrap::{BatchInner, lock};
use infraternal_plugin_api::{PluginState, PluginStatus};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{Mutex as AsyncMutex, watch};

/// Mutable lifecycle facts, always read and written under one lock.
struct State {
    /// Whether new work is admitted.
    enabled: bool,
    /// Number of live [`Activity`] leases.
    active: usize,
    /// Batches to cancel on disable; weak, so finished batches do not linger.
    batches: Vec<Weak<BatchInner>>,
}

/// Shared by host attempts and their server adapters; construction performs no I/O.
pub(crate) struct Lifecycle {
    /// Enabled flag, lease count and batches.
    state: Mutex<State>,
    /// Serializes `set_enabled` calls so enable and disable do not interleave.
    control: AsyncMutex<()>,
    /// Broadcasts the enabled flag to adapters.
    enabled: watch::Sender<bool>,
    /// Broadcasts the lease count so a disable can wait for zero.
    active: watch::Sender<usize>,
}
impl Lifecycle {
    /// A new lifecycle that starts enabled, with no leases.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                enabled: true,
                active: 0,
                batches: Vec::new(),
            }),
            control: AsyncMutex::new(()),
            enabled: watch::channel(true).0,
            active: watch::channel(0).0,
        })
    }
    /// Take a lease for one unit of work; refused with a message while disabled.
    pub(crate) fn admit(self: &Arc<Self>) -> Result<Activity, &'static str> {
        let mut state = lock(&self.state);
        if !state.enabled {
            return Err("SSH host provisioning is off.");
        }
        state.active += 1;
        self.active.send_replace(state.active);
        Ok(Activity(self.clone()))
    }
    /// Remember a batch so that disabling cancels it; refused while disabled.
    /// Holds only a weak reference and prunes dead ones.
    pub(crate) fn register(&self, batch: &Arc<BatchInner>) -> Result<(), &'static str> {
        let mut state = lock(&self.state);
        if !state.enabled {
            return Err("SSH host provisioning is off.");
        }
        state.batches.retain(|entry| entry.strong_count() > 0);
        state.batches.push(Arc::downgrade(batch));
        Ok(())
    }
    /// Watch the enabled flag; adapters drop their lease when it turns false.
    pub(crate) fn subscribe(&self) -> watch::Receiver<bool> {
        self.enabled.subscribe()
    }
    /// `On` when enabled; otherwise `Stopping` while leases remain, else `Off`.
    pub(crate) fn status(&self) -> PluginStatus {
        let state = lock(&self.state);
        PluginStatus {
            state: if state.enabled {
                PluginState::On
            } else if state.active == 0 {
                PluginState::Off
            } else {
                PluginState::Stopping
            },
            active_work: state.active,
        }
    }
    /// Turn the component on or off.
    ///
    /// Disabling closes admission at once, cancels registered batches and returns
    /// only after all leases are gone. Enabling first waits for any previous
    /// lifetime's leases to drain, so old and new work never overlap. Enabling
    /// while already on does nothing.
    pub(crate) async fn set_enabled(&self, enabled: bool) {
        let _control = self.control.lock().await;
        if enabled && self.status().state == PluginState::On {
            return;
        }
        if !enabled {
            let mut state = lock(&self.state);
            state.enabled = false;
            self.enabled.send_replace(false);
            for entry in state.batches.drain(..) {
                if let Some(batch) = entry.upgrade() {
                    batch.cancel.send_replace(true);
                }
            }
        }
        // A dropped disable future still leaves admission closed. Re-enabling
        // also drains the previous lifetime before any new work can be admitted.
        let mut active = self.active.subscribe();
        if self.status().state != PluginState::On {
            loop {
                if *active.borrow_and_update() == 0 {
                    break;
                }
                if active.changed().await.is_err() {
                    return;
                }
            }
        }
        if enabled {
            let mut state = lock(&self.state);
            state.enabled = true;
            self.enabled.send_replace(true);
        }
    }
}

/// Holds a component lifetime until its attempt, confirmation or socket has retired.
/// Adapters must observe `Bootstrap::enabled_changes` and drop their lease when off.
/// Dropping releases the lease and wakes any waiting disable.
pub struct Activity(Arc<Lifecycle>);
impl Drop for Activity {
    fn drop(&mut self) {
        let mut state = lock(&self.0.state);
        state.active -= 1;
        self.0.active.send_replace(state.active);
    }
}
