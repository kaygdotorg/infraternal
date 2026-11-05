//! Shutdown steps that components hand to the infraternal agent [#221].
//!
//! Some components change host state that must not outlive the process: mesh
//! SSH installs owned firewall rules that redirect a mesh address's TCP/22.
//! The registry that owns a component lives for the whole process and is not
//! dropped on exit, so `Drop` cannot remove that state. Instead a component
//! gives the infraternal agent a [`StopHook`], and the agent runs every live
//! hook as it shuts down, before the process ends.
//!
//! A hook is a [`Weak`] reference, so handing one out never keeps a finished
//! component alive, and the agent can forget hooks whose component is gone.

use std::{future::Future, pin::Pin, sync::Weak};

/// One component's shutdown step.
pub trait Stop: Send + Sync {
    /// Release host state that must not outlive the infraternal agent, and
    /// finish once it is released. After this starts, the component must not
    /// create such state again. The agent bounds how long it waits.
    fn stop(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// What a component hands to the infraternal agent; see [`Stop`].
pub type StopHook = Weak<dyn Stop>;
