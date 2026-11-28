//! Portable userspace mesh engine components.

/// Stage and check incoming configuration chunks.
pub mod config;
/// Bind the Apple userspace device socket.
#[cfg(target_vendor = "apple")]
pub mod udp;
/// Transfer IP packets through an owned utun.
#[cfg(target_vendor = "apple")]
pub mod utun;

/// Run the userspace device behind host networking operations.
#[cfg(target_vendor = "apple")]
pub mod runtime;

/// Restore, configure, and stop the userspace mesh node.
#[cfg(target_vendor = "apple")]
pub mod node;
