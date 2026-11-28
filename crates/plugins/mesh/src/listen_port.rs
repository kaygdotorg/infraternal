//! Reads the mesh listener override from the host environment.

use std::io;

/// Default UDP port used by the Linux node.
#[cfg(target_os = "linux")]
pub(crate) use infraternal_mesh_node::listen_port::DEFAULT_PORT;
/// Preferred port and fallback policy consumed by the host listener.
pub(crate) use infraternal_mesh_node::listen_port::Request;
use infraternal_mesh_node::listen_port::requested;

/// Read the optional mesh UDP override and combine it with the last default-selected port.
///
/// The override is `INFRATERNAL_MESH_PORT`. It is an exact operator choice; only an absent
/// override allows the listener to fall back when its port is already occupied.
/// # Errors
/// Refuses a non-UTF-8, malformed, zero, or reserved port before the node starts.
pub(crate) fn from_environment(saved: Option<u16>) -> io::Result<Request> {
    let configured = match std::env::var_os("INFRATERNAL_MESH_PORT") {
        Some(value) => Some(
            value
                .into_string()
                .map_err(|_| io::ErrorKind::InvalidInput)?,
        ),
        None => None,
    };
    requested(configured.as_deref(), saved)
}
