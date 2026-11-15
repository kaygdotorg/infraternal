//! Shares the active mesh SSH listener port with the GotaTun packet filter [D384].
//!
//! A private listener is still bound by the SSH component when TCP/22 is occupied. The filter
//! applies its address-specific destination translation after checking the peer's TCP/22 grant.
//! The fixed registry is small and preallocated so reading it never allocates on the packet path.

use std::{io, net::IpAddr, sync::RwLock};

/// The largest number of simultaneously installed mesh addresses the SSH service can publish.
const LISTENER_SLOTS: usize = 64;

/// One exact mesh address and the port currently held by its SSH listener.
#[derive(Clone, Copy)]
struct Listener {
    address: Option<IpAddr>,
    port: u16,
}

/// Empty value used to initialize or clear a listener registry slot.
const EMPTY: Listener = Listener {
    address: None,
    port: 0,
};

/// Fixed listener registry; its read path never creates or grows a collection.
static LISTENERS: RwLock<[Listener; LISTENER_SLOTS]> = RwLock::new([EMPTY; LISTENER_SLOTS]);

/// Publish the port held for one exact mesh address.
///
/// The listener is registered only after its socket is bound. A private port is safe to publish:
/// packets reach it only after the packet filter has checked the original TCP/22 grant.
///
/// # Errors
/// Returns `InvalidInput` for port zero and `AddrInUse` if this address already has a different
/// published listener. A full fixed registry returns `Other`.
pub fn publish_listener(address: IpAddr, port: u16) -> io::Result<()> {
    if port == 0 || address.is_unspecified() || address.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mesh SSH listener address or port is invalid",
        ));
    }
    let mut listeners = LISTENERS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(listener) = listeners
        .iter_mut()
        .find(|listener| listener.address == Some(address))
    {
        if listener.port != port {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "mesh SSH listener address already has a different port",
            ));
        }
        return Ok(());
    }
    let slot = listeners
        .iter_mut()
        .find(|listener| listener.address.is_none())
        .ok_or_else(|| io::Error::other("mesh SSH listener registry is full"))?;
    *slot = Listener {
        address: Some(address),
        port,
    };
    Ok(())
}

/// Clear one listener only if its address and port still match the publishing owner.
pub fn clear_listener(address: IpAddr, port: u16) {
    let mut listeners = LISTENERS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(listener) = listeners
        .iter_mut()
        .find(|listener| listener.address == Some(address) && listener.port == port)
    {
        *listener = EMPTY;
    }
}

/// Read the private listener port for one exact destination address without allocating.
#[must_use]
pub fn listener_port(address: IpAddr) -> Option<u16> {
    LISTENERS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .find(|listener| listener.address == Some(address))
        .map(|listener| listener.port)
}

#[cfg(test)]
#[path = "mesh_ssh_tests.rs"]
/// Checks publication, address isolation, and owner-scoped cleanup.
mod tests;
