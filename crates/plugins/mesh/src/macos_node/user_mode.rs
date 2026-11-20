//! The Mac node's user-mode plumbing (#146, D203 C2 as amended 2026-11-20).
//!
//! In user mode the node runs as the logged-in person and the root helper
//! ([`crate::macos_helper`]) makes the host changes: the utun's addresses and MTU, the mesh
//! prefix routes, and the resolver files. These functions turn the node's snapshot into
//! helper requests, attach the utun so the helper changes only the utun this node holds, and
//! skip a request identical to the last one that took effect on it.

use super::{Config, MacUtun};
use std::io;

/// The helper requests that already took effect on one utun.
#[derive(Default)]
pub(super) struct HelperApplied {
    /// The last `address` or `mtu` request.
    pub(super) interface: Option<crate::macos_user_mode::Request>,
    /// The last `resolver` request.
    pub(super) resolver: Option<crate::macos_user_mode::Request>,
}

/// Ask the user-mode helper to set the utun's MTU and, with a snapshot, its addresses and
/// mesh routes (#146).
///
/// The utun's own descriptor goes with the request, so the helper changes only the utun this
/// node holds. The IPv4 route covers this node and its peers ([`covering_ipv4_prefix`]); the
/// IPv6 route is the deployment's `/48`.
///
/// [`covering_ipv4_prefix`]: crate::macos_user_mode::covering_ipv4_prefix
/// # Errors
/// Reports the helper's refusal, such as a local network that overlaps the mesh.
pub(super) fn configure_through_helper(
    utun: &MacUtun,
    config: Option<&Config>,
    mtu: u16,
) -> io::Result<()> {
    use crate::macos_user_mode::{MAX_MTU, MIN_MTU, Request, covering_ipv4_prefix};
    let mtu = mtu.clamp(MIN_MTU, MAX_MTU);
    let request = match config {
        Some(config) => Request::Address {
            ipv4: config.addresses.ipv4,
            ipv4_prefix: covering_ipv4_prefix(
                config.addresses.ipv4,
                config
                    .peers
                    .values()
                    .map(|policy| policy.peer.addresses.ipv4),
            ),
            ipv6: config.addresses.ipv6,
            mtu,
        },
        None => Request::Mtu { mtu },
    };
    helper_request_once(utun, request, |applied| &mut applied.interface).map(|_| ())
}

/// Send `request` for `utun` unless the same request already took effect on it.
///
/// `slot` picks which kind of request is remembered. A failed request clears the memory, so
/// the next snapshot asks again.
/// # Errors
/// Reports the helper's refusal or an unreachable helper.
fn helper_request_once(
    utun: &MacUtun,
    request: crate::macos_user_mode::Request,
    slot: impl Fn(&mut HelperApplied) -> &mut Option<crate::macos_user_mode::Request>,
) -> io::Result<crate::macos_user_mode::Reply> {
    use std::os::fd::AsFd;
    let mut applied = utun
        .helper_applied
        .lock()
        .map_err(|_| io::Error::other("mesh helper state is poisoned"))?;
    if slot(&mut applied).as_ref() == Some(&request) {
        return Ok(crate::macos_user_mode::Reply {
            ok: true,
            ..crate::macos_user_mode::Reply::default()
        });
    }
    *slot(&mut applied) = None;
    let (reply, _) = crate::macos_helper::request(&request, Some(utun.fd.get_ref().as_fd()))?;
    *slot(&mut applied) = Some(request);
    Ok(reply)
}

/// The utun MTU in user mode: the smallest peer budget, kept within what the helper sets.
///
/// Root mode gives each peer its own host route MTU and lets the interface take the largest
/// budget. User mode has one prefix route and no per-peer MTU (#146), so the interface must
/// fit the narrowest path instead, or packets to that peer would fragment outside the tunnel.
/// IPv6 needs at least 1280 bytes on the link, so a narrower path still fragments.
pub(super) fn user_mode_interface_mtu(peer_mtus: &[u16]) -> u16 {
    peer_mtus
        .iter()
        .copied()
        .min()
        .unwrap_or(crate::macos_user_mode::MIN_MTU)
        .clamp(
            crate::macos_user_mode::MIN_MTU,
            crate::macos_user_mode::MAX_MTU,
        )
}

/// Point the system resolver for the mesh suffixes at this node's DNS listener.
///
/// Root mode writes `/etc/resolver` itself. User mode asks the helper, attaching the utun so
/// the helper can check the listener's address is on it (#146); suffixes outside the reserved
/// private-use names are refused there and logged here.
/// # Errors
/// Reports a failed resolver write or helper request.
#[cfg(feature = "mesh-dns")]
pub(super) fn configure_host_dns(
    integration: &mut crate::dns_integration::DnsIntegration,
    utun: &MacUtun,
    records: &crate::dns::Records,
) -> io::Result<()> {
    if crate::macos_helper::user_mode() {
        let request = crate::macos_user_mode::Request::Resolver {
            address: records.local_address(),
            suffixes: records.suffixes().to_vec(),
        };
        let reply = helper_request_once(utun, request, |applied| &mut applied.resolver)?;
        if !reply.refused_suffixes.is_empty() {
            tracing::warn!(
                refused = ?reply.refused_suffixes,
                "user mode points only internal and home.arpa names at the mesh resolver"
            );
        }
        return Ok(());
    }
    integration.configure(utun.name(), records, nix::unistd::Uid::effective().as_raw())
}
