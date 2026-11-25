//! The device-level switch for `GotaTun`'s second ("side") UDP socket (#260, J1211).
//!
//! A node that runs `GotaTun` binds a second socket beside its mesh port and sends small data
//! datagrams to capable peers from it, so the sending host's flow-fair qdisc gives them their
//! own flow instead of queueing them behind our own bulk to the same peer. The node also listens
//! on that second socket, as insurance for a peer that reaches it anyway.
//!
//! **On by default** for every node that runs `GotaTun`, Linux and macOS alike. `INFRATERNAL_MESH_SIDE_SOCKET=off`
//! (or `0`) turns it off for one node: it then binds no second socket, sends no marks, and does
//! not advertise the capability to its peers.
//!
//! **Per peer, never by default.** A marked datagram is dropped by kernel `WireGuard` and by a
//! plain `GotaTun` (J1159 measured 71.7% ping loss to kernel `WireGuard` under bulk). So a node
//! sends marks only to a peer whose own node said, through the coordinator, that it runs the
//! receive rule (`Peer::side_port`). Everything else is sent exactly as with one socket.

/// The environment variable that turns the second socket off for this node.
const SWITCH: &str = "INFRATERNAL_MESH_SIDE_SOCKET";

/// Whether this node's `GotaTun` binds and uses the second socket, read once.
///
/// The kernel `WireGuard` engine has no second socket; callers that know the engine combine this
/// with it before advertising anything.
pub(crate) fn enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| parse(std::env::var(SWITCH).ok().as_deref()))
}

/// Read the switch's value: only an explicit `off` or `0` turns the second socket off.
fn parse(value: Option<&str>) -> bool {
    !matches!(value.map(str::trim), Some("off" | "0"))
}

/// Tests for the switch's parsing.
#[cfg(test)]
mod tests {
    use super::parse;

    /// The second socket is on unless the operator says `off` or `0`.
    #[test]
    fn only_an_explicit_off_turns_it_off() {
        assert!(parse(None));
        assert!(parse(Some("on")));
        assert!(parse(Some("1")));
        assert!(parse(Some("")));
        assert!(!parse(Some("off")));
        assert!(!parse(Some(" 0 ")));
    }
}
