//! Break-it review of the "Copy commands" text a failed host uninstall hands the owner (#235).
//!
//! The person pastes these into a root or account shell on a machine the server
//! can no longer see. They must delete no more than the automatic cleanup would:
//! only an installation whose `.bootstrap-owner` names this host, and only a mesh
//! interface or packet filter carrying our ownership marker.
use super::outcome;

fn manual(mode: &str) -> String {
    outcome("unreachable", mode, "host.example").1.unwrap()
}

/// The server machine joins its own mesh (D239) with the same interface name;
/// another tool may own an `infraternal0` too. An unconditional delete of the
/// name takes that link (and the server's mesh address) down.
#[test]
fn review_manual_rootful_commands_delete_only_marked_kernel_objects() {
    let commands = manual("rootful");
    assert!(
        !commands.contains("ip link delete infraternal0;")
            && !commands.contains("nft delete table inet infraternal_mesh;"),
        "the copied commands delete any interface or table with our name: {commands}"
    );
}

/// `~/.local/share/infraternal` is also the XDG parent of the server's CA
/// (`infraternal/ca`) and a joined node's data (`infraternal/agent`). The
/// commands are shown for every unreachable host, bootstrap-installed or not;
/// an unconditional `rm -rf` of the parent wipes those on a shared account.
#[test]
fn review_manual_commands_are_gated_on_this_hosts_bootstrap_owner() {
    for mode in ["rootful", "rootless"] {
        let commands = manual(mode);
        assert!(
            commands.contains(".bootstrap-owner"),
            "{mode}: rm -rf runs without checking the installation is this host's: {commands}"
        );
    }
}

/// Session scopes are named per session, not per installation. Stopping every
/// `infraternal-session-*` unit also ends terminals of any other infraternal
/// agent under the same manager (the server's embedded one, a joined node).
#[test]
fn review_manual_commands_stop_only_this_installations_sessions() {
    for mode in ["rootful", "rootless"] {
        let commands = manual(mode);
        assert!(
            !commands.contains("stop 'infraternal-session-*.scope'"),
            "{mode}: stops every infraternal session on the machine: {commands}"
        );
    }
}
