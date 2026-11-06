//! Break-it review of the "Copy commands" text a failed host uninstall hands the owner (#235).
//!
//! The person pastes these into a root or account shell on a machine the server
//! can no longer see. They must delete no more than the automatic cleanup would:
//! only an installation whose `.bootstrap-owner` names this host, and only a mesh
//! interface or packet filter carrying our ownership marker.
use super::outcome;

const HOST: &str = "0123456789abcdef0123456789abcdef";

/// Extract the ownership-checked command from a completed removal response.
fn manual(mode: &str) -> String {
    outcome("unreachable", mode, "host.example", &[], Some(HOST), false)
        .1
        .unwrap()
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
///
/// Fix (#235): the command is the installed binary's own uninstall for this
/// host id, which refuses unless `.bootstrap-owner` names it
/// (`manual_uninstall_refuses_another_hosts_installation` in the remote
/// plugin) and keeps entries setup did not create; no path is deleted by name.
#[test]
fn review_manual_commands_are_gated_on_this_hosts_bootstrap_owner() {
    for (mode, launcher) in [
        ("rootful", "/usr/local/bin/infraternal"),
        ("rootless", "~/.local/bin/infraternal"),
    ] {
        let commands = manual(mode);
        assert_eq!(
            commands,
            format!("{launcher} --bootstrap-uninstall {HOST}"),
            "{mode}: the commands do not run the ownership-checked uninstall"
        );
        assert!(!commands.contains("rm "), "{mode}: {commands}");
    }
}

/// A host infraternal setup did not install has no installation to check:
/// no commands, and the message says so.
#[test]
fn no_commands_for_a_host_setup_did_not_install() {
    let (message, manual) = outcome("unreachable", "rootless", "host.example", &[], None, false);
    assert!(manual.is_none());
    assert!(
        message.contains("infraternal setup didn't install"),
        "{message}"
    );
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

/// A kernel object the host's installation did not create is named in the
/// message, so the owner knows it stayed on purpose (#235).
#[test]
fn accepted_uninstall_names_the_objects_it_leaves() {
    let (message, manual) = outcome(
        "requested",
        "rootful",
        "host.example",
        &["infraternal0"],
        Some(HOST),
        false,
    );
    assert_eq!(
        message,
        "host.example was removed. Its infraternal agent is uninstalling itself. Left infraternal0 because infraternal didn't create it here."
    );
    assert!(manual.is_none());
}
