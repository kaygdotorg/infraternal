//! Proves mesh DNS only ever configures systemd-resolved for its own link, in its own namespace (#584).
//!
//! On compute01 a root test ran two nodes in `unshare -m -n` namespaces. The host's
//! `/run/dbus` stayed visible, so `resolvectl dns infraternal0 ...` turned the name into the
//! namespace's ifindex (3) and the host's systemd-resolved applied mesh DNS to its own link 3
//! (`tailscale0`), and to eth0, docker0 and wt0 from other fixtures. These probes rebuild that
//! shape with nothing real behind it: `scripts/review-j1208-resolved-scope` runs each one alone
//! in throwaway user, mount, PID and network namespaces, with a fake `resolvectl` that only logs
//! its arguments and a stand-in process named like resolved. No real resolver is reachable.
//!
//! The harness prepares an owned mesh link `infraternal0` (a TUN with the infraternal agent's
//! marker) in the probe's namespace, so its index is a real one to compare against.

#![expect(
    clippy::expect_used,
    reason = "isolated review fixtures report setup failures at the exact step that failed"
)]

use super::*;

/// Where the harness's fake `resolvectl` appends one line per call.
const CALLS: &str = "/tmp/j1208/resolvectl.calls";

/// Builds a public-only DNS snapshot for node 10.254.0.1 without touching host networking.
fn records() -> Records {
    let config: crate::dataplane::Config = serde_json::from_value(serde_json::json!({
        "node": 1,
        "version": 1,
        "addresses": {"ipv4": "10.254.0.1", "ipv6": "fd01::1"},
        "default_policy": "Deny",
        "peers": {}
    }))
    .expect("public test configuration");
    Records::from_config(&config).expect("valid DNS snapshot")
}

/// The fake `resolvectl` calls so far, without the read-only `status` probes.
fn changing_calls() -> Vec<String> {
    fs::read_to_string(CALLS)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line != "status")
        .map(str::to_owned)
        .collect()
}

/// Forgets the calls logged so far, so each step checks only its own.
fn clear_calls() {
    fs::write(CALLS, "").expect("reset the fake resolvectl log");
}

/// Runs `ip` with `arguments` from the calling thread's network namespace.
fn ip(arguments: &[&str]) {
    let status = std::process::Command::new("ip")
        .args(arguments)
        .status()
        .expect("run ip");
    assert!(status.success(), "ip {arguments:?} failed");
}

/// Reads the index of `infraternal0` in the calling thread's network namespace.
fn mesh_ifindex() -> u32 {
    crate::wireguard::Device::active_link()
        .expect("read the mesh link")
        .expect("the harness created the mesh link")
        .ifindex
}

/// The incident itself: a node on a thread inside its own network namespace, with an owned mesh
/// link of the same name and the same index as the outer one, must not reach the resolved that
/// lives outside, neither to install nor to revert, and must not fall back to host files.
#[test]
#[ignore = "MESH_REVIEW_PROBE: run with scripts/review-j1208-resolved-scope in throwaway namespaces."]
fn review_j1208_foreign_namespace_never_reaches_resolved() {
    let outer_index = mesh_ifindex();
    let hosts_before = fs::read_to_string(HOSTS_PATH).unwrap_or_default();
    clear_calls();
    let (error, state, removed, inner_index) = std::thread::spawn(|| {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).expect("a private netns");
        ip(&["link", "set", "lo", "up"]);
        ip(&["tuntap", "add", "dev", "infraternal0", "mode", "tun"]);
        ip(&[
            "link",
            "set",
            "dev",
            "infraternal0",
            "alias",
            "infraternal.mesh.gotatun.v1",
        ]);
        let inner_index = mesh_ifindex();
        let mut integration = DnsIntegration::default();
        let error = integration.configure("infraternal0", &records(), 0).err();
        let state = integration.state();
        let removed = integration.remove();
        (error, state, removed, inner_index)
    })
    .join()
    .expect("probe thread");
    println!("J1208_OUTER_IFINDEX={outer_index} J1208_INNER_IFINDEX={inner_index}");
    println!("J1208_FOREIGN_CALLS={:?}", changing_calls());
    println!("J1208_FOREIGN_ERROR={error:?}");
    assert!(
        changing_calls().is_empty(),
        "a node in a foreign network namespace changed resolved: {:?}",
        changing_calls()
    );
    let error = error.expect("configure from a foreign namespace must report the refusal");
    assert!(
        error.to_string().contains("network namespace"),
        "the refusal names the cause: {error}"
    );
    assert_eq!(state.mode, "unavailable");
    removed.expect("removing nothing succeeds");
    assert!(
        changing_calls().is_empty(),
        "remove reverted a link that is not ours"
    );
    assert_eq!(
        fs::read_to_string(HOSTS_PATH).unwrap_or_default(),
        hosts_before,
        "a refused node must not fall back to the host's /etc/hosts"
    );
}

/// In resolved's own namespace the owned link is configured by its proven index, never by name,
/// and stop reverts exactly that index.
#[test]
#[ignore = "MESH_REVIEW_PROBE: run with scripts/review-j1208-resolved-scope in throwaway namespaces."]
fn review_j1208_owned_link_is_addressed_by_index_and_reverted_alone() {
    let index = mesh_ifindex().to_string();
    clear_calls();
    let mut integration = DnsIntegration::default();
    integration
        .configure("infraternal0", &records(), 0)
        .expect("the owned link in resolved's namespace is configured");
    println!("J1208_OWNED_CALLS={:?}", changing_calls());
    assert_eq!(
        changing_calls(),
        [
            format!("default-route {index} no"),
            format!("dns {index} 10.254.0.1:1053"),
            format!("domain {index} ~internal"),
        ]
    );
    assert_eq!(integration.state().mode, "resolved");
    clear_calls();
    integration
        .configure("infraternal0", &records(), 0)
        .expect("an unchanged snapshot is a no-op");
    assert!(changing_calls().is_empty(), "{:?}", changing_calls());
    integration.remove().expect("stop");
    assert_eq!(changing_calls(), [format!("revert {index}")]);
}

/// A link with the mesh name that the infraternal agent did not create (no marker) is refused,
/// and so is a missing link; neither reaches resolved or falls back to host files.
#[test]
#[ignore = "MESH_REVIEW_PROBE: run with scripts/review-j1208-resolved-scope in throwaway namespaces."]
fn review_j1208_unowned_or_missing_link_is_refused() {
    let hosts_before = fs::read_to_string(HOSTS_PATH).unwrap_or_default();
    ip(&[
        "link",
        "set",
        "dev",
        "infraternal0",
        "alias",
        "someone-else",
    ]);
    clear_calls();
    let mut integration = DnsIntegration::default();
    let unowned = integration
        .configure("infraternal0", &records(), 0)
        .expect_err("an unmarked link with the mesh name is not ours");
    println!("J1208_UNOWNED_ERROR={unowned}");
    assert!(changing_calls().is_empty(), "{:?}", changing_calls());

    ip(&["link", "del", "dev", "infraternal0"]);
    let missing = integration
        .configure("infraternal0", &records(), 0)
        .expect_err("a missing mesh link is refused");
    println!("J1208_MISSING_ERROR={missing}");
    assert!(changing_calls().is_empty(), "{:?}", changing_calls());
    integration.remove().expect("removing nothing succeeds");
    assert!(changing_calls().is_empty(), "{:?}", changing_calls());
    assert_eq!(
        fs::read_to_string(HOSTS_PATH).unwrap_or_default(),
        hosts_before
    );
}

/// When the mesh link disappears after install, stop must not revert whatever now holds the
/// remembered index; resolved already forgot the vanished link's settings.
#[test]
#[ignore = "MESH_REVIEW_PROBE: run with scripts/review-j1208-resolved-scope in throwaway namespaces."]
fn review_j1208_vanished_link_is_not_reverted() {
    clear_calls();
    let mut integration = DnsIntegration::default();
    integration
        .configure("infraternal0", &records(), 0)
        .expect("install on the owned link");
    ip(&["link", "del", "dev", "infraternal0"]);
    clear_calls();
    integration.remove().expect("stop after the link vanished");
    assert!(changing_calls().is_empty(), "{:?}", changing_calls());
}
