//! Checks NetworkManager's DNS-only reload and mesh suffix forwarding contract (#266).
#![allow(clippy::expect_used)]
use super::*;

/// Install and cleanup reload DNS without naming or reapplying the mesh device.
#[test]
fn review_j354_networkmanager_dns_reload_is_dns_only() {
    assert_eq!(
        networkmanager_route_commands(),
        vec![vec![
            "general".to_owned(),
            "reload".to_owned(),
            "dns-full".to_owned(),
        ]]
    );
    assert_eq!(
        networkmanager_clear_commands(),
        networkmanager_route_commands()
    );
}

/// Mesh queries use the high-port listener while `NetworkManager` keeps host search and upstreams.
#[test]
fn review_j254_dnsmasq_config_contains_only_mesh_suffix_routes() {
    let config = render_networkmanager_dnsmasq_config(
        Ipv4Addr::new(10, 254, 0, 2),
        &["internal".to_owned(), "mesh.kayg.org".to_owned()],
    )
    .expect("valid mesh suffixes");

    assert_eq!(
        config,
        format!(
            "{NETWORKMANAGER_MESH_DNS_MARKER}\nserver=/internal/10.254.0.2#1053\nserver=/mesh.kayg.org/10.254.0.2#1053\n"
        )
    );
    assert!(!config.contains("no-resolv"));
    assert!(!config.contains("search="));
}
