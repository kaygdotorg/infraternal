//! Exercises restart cleanup and unavailable resolver diagnostics in a disposable mount namespace (#483).

use super::*;

/// Builds a public-only DNS snapshot without starting a mesh node or touching host networking.
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

/// A process restart must not strand its marked forwarding file after losing the in-memory record.
#[test]
#[ignore = "Run in a disposable user/network/mount namespace with a private /etc."]
fn review_j519_restart_cleanup_removes_owned_file() {
    let directory = Path::new(NETWORKMANAGER_DNSMASQ_DIRECTORY);
    fs::create_dir_all(directory).expect("private resolver directory");
    let path = directory.join(NETWORKMANAGER_MESH_DNS_FILE);
    fs::write(
        &path,
        format!("{NETWORKMANAGER_MESH_DNS_MARKER}\nserver=/internal/10.254.0.9#1053\n"),
    )
    .expect("simulate the previous process's owned forwarding file");
    let mut integration = DnsIntegration::default();
    integration.remove().expect("first cleanup");
    integration.remove().expect("idempotent cleanup");
    assert!(
        !path.exists(),
        "restart cleanup stranded a marked forwarding file"
    );
}

/// Missing resolver tools must produce an actionable error instead of caching apparent success.
#[test]
#[ignore = "Run in a disposable user/network/mount namespace with resolver binaries hidden."]
fn review_j519_missing_tools_are_reported() {
    assert!(trusted_program(RESOLVECTL_PATHS).is_none());
    assert!(trusted_program(NMCLI_PATHS).is_none());
    let mut integration = DnsIntegration::default();
    let error = integration
        .configure("infraternal0", &records(), 0)
        .expect_err("missing resolver tools must not silently disable host mesh DNS");
    assert!(error.to_string().contains("nmcli") || error.to_string().contains("resolvectl"));
}
