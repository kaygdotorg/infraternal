//! Exercises restart cleanup and unavailable resolver diagnostics in a disposable mount namespace (#483).

#![expect(
    clippy::expect_used,
    reason = "isolated review fixtures report setup failures at the exact step that failed"
)]

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
#[ignore = "MESH_REVIEW_PROBE: run with scripts/review-j519-dns-regressions in private /etc and Nix profile mounts."]
fn review_j519_restart_cleanup_removes_owned_file() {
    let directory = Path::new(NETWORKMANAGER_DNSMASQ_DIRECTORY);
    fs::create_dir_all(directory).expect("private resolver directory");
    let path = directory.join(NETWORKMANAGER_MESH_DNS_FILE);
    let unrelated = directory.join("unrelated.conf");
    fs::write(
        &path,
        format!("{NETWORKMANAGER_MESH_DNS_MARKER}\nserver=/internal/10.254.0.9#1053\n"),
    )
    .expect("simulate the previous process's owned forwarding file");
    fs::write(&unrelated, "server=/host/192.0.2.1\n").expect("unrelated host drop-in");
    install_nix_profile_tool("nmcli");
    install_nix_profile_tool("resolvectl");
    let mut integration = DnsIntegration::default();
    integration
        .configure("infraternal0", &records(), 0)
        .expect("a fresh process should select its current resolver");
    assert!(
        !path.exists(),
        "a fresh process left the previous resolver mode's marked drop-in behind"
    );
    integration.remove().expect("first cleanup");
    integration.remove().expect("idempotent cleanup");
    assert!(
        !path.exists(),
        "restart cleanup stranded a marked forwarding file"
    );
    assert!(
        unrelated.exists(),
        "cleanup must leave other drop-ins alone"
    );

    fs::write(&path, "server=/host/192.0.2.2\n").expect("unmarked file at the owned name");
    assert!(
        integration.remove().is_err(),
        "cleanup must refuse an unmarked file at its owned name"
    );
    assert!(path.exists(), "cleanup must preserve an unmarked file");
    fs::remove_file(path).expect("remove the test's unmarked file");
}

/// Missing resolver tools must produce an actionable error instead of caching apparent success.
#[test]
#[ignore = "MESH_REVIEW_PROBE: run with scripts/review-j519-dns-regressions in a private Nix profile mount."]
fn review_j519_missing_tools_are_reported() {
    assert!(trusted_program("resolvectl", RESOLVECTL_PATHS).is_err());
    assert!(trusted_program("nmcli", NMCLI_PATHS).is_err());
    assert!(trusted_program("NetworkManager", NETWORKMANAGER_PATHS).is_err());
    let mut integration = DnsIntegration::default();
    let error = integration
        .configure("infraternal0", &records(), 0)
        .expect_err("missing resolver tools must not silently disable host mesh DNS");
    let message = error.to_string();
    assert!(message.contains("resolvectl"));
    assert!(message.contains("looked in"));
    assert!(message.contains(RESOLVECTL_PATHS[0]));
    assert!(message.contains(RESOLVECTL_PATHS[RESOLVECTL_PATHS.len() - 1]));
    assert!(
        integration.linux.is_none(),
        "a failed setup is not a cached install"
    );
    integration
        .configure("infraternal0", &records(), 0)
        .expect_err("the next identical snapshot must retry and report missing tools");

    install_nix_profile_tool("resolvectl");
    integration
        .configure("infraternal0", &records(), 0)
        .expect("a later Nix-provided resolver must satisfy the same snapshot");
    assert!(
        matches!(
            integration.linux.as_ref().map(|install| install.mode),
            Some(LinuxMode::Resolved)
        ),
        "the retry should cache the successfully installed resolver only"
    );
}

/// A protected root Nix profile supplies the resolver when distro paths are absent.
#[test]
#[ignore = "MESH_REVIEW_PROBE: run with scripts/review-j519-dns-regressions in a private /etc and Nix profile mount."]
fn review_j519_nix_profile_tool_is_discovered() {
    let tool = install_nix_profile_tool("resolvectl");
    let expected = fs::canonicalize(&tool).expect("canonical Nix profile tool");
    assert_eq!(
        trusted_program(
            "resolvectl",
            &[
                "/root/.local/state/nix/profiles/profile/bin/resolvectl",
                "/nix/var/nix/profiles/default/bin/resolvectl",
            ],
        )
        .expect("an inaccessible profile candidate must not hide the next trusted path"),
        expected,
        "an unavailable earlier candidate must not hide a safe Nix profile tool"
    );
    assert_eq!(
        trusted_program("resolvectl", RESOLVECTL_PATHS)
            .expect("the fixed root Nix profile resolver should be trusted"),
        fs::canonicalize(&tool).expect("canonical Nix profile tool"),
        "fixed resolver candidates must include the root Nix profile"
    );

    let mut integration = DnsIntegration::default();
    integration
        .configure("infraternal0", &records(), 0)
        .expect("configure through the Nix profile resolver");
    assert_eq!(
        integration.linux.as_ref().map(|install| install.mode),
        Some(LinuxMode::Resolved)
    );
}

/// Writes a harmless resolver client into the private root profile used by the regression probes.
fn install_nix_profile_tool(name: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let directory = Path::new("/nix/var/nix/profiles/default/bin");
    fs::create_dir_all(directory).expect("private root Nix profile directory");
    let tool = directory.join(name);
    fs::write(&tool, "#!/bin/sh\nexit 0\n").expect("fake fixed resolver tool");
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755))
        .expect("make fake resolver tool executable");
    tool
}

/// A failed resolver removal must invalidate the old success cache before records return to it.
#[test]
#[ignore = "Run in the J519 private resolver filesystem namespace."]
fn review_j529_failed_cleanup_does_not_cache_previous_success() {
    let nmcli = install_nix_profile_tool("nmcli");
    let daemon = install_nix_profile_tool("NetworkManager");
    fs::write(&daemon, "#!/bin/sh\nprintf '[main]\\ndns=dnsmasq\\n'\n")
        .expect("resolver fixture setup or inspection");
    let original = records();
    let changed_config: crate::dataplane::Config = serde_json::from_value(serde_json::json!({
        "node": 1,
        "version": 2,
        "addresses": {"ipv4": "10.254.0.1", "ipv6": "fd01::1"},
        "default_policy": "Deny",
        "dns_suffix": "corp.example",
        "peers": {}
    }))
    .expect("resolver fixture setup or inspection");
    let changed =
        Records::from_config(&changed_config).expect("resolver fixture setup or inspection");
    let mut integration = DnsIntegration::default();
    integration
        .configure("infraternal0", &original, 0)
        .expect("resolver fixture setup or inspection");
    assert!(matches!(
        integration.linux.as_ref().map(|install| install.mode),
        Some(LinuxMode::NetworkManager)
    ));
    fs::write(&nmcli, "#!/bin/sh\nexit 1\n").expect("resolver fixture setup or inspection");
    integration
        .configure("infraternal0", &changed, 0)
        .expect_err("the changed snapshot's cleanup reload fails");
    let path = Path::new(NETWORKMANAGER_DNSMASQ_DIRECTORY).join(NETWORKMANAGER_MESH_DNS_FILE);
    let contents = fs::read_to_string(&path).expect("resolver fixture setup or inspection");
    println!("J529_FILE_AFTER_FAILED_CLEANUP={contents:?}");
    assert_eq!(contents, format!("{NETWORKMANAGER_MESH_DNS_MARKER}\n"));
    integration.configure("infraternal0", &original, 0).expect_err("returning to the old snapshot must retry the failed cleanup, not return cached success for the now-empty file");
}

/// Changed or deleted forwarding files must be rebuilt even for an identical snapshot.
#[test]
#[ignore = "Run in the J519 private resolver filesystem namespace."]
fn review_j485c_changed_file_invalidates_success() {
    install_nix_profile_tool("nmcli");
    let daemon = install_nix_profile_tool("NetworkManager");
    fs::write(&daemon, "#!/bin/sh\nprintf '[main]\\ndns=dnsmasq\\n'\n")
        .expect("resolver fixture setup or inspection");
    let records = records();
    let mut integration = DnsIntegration::default();
    integration
        .configure("infraternal0", &records, 0)
        .expect("resolver fixture setup or inspection");
    let path = Path::new(NETWORKMANAGER_DNSMASQ_DIRECTORY).join(NETWORKMANAGER_MESH_DNS_FILE);
    let expected = fs::read_to_string(&path).expect("resolver fixture setup or inspection");
    fs::write(&path, format!("{NETWORKMANAGER_MESH_DNS_MARKER}\n"))
        .expect("resolver fixture setup or inspection");
    integration
        .configure("infraternal0", &records, 0)
        .expect("resolver fixture setup or inspection");
    assert_eq!(
        fs::read_to_string(&path).expect("resolver fixture setup or inspection"),
        expected
    );
    fs::remove_file(&path).expect("resolver fixture setup or inspection");
    integration
        .configure("infraternal0", &records, 0)
        .expect("resolver fixture setup or inspection");
    assert_eq!(
        fs::read_to_string(&path).expect("resolver fixture setup or inspection"),
        expected
    );
    fs::write(&path, "# unrelated\n").expect("resolver fixture setup or inspection");
    assert!(integration.configure("infraternal0", &records, 0).is_err());
    assert_eq!(
        fs::read_to_string(&path).expect("resolver fixture setup or inspection"),
        "# unrelated\n"
    );
    fs::remove_file(path).expect("resolver fixture setup or inspection");
}
