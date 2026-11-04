//! Checks Darwin core-dump protection before the CLI dispatches the daemon.

#[test]
fn core_dump_limit_is_zero_before_dispatch() {
    const NAME: &str = "startup_tests::core_dump_limit_is_zero_before_dispatch";
    if std::env::var_os("INFRATERAL_DUMP_TEST").is_some() {
        super::harden_startup().expect("harden startup");
        let (soft, hard) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_CORE)
            .expect("read core limit");
        assert_eq!(soft, 0, "soft core limit remains enabled");
        assert_eq!(hard, 0, "hard core limit remains enabled");
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERAL_DUMP_TEST", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run isolated hardening test");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn macos_agent_registry_includes_the_mesh_node() {
    assert!(
        infraternal_agent::plugins::descriptors()
            .iter()
            .any(|descriptor| descriptor.id == "mesh"),
        "the macOS system daemon must register the Mesh node before server connectivity"
    );
}

#[test]
fn public_status_action_does_not_require_hidden_service_flag() {
    let matches = clap::Command::new("mesh-status").get_matches_from(["mesh-status"]);
    assert!(!super::system_service_requested(&matches));
}
