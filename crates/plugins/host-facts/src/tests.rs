//! Behavioural tests for host facts parsing, collection timing, and runtime configuration.
use super::{
    AgentMode, DESCRIPTOR, FactsError, HostFacts, HostFactsPlugin, MAX_FACTS_REQUEST_BYTES,
    decode_configure_request, decode_read_request, parse_load_average_text,
    parse_macos_load_average, parse_os_release,
};
use infraternal_plugin_api::{AgentPlugin, PluginError};

#[test]
fn os_release_uses_distribution_name_and_version_without_shell_evaluation() {
    let release = parse_os_release(
        "NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n",
    )
    .expect("valid os-release fields");

    assert_eq!(release.name, "Debian GNU/Linux");
    assert_eq!(release.version, "13");
}

#[test]
fn os_release_parser_rejects_unbounded_input_and_ignores_untrusted_lines() {
    assert!(parse_os_release(&"N".repeat(20 * 1_024)).is_none());
    assert!(parse_os_release("NAME=$(touch /tmp/should-not-run)\nVERSION_ID=13\n").is_some());
    assert!(parse_os_release("# comment\nVERSION_ID=13\n").is_none());
}

#[test]
fn macos_load_average_decodes_the_bounded_64_bit_sysctl_shape() {
    let mut value = vec![0; 24];
    value[0..4].copy_from_slice(&1_500_u32.to_ne_bytes());
    value[4..8].copy_from_slice(&2_250_u32.to_ne_bytes());
    value[8..12].copy_from_slice(&3_000_u32.to_ne_bytes());
    value[16..24].copy_from_slice(&1_000_i64.to_ne_bytes());

    assert_eq!(parse_macos_load_average(&value), Some([1.5, 2.25, 3.0]));
    assert_eq!(parse_macos_load_average(&value[..23]), None);
    value[16..24].copy_from_slice(&0_i64.to_ne_bytes());
    assert_eq!(parse_macos_load_average(&value), None);
}

#[test]
fn linux_load_average_text_ignores_proc_metadata_and_rejects_invalid_values() {
    assert_eq!(
        parse_load_average_text("0.50 1.00 2.00 3/120 2323"),
        Some([0.5, 1.0, 2.0])
    );
    assert_eq!(parse_load_average_text("0.5 1.0"), None);
    assert_eq!(parse_load_average_text("0.5 -1 2"), None);
    assert_eq!(parse_load_average_text("NaN 1 2"), None);
    assert_eq!(parse_load_average_text(&"0 ".repeat(129)), None);
}

#[test]
fn action_decoders_reject_unknown_and_oversized_fields() {
    assert_eq!(decode_read_request(br#"{"includeLive":true}"#), Ok(true));
    assert_eq!(
        decode_read_request(br#"{"includeLive":true,"other":1}"#),
        Err(FactsError::InvalidRequest)
    );
    assert_eq!(decode_configure_request(br#"{"enabled":false}"#), Ok(false));
    assert_eq!(
        decode_configure_request(br#"{"enabled":false,"extra":1}"#),
        Err(FactsError::InvalidRequest)
    );
    assert_eq!(
        decode_read_request(&vec![b' '; MAX_FACTS_REQUEST_BYTES + 1]),
        Err(FactsError::InvalidRequest)
    );
}

#[test]
fn static_facts_are_cached_and_live_counters_are_collected_only_when_requested() {
    let mut plugin = HostFactsPlugin::new(AgentMode::Embedded);
    let static_json = plugin
        .call("host.facts.read", b"{}")
        .expect("static host facts");
    let static_facts =
        serde_json::from_slice::<super::HostFacts>(&static_json).expect("valid host facts");
    assert_eq!(static_facts.mode, AgentMode::Embedded);
    assert!(static_facts.memory.is_none());
    assert!(static_facts.root_disk.is_none());
    assert!(static_facts.uptime_seconds.is_none());
    assert!(static_json.len() < infraternal_plugin_api::MAX_ACTION_BYTES);

    #[cfg(target_os = "linux")]
    {
        let live_json = plugin
            .call("host.facts.read", br#"{"includeLive":true}"#)
            .expect("live host facts");
        let live_facts =
            serde_json::from_slice::<super::HostFacts>(&live_json).expect("valid live facts");
        assert!(live_facts.memory.is_some());
        assert!(live_facts.root_disk.is_some());
        assert!(live_facts.uptime_seconds.is_some());
    }
}

#[test]
fn runtime_disable_drops_cached_facts_and_reenable_collects_them_again() {
    let mut plugin = HostFactsPlugin::new(AgentMode::Remote);
    assert!(plugin.is_enabled());
    plugin
        .call("host.facts.configure", br#"{"enabled":false}"#)
        .expect("disable host facts");
    assert!(!plugin.is_enabled());
    assert_eq!(
        plugin.call("host.facts.read", b"{}"),
        Err(PluginError::Rejected)
    );
    plugin
        .call("host.facts.configure", br#"{"enabled":true}"#)
        .expect("enable host facts");
    assert!(plugin.is_enabled());
    let reenabled = plugin
        .call("host.facts.read", b"{}")
        .expect("read reenabled host facts");
    let facts = serde_json::from_slice::<super::HostFacts>(&reenabled).expect("valid host facts");
    assert_eq!(facts.mode, AgentMode::Remote);
}

#[test]
fn compatibility_fields_are_kept_in_the_rust_shape_and_architecture_on_wire() {
    let mut plugin = HostFactsPlugin::new(AgentMode::Embedded);
    let response = plugin.call("host.facts.read", b"{}").expect("cached facts");
    let value = serde_json::from_slice::<serde_json::Value>(&response).expect("serialize facts");
    let facts = serde_json::from_slice::<HostFacts>(&response).expect("deserialize facts");
    assert_eq!(facts.uid, nix::unistd::geteuid().as_raw());
    assert!(facts.cpus > 0);
    assert!(value.get("architecture").is_some());
    assert!(value.get("arch").is_none());
    assert!(value.get("executionUid").is_some());
    assert!(value.get("logicalCpus").is_some());
}

#[test]
fn descriptor_declares_default_settings_actions_and_no_hidden_role_dependency() {
    assert_eq!(DESCRIPTOR.id, "host");
    assert_eq!(DESCRIPTOR.settings.defaults, r#"{"enabled":true}"#);
    assert_eq!(DESCRIPTOR.settings.configure_action, "host.facts.configure");
    assert_eq!(DESCRIPTOR.actions.len(), 2);
    assert_eq!(DESCRIPTOR.role_dependencies, &[] as &[&str]);
}
