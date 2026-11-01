//! Regressions for temporary node-local DNS token custody.

use super::custody::{DnsTokenCustody, FileDnsTokenCustody, SecretToken};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

struct TempState(PathBuf);

impl TempState {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("infraternal-proxy-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).expect("create private state root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("set private state root mode");
        Self(path)
    }
}

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn file_custody_writes_private_secret_and_exposes_only_its_path() {
    let state = TempState::new();
    let custody = FileDnsTokenCustody::open(&state.0).expect("open custody");
    let secret = b"do-not-log-this-token";
    let token = SecretToken::new(secret.to_vec());
    let path = custody
        .put("cloudflare", "CF_DNS_API_TOKEN", token)
        .expect("store token");

    let metadata = fs::symlink_metadata(&path).expect("token metadata");
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(fs::read(&path).expect("test token contents"), secret);
    assert_eq!(custody.get("cloudflare", "CF_DNS_API_TOKEN").unwrap(), path);
}

#[test]
fn custody_refuses_a_group_readable_secret_directory() {
    let state = TempState::new();
    let directory = state.0.join("proxy-secrets");
    fs::create_dir(&directory).expect("create secrets directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o750))
        .expect("set unsafe directory mode");

    assert!(FileDnsTokenCustody::open(&state.0).is_err());
}

#[test]
fn custody_refuses_a_group_readable_state_directory() {
    let state = TempState::new();
    fs::set_permissions(&state.0, fs::Permissions::from_mode(0o750))
        .expect("make state mode unsafe");

    assert!(FileDnsTokenCustody::open(&state.0).is_err());
}

#[test]
fn custody_uses_private_state_provider_and_secret_modes() {
    let state = TempState::new();
    let custody = FileDnsTokenCustody::open(&state.0).expect("open custody");
    let path = custody
        .put(
            "cloudflare",
            "CF_DNS_API_TOKEN",
            SecretToken::new(b"private".to_vec()),
        )
        .expect("store token");

    for (path, expected_mode) in [
        (state.0.join("proxy-secrets"), 0o700),
        (state.0.join("proxy-secrets/cloudflare"), 0o700),
        (path, 0o600),
    ] {
        let metadata = fs::symlink_metadata(path).expect("private path metadata");
        assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
        assert_eq!(metadata.mode() & 0o777, expected_mode);
    }
}

#[test]
fn get_refuses_a_provider_directory_with_changed_mode() {
    let state = TempState::new();
    let custody = FileDnsTokenCustody::open(&state.0).expect("open custody");
    let path = custody
        .put(
            "cloudflare",
            "CF_DNS_API_TOKEN",
            SecretToken::new(b"private".to_vec()),
        )
        .expect("store token");
    let provider_dir = path.parent().expect("provider directory");
    fs::set_permissions(provider_dir, fs::Permissions::from_mode(0o755))
        .expect("make provider directory unsafe");

    assert!(custody.get("cloudflare", "CF_DNS_API_TOKEN").is_err());
}

#[test]
fn custody_refuses_a_symlinked_secret_directory() {
    use std::os::unix::fs::symlink;

    let state = TempState::new();
    let target = state.0.join("private-target");
    fs::create_dir(&target).expect("create private target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
        .expect("set private target mode");
    symlink(&target, state.0.join("proxy-secrets")).expect("link secret directory");

    assert!(FileDnsTokenCustody::open(&state.0).is_err());
}

#[test]
fn rotating_replaces_atomically_and_provider_removal_deletes_files() {
    let state = TempState::new();
    let custody = FileDnsTokenCustody::open(&state.0).expect("open custody");
    let old = custody
        .put(
            "cloudflare",
            "CF_DNS_API_TOKEN",
            SecretToken::new(b"old-token".to_vec()),
        )
        .expect("store old token");
    let replacement = custody
        .rotate(
            "cloudflare",
            "CF_DNS_API_TOKEN",
            SecretToken::new(b"new-token".to_vec()),
        )
        .expect("rotate token");

    assert_eq!(replacement, old);
    assert_eq!(fs::read(&replacement).unwrap(), b"new-token");
    custody.delete("cloudflare").expect("remove provider");
    assert!(custody.get("cloudflare", "CF_DNS_API_TOKEN").is_err());
}

#[test]
fn put_does_not_replace_and_delete_is_scoped_to_one_provider() {
    let state = TempState::new();
    let custody = FileDnsTokenCustody::open(&state.0).expect("open custody");
    let first = custody
        .put(
            "cloudflare",
            "CF_DNS_API_TOKEN",
            SecretToken::new(b"original".to_vec()),
        )
        .expect("store first token");
    let second = custody
        .put(
            "route53",
            "AWS_SECRET_ACCESS_KEY",
            SecretToken::new(b"other-provider".to_vec()),
        )
        .expect("store second provider token");

    assert!(
        custody
            .put(
                "cloudflare",
                "CF_DNS_API_TOKEN",
                SecretToken::new(b"replacement".to_vec()),
            )
            .is_err()
    );
    custody.delete("cloudflare").expect("remove one provider");
    assert!(!first.exists());
    assert_eq!(fs::read(&second).unwrap(), b"other-provider");
}

#[test]
fn get_refuses_a_token_file_with_changed_mode_or_a_symlink() {
    use std::os::unix::fs::symlink;

    let state = TempState::new();
    let custody = FileDnsTokenCustody::open(&state.0).expect("open custody");
    let path = custody
        .put(
            "cloudflare",
            "CF_DNS_API_TOKEN",
            SecretToken::new(b"private".to_vec()),
        )
        .expect("store token");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("make token mode unsafe");
    assert!(custody.get("cloudflare", "CF_DNS_API_TOKEN").is_err());

    fs::remove_file(&path).expect("remove unsafe token file");
    let other = state.0.join("other");
    fs::write(&other, b"not a provider token").expect("write nonsecret target");
    symlink(other, &path).expect("replace token with symlink");
    assert!(custody.get("cloudflare", "CF_DNS_API_TOKEN").is_err());
}

#[test]
fn custody_rejects_provider_and_variable_names_that_can_escape_or_override() {
    let state = TempState::new();
    let custody = FileDnsTokenCustody::open(&state.0).expect("open custody");
    assert!(
        custody
            .put(
                "../outside",
                "CF_DNS_API_TOKEN",
                SecretToken::new(b"token".to_vec()),
            )
            .is_err()
    );
    assert!(
        super::custody::provider_file_variable(
            "CF_DNS_API_TOKEN=value",
            std::path::Path::new("/private/token"),
        )
        .is_err()
    );
}

#[test]
fn secret_debug_and_provider_file_environment_never_include_the_value() {
    let token = SecretToken::new(b"must-not-appear-in-debug-or-env".to_vec());
    let debug = format!("{token:?}");
    assert!(!debug.contains("must-not-appear-in-debug-or-env"));

    let variable = super::custody::provider_file_variable(
        "CF_DNS_API_TOKEN",
        std::path::Path::new("/private/state/proxy-secrets/cloudflare/CF_DNS_API_TOKEN"),
    )
    .expect("provider file variable");
    assert_eq!(variable.0, "CF_DNS_API_TOKEN_FILE");
    assert_eq!(
        variable.1,
        "/private/state/proxy-secrets/cloudflare/CF_DNS_API_TOKEN"
    );
    assert!(!variable.1.contains("must-not-appear-in-debug-or-env"));
}

#[test]
fn agent_start_removes_custody_files_for_a_removed_dns_provider() {
    const CHILD_STATE: &str = "INFRATERAL_PROXY_CUSTODY_TEST_STATE";
    if let Some(state) = std::env::var_os(CHILD_STATE) {
        let log: Arc<super::supervisor::ProxyLog> = Arc::new(|_| {});
        let _controller = super::controller::ProxyController::for_agent(Path::new(&state), log)
            .expect("load proxy without a DNS provider");
        return;
    }

    let state = TempState::new();
    let custody = FileDnsTokenCustody::open(&state.0).expect("open custody");
    let provider = format!("removed-{}", uuid::Uuid::new_v4().simple());
    let path = custody
        .put(
            &provider,
            "TEST_DNS_API_TOKEN",
            SecretToken::new(b"removed-provider-test-value".to_vec()),
        )
        .expect("store removed provider token");

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "tests::agent_start_removes_custody_files_for_a_removed_dns_provider",
            "--nocapture",
        ])
        .env_clear()
        .env(CHILD_STATE, &state.0)
        .output()
        .expect("start isolated agent configuration check");
    let child_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "isolated agent configuration failed: {child_output}"
    );
    assert!(
        child_output.contains("1 passed"),
        "isolated process did not run the custody regression: {child_output}"
    );
    assert!(
        !path.exists(),
        "token file for the removed DNS provider survived agent startup"
    );
}

#[test]
fn agent_restart_retains_the_configured_dns_provider_files_for_renewal() {
    const CHILD_STATE: &str = "INFRATERAL_PROXY_CUSTODY_TEST_STATE";
    if let Some(state) = std::env::var_os(CHILD_STATE) {
        let provider = std::env::var("INFRATERAL_DNS_PROVIDER")
            .expect("configured provider identity is present in the child");
        let profile = super::controller::DnsProviderProfile::from_environment()
            .expect("configured DNS provider profile is valid");
        assert_eq!(
            profile.as_ref().map(|profile| profile.provider.as_str()),
            Some(provider.as_str()),
            "restart selected a different DNS provider"
        );
        let custody = FileDnsTokenCustody::open(Path::new(&state)).expect("open child custody");
        custody
            .get(&provider, "TEST_DNS_API_TOKEN")
            .expect("configured provider file exists before controller startup");
        custody
            .remove_unconfigured_providers(Some(&provider))
            .expect("cleanup preserves the configured provider");
        custody
            .get(&provider, "TEST_DNS_API_TOKEN")
            .expect("configured provider survives direct cleanup");
        let log: Arc<super::supervisor::ProxyLog> = Arc::new(|_| {});
        let _controller = super::controller::ProxyController::for_agent(Path::new(&state), log)
            .expect("load proxy with its configured DNS provider");
        custody
            .get(&provider, "TEST_DNS_API_TOKEN")
            .expect("configured provider file survives controller startup");
        return;
    }

    let state = TempState::new();
    let custody = FileDnsTokenCustody::open(&state.0).expect("open custody");
    let provider = format!("renewal-{}", uuid::Uuid::new_v4().simple());
    let path = custody
        .put(
            &provider,
            "TEST_DNS_API_TOKEN",
            SecretToken::new(b"renewal-test-value".to_vec()),
        )
        .expect("store provider token");

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "tests::agent_restart_retains_the_configured_dns_provider_files_for_renewal",
            "--nocapture",
        ])
        .env_clear()
        .env(CHILD_STATE, &state.0)
        .env("INFRATERAL_DNS_PROVIDER", &provider)
        .env("INFRATERAL_DNS_EMAIL", "proxy-test@example.org")
        .env("INFRATERAL_DNS_CREDENTIAL_VARIABLES", "TEST_DNS_API_TOKEN")
        .output()
        .expect("start isolated configured agent");
    let child_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "configured agent startup failed: {child_output}"
    );
    assert!(
        child_output.contains("1 passed"),
        "isolated process did not run the renewal custody regression: {child_output}"
    );
    assert!(
        path.exists(),
        "token file for the active DNS provider did not survive agent restart"
    );
}
