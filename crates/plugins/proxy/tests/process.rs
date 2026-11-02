//! Checks the owned Traefik child boundary and its file-only provider environment [#281, #289].

#![allow(
    clippy::expect_used,
    reason = "Integration fixture failures should identify the exact operation that failed."
)]

use infraternal_plugin_proxy::supervisor::TraefikChild;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

#[test]
fn traefik_child_receives_only_credential_file_paths_and_redacts_its_logs() {
    let root = std::env::temp_dir().join(format!("proxy-child-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).expect("create process fixture");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private fixture");
    let executable = root.join("fake-traefik");
    let config = root.join("static.toml");
    let token_path = root.join("dns-token");
    let capture = root.join("child-input.txt");
    fs::write(&config, b"private config").expect("write fixture config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600))
        .expect("private fixture config");
    fs::write(&token_path, b"token-value-canary").expect("write fixture token");
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))
        .expect("private fixture token");
    fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$DNS_API_TOKEN_FILE\" \"$DNS_API_TOKEN\" \"$@\" > '{}'\nprintf '%s\\n' 'Authorization: Bearer header-secret Cookie: session=cookie-secret url=https://dns.invalid/?api_key=query-secret raw token-value-canary' >&2\nexec /bin/sleep 60\n",
            capture.display()
        ),
    )
    .expect("write fake executable");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o500))
        .expect("executable fixture mode");

    let (logs, received) = mpsc::channel();
    let log = Arc::new(move |line: String| {
        let _ = logs.send(line);
    });
    let mut child = TraefikChild::spawn(
        &executable,
        &config,
        &[("DNS_API_TOKEN", token_path.as_path())],
        log,
    )
    .expect("spawn owned child");

    let deadline = Instant::now() + Duration::from_secs(2);
    while !capture.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let invocation = fs::read_to_string(&capture).expect("read child invocation");
    assert!(invocation.starts_with(&format!(
        "{}\n\n--configFile\n{}\n",
        token_path.display(),
        config.display()
    )));
    assert!(!invocation.contains("token-value-canary"));
    let line = received
        .recv_timeout(Duration::from_secs(2))
        .expect("receive sanitized child log");
    for secret in [
        "header-secret",
        "cookie-secret",
        "query-secret",
        "token-value-canary",
    ] {
        assert!(!line.contains(secret), "child log leaked {secret}");
    }
    assert!(line.contains("[REDACTED]"));
    child.stop().expect("stop and reap owned child");
    fs::remove_dir_all(root).expect("remove process fixture");
}
