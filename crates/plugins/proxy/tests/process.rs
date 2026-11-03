//! Checks the owned Traefik child boundary and its file-only provider environment [#281, #289].

#![allow(
    clippy::expect_used,
    reason = "Integration fixture failures should identify the exact operation that failed."
)]

use infraternal_plugin_proxy::supervisor::{TraefikChild, child_identity};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

fn rootful_permissions(path: &std::path::Path, rootful: bool, uid: u32, gid: u32) {
    if rootful {
        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        )
        .expect("set fixture ownership");
    }
}

fn proxy_mode(rootful: bool, rootful_mode: u32, rootless_mode: u32) -> u32 {
    if rootful { rootful_mode } else { rootless_mode }
}

fn proxy_child_ids() -> (u32, u32) {
    child_identity().expect("resolve the proxy child identity")
}

fn read_child_process_status(
    received: &mpsc::Receiver<String>,
    deadline: Instant,
) -> BTreeMap<String, String> {
    let mut status = BTreeMap::new();
    while !status.contains_key("NoNewPrivs") && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = received
            .recv_timeout(remaining)
            .expect("receive child process status");
        if let Some((name, value)) = line.split_once(':')
            && matches!(
                name,
                "Uid" | "Gid" | "CapInh" | "CapPrm" | "CapEff" | "CapBnd" | "CapAmb" | "NoNewPrivs"
            )
        {
            status.insert(name.to_owned(), value.trim().to_owned());
        }
    }
    status
}

fn assert_proxy_child_ids(status: &BTreeMap<String, String>, user: u32, group: u32) {
    for (field, expected) in [("Uid", user), ("Gid", group)] {
        let values = status
            .get(field)
            .expect("child identity in /proc status")
            .split_whitespace()
            .map(|value| value.parse::<u32>().expect("numeric process identity"))
            .collect::<Vec<_>>();
        assert_eq!(values, [expected; 4]);
    }
}

fn assert_proxy_child_capabilities(status: &BTreeMap<String, String>, rootful: bool) {
    if rootful {
        for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            assert_eq!(
                status.get(field).map(String::as_str),
                Some("0000000000000400"),
                "rootful child {field} must contain only CAP_NET_BIND_SERVICE"
            );
        }
    } else {
        for field in ["CapEff", "CapAmb"] {
            assert_eq!(
                status.get(field).map(String::as_str),
                Some("0000000000000000")
            );
        }
    }
}

fn assert_proxy_file_identity(path: &std::path::Path, user: u32, group: u32, mode: u32) {
    let metadata = fs::metadata(path).expect("child custody metadata");
    assert_eq!(metadata.uid(), user);
    assert_eq!(metadata.gid(), group);
    assert_eq!(metadata.mode() & 0o777, mode);
}

#[test]
fn traefik_child_receives_only_credential_file_paths_and_redacts_its_logs() {
    let rootful = nix::unistd::Uid::effective().is_root();
    let (child_user, child_group) = proxy_child_ids();
    let root = std::env::temp_dir().join(format!("proxy-child-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).expect("create process fixture");
    rootful_permissions(&root, rootful, 0, child_group);
    fs::set_permissions(
        &root,
        fs::Permissions::from_mode(proxy_mode(rootful, 0o750, 0o700)),
    )
    .expect("private fixture");
    let executable = root.join("fake-traefik");
    let config = root.join("static.toml");
    let secrets = root.join("secrets");
    fs::create_dir(&secrets).expect("create provider custody directory");
    rootful_permissions(&secrets, rootful, child_user, child_group);
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
        .expect("private provider custody directory");
    let token_path = secrets.join("dns-token");
    let capture = secrets.join("child-input.txt");
    fs::write(&config, b"private config").expect("write fixture config");
    rootful_permissions(&config, rootful, 0, child_group);
    fs::set_permissions(
        &config,
        fs::Permissions::from_mode(proxy_mode(rootful, 0o640, 0o600)),
    )
    .expect("private fixture config");
    fs::write(&token_path, b"token-value-canary").expect("write fixture token");
    rootful_permissions(&token_path, rootful, child_user, child_group);
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
    rootful_permissions(&executable, rootful, 0, child_group);
    fs::set_permissions(
        &executable,
        fs::Permissions::from_mode(proxy_mode(rootful, 0o550, 0o500)),
    )
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
    let token_file_path = invocation.lines().next().expect("provider file path");
    assert!(token_file_path.contains("/fd/"));
    assert!(token_file_path.ends_with("/dns-token"));
    assert!(invocation.contains("\n\n--configFile\nstatic.toml\n"));
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

#[test]
fn traefik_child_obeys_the_rootful_identity_and_capability_boundary() {
    let rootful = nix::unistd::Uid::effective().is_root();
    let (child_user, child_group) = proxy_child_ids();
    let root = std::env::temp_dir().join(format!("proxy-sandbox-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).expect("create process fixture");
    rootful_permissions(&root, rootful, 0, child_group);
    fs::set_permissions(
        &root,
        fs::Permissions::from_mode(proxy_mode(rootful, 0o750, 0o700)),
    )
    .expect("private fixture");
    let executable = root.join("fake-traefik");
    let config = root.join("static.toml");
    let secrets = root.join("secrets");
    fs::create_dir(&secrets).expect("create provider custody directory");
    rootful_permissions(&secrets, rootful, child_user, child_group);
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o700))
        .expect("private provider custody directory");
    let token_path = secrets.join("dns-token");
    fs::write(&config, b"private config").expect("write fixture config");
    rootful_permissions(&config, rootful, 0, child_group);
    fs::set_permissions(
        &config,
        fs::Permissions::from_mode(proxy_mode(rootful, 0o640, 0o600)),
    )
    .expect("private fixture config");
    fs::write(&token_path, b"token-value-canary").expect("write fixture token");
    rootful_permissions(&token_path, rootful, child_user, child_group);
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600))
        .expect("private fixture token");
    fs::write(
        &executable,
        "#!/bin/sh\ncat \"$DNS_API_TOKEN_FILE\" >/dev/null\ncat /proc/self/status >&2\nexec /bin/sleep 60\n",
    )
    .expect("write fake executable");
    rootful_permissions(&executable, rootful, 0, child_group);
    fs::set_permissions(
        &executable,
        fs::Permissions::from_mode(proxy_mode(rootful, 0o550, 0o500)),
    )
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
    .expect("spawn constrained child");

    let deadline = Instant::now() + Duration::from_secs(2);
    let status = read_child_process_status(&received, deadline);
    let (expected_user, expected_group) = (child_user, child_group);
    assert_eq!(status.get("NoNewPrivs").map(String::as_str), Some("1"));
    assert_proxy_child_ids(&status, expected_user, expected_group);
    assert_proxy_child_capabilities(&status, rootful);
    for (path, file_user, file_group, mode) in [
        (
            &executable,
            if rootful { 0 } else { expected_user },
            expected_group,
            proxy_mode(rootful, 0o550, 0o500),
        ),
        (
            &config,
            if rootful { 0 } else { expected_user },
            expected_group,
            proxy_mode(rootful, 0o640, 0o600),
        ),
        (&token_path, expected_user, expected_group, 0o600),
    ] {
        assert_proxy_file_identity(path, file_user, file_group, mode);
    }

    child.stop().expect("stop and reap constrained child");
    fs::remove_dir_all(root).expect("remove process fixture");
}
