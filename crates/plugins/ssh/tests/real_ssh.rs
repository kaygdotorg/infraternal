//! Real-sshd oracle using only the memory-held synthetic key supplied by research/ssh-client/measure.py.
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    model::{Destination, FailureKind, MeshEvidence},
    openssh::OpenSsh,
    probe::{CHECK_SCRIPT, Check},
    transport::{Credentials, Input, Secret, SshTransport},
};
use std::os::unix::fs::PermissionsExt;
use std::{
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};

/// Exercise strict authentication and progress-bounded uploads through a real SSH master.
#[tokio::test]
#[ignore = "run through research/ssh-client/measure.py with the synthetic rootless sshd fixture"]
async fn actual_ssh_authentication_check_and_strict_host_key_rejection() {
    let fixture = PathBuf::from(std::env::var_os("INFRATERNAL_SSH_FIXTURE").unwrap());
    let port: u16 = std::env::var("INFRATERNAL_SSH_FIXTURE_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let relay_port: u16 = std::env::var("INFRATERNAL_SSH_FIXTURE_RELAY_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let user = std::env::var("USER").unwrap();
    let mut private = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut private)
        .unwrap();
    assert!(private.len() <= 65536);
    let adapter = OpenSsh {
        ssh: fixture.join("ssh"),
        ssh_agent: "/usr/bin/ssh-agent".into(),
        ssh_add: "/usr/bin/ssh-add".into(),
        ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
        ssh_keygen: "/usr/bin/ssh-keygen".into(),
        askpass_binary: std::env::current_exe().unwrap(),
        tcp_connector: None,
        scratch: fixture.clone(),
        command_timeout: Duration::from_secs(30),
    };
    // D183 network auth must not inherit the fixture's authorized SSH agent.
    let network_result = adapter
        .open(
            Destination::parse(&format!("{user}@127.0.0.1:{port}")).unwrap(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await;
    assert!(
        matches!(network_result, Err(ref error) if error.kind == FailureKind::Auth),
        "network-only authentication must not use ambient local SSH identities"
    );
    let private = Secret::new(private);
    let opened = Instant::now();
    let session = adapter
        .open(
            Destination::parse(&format!("{user}@127.0.0.1:{port}")).unwrap(),
            Credentials::PrivateKey {
                key: Secret::new(private.expose().to_vec()),
                passphrase: None,
            },
            MeshEvidence::default(),
        )
        .await
        .unwrap();
    let preparation_us = opened.elapsed().as_micros();
    let started = Instant::now();
    let check = session.run(CHECK_SCRIPT, Input::Empty).await.unwrap();
    let check = Check::parse(&check.stdout).unwrap();
    assert_ne!(check.uid, 0);
    println!(
        "METRIC real_sshd preparation_us={preparation_us} check_us={} uid={}",
        started.elapsed().as_micros(),
        check.uid
    );
    // Consume 256 chunks at a deliberately slow rate. This exceeds the old
    // 30-second command clock without asserting speed on a shared build VM.
    let upload = vec![42; 256 * 65536];
    let script = r#"python3 -c '
import os, time
for _ in range(256):
    remaining = 65536
    while remaining:
        chunk = os.read(0, remaining)
        assert chunk and all(byte == 42 for byte in chunk)
        remaining -= len(chunk)
    # sleep: throttle the synthetic upload beyond the former total command deadline.
    time.sleep(.15)
assert not os.read(0, 1)
print("UPLOAD complete")
'"#;
    let output = session.run(script, Input::Bytes(&upload)).await.unwrap();
    assert_eq!(output.stdout, b"UPLOAD complete\n");
    println!(
        "PROOF real_sshd progressing_upload bytes={} chunks=256 complete",
        upload.len()
    );

    drop(session);
    assert!(
        std::fs::read_dir(&fixture).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("ssh-")),
        "credential session did not remove its helpers"
    );

    for (rtt, port) in [(0, port), (300, relay_port)] {
        let session = adapter
            .open(
                Destination::parse(&format!("{user}@127.0.0.1:{port}")).unwrap(),
                Credentials::PrivateKey {
                    key: Secret::new(private.expose().to_vec()),
                    passphrase: None,
                },
                MeshEvidence::default(),
            )
            .await
            .unwrap();
        let started = Instant::now();
        let jobs = (0..10).map(|_| session.run(CHECK_SCRIPT, Input::Empty));
        let controller_baseline_kib = rss(std::process::id());
        let mut controller_peak_kib = controller_baseline_kib;
        let mut child_peak_kib = 0;
        let results = futures_util::future::join_all(jobs);
        tokio::pin!(results);
        let results = loop {
            tokio::select! {
                results = &mut results => break results,
                () = tokio::time::sleep(Duration::from_millis(5)) => {
                    controller_peak_kib = controller_peak_kib.max(rss(std::process::id()));
                    child_peak_kib = child_peak_kib.max(owned_children_rss());
                }
            }
        };
        assert!(results.into_iter().all(|result| result.is_ok()));
        println!(
            "METRIC real_sshd rtt_ms={rtt} controller_baseline_rss_kib={controller_baseline_kib} controller_peak_rss_kib={controller_peak_kib} owned_ssh_children_peak_rss_kib={child_peak_kib}"
        );
        println!(
            "METRIC real_sshd rtt_ms={rtt} concurrent_checks=10 elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }
    let unknown_config = fixture.join("unknown-config");
    std::fs::write(&unknown_config, format!("# Synthetic missing-known-host fixture; strict mode remains mandatory.\nHost *\n  Port {port}\n  UserKnownHostsFile /dev/null\n  GlobalKnownHostsFile /dev/null\n")).unwrap();
    let unknown_wrapper = fixture.join("unknown-ssh");
    std::fs::write(
        &unknown_wrapper,
        format!(
            "#!/bin/sh\nexec /usr/bin/ssh -F '{}' \"$@\"\n",
            unknown_config.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&unknown_wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let adapter = OpenSsh {
        ssh: unknown_wrapper,
        ..adapter
    };
    let configuration = std::process::Command::new(&adapter.ssh)
        .args(["-G", "-l", &user, "127.0.0.1"])
        .output()
        .unwrap();
    let effective = infraternal_plugin_ssh::openssh::scan_destination(
        &Destination::parse(&format!("{user}@127.0.0.1")).unwrap(),
        &configuration.stdout,
    );
    assert_eq!(effective.unwrap().port(), Some(port));
    let error = adapter
        .open(
            Destination::parse(&format!("{user}@127.0.0.1")).unwrap(),
            Credentials::Network,
            MeshEvidence::default(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind, FailureKind::HostKey);
    assert_ne!(error.fingerprints.len(), 0);
}

fn rss(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    // Only own child counters are observed; a pid that has already been reused
    // by another process is excluded. No argv, environment or memory is read.
    if pid != std::process::id()
        && !status.lines().any(|line| {
            line.strip_prefix("PPid:")
                .is_some_and(|value| value.trim().parse::<u32>().ok() == Some(std::process::id()))
        })
    {
        return 0;
    }
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next()?.parse().ok())
        })
        .unwrap_or(0)
}
fn owned_children_rss() -> u64 {
    std::fs::read_dir("/proc/self/task")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|task| std::fs::read_to_string(task.path().join("children")).ok())
        .flat_map(|children| {
            children
                .split_whitespace()
                .filter_map(|pid| pid.parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .map(rss)
        .sum()
}
