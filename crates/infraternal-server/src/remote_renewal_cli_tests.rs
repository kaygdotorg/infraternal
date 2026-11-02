//! Real rootless CLI live renewal, durable identity and independent process-cost proof [133][167][168], #78.
use super::*;
fn process_cpu_ns(pid: u32) -> u64 {
    let output=Command::new("python3").args(["-c", "import ctypes,sys,time; clock=ctypes.c_int(); status=ctypes.CDLL(None).clock_getcpuclockid(int(sys.argv[1]),ctypes.byref(clock)); assert status==0; print(time.clock_gettime_ns(clock.value))", &pid.to_string()]).output().unwrap();
    assert!(output.status.success(), "process CPU clock unavailable");
    std::str::from_utf8(&output.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}
fn process_rss_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}
fn seed_cli_identity(
    directory: &Directory,
    fixture: &Fixture,
    host: uuid::Uuid,
    identity: &infraternal_agent::remote_tls::Identity,
) {
    use std::os::unix::fs::OpenOptionsExt;
    let data = directory.0.join("data");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&data)
        .unwrap();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "host_id":host, "execution_uid":nix::unistd::Uid::effective().as_raw(),
        "endpoint":fixture.listeners.as_ref().unwrap().local_addr().unwrap(),
        "server_name":"localhost", "ca_der":B64.encode(fixture.root.to_der().unwrap()),
        "certificate_der":B64.encode(identity.certificate.to_der().unwrap()),
        "key_der":B64.encode(identity.key.private_key_to_pkcs8().unwrap())
    }))
    .unwrap();
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(data.join("identity.json"))
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}
async fn acknowledged_replacement(
    fixture: &Fixture,
    host: uuid::Uuid,
    predecessor: [u8; 32],
) -> crate::remote_guard::AuthorityGuard {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(guard) = fixture
                .listeners
                .as_ref()
                .unwrap()
                .diagnostic_hosts
                .admission_for_test(host)
                .await
                && guard.predecessor() != predecessor
            {
                return guard;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap()
}

/// Intersect this process's socket descriptors with the kernel's network tables.
/// Namespace-wide /proc/net entries alone would include the co-located server.
fn network_sockets(
    pid: u32,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    use std::collections::BTreeSet;
    let owned: BTreeSet<String> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .filter_map(|target| {
            let value = target.to_str()?;
            value
                .strip_prefix("socket:[")?
                .strip_suffix(']')
                .map(str::to_owned)
        })
        .collect();
    let table = |protocol: &str| -> BTreeSet<String> {
        [protocol.to_owned(), format!("{protocol}6")]
            .iter()
            .flat_map(|name| {
                std::fs::read_to_string(format!("/proc/{pid}/net/{name}"))
                    .unwrap()
                    .lines()
                    .skip(1)
                    .filter_map(|line| line.split_whitespace().nth(9).map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .filter(|inode| owned.contains(inode))
            .collect()
    };
    (table("udp"), table("tcp"))
}
fn assert_transport(
    pid: u32,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let sockets = network_sockets(pid);
    if std::env::var_os("INFRATERNAL_REMOTE_FORCE_TCP").is_some() {
        assert!(sockets.0.is_empty());
        assert_eq!(sockets.1.len(), 1);
    } else {
        assert_eq!(sockets.0.len(), 1);
        assert!(sockets.1.is_empty());
    }
    sockets
}

fn assert_durable_identity(
    directory: &Directory,
    identity: &infraternal_agent::remote_tls::Identity,
    host: uuid::Uuid,
    predecessor: [u8; 32],
    renewed: &crate::remote_guard::AuthorityGuard,
) {
    let stored: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.0.join("data/identity.json")).unwrap())
            .unwrap();
    assert!(
        stored["key_der"].as_str().unwrap()
            == B64.encode(identity.key.private_key_to_pkcs8().unwrap()),
        "host key changed during renewal"
    );
    assert_eq!(stored["host_id"].as_str().unwrap(), host.to_string());
    let leaf = X509::from_der(
        &B64.decode(stored["certificate_der"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let fingerprint: [u8; 32] = leaf
        .digest(openssl::hash::MessageDigest::sha256())
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap();
    assert_eq!(fingerprint, renewed.predecessor());
    assert_ne!(fingerprint, predecessor);
}

#[tokio::test]
#[ignore = "real CLI renewal measurement requires release binary and exclusive port4701; no own compilation/browser overlap"]
async fn cli_live_renewal_cost_and_durable_identity_on_unchanged_transport() {
    let binary = PathBuf::from(
        std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").expect("real CLI binary required"),
    );
    assert_ne!(nix::unistd::Uid::effective().as_raw(), 0);
    assert!(
        std::env::var_os("INFRATERNAL_REMOTE_IDLE_CANARY").is_some(),
        "ten-second process canary must be enabled"
    );
    let directory = Directory::new();
    let fixture = fixture_at_with_lock(
        &directory,
        "127.0.0.1:4701".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        true,
    )
    .await;
    let (host, identity) = super::renewal::enrolled_at_half_life(&fixture).await;
    seed_cli_identity(&directory, &fixture, host, &identity);
    let process = cli(&binary, &directory, false, "https://localhost:4701");
    let mut browser = browser(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
    )
    .await;
    let _session = open_remote(&mut browser, host, Instant::now()).await;
    // Allow losing-dial and blocking-pool retirement before the idle baseline.
    tokio::time::sleep(Duration::from_secs(11)).await;
    idle_canary(&process).await;
    let guard = fixture
        .listeners
        .as_ref()
        .unwrap()
        .diagnostic_hosts
        .admission_for_test(host)
        .await
        .unwrap();
    let predecessor = guard.predecessor();
    let sockets = assert_transport(process.0.id());
    let before_cpu = process_cpu_ns(process.0.id());
    let before_rss = process_rss_kib(process.0.id());
    // This process owns the real listener and browser fixture; the measured
    // CPU includes their coordination, not the independent CLI or Python child.
    let server_pid = std::process::id();
    let server_before_rss = process_rss_kib(server_pid);
    let server_before_cpu = process_cpu_ns(server_pid);
    let started = Instant::now();
    fixture
        .signer
        .unlock_from(&Administrator(fixture.material.clone()))
        .unwrap();
    let renewed = acknowledged_replacement(&fixture, host, predecessor).await;
    let elapsed = started.elapsed().as_micros();
    let server_cpu = process_cpu_ns(server_pid).saturating_sub(server_before_cpu);
    let server_rss = process_rss_kib(server_pid);
    assert_eq!(
        network_sockets(process.0.id()),
        sockets,
        "renewal changed network connection"
    );
    let cpu = process_cpu_ns(process.0.id()).saturating_sub(before_cpu);
    let rss = process_rss_kib(process.0.id());
    assert_durable_identity(&directory, &identity, host, predecessor, &renewed);
    let transport = if sockets.0.is_empty() { "tcp" } else { "quic" };
    println!(
        "cli_renewal transport={transport} network_connection_unchanged=true rootless=true cpu_ns={cpu} elapsed_us={elapsed} before_rss_kib={before_rss} after_rss_kib={rss} rss_delta_kib={} durable_certificate_matches_ack=true retained_host_key=true machine={} cores={} load={}",
        rss.saturating_sub(before_rss),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    println!(
        "server_fixture_renewal transport={transport} cpu_ns={server_cpu} before_rss_kib={server_before_rss} after_rss_kib={server_rss} rss_delta_kib={} includes_in_process_browser_and_measurement_coordination=true production_server_isolation=false",
        server_rss.saturating_sub(server_before_rss)
    );
    tokio::time::sleep(Duration::from_secs(11)).await;
    idle_canary(&process).await;
    println!(
        "cli_renewal_retired transport={transport} settled_rss_kib={} rss_delta_kib={} idle_scheduled_slices=0 observed_seconds=10",
        process_rss_kib(process.0.id()),
        process_rss_kib(process.0.id()).saturating_sub(before_rss)
    );
}

#[path = "remote_renewal_flood_tests.rs"]
mod flood;
