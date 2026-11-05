//! Measure real-shim SIGKILL through the production server inventory actor, with no attach/poll traffic [D81], #168.
use super::*;
use std::{fs, os::unix::fs::PermissionsExt, time::Instant};

struct Fixture {
    root: PathBuf,
    shims: Vec<u32>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for pid in &self.shims {
            if let Ok(pid) = i32::try_from(*pid) {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

async fn census(
    inventory: &mut watch::Receiver<SessionInventoryState>,
    id: [u8; 16],
    present: bool,
) {
    loop {
        if matches!(&*inventory.borrow_and_update(), SessionInventoryState::Available(ids) if ids.contains(&id) == present)
        {
            return;
        }
        inventory.changed().await.unwrap();
    }
}

// Keep the scale setup and timed retirement sequence in one benchmark oracle.
#[tokio::test]
#[ignore = "real daemon artifact and 200 shim exits; run with INFRATERNAL_BIN in a weighted scope"]
async fn shim_sigkill_to_server_inventory_latency() {
    let binary =
        PathBuf::from(std::env::var_os("INFRATERNAL_BIN").expect("real built binary required"));
    let root = PathBuf::from(
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").expect("private short state root required"),
    )
    .join(format!(
        "s{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let mut fixture = Fixture {
        root: root.clone(),
        shims: Vec::new(),
    };
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let quote = |path: &Path| format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"));
    let wrapper = root.join("daemon");
    let profile = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../infraternal/tests/profile")
        .canonicalize()
        .unwrap();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let runner = std::process::Command::new("which")
        .arg("systemd-run")
        .output()
        .unwrap();
    if runner.status.success() {
        let runner = PathBuf::from(std::str::from_utf8(&runner.stdout).unwrap().trim());
        let weighted = bin.join("systemd-run");
        fs::write(&weighted, format!("#!/bin/sh\n# Carry the benchmark scope weight to its fixture-owned shim scopes.\nexec {} -p CPUWeight=10000 \"$@\"\n", quote(&runner))).unwrap();
        fs::set_permissions(weighted, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(&wrapper, format!("#!/bin/sh\n# Isolate the real daemon/shim test state and login profile.\nZDOTDIR={}; export ZDOTDIR\nPATH={}:\"$PATH\"; export PATH\nprintf '%s\\n' \"$$\" > {}\nexec {} \"$@\" --state {}\n", quote(&profile), quote(&bin), quote(&root.join("daemon.pid")), quote(&binary), quote(&root))).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    let agent = EmbeddedAgent::spawn(wrapper);
    let mut inventory = agent.session_inventory();
    let mut ids = Vec::with_capacity(200);
    let mut processes = HashMap::with_capacity(200);
    for _ in 0..200 {
        let id = tokio::time::timeout(
            Duration::from_secs(30),
            agent.open(TerminalSize {
                cols: 80,
                rows: 24,
                px_w: 0,
                px_h: 0,
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let shim = infraternal_agent::sessions::connect(
            infraternal_agent::sessions::rendezvous(&root, id),
            id,
        )
        .await
        .unwrap();
        fixture.shims.push(shim.pid);
        processes.insert(id, shim.pid);
        drop(shim);
        ids.push(id);
    }
    census(&mut inventory, ids[199], true).await;
    let daemon_pid = fs::read_to_string(root.join("daemon.pid"))
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    idle(daemon_pid, "200 live shims").await;
    let mut samples = Vec::with_capacity(200);
    for id in ids {
        let pid = processes[&id];
        let before = Instant::now();
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap()),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();
        tokio::time::timeout(
            Duration::from_millis(400),
            census(&mut inventory, id, false),
        )
        .await
        .expect("SIGKILL census exceeded former 400 ms worst case");
        samples.push(before.elapsed().as_micros());
        fixture.shims.retain(|process| *process != pid);
    }
    samples.sort_unstable();
    println!(
        "shim_sigkill_to_server_inventory: n=200 initial_live_shims=200 attached=false p50_us={} p99_us={} max_us={} budget_us=400000 arch={} cores={} load={}",
        samples[99],
        samples[197],
        samples[199],
        std::env::consts::ARCH,
        std::thread::available_parallelism().unwrap(),
        fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    idle(daemon_pid, "all 200 shims exited").await;
    drop(agent);
}

async fn idle(pid: u32, label: &str) {
    let output = tokio::process::Command::new("python3")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/idle_canary.py"))
        .args([
            "--pid",
            &pid.to_string(),
            "--seconds",
            "2.2",
            "--label",
            label,
        ])
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "scale idle canary: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
