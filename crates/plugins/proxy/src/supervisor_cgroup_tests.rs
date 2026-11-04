//! A Traefik child that double-forks must leave nothing behind, after a stop and after an
//! infraternal agent crash [#281 J152 P3-4, D336].
//!
//! The fake Traefik starts a grandchild with `setsid`, so it leaves the child's process group
//! and session and carries no parent-death signal: only the cgroup can still find it. The
//! grandchild runs `sleep` with a unique duration, which is how the test finds it without
//! asking the code under test.
//!
//! Without delegation the supervisor falls back to reaping the direct child, and the
//! grandchild survives. These tests then report what they saw and pass, unless
//! `INFRATERNAL_REQUIRE_PROXY_CGROUP=1` says this run must prove containment (the root run in
//! a `Delegate=yes` unit does).

use super::{
    DYNAMIC_CONFIG_FILENAME, TraefikSupervisor, fake_traefik, generation_probe_server,
    generation_probe_settings, public_service, supervisor_fixture,
};
use crate::cgroup::Containment;
use std::{
    io::BufRead,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CRASH_HELPER: &str = "INFRATERNAL_PROXY_CRASH_HELPER";
// libtest prints "test <name> ... " on the same line as captured-off output, so the parent
// looks for this token anywhere in a line.
const HELPER_READY: &str = "proxy-crash-helper-ready";

fn must_contain() -> bool {
    std::env::var_os("INFRATERNAL_REQUIRE_PROXY_CGROUP").is_some_and(|value| value == "1")
}

/// A `sleep` duration no other process on the machine is running.
fn marker() -> String {
    let id = uuid::Uuid::new_v4().as_u128();
    format!("{}.{}", 3000 + id % 1000, id % 1_000_000)
}

fn fake_double_forking_traefik(path: &Path, marker: &str) {
    let script = format!(
        "#!/bin/sh\n/usr/bin/setsid /bin/sleep {marker} </dev/null >/dev/null 2>&1 &\nexec /bin/sleep 120\n"
    );
    fake_traefik(path, script.as_bytes());
}

/// Live (non-zombie) processes running `sleep <marker>`.
fn grandchildren(marker: &str) -> Vec<u32> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let args: Vec<_> = cmdline.split(|b| *b == 0).collect();
        let zombie = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(") ")
                    .map(|(_, rest)| rest.starts_with('Z'))
            })
            .unwrap_or(true);
        if !zombie && args.len() >= 2 && args[1] == marker.as_bytes() {
            found.push(pid);
        }
    }
    found
}

fn wait_for(mut done: impl FnMut() -> bool, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    done()
}

fn proxy_leaves(lock_directory: &Path) -> Vec<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(own) = std::fs::read_to_string("/proc/self/cgroup") else {
        return Vec::new();
    };
    let Some(relative) = own.lines().find_map(|line| line.strip_prefix("0::")) else {
        return Vec::new();
    };
    let tag = std::fs::metadata(lock_directory).map_or(0, |metadata| metadata.ino());
    let prefix = format!("proxy-{tag:x}-");
    std::fs::read_dir(format!("/sys/fs/cgroup{relative}"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .map(|entry| entry.path())
        .collect()
}

/// Kills whatever is left when the test ends, even when an assertion failed first, so a run
/// without delegation (or a failing one) leaves no process behind.
struct Cleanup {
    marker: String,
    agent: Option<std::process::Child>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(agent) = self.agent.as_mut() {
            let _ = agent.kill();
            let _ = agent.wait();
        }
        sweep(&self.marker);
    }
}

/// Kill whatever the fallback left behind, so a run without delegation stays clean.
fn sweep(marker: &str) {
    for pid in grandchildren(marker) {
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(pid).unwrap_or(i32::MAX)),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
}

fn verdict(name: &str, survivors: &[u32], leaves: &[std::path::PathBuf]) {
    let containment = crate::cgroup::containment();
    eprintln!(
        "{name}: containment={} survivors={survivors:?} leaves={leaves:?}",
        containment.kind()
    );
    if containment == Containment::Cgroup || must_contain() {
        assert_eq!(
            containment,
            Containment::Cgroup,
            "this run must contain the proxy"
        );
        assert!(
            survivors.is_empty(),
            "{name}: processes outlived the proxy: {survivors:?}"
        );
        assert!(
            leaves.is_empty(),
            "{name}: proxy cgroups were left: {leaves:?}"
        );
    }
}

#[test]
fn a_stopped_child_leaves_no_forked_process_behind() {
    let root = std::env::temp_dir().join(format!("proxy-cg-stop-{}", uuid::Uuid::new_v4()));
    let (state, lock_directory) = supervisor_fixture(&root);
    let executable = root.join("fake-traefik");
    let marker = marker();
    let _cleanup = Cleanup {
        marker: marker.clone(),
        agent: None,
    };
    fake_double_forking_traefik(&executable, &marker);
    let probe = generation_probe_server(state.join(DYNAMIC_CONFIG_FILENAME), false);
    let supervisor = TraefikSupervisor::start(
        generation_probe_settings(&root, &state, &lock_directory, executable, probe.address),
        std::sync::Arc::new(|_: String| {}),
    )
    .expect("start supervisor");
    supervisor
        .replace(vec![public_service()])
        .expect("start the child");
    assert!(
        wait_for(
            || !grandchildren(&marker).is_empty(),
            Duration::from_secs(5)
        ),
        "the fake Traefik forked its grandchild"
    );
    if supervisor.containment() == &Containment::Cgroup {
        assert_eq!(proxy_leaves(&lock_directory).len(), 1, "one leaf per child");
    }
    drop(supervisor);
    // cgroup.kill is synchronous up to "populated 0"; the fallback gets the same grace.
    wait_for(|| grandchildren(&marker).is_empty(), Duration::from_secs(2));
    let survivors = grandchildren(&marker);
    let leaves = proxy_leaves(&lock_directory);
    sweep(&marker);
    drop(probe);
    let _ = std::fs::remove_dir_all(&root);
    verdict("stop", &survivors, &leaves);
}

/// Runs only inside the re-executed test binary: an infraternal agent that is about to crash.
#[test]
fn proxy_crash_helper() {
    let Some(root) = std::env::var_os(CRASH_HELPER) else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let state = root.join("state");
    let lock_directory = root.join("private");
    let executable = root.join("fake-traefik");
    let probe = generation_probe_server(state.join(DYNAMIC_CONFIG_FILENAME), false);
    let supervisor = TraefikSupervisor::start(
        generation_probe_settings(&root, &state, &lock_directory, executable, probe.address),
        std::sync::Arc::new(|_: String| {}),
    )
    .expect("start helper supervisor");
    supervisor
        .replace(vec![public_service()])
        .expect("start the helper's child");
    println!("\n{HELPER_READY}");
    thread::sleep(Duration::from_secs(120));
}

#[test]
fn an_agent_crash_leaves_no_forked_process_behind_once_the_next_agent_starts() {
    let root = std::env::temp_dir().join(format!("proxy-cg-crash-{}", uuid::Uuid::new_v4()));
    let (state, lock_directory) = supervisor_fixture(&root);
    let executable = root.join("fake-traefik");
    let marker = marker();
    let mut cleanup = Cleanup {
        marker: marker.clone(),
        agent: None,
    };
    fake_double_forking_traefik(&executable, &marker);

    // The "agent" is this test binary, re-executed to run only the helper, then SIGKILLed.
    let mut agent = Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "supervisor_tests::cgroup_containment::proxy_crash_helper",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CRASH_HELPER, &root)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the crashing agent");
    let output = agent.stdout.take().expect("agent output");
    cleanup.agent = Some(agent);
    let mut ready = false;
    for line in std::io::BufReader::new(output).lines() {
        if line.is_ok_and(|line| line.contains(HELPER_READY)) {
            ready = true;
            break;
        }
    }
    assert!(ready, "the crashing agent started its child");
    assert!(
        wait_for(
            || !grandchildren(&marker).is_empty(),
            Duration::from_secs(5)
        ),
        "the fake Traefik forked its grandchild"
    );
    let agent = cleanup.agent.as_mut().expect("agent handle");
    agent.kill().expect("crash the agent");
    agent.wait().expect("reap the crashed agent");
    // The parent-death signal takes the direct child; the detached grandchild stays.
    thread::sleep(Duration::from_millis(200));
    let orphaned = grandchildren(&marker);
    assert!(
        !orphaned.is_empty(),
        "the crash left an orphan, so the restart has something to stop"
    );

    let restarted = TraefikSupervisor::start(
        generation_probe_settings(
            &root,
            &state,
            &lock_directory,
            root.join("fake-traefik"),
            "127.0.0.1:9".parse().expect("unused probe"),
        ),
        std::sync::Arc::new(|_: String| {}),
    );
    wait_for(|| grandchildren(&marker).is_empty(), Duration::from_secs(2));
    let survivors = grandchildren(&marker);
    let leaves = proxy_leaves(&lock_directory);
    drop(restarted);
    sweep(&marker);
    let _ = std::fs::remove_dir_all(&root);
    verdict("crash", &survivors, &leaves);
}
