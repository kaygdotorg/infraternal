//! Executable reproduction of the long-OSC cgroup isolation failure on the perf VM [D270, #205].
#![cfg(all(feature = "process-per-user", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, path::PathBuf, process::Command};

/// The caller holds the perf lock and supplies the staged research image and
/// driver. The driver caps only its private host/shell scope; the Rust runner
/// remains outside that OOM domain and requires every sibling to accept input.
#[test]
fn long_osc_under_tight_memory_cap_keeps_every_sibling_typable() {
    // The ordinary build-host suite has no memory-measurement authority. The
    // mandatory perf gate opts in with all three fixture paths; never substitute
    // build-host cgroups or treat this explicit skip as isolation evidence.
    if std::env::var_os("INFRATERNAL_PPU_BINARY").is_none() {
        eprintln!("SKIP: perf VM allocation gate requires staged fixture paths");
        return;
    }
    assert_eq!(
        fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "infraternal-perf-test",
        "this memory-pressure regression belongs on the explicitly named perf VM"
    );
    assert!(nix::unistd::Uid::effective().is_root());
    let binary =
        std::env::var_os("INFRATERNAL_PPU_BINARY").expect("staged research binary required");
    let script = std::env::var_os("INFRATERNAL_PPU_SCRIPT").expect("staged ppu_soak.py required");
    let evidence = PathBuf::from(
        std::env::var_os("INFRATERNAL_PPU_EVIDENCE").expect("unique short evidence path required"),
    );
    let output = Command::new("python3")
        .arg("-B")
        .arg(script)
        .arg("--binary")
        .arg(binary)
        .arg("--source")
        .arg("ppu-memory-regression")
        .arg("--evidence")
        .arg(evidence)
        .args(["--mode", "memory", "--sessions", "20"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "shared host or sibling input failed at the tight cgroup cap:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
