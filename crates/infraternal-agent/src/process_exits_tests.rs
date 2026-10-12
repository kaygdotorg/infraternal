//! Real-child exit readiness, lifetime isolation and descriptor cleanup checks for the shared queue [D81].
use super::process_exits::ProcessExits;
use nix::{
    fcntl::{FcntlArg, FdFlag, fcntl},
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Fixture(Child);
impl Fixture {
    fn new() -> Self {
        Self(
            Command::new("sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn stop(&mut self) {
        kill(
            Pid::from_raw(i32::try_from(self.0.id()).unwrap()),
            Signal::SIGKILL,
        )
        .unwrap();
        self.0.wait().unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn shared_queue_detects_exit_and_does_not_repeat_or_retain_descriptors() {
    let mut exits = ProcessExits::default();
    let mut first = Fixture::new();
    let mut second = Fixture::new();
    assert!(exits.watch([1; 16], first.0.id()).unwrap());
    assert!(exits.watch([2; 16], second.0.id()).unwrap());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), exits.changed())
            .await
            .is_err()
    );
    first.stop();
    let ids = tokio::time::timeout(Duration::from_secs(2), exits.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ids, vec![[1; 16]]);
    exits.retain(|id| *id == [2; 16]);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), exits.changed())
            .await
            .is_err()
    );
    second.stop();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), exits.changed())
            .await
            .unwrap()
            .unwrap(),
        vec![[2; 16]]
    );
    exits.retain(|_| false);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), exits.changed())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn exited_before_registration_is_not_a_live_registration() {
    let mut exits = ProcessExits::default();
    let mut child = Fixture::new();
    child.stop();
    assert!(!exits.watch([3; 16], child.0.id()).unwrap());
}

#[test]
fn process_descriptor_is_cloexec_and_rejects_invalid_pid() {
    let fd = infraternal_shim::process_exit_descriptor(std::process::id()).unwrap();
    let flags = FdFlag::from_bits_truncate(fcntl(&fd, FcntlArg::F_GETFD).unwrap());
    assert!(flags.contains(FdFlag::FD_CLOEXEC));
    assert!(infraternal_shim::process_exit_descriptor(0).is_err());
    assert!(infraternal_shim::process_exit_descriptor(u32::MAX).is_err());
}

#[tokio::test]
#[ignore = "200 live process lifetimes; run in a weighted benchmark scope"]
async fn shared_exit_queue_at_200_processes() {
    let mut children: Vec<_> = (0..200).map(|_| Fixture::new()).collect();
    let mut exits = ProcessExits::default();
    let descriptors = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before_fds = descriptors();
    let started = std::time::Instant::now();
    for (index, child) in children.iter().enumerate() {
        let mut id = [0; 16];
        id[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
        assert!(exits.watch(id, child.0.id()).unwrap());
    }
    let registration_us = started.elapsed().as_micros();
    let active_fds = descriptors();
    assert_eq!(
        active_fds - before_fds,
        201,
        "200 pidfds and one shared epoll source"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), exits.changed())
            .await
            .is_err()
    );
    let started = std::time::Instant::now();
    for child in &mut children {
        child.stop();
    }
    let mut ended = std::collections::HashSet::new();
    while ended.len() < 200 {
        let batch = tokio::time::timeout(Duration::from_secs(2), exits.changed())
            .await
            .unwrap()
            .unwrap();
        ended.extend(batch);
        exits.retain(|id| !ended.contains(id));
    }
    let detection_us = started.elapsed().as_micros();
    let retired_fds = descriptors();
    assert_eq!(
        retired_fds - before_fds,
        1,
        "only the shared queue remains after all lifetimes retire"
    );
    println!(
        "shared_exit_descriptors: live=200 before={before_fds} active={active_fds} retired={retired_fds} per_lifetime=1 shared=1"
    );
    println!(
        "shared_exit_queue: lifetimes=200 registrations_us={registration_us} stop_and_drain_us={detection_us} readiness_sources=1 shim_tasks=0 pidfds_per_lifetime=1 arch={} cores={} load={}",
        std::env::consts::ARCH,
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), exits.changed())
            .await
            .is_err()
    );
}
