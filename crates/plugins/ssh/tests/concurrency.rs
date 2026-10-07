//! Proves global admission, failure isolation and credential precedence using deterministic held backend calls.
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    bootstrap::{Backend, Bootstrap, Resolved},
    install::{BinaryPaths, JoinMaterial},
    model::{Destination, Failure, InstallMode, MeshEvidence, Step, Target, TargetAddress},
    probe::Check,
    transport::{CommandOutput, Credentials, Input, Operation, SshSession, SshTransport},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;

struct HeldBackend {
    entered: Semaphore,
    release: Semaphore,
    active: AtomicUsize,
    peak: AtomicUsize,
}
impl Backend for HeldBackend {
    fn resolve<'a>(
        &'a self,
        _: &'a str,
        target: &'a Target,
        credential: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async move {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
            self.active.fetch_sub(1, Ordering::SeqCst);
            assert_eq!(
                credential,
                Some(if target.id == "a0" {
                    "individual"
                } else {
                    "shared"
                })
            );
            Ok(Resolved {
                destination: Destination::parse("user@fixture").unwrap(),
                credentials: Credentials::ServerIdentity,
                mesh: MeshEvidence::default(),
            })
        })
    }
    fn invitation<'a>(
        &'a self,
        _: &'a str,
        _: &'a Target,
        _: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async { Err(Failure::install("The enrollment runtime is unavailable.")) })
    }
    fn connected_facts<'a>(&'a self, _: &'a str, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("facts before admission") })
    }
    fn terminal_canary<'a>(&'a self, _: &'a str, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("terminal before admission") })
    }
    fn failed<'a>(&'a self, _: &'a str, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("no host invitation was issued") })
    }
}
struct ReadOnly;
impl SshTransport for ReadOnly {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async { Ok(Arc::new(ReadOnly) as Arc<dyn SshSession>) })
    }
}
impl SshSession for ReadOnly {
    fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            assert_eq!(
                script,
                infraternal_plugin_ssh::probe::CHECK_SCRIPT,
                "locked/unavailable enrollment must fail before any host mutation"
            );
            Ok(CommandOutput {
                stdout: b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n"
                    .to_vec(),
            })
        })
    }
}
fn targets(prefix: &str, count: usize) -> Vec<Target> {
    (0..count)
        .map(|index| Target {
            id: format!("{prefix}{index}"),
            address: TargetAddress::Manual("user@fixture".into()),
            credential: if prefix == "a" && index == 0 {
                Some("individual".into())
            } else {
                None
            },
            mode: InstallMode::Rootless,
            root_consent: false,
        })
        .collect()
}

#[tokio::test]
async fn concurrency_is_eight_across_batches_and_all_ten_hosts_fail_independently() {
    let backend = Arc::new(HeldBackend {
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
    });
    let runner = Bootstrap::new(
        Arc::new(ReadOnly),
        backend.clone(),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    );
    let a = runner
        .start("owner".into(), targets("a", 6), Some("shared".into()))
        .unwrap();
    let b = runner
        .start("owner".into(), targets("b", 4), Some("shared".into()))
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        backend.entered.acquire_many(8),
    )
    .await
    .unwrap()
    .unwrap()
    .forget();
    assert_eq!(backend.active.load(Ordering::SeqCst), 8);
    assert_eq!(backend.peak.load(Ordering::SeqCst), 8);
    assert!(runner.retry(&a, "owner", "a0").is_err());
    assert!(runner.retry(&a, "foreign", "a0").is_err());
    backend.release.add_permits(10);
    let mut updates = a.subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while a
            .events(0)
            .1
            .iter()
            .filter(|e| e.step == Step::Failed)
            .count()
            != 6
        {
            updates.changed().await.unwrap();
        }
        let mut updates = b.subscribe();
        while b
            .events(0)
            .1
            .iter()
            .filter(|e| e.step == Step::Failed)
            .count()
            != 4
        {
            updates.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(backend.peak.load(Ordering::SeqCst), 8);
    for batch in [&a, &b] {
        let (_, events) = batch.events(0);
        assert!(
            events
                .windows(2)
                .all(|pair| pair[1].sequence == pair[0].sequence + 1)
        );
        assert!(!events.iter().any(|event| event.step == Step::Install));
    }
    backend.release.add_permits(1);
    runner.retry(&a, "owner", "a0").unwrap();
    let mut updates = a.subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !a
            .events(0)
            .1
            .iter()
            .any(|e| e.target == "a0" && e.attempt == 2 && e.step == Step::Failed)
        {
            updates.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn entire_batch_validates_before_start_and_duplicates_are_refused() {
    let backend = Arc::new(HeldBackend {
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
    });
    let runner = Bootstrap::new(
        Arc::new(ReadOnly),
        backend.clone(),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    );
    let mut batch = targets("a", 2);
    batch[1].mode = InstallMode::Root;
    assert!(runner.start("owner".into(), batch, None).is_err());
    let mut batch = targets("a", 2);
    batch[1].id = batch[0].id.clone();
    assert!(runner.start("owner".into(), batch, None).is_err());
    assert_eq!(backend.entered.available_permits(), 0);
}

#[tokio::test]
#[ignore = "explicit CPUWeight10000 scale measurement with a controlled unavailable backend"]
async fn a_thousand_admitted_targets_keep_eight_active_backend_calls() {
    fn rss() -> u64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmRSS:")?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
            .unwrap()
    }
    let baseline = rss();
    let backend = Arc::new(HeldBackend {
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
    });
    let runner = Bootstrap::new(
        Arc::new(ReadOnly),
        backend.clone(),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    );
    let started = std::time::Instant::now();
    let batches: Vec<_> = (0..10)
        .map(|index| {
            runner
                .start(
                    "owner".into(),
                    targets(&format!("batch{index}-"), 100),
                    Some("shared".into()),
                )
                .unwrap()
        })
        .collect();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        backend.entered.acquire_many(8),
    )
    .await
    .unwrap()
    .unwrap()
    .forget();
    let held = rss();
    assert_eq!(backend.active.load(Ordering::SeqCst), 8);
    backend.release.add_permits(1000);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for batch in &batches {
            let mut updates = batch.subscribe();
            while batch
                .events(0)
                .1
                .iter()
                .filter(|event| event.step == Step::Failed)
                .count()
                != 100
            {
                updates.changed().await.unwrap();
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(backend.peak.load(Ordering::SeqCst), 8);
    println!(
        "METRIC controlled_backend targets=1000 batches=10 active_peak=8 baseline_rss_kib={baseline} held_rss_kib={held} completed_rss_kib={} elapsed_ms={} excludes_full_server=true",
        rss(),
        started.elapsed().as_millis()
    );
}
