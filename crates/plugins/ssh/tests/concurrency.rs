//! Exercises global admission, component shutdown and login selection using held backend calls and a real helper.
#![allow(clippy::unwrap_used)]

mod common;

use infraternal_plugin_ssh::{
    bootstrap::{Authority, Backend, Bootstrap, Resolved},
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
    helper: Option<std::path::PathBuf>,
}
struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Backend for HeldBackend {
    fn resolve<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        credential: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async move {
            assert_eq!(authority.owner, "owner");
            if let Some(session) = authority.session() {
                // A failed assertion must not format the private capability.
                assert!(session.expose().eq(b"synthetic-session-capability"));
            }
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            self.entered.add_permits(1);
            let _active = Active(&self.active);
            if let Some(path) = &self.helper {
                let mut command = tokio::process::Command::new("/bin/sh");
                let script = format!(
                    "printf '%s' \"$$\" > {}; sleep 60 & wait",
                    infraternal_plugin_ssh::transport::shell_quote(path.to_str().unwrap())
                );
                command.args(["-c", &script]);
                infraternal_plugin_ssh::process::execute(
                    &mut command,
                    Input::Empty,
                    std::time::Duration::from_secs(70),
                )
                .await?;
            } else {
                self.release.acquire().await.unwrap().forget();
            }
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
                credentials: Credentials::Network,
                mesh: MeshEvidence::default(),
            })
        })
    }
    fn invitation<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async { Err(Failure::install("The enrollment runtime is unavailable.")) })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("facts before admission") })
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("terminal before admission") })
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
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
        helper: None,
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
        helper: None,
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
        helper: None,
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

#[tokio::test]
async fn authenticated_batches_retain_an_opaque_session_for_trusted_issuance() {
    use infraternal_plugin_ssh::transport::Secret;
    let backend = Arc::new(HeldBackend {
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        helper: None,
    });
    let runner = Bootstrap::new(
        Arc::new(ReadOnly),
        backend.clone(),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    );
    assert!(
        runner
            .start_authenticated(
                "owner".into(),
                Secret::new(Vec::new()),
                targets("b", 1),
                Some("shared".into())
            )
            .is_err()
    );
    let batch = runner
        .start_authenticated(
            "owner".into(),
            Secret::new(b"synthetic-session-capability".to_vec()),
            targets("b", 1),
            Some("shared".into()),
        )
        .unwrap();
    backend.entered.acquire().await.unwrap().forget();
    backend.release.add_permits(1);
    let mut changed = batch.subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !batch
            .events(0)
            .1
            .iter()
            .any(|event| event.step == Step::Failed)
        {
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(batch.events(0).1.iter().all(|event| {
        !serde_json::to_string(event)
            .unwrap()
            .contains("synthetic-session-capability")
    }));
}

#[tokio::test]
async fn turning_off_drains_queued_work_and_reenable_never_resumes_old_batches() {
    use infraternal_plugin_api::{Plugin, PluginState};
    let backend = Arc::new(HeldBackend {
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        helper: None,
    });
    let runner = Bootstrap::new(
        Arc::new(ReadOnly),
        backend.clone(),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    );
    runner.descriptor().validate().unwrap();
    assert_eq!(runner.status().state, PluginState::On);
    assert_eq!(runner.status().active_work, 0);
    // Idempotent enable must not terminate any adapter listening for off.
    let mut enabled = runner.enabled_changes();
    runner.set_enabled(true).await.unwrap();
    assert!(!enabled.has_changed().unwrap());
    let batch = runner
        .start("owner".into(), targets("batch", 100), Some("shared".into()))
        .unwrap();
    backend.entered.acquire_many(8).await.unwrap().forget();
    assert_eq!(runner.status().active_work, 100);
    tokio::time::timeout(std::time::Duration::from_secs(5), runner.set_enabled(false))
        .await
        .unwrap()
        .unwrap();
    enabled.changed().await.unwrap();
    assert!(!*enabled.borrow());
    assert_eq!(runner.status().state, PluginState::Off);
    assert_eq!(runner.status().active_work, 0);
    assert_eq!(backend.active.load(Ordering::SeqCst), 0);
    assert_eq!(
        batch
            .events(0)
            .1
            .iter()
            .filter(|event| event.step == Step::Failed)
            .count(),
        100
    );
    assert!(
        runner
            .start("owner".into(), targets("a", 1), Some("shared".into()))
            .is_err()
    );
    assert!(runner.activity().is_err());
    runner.set_enabled(true).await.unwrap();
    assert!(runner.retry(&batch, "owner", "batch0").is_err());
    let fresh = runner
        .start("owner".into(), targets("b", 1), Some("shared".into()))
        .unwrap();
    backend.entered.acquire().await.unwrap().forget();
    runner.set_enabled(false).await.unwrap();
    assert_eq!(
        fresh
            .events(0)
            .1
            .iter()
            .filter(|event| event.step == Step::Failed)
            .count(),
        1
    );
}

#[tokio::test]
async fn an_interrupted_disable_keeps_admission_closed_until_its_adapter_retires() {
    use infraternal_plugin_api::{Plugin, PluginState};
    let backend = Arc::new(HeldBackend {
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        helper: None,
    });
    let runner = Bootstrap::new(
        Arc::new(ReadOnly),
        backend,
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    );
    let activity = runner.activity().unwrap();
    let mut enabled = runner.enabled_changes();
    let stopping = runner.clone();
    let disabled = tokio::spawn(async move { stopping.set_enabled(false).await });
    enabled.changed().await.unwrap();
    assert_eq!(runner.status().state, PluginState::Stopping);
    disabled.abort();
    let _ = disabled.await;
    assert!(runner.activity().is_err());
    let starting = runner.clone();
    let (entered, admission) = tokio::sync::oneshot::channel();
    let started = tokio::spawn(async move {
        entered.send(()).unwrap();
        starting.set_enabled(true).await
    });
    admission.await.unwrap();
    assert!(!started.is_finished());
    drop(activity);
    tokio::time::timeout(std::time::Duration::from_secs(5), started)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(runner.status().state, PluginState::On);
    assert_eq!(runner.status().active_work, 0);
}

#[tokio::test]
async fn component_off_retires_a_real_native_helper() {
    use infraternal_plugin_api::Plugin;
    let path = common::scratch().join(format!("component-helper-{}", uuid::Uuid::new_v4()));
    let backend = Arc::new(HeldBackend {
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        helper: Some(path.clone()),
    });
    let runner = Bootstrap::new(
        Arc::new(ReadOnly),
        backend.clone(),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    );
    let _batch = runner
        .start("owner".into(), targets("b", 1), Some("shared".into()))
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while std::fs::read_to_string(&path)
            .unwrap_or_default()
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let pid: u32 = std::fs::read_to_string(&path).unwrap().parse().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), runner.set_enabled(false))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(runner.status().active_work, 0);
    assert_eq!(backend.active.load(Ordering::SeqCst), 0);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|stat| stat.split_whitespace().nth(2) != Some("Z"))
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    std::fs::remove_file(path).unwrap();
}
