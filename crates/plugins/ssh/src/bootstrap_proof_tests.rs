//! Exercises overlapping post-publication proofs and the one-use commit fence without clocks or host state (#189).
use super::*;
use crate::model::{InstallMode, TargetAddress};
use crate::transport::CommandOutput;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
struct Proofs {
    commit_budget: Mutex<Option<Duration>>,
    observed_commit_timeout: Mutex<Option<Duration>>,
    facts_started: tokio::sync::Notify,
    canary_started: tokio::sync::Notify,
    facts_release: tokio::sync::Notify,
    canary_release: tokio::sync::Notify,
    fail_facts: AtomicBool,
    cleaned: AtomicBool,
    committed: AtomicBool,
    commit_failure: tokio::sync::Notify,
}
impl Backend for Proofs {
    fn setup_commit_timeout(&self, _: &Authority, _: uuid::Uuid) -> Option<Duration> {
        *self.commit_budget.lock().unwrap()
    }
    fn resolve<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async { panic!("not part of proof") })
    }
    fn invitation<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async { panic!("not part of proof") })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            self.facts_started.notify_one();
            self.facts_release.notified().await;
            if self.fail_facts.load(Ordering::SeqCst) {
                Err(Failure::install("The proof fixture refused its facts."))
            } else {
                Ok(())
            }
        })
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            self.canary_started.notify_one();
            self.canary_release.notified().await;
            Ok(())
        })
    }
    fn cleanup_sessions<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            self.cleaned.store(true, Ordering::SeqCst);
            Ok(())
        })
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("published shell cannot be retired") })
    }
}
impl SshTransport for Proofs {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async { panic!("not part of proof") })
    }
}
struct Commit(Arc<Proofs>);
impl SshSession for Commit {
    fn setup_steps(&self) -> bool {
        true
    }
    fn run<'a>(&'a self, _: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let Input::Signal(release) = input else {
                panic!("only a commit signal is allowed");
            };
            tokio::select! {
                approved = release => approved.map_err(|_| Failure::install("No proof approval."))?,
                () = self.0.commit_failure.notified() => return Err(Failure::install("The commit channel stopped.")),
            }
            self.0.committed.store(true, Ordering::SeqCst);
            Ok(CommandOutput { stdout: Vec::new() })
        })
    }
    fn run_with_timeout<'a>(
        &'a self,
        script: &'a str,
        input: Input<'a>,
        timeout: Duration,
    ) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            *self.0.observed_commit_timeout.lock().unwrap() = Some(timeout);
            tokio::time::timeout(timeout, self.run(script, input))
                .await
                .map_err(|_| Failure::install("The SSH commit command exceeded its time limit."))?
        })
    }
}

/// A caller's anomalous observation cannot create a command timer past the
/// setup limit, and the timer must not impose any minimum successful duration.
#[tokio::test(start_paused = true)]
async fn review_commit_clamps_outliers_and_releases_immediately() {
    for budget in [
        Duration::from_secs(60),
        Duration::from_secs(114),
        Duration::from_secs(186),
        Duration::MAX,
    ] {
        let (runner, authority, installation, proofs, host) = context();
        *proofs.commit_budget.lock().unwrap() = Some(budget);
        proofs.facts_release.notify_one();
        proofs.canary_release.notify_one();
        let started = tokio::time::Instant::now();
        runner
            .complete_setup(&authority, host, &installation, true)
            .await
            .unwrap();
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(
            *proofs.observed_commit_timeout.lock().unwrap(),
            Some(budget.min(Duration::from_secs(180)))
        );
        assert!(proofs.committed.load(Ordering::SeqCst));
    }
}

/// An outlier must not leave a stalled command or its private proof alive
/// beyond the attempt cap, even when no readiness notification arrives.
#[tokio::test(start_paused = true)]
async fn review_stalled_commit_cannot_outlive_attempt_cap() {
    let (runner, authority, installation, proofs, host) = context();
    *proofs.commit_budget.lock().unwrap() = Some(Duration::MAX);
    let started = tokio::time::Instant::now();
    let error = runner
        .complete_setup(&authority, host, &installation, true)
        .await
        .unwrap_err();
    assert_eq!(started.elapsed(), Duration::from_secs(180));
    assert!(matches!(
        error.failed_step,
        Some(crate::model::InstallStep::Install)
    ));
    assert!(proofs.cleaned.load(Ordering::SeqCst));
    assert!(!proofs.committed.load(Ordering::SeqCst));
}

fn context() -> (Bootstrap, Authority, Installation, Arc<Proofs>, uuid::Uuid) {
    let proofs = Arc::new(Proofs::default());
    let runner = Bootstrap::new(
        proofs.clone(),
        proofs.clone(),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    );
    let host = uuid::Uuid::new_v4();
    let authority = Authority {
        owner: "owner".into(),
        batch: uuid::Uuid::new_v4(),
        session: None,
        api_key_hash: None,
    };
    let target = Target {
        id: "proof".into(),
        address: TargetAddress::Manual("owner@fixture.test".into()),
        credential: None,
        mode: InstallMode::Rootless,
        root_consent: false,
    };
    let join = JoinMaterial {
        host,
        url: "https://fixture.test/join".into(),
        stdin: Secret::new(Vec::new()),
    };
    let installation = Installation::new(Arc::new(Commit(proofs.clone())), &target, &join).unwrap();
    (runner, authority, installation, proofs, host)
}

#[tokio::test]
async fn api_key_bootstrap_accepts_the_server_sha256_base64url_key_id() {
    let (runner, _, _, _, _) = context();
    let key_hash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(key_hash.len(), 43);

    let result = runner.start_api_key(
        "owner".into(),
        key_hash.into(),
        vec![Target {
            id: "api-target".into(),
            address: TargetAddress::Manual("owner@fixture.test".into()),
            credential: None,
            mode: InstallMode::Rootless,
            root_consent: false,
        }],
    );
    assert!(
        result.is_ok(),
        "Auth::hash uses unpadded base64url SHA-256 ids, not hex"
    );
}

#[tokio::test]
async fn api_key_bootstrap_rejects_noncanonical_key_ids() {
    let (runner, _, _, _, _) = context();
    let result = runner.start_api_key(
        "owner".into(),
        "B".repeat(43),
        vec![Target {
            id: "api-target".into(),
            address: TargetAddress::Manual("owner@fixture.test".into()),
            credential: None,
            mode: InstallMode::Rootless,
            root_consent: false,
        }],
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn published_proofs_start_together_and_commit_requires_both() {
    let (runner, authority, installation, proofs, host) = context();
    let operation = runner.complete_setup(&authority, host, &installation, true);
    tokio::pin!(operation);
    tokio::select! {
        result = &mut operation => panic!("proofs completed before release: {result:?}"),
        ready = tokio::time::timeout(Duration::from_secs(3), async {
            proofs.facts_started.notified().await;
            proofs.canary_started.notified().await;
        }) => ready.unwrap(),
    }
    assert!(!proofs.committed.load(Ordering::SeqCst));
    proofs.facts_release.notify_one();
    tokio::select! {
        result = &mut operation => panic!("one proof permitted commit: {result:?}"),
        () = tokio::task::yield_now() => {}
    }
    assert!(!proofs.committed.load(Ordering::SeqCst));
    proofs.canary_release.notify_one();
    operation.await.unwrap();
    assert!(proofs.committed.load(Ordering::SeqCst));
    assert!(!proofs.cleaned.load(Ordering::SeqCst));
}

#[tokio::test]
async fn failed_published_facts_clean_only_the_private_probe_and_never_commit() {
    let (runner, authority, installation, proofs, host) = context();
    proofs.fail_facts.store(true, Ordering::SeqCst);
    proofs.facts_release.notify_one();
    assert!(
        runner
            .complete_setup(&authority, host, &installation, true)
            .await
            .is_err()
    );
    assert!(proofs.cleaned.load(Ordering::SeqCst));
    assert!(!proofs.committed.load(Ordering::SeqCst));
}

/// A stopped commit channel cancels the sibling proof futures after the private
/// probe has started. Cleanup must cover this exit as well as a proof refusal.
#[tokio::test]
async fn review_stopped_commit_channel_finishes_the_private_probe() {
    let (runner, authority, installation, proofs, host) = context();
    let operation = runner.complete_setup(&authority, host, &installation, true);
    tokio::pin!(operation);
    tokio::select! {
        result = &mut operation => panic!("proof completed before release: {result:?}"),
        ready = tokio::time::timeout(Duration::from_secs(3), async {
            proofs.facts_started.notified().await;
            proofs.canary_started.notified().await;
        }) => ready.unwrap(),
    }
    proofs.commit_failure.notify_one();
    assert!(operation.await.is_err());
    assert!(!proofs.committed.load(Ordering::SeqCst));
    assert!(
        proofs.cleaned.load(Ordering::SeqCst),
        "a stopped commit channel left the registered private probe without cleanup"
    );
}
