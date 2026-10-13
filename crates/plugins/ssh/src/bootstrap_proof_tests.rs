//! Exercises overlapping post-publication proofs and the one-use commit fence without clocks or host state (#189).
use super::*;
use crate::model::{InstallMode, TargetAddress};
use crate::transport::CommandOutput;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
struct Proofs {
    facts_started: tokio::sync::Notify,
    canary_started: tokio::sync::Notify,
    facts_release: tokio::sync::Notify,
    canary_release: tokio::sync::Notify,
    fail_facts: AtomicBool,
    cleaned: AtomicBool,
    committed: AtomicBool,
}
impl Backend for Proofs {
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
            release
                .await
                .map_err(|_| Failure::install("No proof approval."))?;
            self.0.committed.store(true, Ordering::SeqCst);
            Ok(CommandOutput { stdout: Vec::new() })
        })
    }
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
