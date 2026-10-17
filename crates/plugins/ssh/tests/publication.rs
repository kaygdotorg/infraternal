//! Checks that a routing refusal after shim creation terminates wizard progress without rolling back the protected session (D255).
#![allow(clippy::unwrap_used)]

mod common;

use infraternal_plugin_ssh::{
    bootstrap::{Authority, Backend, Bootstrap, Resolved},
    install::{BinaryPaths, JoinMaterial},
    model::{Destination, InstallMode, MeshEvidence, Step, Target, TargetAddress},
    probe::Check,
    transport::{CommandOutput, Credentials, Input, Operation, Secret, SshSession, SshTransport},
};
use std::sync::Arc;

struct Refused;
impl Backend for Refused {
    fn early_terminal(&self) -> bool {
        true
    }
    fn resolve<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async {
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
        Box::pin(async {
            Ok(JoinMaterial {
                host: uuid::Uuid::new_v4(),
                url: "https://fixture.test/join".into(),
                stdin: Secret::new(b"synthetic-private-input".to_vec()),
            })
        })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("facts after refused publication") })
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("canary after refused publication") })
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("protected shim cannot be rolled back") })
    }
}
struct Receipts;
impl SshTransport for Receipts {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async { Ok(Arc::new(Receipts) as Arc<dyn SshSession>) })
    }
}
impl SshSession for Receipts {
    fn session_bridge(&self) -> bool {
        true
    }
    fn run<'a>(&'a self, _: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async {
            Ok(CommandOutput { stdout: b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_CLEAR\n".to_vec() })
        })
    }
    fn stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<'a, infraternal_plugin_ssh::duplex::Duplex> {
        Box::pin(async move {
            // Only public session receipts are simulated. Real shim identity,
            // ownership and byte continuity have separate real-process oracles.
            let mut command = tokio::process::Command::new("/bin/sh");
            let receipts = if script.contains("--session ") {
                "printf 'SESSION 12345678-1234-4234-8234-123456789012\n'; exec cat"
            } else {
                "printf 'STEP upload\nTRANSFER reuse\nSTEP start\nSESSION 12345678-1234-4234-8234-123456789012\n'; exec cat"
            };
            command.args(["-c", receipts]);
            infraternal_plugin_ssh::duplex::Duplex::spawn(&mut command)
        })
    }
}

#[tokio::test]
async fn refused_publication_reports_failure_to_the_waiting_wizard() {
    let path = common::scratch().join(format!("public-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&path, b"synthetic public payload").unwrap();
    let runner = Bootstrap::new(
        Arc::new(Receipts),
        Arc::new(Refused),
        BinaryPaths {
            x86_64: path.clone(),
            aarch64: path.clone(),
        },
    );
    let batch = runner
        .start(
            "owner".into(),
            vec![Target {
                id: "host".into(),
                address: TargetAddress::Manual("user@fixture".into()),
                credential: None,
                mode: InstallMode::Rootless,
                root_consent: false,
            }],
            None,
        )
        .unwrap();
    let mut changed = batch.subscribe();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if batch
                .events(0)
                .1
                .iter()
                .any(|event| event.step == Step::Failed)
            {
                break;
            }
            changed.changed().await.unwrap();
        }
    })
    .await;
    std::fs::remove_file(path).unwrap();
    assert!(
        result.is_ok(),
        "routing refusal left the wizard waiting without Done or Failed"
    );
    assert!(
        !batch
            .events(0)
            .1
            .iter()
            .any(|event| event.step == Step::Done)
    );
}

struct DeferredPayload {
    session: std::path::PathBuf,
    calls: tokio::sync::watch::Sender<usize>,
    release: tokio::sync::Semaphore,
}
impl infraternal_plugin_ssh::install::PayloadSource for DeferredPayload {
    fn session(
        &self,
        _: infraternal_plugin_ssh::probe::Architecture,
    ) -> Operation<'_, Option<std::path::PathBuf>> {
        Box::pin(async { Ok(Some(self.session.clone())) })
    }
    fn get(
        &self,
        _: infraternal_plugin_ssh::probe::Architecture,
    ) -> Operation<'_, std::path::PathBuf> {
        Box::pin(async {
            self.calls.send_modify(|calls| *calls += 1);
            self.release.acquire().await.unwrap().forget();
            Err(infraternal_plugin_ssh::model::Failure::install(
                "the binary does not match the signed checksum.",
            )
            .at(infraternal_plugin_ssh::model::InstallStep::GetX86_64Binary))
        })
    }
}
struct Published {
    host: uuid::Uuid,
    sessions: std::sync::Mutex<Vec<uuid::Uuid>>,
    channels: std::sync::Mutex<Vec<infraternal_plugin_ssh::duplex::Duplex>>,
}
impl Backend for Published {
    fn early_terminal(&self) -> bool {
        true
    }
    fn resolve<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        credential: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Refused.resolve(authority, target, credential)
    }
    fn invitation<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async {
            Ok(JoinMaterial {
                host: self.host,
                url: "https://fixture.test/join".into(),
                stdin: Secret::new(b"synthetic-private-input".to_vec()),
            })
        })
    }
    fn reissue_invitation<'a>(
        &'a self,
        _: &'a Authority,
        _: uuid::Uuid,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async { panic!("a refused full image must not renew enrollment authority") })
    }
    fn publish_terminal<'a>(
        &'a self,
        _: &'a Authority,
        host: uuid::Uuid,
        session: uuid::Uuid,
        channel: infraternal_plugin_ssh::duplex::Duplex,
        _: Arc<dyn SshSession>,
    ) -> Operation<'a, ()> {
        Box::pin(async move {
            assert_eq!(host, self.host);
            channel.write(b"typed-before-full-image\n").await.unwrap();
            assert_eq!(
                channel.line(64).await.unwrap(),
                b"typed-before-full-image\n"
            );
            self.sessions.lock().unwrap().push(session);
            self.channels.lock().unwrap().push(channel);
            Ok(())
        })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("facts before verified full installation") })
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("canary before verified full installation") })
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("late image failure must preserve the published shim") })
    }
}

async fn failed_setup(
    status: &infraternal_plugin_ssh::setup::Status,
    host: uuid::Uuid,
    attempt: u32,
) -> infraternal_plugin_ssh::setup::Event {
    let mut changed = status.subscribe("owner", host).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let events = status.events("owner", host, 0).unwrap().1;
            if let Some(failed) = events.into_iter().find(|event| {
                event.attempt == attempt
                    && event.state == infraternal_plugin_ssh::setup::State::Failed
            }) {
                return failed;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

struct RecoverableTransport {
    opens: std::sync::atomic::AtomicUsize,
    disconnected: Arc<std::sync::atomic::AtomicBool>,
}
impl SshTransport for RecoverableTransport {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        let generation = self.opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let disconnected = self.disconnected.clone();
        Box::pin(async move {
            Ok(Arc::new(RecoverableSession {
                generation,
                disconnected,
            }) as Arc<dyn SshSession>)
        })
    }
}
struct RecoverableSession {
    generation: usize,
    disconnected: Arc<std::sync::atomic::AtomicBool>,
}
impl RecoverableSession {
    fn available(&self) -> bool {
        self.generation != 0 || !self.disconnected.load(std::sync::atomic::Ordering::SeqCst)
    }
}
impl SshSession for RecoverableSession {
    fn session_bridge(&self) -> bool {
        true
    }
    fn stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<'a, infraternal_plugin_ssh::duplex::Duplex> {
        if !self.available() {
            return Box::pin(async {
                Err(infraternal_plugin_ssh::model::Failure::new(
                    infraternal_plugin_ssh::model::FailureKind::Unreachable,
                    "The SSH connection has closed.",
                ))
            });
        }
        Receipts.stream(script)
    }
    fn run<'a>(&'a self, script: &'a str, _input: Input<'a>) -> Operation<'a, CommandOutput> {
        if !self.available() {
            return Box::pin(async {
                Err(infraternal_plugin_ssh::model::Failure::new(
                    infraternal_plugin_ssh::model::FailureKind::Unreachable,
                    "The SSH connection has closed.",
                ))
            });
        }
        let stdout = if script.contains("INFRATERNAL_CHECK_V1") {
            b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_CLEAR\n".to_vec()
        } else if script.contains("printf 'reuse\\n'") {
            b"reuse\n".to_vec()
        } else if script.contains("enable-linger") {
            b"no\n".to_vec()
        } else {
            Vec::new()
        };
        Box::pin(async move { Ok(CommandOutput { stdout }) })
    }
}

struct RetryOncePayload {
    path: std::path::PathBuf,
    full_calls: std::sync::atomic::AtomicUsize,
}
impl infraternal_plugin_ssh::install::PayloadSource for RetryOncePayload {
    fn session(
        &self,
        _: infraternal_plugin_ssh::probe::Architecture,
    ) -> Operation<'_, Option<std::path::PathBuf>> {
        let path = self.path.clone();
        Box::pin(async move { Ok(Some(path)) })
    }
    fn get(
        &self,
        _: infraternal_plugin_ssh::probe::Architecture,
    ) -> Operation<'_, std::path::PathBuf> {
        let call = self
            .full_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = self.path.clone();
        Box::pin(async move {
            if call == 0 {
                Err(infraternal_plugin_ssh::model::Failure::install(
                    "the upload was interrupted by the target network reset.",
                )
                .at(infraternal_plugin_ssh::model::InstallStep::GetX86_64Binary))
            } else {
                Ok(path)
            }
        })
    }
}

struct RetryBackend {
    host: uuid::Uuid,
    disconnect: Arc<std::sync::atomic::AtomicBool>,
    sessions: std::sync::Mutex<Vec<uuid::Uuid>>,
    resolves: std::sync::atomic::AtomicUsize,
}
impl RetryBackend {
    fn material(&self) -> JoinMaterial {
        JoinMaterial {
            host: self.host,
            url: "https://fixture.test/join".into(),
            stdin: Secret::new(b"synthetic-private-input".to_vec()),
        }
    }
}
impl Backend for RetryBackend {
    fn early_terminal(&self) -> bool {
        true
    }
    fn resolve<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        credential: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        self.resolves
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(credential, Some("saved-key"));
        Refused.resolve(authority, target, credential)
    }
    fn invitation<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async move { Ok(self.material()) })
    }
    fn reissue_invitation<'a>(
        &'a self,
        _: &'a Authority,
        _: uuid::Uuid,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async move { Ok(self.material()) })
    }
    fn publish_terminal<'a>(
        &'a self,
        _: &'a Authority,
        host: uuid::Uuid,
        session: uuid::Uuid,
        channel: infraternal_plugin_ssh::duplex::Duplex,
        _: Arc<dyn SshSession>,
    ) -> Operation<'a, ()> {
        Box::pin(async move {
            assert_eq!(host, self.host);
            channel.write(b"typed-before-full-image\n").await.unwrap();
            assert_eq!(
                channel.line(64).await.unwrap(),
                b"typed-before-full-image\n"
            );
            let mut sessions = self.sessions.lock().unwrap();
            if sessions.is_empty() {
                // Model a transport that dies after publishing its usable shell.
                self.disconnect
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            sessions.push(session);
            Ok(())
        })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

async fn setup_attempt_end(
    status: &infraternal_plugin_ssh::setup::Status,
    host: uuid::Uuid,
    attempt: u32,
) -> infraternal_plugin_ssh::setup::Event {
    let mut changed = status.subscribe("owner", host).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(event) =
                status
                    .events("owner", host, 0)
                    .unwrap()
                    .1
                    .into_iter()
                    .find(|event| {
                        event.attempt == attempt
                            && (event.state == infraternal_plugin_ssh::setup::State::Failed
                                || (event.stage == infraternal_plugin_ssh::setup::Stage::Ready
                                    && event.state == infraternal_plugin_ssh::setup::State::Done))
                    })
            {
                return event;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn retry_reopens_ssh_after_transport_loss_and_keeps_the_published_shell() {
    let path = common::scratch().join(format!("reconnect-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&path, b"synthetic verified full payload").unwrap();
    let disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let transport = Arc::new(RecoverableTransport {
        opens: std::sync::atomic::AtomicUsize::new(0),
        disconnected: disconnected.clone(),
    });
    let backend = Arc::new(RetryBackend {
        host: uuid::Uuid::new_v4(),
        disconnect: disconnected,
        sessions: std::sync::Mutex::new(Vec::new()),
        resolves: std::sync::atomic::AtomicUsize::new(0),
    });
    let source = Arc::new(RetryOncePayload {
        path: path.clone(),
        full_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let runner = Bootstrap::new(
        transport.clone(),
        backend.clone(),
        BinaryPaths {
            x86_64: "unverified-local-image-must-not-be-used".into(),
            aarch64: "unverified-local-image-must-not-be-used".into(),
        },
    )
    .with_payload_source(source);
    let batch = runner
        .start(
            "owner".into(),
            vec![Target {
                id: "host".into(),
                address: TargetAddress::Manual("user@fixture".into()),
                credential: Some("saved-key".into()),
                mode: InstallMode::Rootless,
                root_consent: false,
            }],
            None,
        )
        .unwrap();
    let published = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if !backend.sessions.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        published.is_ok(),
        "initial attempt events: {:?}",
        batch.events(0).1
    );
    let failed = failed_setup(&runner.setup_status(), backend.host, 1).await;
    assert!(failed.retry_available);
    runner
        .retry_setup(
            "owner".into(),
            Secret::new(b"synthetic-requester-session".to_vec()),
            backend.host,
        )
        .unwrap();
    let completed = setup_attempt_end(&runner.setup_status(), backend.host, 2).await;
    assert_eq!(
        completed.stage,
        infraternal_plugin_ssh::setup::Stage::Ready,
        "retry event={completed:?}, opens={}, resolves={}, published_sessions={}",
        transport.opens.load(std::sync::atomic::Ordering::SeqCst),
        backend.resolves.load(std::sync::atomic::Ordering::SeqCst),
        backend.sessions.lock().unwrap().len(),
    );
    assert_eq!(completed.state, infraternal_plugin_ssh::setup::State::Done);
    assert_eq!(transport.opens.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(
        backend.resolves.load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    let sessions = backend.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(
        sessions[0], sessions[1],
        "retry replaced the published shell"
    );
    drop(sessions);
    drop(batch);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn signed_session_is_typable_before_full_resolution_and_late_failure_retries_the_same_shell()
{
    let path = common::scratch().join(format!("deferred-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&path, b"synthetic verified session payload").unwrap();
    let source = Arc::new(DeferredPayload {
        session: path.clone(),
        calls: tokio::sync::watch::channel(0).0,
        release: tokio::sync::Semaphore::new(0),
    });
    let backend = Arc::new(Published {
        host: uuid::Uuid::new_v4(),
        sessions: std::sync::Mutex::new(Vec::new()),
        channels: std::sync::Mutex::new(Vec::new()),
    });
    let runner = Bootstrap::new(
        Arc::new(Receipts),
        backend.clone(),
        BinaryPaths {
            x86_64: "unverified-local-image-must-not-be-used".into(),
            aarch64: "unverified-local-image-must-not-be-used".into(),
        },
    )
    .with_payload_source(source.clone());
    let mut calls = source.calls.subscribe();
    let batch = runner
        .start(
            "owner".into(),
            vec![Target {
                id: "host".into(),
                address: TargetAddress::Manual("user@fixture".into()),
                credential: None,
                mode: InstallMode::Rootless,
                root_consent: false,
            }],
            None,
        )
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), calls.changed())
        .await
        .unwrap()
        .unwrap();
    let published_before_full = backend.sessions.lock().unwrap().len();
    let wizard_done_before_full = batch
        .events(0)
        .1
        .iter()
        .any(|event| event.step == Step::Done);
    source.release.add_permits(1);
    // Release the blocked source before asserting, so a failing red test also
    // discharges the acquisition future instead of relying on runtime teardown.
    assert_eq!(
        published_before_full, 1,
        "full acquisition started before a usable SSH session was published"
    );
    assert!(
        wizard_done_before_full,
        "the wizard waited for full image acquisition"
    );
    let status = runner.setup_status();
    for attempt in [1, 2] {
        let failed = failed_setup(&status, backend.host, attempt).await;
        assert!(failed.retry_available);
        assert!(matches!(
            failed.failed_step,
            Some(infraternal_plugin_ssh::model::InstallStep::Install)
        ));
        if attempt == 1 {
            runner
                .retry_setup(
                    "owner".into(),
                    Secret::new(b"synthetic-requester-session".to_vec()),
                    backend.host,
                )
                .unwrap();
            calls.changed().await.unwrap();
            source.release.add_permits(1);
        }
    }
    let sessions = backend.sessions.lock().unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(
        sessions[0], sessions[1],
        "retry replaced the published shell"
    );
    std::fs::remove_file(path).unwrap();
}

struct WarmPayload {
    path: std::path::PathBuf,
    sessions: std::sync::atomic::AtomicUsize,
    full: std::sync::atomic::AtomicUsize,
}
impl infraternal_plugin_ssh::install::PayloadSource for WarmPayload {
    fn session(
        &self,
        _: infraternal_plugin_ssh::probe::Architecture,
    ) -> Operation<'_, Option<std::path::PathBuf>> {
        Box::pin(async {
            self.sessions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Some(self.path.clone()))
        })
    }
    fn get(
        &self,
        _: infraternal_plugin_ssh::probe::Architecture,
    ) -> Operation<'_, std::path::PathBuf> {
        Box::pin(async {
            self.full.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(self.path.clone())
        })
    }
}

#[tokio::test]
async fn encoding_warmup_resolves_admitted_source_images_instead_of_configured_paths() {
    let path = common::scratch().join(format!("warm-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&path, b"synthetic verified payload for encoding warmup").unwrap();
    let source = Arc::new(WarmPayload {
        path: path.clone(),
        sessions: std::sync::atomic::AtomicUsize::new(0),
        full: std::sync::atomic::AtomicUsize::new(0),
    });
    let runner = Bootstrap::new(
        Arc::new(Receipts),
        Arc::new(Refused),
        BinaryPaths {
            x86_64: "unverified-local-image-must-not-be-warmed".into(),
            aarch64: "unverified-local-image-must-not-be-warmed".into(),
        },
    )
    .with_payload_source(source.clone());
    runner.prepare_payloads().await;
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        source.sessions.load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    assert_eq!(source.full.load(std::sync::atomic::Ordering::Relaxed), 2);
}
