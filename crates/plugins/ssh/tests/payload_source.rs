//! Ensures injected payload failures stop bootstrap before upload and retain their named architecture step [225].
#![allow(clippy::unwrap_used)]
use infraternal_plugin_ssh::{
    bootstrap::{Authority, Backend, Bootstrap, Resolved},
    install::{BinaryPaths, JoinMaterial, PayloadSource},
    model::{
        Destination, Failure, InstallMode, InstallStep, MeshEvidence, Step, Target, TargetAddress,
    },
    probe::Check,
    transport::{CommandOutput, Credentials, Input, Operation, Secret, SshSession, SshTransport},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Session(AtomicUsize);
impl SshTransport for Session {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async { Ok(Arc::new(Self(AtomicUsize::new(0))) as Arc<dyn SshSession>) })
    }
}
impl SshSession for Session {
    fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let call = self.0.fetch_add(1, Ordering::Relaxed);
            if call == 0 {
                // Start-fresh folds read-only ownership inspection into the same
                // sniff command; payload failure must still precede every upload.
                assert!(script.starts_with(infraternal_plugin_ssh::probe::CHECK_SCRIPT));
                assert!(script.ends_with("\ninspect_previous"));
                Ok(CommandOutput {
                    stdout:
                        b"INFRATERNAL_CHECK_V1\nLinux\naarch64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_CLEAR\n"
                            .to_vec(),
                })
            } else {
                panic!("a failed payload resolution must never upload or run an install command");
            }
        })
    }
}
struct ReadyBackend;
impl Backend for ReadyBackend {
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
                url: "https://localhost/remote/join".into(),
                stdin: Secret::new(b"synthetic-capability".to_vec()),
            })
        })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("payload unavailable") })
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("payload unavailable") })
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}
struct RefusedPayload;
impl PayloadSource for RefusedPayload {
    fn get(&self, arch: infraternal_plugin_ssh::probe::Architecture) -> Operation<'_, PathBuf> {
        Box::pin(async move {
            assert!(matches!(
                arch,
                infraternal_plugin_ssh::probe::Architecture::Aarch64
            ));
            Err(
                Failure::install("the binary does not match the signed checksum.")
                    .at(InstallStep::GetArm64Binary),
            )
        })
    }
}
#[tokio::test]
async fn verification_failure_names_step_and_stops_before_upload() {
    let bootstrap = Bootstrap::new(
        Arc::new(Session(AtomicUsize::new(0))),
        Arc::new(ReadyBackend),
        BinaryPaths {
            x86_64: "must-not-read".into(),
            aarch64: "must-not-read".into(),
        },
    )
    .with_payload_source(Arc::new(RefusedPayload));
    let batch = bootstrap
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
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let events = batch.events(0).1;
            if let Some(failed) = events.iter().find(|event| event.step == Step::Failed) {
                let failure = failed.failure.as_ref().unwrap();
                assert_eq!(
                    format!("{failure}"),
                    "Get the arm64 binary: the binary does not match the signed checksum."
                );
                assert!(
                    events
                        .iter()
                        .any(|event| event.message == "Get the arm64 binary")
                );
                assert!(
                    serde_json::to_string(failure)
                        .unwrap()
                        .contains("get-arm64-binary")
                );
                assert!(!events.iter().any(|event| event.step == Step::Done));
                break;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}

struct StalledPayload;
impl PayloadSource for StalledPayload {
    fn get(&self, _: infraternal_plugin_ssh::probe::Architecture) -> Operation<'_, PathBuf> {
        Box::pin(std::future::pending())
    }
}

/// Read real stream bytes while the synthetic release supplies them over virtual time.
struct ProgressingPayload {
    read: tokio::sync::Mutex<tokio::io::DuplexStream>,
    bytes: tokio::sync::watch::Sender<u64>,
}
impl PayloadSource for ProgressingPayload {
    fn progress(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        Some(self.bytes.subscribe())
    }
    fn get(&self, _: infraternal_plugin_ssh::probe::Architecture) -> Operation<'_, PathBuf> {
        Box::pin(async move {
            use tokio::io::AsyncReadExt;
            let mut reader = self.read.lock().await;
            for count in 1..=10 {
                let mut byte = [0];
                reader.read_exact(&mut byte).await.unwrap();
                assert_eq!(byte, [42]);
                self.bytes.send_replace(count);
            }
            Err(
                Failure::install("the progressing acquisition reached its final verification.")
                    .at(InstallStep::GetArm64Binary),
            )
        })
    }
}

/// Neither a 60-second acquisition nor a 180-second attempt may cut off real byte progress.
#[tokio::test(start_paused = true)]
async fn acquisition_progress_outlives_both_whole_transfer_clocks() {
    use tokio::io::AsyncWriteExt;
    let (mut remote, local) = tokio::io::duplex(64);
    let sending = tokio::spawn(async move {
        for _ in 0..10 {
            // sleep: release each actual acquisition byte after advancing virtual time.
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            if remote.write_all(&[42]).await.is_err() {
                return;
            }
        }
    });
    let source = ProgressingPayload {
        read: tokio::sync::Mutex::new(local),
        bytes: tokio::sync::watch::channel(0).0,
    };
    let bootstrap = Bootstrap::new(
        Arc::new(Session(AtomicUsize::new(0))),
        Arc::new(ReadyBackend),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
        },
    )
    .with_payload_source(Arc::new(source));
    let batch = bootstrap
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
    loop {
        if let Some(failed) = batch
            .events(0)
            .1
            .iter()
            .find(|event| event.step == Step::Failed)
        {
            assert_eq!(
                failed.failure.as_ref().unwrap().message,
                "the progressing acquisition reached its final verification."
            );
            break;
        }
        changed.changed().await.unwrap();
    }
    sending.await.unwrap();
}
#[tokio::test(start_paused = true)]
async fn stalled_download_retains_the_named_step_before_the_attempt_deadline() {
    let bootstrap = Bootstrap::new(
        Arc::new(Session(AtomicUsize::new(0))),
        Arc::new(ReadyBackend),
        BinaryPaths {
            x86_64: "must-not-read".into(),
            aarch64: "must-not-read".into(),
        },
    )
    .with_payload_source(Arc::new(StalledPayload));
    let batch = bootstrap
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
    tokio::time::timeout(std::time::Duration::from_secs(181), async {
        loop {
            let events = batch.events(0).1;
            if let Some(failed) = events.iter().find(|event| event.step == Step::Failed) {
                assert_eq!(
                    format!("{}", failed.failure.as_ref().unwrap()),
                    "Get the arm64 binary: the builds host did not respond in time."
                );
                break;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}
