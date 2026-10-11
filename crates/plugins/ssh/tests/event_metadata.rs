//! Verifies authentication evidence survives unsupported checks and resets independently on retry.
#![allow(clippy::unwrap_used)]
use infraternal_plugin_ssh::{
    auth_order::{AuthMethod, Authentication},
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

struct Transport(AtomicUsize);
impl SshTransport for Transport {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                Ok(Arc::new(UnsupportedHost) as Arc<dyn SshSession>)
            } else {
                Err(Failure::new(
                    infraternal_plugin_ssh::model::FailureKind::Auth,
                    "Choose an authentication method.",
                ))
            }
        })
    }
}
struct UnsupportedHost;
impl SshSession for UnsupportedHost {
    fn authentication(&self) -> Option<Authentication> {
        Some(Authentication {
            method: AuthMethod::ServerKey,
            network: None,
        })
    }
    fn run<'a>(&'a self, _: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async {
            Ok(CommandOutput {
                stdout: b"INFRATERNAL_CHECK_V1\nDarwin\nx86_64\nnone\n1002\nno\nno\nno\nno\n"
                    .to_vec(),
            })
        })
    }
}
struct ReadOnly;
impl Backend for ReadOnly {
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
        Box::pin(async { panic!("unsupported host cannot enroll") })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("unsupported host cannot join") })
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("unsupported host cannot open terminals") })
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("no invitation to revoke") })
    }
}
#[tokio::test]
async fn unsupported_host_reports_method_and_retry_never_replays_it_as_current() {
    let runner = Bootstrap::new(
        Arc::new(Transport(AtomicUsize::new(0))),
        Arc::new(ReadOnly),
        BinaryPaths {
            x86_64: "unused".into(),
            aarch64: "unused".into(),
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
    let mut changes = batch.subscribe();
    for attempt in 1..=2 {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !batch
                .events(0)
                .1
                .iter()
                .any(|e| e.attempt == attempt && e.step == Step::Failed)
            {
                changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let events = batch.events(0).1;
        let failure = events
            .iter()
            .find(|e| e.attempt == attempt && e.step == Step::Failed)
            .unwrap();
        assert!(events.iter().all(|e| e.host_id.is_none()));
        if attempt == 1 {
            assert_eq!(
                failure.authentication.unwrap().method,
                AuthMethod::ServerKey
            );
            let replay = serde_json::to_string(failure).unwrap();
            assert!(replay.contains("server-key"));
            runner.retry(&batch, "owner", "host").unwrap();
        } else {
            assert!(
                events
                    .iter()
                    .filter(|e| e.attempt == 2)
                    .all(|e| e.authentication.is_none())
            );
            assert_eq!(
                events
                    .iter()
                    .find(|e| e.attempt == 1 && e.step == Step::Failed)
                    .unwrap()
                    .authentication
                    .unwrap()
                    .method,
                AuthMethod::ServerKey
            );
        }
    }
}
