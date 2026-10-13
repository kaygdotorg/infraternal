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
    fn stream<'a>(&'a self, _: &'a str) -> Operation<'a, infraternal_plugin_ssh::duplex::Duplex> {
        Box::pin(async {
            // Only public session receipts are simulated. Real shim identity,
            // ownership and byte continuity have separate real-process oracles.
            let mut command = tokio::process::Command::new("/bin/sh");
            command.args(["-c", "printf 'STEP upload\nTRANSFER reuse\nSTEP start\nSESSION 12345678-1234-4234-8234-123456789012\n'; sleep 30"]);
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
