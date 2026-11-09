//! Keep full terminal confirmation records on the server-enrollment check path (D368, #433).
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    bootstrap::{Authority, Backend, Bootstrap, Resolved},
    install::{BinaryPaths, Checked, JoinMaterial},
    model::{Destination, Failure, InstallMode, MeshEvidence, Target, TargetAddress},
    probe::Check,
    transport::{CommandOutput, Credentials, Input, Operation, SshSession, SshTransport},
};
use std::sync::Arc;

/// A real-server enrollment origin must not route the check through the ordinary small command reader.
struct Enrollment;
impl Backend for Enrollment {
    fn enrollment_origin(&self) -> Option<String> {
        Some("https://fixture.test".into())
    }
    fn takeover_allowed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, bool> {
        Box::pin(async { Ok(true) })
    }
    fn resolve<'a>(
        &'a self,
        _: &'a Authority,
        _: &'a Target,
        _: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async {
            Ok(Resolved {
                destination: Destination::parse("root@fixture").unwrap(),
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
        Box::pin(async { panic!("no enrollment before confirmation") })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("no facts before confirmation") })
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("no new terminal before confirmation") })
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { panic!("no invitation to retire") })
    }
}

/// Model OpenSSH's small ordinary reader and its separate bounded check reader.
struct LongCheck;
impl SshTransport for LongCheck {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async { Ok(Arc::new(Self) as Arc<dyn SshSession>) })
    }
}
impl SshSession for LongCheck {
    fn run<'a>(&'a self, _: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async {
            Err(Failure::install(
                "The SSH output exceeded its safety limit.",
            ))
        })
    }
    fn check_stream<'a>(&'a self, _: &'a str) -> Operation<'a, (CommandOutput, Option<Checked>)> {
        Box::pin(async {
            let terminals = (1..=40)
                .map(|id| {
                    format!(
                        "{id:032x},726f6f74,62617368,1792195200,7074732f33,0,session-8.scope,{}",
                        "a".repeat(64)
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            let record = format!(
                "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n0\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_INSTALLED {} 64:1234 live ready {terminals}\n",
                "1".repeat(32)
            );
            assert!(record.len() > 4096);
            Ok((
                CommandOutput {
                    stdout: record.into_bytes(),
                },
                None,
            ))
        })
    }
}

/// All terminal metadata must reach the offer before the server can ask for consent.
#[tokio::test]
async fn server_enrollment_uses_the_bounded_check_reader_for_long_terminal_lists() {
    let runner = Bootstrap::new(
        Arc::new(LongCheck),
        Arc::new(Enrollment),
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
                address: TargetAddress::Manual("root@fixture".into()),
                credential: None,
                mode: InstallMode::Root,
                root_consent: true,
            }],
            None,
        )
        .unwrap();
    let mut changes = batch.subscribe();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !batch
            .events(0)
            .1
            .iter()
            .any(|event| event.failure.is_some())
        {
            changes.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let events = batch.events(0).1;
    let failure = events
        .iter()
        .find_map(|event| event.failure.as_ref())
        .unwrap();
    let public = serde_json::to_value(failure).unwrap();
    assert_eq!(
        public["takeover"]["terminals"].as_array().map(Vec::len),
        Some(40)
    );
    let generic = events
        .iter()
        .find_map(|event| event.leftovers.as_ref())
        .unwrap()
        .challenge;
    // A cached UI that ignores terminal metadata must not authorize closing it.
    assert!(
        runner
            .start_fresh(&batch, "owner", "host", generic)
            .is_err()
    );
    let close =
        uuid::Uuid::parse_str(public["takeover"]["close_challenge"].as_str().unwrap()).unwrap();
    assert_ne!(close, uuid::Uuid::nil());
    assert!(runner.start_fresh(&batch, "owner", "host", close).is_ok());
}
