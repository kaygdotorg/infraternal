//! Provides a fail-closed default until #78 supplies production enrollment, discovery/vault and remote readiness adapters.

use crate::{ServerConfig, ServerError, auth::Auth};
use sqlx::SqlitePool;

use infraternal_plugin_ssh::{
    bootstrap::{Authority, Backend, Bootstrap, Resolved},
    install::{BinaryPaths, JoinMaterial},
    model::{Destination, Failure, FailureKind, MeshEvidence, Target, TargetAddress},
    openssh::OpenSsh,
    probe::Check,
    transport::{Credentials, Operation},
};
use std::{path::Path, sync::Arc, time::Duration};

/// Receives the exact live authenticator and database, after safe server initialization.
/// #78 supplies its CA/enrollment/remote registry here; no parallel owner/session state.
pub type BootstrapFactory = Box<dyn FnOnce(Auth, SqlitePool) -> Bootstrap + Send>;

/// Serve with the trusted remote runtime's bootstrap adapter.
/// # Errors
/// Returns the existing server startup/listener error contract.
pub async fn serve_with_bootstrap(
    config: ServerConfig,
    factory: BootstrapFactory,
) -> Result<(), ServerError> {
    crate::runtime::serve_with_bootstrap(config, Some(factory)).await
}

/// Manual server-identity checks work now; missing trusted integration never permits mutation.
pub(crate) fn default_runner(data_dir: &Path) -> Result<Bootstrap, ServerError> {
    let executable = std::env::current_exe().map_err(|_| ServerError::InvalidConfiguration)?;
    Ok(Bootstrap::new(
        Arc::new(OpenSsh {
            ssh: "ssh".into(),
            ssh_agent: "ssh-agent".into(),
            ssh_add: "ssh-add".into(),
            ssh_keyscan: "ssh-keyscan".into(),
            ssh_keygen: "ssh-keygen".into(),
            askpass_binary: executable.clone(),
            scratch: data_dir.join("ssh"),
            command_timeout: Duration::from_secs(30),
        }),
        Arc::new(PendingRemoteRuntime),
        BinaryPaths {
            x86_64: std::env::var_os("INFRATERNAL_BOOTSTRAP_X86_64_BINARY").map_or_else(
                || executable.with_file_name("infraternal-x86_64-musl"),
                Into::into,
            ),
            aarch64: std::env::var_os("INFRATERNAL_BOOTSTRAP_AARCH64_BINARY").map_or_else(
                || executable.with_file_name("infraternal-aarch64-musl"),
                Into::into,
            ),
        },
    ))
}

struct PendingRemoteRuntime;
impl Backend for PendingRemoteRuntime {
    fn resolve<'a>(
        &'a self,
        _: &'a Authority,
        target: &'a Target,
        credential: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async move {
            if credential.is_some() {
                return Err(Failure::new(
                    FailureKind::Auth,
                    "The unlocked SSH credential vault is unavailable in this build.",
                ));
            }
            let TargetAddress::Manual(address) = &target.address else {
                return Err(Failure::unsupported(
                    "Host discovery is unavailable in this build. Use an SSH address.",
                ));
            };
            Ok(Resolved {
                destination: Destination::parse(address)?,
                credentials: Credentials::ServerIdentity,
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
            Err(Failure::install(
                "Remote enrollment is unavailable in this build.",
            ))
        })
    }
    fn connected_facts<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        not_ready()
    }
    fn terminal_canary<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        not_ready()
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        not_ready()
    }
}
fn not_ready<'a>() -> Operation<'a, ()> {
    Box::pin(async {
        Err(Failure::install(
            "Remote host routing is unavailable in this build.",
        ))
    })
}

#[cfg(test)]
mod tests {
    //! Checks the unavailable integration against a transport that permits only the read-only sniff.
    use super::*;
    use infraternal_plugin_ssh::{
        model::{InstallMode, Step},
        probe::CHECK_SCRIPT,
        transport::{CommandOutput, Input, SshSession, SshTransport},
    };

    struct CheckOnly;
    impl SshTransport for CheckOnly {
        fn open(
            &self,
            _: Destination,
            _: Credentials,
            _: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            Box::pin(async { Ok(Arc::new(Self) as Arc<dyn SshSession>) })
        }
    }
    impl SshSession for CheckOnly {
        fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
            Box::pin(async move {
                assert_eq!(
                    script, CHECK_SCRIPT,
                    "pending integration must never upload"
                );
                Ok(CommandOutput {
                    stdout:
                        b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n"
                            .to_vec(),
                })
            })
        }
    }

    #[tokio::test]
    async fn pending_integration_refuses_enrollment_vault_and_discovery() {
        let runner = Bootstrap::new(
            Arc::new(CheckOnly),
            Arc::new(PendingRemoteRuntime),
            BinaryPaths {
                x86_64: "must-not-read".into(),
                aarch64: "must-not-read".into(),
            },
        );
        for (address, credential, expected) in [
            (
                TargetAddress::Manual("user@fixture".into()),
                None,
                FailureKind::Install,
            ),
            (
                TargetAddress::Manual("user@fixture".into()),
                Some("vault".into()),
                FailureKind::Auth,
            ),
            (
                TargetAddress::Discovered("inventory".into()),
                None,
                FailureKind::Unsupported,
            ),
        ] {
            let batch = runner
                .start(
                    "owner".into(),
                    vec![Target {
                        id: "host".into(),
                        address,
                        credential,
                        mode: InstallMode::Rootless,
                        root_consent: false,
                    }],
                    None,
                )
                .unwrap();
            let mut changed = batch.subscribe();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let events = batch.events(0).1;
                    assert!(
                        events
                            .iter()
                            .all(|event| event.step == Step::Check || event.step == Step::Failed)
                    );
                    if let Some(event) = events.iter().find(|event| event.step == Step::Failed) {
                        assert_eq!(event.failure.as_ref().unwrap().kind, expected);
                        break;
                    }
                    changed.changed().await.unwrap();
                }
            })
            .await
            .unwrap();
        }
    }
}
