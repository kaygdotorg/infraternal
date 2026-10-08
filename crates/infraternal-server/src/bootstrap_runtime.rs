//! Provides a fail-closed default until #78 supplies production enrollment, discovery/vault and remote readiness adapters.

use crate::{
    ServerConfig, ServerError,
    auth::Auth,
    ssh_key::{SshKeySource, SshKeyVault, StoredSshKey},
};
use sqlx::SqlitePool;

use infraternal_plugin_ssh::{
    auth_order::{AuthProvider, AutoAuth, NetworkProvider},
    bootstrap::{Authority, Backend, Bootstrap, Resolved},
    install::{BinaryPaths, JoinMaterial},
    model::{Destination, Failure, MeshEvidence, Target, TargetAddress},
    openssh::OpenSsh,
    probe::Check,
    transport::{Credentials, Operation, Secret},
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

/// Trusted administrator-envelope custody is injected by the same integration
/// boundary as #78's CA source. Server startup generates once and stays locked.
/// Ordinary owner/browser login never unwraps either signing identity.
pub struct KeyInitialization {
    /// Wrap for current administrators through their existing custody adapter.
    pub vault: Arc<dyn SshKeyVault>,
    /// Retain this exact source so administrator unlock, Settings and SSH share a lock.
    pub factory: KeyBootstrapFactory,
}

/// Shares one cold-locked source between Settings, administrator unlock and SSH.
pub type KeyBootstrapFactory =
    Box<dyn FnOnce(Auth, SqlitePool, Arc<StoredSshKey>) -> Bootstrap + Send>;

/// Initialize dedicated encrypted SSH custody and serve with the trusted remote runtime.
/// # Errors
/// Refuses unavailable administrator envelopes and existing sanitized startup errors.
pub async fn serve_with_provisioning(
    config: ServerConfig,
    setup: KeyInitialization,
) -> Result<(), ServerError> {
    crate::runtime::serve_with_key_setup(config, None, Some(setup)).await
}

/// Manual server-identity checks work now; missing trusted integration never permits mutation.
pub(crate) fn default_runner(
    data_dir: &Path,
    auth: Auth,
    key: Arc<dyn SshKeySource>,
) -> Result<Bootstrap, ServerError> {
    let executable = std::env::current_exe().map_err(|_| ServerError::InvalidConfiguration)?;
    Ok(Bootstrap::new(
        Arc::new(AutoAuth::new(Arc::new(OpenSsh {
            ssh: "ssh".into(),
            ssh_agent: "ssh-agent".into(),
            ssh_add: "ssh-add".into(),
            ssh_keyscan: "ssh-keyscan".into(),
            ssh_keygen: "ssh-keygen".into(),
            askpass_binary: executable.clone(),
            scratch: data_dir.join("ssh"),
            command_timeout: Duration::from_secs(30),
        }))),
        Arc::new(PendingRemoteRuntime {
            auth: Some(auth),
            key,
        }),
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

struct PendingRemoteRuntime {
    auth: Option<Auth>,
    key: Arc<dyn SshKeySource>,
}
impl Backend for PendingRemoteRuntime {
    fn resolve<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        _: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async move {
            let TargetAddress::Manual(address) = &target.address else {
                return Err(Failure::unsupported(
                    "Host discovery is unavailable in this build. Use an SSH address.",
                ));
            };
            Ok(Resolved {
                destination: Destination::parse(address)?,
                // Vault selectors are not resolved ahead of earlier methods.
                // Until a browser unlock/vault adapter is present, later inputs
                // are absent and exhaustion yields the typed choose-method result.
                credentials: Credentials::Automatic(Arc::new(ServerAuthentication {
                    auth: self.auth.clone(),
                    key: self.key.clone(),
                    owner: authority.owner.clone(),
                    session: authority
                        .session()
                        .map(|session| Secret::new(session.expose().to_vec())),
                })),
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
/// The exact queued browser capability is checked immediately before exporting
/// signing material; Settings access and owner status never unlock a cold key.
struct ServerAuthentication {
    auth: Option<Auth>,
    key: Arc<dyn SshKeySource>,
    owner: String,
    session: Option<Secret>,
}
impl AuthProvider for ServerAuthentication {
    fn network(&self) -> Option<NetworkProvider> {
        None
    }
    fn server_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async move {
            let (Some(auth), Some(session)) = (&self.auth, &self.session) else {
                return Ok(None);
            };
            let token = std::str::from_utf8(session.expose())
                .map_err(|_| Failure::unsupported("The bootstrap session is unavailable."))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|time| i64::try_from(time.as_secs()).ok())
                .ok_or_else(|| Failure::install("The server clock is unavailable."))?;
            if !auth
                .bootstrap_owner(token, now)
                .await
                .is_ok_and(|owner| owner == self.owner)
            {
                // Revoked authority stops all fallback, rather than admitting a
                // later browser key/password after a permission failure.
                return Err(Failure::unsupported(
                    "The bootstrap session is no longer authorized.",
                ));
            }
            self.key
                .load()
                .ok()
                .map(|key| {
                    key.credentials().map_err(|_| {
                        Failure::install("The dedicated server SSH key is unavailable.")
                    })
                })
                .transpose()
        })
    }
    fn user_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { Ok(None) })
    }
    fn password(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { Ok(None) })
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
        model::{FailureKind, InstallMode, Step},
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
            Arc::new(AutoAuth::new(Arc::new(CheckOnly))),
            Arc::new(PendingRemoteRuntime {
                auth: None,
                key: Arc::new(crate::ssh_key::UnavailableSshKey),
            }),
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
                FailureKind::Install,
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
