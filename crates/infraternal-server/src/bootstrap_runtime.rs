//! Builds SSH bootstrap adapters around server authorization, CA enrollment and remote readiness.

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
    model::{
        Destination, Failure, InstallMode, InstallStep, MeshEvidence, Step, Target, TargetAddress,
    },
    openssh::OpenSsh,
    probe::Check,
    transport::{Credentials, Operation, Secret},
    trust::TrustedOpenSsh,
};
#[cfg(test)]
use std::time::Duration;
use std::{path::Path, sync::Arc};

#[cfg(feature = "remote")]
#[path = "bootstrap_remote.rs"]
mod remote_backend;
#[cfg(feature = "remote")]
pub(crate) type RemoteBootstrap = (
    crate::remote_http::InvitationIssuer,
    crate::remote_runtime::RemoteHosts,
);
#[cfg(not(feature = "remote"))]
pub(crate) type RemoteBootstrap = ();

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

/// Compose one cold-locked SSH identity and runner with the server's live authority.
/// No alternate authentication or enrollment store is created [23,138,168,183].
pub(crate) async fn initialize(
    data_dir: &Path,
    auth: &Auth,
    pool: &SqlitePool,
    factory: Option<BootstrapFactory>,
    key_setup: Option<KeyInitialization>,
    remote: Option<RemoteBootstrap>,
) -> Result<(Bootstrap, Arc<dyn SshKeySource>), ServerError> {
    let result: (_, Arc<dyn SshKeySource>) = if let Some(setup) = key_setup {
        let key = Arc::new(
            StoredSshKey::initialize(pool, setup.vault.as_ref())
                .await
                .map_err(|_| ServerError::InvalidConfiguration)?,
        );
        (
            (setup.factory)(auth.clone(), pool.clone(), key.clone()),
            key,
        )
    } else {
        let key: Arc<dyn SshKeySource> = match StoredSshKey::cold_start(pool)
            .await
            .map_err(|_| ServerError::InvalidConfiguration)?
        {
            Some(key) => Arc::new(key),
            None => Arc::new(crate::ssh_key::UnavailableSshKey),
        };
        let bootstrap = match factory {
            Some(factory) => factory(auth.clone(), pool.clone()),
            None => default_runner(data_dir, auth.clone(), key.clone(), remote)?,
        };
        (bootstrap, key)
    };
    Ok(result)
}

/// Manual server-identity checks work now; missing trusted integration never permits mutation.
pub(crate) fn default_runner(
    data_dir: &Path,
    auth: Auth,
    key: Arc<dyn SshKeySource>,
    remote: Option<RemoteBootstrap>,
) -> Result<Bootstrap, ServerError> {
    let running = std::env::current_exe().map_err(|_| ServerError::InvalidConfiguration)?;
    // Anonymous replacement labels have no filesystem siblings. Preserve the
    // original absolute invocation path only for adjacent development payloads;
    // the prompt helper always copies the kernel running image, never this path.
    let executable = if running
        .as_os_str()
        .as_encoded_bytes()
        .ends_with(b" (deleted)")
    {
        std::env::args_os()
            .next()
            .map(std::path::PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or(running)
    } else {
        running
    };
    let base = PendingRemoteRuntime {
        auth: Some(auth),
        key,
    };
    #[cfg(feature = "remote")]
    let backend: Arc<dyn Backend> = if let Some((issuer, hosts)) = remote {
        Arc::new(remote_backend::RemoteBackend {
            base,
            issuer,
            hosts,
            attempts: std::sync::Mutex::default(),
            sessions_changed: std::sync::Mutex::default(),
        })
    } else {
        Arc::new(base)
    };
    #[cfg(not(feature = "remote"))]
    let backend: Arc<dyn Backend> = {
        let _ = remote;
        Arc::new(base)
    };
    let binaries = BinaryPaths {
        x86_64: std::env::var_os("INFRATERNAL_BOOTSTRAP_X86_64_BINARY").map_or_else(
            || executable.with_file_name("infraternal-x86_64-musl"),
            Into::into,
        ),
        aarch64: std::env::var_os("INFRATERNAL_BOOTSTRAP_AARCH64_BINARY").map_or_else(
            || executable.with_file_name("infraternal-aarch64-musl"),
            Into::into,
        ),
    };
    // Linux exposes the exact running inode even after its installation path is
    // atomically replaced. The public file source opens this in the server process [225].
    let payloads = crate::release_payload::ReleasePayload::new(
        "/proc/self/exe".into(),
        binaries.clone(),
        data_dir,
    );
    Ok(Bootstrap::new(
        Arc::new(AutoAuth::new(Arc::new(TrustedOpenSsh::new(
            OpenSsh {
                ssh: "ssh".into(),
                ssh_agent: "ssh-agent".into(),
                ssh_add: "ssh-add".into(),
                ssh_keyscan: "ssh-keyscan".into(),
                ssh_keygen: "ssh-keygen".into(),
                askpass_binary: "/proc/self/exe".into(),
                tcp_connector: Some(executable.clone()),
                scratch: infraternal_plugin_ssh::credentials::runtime_root(),
                // Byte receipts renew transfers; short commands keep this bound.
                command_timeout: infraternal_plugin_ssh::transport::TRANSFER_IDLE,
            },
            data_dir.join("ssh-trust"),
        )))),
        backend,
        binaries,
    )
    .with_payload_source(payloads))
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
                    api_key_hash: authority.api_key_hash().map(str::to_owned),
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
    fn record_start_fresh(
        &self,
        target: &Target,
        host: uuid::Uuid,
        transaction: uuid::Uuid,
        outcome: &'static str,
    ) {
        tracing::info!(target_id = %target.id, previous_host = %host,
            previous_transaction = %transaction, mode = ?target.mode, outcome,
            ownership_journal = "fresh",
            "host provisioning start fresh");
    }
    fn record_failure(
        &self,
        target: &Target,
        host: Option<uuid::Uuid>,
        phase: Step,
        failure: &Failure,
    ) {
        log_bootstrap_failure(target, host, phase, failure);
    }
    fn failed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        not_ready()
    }
}
/// Emit no remote text or credentials: these bounded coordinates describe one failed attempt.
fn log_bootstrap_failure(
    target: &Target,
    host: Option<uuid::Uuid>,
    phase: Step,
    failure: &Failure,
) {
    let step = match failure.failed_step {
        Some(InstallStep::GetArm64Binary) => "get-arm64-binary",
        Some(InstallStep::GetX86_64Binary) => "get-x86-64-binary",
        Some(InstallStep::Connect) => "connect",
        Some(InstallStep::Upload) => "upload",
        Some(InstallStep::Install) => "install",
        Some(InstallStep::Join) => "join",
        Some(InstallStep::Start) => "start",
        Some(InstallStep::Readiness) => "readiness",
        None => match phase {
            Step::Check => "check",
            Step::Facts => "facts",
            Step::Connect => "terminal",
            _ => "install",
        },
    };
    let mode = match target.mode {
        InstallMode::Rootless => "rootless",
        InstallMode::Root => "root",
    };
    tracing::warn!(host_id = %host.map_or_else(|| "unassigned".into(), |host| host.to_string()),
        target_id = %target.id, step, failure_kind = failure.diagnostic_kind(), exit_status = %failure.exit_status.map_or_else(|| "unavailable".into(), |status| status.to_string()),
        mode, "host bootstrap failed");
}

/// The exact queued browser capability is checked immediately before exporting
/// signing material; Settings access and owner status never unlock a cold key.
struct ServerAuthentication {
    auth: Option<Auth>,
    key: Arc<dyn SshKeySource>,
    owner: String,
    session: Option<Secret>,
    api_key_hash: Option<String>,
}
impl AuthProvider for ServerAuthentication {
    fn network(&self) -> Option<NetworkProvider> {
        None
    }
    fn server_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async move {
            // Without a browser session or key there is no live authority to export under:
            // offer no server key and leave the ordinary credential fallback in place.
            let (Some(auth), true) = (
                &self.auth,
                self.session.is_some() || self.api_key_hash.is_some(),
            ) else {
                return Ok(None);
            };
            let authorized = if let Some(session) = &self.session {
                let token = std::str::from_utf8(session.expose())
                    .map_err(|_| Failure::unsupported("The bootstrap session is unavailable."))?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .and_then(|time| i64::try_from(time.as_secs()).ok())
                    .ok_or_else(|| Failure::install("The server clock is unavailable."))?;
                auth.bootstrap_owner(token, now)
                    .await
                    .is_ok_and(|owner| owner == self.owner)
            } else if let Some(key_hash) = &self.api_key_hash {
                auth.api_authorize_key_hash(key_hash, "hosts:write")
                    .await
                    .is_ok_and(|owner| owner == self.owner)
            } else {
                false
            };
            if !authorized {
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

/// Recheck the exact session or narrow API key before every server-side action boundary.
pub(crate) async fn authorize_authority(auth: &Auth, authority: &Authority) -> bool {
    if let Some(session) = authority.session() {
        let Ok(token) = std::str::from_utf8(session.expose()) else {
            return false;
        };
        let Some(now) = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|time| i64::try_from(time.as_secs()).ok())
        else {
            return false;
        };
        auth.bootstrap_owner(token, now)
            .await
            .is_ok_and(|owner| owner == authority.owner)
    } else if let Some(key_hash) = authority.api_key_hash() {
        auth.api_authorize_key_hash(key_hash, "hosts:write")
            .await
            .is_ok_and(|owner| owner == authority.owner)
    } else {
        false
    }
}

fn not_ready<'a>() -> Operation<'a, ()> {
    Box::pin(async {
        Err(Failure::install(
            "Remote host routing is unavailable in this build.",
        ))
    })
}

#[cfg(feature = "remote")]
fn unix_now() -> Result<i64, Failure> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .ok_or_else(|| Failure::install("The server clock is unavailable."))
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
                assert!(
                    script.starts_with(CHECK_SCRIPT),
                    "pending integration must never upload"
                );
                Ok(CommandOutput {
                    stdout:
                        b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_CLEAR\n"
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

#[cfg(test)]
#[path = "key_authority_tests.rs"]
mod key_authority_tests;

#[cfg(test)]
mod failure_log_tests {
    //! Public setup failure and recovery coordinates are logged without private target details or remote output.
    use super::*;
    use std::{io::Write, sync::Mutex};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }
    #[test]
    fn one_line_contains_only_classified_public_coordinates() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(Capture(bytes.clone()))
            .finish();
        let target = Target {
            id: "one".into(),
            address: TargetAddress::Manual("user@host".into()),
            credential: None,
            mode: InstallMode::Rootless,
            root_consent: false,
        };
        let host = uuid::Uuid::new_v4();
        let mut failure = infraternal_plugin_ssh::openssh::classify(
            b"private-output-sentinel",
            false,
            infraternal_plugin_ssh::model::MeshEvidence::default(),
        );
        failure.message = "private-message-sentinel";
        failure.failed_step = Some(InstallStep::Upload);
        failure.exit_status = Some(71);
        failure.log_tail.push("private-output-sentinel");
        tracing::subscriber::with_default(subscriber, || {
            log_bootstrap_failure(&target, Some(host), Step::Install, &failure);
        });
        let text = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 1);
        for field in [
            host.to_string(),
            "target_id=one".into(),
            "step=\"upload\"".into(),
            "exit_status=71".into(),
            "failure_kind=\"channel\"".into(),
            "mode=\"rootless\"".into(),
        ] {
            assert!(
                text.contains(&field),
                "missing public field {field}: {text}"
            );
        }
        assert!(!text.contains("private-message-sentinel"));
        assert!(!text.contains("private-output-sentinel"));
    }
    #[test]
    fn start_fresh_logs_only_the_exact_public_ownership_journal_and_outcome() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(Capture(bytes.clone()))
            .finish();
        let target = Target {
            id: "one".into(),
            address: TargetAddress::Manual("private-address-sentinel".into()),
            credential: Some("private-selector-sentinel".into()),
            mode: InstallMode::Rootless,
            root_consent: false,
        };
        let backend = PendingRemoteRuntime {
            auth: None,
            key: Arc::new(crate::ssh_key::UnavailableSshKey),
        };
        let host = uuid::Uuid::new_v4();
        let transaction = uuid::Uuid::new_v4();
        tracing::subscriber::with_default(subscriber, || {
            backend.record_start_fresh(&target, host, transaction, "started");
            backend.record_start_fresh(&target, host, transaction, "completed");
        });
        let text = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 2);
        for field in [
            host.to_string(),
            transaction.to_string(),
            "target_id=one".into(),
            "ownership_journal=\"fresh\"".into(),
            "outcome=\"started\"".into(),
            "outcome=\"completed\"".into(),
        ] {
            assert!(text.contains(&field));
        }
        assert!(!text.contains("private-address-sentinel"));
        assert!(!text.contains("private-selector-sentinel"));
    }
}
