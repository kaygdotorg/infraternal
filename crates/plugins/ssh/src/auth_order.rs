//! Tries D183 authentication in order, exposing each one-connection secret only when needed.

use crate::probe::CHECK_SCRIPT;
use crate::{
    model::{Destination, Failure, FailureKind, InstallMode, MeshEvidence},
    transport::{CommandOutput, Credentials, Input, Operation, SshSession, SshTransport},
};
use serde::Serialize;
use std::sync::{Arc, Mutex, OnceLock};

/// Mesh identity is trusted inventory evidence; an SSH banner cannot identify a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkProvider {
    Netbird,
    Tailscale,
    Twingate,
    Other,
}

/// The method that actually completed a bounded authenticated command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMethod {
    Network,
    ServerKey,
    UserKey,
    Password,
}

/// Public connection metadata; no identity, secret, or remote diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Authentication {
    pub method: AuthMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkProvider>,
}

/// Trusted adapters consume browser-unwrapped secrets once, bound to this host and session.
/// Missing/locked material returns None; no method may prompt or decrypt a later method early.
pub trait AuthProvider: Send + Sync {
    fn network(&self) -> Option<NetworkProvider>;
    fn server_key(&self) -> Operation<'_, Option<Credentials>>;
    fn user_key(&self) -> Operation<'_, Option<Credentials>>;
    fn password(&self) -> Operation<'_, Option<Credentials>>;
}

/// Reuses the selected SSH transport and its strict trust/lifetime boundaries.
pub struct AutoAuth {
    transport: Arc<dyn SshTransport>,
}

impl AutoAuth {
    #[must_use]
    pub fn new(transport: Arc<dyn SshTransport>) -> Self {
        Self { transport }
    }

    async fn authenticate(
        &self,
        destination: &Destination,
        credentials: Credentials,
        mesh: MeshEvidence,
        script: &str,
        bridge: bool,
    ) -> Result<
        (
            Arc<dyn SshSession>,
            Result<(CommandOutput, Option<crate::install::Checked>), Failure>,
        ),
        Failure,
    > {
        let session = self
            .transport
            .open(destination.clone(), credentials, mesh)
            .await?;
        // Opening the SSH session proves this credential authenticated. Keep the
        // session even when the read-only check returns a recoverable command status:
        // callers may need the same connection to refresh an old setup helper.
        let result = if bridge {
            session.check_stream(script).await
        } else {
            session
                .run(script, Input::Empty)
                .await
                .map(|output| (output, None))
        };
        Ok((session, result))
    }

    async fn automatic(
        &self,
        destination: Destination,
        provider: Arc<dyn AuthProvider>,
        mesh: MeshEvidence,
        script: &str,
        bridge: bool,
    ) -> Result<
        (
            Arc<dyn SshSession>,
            Result<(CommandOutput, Option<crate::install::Checked>), Failure>,
            Authentication,
        ),
        Failure,
    > {
        // OpenSSH performs its protocol none exchange inside a local-method
        // connection too. Unknown/manual hosts need no separate refusal login.
        // Trusted known network providers keep the earlier lazy network path;
        // credentialless manual hosts still reach the final network fallback.
        let network = provider.network();
        let methods = if network.is_some() {
            [
                AuthMethod::Network,
                AuthMethod::ServerKey,
                AuthMethod::UserKey,
                AuthMethod::Password,
            ]
        } else {
            [
                AuthMethod::ServerKey,
                AuthMethod::UserKey,
                AuthMethod::Password,
                AuthMethod::Network,
            ]
        };
        for method in methods {
            // The future is created inside the loop: successful earlier auth must
            // not request the next browser secret or read the locked server key.
            let credentials = match method {
                AuthMethod::ServerKey => provider.server_key().await,
                AuthMethod::UserKey => provider.user_key().await,
                AuthMethod::Password => provider.password().await,
                AuthMethod::Network => Ok(Some(Credentials::Network)),
            };
            let credentials = match credentials {
                Ok(Some(credentials)) => credentials,
                Ok(None) => continue,
                Err(error) if error.kind == FailureKind::Auth => continue,
                Err(error) => return Err(error),
            };
            if !matches!(
                (&credentials, method),
                (
                    Credentials::PrivateKey { .. },
                    AuthMethod::ServerKey | AuthMethod::UserKey
                ) | (Credentials::Password(_), AuthMethod::Password)
                    | (Credentials::Network, AuthMethod::Network)
            ) {
                return Err(Failure::install(
                    "The SSH credential provider returned the wrong method.",
                ));
            }
            match self
                .authenticate(&destination, credentials, mesh, script, bridge)
                .await
            {
                Ok((session, result)) => {
                    let evidence = session.authentication();
                    return Ok((
                        session,
                        result,
                        Authentication {
                            method: if evidence
                                .is_some_and(|receipt| receipt.method == AuthMethod::Network)
                            {
                                AuthMethod::Network
                            } else {
                                method
                            },
                            network: if method == AuthMethod::Network
                                || evidence
                                    .is_some_and(|receipt| receipt.method == AuthMethod::Network)
                            {
                                network
                            } else {
                                None
                            },
                        },
                    ));
                }
                Err(error) if error.kind == FailureKind::Auth && error.exit_status.is_none() => {}
                Err(error) => return Err(error),
            }
        }
        let mut failure = Failure::new(FailureKind::Auth, "Choose an SSH authentication method.");
        failure.choose_method = true;
        Err(failure)
    }
}

impl SshTransport for AutoAuth {
    fn open(
        &self,
        destination: Destination,
        credentials: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            match credentials {
                Credentials::Automatic(provider) => Ok(Arc::new(Pending {
                    transport: self.transport.clone(),
                    destination,
                    mesh,
                    provider: Mutex::new(Some(provider)),
                    selected: tokio::sync::Mutex::new(None),
                    authentication: Mutex::new(None),
                    trust_lookup: Mutex::new(None),
                }) as Arc<dyn SshSession>),
                credentials => self.transport.open(destination, credentials, mesh).await,
            }
        })
    }
    fn confirm_host_key<'a>(
        &'a self,
        destination: Destination,
        challenge: &'a str,
        fingerprint: &'a str,
        authority: &'a dyn crate::transport::ConfirmationAuthority,
    ) -> Operation<'a, ()> {
        self.transport
            .confirm_host_key(destination, challenge, fingerprint, authority)
    }
}

/// Serialize the first read-only check, then reuse its authenticated method.
/// This avoids a successful authentication-only SSH round trip before the check.
struct Pending {
    transport: Arc<dyn SshTransport>,
    destination: Destination,
    mesh: MeshEvidence,
    provider: Mutex<Option<Arc<dyn AuthProvider>>>,
    selected: tokio::sync::Mutex<Option<Arc<dyn SshSession>>>,
    authentication: Mutex<Option<Authentication>>,
    trust_lookup: Mutex<Option<String>>,
}
impl SshSession for Pending {
    fn session_bridge(&self) -> bool {
        self.selected.try_lock().is_ok_and(|selected| {
            selected
                .as_ref()
                .is_some_and(|session| session.session_bridge())
        })
    }
    fn stream<'a>(&'a self, script: &'a str) -> Operation<'a, crate::duplex::Duplex> {
        Box::pin(async move {
            let session = self
                .selected
                .lock()
                .await
                .as_ref()
                .cloned()
                .ok_or_else(|| {
                    Failure::unsupported("Sign in before opening the SSH terminal bridge.")
                })?;
            session.stream(script).await
        })
    }

    fn setup_steps(&self) -> bool {
        self.selected.try_lock().is_ok_and(|selected| {
            selected
                .as_ref()
                .is_some_and(|session| session.setup_steps())
        })
    }
    fn trust_lookup(&self) -> Option<String> {
        self.trust_lookup
            .lock()
            .ok()
            .and_then(|lookup| lookup.clone())
    }
    fn authentication(&self) -> Option<Authentication> {
        self.authentication
            .lock()
            .ok()
            .and_then(|metadata| *metadata)
    }
    fn check_stream<'a>(
        &'a self,
        script: &'a str,
    ) -> Operation<'a, (CommandOutput, Option<crate::install::Checked>)> {
        Box::pin(self.select_check(script, true))
    }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            if let Some(session) = self.selected.lock().await.as_ref().cloned() {
                return session.run(script, input).await;
            }
            if !matches!(input, Input::Empty) {
                return Err(Failure::install(
                    "SSH authentication requires the read-only system check.",
                ));
            }
            self.select_check(script, false)
                .await
                .map(|(output, _)| output)
        })
    }

    fn run_with_timeout<'a>(
        &'a self,
        script: &'a str,
        input: Input<'a>,
        timeout: std::time::Duration,
    ) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            // A commit can run only after the read-only check selected and
            // authenticated its method. Preserve that connection's caller
            // deadline instead of falling back to its ordinary SSH timeout.
            let session = self
                .selected
                .lock()
                .await
                .as_ref()
                .cloned()
                .ok_or_else(|| {
                    Failure::install("SSH authentication requires the read-only system check.")
                })?;
            session.run_with_timeout(script, input, timeout).await
        })
    }
}
impl Pending {
    async fn select_check(
        &self,
        script: &str,
        bridge: bool,
    ) -> Result<(CommandOutput, Option<crate::install::Checked>), Failure> {
        let mut selected = self.selected.lock().await;
        if let Some(session) = selected.as_ref().cloned() {
            drop(selected);
            return if bridge {
                session.check_stream(script).await
            } else {
                session
                    .run(script, Input::Empty)
                    .await
                    .map(|output| (output, None))
            };
        }
        // Fallback may replay only the exact read-only check. The duplex channel
        // stops at CHECK ready until the caller explicitly writes public setup.
        if !authentication_check(script) {
            return Err(Failure::install(
                "SSH authentication requires the read-only system check.",
            ));
        }
        let provider = self
            .provider
            .lock()
            .map_err(|_| Failure::install("The SSH credential scope is unavailable."))?
            .take()
            .ok_or_else(|| {
                Failure::install("The one-connection authentication attempt has ended.")
            })?;
        let (session, result, authentication) = AutoAuth::new(self.transport.clone())
            .automatic(
                self.destination.clone(),
                provider,
                self.mesh,
                script,
                bridge,
            )
            .await?;
        *self
            .authentication
            .lock()
            .map_err(|_| Failure::install("The SSH authentication result is unavailable."))? =
            Some(authentication);
        *self
            .trust_lookup
            .lock()
            .map_err(|_| Failure::install("The SSH trust result is unavailable."))? =
            session.trust_lookup();
        *selected = Some(session);
        result
    }
}

/// Ownership inspection is part of the fixed read-only check after start-fresh.
/// Exact equality is essential: a caller cannot append a mutation and have an
/// authentication refusal cause it to replay under another credential.
fn authentication_check(script: &str) -> bool {
    static CHECKS: OnceLock<[String; 3]> = OnceLock::new();
    if script == CHECK_SCRIPT {
        return true;
    }
    CHECKS
        .get_or_init(|| {
            [
                crate::previous_attempt::check_script(InstallMode::Rootless),
                crate::previous_attempt::check_script(InstallMode::Root),
                format!("{CHECK_SCRIPT}\nprintf 'INFRATERNAL_SETUP_CLEAR\\n'"),
            ]
        })
        .iter()
        .any(|check| script == check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TimedSession(Mutex<Option<std::time::Duration>>);
    impl SshSession for TimedSession {
        fn run<'a>(&'a self, _: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
            Box::pin(async { panic!("ordinary timeout path used") })
        }

        fn run_with_timeout<'a>(
            &'a self,
            _: &'a str,
            _: Input<'a>,
            timeout: std::time::Duration,
        ) -> Operation<'a, CommandOutput> {
            *self.0.lock().unwrap() = Some(timeout);
            Box::pin(async { Ok(CommandOutput { stdout: Vec::new() }) })
        }
    }

    #[tokio::test]
    async fn pending_forwards_the_caller_deadline_to_its_selected_session() {
        let selected = Arc::new(TimedSession(Mutex::new(None)));
        let pending = Pending {
            transport: Arc::new(UnusedTransport),
            destination: Destination::parse("user@fixture").unwrap(),
            mesh: MeshEvidence::default(),
            provider: Mutex::new(None),
            selected: tokio::sync::Mutex::new(Some(selected.clone())),
            authentication: Mutex::new(None),
            trust_lookup: Mutex::new(None),
        };
        let timeout = std::time::Duration::from_secs(91);
        pending
            .run_with_timeout("commit", Input::Empty, timeout)
            .await
            .unwrap();
        assert_eq!(*selected.0.lock().unwrap(), Some(timeout));
    }

    struct UnusedTransport;
    impl SshTransport for UnusedTransport {
        fn open(
            &self,
            _: Destination,
            _: Credentials,
            _: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            Box::pin(async { Err(Failure::install("Unexpected SSH transport open.")) })
        }
    }

    #[test]
    fn only_exact_generated_read_only_checks_can_choose_credentials() {
        let mut checks = vec![
            CHECK_SCRIPT.to_owned(),
            format!("{CHECK_SCRIPT}\nprintf 'INFRATERNAL_SETUP_CLEAR\\n'"),
        ];
        checks.extend(
            [InstallMode::Rootless, InstallMode::Root].map(crate::previous_attempt::check_script),
        );
        for check in checks {
            assert!(authentication_check(&check));
            assert!(!authentication_check(&format!("{check}\ntouch unexpected")));
        }
        assert!(!authentication_check("true"));
    }

    struct FailingCheckSession(AtomicUsize);
    impl SshSession for FailingCheckSession {
        fn run<'a>(&'a self, _: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
            let call = self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if call == 0 {
                    let mut failure = Failure::install("The cached setup helper needs refresh.");
                    failure.exit_status = Some(76);
                    Err(failure)
                } else {
                    Ok(CommandOutput {
                        stdout: b"check complete\n".to_vec(),
                    })
                }
            })
        }
    }

    struct FailingCheckTransport {
        opens: AtomicUsize,
        session: Arc<FailingCheckSession>,
    }
    impl SshTransport for FailingCheckTransport {
        fn open(
            &self,
            _: Destination,
            _: Credentials,
            _: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            let session: Arc<dyn SshSession> = self.session.clone();
            Box::pin(async move { Ok(session) })
        }
    }

    struct NetworkOnlyProvider;
    impl AuthProvider for NetworkOnlyProvider {
        fn network(&self) -> Option<NetworkProvider> {
            Some(NetworkProvider::Other)
        }
        fn server_key(&self) -> Operation<'_, Option<Credentials>> {
            Box::pin(async { Ok(None) })
        }
        fn user_key(&self) -> Operation<'_, Option<Credentials>> {
            Box::pin(async { Ok(None) })
        }
        fn password(&self) -> Operation<'_, Option<Credentials>> {
            Box::pin(async { Ok(None) })
        }
    }

    #[tokio::test]
    async fn authenticated_nonzero_check_keeps_session_for_helper_refresh() {
        let session = Arc::new(FailingCheckSession(AtomicUsize::new(0)));
        let transport = Arc::new(FailingCheckTransport {
            opens: AtomicUsize::new(0),
            session: session.clone(),
        });
        let pending = Pending {
            transport: transport.clone(),
            destination: Destination::parse("user@fixture").unwrap(),
            mesh: MeshEvidence::default(),
            provider: Mutex::new(Some(Arc::new(NetworkOnlyProvider))),
            selected: tokio::sync::Mutex::new(None),
            authentication: Mutex::new(None),
            trust_lookup: Mutex::new(None),
        };

        let Err(failure) = pending.run(CHECK_SCRIPT, Input::Empty).await else {
            panic!("first helper probe must request refresh");
        };
        assert_eq!(failure.exit_status, Some(76));
        let output = pending
            .run(CHECK_SCRIPT, Input::Empty)
            .await
            .expect("the authenticated session must remain available for retry");

        assert_eq!(output.stdout, b"check complete\n");
        assert_eq!(session.0.load(Ordering::SeqCst), 2);
        assert_eq!(transport.opens.load(Ordering::SeqCst), 1);
    }
}
