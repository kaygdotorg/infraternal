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
    ) -> Result<(Arc<dyn SshSession>, CommandOutput), Failure> {
        let session = self
            .transport
            .open(destination.clone(), credentials, mesh)
            .await?;
        // Only an allowlisted read-only check reaches this method; it proves auth.
        // Command-status failures do not qualify as SSH authentication refusals.
        let output = session.run(script, Input::Empty).await?;
        Ok((session, output))
    }

    async fn automatic(
        &self,
        destination: Destination,
        provider: Arc<dyn AuthProvider>,
        mesh: MeshEvidence,
        script: &str,
    ) -> Result<(Arc<dyn SshSession>, CommandOutput, Authentication), Failure> {
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
                .authenticate(&destination, credentials, mesh, script)
                .await
            {
                Ok((session, output)) => {
                    let evidence = session.authentication();
                    return Ok((
                        session,
                        output,
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
                Err(error) if error.kind == FailureKind::Auth => {}
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
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let mut selected = self.selected.lock().await;
            if let Some(session) = &*selected {
                let session = session.clone();
                drop(selected);
                return session.run(script, input).await;
            }
            // Authentication fallback can repeat only the fixed read-only check.
            // Never replay an upload, join capability or mutating command.
            if !authentication_check(script) || !matches!(input, Input::Empty) {
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
            let adapter = AutoAuth::new(self.transport.clone());
            let (session, output, authentication) = adapter
                .automatic(self.destination.clone(), provider, self.mesh, script)
                .await?;
            *self
                .authentication
                .lock()
                .map_err(|_| Failure::install("The SSH authentication result is unavailable."))? =
                Some(authentication);
            // Preserve the authenticated connection's exact public lookup;
            // removal must forget its pin, including after method fallback.
            *self
                .trust_lookup
                .lock()
                .map_err(|_| Failure::install("The SSH trust result is unavailable."))? =
                session.trust_lookup();
            *selected = Some(session);
            Ok(output)
        })
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
}
