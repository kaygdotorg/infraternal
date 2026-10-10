//! Checks lazy ordered authentication, method reporting and trust failures without materializing later secrets.
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::{
    auth_order::{AuthMethod, AuthProvider, AutoAuth, NetworkProvider},
    model::{Destination, Failure, FailureKind, MeshEvidence},
    transport::{CommandOutput, Credentials, Input, Operation, Secret, SshSession, SshTransport},
};
use std::sync::{Arc, Mutex};

struct Provider {
    requested: Mutex<Vec<AuthMethod>>,
}
impl Provider {
    fn key(&self, method: AuthMethod) -> Operation<'_, Option<Credentials>> {
        self.requested.lock().unwrap().push(method);
        Box::pin(async {
            Ok(Some(Credentials::PrivateKey {
                key: Secret::new(b"synthetic-key-not-used-by-ssh".to_vec()),
                passphrase: None,
            }))
        })
    }
}
impl AuthProvider for Provider {
    fn network(&self) -> Option<NetworkProvider> {
        Some(NetworkProvider::Netbird)
    }
    fn server_key(&self) -> Operation<'_, Option<Credentials>> {
        self.key(AuthMethod::ServerKey)
    }
    fn user_key(&self) -> Operation<'_, Option<Credentials>> {
        self.key(AuthMethod::UserKey)
    }
    fn password(&self) -> Operation<'_, Option<Credentials>> {
        self.requested.lock().unwrap().push(AuthMethod::Password);
        Box::pin(async {
            Ok(Some(Credentials::Password(Secret::new(
                b"synthetic-password".to_vec(),
            ))))
        })
    }
}
struct Transport {
    succeed_at: usize,
    failure: FailureKind,
    opens: Mutex<usize>,
}
impl SshTransport for Transport {
    fn open(
        &self,
        _: Destination,
        credentials: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        let mut opens = self.opens.lock().unwrap();
        *opens += 1;
        assert!(!matches!(credentials, Credentials::Automatic(_)));
        let success = *opens == self.succeed_at;
        let failure = self.failure;
        Box::pin(async move { Ok(Arc::new(Session { success, failure }) as Arc<dyn SshSession>) })
    }
}
struct Session {
    success: bool,
    failure: FailureKind,
}
impl SshSession for Session {
    fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        assert_eq!(script, infraternal_plugin_ssh::probe::CHECK_SCRIPT);
        Box::pin(async move {
            if self.success {
                Ok(CommandOutput { stdout: Vec::new() })
            } else {
                Err(Failure::new(
                    self.failure,
                    "Synthetic authentication refusal.",
                ))
            }
        })
    }
}

#[tokio::test]
async fn successful_authentication_is_reported_and_later_secrets_are_never_requested() {
    for (index, method, requested) in [
        (1, AuthMethod::Network, vec![]),
        (2, AuthMethod::ServerKey, vec![AuthMethod::ServerKey]),
        (
            3,
            AuthMethod::UserKey,
            vec![AuthMethod::ServerKey, AuthMethod::UserKey],
        ),
        (
            4,
            AuthMethod::Password,
            vec![
                AuthMethod::ServerKey,
                AuthMethod::UserKey,
                AuthMethod::Password,
            ],
        ),
    ] {
        let transport = Arc::new(Transport {
            succeed_at: index,
            failure: FailureKind::Auth,
            opens: Mutex::new(0),
        });
        let adapter = AutoAuth::new(transport.clone());
        let provider = Arc::new(Provider {
            requested: Mutex::new(Vec::new()),
        });
        let session = adapter
            .open(
                Destination::parse("user@fixture").unwrap(),
                Credentials::Automatic(provider.clone()),
                MeshEvidence::default(),
            )
            .await
            .unwrap();
        assert!(session.authentication().is_none());
        session
            .run(infraternal_plugin_ssh::probe::CHECK_SCRIPT, Input::Empty)
            .await
            .unwrap();
        assert_eq!(*provider.requested.lock().unwrap(), requested);
        assert_eq!(*transport.opens.lock().unwrap(), index);
        let auth = session.authentication().unwrap();
        assert_eq!(auth.method, method);
        assert_eq!(
            auth.network,
            if index == 1 {
                Some(NetworkProvider::Netbird)
            } else {
                None
            }
        );
    }
}

#[tokio::test]
async fn trust_network_and_remote_command_failures_stop_without_loading_local_secrets() {
    for kind in [
        FailureKind::HostKey,
        FailureKind::Unreachable,
        FailureKind::MeshPolicy,
        FailureKind::Install,
        FailureKind::Unsupported,
    ] {
        let transport = Arc::new(Transport {
            succeed_at: 0,
            failure: kind,
            opens: Mutex::new(0),
        });
        let adapter = AutoAuth::new(transport.clone());
        let provider = Arc::new(Provider {
            requested: Mutex::new(Vec::new()),
        });
        let result = adapter
            .open(
                Destination::parse("user@fixture").unwrap(),
                Credentials::Automatic(provider.clone()),
                MeshEvidence::default(),
            )
            .await;
        let session = result.unwrap();
        let result = session
            .run(infraternal_plugin_ssh::probe::CHECK_SCRIPT, Input::Empty)
            .await;
        let Err(error) = result else {
            panic!("must refuse connection")
        };
        assert_eq!(error.kind, kind);
        assert!(!error.choose_method);
        assert!(provider.requested.lock().unwrap().is_empty());
        assert_eq!(*transport.opens.lock().unwrap(), 1);
    }
}

#[tokio::test]
async fn only_exhausted_auth_returns_typed_choose_method() {
    let adapter = AutoAuth::new(Arc::new(Transport {
        succeed_at: 0,
        failure: FailureKind::Auth,
        opens: Mutex::new(0),
    }));
    let provider = Arc::new(Provider {
        requested: Mutex::new(Vec::new()),
    });
    let result = adapter
        .open(
            Destination::parse("user@fixture").unwrap(),
            Credentials::Automatic(provider.clone()),
            MeshEvidence::default(),
        )
        .await;
    let session = result.unwrap();
    let result = session
        .run(infraternal_plugin_ssh::probe::CHECK_SCRIPT, Input::Empty)
        .await;
    let Err(error) = result else {
        panic!("must refuse connection")
    };
    assert_eq!(error.kind, FailureKind::Auth);
    assert!(error.choose_method);
    assert_eq!(
        *provider.requested.lock().unwrap(),
        vec![
            AuthMethod::ServerKey,
            AuthMethod::UserKey,
            AuthMethod::Password
        ]
    );
}

#[tokio::test]
async fn authentication_never_replays_a_mutating_first_command_or_reuses_a_failed_scope() {
    let transport = Arc::new(Transport {
        succeed_at: 0,
        failure: FailureKind::Auth,
        opens: Mutex::new(0),
    });
    let adapter = AutoAuth::new(transport.clone());
    let provider = Arc::new(Provider {
        requested: Mutex::new(Vec::new()),
    });
    let session = adapter
        .open(
            Destination::parse("user@fixture").unwrap(),
            Credentials::Automatic(provider.clone()),
            MeshEvidence::default(),
        )
        .await
        .unwrap();
    assert!(
        session
            .run("mutating fixture must not run", Input::Empty)
            .await
            .is_err()
    );
    assert_eq!(*transport.opens.lock().unwrap(), 0);
    assert!(provider.requested.lock().unwrap().is_empty());
    assert!(
        session
            .run(infraternal_plugin_ssh::probe::CHECK_SCRIPT, Input::Empty)
            .await
            .is_err()
    );
    assert_eq!(*transport.opens.lock().unwrap(), 4);
    assert!(
        session
            .run(infraternal_plugin_ssh::probe::CHECK_SCRIPT, Input::Empty)
            .await
            .is_err()
    );
    assert_eq!(*transport.opens.lock().unwrap(), 4);
}

#[tokio::test]
async fn later_command_auth_errors_never_restart_the_selected_method_sequence() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Ready {
        opens: AtomicUsize,
        commands: AtomicUsize,
    }
    impl SshTransport for Ready {
        fn open(
            &self,
            _: Destination,
            _: Credentials,
            _: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            self.opens.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Ok(Arc::new(Ready {
                    opens: AtomicUsize::new(0),
                    commands: AtomicUsize::new(0),
                }) as Arc<dyn SshSession>)
            })
        }
    }
    impl SshSession for Ready {
        fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
            self.commands.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                if script == infraternal_plugin_ssh::probe::CHECK_SCRIPT {
                    Ok(CommandOutput { stdout: Vec::new() })
                } else {
                    Err(Failure::new(
                        FailureKind::Auth,
                        "Synthetic later command refusal.",
                    ))
                }
            })
        }
    }
    let transport = Arc::new(Ready {
        opens: AtomicUsize::new(0),
        commands: AtomicUsize::new(0),
    });
    let provider = Arc::new(Provider {
        requested: Mutex::new(Vec::new()),
    });
    let session = AutoAuth::new(transport.clone())
        .open(
            Destination::parse("user@fixture").unwrap(),
            Credentials::Automatic(provider.clone()),
            MeshEvidence::default(),
        )
        .await
        .unwrap();
    session
        .run(infraternal_plugin_ssh::probe::CHECK_SCRIPT, Input::Empty)
        .await
        .unwrap();
    assert!(session.run("later command", Input::Empty).await.is_err());
    assert_eq!(transport.opens.load(Ordering::Relaxed), 1);
    assert!(provider.requested.lock().unwrap().is_empty());
    assert_eq!(
        session.authentication().unwrap().method,
        AuthMethod::Network
    );
}

#[tokio::test]
async fn cancelling_authentication_consumes_the_attempt_without_requesting_secrets() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Waiting(AtomicUsize);
    impl SshTransport for Waiting {
        fn open(
            &self,
            _: Destination,
            _: Credentials,
            _: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::pending())
        }
    }
    let transport = Arc::new(Waiting(AtomicUsize::new(0)));
    let provider = Arc::new(Provider {
        requested: Mutex::new(Vec::new()),
    });
    let session = AutoAuth::new(transport.clone())
        .open(
            Destination::parse("user@fixture").unwrap(),
            Credentials::Automatic(provider.clone()),
            MeshEvidence::default(),
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(5),
            session.run(infraternal_plugin_ssh::probe::CHECK_SCRIPT, Input::Empty)
        )
        .await
        .is_err()
    );
    assert!(
        session
            .run(infraternal_plugin_ssh::probe::CHECK_SCRIPT, Input::Empty)
            .await
            .is_err()
    );
    assert_eq!(transport.0.load(Ordering::Relaxed), 1);
    assert!(provider.requested.lock().unwrap().is_empty());
    assert!(session.authentication().is_none());
}
