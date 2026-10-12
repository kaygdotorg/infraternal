/// Opt-in disposable-target timing of real SSH upload, enrollment, service and private terminal proof (#169).
use super::*;
use infraternal_plugin_ssh::auth_order::{AuthProvider, AutoAuth, NetworkProvider};
use infraternal_plugin_ssh::openssh::OpenSsh;
use std::{io::Read, path::PathBuf, time::Instant};

static FIRST_INSTALL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
static UPLOAD_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct TimedSession {
    inner: Arc<dyn SshSession>,
}
impl SshSession for TimedSession {
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let step = match &input {
                Input::File(_) => "upload",
                Input::Bytes(_) => "join",
                Input::Empty if script == infraternal_plugin_ssh::probe::CHECK_SCRIPT => "check",
                Input::Empty if script.contains("ln \"$cache/payload\" \"$stage/payload\"") => "reuse_payload",
                Input::Empty if script.contains("validate_cache") => "payload_lookup",
                Input::Empty if script.contains("validate_receipt") => "rollback",
                Input::Empty if script.contains("enable --now") => "start",
                Input::Empty if script.contains("enable-linger") => "linger",
                Input::Empty if script.contains("stage/activating") => "install",
                Input::Empty => "commit",
            };
            if step == "upload" {
                UPLOAD_STARTED.store(true, Ordering::SeqCst);
            }
            if step == "install"
                && std::env::var_os("BREAKIT2_RETRY").is_some()
                && FIRST_INSTALL.swap(false, Ordering::SeqCst)
            {
                println!("RETRY breakit2 inject=first_install_refusal uploaded_and_joined=true");
                return Err(Failure::install(
                    "The fixture refused its first install boundary.",
                ));
            }
            let file_bytes = if let Input::File(path) = &input {
                path.metadata().ok().map(|metadata| metadata.len())
            } else { None };
            let started = Instant::now();
            let result = self.inner.run(script, input).await;
            if let Some(bytes) = file_bytes {
                println!("METRIC breakit2 file_input_bytes={bytes} accepted={}", result.is_ok());
            }

            println!(
                "METRIC breakit2 step={step} elapsed_ms={:.3} ok={}",
                started.elapsed().as_secs_f64() * 1000.0,
                result.is_ok()
            );
            result
        })
    }
}
struct TimedTransport {
    adapter: OpenSsh,
}
impl SshTransport for TimedTransport {
    fn open(
        &self,
        destination: Destination,
        credentials: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            let step = if matches!(credentials, Credentials::Network) {
                "network_discovery"
            } else {
                "key_sign_in"
            };
            let started = Instant::now();
            let result = self.adapter.open(destination, credentials, mesh).await;
            println!(
                "METRIC breakit2 step={step} elapsed_ms={:.3} ok={}",
                started.elapsed().as_secs_f64() * 1000.0,
                result.is_ok()
            );
            Ok(Arc::new(TimedSession { inner: result? }) as Arc<dyn SshSession>)
        })
    }
}

struct FixtureProvider(Mutex<Option<Secret>>);
impl AuthProvider for FixtureProvider {
    fn network(&self) -> Option<NetworkProvider> {
        None
    }
    fn server_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { Ok(None) })
    }
    fn user_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async move {
            Ok(self
                .0
                .lock()
                .unwrap()
                .take()
                .map(|key| Credentials::PrivateKey {
                    key,
                    passphrase: None,
                }))
        })
    }
    fn password(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { Ok(None) })
    }
}
struct FixtureTransport {
    transport: Arc<dyn SshTransport>,
    private: Mutex<Option<Secret>>,
}
impl SshTransport for FixtureTransport {
    fn open(
        &self,
        destination: Destination,
        _: Credentials,
        mesh: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            // Feed only a generated one-use identity to the production automatic
            // order: real network-only refusal, then lazy key authentication.
            // Browser passkey unlocking is outside this native fixture.
            let key = self.private.lock().unwrap().take();
            AutoAuth::new(self.transport.clone())
                .open(
                    destination,
                    Credentials::Automatic(Arc::new(FixtureProvider(Mutex::new(key)))),
                    mesh,
                )
                .await
        })
    }
}

// Keep diagnosis in a test adapter: the production backend/functions remain
// unchanged, and this prints only fixed boundaries and typed local errors.
struct ObservedBackend(Arc<RemoteBackend>);
impl Backend for ObservedBackend {
    fn record_failure(&self, t: &Target, h: Option<Uuid>, p: Step, f: &Failure) {
        self.0.record_failure(t, h, p, f);
    }
    fn invitation_with_trust<'a>(
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: &'a Check,
        lookup: Option<String>,
    ) -> Operation<'a, JoinMaterial> {
        self.0.invitation_with_trust(a, t, c, lookup)
    }
    fn invitation_registered<'a>(
        &'a self, a: &'a Authority, t: &'a Target, c: &'a Check,
        lookup: Option<String>, register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        self.0.invitation_registered(a, t, c, lookup, register)
    }
    fn resolve<'a>(
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        self.0.resolve(a, t, c)
    }
    fn invitation<'a>(
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        self.0.invitation(a, t, c)
    }
    fn connected_facts<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        self.0.connected_facts(a, h)
    }
    fn terminal_canary<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            if std::env::var_os("BREAKIT2_DIAG").is_none() {
                return self.0.terminal_canary(a, h).await;
            }
            let actor = self.0.actor(a, h).await?;
            let result = actor
                .open_readiness(TerminalSize {
                    cols: 80,
                    rows: 24,
                    px_w: 0,
                    px_h: 0,
                })
                .await;
            println!(
                "DIAG breakit2 canary_open_ok={} error={:?}",
                result.is_ok(),
                result.as_ref().err()
            );
            let session = result.map_err(|_| unavailable())?;
            self.0.attempts.lock().unwrap().get_mut(&h).unwrap().canary =
                Some((actor.clone(), session));
            let output = tokio::time::timeout(
                Duration::from_secs(10),
                diagnostic_canary_output(&actor, session),
            )
            .await
            .unwrap_or_else(|_| Err(unavailable()));
            println!("DIAG breakit2 canary_output_ok={}", output.is_ok());
            let cleanup = finish_canary(&actor, session).await;
            println!("DIAG breakit2 canary_cleanup_ok={}", cleanup.is_ok());
            output.and(cleanup)
        })
    }
    fn cleanup_sessions<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        self.0.cleanup_sessions(a, h)
    }
    fn failed<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        self.0.failed(a, h)
    }
    fn completed<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        self.0.completed(a, h)
    }
}

// Mirror the fixed production canary only for opt-in boundary diagnostics.
// No remote text or capability is logged; normal measurements delegate unchanged.
async fn diagnostic_canary_output(actor: &EmbeddedAgent, session: [u8; 16]) -> Result<(), Failure> {
    use infraternal_protocol::{Frame, encode_muxed_frame_into};
    let (handle, mut output) = actor
        .attach(session, 0, 0, 2)
        .await
        .map_err(|_| unavailable())?
        .split();
    println!("DIAG breakit2 canary_attach_ok=true");
    let marker = "infraternal-ready";
    // The fixed non-login command waits for input so its output cannot precede
    // attachment. No user shell startup or echoed marker supplies readiness.
    let command = "\n";
    let mut wire = Vec::new();
    let delayed_credit = std::env::var_os("BREAKIT2_DELAY_CREDIT").is_some();
    let input = Frame::Input { in_seq: 0, bytes: command.as_bytes() };
    let credit = Frame::Credit { bytes: 65536 };
    let frames = if delayed_credit { [input, credit] } else { [credit, input] };
    for frame in frames {
        // A valid unfunded attachment makes owner EOF win while final PTY bytes
        // remain queued. Normal timing runs preserve the production input order.
        if delayed_credit && matches!(frame, Frame::Credit { .. }) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        // Input is leg A (odd); the attachment maps it onto its even leg-B stream.
        encode_muxed_frame_into(1, &frame, &mut wire).map_err(|_| unavailable())?;
        handle
            .send_frame(bytes::Bytes::copy_from_slice(&wire))
            .await
            .map_err(|_| unavailable())?;
    }
    let mut received = Vec::new();
    while let Some(event) = output.recv().await {
        match event {
            // A fast first command may be included in the initial faithful
            // repaint; snapshots carry confirmed PTY output just as deltas do.
            TerminalOutput::Output { bytes, .. } | TerminalOutput::Snapshot { bytes, .. } => {
                if received.len() + bytes.len() > 65536 {
                    return Err(unavailable());
                }
                println!("DIAG breakit2 confirmed_output_bytes={}", bytes.len());
                received.extend_from_slice(&bytes);
                if received
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
                {
                    return Ok(());
                }
            }
            TerminalOutput::Closed { code, .. } => {
                println!("DIAG breakit2 output_closed_code={code}");
                break;
            }
            _ => {}
        }
    }
    println!("DIAG breakit2 canary_stream_ended=true marker_found=false");
    Err(unavailable())
}

#[tokio::test]
#[ignore = "#169 live disposable Docker target; invoke docs/verification/addhost-breakit2/measure.py"]
#[allow(clippy::too_many_lines)]
async fn breakit2_live_ssh_install_join_and_terminal() {
    let scratch = PathBuf::from(std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").unwrap());
    let binary = PathBuf::from(std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").unwrap());
    let address = std::env::var("BREAKIT2_TARGET").unwrap();
    let mode = if std::env::var("BREAKIT2_MODE").unwrap_or_default() == "root" {
        InstallMode::Root
    } else {
        InstallMode::Rootless
    };
    let mut private = Vec::new();
    std::io::stdin()
        .take(24577)
        .read_to_end(&mut private)
        .unwrap();
    assert!(private.len() <= 24576);
    let mut f = fixture(true).await;
    let (identity, material) =
        crate::remote_runtime::tests::server_material_for_name("addhost-breakit2.test");
    let source: Arc<dyn CaKeySource> = Arc::new(Signer(Some(material.clone())));
    let hosts = RemoteHosts::from_source(Some(source.clone()));
    let store = f.backend.issuer.store().clone();
    let listeners = crate::remote_runtime::RemoteListeners::start(
        "10.69.69.125:4930".parse().unwrap(),
        &identity,
        &[material.issuer().clone()],
        store.clone(),
        hosts.clone(),
    )
    .await
    .unwrap();
    let endpoint = EnrollmentEndpoint {
        ca_der: material.issuer().to_der().unwrap(),
        endpoint: listeners.local_addr().unwrap(),
        server_name: "addhost-breakit2.test".into(),
    };
    let auth = Auth::new(
        f.pool.clone(),
        "addhost-breakit2.test",
        "https://addhost-breakit2.test:4929",
    )
    .await
    .unwrap();
    let service = EnrollmentService {
        source: source.clone(),
        endpoint: endpoint.clone(),
    };
    let http = crate::remote_http::router_with_store(
        auth.clone(),
        f.pool.clone(),
        store.clone(),
        source,
        endpoint,
    );
    let http_tls = axum_server::tls_openssl::OpenSSLConfig::from_der(
        &identity.certificate.to_der().unwrap(),
        &identity.key.private_key_to_der().unwrap(),
    )
    .unwrap();
    let server = tokio::spawn(
        axum_server::bind_openssl(
            "10.69.69.125:4929".parse::<std::net::SocketAddr>().unwrap(),
            http_tls,
        )
        .serve(http.into_make_service_with_connect_info::<std::net::SocketAddr>()),
    );
    f.backend = Arc::new(RemoteBackend {
        base: PendingRemoteRuntime {
            auth: Some(auth.clone()),
            key: Arc::new(crate::ssh_key::UnavailableSshKey),
        },
        issuer: InvitationIssuer::new(auth, f.pool.clone(), store, service),
        hosts,
        attempts: Mutex::default(),
    });
    let retry_private = std::env::var_os("BREAKIT2_RETRY").map(|_| private.clone());
    let transport = Arc::new(FixtureTransport {
        transport: Arc::new(TimedTransport {
            adapter: OpenSsh {
                ssh: scratch.join("ssh"),
                ssh_agent: "/usr/bin/ssh-agent".into(),
                ssh_add: "/usr/bin/ssh-add".into(),
                ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
                ssh_keygen: "/usr/bin/ssh-keygen".into(),
                askpass_binary: binary.clone(),
                scratch: scratch.clone(),
                command_timeout: Duration::from_secs(30),
            },
        }),
        private: Mutex::new(Some(Secret::new(private))),
    });
    let runner = Bootstrap::new(
        transport.clone(),
        Arc::new(ObservedBackend(f.backend.clone())),
        BinaryPaths {
            x86_64: binary.clone(),
            aarch64: binary,
        },
    );
    let batch = runner
        .start_authenticated(
            "owner".into(),
            Secret::new(f.cookie.as_bytes().to_vec()),
            vec![Target {
                id: "live".into(),
                address: TargetAddress::Manual(address),
                credential: None,
                mode,
                root_consent: mode == InstallMode::Root,
            }],
            None,
        )
        .unwrap();
    if std::env::var_os("BREAKIT2_CANCEL_UPLOAD").is_some() {
        tokio::time::timeout(Duration::from_secs(60), async {
            while !UPLOAD_STARTED.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        println!("CANCEL breakit2 boundary=upload action=drop_batch");
        drop(batch);
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                if f.backend.attempts.lock().unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM remote_hosts WHERE revoked_at IS NULL")
                .fetch_one(&f.pool)
                .await
                .unwrap();
        println!("CANCEL breakit2 active_hosts={active} prior_hosts=1 attempts=0");
        server.abort();
        drop(listeners);
        assert_eq!(active, 1, "cancel must retire enrollment authority");
        return;
    }
    let mut changed = batch.subscribe();
    let mut retry_private = retry_private;
    let mut selected_attempt = 1;
    let result = tokio::time::timeout(Duration::from_secs(220), async {
        loop {
            let events = batch.events(0).1;
            if let Some(event) = events.iter().find(|event| {
                event.attempt == selected_attempt && matches!(event.step, Step::Done | Step::Failed)
            }) {
                if event.step == Step::Failed
                    && selected_attempt == 1
                    && let Some(private) = retry_private.take()
                {
                    *transport.private.lock().unwrap() = Some(Secret::new(private));
                    println!(
                        "RETRY breakit2 first_failure_step={:?}",
                        event.failure.as_ref().and_then(|f| f.failed_step)
                    );
                    runner.retry(&batch, "owner", "live").unwrap();
                    selected_attempt = 2;
                    continue;
                }
                for phase in &events {
                    println!(
                        "METRIC breakit2 event={:?} cumulative_ms={} message={}",
                        phase.step, phase.elapsed_ms, phase.message
                    );
                }
                if let Some(failure) = &event.failure {
                    println!(
                        "METRIC breakit2 failed_step={:?} status={:?}",
                        failure.failed_step, failure.exit_status
                    );
                }
                return event.step;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let active: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_hosts WHERE revoked_at IS NULL")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let usable: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_join_tokens t JOIN remote_hosts h ON h.id=t.host_id WHERE t.consumed_at IS NULL AND h.revoked_at IS NULL").fetch_one(&f.pool).await.unwrap();
    println!(
        "LEDGER breakit2 active_hosts={active} prior_hosts=1 unconsumed_live_tokens={usable} attempts={}",
        f.backend.attempts.lock().unwrap().len()
    );
    server.abort();
    drop(listeners);
    if std::env::var_os("BREAKIT2_EXPECT_FAILURE").is_some() {
        assert_eq!(result, Step::Failed, "target restriction must be refused");
        assert_eq!(active, 1, "failed attempt must retire its host authority");
        assert_eq!(usable, 0, "failed attempt must retire its invitation");
    } else {
        assert_eq!(result, Step::Done, "real SSH bootstrap did not complete");
    }
}
