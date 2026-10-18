/// Opt-in disposable-target timing of real SSH upload, enrollment, service and private terminal proof (#169).
use super::*;
use infraternal_plugin_ssh::auth_order::{AuthProvider, AutoAuth, NetworkProvider};
use infraternal_plugin_ssh::openssh::OpenSsh;
use infraternal_plugin_ssh::transport::TransferChoice;
use std::{io::Read, path::PathBuf, time::Instant};

#[path = "bootstrap_instant_tests.rs"]
mod instant;
#[path = "bootstrap_browser_tests.rs"]
mod browser;
static FULLY_JOINED: Mutex<Option<Instant>> = Mutex::new(None);

/// Own only this live controller's private fixture files until its bindings drop.
struct LiveFixtureDirectory(PathBuf);
impl Drop for LiveFixtureDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn live_fixture(scratch: &std::path::Path) -> (LiveFixtureDirectory, Fixture) {
    let directory = LiveFixtureDirectory(scratch.join(format!("live-authority-{}", Uuid::new_v4())));
    // Use the runtime's private persistent pool, including its connection and
    // journal settings. A cancelled acquisition must not reset authority.
    let pool = crate::runtime::test_open_database(&directory.0).await.unwrap();
    let (store, pool, prior) = crate::enrollment::authority::tests::enrolled_with_pool(pool).await;
    (directory, fixture_with_store(true, store, pool, prior).await)
}

#[tokio::test]
async fn live_fixture_keeps_authority_after_connection_retirement() {
    let scratch = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
        || PathBuf::from(std::env::var_os("HOME").unwrap()).join(".cache/codex-scratch/addhost-instant"),
        PathBuf::from,
    );
    // Retain the file owner until after the fixture and its pool handles drop.
    let (_directory, fixture) = live_fixture(&scratch).await;
    let connection = fixture.pool.acquire().await.unwrap();
    connection.close().await.unwrap();
    let owners: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id='owner'")
        .fetch_one(&fixture.pool).await.unwrap();
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash=?")
        .bind(crate::auth::hash(&fixture.cookie)).fetch_one(&fixture.pool).await.unwrap();
    assert_eq!(owners, 1);
    assert_eq!(sessions, 1);
}

// Fixture images are explicit trusted inputs, independent of release HTTP/signing tests.
struct FixturePayloads {
    binaries: BinaryPaths,
    session: Option<PathBuf>,
}
impl infraternal_plugin_ssh::install::PayloadSource for FixturePayloads {
    fn get(&self, architecture: infraternal_plugin_ssh::probe::Architecture) -> Operation<'_, PathBuf> {
        infraternal_plugin_ssh::install::PayloadSource::get(&self.binaries, architecture)
    }
    fn session(&self, _architecture: infraternal_plugin_ssh::probe::Architecture) -> Operation<'_, Option<PathBuf>> {
        Box::pin(async { Ok(self.session.clone()) })
    }
}
fn fixture_payload_source(
    binaries: BinaryPaths,
    session: Option<PathBuf>,
) -> Arc<dyn infraternal_plugin_ssh::install::PayloadSource> {
    Arc::new(FixturePayloads { binaries, session })
}

#[tokio::test]
async fn live_fixture_keeps_the_full_image_and_selects_the_explicit_session_image() {
    let full = PathBuf::from("full-fixture");
    let session = PathBuf::from("session-fixture");
    let binaries = BinaryPaths { x86_64: full.clone(), aarch64: full.clone() };
    let legacy = fixture_payload_source(binaries.clone(), None);
    assert_eq!(legacy.get(infraternal_plugin_ssh::probe::Architecture::X86_64).await.unwrap(), full);
    assert!(legacy.session(infraternal_plugin_ssh::probe::Architecture::X86_64).await.unwrap().is_none());
    let instant = fixture_payload_source(binaries, Some(session.clone()));
    assert_eq!(instant.get(infraternal_plugin_ssh::probe::Architecture::X86_64).await.unwrap(), full);
    assert_eq!(instant.session(infraternal_plugin_ssh::probe::Architecture::X86_64).await.unwrap(), Some(session));
}

/// The provisioning listener's socket admission is exercised directly below.
fn enrollment_acceptor(
    config: axum_server::tls_openssl::OpenSSLConfig,
) -> axum_server::tls_openssl::OpenSSLAcceptor<axum_server::accept::NoDelayAcceptor> {
    crate::server_tls::acceptor(config)
}

#[tokio::test]
async fn provisioning_https_uses_production_tcp_admission() {
    crate::server_tls::tests::assert_nodelay_with(enrollment_acceptor).await;
}

static FIRST_INSTALL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
static UPLOAD_STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn timeline(step: &'static str, state: &'static str) {
    if std::env::var_os("ADDHOST_BROWSER_TIMELINE").is_some() {
        let epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        println!("TIMELINE source=server step={step} state={state} epoch_ms={:.3}", epoch.as_secs_f64() * 1000.0);
    }
}

/// Time only the delegated production operation; emit no arguments or payload.
async fn measured<T>(step: &'static str, operation: Operation<'_, T>) -> Result<T, Failure> {
    let started = Instant::now();
    timeline(step, "start");
    let result = operation.await;
    timeline(step, "end");
    println!(
        "METRIC breakit2 step={step} elapsed_ms={:.3} ok={}",
        started.elapsed().as_secs_f64() * 1000.0,
        result.is_ok()
    );
    result
}

struct TimedSession {
    inner: Arc<dyn SshSession>,
}
impl SshSession for TimedSession {
    fn session_bridge(&self) -> bool { std::env::var_os("ADDHOST_INSTANT").is_some() && self.inner.session_bridge() }
    fn stream<'a>(&'a self, script: &'a str) -> Operation<'a, infraternal_plugin_ssh::duplex::Duplex> {
        if script.contains("setup_step upload") { UPLOAD_STARTED.store(true, Ordering::SeqCst); }
        Box::pin(measured("launch_channel_helper", self.inner.stream(script)))
    }

    fn check_stream<'a>(&'a self, script: &'a str) -> Operation<'a, (CommandOutput, Option<infraternal_plugin_ssh::install::Checked>)> {
        Box::pin(measured("check_and_retain_channel", self.inner.check_stream(script)))
    }
    fn setup_steps(&self) -> bool { self.inner.setup_steps() }
    fn authentication(&self) -> Option<infraternal_plugin_ssh::auth_order::Authentication> {
        self.inner.authentication()
    }
    fn trust_lookup(&self) -> Option<String> { self.inner.trust_lookup() }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            let step = match &input {
                Input::Negotiated { .. } | Input::PayloadAndInvitation { .. } => "upload_setup",
                Input::Bytes(_) if script.contains("zstd -dc >") || script.contains("gzip -dc >") => "upload",
                Input::File(_) => "upload",
                Input::Bytes(_) if script.starts_with("# INFRATERNAL_TRANSFER_SETUP_V1") => "reuse_setup",
                Input::Bytes(_) if script.starts_with("# INFRATERNAL_SETUP_STEPS_V1") => "setup",
                Input::Bytes(_) => "join",
                Input::Empty if script.starts_with(infraternal_plugin_ssh::probe::CHECK_SCRIPT) => {
                    "check"
                }
                Input::Empty if script.contains("ln \"$cache/payload\" \"$stage/payload\"") => {
                    "reuse_payload"
                }
                Input::Empty if script.contains("validate_cache") => "payload_lookup",
                Input::Empty if script.contains("validate_receipt") => "rollback",
                Input::Empty if script.contains("enable --now") => "start",
                Input::Empty if script.contains("enable-linger") => "linger",
                Input::Empty if script.contains("stage/activating") => "install",
                Input::Signal(_) | Input::Empty => "commit",
            };
            if matches!(step, "upload" | "upload_setup") {
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
            let negotiated_sizes = if let Input::Negotiated { raw, gzip, zstd, .. } = &input {
                Some((match raw { infraternal_plugin_ssh::transport::PayloadInput::Bytes(bytes) => bytes.len() as u64, infraternal_plugin_ssh::transport::PayloadInput::File { size, .. } => *size }, gzip.map_or(0, |bytes| bytes.len() as u64), zstd.map_or(0, |bytes| bytes.len() as u64)))
            } else { None };
            let mut file_bytes = if let Input::PayloadAndInvitation { payload, .. } = &input {
                Some(match payload {
                    infraternal_plugin_ssh::transport::PayloadInput::Bytes(bytes) => bytes.len() as u64,
                    infraternal_plugin_ssh::transport::PayloadInput::File { size, .. } => *size,
                })
            } else if let Input::File(path) = &input {
                path.metadata().ok().map(|metadata| metadata.len())
            } else if let Input::Bytes(bytes) = &input {
                (step == "upload").then(|| u64::try_from(bytes.len()).unwrap())
            } else {
                None
            };
            // Refuse activation only after the real staged enrollment has run.
            // A compound command's outer transport receipt remains successful;
            // its fixed FAIL receipt is classified by the production decoder.
            let refused = (matches!(step, "setup" | "upload_setup" | "reuse_setup")
                && std::env::var_os("BREAKIT2_RETRY").is_some()
                && FIRST_INSTALL.swap(false, Ordering::SeqCst))
                .then(|| script.replacen("if sh -c \"$2\"; then", "if [ \"$1\" != install ] && sh -c \"$2\"; then", 1));
            let started = Instant::now();
            let result = self.inner.run(refused.as_deref().unwrap_or(script), input).await;
            if let (Some((raw, gzip, zstd)), Ok(output)) = (negotiated_sizes, &result) {
                let choice = output.stdout.split_inclusive(|byte| *byte == b'\n').find_map(TransferChoice::parse);
                file_bytes = match choice { Some(TransferChoice::Raw) => Some(raw), Some(TransferChoice::Gzip) => Some(gzip), Some(TransferChoice::Zstd) => Some(zstd), _ => None };
            }
            if let Some(bytes) = file_bytes {
                println!(
                    "METRIC breakit2 file_input_bytes={bytes} accepted={}",
                    result.is_ok()
                );
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
pub(super) struct TimedTransport {
    pub(super) adapter: OpenSsh,
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
            timeline(step, "start");
            let result = self.adapter.open(destination, credentials, mesh).await;
            timeline(step, "end");
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
pub(super) struct FixtureTransport {
    pub(super) transport: Arc<dyn SshTransport>,
    pub(super) private: Mutex<Option<Secret>>,
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
pub(super) type CanaryHook = Arc<dyn Fn() -> Result<(), Failure> + Send + Sync>;
pub(super) type CanaryReturnHook = Arc<
    dyn Fn(Uuid, Option<Failure>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;
pub(super) struct ObservedBackend(
    pub(super) Arc<RemoteBackend>,
    pub(super) Option<CanaryHook>,
    pub(super) Option<CanaryReturnHook>,
);
impl Backend for ObservedBackend {
    fn early_terminal(&self) -> bool { std::env::var_os("ADDHOST_INSTANT").is_some() && self.0.early_terminal() }
    fn publish_terminal<'a>(&'a self, a: &'a Authority, h: Uuid, id: Uuid, channel: infraternal_plugin_ssh::duplex::Duplex, session: Arc<dyn SshSession>) -> Operation<'a, ()> {
        Box::pin(measured("publish_terminal", self.0.publish_terminal(a, h, id, channel, session)))
    }
    fn authority_cancelled<'a>(&'a self, a: &'a Authority) -> Operation<'a, ()> { self.0.authority_cancelled(a) }
    fn setup_cancelled(&self, h: Uuid) -> Operation<'_, ()> { self.0.setup_cancelled(h) }
    fn reissue_invitation<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, JoinMaterial> { self.0.reissue_invitation(a,h) }
    fn stop(&self) -> Operation<'_, ()> { self.0.stop() }
    fn owns_failed_setup<'a>(
        &'a self, a: &'a Authority, t: &'a Target, c: &'a Check,
        host: Uuid, lookup: Option<String>,
    ) -> Operation<'a, bool> {
        self.0.owns_failed_setup(a, t, c, host, lookup)
    }

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
        &'a self,
        a: &'a Authority,
        t: &'a Target,
        c: &'a Check,
        lookup: Option<String>,
        register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(measured(
            "invitation",
            self.0.invitation_registered(a, t, c, lookup, register),
        ))
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
        Box::pin(measured("facts", self.0.connected_facts(a, h)))
    }
    fn terminal_canary<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            if let Some(before_canary) = &self.1 {
                before_canary()?;
            }
            if self.1.is_some() || self.2.is_some() || std::env::var_os("BREAKIT2_DIAG").is_none() {
                // Optional observations run only after the unmodified production
                // canary returns, before Bootstrap can roll back its authority.
                let result = measured("readiness", self.0.terminal_canary(a, h)).await;
                if let Some(after_canary) = &self.2 {
                    after_canary(h, result.as_ref().err().cloned()).await;
                }
                return result;
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
                Some((actor.clone(), session, [2, 4]));
            let output = tokio::time::timeout(
                Duration::from_secs(10),
                diagnostic_canary_output(&actor, session),
            )
            .await
            .unwrap_or_else(|_| Err(unavailable()));
            println!("DIAG breakit2 canary_output_ok={}", output.is_ok());
            if output.is_ok() {
                self.0.attempts.lock().unwrap().get_mut(&h).unwrap().canary = None;
                println!("DIAG breakit2 canary_cleanup_ok=true primary_exit=true");
            } else {
                let cleanup = finish_canary(&actor, session, 4).await;
                println!("DIAG breakit2 canary_cleanup_ok={}", cleanup.is_ok());
            }
            output
        })
    }
    fn cleanup_sessions<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        self.0.cleanup_sessions(a, h)
    }
    fn retire_failed(&self, a: &Authority, h: Uuid) -> Result<(), Failure> {
        self.0.retire_failed(a, h)
    }
    fn failed<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        Box::pin(measured("authority_retirement", self.0.failed(a, h)))
    }
    fn completed<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            measured("authority_commit", self.0.completed(a, h)).await?;
            *FULLY_JOINED.lock().unwrap() = Some(Instant::now());
            Ok(())
        })
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
    let input = Frame::Input {
        in_seq: 0,
        bytes: command.as_bytes(),
    };
    let credit = Frame::Credit { bytes: 65536 };
    let frames = if delayed_credit {
        [input, credit]
    } else {
        [credit, input]
    };
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
    let mut confirmed = false;
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
                confirmed = received
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes());
            }
            TerminalOutput::Event { event_json } => {
                let notice: serde_json::Value =
                    serde_json::from_slice(&event_json).map_err(|_| unavailable())?;
                if notice["type"] == "terminal.exited" {
                    let exited = notice["session_id"]
                        .as_str()
                        .and_then(|id| Uuid::parse_str(id).ok())
                        .is_some_and(|id| id.as_bytes() == &session);
                    println!(
                        "DIAG breakit2 primary_exit_matches={exited} marker_found={confirmed}"
                    );
                    return if confirmed && exited && notice["status"] == 0 {
                        Ok(())
                    } else {
                        Err(unavailable())
                    };
                }
            }
            TerminalOutput::Closed { code, .. } => {
                println!("DIAG breakit2 output_closed_code={code}");
                break;
            }
            TerminalOutput::Ack { .. } | TerminalOutput::Reconnecting | TerminalOutput::LinkDoubt | TerminalOutput::Recovered | TerminalOutput::RouteExpired => {}
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
    let controller_ip = std::env::var("BREAKIT2_CONTROLLER_IP")
        .unwrap_or_else(|_| "10.69.69.125".into())
        .parse::<std::net::IpAddr>()
        .unwrap();
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
    let (_directory, mut f) = live_fixture(&scratch).await;
    let server_name = std::env::var("BREAKIT2_SERVER_NAME")
        .unwrap_or_else(|_| "addhost-breakit2.test".into());
    let (identity, material) =
        crate::remote_runtime::tests::server_material_for_name(&server_name);
    let source: Arc<dyn CaKeySource> = Arc::new(Signer(Some(material.clone())));
    let hosts = RemoteHosts::from_source(Some(source.clone()));
    let store = f.backend.issuer.store().clone();
    let listeners = crate::remote_runtime::RemoteListeners::start(
        std::net::SocketAddr::new(controller_ip, 4930),
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
        server_name: server_name.clone(),
    };
    let auth = Auth::new(
        f.pool.clone(),
        &server_name,
        &format!("https://{server_name}:4929"),
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
    f.backend = Arc::new(RemoteBackend {
        base: PendingRemoteRuntime {
            auth: Some(auth.clone()),
            key: Arc::new(crate::ssh_key::UnavailableSshKey),
        },
        issuer: InvitationIssuer::new(auth.clone(), f.pool.clone(), store, service),
        hosts,
        attempts: Mutex::default(),
        sessions_changed: Mutex::default(),
    });
    let timeout_retry = std::env::var_os("BREAKIT2_TIMEOUT_RETRY").is_some();
    let retry_private = (timeout_retry || std::env::var_os("BREAKIT2_RETRY").is_some())
        .then(|| private.clone());
    // Adding the same host a second time must name the existing host (#189).
    let readd_private = std::env::var_os("BREAKIT2_READD").is_some().then(|| private.clone());
    let transport = Arc::new(FixtureTransport {
        transport: Arc::new(TimedTransport {
            adapter: OpenSsh {
                ssh: scratch.join("ssh"),
                ssh_agent: "/usr/bin/ssh-agent".into(),
                ssh_add: "/usr/bin/ssh-add".into(),
                ssh_keyscan: "/usr/bin/ssh-keyscan".into(),
                ssh_keygen: "/usr/bin/ssh-keygen".into(),
                askpass_binary: binary.clone(),
                tcp_connector: Some(binary.clone()),
                scratch: scratch.clone(),
                command_timeout: Duration::from_secs(30),
            },
        }),
        private: Mutex::new(Some(Secret::new(private))),
    });
    let binaries = BinaryPaths { x86_64: binary.clone(), aarch64: binary.clone() };
    let session_image = std::env::var_os("INFRATERNAL_REMOTE_TEST_SESSION_BINARY").map(PathBuf::from);
    let runner = Bootstrap::new(
        transport.clone(),
        Arc::new(ObservedBackend(f.backend.clone(), None, None)),
        BinaryPaths {
            x86_64: binary.clone(),
            aarch64: binary,
        },
    ).with_payload_source(fixture_payload_source(binaries, session_image));
    let prepared = Instant::now();
    runner.prepare_payloads().await;
    println!("METRIC payload_prepare startup_ms={:.3}", prepared.elapsed().as_secs_f64() * 1000.0);
    if std::env::var_os("ADDHOST_BROWSER_TIMELINE").is_some() {
        browser::run(&f, auth, runner, http, http_tls, controller_ip, &address).await;
        drop(listeners);
        return;
    }
    let server = tokio::spawn(
        axum_server::bind(std::net::SocketAddr::new(controller_ip, 4929))
        .acceptor(enrollment_acceptor(http_tls))
        .serve(http.into_make_service_with_connect_info::<std::net::SocketAddr>()),
    );
    let started = Instant::now();
    *FULLY_JOINED.lock().unwrap() = None;
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
    let mut published_retry = false;
    let mut joined_host = None;
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
                    if timeout_retry {
                        assert_eq!(event.step, Step::Failed);
                        assert!(events.iter().any(|phase| phase.step == Step::Facts));
                        assert!(std::process::Command::new("nft")
                            .args(["delete", "table", "inet", "addhost_retry_230"])
                            .status().unwrap().success());
                        println!("RETRY timeout=facts network_restored=true");
                    }
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
                if event.step == Step::Done {
                    joined_host = event.host_id;
                }
                if event.step == Step::Done && std::env::var_os("ADDHOST_INSTANT").is_some() {
                    assert!(event.session_id.is_some(), "instant acceptance requires a published shim, never a legacy completion");
                }
                if event.step == Step::Done && let (Some(host), Some(session)) = (event.host_id, event.session_id) {
                    // Persist the native fixture's writer exactly as a browser
                    // would, so private readiness shares its real allocator.
                    let connection = Uuid::new_v4();
                    sqlx::query("INSERT INTO websocket_connections(connection_id,token_hash,user_id,created_at,active) VALUES(?,?,'owner',unixepoch(),1)")
                        .bind(connection.as_bytes().as_slice()).bind([0_u8;32].as_slice()).execute(&f.pool).await.unwrap();
                    sqlx::query("INSERT INTO terminal_writers(connection_id,client_stream,session_id) VALUES(?,1,?)")
                        .bind(connection.as_bytes().as_slice()).bind(session.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
                    let actor = f.backend.hosts.actor(host).await.unwrap();
                    let terminal = instant::EarlyTerminal::attach(&actor, session, started).await;
                    // Once the published shim is interactive, closing the wizard
                    // must leave the same bounded background setup alive.
                    drop(batch);
                    let status = runner.setup_status();
                    let mut setup_changed = status.subscribe("owner", host).unwrap();
                    // A published setup that fails after the network kill retries
                    // through the same owner path the browser uses (#230).
                    let mut retried_attempt = None;
                    loop {
                        let events = status.events("owner", host, 0).unwrap().1;
                        let current = |event: &&infraternal_plugin_ssh::setup::Event| retried_attempt.is_none_or(|attempt| event.attempt > attempt);
                        if let Some(failure) = events.iter().filter(current).find(|event| event.state == infraternal_plugin_ssh::setup::State::Failed) {
                            if timeout_retry && retried_attempt.is_none() {
                                assert!(std::process::Command::new("nft")
                                    .args(["delete", "table", "inet", "addhost_retry_230"])
                                    .status().unwrap().success());
                                println!("RETRY timeout=published_setup stage={:?} failed_step={:?} network_restored=true", failure.stage, failure.failed_step);
                                retried_attempt = Some(failure.attempt);
                                published_retry = true;
                                // A retry re-authenticates when its saved route is gone;
                                // hand the fixture key over again, as the batch retry does.
                                if let Some(private) = retry_private.take() {
                                    *transport.private.lock().unwrap() = Some(Secret::new(private));
                                }
                                runner.retry_setup("owner".into(), Secret::new(f.cookie.as_bytes().to_vec()), host).unwrap();
                                continue;
                            }
                            panic!("published setup failed at {:?}: step={:?} message={:?}", failure.stage, failure.failed_step, failure.message);
                        }
                        if events.iter().filter(current).any(|event| event.stage == infraternal_plugin_ssh::setup::Stage::Ready && event.state == infraternal_plugin_ssh::setup::State::Done) { break; }
                        setup_changed.changed().await.unwrap();
                    }
                    let joined = FULLY_JOINED.lock().unwrap().unwrap();
                    println!("METRIC addhost_instant fully_joined_ms={:.3}", joined.duration_since(started).as_secs_f64() * 1000.0);
                    assert!(f.backend.hosts.installed(host).await);
                    terminal.after_handover().await;
                    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM terminal_sessions WHERE remote_host_id=?")
                        .bind(host.as_bytes().as_slice()).fetch_one(&f.pool).await.unwrap();
                    assert_eq!(sessions, 1, "handover cannot create another public shell");
                }
                return event.step;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    if timeout_retry {
        assert!(
            selected_attempt == 2 || published_retry,
            "a network timeout must precede the retry"
        );
    }
    if let Some(private) = readd_private
        && result == Step::Done
    {
        let host = joined_host.expect("a finished add names its host");
        already_added_opens_a_terminal(&f, &runner, &transport, private, host).await;
    }
    if std::env::var_os("BREAKIT2_REMOVE").is_some() {
        // #235: removal asks the joined host to uninstall itself through the
        // same server path as the canvas, then revokes it. The harness then
        // proves on the machine that nothing is left and that it re-adds.
        let host = joined_host.expect("removal needs a joined host");
        // Let the harness place the kernel objects a running rootful mesh node
        // owns before removal starts, so their removal is observed, not assumed.
        std::fs::write(scratch.join("removal-ready"), b"").unwrap();
        tokio::time::timeout(Duration::from_secs(60), async {
            while !scratch.join("removal-go").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the harness did not release removal");
        let (cleanup, left) =
            crate::remote_removal::request_uninstall(&f.backend.hosts, host).await;
        println!("REMOVAL breakit2 host_cleanup={cleanup} left={left:?}");
        assert_eq!(cleanup, "requested", "the joined host did not accept its uninstall");
        // The harness seeds marked mesh objects this installation never
        // recorded on a rootful host; the host must name them as left (#235).
        if std::env::var("BREAKIT2_MODE").as_deref() == Ok("root") {
            assert_eq!(left, ["infraternal0", "infraternal_mesh"]);
        }
        f.backend
            .issuer
            .store()
            .revoke("owner", host, crate::runtime::unix_seconds().unwrap())
            .await
            .unwrap();
    }
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

/// Adds the just-added host again, then opens a terminal on the host id the
/// refusal names, the way the wizard's "Open a terminal" does (#189).
async fn already_added_opens_a_terminal(
    f: &Fixture,
    runner: &Bootstrap,
    transport: &FixtureTransport,
    private: Vec<u8>,
    host: Uuid,
) {
    *transport.private.lock().unwrap() = Some(Secret::new(private));
    let address = std::env::var("BREAKIT2_TARGET").unwrap();
    let mode = if std::env::var("BREAKIT2_MODE").unwrap_or_default() == "root" {
        InstallMode::Root
    } else {
        InstallMode::Rootless
    };
    let started = Instant::now();
    let batch = runner
        .start_authenticated(
            "owner".into(),
            Secret::new(f.cookie.as_bytes().to_vec()),
            vec![Target {
                id: "again".into(),
                address: TargetAddress::Manual(address),
                credential: None,
                mode,
                root_consent: mode == InstallMode::Root,
            }],
            None,
        )
        .unwrap();
    let mut changed = batch.subscribe();
    let failure = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(event) = batch
                .events(0)
                .1
                .into_iter()
                .find(|event| matches!(event.step, Step::Done | Step::Failed))
            {
                return event;
            }
            changed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(failure.step, Step::Failed, "a second add of the same host must be refused");
    let failure = failure.failure.expect("the refusal carries its failure");
    let wire = serde_json::to_value(&failure).unwrap();
    println!(
        "PROOF already_added={} host_id_matches={} refused_ms={}",
        failure.already_added,
        wire["host_id"] == host.to_string(),
        started.elapsed().as_millis()
    );
    assert!(failure.already_added);
    assert_eq!(wire["host_id"], host.to_string());
    let actor = f.backend.hosts.actor(host).await.unwrap();
    let session = actor
        .open(TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        })
        .await
        .unwrap();
    instant::EarlyTerminal::open_on_named_host(&actor, Uuid::from_bytes(session)).await;
}

/// Observe only whether the test fixture reaches the intended fixed failure step.
struct RetryObservation(std::sync::atomic::AtomicBool);
impl SshSession for RetryObservation {
    fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            self.0.store(script.contains("if [ \"$1\" != install ] && sh -c"), Ordering::SeqCst);
            Ok(CommandOutput { stdout: b"STEP join\nSTEP install\nFAIL install 1\n".to_vec() })
        })
    }
}

#[tokio::test]
async fn compound_retry_fixture_reaches_install_boundary() {
    // Environment changes belong to a fresh child, never to concurrent tests.
    if std::env::var_os("ADDHOST_FAST_RETRY_CHILD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["bootstrap_runtime::remote_backend::tests::breakit2_live::compound_retry_fixture_reaches_install_boundary", "--exact"])
            .env("ADDHOST_FAST_RETRY_CHILD", "1")
            .env("BREAKIT2_RETRY", "1")
            .output().unwrap();
        assert!(output.status.success() && String::from_utf8_lossy(&output.stdout).contains("running 1 test"), "compound retry fixture did not inject at install");
        return;
    }
    let observation = Arc::new(RetryObservation(std::sync::atomic::AtomicBool::new(false)));
    let session = TimedSession { inner: observation.clone() };
    session.run("# INFRATERNAL_SETUP_STEPS_V1\nif sh -c \"$2\"; then :; fi\n", Input::Bytes(b"public-fixture")).await.unwrap();
    assert!(observation.0.load(Ordering::SeqCst));
}
