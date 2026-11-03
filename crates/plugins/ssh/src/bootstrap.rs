//! Runs independent host attempts under one global concurrency bound and a bounded replayable event log [138 H4].

use crate::{
    auth_once::{OneUseAuth, TargetAuth},
    auth_order::Authentication,
    install::{BinaryPaths, Cleanup, Installation, JoinMaterial, PayloadSource},
    lifecycle::Lifecycle,
    model::{Destination, Event, Failure, InstallStep, MeshEvidence, Step, Target, identifier},
    previous_attempt::{self, PreviousAttempt},
    probe::Check,
    transport::{
        ConfirmationAuthority, Credentials, Input, Operation, Secret, SshSession, SshTransport,
    },
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, oneshot, watch};

/// Discovery and vault authority are resolved independently of untrusted request fields.
pub struct Resolved {
    pub destination: Destination,
    pub credentials: Credentials,
    pub mesh: MeshEvidence,
}

/// Public host identity prepared by the installed infraternal agent over authenticated SSH.
pub struct PreparedHostKey {
    pub host: uuid::Uuid,
    pub digest: [u8; 32],
}

/// Trusted request authority stays in memory and is never Debug or serialized.
/// Browser enrollment must recheck this exact session atomically, not owner id alone.
pub struct Authority {
    pub owner: String,
    /// Nonsecret batch identity lets backends retire only their own attempt authority.
    pub batch: uuid::Uuid,
    session: Option<Secret>,
    /// API-key actions retain only the key hash and recheck its narrow scope at use time.
    api_key_hash: Option<String>,
}
impl Authority {
    /// The opaque live cookie is available only to trusted backend implementations.
    #[must_use]
    pub fn session(&self) -> Option<&Secret> {
        self.session.as_ref()
    }

    /// The one-way API-key id used to recheck `hosts:write` for an action stream.
    #[must_use]
    pub fn api_key_hash(&self) -> Option<&str> {
        self.api_key_hash.as_deref()
    }
}

/// Accept only canonical unpadded base64url SHA-256 lookup ids from the server auth store.
fn valid_api_key_hash(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 43
        && bytes[..42]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        // A 32-byte digest leaves two zero pad bits in the final base64 sextet.
        && matches!(
            bytes[42],
            b'A' | b'E' | b'I' | b'M' | b'Q' | b'U' | b'Y' | b'c' | b'g' | b'k' | b'o' | b's'
                | b'w' | b'0' | b'4' | b'8'
        )
}

/// #78 owns enrollment, CA state, authenticated online status, facts and terminal routing.
/// Implementations must recheck this exact live session before new work and never treat token redemption as online proof.
/// Invitation issuance must serialize by host and associate authority with this batch.
/// `failed` retires only this batch's new invitation/certificate, even after logout;
/// it must preserve prior enrolled authority and never invalidate another batch.
pub trait Backend: Send + Sync {
    /// Bound readiness using an authenticated command exchange on this connection.
    /// Command execution is included, so the observation conservatively exceeds link RTT.
    fn observe_link(&self, _: &Authority, _: uuid::Uuid, _: Duration) {}
    /// Extend the SSH commit command through this attempt's route and final proof.
    /// Older adapters keep their transport's configured command deadline.
    fn setup_commit_timeout(&self, _: &Authority, _: uuid::Uuid) -> Option<Duration> {
        None
    }
    /// Reuse the server's existing session inventory notification source.
    fn session_notifications(&self, _: tokio::sync::watch::Sender<u64>) {}
    /// Retained subscriptions follow host revocation across transport replacement.
    fn setup_cancelled(&self, _: uuid::Uuid) -> Operation<'_, ()> {
        Box::pin(std::future::pending())
    }
    /// Renew enrollment for the exact published host, using fresh requester authority.
    fn reissue_invitation<'a>(
        &'a self,
        _: &'a Authority,
        _: uuid::Uuid,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async { Err(Failure::unsupported("Host setup retry is unavailable.")) })
    }
    /// Detached setup observes revocation independently of the wizard socket.
    fn authority_cancelled<'a>(&'a self, _: &'a Authority) -> Operation<'a, ()> {
        Box::pin(std::future::pending())
    }
    /// Retire component-owned provisional transports after active setup drains.
    fn stop(&self) -> Operation<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    /// Older adapters retain synchronous setup until they implement routing.
    fn early_terminal(&self) -> bool {
        false
    }
    fn publish_terminal<'a>(
        &'a self,
        _: &'a Authority,
        _: uuid::Uuid,
        _: uuid::Uuid,
        _: crate::duplex::Duplex,
        _: Arc<dyn SshSession>,
    ) -> Operation<'a, ()> {
        Box::pin(async {
            Err(Failure::unsupported(
                "Early terminal routing is unavailable.",
            ))
        })
    }

    fn resolve<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        credential: Option<&'a str>,
    ) -> Operation<'a, Resolved>;
    /// Public origin used for target-side HTTPS preflight before enrollment.
    fn enrollment_origin(&self) -> Option<String> {
        None
    }
    /// Reject a persisted duplicate before staging a payload on the SSH host.
    /// The later invitation reservation still serializes concurrent attempts.
    fn preflight_existing_host<'a>(
        &'a self,
        _authority: &'a Authority,
        _target: &'a Target,
        _lookup: Option<String>,
    ) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn invitation<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
    ) -> Operation<'a, JoinMaterial>;
    /// Only a durable failed-host binding may replace the earlier-setup confirmation.
    /// Unknown servers, hosts, accounts and destinations must return false.
    fn owns_failed_setup<'a>(
        &'a self,
        _authority: &'a Authority,
        _target: &'a Target,
        _check: &'a Check,
        _host: uuid::Uuid,
        _lookup: Option<String>,
    ) -> Operation<'a, bool> {
        Box::pin(async { Ok(false) })
    }
    /// Bind nonsecret cleanup coordinates to the connection that actually authenticated.
    fn invitation_with_trust<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
        _lookup: Option<String>,
    ) -> Operation<'a, JoinMaterial> {
        self.invitation(authority, target, check)
    }
    /// Durable backends register their exact host before any commit can execute.
    /// The caller retains cleanup coordinates if the invitation future is cancelled.
    /// Existing nondurable adapters retain their post-result registration behavior.
    fn invitation_registered<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
        lookup: Option<String>,
        register: &'a mut (dyn FnMut(uuid::Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async move {
            let join = self
                .invitation_with_trust(authority, target, check, lookup)
                .await?;
            register(join.host)?;
            Ok(join)
        })
    }
    /// Issue an invitation only after the host key was prepared over this SSH session.
    fn invitation_registered_with_key<'a>(
        &'a self,
        _authority: &'a Authority,
        _target: &'a Target,
        _check: &'a Check,
        _lookup: Option<String>,
        _binding: PreparedHostKey,
        _register: &'a mut (dyn FnMut(uuid::Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async { Err(Failure::install("SSH host-key proof is unavailable.")) })
    }
    fn connected_facts<'a>(
        &'a self,
        authority: &'a Authority,
        host: uuid::Uuid,
    ) -> Operation<'a, ()>;
    fn terminal_canary<'a>(
        &'a self,
        authority: &'a Authority,
        host: uuid::Uuid,
    ) -> Operation<'a, ()>;
    /// Record earlier-attempt recovery using only public coordinates.
    fn record_start_fresh(&self, _: &Target, _: uuid::Uuid, _: uuid::Uuid, _: &'static str) {}

    /// One public failure record per attempt, before cleanup changes its progress phase.
    fn record_failure(&self, _: &Target, _: Option<uuid::Uuid>, _: Step, _: &Failure) {}
    /// Cut this exact attempt's authority and retain its retirement obligation
    /// before session or SSH cleanup can await. Durable backends keep the
    /// writer alive even if the later `failed` acknowledgement is cancelled.
    /// # Errors
    /// Refuses foreign attempt ownership or unavailable retirement admission.
    fn retire_failed(&self, _: &Authority, _: uuid::Uuid) -> Result<(), Failure> {
        Ok(())
    }
    /// Finish this attempt's private sessions before SSH rollback stops the service.
    fn cleanup_sessions<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn failed<'a>(&'a self, authority: &'a Authority, host: uuid::Uuid) -> Operation<'a, ()>;
    /// Retire only transient attempt ownership after durable installation commits.
    fn completed<'a>(&'a self, _: &'a Authority, _: uuid::Uuid) -> Operation<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// Eight concurrent hosts by default across every socket/batch, not eight per request.
#[derive(Clone)]
pub struct Bootstrap {
    transport: Arc<dyn SshTransport>,
    backend: Arc<dyn Backend>,
    binaries: BinaryPaths,
    payloads: Option<Arc<dyn PayloadSource>>,
    concurrency: Arc<Semaphore>,
    batches: Arc<Semaphore>,
    deadline: Duration,
    lifecycle: Arc<Lifecycle>,
    setup: Arc<crate::setup::Status>,
    pending_setup: Arc<Mutex<HashMap<uuid::Uuid, SetupAttempt>>>,
}

impl Bootstrap {
    /// Bind inventory publication to the server's existing watch, with no new task.
    pub fn session_notifications(&self, notify: tokio::sync::watch::Sender<u64>) {
        self.backend.session_notifications(notify);
    }
    /// Shared retained progress belongs to a host, not a wizard socket.
    #[must_use]
    pub fn setup_status(&self) -> Arc<crate::setup::Status> {
        self.setup.clone()
    }

    /// Wait for host authority retirement without polling or a wizard lifetime.
    pub fn setup_cancelled(&self, host: uuid::Uuid) -> Operation<'_, ()> {
        self.backend.setup_cancelled(host)
    }

    /// Retry setup for a published shell under a newly authenticated capability.
    /// The saved coordinates contain no invitation or browser login material.
    /// # Errors
    /// Refuses foreign/running attempts, component-off or saturated worker admission.
    pub fn retry_setup(
        &self,
        owner: String,
        session: Secret,
        host: uuid::Uuid,
    ) -> Result<(), Failure> {
        let activity = self.activity().map_err(Failure::install)?;
        let permit = self
            .concurrency
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::install("Host setup is busy. Try again shortly."))?;
        let saved = {
            let mut pending = lock(&self.pending_setup);
            let saved = pending
                .get_mut(&host)
                .filter(|saved| saved.owner == owner && !saved.running)
                .ok_or_else(|| {
                    Failure::unsupported("This host has no failed setup steps to retry.")
                })?;
            self.setup.begin(&owner, host, saved.session_id)?;
            saved.running = true;
            saved.clone()
        };
        let authority = Authority {
            owner,
            batch: saved.batch,
            session: Some(session),
            api_key_hash: None,
        };
        let runner = self.clone();
        crate::tasks::spawn(async move {
            let _activity = activity;
            let _permit = permit;
            runner.resume_setup(authority, host, saved).await;
        });
        Ok(())
    }

    async fn resume_setup(&self, authority: Authority, host: uuid::Uuid, saved: SetupAttempt) {
        use crate::setup::{Stage, State};
        let mut enabled = self.enabled_changes();
        let started = Instant::now();
        let work = async {
            self.setup
                .emit(&authority.owner, host, Stage::Install, State::Running, None)?;
            let mut installation = saved.installation.clone();
            let link_started = Instant::now();
            let channel = match installation.resume_session(saved.session_id).await {
                Ok(channel) => channel,
                Err(failure) if failure.kind == crate::model::FailureKind::Unreachable => {
                    // Retry is a fresh authorized operation: resolve the stored credential reference and enforce
                    // SSH host trust again, then reattach only the already-owned shim ID.
                    let resolved = self
                        .backend
                        .resolve(&authority, &saved.target, saved.credential.as_deref())
                        .await?;
                    let session = self
                        .transport
                        .open(resolved.destination, resolved.credentials, resolved.mesh)
                        .await?;
                    // Automatic credentials return a lazy session that admits only the exact
                    // read-only check until it has selected and authenticated its SSH method.
                    // Retry must perform that check before the first exec reattaches the saved
                    // shim; otherwise the bridge sees an unopened authentication wrapper.
                    session
                        .run(crate::probe::CHECK_SCRIPT, Input::Empty)
                        .await?;
                    installation = installation.with_session(session);
                    installation.resume_session(saved.session_id).await?
                }
                Err(failure) => return Err(failure),
            };
            self.backend
                .observe_link(&authority, host, link_started.elapsed());
            self.backend
                .publish_terminal(
                    &authority,
                    host,
                    saved.session_id,
                    channel,
                    installation.ssh_session(),
                )
                .await?;
            // A previous acquisition may have failed before a full image existed.
            // Reverify it before renewing any enrollment authority for this retry.
            let (binary, _) = self
                .resolve_payload(saved.architecture, false, self.payload_budget(started))
                .await?;
            let join = self.backend.reissue_invitation(&authority, host).await?;
            installation.restart_setup(&binary, &join).await?;
            drop(join);
            for stage in [Stage::Install, Stage::Join, Stage::Start] {
                self.setup
                    .emit(&authority.owner, host, stage, State::Done, None)?;
            }
            self.setup
                .emit(&authority.owner, host, Stage::Ready, State::Running, None)?;
            self.complete_setup(&authority, host, &installation, true)
                .await?;
            self.setup
                .emit(&authority.owner, host, Stage::Ready, State::Done, None)
        };
        let result = tokio::select! {
            biased;
            _ = enabled.changed() => Err(Failure::install("SSH host provisioning is off.")),
            _ = self.backend.authority_cancelled(&authority) => Err(Failure::unsupported("The setup request is no longer authorized.")),
            _ = self.backend.setup_cancelled(host) => Err(Failure::unsupported("The host setup is no longer authorized.")),
            result = tokio::time::timeout(self.deadline, work) => result.unwrap_or_else(|_| Err(Failure::install("Host setup exceeded its time limit."))),
        };
        if let Err(failure) = &result {
            self.cleanup_probe(&authority, host).await;
            self.backend
                .record_failure(&saved.target, Some(host), Step::Install, failure);
        }
        self.finish_setup_attempt(&authority, host, &result);
    }

    /// Serialize failure publication with retry admission. A status watcher may
    /// request retry on another worker as soon as it receives the failure.
    fn finish_setup_attempt(
        &self,
        authority: &Authority,
        host: uuid::Uuid,
        result: &Result<(), Failure>,
    ) {
        let mut pending = lock(&self.pending_setup);
        if result.is_ok() {
            pending.remove(&host);
        } else {
            if let Some(saved) = pending.get_mut(&host) {
                saved.running = false;
            }
            if let Err(failure) = result {
                // Retained setup has six stable wire steps. Acquisition belongs
                // to Install there; backend diagnostics keep its architecture step
                // and the actionable sanitized reason remains unchanged.
                let mut published = failure.clone();
                if matches!(
                    published.failed_step,
                    Some(InstallStep::GetArm64Binary | InstallStep::GetX86_64Binary)
                ) {
                    published.failed_step = Some(InstallStep::Install);
                }
                let _ = self.setup.emit(
                    &authority.owner,
                    host,
                    setup_failure_stage(&published),
                    crate::setup::State::Failed,
                    Some(&published),
                );
            }
        }
    }

    /// Warm the admitted source images without blocking HTTP admission.
    /// Missing files/tools retain the existing actionable per-host refusal/raw path.
    pub async fn prepare_payloads(&self) {
        let Ok(_activity) = self.activity() else {
            return;
        };
        for architecture in [
            crate::probe::Architecture::X86_64,
            crate::probe::Architecture::Aarch64,
        ] {
            // Encode the small first image before acquiring the full image, so
            // a stalled full release cannot delay a verified prompt payload.
            let budget = Duration::from_secs(60);
            if let Ok((session, full)) = self.resolve_payload(architecture, true, budget).await {
                Self::warm_payload(&session).await;
                let full = if let Some(full) = full {
                    Some(full)
                } else {
                    self.resolve_payload(architecture, false, budget)
                        .await
                        .ok()
                        .map(|(path, _)| path)
                };
                if let Some(full) = full
                    && full != session
                {
                    Self::warm_payload(&full).await;
                }
            }
        }
    }

    async fn warm_payload(path: &std::path::Path) {
        if crate::payload::digest(path).await.is_ok() {
            for codec in [
                crate::payload_encoding::Codec::Zstd,
                crate::payload_encoding::Codec::Gzip,
            ] {
                let _ = crate::payload_encoding::encoded(path, codec).await;
            }
        }
    }
    /// Warm public encodings after the listener is bound; component-off cancels
    /// the owned compressors and waits for their existing activity lease.
    pub fn warm_payloads(&self) {
        let bootstrap = self.clone();
        let mut enabled = self.enabled_changes();
        crate::tasks::spawn(async move {
            tokio::select! {
                () = bootstrap.prepare_payloads() => {},
                _ = enabled.changed() => {},
            }
        });
    }
    /// Construct an adapter with no network side effects or idle timers.
    #[must_use]
    pub fn new(
        transport: Arc<dyn SshTransport>,
        backend: Arc<dyn Backend>,
        binaries: BinaryPaths,
    ) -> Self {
        Self {
            transport,
            backend,
            binaries,
            payloads: None,
            concurrency: Arc::new(Semaphore::new(crate::manifest::CONCURRENT_HOSTS)),
            batches: Arc::new(Semaphore::new(crate::manifest::CONCURRENT_BATCHES)),
            deadline: Duration::from_secs(crate::manifest::ATTEMPT_SECONDS),
            lifecycle: Lifecycle::new(),
            setup: Arc::default(),
            pending_setup: Arc::default(),
        }
    }

    /// Resolve signed production payloads through the existing installation transaction [225].
    #[must_use]
    pub fn with_payload_source(mut self, source: Arc<dyn PayloadSource>) -> Self {
        self.payloads = Some(source);
        self
    }

    /// Validate the whole batch before admitting any host, then schedule independent attempts.
    /// # Errors
    /// Refuses empty/oversized/duplicate targets, invalid consent/references or global overload.
    pub fn start(
        &self,
        owner: String,
        targets: Vec<Target>,
        credential: Option<String>,
    ) -> Result<Batch, Failure> {
        self.start_authority(
            Authority {
                owner,
                batch: uuid::Uuid::new_v4(),
                session: None,
                api_key_hash: None,
            },
            targets,
            credential,
            Vec::new(),
        )
    }

    /// Carry a browser's already validated live cookie to atomic backend authorization.
    /// # Errors
    /// Refuses empty/oversized capabilities and the same bounded batch admission errors.
    pub fn start_authenticated(
        &self,
        owner: String,
        session: Secret,
        targets: Vec<Target>,
        credential: Option<String>,
    ) -> Result<Batch, Failure> {
        if session.expose().is_empty() || session.expose().len() > 512 {
            return Err(Failure::unsupported(
                "The bootstrap session is unavailable.",
            ));
        }
        self.start_authority(
            Authority {
                owner,
                batch: uuid::Uuid::new_v4(),
                session: Some(session),
                api_key_hash: None,
            },
            targets,
            credential,
            Vec::new(),
        )
    }

    /// Start the same host-setup handler under a scope-checked API-key identity.
    /// The bearer value never enters the SSH plugin; only its one-way id is retained.
    /// # Errors
    /// Refuses malformed key ids and the ordinary bounded batch admission errors.
    pub fn start_api_key(
        &self,
        owner: String,
        key_hash: String,
        targets: Vec<Target>,
    ) -> Result<Batch, Failure> {
        if !valid_api_key_hash(&key_hash) {
            return Err(Failure::unsupported("The bootstrap key is unavailable."));
        }
        self.start_authority(
            Authority {
                owner,
                batch: uuid::Uuid::new_v4(),
                session: None,
                api_key_hash: Some(key_hash),
            },
            targets,
            None,
            Vec::new(),
        )
    }

    /// Start with private material bound to one target attempt, never the whole batch.
    /// # Errors
    /// Refuses invalid sessions, duplicate/foreign material and all normal batch admission errors.
    pub fn start_authenticated_with_auth(
        &self,
        owner: String,
        session: Secret,
        targets: Vec<Target>,
        credential: Option<String>,
        auth_once: Vec<TargetAuth>,
    ) -> Result<Batch, Failure> {
        if session.expose().is_empty() || session.expose().len() > 512 {
            return Err(Failure::unsupported(
                "The bootstrap session is unavailable.",
            ));
        }
        self.start_authority(
            Authority {
                owner,
                batch: uuid::Uuid::new_v4(),
                session: Some(session),
                api_key_hash: None,
            },
            targets,
            credential,
            auth_once,
        )
    }

    fn start_authority(
        &self,
        authority: Authority,
        targets: Vec<Target>,
        credential: Option<String>,
        auth_once: Vec<TargetAuth>,
    ) -> Result<Batch, Failure> {
        if targets.is_empty()
            || targets.len() > 100
            || credential.as_ref().is_some_and(|v| !identifier(v))
        {
            return Err(Failure::unsupported(
                "Select between one and 100 hosts and a valid credential reference.",
            ));
        }
        let mut states = HashMap::new();
        for target in targets {
            target.validate()?;
            let id = target.id.clone();
            if states
                .insert(
                    id,
                    HostState {
                        target,
                        attempt: 0,
                        running: false,
                        failed: false,
                        cleanup: None,
                        last_failure: None,
                        start_fresh: None,
                    },
                )
                .is_some()
            {
                return Err(Failure::unsupported(
                    "Each selected host needs a unique identifier.",
                ));
            }
        }
        // Validate every private binding before spawning even the first target.
        let mut private = HashMap::new();
        for input in auth_once {
            input.auth.validate()?;
            if !states.contains_key(&input.target)
                || private.insert(input.target, input.auth).is_some()
            {
                return Err(Failure::unsupported(
                    "One-use credentials need unique selected targets.",
                ));
            }
        }
        let permit = self.batches.clone().try_acquire_owned().map_err(|_| {
            Failure::install("Too many bootstrap batches are running. Try again shortly.")
        })?;
        let (changed, _) = watch::channel(0);
        let (cancel, _) = watch::channel(false);
        let batch = Batch {
            inner: Arc::new(BatchInner {
                authority,
                credential,
                states: Mutex::new(states),
                history: Mutex::new(History {
                    sequence: 0,
                    events: VecDeque::new(),
                    metadata: HashMap::new(),
                }),
                changed,
                cancel,
                socket_closed: watch::channel(false).0,
                _permit: permit,
            }),
        };
        self.lifecycle
            .register(&batch.inner)
            .map_err(Failure::install)?;
        let ids: Vec<_> = lock(&batch.inner.states).keys().cloned().collect();
        for id in ids {
            self.schedule(batch.inner.clone(), &id, private.remove(&id))?;
        }
        Ok(batch)
    }

    fn schedule(
        &self,
        batch: Arc<BatchInner>,
        id: &str,
        auth_once: Option<OneUseAuth>,
    ) -> Result<(), Failure> {
        if *batch.cancel.borrow() {
            return Err(Failure::install("The host setup batch has stopped."));
        }
        let activity = self.activity().map_err(Failure::install)?;
        if let Some(material) = &auth_once {
            material.validate()?;
        }
        let (target, attempt) = {
            let mut states = lock(&batch.states);
            let state = states
                .get_mut(id)
                .ok_or_else(|| Failure::unsupported("This host is not in the batch."))?;
            if state.running || state.attempt > 0 && !state.failed || state.attempt >= 8 {
                return Err(Failure::unsupported(
                    "Only failed hosts can be retried, up to eight attempts.",
                ));
            }
            state.running = true;
            state.failed = false;
            state.last_failure = None;
            state.attempt += 1;
            (state.target.clone(), state.attempt)
        };
        lock(&batch.history).metadata.insert(
            target.id.clone(),
            HostMetadata {
                attempt,
                authentication: None,
                host_id: None,
                session_id: None,
            },
        );
        let runner = self.clone();
        crate::tasks::spawn(async move {
            let _activity = activity;
            runner.attempt(batch, target, attempt, auth_once).await;
        });
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep failure recording, session cleanup, rollback and final state ordered in one attempt."
    )]
    async fn attempt(
        &self,
        batch: Arc<BatchInner>,
        target: Target,
        attempt: u32,
        auth_once: Option<OneUseAuth>,
    ) {
        let mut cancel = batch.cancel.subscribe();
        let mut socket_closed = batch.socket_closed.subscribe();
        let started = Instant::now();
        let mut resources = AttemptResources::default();
        let cancelled = Failure::install("Host installation was cancelled.");
        // Hold the admission slot through rollback too: failed hosts must not
        // create another eight live SSH children while the next hosts install.
        // Queued plaintext never waits behind the full 180-second install limit.
        // It belongs to this future, not HostState, and drops on timeout/cancellation.
        let queue_limit = auth_once.as_ref().map(OneUseAuth::remaining);
        let admission = if *cancel.borrow() || *socket_closed.borrow() {
            Err(cancelled.clone())
        } else {
            tokio::select! {
                _ = cancel.changed() => Err(cancelled.clone()),
                _ = socket_closed.changed() => Err(cancelled.clone()),
                permit = async {
                    if let Some(limit) = queue_limit {
                        match tokio::time::timeout(limit, self.concurrency.clone().acquire_owned()).await {
                            Ok(permit) => permit.map_err(|_| Failure::install("Bootstrap is shutting down.")),
                            Err(_) => Err(Failure::unsupported("Queued SSH credentials expired. Retry with fresh material.")),
                        }
                    } else {
                        self.concurrency.clone().acquire_owned().await.map_err(|_| Failure::install("Bootstrap is shutting down."))
                    }
                } => permit,
            }
        };
        let result = if let Err(error) = &admission {
            Err(error.clone())
        } else if *cancel.borrow() {
            Err(cancelled)
        } else {
            let mut closed = batch.socket_closed.subscribe();
            let mut detached = false;
            let running = tokio::time::timeout(
                self.deadline,
                self.run(&batch, &target, attempt, started, &mut resources, auth_once),
            );
            tokio::pin!(running);
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.changed() => break Err(cancelled),
                    _ = self.backend.authority_cancelled(&batch.authority) => break Err(cancelled),
                    () = async { if *closed.borrow() { return; } let _ = closed.changed().await; }, if !detached => {
                        let published = lock(&batch.history).metadata.get(&target.id).is_some_and(|m| m.session_id.is_some());
                        if !published { break Err(cancelled); }
                        detached = true;
                    },
                    result = &mut running => break result.unwrap_or_else(|_| Err(Failure::install("Host installation exceeded its time limit."))),
                }
            }
        };
        if let Err(failure) = &result {
            let phase = lock(&batch.history)
                .events
                .iter()
                .rev()
                .find(|event| event.target == target.id && event.attempt == attempt)
                .map_or(Step::Check, |event| event.step);
            self.backend
                .record_failure(&target, resources.host, phase, failure);
            if resources.published
                && let Some(host) = resources.host
            {
                self.cleanup_probe(&batch.authority, host).await;
            }
            if !resources.published {
                if let Some(host) = resources.host {
                    let _ = self.backend.retire_failed(&batch.authority, host);
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        self.backend.cleanup_sessions(&batch.authority, host),
                    )
                    .await;
                }
                if let Some(installation) = resources.installation {
                    let cleanup =
                        tokio::time::timeout(Duration::from_secs(30), installation.rollback())
                            .await;
                    if !matches!(cleanup, Ok(Ok(()))) {
                        if let Some(state) = lock(&batch.states).get_mut(&target.id) {
                            state.cleanup = Some(installation.cleanup_coordinates());
                        }
                        emit(
                            &batch,
                            &target,
                            attempt,
                            Step::Install,
                            "Automatic cleanup could not finish. Retry to finish the earlier setup before continuing.",
                            started,
                            None,
                        );
                    }
                }
                if let Some(host) = resources.host {
                    // Invalidate invitations/partial new authority through the trusted
                    // backend; it must preserve an existing enrolled installation.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        self.backend.failed(&batch.authority, host),
                    )
                    .await;
                }
            }
        }
        let mut states = lock(&batch.states);
        if let Some(state) = states.get_mut(&target.id) {
            state.start_fresh = None;
            state.running = false;
            state.failed = result.is_err();
            state.last_failure = result.as_ref().err().cloned();
        }
        // Keep state and completion event ordered: retry after failed cannot race
        // the final event from its predecessor.
        if resources.published {
            if let Some(host) = resources.host {
                self.finish_setup_attempt(&batch.authority, host, &result);
            }
            if resources.announced {
                return;
            }
        }
        match result {
            Ok(()) => emit(
                &batch,
                &target,
                attempt,
                Step::Done,
                "The infraternal agent is ready.",
                started,
                None,
            ),
            Err(failure) => emit(
                &batch,
                &target,
                attempt,
                Step::Failed,
                failure.message,
                started,
                Some(failure),
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    // Transient bytes remain in this future and its lazy provider, never batch state.
    async fn resolve_attempt(
        &self,
        batch: &BatchInner,
        target: &Target,
        auth_once: Option<OneUseAuth>,
    ) -> Result<Resolved, Failure> {
        let resolving = self.backend.resolve(
            &batch.authority,
            target,
            target.credential.as_deref().or(batch.credential.as_deref()),
        );
        let mut resolved = if let Some(material) = &auth_once {
            tokio::time::timeout(material.remaining(), resolving)
                .await
                .map_err(|_| {
                    Failure::unsupported(
                        "Queued SSH credentials expired. Retry with fresh material.",
                    )
                })??
        } else {
            resolving.await?
        };
        if let Some(material) = auth_once {
            let Credentials::Automatic(base) = resolved.credentials else {
                return Err(Failure::unsupported(
                    "One-use credentials need automatic authentication.",
                ));
            };
            resolved.credentials = Credentials::Automatic(material.layer(base));
        }
        Ok(resolved)
    }

    /// Resolve the first trusted image before any installation writes. A full
    /// fallback is retained so an older release does not repeat its acquisition.
    async fn payload(
        &self,
        batch: &BatchInner,
        target: &Target,
        attempt: u32,
        started: Instant,
        architecture: crate::probe::Architecture,
        early: bool,
    ) -> Result<(std::path::PathBuf, Option<std::path::PathBuf>), Failure> {
        if self.payloads.is_some() {
            emit(
                batch,
                target,
                attempt,
                Step::Install,
                match architecture {
                    crate::probe::Architecture::Aarch64 => "Get the arm64 binary",
                    crate::probe::Architecture::X86_64 => "Get the x86_64 binary",
                },
                started,
                None,
            );
        }
        self.resolve_payload(architecture, early, self.payload_budget(started))
            .await
    }

    fn payload_budget(&self, started: Instant) -> Duration {
        // End acquisition before the enclosing attempt deadline so its named
        // failure survives instead of becoming a generic installation timeout.
        self.deadline
            .saturating_sub(started.elapsed())
            .saturating_sub(Duration::from_secs(1))
            .min(Duration::from_secs(60))
    }

    /// Source admission is authoritative for both images: session absence may
    /// fall back only through that source's verified full-image acquisition.
    async fn resolve_payload(
        &self,
        architecture: crate::probe::Architecture,
        early: bool,
        budget: Duration,
    ) -> Result<(std::path::PathBuf, Option<std::path::PathBuf>), Failure> {
        if let Some(source) = &self.payloads {
            let step = match architecture {
                crate::probe::Architecture::Aarch64 => InstallStep::GetArm64Binary,
                crate::probe::Architecture::X86_64 => InstallStep::GetX86_64Binary,
            };
            tokio::time::timeout(budget, async {
                if early && let Some(session) = source.session(architecture).await? {
                    return Ok((session, None));
                }
                let full = source.get(architecture).await?;
                Ok((full.clone(), Some(full)))
            })
            .await
            .map_err(|_| Failure::install("the builds host did not respond in time.").at(step))?
        } else {
            let full = self.binaries.get(architecture).to_owned();
            let first = if early {
                self.binaries.session_payload(architecture)?
            } else {
                full.clone()
            };
            Ok((first, Some(full)))
        }
    }

    /// Old hosts may have no runtime helper, or a cached binary that predates
    /// the capability level cleanup needs (exit 76). Resolve and verify our
    /// full executable and publish it to the cache; never ask the host to
    /// install an interpreter or trust its PATH (#230). The early session
    /// image never serves here: it has no runtime-lock helper.
    #[cold]
    #[inline(never)]
    fn refresh_helper<'a>(
        &'a self,
        batch: &'a BatchInner,
        target: &'a Target,
        attempt: u32,
        started: Instant,
        session: &'a dyn SshSession,
        architecture: Option<crate::probe::Architecture>,
    ) -> Operation<'a, ()> {
        Box::pin(async move {
            let architecture = if let Some(architecture) = architecture {
                architecture
            } else {
                let sniff = session
                    .run(crate::probe::CHECK_SCRIPT, Input::Empty)
                    .await?;
                let check = crate::probe::Check::parse(&sniff.stdout)?;
                check.authorize_mode(target.mode)?;
                check.architecture
            };
            let (binary, _) = self
                .payload(batch, target, attempt, started, architecture, false)
                .await?;
            Installation::prepare_recovery(session, target, &binary).await
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "Keep ordered bootstrap steps and transaction ownership in one cancellation-safe attempt."
    )]
    fn run<'a>(
        &'a self,
        batch: &'a BatchInner,
        target: &'a Target,
        attempt: u32,
        started: Instant,
        resources: &'a mut AttemptResources,
        auth_once: Option<OneUseAuth>,
    ) -> Operation<'a, ()> {
        // One setup state machine is shared with the deadline/cancellation driver [243].
        // The allocation ends with this host attempt and is never on a session path.
        Box::pin(async move {
            emit(
                batch,
                target,
                attempt,
                Step::Check,
                "Checking the SSH host.",
                started,
                None,
            );
            let resolved = self.resolve_attempt(batch, target, auth_once).await?;
            let session = self
                .transport
                .open(resolved.destination, resolved.credentials, resolved.mesh)
                .await
                .map_err(|error| error.at(InstallStep::Connect))?;
            let server_origin = self.backend.enrollment_origin();
            let early_candidate = self.backend.early_terminal() && server_origin.is_none();
            let owns_cleanup = lock(&batch.states)
                .get(&target.id)
                .is_some_and(|state| state.cleanup.is_some());
            // Stored coordinates already authorize this attempt's rollback. Restore
            // it before inspecting earlier attempts; its own lease is not foreign.
            let script = if owns_cleanup {
                format!(
                    "{}\nprintf 'INFRATERNAL_SETUP_CLEAR\\n'",
                    crate::probe::CHECK_SCRIPT
                )
            } else {
                previous_attempt::check_script(target.mode)
            };
            // An outdated or missing cached runtime helper asks for a refresh
            // (76): publish our verified full executable, then inspect again (#230).
            let mut refreshed = false;
            let link_started = Instant::now();
            let (output, checked) = loop {
                let result = if early_candidate {
                    session.check_stream(&script).await
                } else {
                    session
                        .run(&script, Input::Empty)
                        .await
                        .map(|output| (output, None))
                        .map_err(|error| previous_attempt::classify(error.at(InstallStep::Connect)))
                };
                match result {
                    Err(error) if error.exit_status == Some(76) && !refreshed => {
                        refreshed = true;
                        self.refresh_helper(
                            batch,
                            target,
                            attempt,
                            started,
                            session.as_ref(),
                            None,
                        )
                        .await?;
                    }
                    result => break result?,
                }
            };
            let link_round_trip = link_started.elapsed();
            // Automatic sign-in selects its authenticated adapter during the
            // read-only check; query bridge support after that selection.
            let early = early_candidate && session.session_bridge();
            // Preserve method evidence even if the authenticated host is unsupported.
            // Public metadata only; no provider or private material enters replay state.
            if let Some(metadata) = lock(&batch.history).metadata.get_mut(&target.id) {
                metadata.authentication = session.authentication();
            }
            let (check, previous) = previous_attempt::parse_check(&output.stdout)?;
            check.authorize_mode(target.mode)?;
            match restore_previous(batch, target, attempt, started, session.clone()).await {
                Err(error) if error.exit_status == Some(76) => {
                    self.refresh_helper(
                        batch,
                        target,
                        attempt,
                        started,
                        session.as_ref(),
                        Some(check.architecture),
                    )
                    .await?;
                    restore_previous(batch, target, attempt, started, session.clone()).await?;
                }
                result => result?,
            }
            let lookup = session.trust_lookup();
            if let Some(previous) = previous {
                // Only this server's durable failed-host binding finishes the
                // earlier setup without asking; anything else still asks (#230).
                let automatic = self
                    .backend
                    .owns_failed_setup(
                        &batch.authority,
                        target,
                        &check,
                        previous.host,
                        lookup.clone(),
                    )
                    .await?;
                self.await_start_fresh(
                    batch,
                    target,
                    attempt,
                    started,
                    session.as_ref(),
                    &previous,
                    automatic,
                )
                .await?;
            }
            // Existing remote identities must be reported before the first
            // payload is staged, even if the replacement binary is unavailable.
            if server_origin.is_some() {
                self.backend
                    .preflight_existing_host(&batch.authority, target, lookup.clone())
                    .await?;
            }
            // Public HTTPS must be reachable and the host key prepared before the
            // backend creates the one-use invitation. The staged transaction remains
            // rollback-owned if preflight or invitation issuance fails.
            let mut staged_payload = None;
            let key_binding = if let Some(origin) = server_origin.as_deref() {
                let (session_binary, full_binary) = self
                    .payload(batch, target, attempt, started, check.architecture, false)
                    .await?;
                let binary = full_binary
                    .clone()
                    .unwrap_or_else(|| session_binary.clone());
                let host = uuid::Uuid::new_v4();
                resources.installation =
                    Some(Installation::new_pending(session.clone(), target, host)?);
                let transaction = resources.installation.as_ref().ok_or_else(|| {
                    Failure::install("The installation transaction is unavailable.")
                })?;
                let digest = transaction.prepare_join_key(&binary, origin).await?;
                staged_payload = Some((session_binary, full_binary));
                Some(PreparedHostKey { host, digest })
            } else {
                None
            };
            // Durable publication can outlive a cancelled acknowledgement. Bind
            // cleanup ownership before the backend can enqueue its commit.
            let mut register = |host| {
                resources.host = Some(host);
                Ok(())
            };
            let join = if let Some(binding) = key_binding {
                self.backend
                    .invitation_registered_with_key(
                        &batch.authority,
                        target,
                        &check,
                        lookup.clone(),
                        binding,
                        &mut register,
                    )
                    .await?
            } else {
                self.backend
                    .invitation_registered(&batch.authority, target, &check, lookup, &mut register)
                    .await?
            };
            let key_prepared = server_origin.is_some();
            resources.host = Some(join.host);
            self.backend
                .observe_link(&batch.authority, join.host, link_round_trip);
            if let Some(metadata) = lock(&batch.history).metadata.get_mut(&target.id) {
                metadata.host_id = Some(join.host);
            }
            let (session_binary, mut full_binary) = match staged_payload {
                Some(payload) => payload,
                None => {
                    self.payload(batch, target, attempt, started, check.architecture, early)
                        .await?
                }
            };
            if resources.installation.is_none() {
                resources.installation = Some(Installation::new(session.clone(), target, &join)?);
            }
            let transaction = resources
                .installation
                .as_ref()
                .ok_or_else(|| Failure::install("The installation transaction is unavailable."))?;
            emit(
                batch,
                target,
                attempt,
                Step::Install,
                "Installing the infraternal agent.",
                started,
                None,
            );
            let setup = async {
                if early {
                    let encoding = checked
                        .as_ref()
                        .and_then(crate::install::Checked::encoding)
                        .filter(|_| target.mode == crate::model::InstallMode::Rootless);
                    let (session_id, channel) = transaction
                        .stage_session_on(&session_binary, checked)
                        .await?;
                    // Once a real shim exists, rollback must never remove its rendezvous
                    // or stop its shell while publication's durable write is in flight.
                    resources.published = true;
                    if let Some(metadata) = lock(&batch.history).metadata.get_mut(&target.id) {
                        metadata.session_id = Some(session_id);
                    }
                    self.setup
                        .begin(&batch.authority.owner, join.host, session_id)?;
                    lock(&self.pending_setup).insert(
                        join.host,
                        SetupAttempt {
                            owner: batch.authority.owner.clone(),
                            batch: batch.authority.batch,
                            target: target.clone(),
                            credential: target.credential.clone().or(batch.credential.clone()),
                            session_id,
                            installation: transaction.clone(),
                            architecture: check.architecture,
                            running: true,
                        },
                    );
                    self.setup.emit(
                        &batch.authority.owner,
                        join.host,
                        crate::setup::Stage::Install,
                        crate::setup::State::Running,
                        None,
                    )?;
                    self.backend
                        .publish_terminal(&batch.authority, join.host, session_id, channel, session)
                        .await?;
                    emit(
                        batch,
                        target,
                        attempt,
                        Step::Done,
                        "The terminal is ready; setup steps continue.",
                        started,
                        None,
                    );
                    resources.announced = true;
                    tokio::select! {
                        biased;
                        _ = self.backend.setup_cancelled(join.host) => Err(Failure::unsupported("The host setup is no longer authorized.")),
                        result = async {
                            let full = if let Some(full) = &full_binary {
                                full.clone()
                            } else {
                                let (full, _) = self.resolve_payload(
                                    check.architecture,
                                    false,
                                    self.payload_budget(started),
                                ).await?;
                                full_binary = Some(full.clone());
                                full
                            };
                            if session_binary == full {
                                transaction.setup(&join).await
                            } else {
                                // The already-proven retry path retires only the upload
                                // journal, preserving the shim and host identity. It
                                // never truncates the executable's running inode.
                                transaction.restart_setup_with(&full, &join, encoding).await
                            }
                        } => result,
                    }
                } else if key_prepared {
                    transaction.setup(&join).await
                } else {
                    transaction.stage_and_setup(&session_binary, &join).await
                }
            };
            let linger = setup.await.map_err(|mut error| {
                if error.message == "The matching static infraternal binary is unavailable." {
                    error.missing_binary = Some(Box::new(crate::model::MissingBinary {
                        architecture: match check.architecture {
                            crate::probe::Architecture::X86_64 => "x86_64",
                            crate::probe::Architecture::Aarch64 => "aarch64",
                        },
                        path: full_binary
                            .as_ref()
                            .unwrap_or(&session_binary)
                            .display()
                            .to_string(),
                    }));
                }
                error
            })?;
            if early {
                for stage in [
                    crate::setup::Stage::Install,
                    crate::setup::Stage::Join,
                    crate::setup::Stage::Start,
                ] {
                    self.setup.emit(
                        &batch.authority.owner,
                        join.host,
                        stage,
                        crate::setup::State::Done,
                        None,
                    )?;
                }
                self.setup.emit(
                    &batch.authority.owner,
                    join.host,
                    crate::setup::Stage::Ready,
                    crate::setup::State::Running,
                    None,
                )?;
            }
            drop(join); // Capability plaintext is erased immediately after its stdin handoff.
            if !linger && !early {
                emit(
                    batch,
                    target,
                    attempt,
                    Step::Install,
                    "Host policy did not enable user linger; the service may stop after logout.",
                    started,
                    None,
                );
            }
            let host = resources
                .host
                .ok_or_else(|| Failure::install("The enrolled host identity is unavailable."))?;
            if !early {
                emit(
                    batch,
                    target,
                    attempt,
                    Step::Facts,
                    "Waiting for authenticated host facts.",
                    started,
                    None,
                );
            }
            if !early {
                emit(
                    batch,
                    target,
                    attempt,
                    Step::Connect,
                    "Checking a terminal through the infraternal agent.",
                    started,
                    None,
                );
            }
            self.complete_setup(&batch.authority, host, transaction, early)
                .await?;
            if early {
                self.setup.emit(
                    &batch.authority.owner,
                    host,
                    crate::setup::Stage::Ready,
                    crate::setup::State::Done,
                    None,
                )?;
            }
            Ok(())
        })
    }

    /// Initial setup and retry share the same admitted proof/commit path.
    /// Retiring host authority cancels both proof and remote commit together.
    fn complete_setup<'a>(
        &'a self,
        authority: &'a Authority,
        host: uuid::Uuid,
        installation: &'a Installation,
        published: bool,
    ) -> Operation<'a, ()> {
        // Fresh setup and retry share this bounded proof/commit poll function.
        Box::pin(async move {
            let proof = async {
                let (release, approved) = tokio::sync::oneshot::channel();
                // The SSH commit child must outlive both sequential readiness
                // phases and its own command/exit round trips. Clamp it to the
                // attempt limit; below that ceiling, readiness reports its
                // route-specific failure before SSH cancels the command.
                let commit_timeout = self
                    .backend
                    .setup_commit_timeout(authority, host)
                    .map(|timeout| timeout.min(self.deadline));
                tokio::try_join!(
                    async {
                        if published {
                            // Each callback independently awaits installed authority,
                            // ownership and UID admission. Both must succeed before
                            // the commit signal; a failed sibling may leave only the
                            // registered private canary to finish, never the user shell.
                            tokio::try_join!(
                                self.backend.connected_facts(authority, host),
                                self.backend.terminal_canary(authority, host),
                            )?;
                        } else {
                            // Older adapters retain their existing proof ordering.
                            self.backend.connected_facts(authority, host).await?;
                            self.backend.terminal_canary(authority, host).await?;
                        }
                        release.send(()).map_err(|()| {
                            Failure::install("The host commit command ended before terminal proof.")
                        })
                    },
                    installation.commit_after(approved, commit_timeout),
                )?;
                // Completion discharges durable retirement only after proof and commit.
                self.backend.completed(authority, host).await
            };
            let result = if published {
                tokio::select! {
                    biased;
                    _ = self.backend.setup_cancelled(host) => Err(Failure::unsupported("The host setup is no longer authorized.")),
                    result = proof => result,
                }
            } else {
                proof.await
            };
            if published && result.is_err() {
                // Cleanup belongs outside both cancellation fences: a stopped
                // commit channel or retired host drops the private proof future.
                // The callback owns only its registered canary, never the shell.
                self.cleanup_probe(authority, host).await;
            }
            result
        })
    }

    /// Idempotent cleanup also covers an outer setup deadline dropping proof.
    async fn cleanup_probe(&self, authority: &Authority, host: uuid::Uuid) {
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            self.backend.cleanup_sessions(authority, host),
        )
        .await;
    }

    /// Confirm only this failed attempt's public observation; the caller supplies
    /// fresh authority, rechecked by the transport immediately before pin publication.
    /// # Errors
    /// Refuses foreign/running/successful hosts, stale observations and changed trust.
    pub async fn confirm_host_key(
        &self,
        batch: &Batch,
        owner: &str,
        id: &str,
        challenge: &str,
        fingerprint: &str,
        authority: &dyn ConfirmationAuthority,
    ) -> Result<(), Failure> {
        let _activity = self.activity().map_err(Failure::install)?;
        let mut enabled = self.enabled_changes();
        if !*enabled.borrow() {
            return Err(Failure::install("SSH host provisioning is off."));
        }
        tokio::select! {
            biased;
            _ = enabled.changed() => Err(Failure::install("SSH host provisioning is off.")),
            result = async {
        if batch.inner.authority.owner != owner || *batch.inner.cancel.borrow() {
            return Err(Failure::unsupported("The bootstrap batch is unavailable."));
        }
        let target = {
            let states = lock(&batch.inner.states);
            let state = states
                .get(id)
                .ok_or_else(|| Failure::unsupported("This host is not in the batch."))?;
            let failure = state.last_failure.as_ref().ok_or_else(|| {
                Failure::unsupported("Retry the host check before confirming trust.")
            })?;
            if state.running
                || !state.failed
                || failure.kind != crate::model::FailureKind::HostKey
                || failure
                    .host_key_challenge()
                    .is_none_or(|value| value.to_string() != challenge)
                || !failure
                    .fingerprints
                    .iter()
                    .any(|value| value == fingerprint)
            {
                return Err(Failure::unsupported(
                    "This SSH host-key observation is no longer available.",
                ));
            }
            state.target.clone()
        };
        let resolved = self
            .backend
            .resolve(
                &batch.inner.authority,
                &target,
                target
                    .credential
                    .as_deref()
                    .or(batch.inner.credential.as_deref()),
            )
            .await?;
        self.transport
            .confirm_host_key(resolved.destination, challenge, fingerprint, authority)
            .await
            } => result,
        }
    }

    /// Resume only this socket's exact paused observation; no new attempt or identity is issued.
    /// # Errors
    /// Refuses foreign owners, expired observations, running nonpaused hosts and reused challenges.
    pub fn start_fresh(
        &self,
        batch: &Batch,
        owner: &str,
        id: &str,
        challenge: uuid::Uuid,
    ) -> Result<(), Failure> {
        let _activity = self.activity().map_err(Failure::install)?;
        if batch.inner.authority.owner != owner || *batch.inner.cancel.borrow() {
            return Err(Failure::unsupported("The host setup batch is unavailable."));
        }
        let mut states = lock(&batch.inner.states);
        let state = states
            .get_mut(id)
            .ok_or_else(|| Failure::unsupported("This host is not in the batch."))?;
        if !state.running
            || state
                .start_fresh
                .as_ref()
                .is_none_or(|pending| pending.challenge != challenge)
        {
            return Err(Failure::unsupported(
                "This earlier setup observation is no longer available. Retry the host check.",
            ));
        }
        let pending = state
            .start_fresh
            .take()
            .ok_or_else(|| Failure::unsupported("This host is not waiting to start fresh."))?;
        pending.resume.send(()).map_err(|()| {
            Failure::unsupported("This host setup observation expired. Retry the host check.")
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn await_start_fresh(
        &self,
        batch: &BatchInner,
        target: &Target,
        attempt: u32,
        started: Instant,
        session: &dyn SshSession,
        previous: &PreviousAttempt,
        automatic: bool,
    ) -> Result<(), Failure> {
        if automatic {
            emit(
                batch,
                target,
                attempt,
                Step::Install,
                "An earlier setup on this host did not finish; finishing it now.",
                started,
                None,
            );
        } else {
            let challenge = uuid::Uuid::new_v4();
            let (resume, resumed) = oneshot::channel();
            {
                let mut states = lock(&batch.states);
                let state = states
                    .get_mut(&target.id)
                    .ok_or_else(|| Failure::install("The host setup is unavailable."))?;
                state.start_fresh = Some(PendingFresh { challenge, resume });
            }
            emit_with_leftovers(
                batch,
                target,
                attempt,
                Step::Check,
                "This host has leftovers from an earlier setup",
                started,
                Some(Failure::new(
                    crate::model::FailureKind::StalePreviousAttempt,
                    "infraternal didn't finish setting up here before. Start fresh to remove what it left behind and continue.",
                )),
                Some(Box::new(previous.findings(target.mode, challenge))),
            );
            resumed.await.map_err(|_| {
                Failure::install("Host provisioning stopped while waiting to start fresh.")
            })?;
        }
        self.backend
            .record_start_fresh(target, previous.host, previous.transaction, "started");
        let result = previous.start_fresh(session, target).await;
        self.backend.record_start_fresh(
            target,
            previous.host,
            previous.transaction,
            if result.is_ok() {
                "completed"
            } else {
                "refused"
            },
        );
        result?;
        emit(
            batch,
            target,
            attempt,
            Step::Check,
            "Earlier setup leftovers removed. Continuing the setup steps.",
            started,
            None,
        );
        Ok(())
    }

    /// Retry one failed host, keeping its trusted host identity in the backend.
    /// # Errors
    /// Refuses a foreign batch owner, unknown/running/successful host or excessive attempts.
    pub fn retry(&self, batch: &Batch, owner: &str, id: &str) -> Result<(), Failure> {
        if batch.inner.authority.owner != owner || *batch.inner.cancel.borrow() {
            return Err(Failure::unsupported("The bootstrap batch is unavailable."));
        }
        self.retry_with_auth(batch, owner, id, None)
    }

    /// Retry one failed host with transient browser material; no other target or later retry can reuse it.
    /// # Errors
    /// Refuses invalid material and the same owner/host/attempt admission errors as retry.
    pub fn retry_with_auth(
        &self,
        batch: &Batch,
        owner: &str,
        id: &str,
        auth_once: Option<OneUseAuth>,
    ) -> Result<(), Failure> {
        if batch.inner.authority.owner != owner || *batch.inner.cancel.borrow() {
            return Err(Failure::unsupported("The bootstrap batch is unavailable."));
        }
        self.schedule(batch.inner.clone(), id, auth_once)
    }
}

async fn restore_previous(
    batch: &BatchInner,
    target: &Target,
    attempt: u32,
    started: Instant,
    session: Arc<dyn SshSession>,
) -> Result<(), Failure> {
    let cleanup = lock(&batch.states)
        .get(&target.id)
        .and_then(|state| state.cleanup);
    if let Some(cleanup) = cleanup {
        emit(
            batch,
            target,
            attempt,
            Step::Install,
            "An earlier setup on this host did not finish; finishing it now.",
            started,
            None,
        );
        Installation::resume_cleanup(session, target, cleanup)?
            .rollback()
            .await?;
        if let Some(state) = lock(&batch.states).get_mut(&target.id) {
            state.cleanup = None;
        }
    }
    Ok(())
}

/// Mutation resources belong to one attempt, including its rollback and host retirement.
#[derive(Default)]
struct AttemptResources {
    installation: Option<Installation>,
    host: Option<uuid::Uuid>,
    // Protect the real shim before a durable routing write can be cancelled.
    published: bool,
    // Only an acknowledged publication may suppress the wizard failure event.
    announced: bool,
}

// Retain only failed live-session transaction coordinates; success removes the
// record so its SSH master and ephemeral authentication material can retire.
#[derive(Clone)]
struct SetupAttempt {
    owner: String,
    batch: uuid::Uuid,
    target: Target,
    /// Credential reference only; plaintext material is resolved for each explicit authorized retry.
    credential: Option<String>,
    session_id: uuid::Uuid,
    installation: Installation,
    architecture: crate::probe::Architecture,
    running: bool,
}
fn setup_failure_stage(failure: &Failure) -> crate::setup::Stage {
    match failure.failed_step {
        Some(InstallStep::Join) => crate::setup::Stage::Join,
        Some(InstallStep::Start) => crate::setup::Stage::Start,
        Some(InstallStep::Readiness) => crate::setup::Stage::Ready,
        _ => crate::setup::Stage::Install,
    }
}

struct PendingFresh {
    challenge: uuid::Uuid,
    resume: oneshot::Sender<()>,
}

struct HostState {
    target: Target,
    attempt: u32,
    running: bool,
    failed: bool,
    cleanup: Option<Cleanup>,
    last_failure: Option<Failure>,
    start_fresh: Option<PendingFresh>,
}
/// Shares history's lock: emit must not acquire `HostState` while completion holds
/// it to order retries. Exactly one current metadata row per bounded target.
#[derive(Clone, Copy, Default)]
struct HostMetadata {
    attempt: u32,
    authentication: Option<Authentication>,
    host_id: Option<uuid::Uuid>,
    session_id: Option<uuid::Uuid>,
}
struct History {
    sequence: u64,
    events: VecDeque<Event>,
    metadata: HashMap<String, HostMetadata>,
}
pub(crate) struct BatchInner {
    authority: Authority,
    credential: Option<String>,
    states: Mutex<HashMap<String, HostState>>,
    history: Mutex<History>,
    changed: watch::Sender<u64>,
    pub(crate) cancel: watch::Sender<bool>,
    socket_closed: watch::Sender<bool>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Socket closure cancels unpublished work; published terminals keep bounded setup alive.
pub struct Batch {
    inner: Arc<BatchInner>,
}
impl Batch {
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.changed.subscribe()
    }
    /// Returns the oldest retained sequence and every event after `after`.
    #[must_use]
    pub fn events(&self, after: u64) -> (u64, Vec<Event>) {
        let history = lock(&self.inner.history);
        (
            history.events.front().map_or(1, |event| event.sequence),
            history
                .events
                .iter()
                .filter(|event| event.sequence > after)
                .cloned()
                .collect(),
        )
    }
}
impl Drop for Batch {
    fn drop(&mut self) {
        self.inner.socket_closed.send_replace(true);
    }
}

fn emit(
    batch: &BatchInner,
    target: &Target,
    attempt: u32,
    step: Step,
    message: &'static str,
    started: Instant,
    failure: Option<Failure>,
) {
    emit_with_leftovers(
        batch, target, attempt, step, message, started, failure, None,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_with_leftovers(
    batch: &BatchInner,
    target: &Target,
    attempt: u32,
    step: Step,
    message: &'static str,
    started: Instant,
    failure: Option<Failure>,
    leftovers: Option<Box<crate::model::Leftovers>>,
) {
    let mut history = lock(&batch.history);
    history.sequence += 1;
    let sequence = history.sequence;
    if history.events.len() == 1024 {
        history.events.pop_front();
    }
    // Expandable diagnostics contain only trusted phase messages, never remote
    // output. Keep eight breadcrumbs per host attempt; no secret guessing filter.
    let mut log_tail: Vec<_> = history
        .events
        .iter()
        .rev()
        .filter(|event| event.target == target.id && event.attempt == attempt)
        .take(7)
        .map(|event| event.message)
        .collect();
    log_tail.reverse();
    log_tail.push(message);
    let metadata = history
        .metadata
        .get(&target.id)
        .filter(|metadata| metadata.attempt == attempt)
        .copied()
        .unwrap_or_default();
    history.events.push_back(Event {
        sequence,
        target: target.id.clone(),
        attempt,
        step,
        message,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        log_tail,
        leftovers,
        authentication: metadata.authentication,
        host_id: metadata.host_id,
        session_id: metadata.session_id,
        failure,
    });
    batch.changed.send_replace(sequence);
}

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub use crate::lifecycle::Activity;

impl Bootstrap {
    /// Admit an adapter lifetime; it must retire when the component is turned off.
    /// # Errors
    /// Refuses admission while stopping or off.
    pub fn activity(&self) -> Result<Activity, &'static str> {
        self.lifecycle.admit()
    }
    /// Observe component lifetime changes without polling or starting a timer.
    #[must_use]
    pub fn enabled_changes(&self) -> watch::Receiver<bool> {
        self.lifecycle.subscribe()
    }
}
impl infraternal_plugin_api::ComponentPlugin for Bootstrap {
    fn descriptor(&self) -> &'static infraternal_plugin_api::PluginDescriptor {
        &crate::manifest::DESCRIPTOR
    }
    fn status(&self) -> infraternal_plugin_api::PluginStatus {
        self.lifecycle.status()
    }
    fn set_enabled(&self, enabled: bool) -> infraternal_plugin_api::PluginOperation<'_, ()> {
        Box::pin(async move {
            self.lifecycle.set_enabled(enabled).await;
            if !enabled {
                lock(&self.pending_setup).clear();
                self.backend
                    .stop()
                    .await
                    .map_err(|_| "SSH terminal retirement failed.")?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "bootstrap_proof_tests.rs"]
mod proof_tests;
