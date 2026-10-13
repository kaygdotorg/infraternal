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

/// Trusted request authority stays in memory and is never Debug or serialized.
/// Browser enrollment must recheck this exact session atomically, not owner id alone.
pub struct Authority {
    pub owner: String,
    /// Nonsecret batch identity lets backends retire only their own attempt authority.
    pub batch: uuid::Uuid,
    session: Option<Secret>,
}
impl Authority {
    /// The opaque live cookie is available only to trusted backend implementations.
    #[must_use]
    pub fn session(&self) -> Option<&Secret> {
        self.session.as_ref()
    }
}

/// #78 owns enrollment, CA state, authenticated online status, facts and terminal routing.
/// Implementations must recheck this exact live session before new work and never treat token redemption as online proof.
/// Invitation issuance must serialize by host and associate authority with this batch.
/// `failed` retires only this batch's new invitation/certificate, even after logout;
/// it must preserve prior enrolled authority and never invalidate another batch.
pub trait Backend: Send + Sync {
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
    fn invitation<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
    ) -> Operation<'a, JoinMaterial>;
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
    /// Record explicit earlier-attempt recovery using only public coordinates.
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
        };
        let runner = self.clone();
        tokio::spawn(async move {
            let _activity = activity;
            let _permit = permit;
            runner.resume_setup(authority, host, saved).await;
        });
        Ok(())
    }

    async fn resume_setup(&self, authority: Authority, host: uuid::Uuid, saved: SetupAttempt) {
        use crate::setup::{Stage, State};
        let mut enabled = self.enabled_changes();
        let work = async {
            self.setup
                .emit(&authority.owner, host, Stage::Install, State::Running, None)?;
            let channel = saved.installation.resume_session(saved.session_id).await?;
            self.backend
                .publish_terminal(
                    &authority,
                    host,
                    saved.session_id,
                    channel,
                    saved.installation.ssh_session(),
                )
                .await?;
            let join = self.backend.reissue_invitation(&authority, host).await?;
            saved
                .installation
                .restart_setup(&saved.binary, &join)
                .await?;
            drop(join);
            for stage in [Stage::Install, Stage::Join, Stage::Start] {
                self.setup
                    .emit(&authority.owner, host, stage, State::Done, None)?;
            }
            self.setup
                .emit(&authority.owner, host, Stage::Ready, State::Running, None)?;
            self.complete_setup(&authority, host, &saved.installation, true)
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
            self.backend
                .record_failure(&saved.target, Some(host), Step::Install, failure);
            let _ = self.setup.emit(
                &authority.owner,
                host,
                setup_failure_stage(failure),
                State::Failed,
                Some(failure),
            );
        }
        let mut pending = lock(&self.pending_setup);
        if result.is_ok() {
            pending.remove(&host);
        } else if let Some(saved) = pending.get_mut(&host) {
            saved.running = false;
        }
    }

    /// Prepare configured public payloads without blocking HTTP admission.
    /// Missing files/tools retain the existing actionable per-host refusal/raw path.
    pub async fn prepare_payloads(&self) {
        let Ok(_activity) = self.activity() else {
            return;
        };
        for architecture in [
            crate::probe::Architecture::X86_64,
            crate::probe::Architecture::Aarch64,
        ] {
            let path = self.binaries.get(architecture);
            if crate::payload::digest(path).await.is_ok() {
                for codec in [
                    crate::payload_encoding::Codec::Zstd,
                    crate::payload_encoding::Codec::Gzip,
                ] {
                    let _ = crate::payload_encoding::encoded(path, codec).await;
                }
            }
        }
    }
    /// Warm public encodings after the listener is bound; component-off cancels
    /// the owned compressors and waits for their existing activity lease.
    pub fn warm_payloads(&self) {
        let bootstrap = self.clone();
        let mut enabled = self.enabled_changes();
        tokio::spawn(async move {
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
            },
            targets,
            credential,
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
        tokio::spawn(async move {
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
                let stage = setup_failure_stage(failure);
                let _ = self.setup.emit(
                    &batch.authority.owner,
                    host,
                    stage,
                    crate::setup::State::Failed,
                    Some(failure),
                );
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
                            "Automatic cleanup could not finish. Retry when SSH is available.",
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
                let mut pending = lock(&self.pending_setup);
                if result.is_ok() {
                    pending.remove(&host);
                } else if let Some(saved) = pending.get_mut(&host) {
                    saved.running = false;
                }
            }
            return;
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

    /// Resolve before the transaction exists, so a failed trust check cannot upload.
    async fn payload(
        &self,
        batch: &BatchInner,
        target: &Target,
        attempt: u32,
        started: Instant,
        architecture: crate::probe::Architecture,
    ) -> Result<std::path::PathBuf, Failure> {
        if let Some(source) = &self.payloads {
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
            // Preserve the named step before the enclosing attempt deadline;
            // stalled buckets must not become a generic installation failure.
            let budget = self
                .deadline
                .saturating_sub(started.elapsed())
                .saturating_sub(Duration::from_secs(1))
                .min(Duration::from_secs(60));
            let step = match architecture {
                crate::probe::Architecture::Aarch64 => crate::model::InstallStep::GetArm64Binary,
                crate::probe::Architecture::X86_64 => crate::model::InstallStep::GetX86_64Binary,
            };
            tokio::time::timeout(budget, source.get(architecture))
                .await
                .map_err(|_| {
                    Failure::install("the builds host did not respond in time.").at(step)
                })?
        } else {
            Ok(self.binaries.get(architecture).to_owned())
        }
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
        // Bound one setup allocation to each admitted worker. Sharing the poll
        // boundary keeps the large state machine out of its cancellation wrapper.
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
            let (output, checked) = if self.backend.early_terminal() {
                session.check_stream(&script).await?
            } else {
                let output = session
                    .run(&script, Input::Empty)
                    .await
                    .map_err(|error| previous_attempt::classify(error.at(InstallStep::Connect)))?;
                (output, None)
            };
            // Automatic sign-in selects its authenticated adapter during the
            // read-only check; query bridge support after that selection.
            let early = self.backend.early_terminal() && session.session_bridge();
            // Preserve method evidence even if the authenticated host is unsupported.
            // Public metadata only; no provider or private material enters replay state.
            if let Some(metadata) = lock(&batch.history).metadata.get_mut(&target.id) {
                metadata.authentication = session.authentication();
            }
            let (check, previous) = previous_attempt::parse_check(&output.stdout)?;
            check.authorize_mode(target.mode)?;
            restore_previous(batch, target, attempt, started, session.clone()).await?;
            if let Some(previous) = previous {
                self.await_start_fresh(
                    batch,
                    target,
                    attempt,
                    started,
                    session.as_ref(),
                    &previous,
                )
                .await?;
            }
            // A cold-locked CA or unsupported #78 runtime must fail here, before upload.
            // Durable publication can outlive a cancelled acknowledgement. Bind
            // cleanup ownership before the backend can enqueue its commit.
            let mut register = |host| {
                resources.host = Some(host);
                Ok(())
            };
            let join = self
                .backend
                .invitation_registered(
                    &batch.authority,
                    target,
                    &check,
                    session.trust_lookup(),
                    &mut register,
                )
                .await?;
            resources.host = Some(join.host);
            if let Some(metadata) = lock(&batch.history).metadata.get_mut(&target.id) {
                metadata.host_id = Some(join.host);
            }
            // Resolve through the trusted payload source before either early shell or setup.
            let payload = self
                .payload(batch, target, attempt, started, check.architecture)
                .await?;
            resources.installation = Some(Installation::new(session.clone(), target, &join)?);
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
                    let (session_id, channel) =
                        transaction.stage_session_on(&payload, checked).await?;
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
                            session_id,
                            installation: transaction.clone(),
                            binary: payload.clone(),
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
                    tokio::select! {
                        biased;
                        _ = self.backend.setup_cancelled(join.host) => Err(Failure::unsupported("The host setup is no longer authorized.")),
                        result = transaction.setup(&join) => result,
                    }
                } else {
                    transaction.stage_and_setup(&payload, &join).await
                }
            };
            let linger = setup.await.map_err(|mut error| {
                if error.message == "The matching static infraternal binary is unavailable." {
                    error.missing_binary = Some(Box::new(crate::model::MissingBinary {
                        architecture: match check.architecture {
                            crate::probe::Architecture::X86_64 => "x86_64",
                            crate::probe::Architecture::Aarch64 => "aarch64",
                        },
                        path: payload.display().to_string(),
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
                tokio::try_join!(
                    async {
                        self.backend.connected_facts(authority, host).await?;
                        self.backend.terminal_canary(authority, host).await?;
                        release.send(()).map_err(|()| {
                            Failure::install("The host commit command ended before terminal proof.")
                        })
                    },
                    installation.commit_after(approved),
                )?;
                // Completion discharges durable retirement only after proof and commit.
                self.backend.completed(authority, host).await
            };
            if published {
                tokio::select! {
                    biased;
                    _ = self.backend.setup_cancelled(host) => Err(Failure::unsupported("The host setup is no longer authorized.")),
                    result = proof => result,
                }
            } else {
                proof.await
            }
        })
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
                    .host_key_challenge
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
    ) -> Result<(), Failure> {
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
            "Restoring the previous host attempt before retry.",
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
    published: bool,
}

// Retain only failed live-session transaction coordinates; success removes the
// record so its SSH master and ephemeral authentication material can retire.
#[derive(Clone)]
struct SetupAttempt {
    owner: String,
    batch: uuid::Uuid,
    target: Target,
    session_id: uuid::Uuid,
    installation: Installation,
    binary: std::path::PathBuf,
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
