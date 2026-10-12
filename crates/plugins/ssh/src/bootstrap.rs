//! Runs independent host attempts under one global concurrency bound and a bounded replayable event log [138 H4].

use crate::{
    auth_once::{OneUseAuth, TargetAuth},
    auth_order::Authentication,
    install::{BinaryPaths, Cleanup, Installation, JoinMaterial},
    lifecycle::Lifecycle,
    model::{Destination, Event, Failure, InstallStep, MeshEvidence, Step, Target, identifier},
    probe::{CHECK_SCRIPT, Check},
    transport::{
        ConfirmationAuthority, Credentials, Input, Operation, Secret, SshSession, SshTransport,
    },
};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, watch};

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
    /// One public failure record per attempt, before cleanup changes its progress phase.
    fn record_failure(&self, _: &Target, _: Option<uuid::Uuid>, _: Step, _: &Failure) {}
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
    concurrency: Arc<Semaphore>,
    batches: Arc<Semaphore>,
    deadline: Duration,
    lifecycle: Arc<Lifecycle>,
}

impl Bootstrap {
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
            concurrency: Arc::new(Semaphore::new(crate::manifest::CONCURRENT_HOSTS)),
            batches: Arc::new(Semaphore::new(crate::manifest::CONCURRENT_BATCHES)),
            deadline: Duration::from_secs(crate::manifest::ATTEMPT_SECONDS),
            lifecycle: Lifecycle::new(),
        }
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
        let started = Instant::now();
        let mut resources = AttemptResources::default();
        let cancelled = Failure::install("Host installation was cancelled.");
        // Hold the admission slot through rollback too: failed hosts must not
        // create another eight live SSH children while the next hosts install.
        // Queued plaintext never waits behind the full 180-second install limit.
        // It belongs to this future, not HostState, and drops on timeout/cancellation.
        let queue_limit = auth_once.as_ref().map(OneUseAuth::remaining);
        let admission = if *cancel.borrow() {
            Err(cancelled.clone())
        } else {
            tokio::select! {
                _ = cancel.changed() => Err(cancelled.clone()),
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
            tokio::select! {
                _ = cancel.changed() => Err(cancelled),
                result = tokio::time::timeout(self.deadline, self.run(&batch, &target, attempt, started, &mut resources, auth_once)) => result.unwrap_or_else(|_| Err(Failure::install("Host installation exceeded its time limit."))),
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
            if let Some(host) = resources.host {
                let _ = tokio::time::timeout(
                    Duration::from_secs(5),
                    self.backend.cleanup_sessions(&batch.authority, host),
                )
                .await;
            }
            if let Some(installation) = resources.installation {
                let cleanup =
                    tokio::time::timeout(Duration::from_secs(30), installation.rollback()).await;
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
        let mut states = lock(&batch.states);
        if let Some(state) = states.get_mut(&target.id) {
            state.running = false;
            state.failed = result.is_err();
            state.last_failure = result.as_ref().err().cloned();
        }
        // Keep state and completion event ordered: retry after failed cannot race
        // the final event from its predecessor.
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

    #[allow(
        clippy::too_many_lines,
        reason = "Keep ordered bootstrap steps and transaction ownership in one cancellation-safe attempt."
    )]
    async fn run(
        &self,
        batch: &BatchInner,
        target: &Target,
        attempt: u32,
        started: Instant,
        resources: &mut AttemptResources,
        auth_once: Option<OneUseAuth>,
    ) -> Result<(), Failure> {
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
        let output = session
            .run(CHECK_SCRIPT, Input::Empty)
            .await
            .map_err(|error| error.at(InstallStep::Connect))?;
        // Preserve method evidence even if the authenticated host is unsupported.
        // Public metadata only; no provider or private material enters replay state.
        if let Some(metadata) = lock(&batch.history).metadata.get_mut(&target.id) {
            metadata.authentication = session.authentication();
        }
        let check = Check::parse(&output.stdout)?;
        check.authorize_mode(target.mode)?;
        restore_previous(batch, target, attempt, started, session.clone()).await?;
        // A cold-locked CA or unsupported #78 runtime must fail here, before upload.
        let join = self
            .backend
            .invitation_with_trust(&batch.authority, target, &check, session.trust_lookup())
            .await?;
        resources.host = Some(join.host);
        if let Some(metadata) = lock(&batch.history).metadata.get_mut(&target.id) {
            metadata.host_id = Some(join.host);
        }
        resources.installation = Some(Installation::new(session, target, &join)?);
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
        transaction
            .stage(self.binaries.get(check.architecture))
            .await
            .map_err(|mut error| {
                if error.message == "The matching static infraternal binary is unavailable." {
                    error.missing_binary = Some(Box::new(crate::model::MissingBinary {
                        architecture: match check.architecture {
                            crate::probe::Architecture::X86_64 => "x86_64",
                            crate::probe::Architecture::Aarch64 => "aarch64",
                        },
                        path: self.binaries.get(check.architecture).display().to_string(),
                    }));
                }
                error
            })?;
        transaction.enroll_and_start(&join).await?;
        drop(join); // Capability plaintext is erased immediately after its stdin handoff.
        if !transaction.enable_linger().await? {
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
        emit(
            batch,
            target,
            attempt,
            Step::Facts,
            "Waiting for authenticated host facts.",
            started,
            None,
        );
        self.backend.connected_facts(&batch.authority, host).await?;
        emit(
            batch,
            target,
            attempt,
            Step::Connect,
            "Checking a terminal through the infraternal agent.",
            started,
            None,
        );
        self.backend.terminal_canary(&batch.authority, host).await?;
        transaction.commit().await?;
        // This hook releases transient bookkeeping after the durable commit.
        // A housekeeping failure must never revoke an installed, proven host.
        let _ = self.backend.completed(&batch.authority, host).await;
        Ok(())
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
}

struct HostState {
    target: Target,
    attempt: u32,
    running: bool,
    failed: bool,
    cleanup: Option<Cleanup>,
    last_failure: Option<Failure>,
}
/// Shares history's lock: emit must not acquire `HostState` while completion holds
/// it to order retries. Exactly one current metadata row per bounded target.
#[derive(Clone, Copy, Default)]
struct HostMetadata {
    attempt: u32,
    authentication: Option<Authentication>,
    host_id: Option<uuid::Uuid>,
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
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Socket lifetime cancels work; tasks retain state only until cleanup finishes.
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
        self.inner.cancel.send_replace(true);
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
        authentication: metadata.authentication,
        host_id: metadata.host_id,
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
            Ok(())
        })
    }
}
