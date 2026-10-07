//! Runs independent host attempts under one global concurrency bound and a bounded replayable event log [138 H4].

use crate::{
    install::{BinaryPaths, Cleanup, Installation, JoinMaterial},
    model::{Destination, Event, Failure, MeshEvidence, Step, Target, identifier},
    probe::{CHECK_SCRIPT, Check},
    transport::{Credentials, Input, Operation, Secret, SshSession, SshTransport},
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
    fn failed<'a>(&'a self, authority: &'a Authority, host: uuid::Uuid) -> Operation<'a, ()>;
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
            concurrency: Arc::new(Semaphore::new(8)),
            batches: Arc::new(Semaphore::new(16)),
            deadline: Duration::from_secs(180),
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
        )
    }

    fn start_authority(
        &self,
        authority: Authority,
        targets: Vec<Target>,
        credential: Option<String>,
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
                    },
                )
                .is_some()
            {
                return Err(Failure::unsupported(
                    "Each selected host needs a unique identifier.",
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
                }),
                changed,
                cancel,
                _permit: permit,
            }),
        };
        let ids: Vec<_> = lock(&batch.inner.states).keys().cloned().collect();
        for id in ids {
            self.schedule(batch.inner.clone(), &id)?;
        }
        Ok(batch)
    }

    fn schedule(&self, batch: Arc<BatchInner>, id: &str) -> Result<(), Failure> {
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
            state.attempt += 1;
            (state.target.clone(), state.attempt)
        };
        let runner = self.clone();
        tokio::spawn(async move {
            runner.attempt(batch, target, attempt).await;
        });
        Ok(())
    }

    async fn attempt(&self, batch: Arc<BatchInner>, target: Target, attempt: u32) {
        let mut cancel = batch.cancel.subscribe();
        let started = Instant::now();
        let mut installation = None;
        let mut host = None;
        let cancelled = Failure::install("Host installation was cancelled.");
        // Hold the admission slot through rollback too: failed hosts must not
        // create another eight live SSH children while the next hosts install.
        let admission = if *cancel.borrow() {
            Err(cancelled.clone())
        } else {
            tokio::select! {
                _ = cancel.changed() => Err(cancelled.clone()),
                permit = self.concurrency.clone().acquire_owned() => permit.map_err(|_| Failure::install("Bootstrap is shutting down.")),
            }
        };
        let result = if admission.is_err() || *cancel.borrow() {
            Err(cancelled)
        } else {
            tokio::select! {
                _ = cancel.changed() => Err(cancelled),
                result = tokio::time::timeout(self.deadline, self.run(&batch, &target, attempt, started, &mut installation, &mut host)) => result.unwrap_or_else(|_| Err(Failure::install("Host installation exceeded its time limit."))),
            }
        };
        if result.is_err() {
            if let Some(installation) = installation {
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
            if let Some(host) = host {
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
    async fn run(
        &self,
        batch: &BatchInner,
        target: &Target,
        attempt: u32,
        started: Instant,
        installation: &mut Option<Installation>,
        host: &mut Option<uuid::Uuid>,
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
        let resolved = self
            .backend
            .resolve(
                &batch.authority,
                target,
                target.credential.as_deref().or(batch.credential.as_deref()),
            )
            .await?;
        let session = self
            .transport
            .open(resolved.destination, resolved.credentials, resolved.mesh)
            .await?;
        let output = session.run(CHECK_SCRIPT, Input::Empty).await?;
        let check = Check::parse(&output.stdout)?;
        check.authorize_mode(target.mode)?;
        restore_previous(batch, target, attempt, started, session.clone()).await?;
        // A cold-locked CA or unsupported #78 runtime must fail here, before upload.
        let join = self
            .backend
            .invitation(&batch.authority, target, &check)
            .await?;
        *host = Some(join.host);
        *installation = Some(Installation::new(session, target, &join)?);
        let transaction = installation
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
            .await?;
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
        let host =
            host.ok_or_else(|| Failure::install("The enrolled host identity is unavailable."))?;
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
        Ok(())
    }

    /// Retry one failed host, keeping its trusted host identity in the backend.
    /// # Errors
    /// Refuses a foreign batch owner, unknown/running/successful host or excessive attempts.
    pub fn retry(&self, batch: &Batch, owner: &str, id: &str) -> Result<(), Failure> {
        if batch.inner.authority.owner != owner || *batch.inner.cancel.borrow() {
            return Err(Failure::unsupported("The bootstrap batch is unavailable."));
        }
        self.schedule(batch.inner.clone(), id)
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

struct HostState {
    target: Target,
    attempt: u32,
    running: bool,
    failed: bool,
    cleanup: Option<Cleanup>,
}
struct History {
    sequence: u64,
    events: VecDeque<Event>,
}
struct BatchInner {
    authority: Authority,
    credential: Option<String>,
    states: Mutex<HashMap<String, HostState>>,
    history: Mutex<History>,
    changed: watch::Sender<u64>,
    cancel: watch::Sender<bool>,
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
    history.events.push_back(Event {
        sequence,
        target: target.id.clone(),
        attempt,
        step,
        message,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        log_tail,
        failure,
    });
    batch.changed.send_replace(sequence);
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
