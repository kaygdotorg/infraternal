//! Drives one root upgrade of a host end to end (D274, D376, #399; J415 R1–R7).
//!
//! [`Promotions`] is what the browser's privilege endpoints call. It owns no
//! authority of its own: every step is a write on the promotion's row (see
//! `crate::enrollment::promotion`), checked by the database, and the host
//! side is the rootless infraternal agent's `privilege.*` actions
//! (`crate::host_privilege`).
//!
//! The order, and what each failure leaves:
//!
//! | Step | On failure |
//! |---|---|
//! | probe, then begin: the row is bound to the live rootless certificate and link (R7) | nothing happened |
//! | finish: the try is reserved in one write (B2), the password goes to PAM once | `wrong` / `failed`; the try counts if typed |
//! | the relay connects; the root install's rollback is armed first (R4) | the relay puts the host back by itself |
//! | stage, join, activate, start the root unit | rollback over the relay, then the relay's own |
//! | the successor connects on its private lane and proves `executionUid=0` (R2) | rollback; the abandoned successor uninstalls itself (R5) |
//! | the install commits, then the relay's `Commit` | as above |
//! | the handover transaction (R3) | abandoned: the successor uninstalls itself (R5) |
//! | the new root agent retires the rootless install (R5 outbox) | retried on every connection |
//!
//! Before each host-changing step it checks that the rootless link is still
//! the one the promotion was bound to; a replaced link abandons (R7).
use crate::{
    enrollment::{
        EnrollmentStore,
        promotion::{Bound, Method, PromotionError, Settled},
    },
    host_activity::{self, Kind},
    host_privilege::{self, AgentPump, Elevation, Probe, Way},
    remote_http::InvitationIssuer,
    remote_runtime::{RemoteHosts, TerminalPromotionGuard},
};
use infraternal_plugin_ssh::{
    install::{Installation, JoinMaterial, PayloadSource},
    model::{InstallMode, Target, TargetAddress},
    probe::Architecture,
    relay_session::RelaySession,
    transport::Secret,
};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use uuid::Uuid;
use zeroize::Zeroize as _;

/// How long a relay step may run (the payload upload is the longest).
const STEP_BOUND: Duration = Duration::from_mins(5);
/// How long the relay gets to say Ready after the elevation.
const READY_BOUND: Duration = Duration::from_secs(20);
/// How long the successor gets to connect once its unit started.
const SUCCESSOR_BOUND: Duration = Duration::from_secs(90);

/// Where one promotion is, for the browser's progress view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Becoming root (the password is with PAM).
    Checking,
    /// Root reached; the relay is up.
    Elevated,
    /// The root install is staged and joined.
    Installing,
    /// The root unit started; waiting for its proof.
    Starting,
    /// The handover is committing.
    Handover,
    /// The host runs the root infraternal agent.
    Done,
    /// It failed and the host was put back as it was.
    RolledBack,
}

impl Stage {
    /// The word the browser shows a step for.
    const fn word(self) -> &'static str {
        match self {
            Self::Checking => "checking",
            Self::Elevated => "elevated",
            Self::Installing => "installing",
            Self::Starting => "starting",
            Self::Handover => "handover",
            Self::Done => "done",
            Self::RolledBack => "rolled-back",
        }
    }
}

/// One host's root upgrades, driven from the browser's endpoints.
#[derive(Clone)]
pub(crate) struct Promotions {
    store: EnrollmentStore,
    pool: SqlitePool,
    hosts: RemoteHosts,
    issuer: InvitationIssuer,
    payload: Arc<dyn PayloadSource>,
    /// This server's binary, which carries the relay channel helper.
    exe: PathBuf,
    /// A private (0700) directory for the helpers' sockets.
    scratch: PathBuf,
    /// Progress of the promotions this process drives, by attempt.
    progress: Arc<Mutex<HashMap<Uuid, (Uuid, Stage)>>>,
    /// Test only: signal after reserving the try, then wait for the test to release `finish`.
    #[cfg(test)]
    after_reserve: Arc<Mutex<Option<AfterReserveGate>>>,
}

/// The test-only signal and release pair around an already reserved promotion.
#[cfg(test)]
struct AfterReserveGate {
    reserved: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

/// A refused request, as the HTTP layer reports it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Not allowed (or not found): 403.
    Forbidden,
    /// Another promotion of this host is live: 409.
    Busy,
    /// The host or the server can't do it now: 503.
    Unavailable,
}

impl From<PromotionError> for Refused {
    fn from(error: PromotionError) -> Self {
        match error {
            PromotionError::Busy => Self::Busy,
            PromotionError::Storage(_) => Self::Unavailable,
            PromotionError::Denied | PromotionError::Locked { .. } => Self::Forbidden,
        }
    }
}

/// The method a probed way records (and whose account the 2-try rule counts).
const fn method(way: Way) -> Method {
    match way {
        Way::SudoNoPassword => Method::SudoNoPassword,
        Way::Sudo => Method::Sudo,
        Way::Doas => Method::Doas,
        Way::Su => Method::Su,
    }
}

impl Promotions {
    /// Build the driver. `scratch` is created 0700 if missing.
    ///
    /// # Errors
    /// The scratch directory can't be made private.
    pub(crate) fn new(
        store: EnrollmentStore,
        pool: SqlitePool,
        hosts: RemoteHosts,
        issuer: InvitationIssuer,
        payload: Arc<dyn PayloadSource>,
        exe: PathBuf,
        scratch: PathBuf,
    ) -> std::io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&scratch)?;
        std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            store,
            pool,
            hosts,
            issuer,
            payload,
            exe,
            scratch,
            progress: Arc::default(),
            #[cfg(test)]
            after_reserve: Arc::default(),
        })
    }

    /// Whether the session is a host admin of a live rootless `host`, inside
    /// its admin window. A read for probe and status only; every write
    /// rechecks this in its own statement.
    async fn admin(&self, session_hash: &str, host: Uuid, now: i64) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM remote_hosts h JOIN sessions s ON s.user_id = h.owner_id \
             JOIN users u ON u.id = s.user_id WHERE h.id = ? AND h.revoked_at IS NULL \
             AND h.mode IN ('rootless', 'rootful') \
             AND s.token_hash = ? AND s.unlocked = 1 AND s.expires > ? AND u.owner = 1 \
             AND s.fresh <= ? AND ? - s.fresh < ?)",
        )
        .bind(host.as_bytes().as_slice())
        .bind(session_hash)
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(infraternal_plugin_api::ADMIN_WINDOW_SECONDS)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false)
    }

    /// `probe`: how this person would become root on `host`, and whether
    /// the 2-try wait applies. Changes nothing.
    pub(crate) async fn probe(
        &self,
        session_hash: &str,
        host: Uuid,
        now: i64,
    ) -> Result<Value, Refused> {
        if !self.admin(session_hash, host, now).await {
            return Err(Refused::Forbidden);
        }
        let (agent, ..) = self.hosts.binding(host).await.ok_or(Refused::Unavailable)?;
        if let Some(refusal) = refusal_for_os(self.host_os(&agent).await.as_deref()) {
            return Ok(refusal);
        }
        match host_privilege::probe(&agent)
            .await
            .map_err(|_| Refused::Unavailable)?
        {
            Probe::Full => Ok(json!({"full": true})),
            Probe::None => Ok(json!({"full": false, "method": null, "denied": true})),
            Probe::Way { way, denied } => {
                let retry_after = self.store.retry_after(host, method(way), now).await?;
                Ok(json!({
                    "full": false,
                    "method": way.word(),
                    "denied": denied,
                    "retryAfter": retry_after,
                }))
            }
        }
    }

    /// `begin`: open a promotion of `host` bound to its live rootless link
    /// (R7), and, unless the way needs no password, get the one-use seal key.
    pub(crate) async fn begin(
        &self,
        session_hash: &str,
        host: Uuid,
        now: i64,
    ) -> Result<Value, Refused> {
        // J569 P3-3: only a host admin inside the admin window gets past
        // here. Anyone else learns nothing about the host (not its terminals,
        // its way in or its 2-try wait), the host is not called, and no
        // activity row is written in their name. The insert rechecks this.
        if !self.admin(session_hash, host, now).await {
            return Err(Refused::Forbidden);
        }
        // A crashed driver's leftovers end before anything new begins.
        let _ = self.store.sweep_promotions(now, false).await;
        let (agent, uid, fingerprint, generation) =
            self.hosts.binding(host).await.ok_or(Refused::Unavailable)?;
        // A Mac keeps its rootless agent: nothing here turns it into root.
        if let Some(refusal) = refusal_for_os(self.host_os(&agent).await.as_deref()) {
            return Ok(refusal);
        }
        // Until running terminals can be adopted by the person's own process
        // (J415 R6, not built yet), an upgrade with open terminals would
        // leave them unreachable once the rootless agent is retired. Refuse
        // instead, so nothing is ever orphaned: "Close the open terminals
        // on this host first" (J410's slice-1 rule).
        let open = match &*agent.session_inventory().borrow() {
            crate::embedded::SessionInventoryState::Available(sessions) => sessions.len(),
            crate::embedded::SessionInventoryState::Pending
            | crate::embedded::SessionInventoryState::Unavailable => {
                return Err(Refused::Unavailable);
            }
        };
        if open > 0 {
            return Ok(json!({"outcome": "terminals", "open": open}));
        }
        let way = match host_privilege::probe(&agent)
            .await
            .map_err(|_| Refused::Unavailable)?
        {
            Probe::Way { way, .. } => way,
            Probe::Full | Probe::None => return Err(Refused::Forbidden),
        };
        let attempt = Uuid::new_v4();
        let begun = self
            .store
            .begin_promotion(
                session_hash,
                host,
                attempt,
                method(way),
                Bound {
                    from_uid: uid,
                    from_fingerprint: fingerprint,
                    link_generation: generation,
                },
                now,
            )
            .await;
        if let Err(PromotionError::Locked { retry_after }) = begun {
            let person: Option<String> =
                sqlx::query_scalar("SELECT user_id FROM sessions WHERE token_hash = ?")
                    .bind(session_hash)
                    .fetch_optional(&self.pool)
                    .await
                    .ok()
                    .flatten();
            if let Some(person) = person {
                let _ = self
                    .record(host, &person, Kind::Locked, Some(way), None, None, now)
                    .await;
            }
            return Ok(
                json!({"outcome": "locked", "method": way.word(), "retryAfter": retry_after}),
            );
        }
        begun?;
        let key = if way == Way::SudoNoPassword {
            None
        } else {
            let Ok(key) = host_privilege::seal_key(&agent, attempt).await else {
                let _ = self.store.abandon_promotion(attempt, now).await;
                return Err(Refused::Unavailable);
            };
            Some(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                key,
            ))
        };
        Ok(json!({
            "attempt": attempt.simple().to_string(),
            "method": way.word(),
            "sealKey": key,
            "expires": now + crate::enrollment::promotion::LIFETIME,
        }))
    }

    /// `finish`: forward the sealed password (none for passwordless sudo)
    /// and become root once. On success the install runs in the
    /// background; [`Self::status`] follows it.
    pub(crate) async fn finish(
        &self,
        session_hash: &str,
        attempt: Uuid,
        sealed: Option<String>,
        now: i64,
    ) -> Result<Value, Refused> {
        // B2: the 2-try check and this try are one write.
        let reserved = self
            .store
            .reserve_try(session_hash, attempt, sealed.is_some(), now)
            .await;
        let (host, method) = match reserved {
            Ok(reserved) => reserved,
            Err(PromotionError::Locked { retry_after }) => {
                return Ok(json!({"outcome": "locked", "retryAfter": retry_after}));
            }
            Err(error) => return Err(error.into()),
        };
        // J569 P2-1: from here on the try is reserved, so the rest must run
        // to its end even when this request is dropped (the 2-minute request
        // deadline, a closed tab). It runs as its own task: dropping the
        // handle detaches it, and it still settles the row and ends the host
        // side, instead of leaving the row `elevating` (409 Busy for up to 15
        // minutes) for the sweeper to count as a typed try.
        let driver = self.clone();
        tokio::spawn(async move {
            driver
                .finish_reserved(host, method, attempt, sealed, now)
                .await
        })
        .await
        .map_err(|_| Refused::Unavailable)?
    }

    /// The part of [`Self::finish`] after the try was reserved: become root
    /// once, then settle the try, record it and end the host side.
    async fn finish_reserved(
        &self,
        host: Uuid,
        method: Method,
        attempt: Uuid,
        mut sealed: Option<String>,
        now: i64,
    ) -> Result<Value, Refused> {
        #[cfg(test)]
        {
            let gate = self
                .after_reserve
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(gate) = gate {
                let _ = gate.reserved.send(());
                let _ = gate.release.await;
            }
        }
        let way = match method {
            Method::SudoNoPassword => Way::SudoNoPassword,
            Method::Sudo => Way::Sudo,
            Method::Doas => Way::Doas,
            Method::Su => Way::Su,
        };
        let person = self.person(attempt).await.unwrap_or_default();
        let _ = self
            .record(
                host,
                &person,
                Kind::Attempt,
                Some(way),
                Some(attempt),
                None,
                now,
            )
            .await;
        // R7: the rootless link must still be the one this promotion bound.
        let Some((agent, bound_generation)) = self.bound_agent(host, attempt).await else {
            let _ = self
                .store
                .settle_try(attempt, Settled::Failed { typed: false }, now)
                .await;
            sealed.zeroize();
            return Ok(json!({"outcome": "offline"}));
        };
        let Ok(terminal_admission) = self.hosts.block_terminal_opens(host).await else {
            let _ = self
                .store
                .settle_try(attempt, Settled::Failed { typed: false }, now)
                .await;
            sealed.zeroize();
            return Err(Refused::Unavailable);
        };
        self.set(attempt, bound_generation, Stage::Checking);
        let Ok(digest) = self.digest(&agent).await else {
            let _ = self
                .store
                .settle_try(attempt, Settled::Failed { typed: false }, now)
                .await;
            sealed.zeroize();
            return Ok(json!({"outcome": "failed"}));
        };
        let result =
            host_privilege::elevate(&agent, host, attempt, way, sealed.as_deref(), &digest).await;
        sealed.zeroize();
        let now = crate::runtime::unix_seconds().unwrap_or(now);
        let (outcome, typed) = match result {
            Ok(answer) => answer,
            // No answer at all: the password may have reached PAM (B2).
            Err(_) => (Elevation::Timeout, way != Way::SudoNoPassword),
        };
        let word = match outcome {
            Elevation::Started => {
                self.store.settle_try(attempt, Settled::Rooted, now).await?;
                self.set(attempt, bound_generation, Stage::Elevated);
                let driver = self.clone();
                tokio::spawn(async move {
                    driver
                        .install(host, attempt, agent, bound_generation, terminal_admission)
                        .await;
                });
                return Ok(json!({"outcome": "started", "method": way.word()}));
            }
            Elevation::Wrong => {
                self.store.settle_try(attempt, Settled::Wrong, now).await?;
                let _ = self
                    .record(
                        host,
                        &person,
                        Kind::Wrong,
                        Some(way),
                        Some(attempt),
                        None,
                        now,
                    )
                    .await;
                "wrong"
            }
            Elevation::Denied => "denied",
            Elevation::Mismatch => "mismatch",
            Elevation::Timeout => "timeout",
            Elevation::Busy => "busy",
            Elevation::RootShell => "rootshell",
            Elevation::Failed => "failed",
        };
        if outcome != Elevation::Wrong {
            // A mismatch reached root with the right password (J465 P3-2).
            let settled = if outcome == Elevation::Mismatch {
                Settled::Mismatch
            } else {
                Settled::Failed { typed }
            };
            let _ = self.store.settle_try(attempt, settled, now).await;
            let reason = if outcome == Elevation::Denied {
                Kind::Denied
            } else {
                Kind::Failed
            };
            let _ = self
                .record(
                    host,
                    &person,
                    reason,
                    Some(way),
                    Some(attempt),
                    Some(word),
                    now,
                )
                .await;
        }
        host_privilege::end(&agent, attempt).await;
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&attempt);
        let retry_after = self
            .store
            .retry_after(host, method, now)
            .await
            .ok()
            .flatten();
        Ok(json!({"outcome": word, "method": way.word(), "retryAfter": retry_after}))
    }

    /// `status`: where a promotion this person began is.
    pub(crate) async fn status(
        &self,
        session_hash: &str,
        attempt: Uuid,
        now: i64,
    ) -> Result<Value, Refused> {
        let row: Option<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT p.state, p.host_id FROM remote_host_promotions p JOIN sessions s ON s.user_id = p.person \
             WHERE p.attempt = ? AND s.token_hash = ? AND s.unlocked = 1 AND s.expires > ?",
        )
        .bind(attempt.as_bytes().as_slice())
        .bind(session_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| Refused::Unavailable)?;
        let (recorded, _) = row.ok_or(Refused::Forbidden)?;
        let stage = self
            .progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&attempt)
            .map(|(_, stage)| *stage);
        let step = match (recorded.as_str(), stage) {
            ("handed_over", _) => Stage::Done.word(),
            ("rolled_back" | "abandoned", _) => Stage::RolledBack.word(),
            (_, Some(live)) => live.word(),
            _ => recorded.as_str(),
        };
        Ok(json!({"state": recorded, "step": step}))
    }

    /// The live rootless link of `host`, if it is still the one `attempt`
    /// was bound to (R7), with that generation.
    async fn bound_agent(
        &self,
        host: Uuid,
        attempt: Uuid,
    ) -> Option<(crate::embedded::EmbeddedAgent, Uuid)> {
        let bound: Vec<u8> = sqlx::query_scalar(
            "SELECT link_generation FROM remote_host_promotions WHERE attempt = ?",
        )
        .bind(attempt.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .ok()??;
        let bound = Uuid::from_slice(&bound).ok()?;
        let (agent, _, _, generation) = self.hosts.binding(host).await?;
        (generation == bound).then_some((agent, bound))
    }

    /// The promotion's person (for the activity log).
    async fn person(&self, attempt: Uuid) -> Option<String> {
        sqlx::query_scalar("SELECT person FROM remote_host_promotions WHERE attempt = ?")
            .bind(attempt.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await
            .ok()?
    }

    /// The SHA-256 of this server's payload for the host's architecture:
    /// the relay binary the host runs must match it.
    async fn digest(&self, agent: &crate::embedded::EmbeddedAgent) -> Result<String, ()> {
        use std::fmt::Write as _;
        let architecture = self.architecture(agent).await?;
        let path = self.payload.get(architecture).await.map_err(|_| ())?;
        let bytes = tokio::fs::read(&path).await.map_err(|_| ())?;
        Ok(sha2::Sha256::digest(&bytes)
            .iter()
            .fold(String::with_capacity(64), |mut text, byte| {
                let _ = write!(text, "{byte:02x}");
                text
            }))
    }

    /// The host's operating system name from its facts (`Linux`, `macOS`),
    /// or `None` when the facts can't be read.
    async fn host_os(&self, agent: &crate::embedded::EmbeddedAgent) -> Option<String> {
        let facts = tokio::time::timeout(
            Duration::from_secs(15),
            agent.call(
                "host.facts.read".into(),
                br#"{"includeLive":false}"#.to_vec(),
            ),
        )
        .await
        .ok()?
        .ok()?;
        let facts: Value = serde_json::from_slice(&facts).ok()?;
        facts["os"].as_str().map(str::to_owned)
    }

    /// The host's architecture, from its facts.
    async fn architecture(
        &self,
        agent: &crate::embedded::EmbeddedAgent,
    ) -> Result<Architecture, ()> {
        let facts = tokio::time::timeout(
            Duration::from_secs(15),
            agent.call(
                "host.facts.read".into(),
                br#"{"includeLive":false}"#.to_vec(),
            ),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        let facts: Value = serde_json::from_slice(&facts).map_err(|_| ())?;
        match facts["architecture"].as_str() {
            Some("x86_64") => Ok(Architecture::X86_64),
            Some("aarch64") => Ok(Architecture::Aarch64),
            _ => Err(()),
        }
    }

    /// Note where `attempt` is.
    fn set(&self, attempt: Uuid, generation: Uuid, stage: Stage) {
        self.progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(attempt, (generation, stage));
    }

    /// Write one activity row for `person` (a user id); a failure to log
    /// never changes the upgrade, but it is never silent either: D274 says
    /// every privileged action is recorded, so a lost row is logged for the
    /// operator (J569 P3-4).
    async fn record(
        &self,
        host: Uuid,
        person: &str,
        kind: Kind,
        way: Option<Way>,
        attempt: Option<Uuid>,
        reason: Option<&'static str>,
        now: i64,
    ) -> sqlx::Result<()> {
        host_activity::record(
            &self.pool,
            &host_activity::Entry {
                host,
                person: if person.is_empty() { "unknown" } else { person },
                kind,
                method: way.map(Way::method),
                attempt,
                reason,
            },
            now,
        )
        .await
        .inspect_err(|error| {
            tracing::error!(
                ?kind,
                ?reason,
                %error,
                "a root upgrade activity row could not be recorded"
            );
        })
    }

    /// The install, from the relay to the handover (see the module docs).
    /// Every ending writes the row; the host side cleans up by itself.
    async fn install(
        &self,
        host: Uuid,
        attempt: Uuid,
        agent: crate::embedded::EmbeddedAgent,
        generation: Uuid,
        admission: TerminalPromotionGuard,
    ) {
        let person = self.person(attempt).await.unwrap_or_default();
        // The failed step's fixed word goes to the activity log; the
        // install's own fixed failure text (never host output) goes to the
        // operator's log below, for diagnosis.
        let outcome = tokio::time::timeout(
            Duration::from_secs(
                u64::try_from(crate::enrollment::promotion::LIFETIME).unwrap_or(900),
            ),
            self.install_steps(host, attempt, &agent, generation, &admission),
        )
        .await
        .unwrap_or(Err(Ended {
            reason: "deadline",
            restored: false,
        }));
        let now = crate::runtime::unix_seconds().unwrap_or(0);
        match outcome {
            Ok(()) => {
                self.set(attempt, generation, Stage::Done);
                let _ = self
                    .record(
                        host,
                        &person,
                        Kind::Upgraded,
                        None,
                        Some(attempt),
                        None,
                        now,
                    )
                    .await;
            }
            Err(Ended { reason, restored }) => {
                // One write that bars the handover. When the host is known to
                // be as it was (nothing reached it, or the rollback was
                // verified), the row ends `rolled_back`, and a successor that
                // had joined is revoked: the rollback removed it (J569 P3-1).
                // Otherwise a joined successor is asked to uninstall itself
                // (R5); without one, the relay's own rollback and guard
                // put the host back.
                if !restored || self.store.rolled_back(attempt, now).await.is_err() {
                    let _ = self.store.abandon_promotion(attempt, now).await;
                }
                self.set(attempt, generation, Stage::RolledBack);
                let _ = self
                    .record(
                        host,
                        &person,
                        Kind::RolledBack,
                        None,
                        Some(attempt),
                        Some(reason),
                        now,
                    )
                    .await;
            }
        }
        self.hosts.successors().release(attempt);
        // The rootless link may be gone after a handover; ending is best effort.
        host_privilege::end(&agent, attempt).await;
    }

    /// The install's steps; `Err` names the step that failed (a fixed word)
    /// and whether the host is known to be back as it was.
    async fn install_steps(
        &self,
        host: Uuid,
        attempt: Uuid,
        agent: &crate::embedded::EmbeddedAgent,
        generation: Uuid,
        admission: &TerminalPromotionGuard,
    ) -> Result<(), Ended> {
        // Until the rollback is armed nothing has run on the host; after a
        // relay that was armed but did nothing yet, closing it rolls back
        // nothing. Both leave the host as it was.
        let untouched = |reason| Ended {
            reason,
            restored: true,
        };
        // A short name: Unix socket paths are capped at 108 bytes, and the
        // data directory in front of it can be long (found on the guest rig,
        // where the full attempt id pushed the helper socket past the cap).
        let directory = self.scratch.join(&attempt.simple().to_string()[..8]);
        std::fs::create_dir(&directory).map_err(|_| untouched("local"))?;
        let _cleanup = RemoveDir(directory.clone());
        let session = RelaySession::start(
            Arc::new(AgentPump {
                agent: agent.clone(),
                attempt,
            }),
            &directory,
            self.exe.clone(),
            STEP_BOUND,
            READY_BOUND,
        )
        .await
        .map_err(|_| untouched("relay"))?;
        let session = Arc::new(session);
        let target = Target {
            id: "promotion".into(),
            address: TargetAddress::Discovered("relay".into()),
            credential: None,
            mode: InstallMode::Root,
            root_consent: true,
        };
        let install = Installation::new_pending(session.clone(), &target, host)
            .map_err(|_| untouched("install"))?;
        // R4: before any step, the relay learns how to put the host back.
        if let Err(failure) = session
            .arm_rollback(install.transaction(), install.rollback_script())
            .await
        {
            session.close();
            // P3-4: the activity row takes a fixed word, never the failure's
            // sentence (its CHECK refuses one, and the row was lost).
            return Err(untouched(logged("relay", &failure)));
        }
        // J465 P1: if the relay itself dies later, the uninstall outbox rolls
        // back this exact transaction through the abandoned successor.
        self.store
            .record_install_transaction(attempt, install.transaction())
            .await
            .map_err(|_| untouched("install"))?;
        let result = self
            .run_install(
                host, attempt, agent, generation, &session, &install, admission,
            )
            .await;
        // Only this transaction's verified rollback says the host is back.
        let restored = result.is_err() && !install.committed() && install.rollback().await.is_ok();
        // Without the Commit frame, closing makes the relay roll back too.
        session.close();
        result.map_err(|reason| Ended { reason, restored })
    }

    /// Stage, join, start, prove, commit, hand over.
    async fn run_install(
        &self,
        host: Uuid,
        attempt: Uuid,
        agent: &crate::embedded::EmbeddedAgent,
        generation: Uuid,
        session: &Arc<RelaySession>,
        install: &Installation,
        admission: &TerminalPromotionGuard,
    ) -> Result<(), &'static str> {
        let architecture = self.architecture(agent).await.map_err(|()| "facts")?;
        let binary = self
            .payload
            .get(architecture)
            .await
            .map_err(|_| "payload")?;
        self.still_bound(host, generation).await?;
        let key_digest = install
            .prepare_join_key(&binary, self.issuer.origin())
            .await
            .map_err(|failure| logged("stage", &failure))?;
        self.set(attempt, generation, Stage::Installing);
        let now = crate::runtime::unix_seconds().map_err(|_| "clock")?;
        let mut invitation = self
            .issuer
            .issue_successor(attempt, host, &key_digest, now)
            .await
            .map_err(|_| "join")?;
        let stdin = serde_json::to_vec(&invitation);
        invitation.token.zeroize();
        let join = JoinMaterial {
            host,
            url: format!("{}/remote/join", self.issuer.origin()),
            stdin: Secret::new(stdin.map_err(|_| "join")?),
        };
        self.still_bound(host, generation).await?;
        install
            .setup(&join)
            .await
            .map_err(|failure| logged("start", &failure))?;
        drop(join);
        self.set(attempt, generation, Stage::Starting);
        // R2: the successor proves itself on its private lane only.
        let successor = self
            .hosts
            .successors()
            .wait(attempt, SUCCESSOR_BOUND)
            .await
            .map_err(|_| "connect")?;
        let facts = tokio::time::timeout(
            Duration::from_secs(15),
            successor.call(
                "host.facts.read".into(),
                br#"{"includeLive":false}"#.to_vec(),
            ),
        )
        .await
        .map_err(|_| "proof")?
        .map_err(|_| "proof")?;
        let facts: Value = serde_json::from_slice(&facts).map_err(|_| "proof")?;
        if facts["executionUid"] != 0 || facts["mode"] != "remote" {
            return Err("proof");
        }
        self.still_bound(host, generation).await?;
        // J465 P2-1: a terminal opened on the rootless agent during the
        // install would be orphaned when it is retired; stop here instead.
        no_open_terminals(agent)?;
        self.set(attempt, generation, Stage::Handover);
        install
            .commit()
            .await
            .map_err(|failure| logged("commit", &failure))?;
        // The relay must end before the handover: the handover cuts the
        // rootless link that carries it. With `Commit` first it ends without
        // a rollback; a handover that then fails is undone by the
        // successor's own uninstall (R5).
        session
            .commit(install.transaction())
            .await
            .map_err(|failure| logged("relay", &failure))?;
        if !session.finish(READY_BOUND).await {
            return Err("relay");
        }
        let fingerprint: Vec<u8> = sqlx::query_scalar(
            "SELECT successor_fingerprint FROM remote_host_promotions WHERE attempt = ? AND state = 'enrolled'",
        )
        .bind(attempt.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| "handover")?
        .ok_or("handover")?;
        let fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| "handover")?;
        // Once more right before the point of no return (J465 P2-1, P3-4):
        // still the bound link, and still no terminal on it. A failure here
        // abandons; the committed root install is then removed by the
        // successor's uninstall outbox.
        let now = crate::runtime::unix_seconds().map_err(|_| "clock")?;
        if let Err(reason) = self.still_bound(host, generation).await {
            let _ = self.store.abandon_promotion(attempt, now).await;
            return Err(reason);
        }
        let result = handover_after_final_census(
            admission,
            || no_open_terminals(agent),
            std::future::ready(()),
            async {
                self.store
                    .handover(attempt, &fingerprint, now)
                    .await
                    .map(|_| ())
                    .map_err(|_| "handover")
            },
        )
        .await;
        if let Err(reason) = result {
            // The root install is committed on the host but never became the
            // host: abandon, which queues its own uninstall (R5).
            let _ = self.store.abandon_promotion(attempt, now).await;
            return Err(reason);
        }
        Ok(())
    }

    /// R7: the rootless link is still the one the promotion bound.
    async fn still_bound(&self, host: Uuid, generation: Uuid) -> Result<(), &'static str> {
        if self.hosts.generation(host).await == Some(generation) {
            Ok(())
        } else {
            Err("link")
        }
    }
}

/// Refuse (`terminals`) while the rootless agent reports any open terminal,
/// or can't say (its census is pending or its link is gone).
fn no_open_terminals(agent: &crate::embedded::EmbeddedAgent) -> Result<(), &'static str> {
    match &*agent.session_inventory().borrow() {
        crate::embedded::SessionInventoryState::Available(sessions) if sessions.is_empty() => {
            Ok(())
        }
        _ => Err("terminals"),
    }
}

/// Run the final census while admission stays closed, then commit handover.
async fn handover_after_final_census<Census, Checkpoint, Handover>(
    _admission: &TerminalPromotionGuard,
    census: Census,
    checkpoint: Checkpoint,
    handover: Handover,
) -> Result<(), &'static str>
where
    Census: FnOnce() -> Result<(), &'static str>,
    Checkpoint: std::future::Future<Output = ()>,
    Handover: std::future::Future<Output = Result<(), &'static str>>,
{
    census()?;
    checkpoint.await;
    handover.await
}

/// The answer for a host whose operating system this upgrade doesn't
/// cover, or `None` to go on.
///
/// On a Mac the infraternal agent stays rootless by design: the only part
/// that needs root, the mesh, already runs as its own root launchd service,
/// installed with one sudo prompt by `infraternal up` on the Mac
/// (`infraternal_plugin_mesh::macos_service`). So Full access never turns a
/// Mac agent into a root agent; it refuses and points there instead
/// (owner, 2026-11-10, #399). Unknown facts are not refused here: the probe
/// itself fails closed on a host that can't elevate.
fn refusal_for_os(os: Option<&str>) -> Option<Value> {
    (os == Some("macOS")).then(|| {
        json!({
            "outcome": "macos",
            "full": false,
            "message": "On a Mac, infraternal doesn't need a root agent. To use the mesh, run `infraternal up` on the Mac once; it asks for your password one time to install its system service.",
        })
    })
}

/// Note an install step's failure for the operator and return its word.
/// Only fixed text is logged: the step, the failure's own fixed message,
/// its step and exit status; never host output or a secret.
fn logged(step: &'static str, failure: &infraternal_plugin_ssh::model::Failure) -> &'static str {
    tracing::warn!(
        step,
        message = failure.message,
        failed_step = ?failure.failed_step,
        exit_status = ?failure.exit_status,
        "root upgrade install step failed"
    );
    step
}

/// How a root install ended short of the handover.
struct Ended {
    /// The step that failed, as a fixed word for the activity log.
    reason: &'static str,
    /// Whether the host is known to be as it was: nothing reached it, or
    /// this transaction's rollback was verified.
    restored: bool,
}

/// Removes a private directory when dropped.
struct RemoveDir(PathBuf);

impl Drop for RemoveDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

use sha2::Digest as _;

#[cfg(test)]
mod tests {
    //! The operating-system gate of a root upgrade.
    use super::*;

    /// J465 P2-1: the gate before commit and before the handover refuses
    /// while the rootless agent reports any terminal, or can't say.
    #[tokio::test]
    async fn the_upgrade_stops_while_a_terminal_is_open() {
        use crate::embedded::SessionInventoryState;
        let (agent, _accepts) = crate::embedded::EmbeddedAgent::remote(1001);
        assert_eq!(no_open_terminals(&agent), Err("terminals"));
        agent.set_session_inventory_for_test(SessionInventoryState::Available(Vec::new().into()));
        assert_eq!(no_open_terminals(&agent), Ok(()));
        agent.set_session_inventory_for_test(SessionInventoryState::Available(
            vec![[7u8; 16]].into(),
        ));
        assert_eq!(no_open_terminals(&agent), Err("terminals"));
        agent.set_session_inventory_for_test(SessionInventoryState::Unavailable);
        assert_eq!(no_open_terminals(&agent), Err("terminals"));
    }

    /// An open attempted after the final census cannot cross the handover boundary.
    #[tokio::test]
    async fn a_terminal_open_at_the_census_checkpoint_is_refused() {
        let hosts = crate::remote_runtime::RemoteHosts::default();
        let host = Uuid::from_u128(0x522);
        let admission = Arc::new(hosts.block_terminal_opens(host).await.unwrap());
        let task_admission = Arc::clone(&admission);
        let (at_census, reached_census) = tokio::sync::oneshot::channel();
        let (resume_handover, continue_handover) = tokio::sync::oneshot::channel();
        let handed_over = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let recorded_handover = handed_over.clone();
        let task = tokio::spawn(async move {
            handover_after_final_census(
                task_admission.as_ref(),
                || Ok(()),
                async move {
                    let _ = at_census.send(());
                    let _ = continue_handover.await;
                },
                async move {
                    recorded_handover.store(true, std::sync::atomic::Ordering::Release);
                    Ok(())
                },
            )
            .await
        });

        reached_census.await.unwrap();
        assert!(hosts.admit_terminal_open(host).is_err());
        assert!(!handed_over.load(std::sync::atomic::Ordering::Acquire));
        resume_handover.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(handed_over.load(std::sync::atomic::Ordering::Acquire));
        drop(admission);
        assert!(hosts.admit_terminal_open(host).is_ok());
    }

    /// A [`Promotions`] on the real SQLite fixture (host 42, rootless as uid
    /// 1002, owner session `s` unlocked with its admin window opened at 150)
    /// and an empty host registry: the host has no live link, so a finish
    /// that gets past its reservation ends at the R7 check. The returned
    /// sender releases a `finish` held right after its reservation.
    async fn promotions() -> (
        Promotions,
        EnrollmentStore,
        SqlitePool,
        Uuid,
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        /// A payload source with nothing to give; the harness never installs.
        struct NoPayload;
        impl PayloadSource for NoPayload {
            fn get(
                &self,
                _architecture: Architecture,
            ) -> infraternal_plugin_ssh::transport::Operation<'_, PathBuf> {
                Box::pin(async {
                    Err(infraternal_plugin_ssh::model::Failure::new(
                        infraternal_plugin_ssh::model::FailureKind::Install,
                        "no payload in the harness",
                    ))
                })
            }
        }
        let (store, pool, host) = crate::enrollment::authority::tests::enrolled().await;
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES ('s','owner','fixture',100000,150,1)")
            .execute(&pool)
            .await
            .unwrap();
        let auth = crate::auth::Auth::new(
            pool.clone(),
            "auth.example.test",
            "https://auth.example.test",
        )
        .await
        .unwrap();
        let material = crate::ca::tests::test_material();
        let issuer = InvitationIssuer::new(
            auth,
            pool.clone(),
            store.clone(),
            crate::remote_http::EnrollmentService {
                source: Arc::new(crate::ca_memory::MemoryCaSource::cold_start(
                    material.issuer().clone(),
                )),
                endpoint: crate::remote_http::EnrollmentEndpoint {
                    ca_der: material.issuer().to_der().unwrap(),
                    endpoint: "127.0.0.1:4443".parse().unwrap(),
                    server_name: "localhost".into(),
                },
            },
        );
        let scratch = std::env::temp_dir().join(format!("j574-promotions-{}", Uuid::new_v4()));
        let promotions = Promotions::new(
            store.clone(),
            pool.clone(),
            RemoteHosts::default(),
            issuer,
            Arc::new(NoPayload),
            "/proc/self/exe".into(),
            scratch,
        )
        .unwrap();
        let (release, gate) = tokio::sync::oneshot::channel();
        let (reserved, observed) = tokio::sync::oneshot::channel();
        *promotions.after_reserve.lock().unwrap() = Some(AfterReserveGate {
            reserved,
            release: gate,
        });
        (promotions, store, pool, host, release, observed)
    }

    /// The state and try flag of `attempt`'s row.
    async fn row(pool: &SqlitePool, attempt: Uuid) -> (String, i64) {
        sqlx::query_as("SELECT state, tried FROM remote_host_promotions WHERE attempt = ?")
            .bind(attempt.as_bytes().as_slice())
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// J569 P2-1: a `finish` that the request deadline cuts off after its try
    /// was reserved still settles the row. Before, the work ran inside the
    /// request: a dropped request left the row `elevating` (409 Busy for up
    /// to 15 minutes), never ended the host side, and the sweeper later
    /// counted it as a typed try.
    #[tokio::test]
    async fn a_finish_cut_off_after_its_reservation_still_settles() {
        let (promotions, store, pool, host, release, reserved) = promotions().await;
        let attempt = Uuid::from_u128(0x574);
        let now = 200;
        store
            .begin_promotion(
                "s",
                host,
                attempt,
                Method::Su,
                Bound {
                    from_uid: 1002,
                    from_fingerprint: [1; 32],
                    link_generation: Uuid::from_u128(5),
                },
                now,
            )
            .await
            .unwrap();
        let request = tokio::spawn({
            let promotions = promotions.clone();
            async move {
                promotions
                    .finish("s", attempt, Some("sealed".into()), now)
                    .await
            }
        });
        // Wait for the fixture's post-reservation signal, then cut the request off there.
        tokio::time::timeout(Duration::from_secs(60), reserved)
            .await
            .expect("finish did not reserve the try")
            .expect("reservation observer was dropped");
        request.abort();
        let _ = request.await;
        let _ = release.send(());
        let settled = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let row = row(&pool, attempt).await;
                if row.0 != "elevating" {
                    return row;
                }
                // sleep: polling the row for the settlement; the outcome never depends on timing.
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert_eq!(
            settled.ok(),
            Some(("failed".to_owned(), 0)),
            "a finish cut off after its reservation left the row elevating"
        );
    }

    /// A Mac is refused with a pointer to the mesh service; Linux and
    /// unread facts go on to the probe.
    #[test]
    fn a_mac_is_never_upgraded_to_a_root_agent() {
        let refusal = refusal_for_os(Some("macOS")).unwrap();
        assert_eq!(refusal["outcome"], "macos");
        assert!(
            refusal["message"]
                .as_str()
                .unwrap()
                .contains("infraternal up")
        );
        assert!(refusal_for_os(Some("Linux")).is_none());
        assert!(refusal_for_os(Some("AlmaLinux")).is_none());
        assert!(refusal_for_os(None).is_none());
    }
}
