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
    remote_runtime::RemoteHosts,
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
        })
    }

    /// Whether the session is a host admin of a live rootless `host`, inside
    /// its admin window. A read for probe and status only; every write
    /// rechecks this in its own statement.
    async fn admin(&self, session_hash: &str, host: Uuid, now: i64) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM remote_hosts h JOIN sessions s ON s.user_id = h.owner_id \
             JOIN users u ON u.id = s.user_id WHERE h.id = ? AND h.revoked_at IS NULL \
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
        // A crashed driver's leftovers end before anything new begins.
        let _ = self.store.sweep_promotions(now, false).await;
        let (agent, uid, fingerprint, generation) =
            self.hosts.binding(host).await.ok_or(Refused::Unavailable)?;
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
        mut sealed: Option<String>,
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
                    driver.install(host, attempt, agent, bound_generation).await;
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
            let _ = self
                .store
                .settle_try(attempt, Settled::Failed { typed }, now)
                .await;
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
    /// never changes the upgrade.
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
    }

    /// The install, from the relay to the handover (see the module docs).
    /// Every ending writes the row; the host side cleans up by itself.
    async fn install(
        &self,
        host: Uuid,
        attempt: Uuid,
        agent: crate::embedded::EmbeddedAgent,
        generation: Uuid,
    ) {
        let person = self.person(attempt).await.unwrap_or_default();
        let outcome = tokio::time::timeout(
            Duration::from_secs(
                u64::try_from(crate::enrollment::promotion::LIFETIME).unwrap_or(900),
            ),
            self.install_steps(host, attempt, &agent, generation),
        )
        .await
        .unwrap_or(Err("deadline"));
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
            Err(reason) => {
                // One write that bars the handover; a joined successor is
                // asked to uninstall itself (R5). A row still `installing`
                // without a successor was rolled back by the relay.
                if self.store.rolled_back(attempt, now).await.is_err() {
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

    /// The install's steps; `Err` names the step that failed (a fixed word).
    async fn install_steps(
        &self,
        host: Uuid,
        attempt: Uuid,
        agent: &crate::embedded::EmbeddedAgent,
        generation: Uuid,
    ) -> Result<(), &'static str> {
        let directory = self.scratch.join(attempt.simple().to_string());
        std::fs::create_dir(&directory).map_err(|_| "local")?;
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
        .map_err(|_| "relay")?;
        let session = Arc::new(session);
        let target = Target {
            id: "promotion".into(),
            address: TargetAddress::Discovered("relay".into()),
            credential: None,
            mode: InstallMode::Root,
            root_consent: true,
        };
        let install =
            Installation::new_pending(session.clone(), &target, host).map_err(|_| "install")?;
        // R4: before any step, the relay learns how to put the host back.
        session.arm_rollback(install.rollback_script());
        let result = self
            .run_install(host, attempt, agent, generation, &session, &install)
            .await;
        if result.is_err() && !install.committed() {
            let _ = install.rollback().await;
        }
        // Without the Commit frame, closing makes the relay roll back too.
        session.close();
        result
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
            .map_err(|_| "stage")?;
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
        install.setup(&join).await.map_err(|_| "start")?;
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
        self.set(attempt, generation, Stage::Handover);
        install.commit().await.map_err(|_| "commit")?;
        // The relay must end before the handover: the handover cuts the
        // rootless link that carries it. With `Commit` first it ends without
        // a rollback; a handover that then fails is undone by the
        // successor's own uninstall (R5).
        session.commit();
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
        let now = crate::runtime::unix_seconds().map_err(|_| "clock")?;
        if self
            .store
            .handover(attempt, &fingerprint, now)
            .await
            .is_err()
        {
            // The root install is committed on the host but never became the
            // host: abandon, which queues its own uninstall (R5).
            let _ = self.store.abandon_promotion(attempt, now).await;
            return Err("handover");
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

/// Removes a private directory when dropped.
struct RemoveDir(PathBuf);

impl Drop for RemoveDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

use sha2::Digest as _;
